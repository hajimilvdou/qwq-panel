// SPDX-License-Identifier: AGPL-3.0-only

//go:build linux

package main

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/qwq-panel/qwq/internal/platform/problem"
	"github.com/qwq-panel/qwq/internal/sandbox"
)

// ======================== 真实UID和完整连接；fake后端只生产协议数据 ========================

func generationServerStopFixture() sandbox.GenerationStopRequest {
	return sandbox.GenerationStopRequest{Op: sandbox.HelperOpGenerationStop, ID: "alpha",
		OperationID: "op_01h455vb4pex5vsknk084sn02q", TargetRef: "gen_01h455vb4pex5vsknk084sn02q",
		Expected: sandbox.ProcessProof{Version: 1, Unit: "qwq-plugin@alpha.service", PID: 42, KernelStartTicks: 123,
			UID: 1234, BootID: "0123456789abcdef0123456789abcdef", InvocationID: "fedcba9876543210fedcba9876543210",
			Cgroup: "/system.slice/qwq-plugin@alpha.service", CgroupDevice: 1, CgroupInode: 2}}
}

type generationServerBackend struct {
	calls   atomic.Int32
	observe func(context.Context, string) (sandbox.ProcessProof, error)
}

func (backend *generationServerBackend) ObserveGeneration(ctx context.Context, id string) (sandbox.ProcessProof, error) {
	backend.calls.Add(1)
	if backend.observe != nil {
		return backend.observe(ctx, id)
	}
	return generationServerStopFixture().Expected, nil
}

func (backend *generationServerBackend) StopGeneration(_ context.Context, request sandbox.GenerationStopRequest) (sandbox.GenerationCompletion, error) {
	backend.calls.Add(1)
	return sandbox.NewGenerationCompletion(request, sandbox.StopObservation{Proof: request.Expected, OriginalExited: true, OriginalCgroupEmpty: true}, time.Now())
}

func (backend *generationServerBackend) RetireGeneration(_ context.Context, request sandbox.GenerationRetireRequest) (sandbox.GenerationRecordRef, error) {
	backend.calls.Add(1)
	return request.Reference(), nil
}

func generationServerConnection(t *testing.T, server *helperServer) (net.Conn, func(), func()) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("generation wire正向fixture必须由Root Linux运行")
	}
	address := "@" + filepath.Base(peerArena(t))
	listener, err := net.Listen("unix", address)
	if err != nil {
		t.Fatal(err)
	}
	client, err := net.DialTimeout("unix", address, peerFixtureTimeout)
	if err != nil {
		_ = listener.Close()
		t.Fatal(err)
	}
	connection, err := listener.Accept()
	if err != nil {
		_ = client.Close()
		_ = listener.Close()
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	gate := make(chan struct{})
	var start sync.Once
	release := func() { start.Do(func() { close(gate) }) }
	done := make(chan error, 1)
	go func() {
		select {
		case <-gate:
			server.serveConn(ctx, connection)
		case <-ctx.Done():
			_ = connection.Close()
		}
		done <- nil
	}()
	stop := func() {
		cancel()
		release()
		_ = client.Close()
		_ = connection.Close()
		_ = listener.Close()
	}
	wait := peerFixtureWaiter(t, done, stop)
	if err := client.SetDeadline(time.Now().Add(peerFixtureTimeout)); err != nil {
		t.Fatal(err)
	}
	return client, release, wait
}

func TestGenerationServerUnavailableNeverCallsRunner(t *testing.T) {
	host := newTestHost(t)
	stop := generationServerStopFixture()
	completion, err := sandbox.NewGenerationCompletion(stop, sandbox.StopObservation{Proof: stop.Expected, OriginalExited: true, OriginalCgroupEmpty: true}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	observe := sandbox.GenerationObserveRequest{Op: sandbox.HelperOpGenerationObserve, ID: "alpha"}
	retire := sandbox.GenerationRetireRequest{Op: sandbox.HelperOpGenerationRetire, ID: "alpha", OperationID: stop.OperationID,
		TargetRef: stop.TargetRef, ProofDigest: completion.Reference.ProofDigest, ReceiptDigest: completion.Reference.ReceiptDigest}
	for _, request := range []sandbox.DecodedHelperRequest{{Observe: &observe}, {Stop: &stop}, {Retire: &retire}} {
		response := host.server.handleGeneration(t.Context(), request)
		var status sandbox.GenerationResponseStatus
		switch typed := response.(type) {
		case sandbox.GenerationObserveResponse:
			status = typed.GenerationResponseStatus
		case sandbox.GenerationStopResponse:
			status = typed.GenerationResponseStatus
		case sandbox.GenerationRetireResponse:
			status = typed.GenerationResponseStatus
		default:
			t.Fatalf("缺失typed回应：%T", response)
		}
		if status.OK || status.Code != string(problem.Unavailable) {
			t.Fatalf("未装配后端假成功：%+v", status)
		}
	}
	if len(host.runner.calls) != 0 {
		t.Fatalf("未装配generation执行了命令：%v", host.runner.calls)
	}
}

func TestGenerationServerPrefetchedSecondFrameRejectedBeforeBackend(t *testing.T) {
	host := newTestHost(t)
	backend := &generationServerBackend{}
	host.server.generation = backend
	connection, start, wait := generationServerConnection(t, host.server)
	// 两帧先完整进入socket，再允许server读取，避免把预读回归变成发送时序赌运气。
	if _, err := connection.Write([]byte("{\"op\":\"generation-observe\",\"id\":\"alpha\"}\n{\"op\":\"ping\"}\n")); err != nil {
		t.Fatal(err)
	}
	start()
	var response sandbox.HelperResponse
	if err := sandbox.ReadHelperJSON(connection, &response); err != nil {
		t.Fatal(err)
	}
	wait()
	if response.OK || response.Code != string(problem.ValidationFailed) || backend.calls.Load() != 0 || len(host.runner.calls) != 0 {
		t.Fatalf("已预读第二帧仍触发动作：%+v backend=%d runner=%v", response, backend.calls.Load(), host.runner.calls)
	}
}

func TestGenerationServerRejectsTypedAliasesBeforeBackend(t *testing.T) {
	for _, body := range []string{`{"OP":"generation-observe","id":"alpha"}`, `{"op":"generation-observe","id":"alpha","expected":null}`} {
		host := newTestHost(t)
		backend := &generationServerBackend{}
		host.server.generation = backend
		connection, start, wait := generationServerConnection(t, host.server)
		start()
		if _, err := connection.Write([]byte(body + "\n")); err != nil {
			t.Fatal(err)
		}
		var response sandbox.HelperResponse
		if err := sandbox.ReadHelperJSON(connection, &response); err != nil {
			t.Fatal(err)
		}
		wait()
		if response.OK || response.Code != string(problem.ValidationFailed) || backend.calls.Load() != 0 {
			t.Fatalf("坏typed文档触发backend：%+v", response)
		}
	}
}

func TestGenerationServerBudgetStartsBeforeRequestBody(t *testing.T) {
	host := newTestHost(t)
	host.server.timeout = 400 * time.Millisecond
	entered := make(chan struct{}, 1)
	host.server.afterPeerAuth = func(context.Context) { entered <- struct{}{} }
	remaining := make(chan time.Duration, 1)
	backend := &generationServerBackend{observe: func(ctx context.Context, _ string) (sandbox.ProcessProof, error) {
		deadline, ok := ctx.Deadline()
		if !ok {
			return sandbox.ProcessProof{}, errors.New("missing request deadline")
		}
		remaining <- time.Until(deadline)
		return generationServerStopFixture().Expected, nil
	}}
	host.server.generation = backend
	connection, start, wait := generationServerConnection(t, host.server)
	start()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("服务未在读取正文前建立预算")
	}
	if _, err := connection.Write([]byte(`{"op":"generation-observe"`)); err != nil {
		t.Fatal(err)
	}
	timer := time.NewTimer(100 * time.Millisecond)
	defer timer.Stop()
	<-timer.C
	if _, err := connection.Write([]byte(",\"id\":\"alpha\"}\n")); err != nil {
		t.Fatal(err)
	}
	var response sandbox.GenerationObserveResponse
	if err := sandbox.ReadHelperJSON(connection, &response); err != nil || !response.OK {
		t.Fatalf("预算fixture失败：%+v %v", response, err)
	}
	wait()
	select {
	case budget := <-remaining:
		if budget >= 350*time.Millisecond || budget <= 0 {
			t.Fatalf("正文后重新起预算：%v", budget)
		}
	default:
		t.Fatal("backend未收到原预算")
	}
}

func TestGenerationServerRealUnauthorizedPeerIsDeniedBeforeBody(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("真实降UID的peer门禁由Root Linux运行")
	}
	host := newTestHost(t)
	backend := &generationServerBackend{}
	host.server.generation = backend
	result := peerUnixRequest(t, host.server, sandbox.HelperRequest{Op: sandbox.HelperOpGenerationObserve, ID: "alpha"}, 65534)
	if result.Failure != "" || result.OK || !result.Closed && result.Code != string(problem.Unauthenticated) || backend.calls.Load() != 0 || len(host.runner.calls) != 0 {
		t.Fatalf("未授权真实UID绕过正文前门禁：%+v backend=%d", result, backend.calls.Load())
	}
}
