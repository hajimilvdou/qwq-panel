// SPDX-License-Identifier: AGPL-3.0-only

//go:build linux

package sandbox

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/qwq-panel/qwq/internal/platform/ids"
	"github.com/qwq-panel/qwq/internal/platform/problem"
)

// ======================== 真实 Unix peer 集成：消费者证书四动词往返与 root peer 门禁 ========================

func consumerCertClientFixture(t *testing.T, answer func(DecodedHelperRequest) (any, error)) (*HelperClient, *atomic.Int32) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("consumer-cert 正向协议要求真实 root Unix peer，须在 Root Linux 门禁执行")
	}
	address := "@" + ids.New(nil).New(ids.Generation)
	listener, err := net.Listen("unix", address)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	done := make(chan struct{})
	var fixtureErr error
	var requests atomic.Int32
	go func() {
		defer close(done)
		connection, err := listener.Accept()
		if err != nil {
			fixtureErr = err
			return
		}
		defer connection.Close()
		deadline, _ := ctx.Deadline()
		if err := connection.SetDeadline(deadline); err != nil {
			fixtureErr = err
			return
		}
		raw, err := ReadHelperDocument(bufio.NewReaderSize(connection, 64<<10))
		defer clear(raw)
		if err != nil {
			fixtureErr = err
			return
		}
		request, err := DecodePrivilegedHelperRequest(raw)
		if err != nil {
			fixtureErr = err
			return
		}
		requests.Add(1)
		response, err := answer(request)
		if err != nil {
			fixtureErr = err
			return
		}
		fixtureErr = WriteHelperJSON(connection, response)
	}()
	t.Cleanup(func() {
		cancel()
		_ = listener.Close()
		select {
		case <-done:
			if fixtureErr != nil && !errors.Is(fixtureErr, net.ErrClosed) {
				t.Errorf("协议 fixture 失败：%v", fixtureErr)
			}
		case <-time.After(time.Second):
			t.Error("协议 fixture 未回收")
		}
	})
	client := NewHelperClient("/run/qwq/consumer-cert-test.sock")
	client.dial = func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", address)
	}
	return client, &requests
}

func TestConsumerCertClientRoundTripAllFourVerbs(t *testing.T) {
	stageReq := consumerCertTestStageRequest()
	stageReq.Op = "" // 客户端必须自动补齐固定 op。
	stagedProof := consumerCertTestProof("alpha", "bind-01", 1)

	client, count := consumerCertClientFixture(t, func(decoded DecodedHelperRequest) (any, error) {
		if decoded.ConsumerStage == nil || decoded.ConsumerStage.Op != HelperOpConsumerCertStage ||
			decoded.ConsumerStage.Binding != stageReq.Binding {
			return nil, errors.New("unexpected stage request")
		}
		return ConsumerCertStageResponse{
			ConsumerCertResponseStatus: ConsumerCertResponseStatus{OK: true, UID: 0},
			Proof:                      &stagedProof,
		}, nil
	})
	gotProof, err := client.StageConsumerCert(t.Context(), stageReq)
	if err != nil || gotProof != stagedProof || count.Load() != 1 {
		t.Fatalf("StageConsumerCert 失败：proof=%+v count=%d err=%v", gotProof, count.Load(), err)
	}

	// 首次激活（无 expected，返回 previous=nil）。
	activateReq := consumerCertTestActivateRequest(false)
	activateReq.Op = ""
	client, count = consumerCertClientFixture(t, func(decoded DecodedHelperRequest) (any, error) {
		if decoded.ConsumerActivate == nil || decoded.ConsumerActivate.Expected != nil ||
			decoded.ConsumerActivate.Wanted != activateReq.Wanted {
			return nil, errors.New("unexpected initial activate request")
		}
		return ConsumerCertActivateResponse{
			ConsumerCertResponseStatus: ConsumerCertResponseStatus{OK: true, UID: 0},
		}, nil
	})
	gotPrev, err := client.ActivateConsumerCert(t.Context(), activateReq)
	if err != nil || gotPrev != nil || count.Load() != 1 {
		t.Fatalf("首次 ActivateConsumerCert 失败：prev=%+v count=%d err=%v", gotPrev, count.Load(), err)
	}

	// 轮换激活（含 expected，返回 previous）。
	rotateReq := consumerCertTestActivateRequest(true)
	prevProof := *rotateReq.Expected
	client, count = consumerCertClientFixture(t, func(decoded DecodedHelperRequest) (any, error) {
		if decoded.ConsumerActivate == nil || decoded.ConsumerActivate.Expected == nil ||
			*decoded.ConsumerActivate.Expected != prevProof {
			return nil, errors.New("unexpected rotate activate request")
		}
		return ConsumerCertActivateResponse{
			ConsumerCertResponseStatus: ConsumerCertResponseStatus{OK: true, UID: 0},
			Previous:                   &prevProof,
		}, nil
	})
	gotPrev, err = client.ActivateConsumerCert(t.Context(), rotateReq)
	if err != nil || gotPrev == nil || *gotPrev != prevProof || count.Load() != 1 {
		t.Fatalf("轮换 ActivateConsumerCert 失败：prev=%+v count=%d err=%v", gotPrev, count.Load(), err)
	}

	// CurrentConsumerCert：存在与不存在两种情况。
	currentProof := rotateReq.Wanted
	client, count = consumerCertClientFixture(t, func(decoded DecodedHelperRequest) (any, error) {
		if decoded.ConsumerCurrent == nil || decoded.ConsumerCurrent.PluginID != "alpha" || decoded.ConsumerCurrent.BindingID != "bind-01" {
			return nil, errors.New("unexpected current request")
		}
		return ConsumerCertCurrentResponse{
			ConsumerCertResponseStatus: ConsumerCertResponseStatus{OK: true, UID: 0},
			Current:                    &currentProof,
		}, nil
	})
	gotCurrent, err := client.CurrentConsumerCert(t.Context(), "alpha", "bind-01")
	if err != nil || gotCurrent == nil || *gotCurrent != currentProof || count.Load() != 1 {
		t.Fatalf("CurrentConsumerCert(存在) 失败：cur=%+v count=%d err=%v", gotCurrent, count.Load(), err)
	}

	client, count = consumerCertClientFixture(t, func(decoded DecodedHelperRequest) (any, error) {
		if decoded.ConsumerCurrent == nil {
			return nil, errors.New("unexpected current request")
		}
		return ConsumerCertCurrentResponse{
			ConsumerCertResponseStatus: ConsumerCertResponseStatus{OK: true, UID: 0},
		}, nil
	})
	gotCurrent, err = client.CurrentConsumerCert(t.Context(), "alpha", "bind-01")
	if err != nil || gotCurrent != nil || count.Load() != 1 {
		t.Fatalf("CurrentConsumerCert(空) 失败：cur=%+v count=%d err=%v", gotCurrent, count.Load(), err)
	}

	// RemoveConsumerCert。
	client, count = consumerCertClientFixture(t, func(decoded DecodedHelperRequest) (any, error) {
		if decoded.ConsumerRemove == nil || decoded.ConsumerRemove.PluginID != "alpha" || decoded.ConsumerRemove.BindingID != "bind-01" {
			return nil, errors.New("unexpected remove request")
		}
		return ConsumerCertRemoveResponse{
			ConsumerCertResponseStatus: ConsumerCertResponseStatus{OK: true, UID: 0},
			Removed:                    true,
		}, nil
	})
	removed, err := client.RemoveConsumerCert(t.Context(), "alpha", "bind-01")
	if err != nil || !removed || count.Load() != 1 {
		t.Fatalf("RemoveConsumerCert 失败：removed=%v count=%d err=%v", removed, count.Load(), err)
	}
}

func TestConsumerCertClientActivatePreservesPreviousAndUncertainOnError(t *testing.T) {
	rotateReq := consumerCertTestActivateRequest(true)
	prevProof := *rotateReq.Expected
	client, count := consumerCertClientFixture(t, func(decoded DecodedHelperRequest) (any, error) {
		if decoded.ConsumerActivate == nil {
			return nil, errors.New("unexpected activate request")
		}
		return ConsumerCertActivateResponse{
			ConsumerCertResponseStatus: ConsumerCertResponseStatus{
				OK:        false,
				UID:       0,
				Code:      string(problem.Internal),
				Error:     "activation outcome is uncertain after rename failure",
				Uncertain: true,
			},
			Previous: &prevProof,
		}, nil
	})
	gotPrev, err := client.ActivateConsumerCert(t.Context(), rotateReq)
	var ccErr *ConsumerCertError
	if !errors.As(err, &ccErr) || !ccErr.Uncertain || ccErr.Code != string(problem.Internal) || ccErr.Detail == "" {
		t.Fatalf("ActivateConsumerCert 未保留 Uncertain 错误：%v", err)
	}
	if gotPrev == nil || *gotPrev != prevProof || count.Load() != 1 {
		t.Fatalf("ActivateConsumerCert 在 Uncertain 失败时丢失 Previous：prev=%+v count=%d", gotPrev, count.Load())
	}
}

func TestConsumerCertClientRejectsCrossBindingResponses(t *testing.T) {
	wrongProof := consumerCertTestProof("beta", "bind-99", 1)

	client, _ := consumerCertClientFixture(t, func(DecodedHelperRequest) (any, error) {
		return ConsumerCertStageResponse{
			ConsumerCertResponseStatus: ConsumerCertResponseStatus{OK: true, UID: 0},
			Proof:                      &wrongProof,
		}, nil
	})
	if _, err := client.StageConsumerCert(t.Context(), consumerCertTestStageRequest()); !errors.Is(err, ErrConsumerCertDocument) {
		t.Fatalf("StageConsumerCert 接受了跨绑定 Proof：%v", err)
	}

	client, _ = consumerCertClientFixture(t, func(DecodedHelperRequest) (any, error) {
		return ConsumerCertCurrentResponse{
			ConsumerCertResponseStatus: ConsumerCertResponseStatus{OK: true, UID: 0},
			Current:                    &wrongProof,
		}, nil
	})
	if _, err := client.CurrentConsumerCert(t.Context(), "alpha", "bind-01"); !errors.Is(err, ErrConsumerCertDocument) {
		t.Fatalf("CurrentConsumerCert 接受了跨插件 Proof：%v", err)
	}

	client, _ = consumerCertClientFixture(t, func(DecodedHelperRequest) (any, error) {
		return ConsumerCertActivateResponse{
			ConsumerCertResponseStatus: ConsumerCertResponseStatus{
				OK:        false,
				UID:       0,
				Code:      string(problem.Internal),
				Error:     "uncertain",
				Uncertain: true,
			},
			Previous: &wrongProof,
		}, nil
	})
	if prev, err := client.ActivateConsumerCert(t.Context(), consumerCertTestActivateRequest(true)); !errors.Is(err, ErrConsumerCertDocument) || prev != nil {
		t.Fatalf("ActivateConsumerCert 接受了跨绑定 Previous：prev=%+v err=%v", prev, err)
	}
}

func TestConsumerCertClientRejectsNonUnixPeerBeforeBody(t *testing.T) {
	server, connection := net.Pipe()
	defer server.Close()
	if err := server.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	type received struct {
		count int
		err   error
	}
	done := make(chan received, 1)
	go func() {
		var body [1]byte
		n, err := server.Read(body[:])
		done <- received{n, err}
	}()
	client := NewHelperClient("/run/qwq/consumer-cert-test.sock")
	client.dial = func(context.Context, string, string) (net.Conn, error) { return connection, nil }
	var denied *problem.Error
	if _, err := client.CurrentConsumerCert(t.Context(), "alpha", "bind-01"); !errors.As(err, &denied) || denied.Code != problem.Unauthenticated {
		t.Fatalf("非 Unix peer 未作为未认证拒绝：%v", err)
	}
	select {
	case result := <-done:
		if result.count != 0 || !errors.Is(result.err, io.EOF) {
			t.Fatalf("验证 peer 前已写出正文：%+v", result)
		}
	case <-time.After(time.Second):
		t.Fatal("非 Unix 拒绝路径未关闭连接")
	}
}

func TestConsumerCertClientRejectsNonRootUnixPeerBeforeBody(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("当前测试进程为 root，非 root peer 拒绝在非 root 进程下验证")
	}
	address := "@" + ids.New(nil).New(ids.Generation)
	listener, err := net.Listen("unix", address)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	type received struct {
		count int
		err   error
	}
	done := make(chan received, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			done <- received{0, err}
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(time.Second))
		var body [1]byte
		n, err := conn.Read(body[:])
		done <- received{n, err}
	}()

	client := NewHelperClient("/run/qwq/consumer-cert-test.sock")
	client.dial = func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", address)
	}
	var denied *problem.Error
	if _, err := client.RemoveConsumerCert(t.Context(), "alpha", "bind-01"); !errors.As(err, &denied) || denied.Code != problem.Unauthenticated {
		t.Fatalf("非 root Unix peer 未作为未认证拒绝：%v", err)
	}
	select {
	case result := <-done:
		if result.count != 0 || !errors.Is(result.err, io.EOF) {
			t.Fatalf("非 root peer 拒绝前已写出正文：%+v", result)
		}
	case <-time.After(time.Second):
		t.Fatal("非 root Unix 拒绝路径未关闭连接")
	}
}
