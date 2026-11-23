// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/qwq-panel/qwq/internal/capability/sysctl"
	"github.com/qwq-panel/qwq/internal/sandbox"
)

type fixtureCapabilityRunner struct {
	calls      int
	panicValue bool
}

type cancelCapabilityRunner struct {
	started  chan struct{}
	canceled chan struct{}
}

func (r *cancelCapabilityRunner) Run(ctx context.Context, _ sandbox.CapabilityRequest) (sandbox.CapabilityResponse, error) {
	close(r.started)
	<-ctx.Done()
	close(r.canceled)
	return sandbox.CapabilityResponse{Code: "CANCELED", Error: "已取消"}, nil
}

func TestCapabilityDisconnectCancelsRunner(t *testing.T) {
	listener, err := net.Listen("unix", t.TempDir()+"/cap.sock")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	runner := &cancelCapabilityRunner{started: make(chan struct{}), canceled: make(chan struct{})}
	server := newCapabilityServer(runner, nil, "test")
	server.lookupAgentUID = func(string) (int, error) { return os.Getuid(), nil }
	done := make(chan error, 1)
	go func() { done <- server.serve(t.Context(), listener, true) }()
	connection, err := net.Dial("unix", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	if err := sandbox.WriteHelperJSON(connection, sandbox.CapabilityRequest{Op: "firewall.get", ID: "security.basic"}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-runner.started:
	case <-time.After(time.Second):
		t.Fatal("runner did not start")
	}
	connection.Close()
	select {
	case <-runner.canceled:
	case <-time.After(time.Second):
		t.Fatal("peer disconnect did not cancel the runner")
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("request left a temporary server running")
	}
}

func (r *fixtureCapabilityRunner) Run(_ context.Context, request sandbox.CapabilityRequest) (sandbox.CapabilityResponse, error) {
	r.calls++
	if r.panicValue {
		panic("CANARY_SECRET")
	}
	return sandbox.CapabilityResponse{OK: true, ResultJSON: []byte(`{"revision":"2"}`)}, nil
}

func TestCapabilityDispatchWhitelistAndPanicSafety(t *testing.T) {
	logs := &strings.Builder{}
	runner := &fixtureCapabilityRunner{}
	server := newCapabilityServer(runner, slog.New(slog.NewJSONHandler(logs, nil)), "test")
	for _, op := range []string{"firewall.get", "sshd.get-effective", "account.list-keys", "ban.list"} {
		response := server.handle(t.Context(), sandbox.CapabilityRequest{Op: op, ID: "security.basic", ParamsJSON: []byte(`{}`)})
		if !response.OK {
			t.Fatalf("白名单 verb 不可派发：%s", op)
		}
	}
	if response := server.handle(t.Context(), sandbox.CapabilityRequest{Op: "exec", ID: "security.basic", ParamsJSON: []byte(`{}`)}); response.OK || runner.calls != 4 {
		t.Fatal("任意 exec 被接受")
	}
	runner.panicValue = true
	response := server.handle(t.Context(), sandbox.CapabilityRequest{Op: "account.set-password", ID: "security.basic", ParamsJSON: []byte(`{}`), Secret: []byte("CANARY_SECRET")})
	if response.OK || response.Code != "INTERNAL" || strings.Contains(logs.String(), "CANARY_SECRET") {
		t.Fatal("panic 未安全转换或泄漏秘密")
	}
}

func TestCapabilitySingleRequestActivation(t *testing.T) {
	listener, err := net.Listen("unix", t.TempDir()+"/cap.sock")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	runner := &fixtureCapabilityRunner{}
	server := newCapabilityServer(runner, slog.New(slog.DiscardHandler), "test")
	server.lookupAgentUID = func(string) (int, error) { return os.Getuid(), nil }
	done := make(chan error, 1)
	go func() { done <- server.serve(t.Context(), listener, true) }()
	client := sandbox.NewCapabilityClient(listener.Addr().String())
	response, err := client.Call(t.Context(), sandbox.CapabilityRequest{Op: "firewall.get", ID: "security.basic", ParamsJSON: []byte(`{}`)})
	if err != nil || !response.OK {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("单次激活未退出")
	}
}

func TestCapabilityRootRequirement(t *testing.T) {
	output := io.Discard
	if code := run(t.Context(), nil, output, output, func(string) string { return "" }, func() int { return 123 }); code == 0 {
		t.Fatal("非 root 进程被接受")
	}
}

func TestCapabilityDispatchesSysctlApplyAndRollback(t *testing.T) {
	managedPath := filepath.Join(t.TempDir(), "99-qwq-tcpfit.conf")
	var ranArgs [][]string
	svc := &sysctl.Service{
		ManagedPath: managedPath,
		RunCmd: func(_ context.Context, _ string, args []string) ([]byte, error) {
			ranArgs = append(ranArgs, append([]string(nil), args...))
			return []byte("ok"), nil
		},
	}
	base := &fixtureCapabilityRunner{}
	server := newCapabilityServer(newSysctlDispatchRunner(base, svc), slog.New(slog.DiscardHandler), "test")

	// 1. 允许白名单内的 bbr + fq 参数
	okResp := server.handle(t.Context(), sandbox.CapabilityRequest{
		Op:         "sysctl.apply",
		ID:         "proxy.advanced",
		ParamsJSON: []byte(`{"values":{"net.core.default_qdisc":"fq","net.ipv4.tcp_congestion_control":"bbr"}}`),
	})
	if !okResp.OK {
		t.Fatalf("sysctl.apply(bbr) 应成功，实际: %+v", okResp)
	}
	if _, err := os.Stat(managedPath); err != nil {
		t.Fatalf("sysctl.apply 未落盘配置文件: %v", err)
	}

	// 2. 严禁全局 tcp_congestion_control=brutal
	badResp := server.handle(t.Context(), sandbox.CapabilityRequest{
		Op:         "sysctl.apply",
		ID:         "proxy.advanced",
		ParamsJSON: []byte(`{"values":{"net.ipv4.tcp_congestion_control":"brutal"}}`),
	})
	if badResp.OK || badResp.Code != "VALIDATION_FAILED" {
		t.Fatalf("全局 brutal 必须被拒绝，实际: %+v", badResp)
	}

	// 3. sysctl.rollback 删除托管文件并恢复基线
	rbResp := server.handle(t.Context(), sandbox.CapabilityRequest{
		Op:         "sysctl.rollback",
		ID:         "proxy.advanced",
		ParamsJSON: []byte(`{"baseline":{"net.ipv4.tcp_congestion_control":"cubic"}}`),
	})
	if !rbResp.OK {
		t.Fatalf("sysctl.rollback 应成功，实际: %+v", rbResp)
	}
	if _, err := os.Stat(managedPath); !os.IsNotExist(err) {
		t.Fatalf("sysctl.rollback 应移除托管文件")
	}
	if base.calls != 0 || len(ranArgs) < 2 {
		t.Fatalf("sysctl 请求应由 sysctl.Service 处理，实际 base.calls=%d ranArgs=%v", base.calls, ranArgs)
	}
}
