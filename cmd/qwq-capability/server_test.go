// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"io"
	"log/slog"
	"net"
	"os"
	"strings"
	"testing"
	"time"

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
