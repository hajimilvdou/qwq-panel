// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/qwq-panel/qwq/internal/sandbox"
)

type stubSystemctl struct {
	calls []string
	err   error
}

func (s *stubSystemctl) Start(_ context.Context, unit string) error {
	s.calls = append(s.calls, "start "+unit)
	return s.err
}

func (s *stubSystemctl) Stop(_ context.Context, unit string) error {
	s.calls = append(s.calls, "stop "+unit)
	return s.err
}

func (s *stubSystemctl) Kill(_ context.Context, unit string) error {
	s.calls = append(s.calls, "kill "+unit)
	return s.err
}

func (s *stubSystemctl) Show(_ context.Context, _ string) (sandbox.UnitStatus, error) {
	return sandbox.UnitStatus{}, nil
}

func TestCompatServerHandleAllowlist(t *testing.T) {
	sc := &stubSystemctl{}
	srv := newCompatServer(sc, "qwq", "v0.1.1-test", slog.New(slog.DiscardHandler))
	credDir := t.TempDir()
	srv.credentialsDir = credDir

	resp := srv.handle(context.Background(), sandbox.CompatUnitctlRequest{Action: "ping"})
	if !resp.OK || resp.Version != "v0.1.1-test" {
		t.Fatalf("ping = %+v", resp)
	}

	for _, tc := range []struct {
		action string
		unit   string
	}{
		{"start", "qwq-plugin@security.basic.service"},
		{"stop", "qwq-plugin@security.basic.socket"},
		{"kill", "qwq-plugin@noop.service"},
	} {
		r := srv.handle(context.Background(), sandbox.CompatUnitctlRequest{Action: tc.action, Unit: tc.unit})
		if !r.OK {
			t.Fatalf("%s %s failed: %+v", tc.action, tc.unit, r)
		}
	}
	if st, err := os.Stat(filepath.Join(credDir, "qwq-plugin@security.basic.service")); err != nil || !st.IsDir() {
		t.Fatalf("expected credentials dir for started service: %v", err)
	}
	if len(sc.calls) != 3 {
		t.Fatalf("calls = %v, want 3", sc.calls)
	}

	// Non-plugin units must be refused with FORBIDDEN.
	for _, bad := range []string{"sshd.service", "qwq-controller.service", "qwq-privileged.socket", "qwq-plugin@.service"} {
		r := srv.handle(context.Background(), sandbox.CompatUnitctlRequest{Action: "stop", Unit: bad})
		if r.OK || r.Code != "FORBIDDEN" {
			t.Fatalf("unit %q = %+v, want FORBIDDEN", bad, r)
		}
	}

	// Unknown actions must be refused.
	r := srv.handle(context.Background(), sandbox.CompatUnitctlRequest{Action: "daemon-reload", Unit: "qwq-plugin@noop.service"})
	if r.OK || r.Code != "VALIDATION_FAILED" {
		t.Fatalf("unknown action = %+v, want VALIDATION_FAILED", r)
	}

	// Systemctl error surfaces cleanly.
	sc.err = errors.New("unit not found")
	r = srv.handle(context.Background(), sandbox.CompatUnitctlRequest{Action: "start", Unit: "qwq-plugin@noop.service"})
	if r.OK || !strings.Contains(r.Error, "unit not found") {
		t.Fatalf("systemctl error = %+v", r)
	}
}

func TestCompatServerSocketRoundTrip(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("SO_PEERCRED round-trip test requires Linux")
	}
	dir, err := os.MkdirTemp("/tmp", "qwq-cus-")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	sock := filepath.Join(dir, "compat.sock")

	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	sc := &stubSystemctl{}
	srv := newCompatServer(sc, "qwq", "v0.1.1-test", slog.New(slog.DiscardHandler))
	// Allow the current test user UID in non-root CI environments.
	srv.lookupAgentUID = func(string) (int, error) { return os.Geteuid(), nil }

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.serve(ctx, ln, false) }()

	client := sandbox.NewCompatUnitctlClient(sock, nil)
	if err := client.Start(context.Background(), "qwq-plugin@noop.service"); err != nil {
		t.Fatalf("client.Start: %v", err)
	}
	if err := client.Stop(context.Background(), "qwq-plugin@noop.service"); err != nil {
		t.Fatalf("client.Stop: %v", err)
	}
	cancel()
	_ = ln.Close()
	<-done

	if len(sc.calls) != 2 || sc.calls[0] != "start qwq-plugin@noop.service" || sc.calls[1] != "stop qwq-plugin@noop.service" {
		t.Fatalf("calls = %v", sc.calls)
	}
}
