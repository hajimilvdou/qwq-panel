// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/qwq-panel/qwq/internal/platform/config"
	"github.com/qwq-panel/qwq/internal/platform/problem"
	"github.com/qwq-panel/qwq/internal/pluginhost/supervisor"
)

type stubUnits struct{}

func (stubUnits) Start(context.Context, string) error { return nil }
func (stubUnits) Stop(context.Context, string) error  { return nil }
func (stubUnits) Kill(context.Context, string) error  { return nil }

func (stubUnits) Show(context.Context, string) (supervisor.UnitState, error) {
	return supervisor.UnitState{}, nil
}

type stubHost struct {
	serves  int
	stopped int
}

func (h *stubHost) Serve(context.Context, string) (func(), error) {
	h.serves++
	return func() { h.stopped++ }, nil
}

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func newTestSupervisor(t *testing.T) *supervisor.Supervisor {
	t.Helper()
	sup, err := supervisor.New(supervisor.Options{
		Units:     stubUnits{},
		Host:      &stubHost{},
		PluginDir: func(string) (string, error) { return t.TempDir(), nil },
		Logger:    discardLogger(),
		RunDir:    t.TempDir(),
	})
	if err != nil {
		t.Fatalf("supervisor.New: %v", err)
	}
	t.Cleanup(sup.Close)
	return sup
}

func TestNewRequiresSupervisor(t *testing.T) {
	if _, err := New(Options{}); !problem.HasCode(err, problem.ValidationFailed) {
		t.Fatalf("New without a supervisor = %v, want VALIDATION_FAILED", err)
	}
}

func TestNewCompletesZeroConfig(t *testing.T) {
	a, err := New(Options{Supervisor: newTestSupervisor(t), Logger: discardLogger()})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if a.cfg.RunDir != config.Default().RunDir || a.cfg.DataDir != config.Default().DataDir {
		t.Fatalf("config defaults = %q/%q", a.cfg.RunDir, a.cfg.DataDir)
	}
	if a.HostServer() == nil {
		t.Fatal("HostServer returned nil")
	}
}

func TestNewRejectsRelativeDirectories(t *testing.T) {
	sup := newTestSupervisor(t)
	if _, err := New(Options{Supervisor: sup, Config: config.Config{RunDir: "run", DataDir: "/var/lib/qwq"}}); !problem.HasCode(err, problem.ValidationFailed) {
		t.Fatalf("relative run_dir error = %v, want VALIDATION_FAILED", err)
	}
	if _, err := New(Options{Supervisor: sup, Config: config.Config{RunDir: "/run/qwq", DataDir: "data"}}); !problem.HasCode(err, problem.ValidationFailed) {
		t.Fatalf("relative data_dir error = %v, want VALIDATION_FAILED", err)
	}
}

func TestRunStartsAndClosesSupervisor(t *testing.T) {
	sup := newTestSupervisor(t)
	a, err := New(Options{Config: config.Default(), Logger: discardLogger(), Supervisor: sup})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- a.Run(ctx) }()

	time.Sleep(20 * time.Millisecond)
	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not return after cancellation")
	}
	if err := sup.Start(context.Background()); !problem.HasCode(err, problem.Unavailable) {
		t.Fatalf("supervisor was not closed by Run: %v", err)
	}
}

func TestHostMuxDelegates(t *testing.T) {
	host := &stubHost{}
	var gotPluginID string
	mux := HostMux(func(pluginID string) (supervisor.HostServer, error) {
		gotPluginID = pluginID
		return host, nil
	})
	stop, err := mux.Serve(context.Background(), "alpha")
	if err != nil {
		t.Fatalf("Serve: %v", err)
	}
	if gotPluginID != "alpha" || host.serves != 1 {
		t.Fatalf("factory calls = %q/%d", gotPluginID, host.serves)
	}
	stop()
	if host.stopped != 1 {
		t.Fatalf("stop calls = %d, want 1", host.stopped)
	}
	if _, err := mux.Serve(context.Background(), ""); !problem.HasCode(err, problem.ValidationFailed) {
		t.Fatalf("Serve with an empty plugin id = %v, want VALIDATION_FAILED", err)
	}
}

func TestHostMuxFailures(t *testing.T) {
	if _, err := HostMux(nil).Serve(context.Background(), "alpha"); !problem.HasCode(err, problem.Unavailable) {
		t.Fatalf("nil factory error = %v, want UNAVAILABLE", err)
	}
	broken := HostMux(func(string) (supervisor.HostServer, error) {
		return nil, errors.New("host service is not wired")
	})
	if _, err := broken.Serve(context.Background(), "alpha"); !problem.HasCode(err, problem.Unavailable) {
		t.Fatalf("factory error = %v, want UNAVAILABLE", err)
	}
	nilHost := HostMux(func(string) (supervisor.HostServer, error) { return nil, nil })
	if _, err := nilHost.Serve(context.Background(), "alpha"); !problem.HasCode(err, problem.Unavailable) {
		t.Fatalf("nil host error = %v, want UNAVAILABLE", err)
	}
}

func TestRunFailsWhenSupervisorIsClosed(t *testing.T) {
	sup := newTestSupervisor(t)
	sup.Close()
	a, err := New(Options{Supervisor: sup, Logger: discardLogger()})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := a.Run(context.Background()); !problem.HasCode(err, problem.Unavailable) {
		t.Fatalf("Run on a closed supervisor = %v, want UNAVAILABLE", err)
	}
}
