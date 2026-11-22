// SPDX-License-Identifier: AGPL-3.0-only

package controller

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/qwq-panel/qwq/internal/operations"
	"github.com/qwq-panel/qwq/internal/platform/clock"
	"github.com/qwq-panel/qwq/internal/platform/problem"
	"github.com/qwq-panel/qwq/internal/pluginhost/install"
	"github.com/qwq-panel/qwq/internal/pluginhost/supervisor"
	platformv1 "github.com/qwq-panel/qwq/sdk/gen/qwq/platform/v1"
)

// newRestoreRuntime builds a plugin runtime over the updater fixture's fake
// systemd and plugin socket, so supervisor and updater share one process.
func newRestoreRuntime(t *testing.T, f *runtimeFixture) *PluginRuntime {
	t.Helper()
	rt, err := NewPluginRuntime(PluginRuntimeOptions{
		Units:     UnitManagerAdapter{Systemctl: f.systemctl, NodeID: "local"},
		PluginDir: func(id string) (string, error) { return install.VersionDir(f.pluginsDir, id, f.version), nil },
		RunDir:    f.runDir,
		StateDir:  filepath.Join(filepath.Dir(f.runDir), "state"),
		Host:      func(string) (supervisor.HostServer, error) { return fakeHostServer{}, nil },
		Logger:    slog.New(slog.DiscardHandler),
		Clock:     clock.System{},
	})
	if err != nil {
		t.Fatalf("NewPluginRuntime: %v", err)
	}
	t.Cleanup(rt.Stop)
	if err := rt.Start(t.Context(), HostDeps{}); err != nil {
		t.Fatalf("Start: %v", err)
	}
	return rt
}

func TestAttachOnlyUnitsRefuseStart(t *testing.T) {
	units := &fakeSupervisorUnits{}
	rt := &PluginRuntime{}
	wrapped := attachOnlyUnits{UnitManager: units, rt: rt}
	if err := wrapped.Start(t.Context(), "alpha"); err != nil {
		t.Fatalf("Start without a restorer = %v, want delegation", err)
	}
	rt.SetRestore(func(context.Context, string) error { return nil })
	if err := wrapped.Start(t.Context(), "alpha"); !problem.HasCode(err, problem.PluginUnavailable) {
		t.Fatalf("Start with a restorer = %v, want PLUGIN_UNAVAILABLE", err)
	}
}

func TestDispatchRestoresUninitializedPlugin(t *testing.T) {
	f := newRuntimeFixture(t)
	f.systemctl.setRunning(os.Getpid()) // systemd restarted it; no instance yet
	rt := newRestoreRuntime(t, f)
	rt.SetRestore(func(ctx context.Context, id string) error {
		h, err := f.rt.Attach(ctx, f.spec())
		if err != nil {
			return err
		}
		return f.rt.Activate(ctx, h)
	})

	_, _ = rt.Dispatcher().Invoke(t.Context(), operations.PluginInvokeRequest{
		PluginID: f.pluginID, InstanceID: DefaultInstanceID, Operation: "noop", OperationID: "op-1",
	})
	for _, rpc := range []string{"Initialize", "Start", "Activate"} {
		if n := f.plugin.callCount(rpc); n != 1 {
			t.Fatalf("%s calls = %d, want 1 (restored before dispatch)", rpc, n)
		}
	}
	if len(rt.Supervisor().Instances()) != 1 {
		t.Fatal("the supervisor did not attach after the restore")
	}
}

func TestDispatchDoesNotStartUnitDuringSaga(t *testing.T) {
	f := newRuntimeFixture(t) // the unit is stopped: MainPID 0
	rt := newRestoreRuntime(t, f)
	release := make(chan struct{})
	rt.SetRestore(func(context.Context, string) error {
		<-release // a saga holds the plugin lock
		return problem.New(problem.PluginUnavailable, "the saga failed")
	})
	done := make(chan error, 1)
	go func() {
		_, err := rt.Dispatcher().Invoke(context.Background(), operations.PluginInvokeRequest{
			PluginID: f.pluginID, InstanceID: DefaultInstanceID, Operation: "noop", OperationID: "op-1",
		})
		done <- err
	}()
	time.Sleep(50 * time.Millisecond)
	if starts, _, _ := f.systemctl.counts(); starts != 0 {
		t.Fatalf("the dispatcher started the unit during a saga (%d starts)", starts)
	}
	close(release)
	if err := <-done; err == nil {
		t.Fatal("Invoke succeeded although the restore failed")
	}
	if starts, _, _ := f.systemctl.counts(); starts != 0 {
		t.Fatalf("the dispatcher started the unit after a failed restore (%d starts)", starts)
	}
}

func TestUpdaterRuntimeAttachDetectsNewGeneration(t *testing.T) {
	f := newRuntimeFixture(t)
	f.systemctl.setRunning(os.Getpid())
	first, err := f.rt.Attach(t.Context(), f.spec())
	if err != nil {
		t.Fatalf("Attach: %v", err)
	}
	// systemd restarted the process: new start time, fresh instance state.
	f.systemctl.mu.Lock()
	f.systemctl.status.StartTime = f.systemctl.status.StartTime.Add(time.Minute)
	f.systemctl.mu.Unlock()
	f.plugin.setLifecycle(platformv1.LifecycleState_LIFECYCLE_STATE_UNSPECIFIED)

	second, err := f.rt.Attach(t.Context(), f.spec())
	if err != nil {
		t.Fatalf("Attach(new generation): %v", err)
	}
	if second == first {
		t.Fatal("Attach returned the handle of the previous generation")
	}
	if n := f.plugin.callCount("Initialize"); n != 2 {
		t.Fatalf("Initialize calls = %d, want 2 (the new process was bootstrapped)", n)
	}
	if first.(*pluginHandle).live() {
		t.Fatal("the stale handle is still live")
	}
}
