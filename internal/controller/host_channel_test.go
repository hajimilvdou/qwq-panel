// SPDX-License-Identifier: AGPL-3.0-only

package controller

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/qwq-panel/qwq/internal/platform/clock"
	"github.com/qwq-panel/qwq/internal/pluginhost/supervisor"
)

// hookUnits is a supervisor.UnitManager that runs onStart when Start is called.
type hookUnits struct {
	fakeSupervisorUnits
	onStart func()
}

func (h *hookUnits) Start(ctx context.Context, id string) error {
	if h.onStart != nil {
		h.onStart()
	}
	return h.fakeSupervisorUnits.Start(ctx, id)
}

// mkHostDir creates the per-plugin socket directory the privileged helper
// creates in production; hostsvc only verifies it.
func mkHostDir(t *testing.T, runDir, id string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(supervisor.HostSocketPath(runDir, id)), 0o750); err != nil {
		t.Fatal(err)
	}
}

// newHostRuntime builds a runtime that serves the production host channel
// below a short run directory (unix socket paths are length limited).
func newHostRuntime(t *testing.T, units supervisor.UnitManager) *PluginRuntime {
	t.Helper()
	dir := shortUpdaterTempDir(t)
	mkHostDir(t, filepath.Join(dir, "run"), "alpha")
	rt, err := NewPluginRuntime(PluginRuntimeOptions{
		Units:     units,
		PluginDir: func(string) (string, error) { return filepath.Join(dir, "plugins", "alpha", "1.0.0"), nil },
		RunDir:    filepath.Join(dir, "run"),
		StateDir:  filepath.Join(dir, "state"),
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

func socketExists(rt *PluginRuntime, id string) bool {
	_, err := os.Stat(supervisor.HostSocketPath(rt.opts.RunDir, id))
	return err == nil
}

func TestAttachServesHostChannelBeforeUnitStart(t *testing.T) {
	units := &hookUnits{}
	rt := newHostRuntime(t, units)
	var (
		once   sync.Once
		served bool
	)
	units.onStart = func() { once.Do(func() { served = socketExists(rt, "alpha") }) }
	_, _ = rt.attach(t.Context(), "alpha") // the fake never runs a process
	if !served {
		t.Fatal("the unit was started before the host socket existed")
	}
}

func TestHostChannelSurvivesGenerationChange(t *testing.T) {
	rt := newHostRuntime(t, &fakeSupervisorUnits{})
	if err := rt.EnsureHostChannel("alpha"); err != nil {
		t.Fatalf("EnsureHostChannel: %v", err)
	}
	// The supervisor's per-generation stop must not tear the channel down.
	stop, err := residentHost{rt: rt}.Serve(t.Context(), "alpha")
	if err != nil {
		t.Fatalf("Serve: %v", err)
	}
	stop()
	if !socketExists(rt, "alpha") {
		t.Fatal("the host socket disappeared after a generation drop")
	}
	if err := rt.EnsureHostChannel("alpha"); err != nil {
		t.Fatalf("EnsureHostChannel(again): %v", err)
	}
	rt.ReleaseHostChannel("alpha")
	if socketExists(rt, "alpha") {
		t.Fatal("ReleaseHostChannel left the socket behind")
	}
	rt.ReleaseHostChannel("alpha") // idempotent
}

func TestPluginRuntimeStartServesInstalledPlugins(t *testing.T) {
	dir := shortUpdaterTempDir(t)
	plugins := filepath.Join(dir, "plugins")
	mkHostDir(t, filepath.Join(dir, "run"), "alpha")
	if err := os.MkdirAll(filepath.Join(plugins, "alpha", "1.0.0"), 0o755); err != nil {
		t.Fatal(err)
	}
	rt, err := NewPluginRuntime(PluginRuntimeOptions{
		Units:       &fakeSupervisorUnits{},
		PluginDir:   func(string) (string, error) { return "", nil },
		PluginsRoot: plugins,
		RunDir:      filepath.Join(dir, "run"),
		StateDir:    filepath.Join(dir, "state"),
		Logger:      slog.New(slog.DiscardHandler),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(rt.Stop)
	if err := rt.Start(t.Context(), HostDeps{}); err != nil {
		t.Fatal(err)
	}
	if !socketExists(rt, "alpha") {
		t.Fatal("Start did not serve the host channel of an installed plugin")
	}
	rt.Stop()
	if socketExists(rt, "alpha") {
		t.Fatal("Stop left the host socket behind")
	}
}

func TestPeerVerifierPrefersSystemdMainPID(t *testing.T) {
	const fresh = 4343
	proc := t.TempDir()
	writeCgroup(t, proc, fresh, "0::/system.slice/qwq-plugin@alpha.service\n")
	v := &PeerVerifier{
		PluginID: "alpha",
		Unit:     supervisor.UnitName("alpha"),
		// The supervisor still caches the process the updater just replaced.
		Instances: func(string) (InstanceInfo, bool) { return InstanceInfo{MainPID: 4242}, true },
		MainPID:   func(string) (int, error) { return fresh, nil },
		ProcRoot:  proc,
	}
	if err := v.Verify(fresh, 1001); err != nil {
		t.Fatalf("Verify(new main pid) = %v", err)
	}
	if err := v.Verify(9999, 1001); err == nil {
		t.Fatal("Verify accepted a pid matching neither source")
	}
}

// recordingHostChannels records the unit start count seen at each call.
type recordingHostChannels struct {
	systemctl *sagaSystemctl
	mu        sync.Mutex
	ensured   []int
	released  []string
}

func (r *recordingHostChannels) EnsureHostChannel(string) error {
	starts, _, _ := r.systemctl.counts()
	r.mu.Lock()
	defer r.mu.Unlock()
	r.ensured = append(r.ensured, starts)
	return nil
}

func (r *recordingHostChannels) ReleaseHostChannel(id string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.released = append(r.released, id)
}

func TestUpdaterRuntimeStartEnsuresHostChannelFirst(t *testing.T) {
	f := newRuntimeFixture(t)
	hosts := &recordingHostChannels{systemctl: f.systemctl}
	f.rt.HostChannels = hosts
	if _, err := f.rt.Start(t.Context(), f.spec()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if len(hosts.ensured) != 1 || hosts.ensured[0] != 0 {
		t.Fatalf("host channel ensured at start counts %v, want [0]", hosts.ensured)
	}

	g := newRuntimeFixture(t)
	g.systemctl.setRunning(os.Getpid())
	ghosts := &recordingHostChannels{systemctl: g.systemctl}
	g.rt.HostChannels = ghosts
	if _, err := g.rt.Attach(t.Context(), g.spec()); err != nil {
		t.Fatalf("Attach: %v", err)
	}
	if len(ghosts.ensured) != 1 {
		t.Fatalf("Attach ensured the host channel %d times, want 1", len(ghosts.ensured))
	}
}
