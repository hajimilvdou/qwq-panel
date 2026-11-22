//go:build e2e && linux

// SPDX-License-Identifier: AGPL-3.0-only

package e2e

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/qwq-panel/qwq/internal/controller"
	"github.com/qwq-panel/qwq/internal/pluginhost/updater"
	"github.com/qwq-panel/qwq/internal/sandbox"
	"github.com/qwq-panel/qwq/internal/storage"
)

// TestPluginStartStop100 is the 1C1G endurance baseline: one real plugin is
// installed, then started/stopped (or SIGKILLed) 100 times. It checks that the
// host process does not leak descriptors or goroutines, that the unit never
// stays active after Stop, and that the plugin process RSS stays bounded.
//
// QWQ_E2E_CYCLES overrides the count (default 100); QWQ_E2E_KILL_EVERY overrides
// the SIGKILL interval (default 10). The host is installed like
// TestPluginEndToEnd; the in-process updater takes the controller's place, so
// listenerHostChannels stands in for its resident host channel.
func TestPluginStartStop100(t *testing.T) {
	requireEnv(t, "QWQ_E2E_PKG_V1")
	cycles := envInt(t, "QWQ_E2E_CYCLES", 100)
	killEvery := envInt(t, "QWQ_E2E_KILL_EVERY", 10)
	if cycles < 1 || killEvery < 1 {
		t.Fatalf("cycles and kill interval must be positive")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	logger := newTestLogger()
	prepareHost(t)
	// The test process drives this plugin in-process; the installed controller
	// must not adopt it.
	run(t, "systemctl", "stop", controllerU)

	dbPath := filepath.Join(t.TempDir(), "qwq.db")
	db, err := storage.Open(ctx, storage.Options{Path: dbPath, Logger: logger})
	if err != nil {
		t.Fatalf("open the database: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	hosts := &listenerHostChannels{t: t}
	t.Cleanup(hosts.closeAll)
	systemctl := sandbox.NewExecSystemctl(sandbox.ExecRunner{})
	installer := &controller.PluginInstaller{
		PluginsRoot:  pluginsRoot,
		StagingRoot:  stagingRoot,
		TrustDir:     trustDir,
		Systemctl:    systemctl,
		Helper:       sandbox.NewHelperClient(helperSocket),
		HostChannels: hosts,
		Logger:       logger,
	}
	rt := &controller.UpdaterRuntime{
		Systemctl:    systemctl,
		PluginsRoot:  pluginsRoot,
		RunDir:       runtimeBase,
		HostChannels: hosts,
		Logger:       logger,
		NodeID:       "e2e-cycles",
	}
	u, err := updater.New(updater.Options{
		DB:          db,
		Runtime:     rt,
		Installer:   installer,
		Memory:      &controller.HostMemory{},
		Logger:      logger,
		StopGrace:   10 * time.Second,
		Timeout:     2 * time.Minute,
		RestartOnly: true,
	})
	if err != nil {
		t.Fatalf("updater: %v", err)
	}
	if _, err := u.Install(ctx, updater.InstallRequest{
		PluginID:             pluginID,
		PackagePath:          os.Getenv("QWQ_E2E_PKG_V1"),
		AcceptedCapabilities: pluginCaps,
	}); err != nil {
		t.Fatalf("install: %v", err)
	}
	active, ok := u.Active(pluginID)
	if !ok {
		t.Fatal("the installed version is not active")
	}
	spec := updater.InstanceSpec{
		PluginID: pluginID,
		Version:  active.Version,
		Digest:   active.Digest,
		Manifest: active.Manifest,
	}

	// Warm up once so the gRPC/registry caches are populated before the
	// baseline; the loop itself must be flat.
	// Install leaves the instance running: attach to it for the warm-up
	// instead of asking Start for a second one.
	warm, err := rt.Attach(ctx, spec)
	if err != nil {
		t.Fatalf("warm-up attach: %v", err)
	}
	if err := rt.Ready(ctx, warm); err != nil {
		t.Fatalf("warm-up ready: %v", err)
	}
	if err := rt.Stop(ctx, warm, 10*time.Second); err != nil {
		t.Fatalf("warm-up stop: %v", err)
	}
	if err := rt.Release(ctx, warm); err != nil {
		t.Fatalf("warm-up release: %v", err)
	}
	waitUnitStopped(t)

	baseFD := openFDs(t)
	baseGoroutines := runtime.NumGoroutine()
	var maxRSS int
	started := time.Now()
	for i := 1; i <= cycles; i++ {
		h, err := rt.Start(ctx, spec)
		if err != nil {
			t.Fatalf("cycle %d: start: %v", i, err)
		}
		if err := rt.Ready(ctx, h); err != nil {
			t.Fatalf("cycle %d: ready: %v", i, err)
		}
		if rss := mainPIDRSS(t); rss > maxRSS {
			maxRSS = rss
		}
		if i%killEvery == 0 {
			oldPID := showMainPID(t)
			if err := exec.Command("systemctl", "kill", "--kill-whom=main", "-s", "SIGKILL", pluginService).Run(); err != nil {
				t.Fatalf("cycle %d: SIGKILL: %v", i, err)
			}
			// Restart=on-failure brings the unit back; give systemd a moment to
			// either restart it or settle, then stop both units so the next
			// cycle starts from a clean state instead of racing the restart.
			killDeadline := time.Now().Add(10 * time.Second)
			for time.Now().Before(killDeadline) {
				pid := showMainPID(t)
				if pid == 0 || pid != oldPID {
					break
				}
				time.Sleep(100 * time.Millisecond)
			}
			_ = exec.Command("systemctl", "stop", pluginService).Run()
			_ = exec.Command("systemctl", "stop", pluginSocketU).Run()
			waitUnitStopped(t)
			if err := rt.Release(ctx, h); err != nil {
				t.Fatalf("cycle %d: release after kill: %v", i, err)
			}
		} else {
			if err := rt.Stop(ctx, h, 10*time.Second); err != nil {
				t.Fatalf("cycle %d: stop: %v", i, err)
			}
			if err := rt.Release(ctx, h); err != nil {
				t.Fatalf("cycle %d: release: %v", i, err)
			}
		}
		waitUnitStopped(t)
		if i%10 == 0 {
			t.Logf("cycle %d/%d: fd=%d goroutines=%d max_rss_kb=%d elapsed=%s",
				i, cycles, openFDs(t), runtime.NumGoroutine(), maxRSS, time.Since(started).Round(time.Second))
		}
	}
	// Let the final helper/socket activation settle before comparing.
	time.Sleep(500 * time.Millisecond)
	endFD := openFDs(t)
	endGoroutines := runtime.NumGoroutine()
	if delta := endFD - baseFD; delta > 8 {
		t.Errorf("file descriptors grew by %d (%d -> %d)", delta, baseFD, endFD)
	}
	if delta := endGoroutines - baseGoroutines; delta > 8 {
		t.Errorf("goroutines grew by %d (%d -> %d)", delta, baseGoroutines, endGoroutines)
	}
	if maxRSS > 64*1024 {
		t.Errorf("plugin max RSS = %d KiB, want <= 64 MiB", maxRSS)
	}
	t.Logf("endurance PASS: %d cycles, fd %d->%d, goroutines %d->%d, max plugin RSS %d KiB, %s",
		cycles, baseFD, endFD, baseGoroutines, endGoroutines, maxRSS, time.Since(started).Round(time.Second))

	if err := installer.RemoveUnit(ctx, pluginID, active.Version); err != nil {
		t.Fatalf("RemoveUnit: %v", err)
	}
}

func envInt(t *testing.T, name string, def int) int {
	t.Helper()
	raw := os.Getenv(name)
	if raw == "" {
		return def
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < 1 {
		t.Fatalf("%s=%q is not a positive integer", name, raw)
	}
	return n
}

func newTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
}

// waitUnitStopped waits until systemd reports no MainPID and no active state.
func showMainPID(t *testing.T) int {
	t.Helper()
	st, err := sandbox.NewExecSystemctl(sandbox.ExecRunner{}).Show(context.Background(), pluginService)
	if err != nil {
		return 0
	}
	return st.MainPID
}

func waitUnitStopped(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		st, err := sandbox.NewExecSystemctl(sandbox.ExecRunner{}).Show(context.Background(), pluginService)
		if err == nil && st.MainPID == 0 && st.ActiveState != "active" && st.ActiveState != "activating" {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("unit %s did not stop in time", pluginService)
}

// openFDs counts the descriptors of the test process, which owns the gRPC
// clients, helper client and host listener.
func openFDs(t *testing.T) int {
	t.Helper()
	ents, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatalf("read fd table: %v", err)
	}
	return len(ents)
}

// mainPIDRSS reads the plugin's VmRSS. The unit is restarted by systemd after a
// SIGKILL, so this is called only while the instance is known to be up.
func mainPIDRSS(t *testing.T) int {
	t.Helper()
	st, err := sandbox.NewExecSystemctl(sandbox.ExecRunner{}).Show(context.Background(), pluginService)
	if err != nil || st.MainPID <= 0 {
		return 0
	}
	raw, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", st.MainPID))
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(raw), "\n") {
		if strings.HasPrefix(line, "VmRSS:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				if kb, err := strconv.Atoi(fields[1]); err == nil {
					return kb
				}
			}
		}
	}
	return 0
}

// listenerHostChannels stands in for the controller's resident host channel
// (controller.HostChannels): the lifecycle under test uses no host RPC, so a
// listener in the helper-created directory is enough.
type listenerHostChannels struct {
	t   *testing.T
	mu  sync.Mutex
	lns map[string]net.Listener
}

func (h *listenerHostChannels) EnsureHostChannel(id string) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.lns == nil {
		h.lns = map[string]net.Listener{}
	}
	if _, ok := h.lns[id]; ok {
		return nil
	}
	dir := filepath.Join(runtimeBase, "host", id)
	fi, err := os.Stat(dir)
	if err != nil {
		return err
	}
	sock := filepath.Join(dir, "host.sock")
	_ = os.Remove(sock)
	ln, err := net.Listen("unix", sock)
	if err != nil {
		return err
	}
	// Like the controller: 0660 and the plugin's private group (the setgid
	// directory already gives it the group; chown makes it explicit for root).
	if err := os.Chmod(sock, 0o660); err != nil {
		ln.Close()
		return err
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		if err := os.Chown(sock, -1, int(st.Gid)); err != nil {
			ln.Close()
			return err
		}
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
		}
	}()
	h.lns[id] = ln
	return nil
}

func (h *listenerHostChannels) ReleaseHostChannel(id string) {
	h.mu.Lock()
	ln, ok := h.lns[id]
	delete(h.lns, id)
	h.mu.Unlock()
	if ok {
		_ = ln.Close()
	}
}

func (h *listenerHostChannels) closeAll() {
	h.mu.Lock()
	defer h.mu.Unlock()
	for id, ln := range h.lns {
		_ = ln.Close()
		delete(h.lns, id)
	}
}
