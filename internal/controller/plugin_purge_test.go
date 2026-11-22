// SPDX-License-Identifier: AGPL-3.0-only

package controller

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/qwq-panel/qwq/internal/platform/problem"
	"github.com/qwq-panel/qwq/internal/sandbox"
)

// ============================================================================
// 真实文件树与 Unix helper：清理精确范围，失败保留状态，先关 store 再删文件。
// ============================================================================

func TestPluginPurgeUsesConfiguredRoots(t *testing.T) {
	f := newInstallerFixture(t)
	base := filepath.Dir(f.pluginsRoot)
	f.installer.StateDir = filepath.Join(base, "state")
	f.installer.DataRoot = filepath.Join(base, "data")
	for _, root := range []string{f.installer.StateDir, f.installer.DataRoot} {
		writePurgeMarker(t, filepath.Join(root, "alpha", "default", "state.json"))
		writePurgeMarker(t, filepath.Join(root, "beta", "default", "state.json"))
	}
	outside := filepath.Join(base, "outside", "keep.json")
	writePurgeMarker(t, outside)
	if err := os.Symlink(filepath.Dir(outside), filepath.Join(f.installer.DataRoot, "alpha", "foreign")); err != nil {
		t.Fatal(err)
	}
	if err := f.installer.PurgeData(t.Context(), "alpha"); err != nil {
		t.Fatal(err)
	}
	for _, root := range []string{f.installer.StateDir, f.installer.DataRoot} {
		requirePurgePath(t, filepath.Join(root, "alpha"), false)
		requirePurgePath(t, filepath.Join(root, "beta", "default", "state.json"), true)
	}
	requirePurgePath(t, outside, true)
	if err := f.installer.PurgeData(t.Context(), "alpha"); err != nil {
		t.Fatalf("retry: %v", err)
	}
}

func TestPluginPurgeRefusesRunningUnit(t *testing.T) {
	f := newInstallerFixture(t)
	f.installer.StateDir = filepath.Join(filepath.Dir(f.pluginsRoot), "state")
	marker := filepath.Join(f.installer.StateDir, "alpha", "state.json")
	writePurgeMarker(t, marker)
	f.systemctl.setRunning(os.Getpid())
	err := f.installer.PurgeData(t.Context(), "alpha")
	if !problem.HasCode(err, problem.PreconditionFailed) {
		t.Fatalf("purge=%v; want PRECONDITION_FAILED", err)
	}
	requirePurgePath(t, marker, true)
}

func TestPluginPurgeRejectsInvalidStateRoot(t *testing.T) {
	for _, root := range []string{"", "relative", "/", "/tmp/../state"} {
		t.Run(root, func(t *testing.T) {
			i := &PluginInstaller{StateDir: root}
			if err := i.PurgeData(t.Context(), "alpha"); !problem.HasCode(err, problem.Unavailable) {
				t.Fatalf("purge=%v; want UNAVAILABLE", err)
			}
		})
	}
	base := t.TempDir()
	outside := filepath.Join(base, "outside", "alpha", "state.json")
	writePurgeMarker(t, outside)
	state := filepath.Join(base, "linked-state")
	if err := os.Symlink(filepath.Join(base, "outside"), state); err != nil {
		t.Fatal(err)
	}
	i := &PluginInstaller{StateDir: state}
	if err := i.PurgeData(t.Context(), "alpha"); err == nil {
		t.Fatal("purge accepted a state root symlink")
	}
	requirePurgePath(t, outside, true)
	if err := i.PurgeData(t.Context(), "../alpha"); !problem.HasCode(err, problem.ValidationFailed) {
		t.Fatalf("invalid id=%v", err)
	}
}

type purgeReleaseChannels struct {
	*recordingHostChannels
	release func(string)
}

func (c *purgeReleaseChannels) ReleaseHostChannel(id string) {
	c.recordingHostChannels.ReleaseHostChannel(id)
	c.release(id)
}

func TestPluginPurgeClosesHostBeforeDeletingState(t *testing.T) {
	state := t.TempDir()
	marker := filepath.Join(state, "alpha", "state.json")
	socket, requests := startHelperServer(t, func(req sandbox.HelperRequest) sandbox.HelperResponse {
		if _, err := os.Lstat(marker); err != nil {
			return sandbox.HelperResponse{Code: string(problem.Internal), Error: "TEST-ONLY: host state was deleted before the helper call"}
		}
		return sandbox.HelperResponse{OK: true, Remove: &sandbox.RemoveResult{ID: req.ID}}
	})
	i := helperInstaller(t, socket)
	i.StateDir = state
	i.HostChannels = &purgeReleaseChannels{recordingHostChannels: &recordingHostChannels{}, release: func(id string) {
		writePurgeMarker(t, filepath.Join(state, id, "state.json"))
	}}
	if err := i.PurgeData(t.Context(), "alpha"); err != nil {
		t.Fatal(err)
	}
	req := <-requests
	if req.ID != "alpha" || !req.PurgeData || req.KeepUnit || req.Version != "" || len(req.Paths) != 0 {
		t.Fatalf("purge request=%+v", req)
	}
	requirePurgePath(t, marker, false)
}

func TestPluginPurgeHelperRefusalRetainsHostState(t *testing.T) {
	socket, _ := startHelperServer(t, func(sandbox.HelperRequest) sandbox.HelperResponse {
		return sandbox.HelperResponse{Code: string(problem.PreconditionFailed), Error: "TEST-ONLY: a process is still running"}
	})
	i := helperInstaller(t, socket)
	i.StateDir = t.TempDir()
	marker := filepath.Join(i.StateDir, "alpha", "state.json")
	writePurgeMarker(t, marker)
	if err := i.PurgeData(t.Context(), "alpha"); !problem.HasCode(err, problem.PreconditionFailed) {
		t.Fatalf("purge=%v; want PRECONDITION_FAILED", err)
	}
	requirePurgePath(t, marker, true)
}

func TestPluginPurgeCancellationRetainsData(t *testing.T) {
	state := t.TempDir()
	marker := filepath.Join(state, "alpha", "state.json")
	writePurgeMarker(t, marker)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	i := &PluginInstaller{StateDir: state}
	if err := i.PurgeData(ctx, "alpha"); !problem.HasCode(err, problem.Unavailable) {
		t.Fatalf("cancelled purge=%v", err)
	}
	requirePurgePath(t, marker, true)
}

func writePurgeMarker(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(`{"test_only":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
}

func requirePurgePath(t *testing.T, path string, present bool) {
	t.Helper()
	_, err := os.Lstat(path)
	if present && err != nil {
		t.Fatalf("retained path %s: %v", path, err)
	}
	if !present && !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("purged path %s: %v", path, err)
	}
}
