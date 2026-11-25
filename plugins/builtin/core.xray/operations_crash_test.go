// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/qwq-panel/qwq/internal/xraycore/coreproc"
	"github.com/qwq-panel/qwq/internal/xraycore/state"
	"github.com/qwq-panel/qwq/plugins/builtin/core.xray/internal/apply"
)

// runtimeImage 保存单阶段的真实私有磁盘事实，进程死亡由显式 fake 模拟。
func runtimeImage(t *testing.T, directory string) map[string][]byte {
	t.Helper()
	image := map[string][]byte{}
	root := filepath.Join(directory, "runtime")
	if err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		if !entry.Type().IsRegular() {
			t.Fatal("crash image includes an unexpected file type")
		}
		name, err := filepath.Rel(directory, path)
		if err != nil || strings.HasPrefix(name, "..") || filepath.IsAbs(name) {
			t.Fatal("crash image escaped its private root")
		}
		data, err := os.ReadFile(path)
		if err == nil {
			image[name] = data
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return image
}

func restoreRuntimeImage(t *testing.T, directory string, image map[string][]byte) {
	t.Helper()
	if err := os.RemoveAll(filepath.Join(directory, "runtime")); err != nil {
		t.Fatal(err)
	}
	for name, data := range image {
		if filepath.IsAbs(name) || strings.HasPrefix(name, "..") {
			t.Fatal("invalid image path")
		}
		path := filepath.Join(directory, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func TestFakeCrashAtEveryApplyStepRecoversOnlyCommittedSnapshot(t *testing.T) {
	for _, step := range apply.Steps() {
		t.Run(string(step), func(t *testing.T) {
			f := newApplyFixture(t)
			if _, err := f.engine.Execute(t.Context(), f.request()); err != nil {
				t.Fatal(err)
			}
			f.changeDesired()
			var image map[string][]byte
			f.captureStep, f.capture = step, func() { image = runtimeImage(t, f.directory) }
			if _, err := f.engine.Execute(t.Context(), f.request()); err == nil || image == nil {
				t.Fatal("crash stage was not captured")
			}
			if err := f.engine.Deactivate(t.Context()); err != nil {
				t.Fatal(err)
			}
			restoreRuntimeImage(t, f.directory, image)
			var committed state.Metadata
			if json.Unmarshal(image[filepath.Join("runtime", "state.json")], &committed) != nil {
				t.Fatal("captured state is missing")
			}
			process := &fakeApplyProcess{starts: 100, snapshot: coreproc.Snapshot{State: "STOPPED", APIState: "UNAVAILABLE"}}
			engine, err := apply.New(apply.Options{Store: state.NewStore(f.directory), Process: process, Binary: f.binary, Socket: filepath.Join(f.directory, "runtime", "api.sock")})
			if err != nil {
				t.Fatal(err)
			}
			reveals := len(f.host.revealed)
			if err := engine.Activate(t.Context()); err != nil {
				t.Fatal(err)
			}
			defer engine.Deactivate(context.Background())
			metadata, err := state.Load(t.Context(), f.directory)
			if err != nil || metadata.Current.Revision != committed.Current.Revision || metadata.Current.Digest != committed.Current.Digest || process.Snapshot(t.Context()).Digest != committed.Current.Digest {
				t.Fatal("recovery selected an uncommitted candidate")
			}
			if len(f.host.revealed) != reveals || metadata.ResetEpoch == committed.ResetEpoch {
				t.Fatal("restart revealed material or reused the old process epoch")
			}
		})
	}
}

func TestFakeLifetimeCancelDoesNotRestartOldCoreDuringShutdown(t *testing.T) {
	f := newApplyFixture(t)
	if _, err := f.engine.Execute(t.Context(), f.request()); err != nil {
		t.Fatal(err)
	}
	f.changeDesired()
	f.cancelLifetimeStep = apply.CommitHost
	if _, err := f.engine.Execute(t.Context(), f.request()); err == nil || apply.RolledBack(err) {
		t.Fatal("shutdown cancellation was reported as a healthy running rollback")
	}
	metadata, err := f.store.Committed(t.Context())
	if err != nil || metadata.Current.Revision != "1" || f.process.Snapshot(t.Context()).State != "STOPPED" {
		t.Fatal("shutdown left a new generation or restarted old core")
	}
	if err := f.engine.Activate(t.Context()); err != nil {
		t.Fatal(err)
	}
	if f.process.Snapshot(t.Context()).State != "RUNNING" {
		t.Fatal("next activation could not recover the committed old snapshot")
	}
}

func TestFakeDisabledDesiredIsPreflightedButDoesNotStart(t *testing.T) {
	f := newApplyFixture(t)
	f.host.config = []byte(strings.Replace(string(f.host.config), `"enabled":true`, `"enabled":false`, 1))
	result, err := f.engine.Execute(t.Context(), f.request())
	if err != nil || result.Enabled || result.Started || result.ProcessState != "STOPPED" || f.binary.calls != 1 || len(f.host.revealed) == 0 {
		t.Fatal("disabled configuration skipped full validation or started a core")
	}
}

func TestFakeActivationCleansAbandonedWorkWithoutRevealing(t *testing.T) {
	f := newApplyFixture(t)
	if _, err := f.engine.Execute(t.Context(), f.request()); err != nil {
		t.Fatal(err)
	}
	if err := f.engine.Deactivate(t.Context()); err != nil {
		t.Fatal(err)
	}
	work, err := f.store.Stage(t.Context(), "op-crashed", 7, []byte(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	reveals := len(f.host.revealed)
	if err := f.engine.Activate(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(work.Path); !os.IsNotExist(err) || len(f.host.revealed) != reveals {
		t.Fatal("activation retained interrupted work or revealed material")
	}
}
