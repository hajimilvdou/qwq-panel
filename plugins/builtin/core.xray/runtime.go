// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/qwq-panel/qwq/plugins/builtin/core.xray/internal/anytls"
	"github.com/qwq-panel/qwq/plugins/builtin/core.xray/internal/apply"
	"github.com/qwq-panel/qwq/plugins/builtin/core.xray/internal/coreproc"
	"github.com/qwq-panel/qwq/plugins/builtin/core.xray/internal/state"
	"github.com/qwq-panel/qwq/plugins/builtin/core.xray/internal/xraybin"
	"github.com/qwq-panel/qwq/sdk/pluginsdk"
)

// driverRuntime 绑定同一实例的私有存储、进程、事务与状态源。
type driverRuntime struct {
	store       *state.Store
	process     apply.Process
	obfs        apply.ObfsManager
	anytls      apply.AnyTLSManager
	controller  *apply.Engine
	coreVersion string
	trusted     bool
}

func locateOptionalObfsBinary() *coreproc.ObfsSupervisor {
	exe, err := os.Executable()
	if err != nil {
		return nil
	}
	candidate := filepath.Join(filepath.Dir(exe), "obfs-server")
	if st, err := os.Stat(candidate); err == nil && !st.IsDir() {
		return coreproc.NewObfsSupervisor(candidate, "")
	}
	return nil
}

func newDriverRuntime(i *instance) (*driverRuntime, error) {
	store := state.NewStore(i.DataDir())
	binary, err := xraybin.Locate()
	driver := &driverRuntime{store: store, trusted: err == nil}
	if driver.trusted {
		driver.coreVersion = state.CoreVersion
	}
	if sup := locateOptionalObfsBinary(); sup != nil {
		driver.obfs = sup
	}
	socket := filepath.Join(i.DataDir(), "runtime", "api.sock")
	process, err := coreproc.New(coreproc.Options{
		Socket: socket,
		Command: func(ctx context.Context, config string) (*exec.Cmd, error) {
			if !driver.trusted {
				return nil, xraybin.ErrBinary
			}
			return binary.Command(ctx, config, false)
		},
		Track: i.Go,
		OnExit: func(err error) {
			if i.fail != nil {
				i.fail(err)
			}
		},
	})
	if err != nil {
		return nil, pluginsdk.Errorf("DATA_DIR_UNAVAILABLE", "私有运行目录不可用")
	}
	driver.process = process
	driver.anytls = anytls.NewSupervisor()
	driver.controller, err = apply.New(apply.Options{Store: store, Process: process, Binary: binary, Obfs: driver.obfs, AnyTLS: driver.anytls, Socket: socket, DataDir: i.DataDir()})
	if err != nil {
		return nil, mapApplyError(err)
	}
	return driver, nil
}

func (d *driverRuntime) activate(ctx context.Context) error {
	current, err := d.store.Committed(ctx)
	if err != nil {
		return err
	}
	if current != nil && current.Current.Enabled && !d.trusted {
		return pluginsdk.Errorf("CORE_BINARY_MISMATCH", "包内核心二进制未通过核验")
	}
	return d.controller.Activate(ctx)
}

func (d *driverRuntime) Snapshot(ctx context.Context) (runtimeSnapshot, error) {
	for attempt := 0; attempt < 3; attempt++ {
		before := d.controller.Observe()
		metadata, err := d.store.Committed(ctx)
		if err != nil {
			return runtimeSnapshot{}, err
		}
		process := d.process.Snapshot(ctx)
		after := d.controller.Observe()
		if before.Serial != after.Serial {
			if ctx.Err() != nil {
				return runtimeSnapshot{}, ctx.Err()
			}
			continue
		}
		result := runtimeSnapshot{metadata: metadata, coreVersion: d.coreVersion, processState: process.State, apiState: process.APIState, lastError: after.Failure, applying: after.Busy}
		if metadata != nil {
			if !after.Active && process.State == "STOPPED" {
				metadata.State = "STOPPED"
			}
			if process.State == "RUNNING" && process.Digest != metadata.Current.Digest {
				result.applying = true
				if !after.Busy {
					metadata.State, metadata.LastError = "FAILED", "RECOVERY_FAILED"
					result.applying = false
				}
			}
			if process.State == "RUNNING" && process.Digest == metadata.Current.Digest && process.Epoch != "" {
				metadata.ResetEpoch = process.Epoch
			}
			if result.lastError == "RECOVERY_FAILED" {
				metadata.State, metadata.LastError = "FAILED", "RECOVERY_FAILED"
			}
		}
		if d.obfs != nil {
			if healthy, _ := d.obfs.Status(); !healthy && result.lastError == "" {
				result.lastError = "OBFS_DEGRADED"
			}
		}
		if d.anytls != nil {
			if healthy, _ := d.anytls.Status(); !healthy && result.lastError == "" {
				result.lastError = "ANYTLS_DEGRADED"
			}
		}
		return result, nil
	}
	return runtimeSnapshot{}, pluginsdk.Errorf("CORE_STATE_UNAVAILABLE", "状态正在切换，请重新读取")
}
