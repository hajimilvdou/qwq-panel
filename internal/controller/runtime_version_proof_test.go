// SPDX-License-Identifier: AGPL-3.0-only

package controller

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/qwq-panel/qwq/internal/platform/problem"
	"github.com/qwq-panel/qwq/internal/pluginhost/install"
	platformv1 "github.com/qwq-panel/qwq/sdk/gen/qwq/platform/v1"
)

// ======================== 无版本证明不能接管或初始化未知进程 ========================

func TestUpdaterRuntimeRequiresVersionProof(t *testing.T) {
	for _, mode := range []string{"attach", "start"} {
		for _, missing := range []string{"loaded-path", "manifest-entrypoint", "conflicting-proof"} {
			t.Run(mode+"/"+missing, func(t *testing.T) {
				f := newRuntimeFixture(t)
				f.plugin.setDescriptor(&platformv1.PluginDescriptor{PluginId: f.pluginID})
				if missing == "conflicting-proof" {
					f.plugin.setDescriptor(&platformv1.PluginDescriptor{PluginId: f.pluginID, PluginVersion: f.version})
				}
				spec := f.spec()
				spec.Manifest.Entrypoint = "bin/plugin"
				f.systemctl.mu.Lock()
				f.systemctl.status.ExecStart = filepath.Join(install.VersionDir(f.pluginsDir, f.pluginID, f.version), "bin/plugin")
				if missing == "loaded-path" {
					f.systemctl.status.ExecStart = ""
				} else if missing == "manifest-entrypoint" {
					spec.Manifest.Entrypoint = ""
				} else {
					f.systemctl.status.ExecStart = filepath.Join(install.VersionDir(f.pluginsDir, f.pluginID, "0.9.0"), "bin/plugin")
				}
				f.systemctl.mu.Unlock()
				var err error
				if mode == "attach" {
					f.systemctl.setRunning(os.Getpid())
					_, err = f.rt.Attach(t.Context(), spec)
				} else {
					_, err = f.rt.Start(t.Context(), spec)
				}
				if !problem.HasCode(err, problem.PluginUnavailable) {
					t.Errorf("an unproven runtime version was accepted: %v", err)
				}
				starts, stops, kills := f.systemctl.counts()
				if mode == "attach" && starts+stops+kills != 0 {
					t.Error("an unproven attached process was started, stopped or killed")
				}
				if mode == "start" && (starts != 1 || stops != 1) {
					t.Error("an unproven newly started candidate was not cleaned up")
				}
				if f.plugin.callCount("Initialize") != 0 || f.rt.lookup(f.pluginID, f.version) != nil {
					t.Error("an unproven process was initialized or registered as the requested version")
				}
			})
		}
	}
}
