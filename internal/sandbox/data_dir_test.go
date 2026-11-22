// SPDX-License-Identifier: AGPL-3.0-only

package sandbox

import "testing"

// ======================== 固定实例与路径边界 ========================
func TestRuntimePluginDataDir(t *testing.T) {
	for _, item := range []struct {
		name, path, plugin, want string
	}{
		{"no_directory", "", "", ""},
		{"logical", DefaultPluginDataRoot + "/core.xray/default", "core.xray", DefaultPrivatePluginDataRoot + "/core.xray/default"},
		{"private", DefaultPrivatePluginDataRoot + "/core.xray/default", "core.xray", DefaultPrivatePluginDataRoot + "/core.xray/default"},
		{"explicit_other_root", "/srv/qwq-data/core.xray/default", "core.xray", "/srv/qwq-data/core.xray/default"},
	} {
		t.Run(item.name, func(t *testing.T) {
			got, err := RuntimePluginDataDir(item.path, item.plugin)
			if err != nil || got != item.want {
				t.Fatalf("runtime data dir = %q, %v; want %q", got, err, item.want)
			}
		})
	}
}

func TestRuntimePluginDataDirRejectsForeignOrUnsafePaths(t *testing.T) {
	for _, item := range []struct{ name, path, plugin string }{
		{"relative", "data/default", "core.xray"},
		{"unclean", DefaultPluginDataRoot + "/core.xray/../default", "core.xray"},
		{"root", "/", "core.xray"},
		{"missing_identity", DefaultPluginDataRoot + "/core.xray/default", ""},
		{"invalid_identity", DefaultPluginDataRoot + "/core.xray/default", "../core.xray"},
		{"other_logical_owner", DefaultPluginDataRoot + "/other.plugin/default", "core.xray"},
		{"other_private_owner", DefaultPrivatePluginDataRoot + "/other.plugin/default", "core.xray"},
		{"logical_root", DefaultPluginDataRoot, "core.xray"},
		{"private_root", DefaultPrivatePluginDataRoot, "core.xray"},
		{"other_instance", DefaultPluginDataRoot + "/core.xray/other", "core.xray"},
		{"versioned_path", DefaultPrivatePluginDataRoot + "/core.xray/0.1.1/default", "core.xray"},
	} {
		t.Run(item.name, func(t *testing.T) {
			if _, err := RuntimePluginDataDir(item.path, item.plugin); err == nil {
				t.Fatal("unsafe data directory was accepted")
			}
		})
	}
}
