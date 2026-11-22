// SPDX-License-Identifier: AGPL-3.0-only

package controller

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/qwq-panel/qwq/internal/pluginhost/supervisor"
)

// ======================== 官方模板 slice 的实际文件布局 ========================

func TestHostMemoryReadsTemplateSlice(t *testing.T) {
	root := t.TempDir()
	unit := filepath.Join(root, "system.slice", `system-qwq\x2dplugin.slice`, supervisor.UnitName(updaterTestID))
	if err := os.MkdirAll(unit, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(unit, "memory.current"), []byte("67108864\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	memory := HostMemory{CgroupRoot: root}
	current, err := memory.Current(updaterTestID)
	if err != nil || current != 64<<20 {
		t.Fatalf("template slice memory: current=%d error=%v", current, err)
	}
}
