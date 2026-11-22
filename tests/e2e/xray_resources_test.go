// SPDX-License-Identifier: AGPL-3.0-only

//go:build e2e && linux

package e2e

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/qwq-panel/qwq/internal/sandbox"
)

// markXrayResourcePhase 为独立只读采样器发布有界阶段与客户端 PID，不写业务状态。
func markXrayResourcePhase(t *testing.T, phase string, clients ...int) {
	t.Helper()
	path := os.Getenv("QWQ_E2E_RESOURCE_MARKER")
	if path == "" {
		return
	}
	if !validXrayResourceMarkerPath(path) || len(clients) > 8 {
		t.Fatal("资源阶段标记必须位于本轮专用测试目录")
	}
	for _, pid := range clients {
		if pid <= 0 {
			t.Fatal("资源阶段客户端 PID 无效")
		}
	}
	if clients == nil {
		clients = []int{}
	}
	allowed := map[string]bool{"startup": true, "apply": true, "idle": true, "traffic": true, "update": true, "update_recovery": true, "rollback": true, "uninstall": true}
	if !allowed[phase] {
		t.Fatal("未知资源采样阶段")
	}
	root, err := openXrayResourceMarker(path)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	data, err := json.Marshal(map[string]any{"phase": phase, "client_pids": clients})
	if err != nil {
		t.Fatal(err)
	}
	if err := sandbox.WriteFileAtomicIn(root, filepath.Base(path), data, 0o600); err != nil {
		t.Fatal("资源阶段标记无法原子提交")
	}
}

// ======================== 固定工作区与本轮私有目录 ========================

func validXrayResourceMarkerPath(marker string) bool {
	if !filepath.IsAbs(marker) || filepath.Clean(marker) != marker || filepath.Base(marker) != "resources.phase.json" {
		return false
	}
	round := filepath.Dir(marker)
	output := filepath.Dir(round)
	if !strings.HasPrefix(filepath.Base(round), "TestXray") || filepath.Base(output) != "out" {
		return false
	}
	workspace := filepath.Base(filepath.Dir(output))
	if workspace == "core-xray-e2e" {
		return true
	}
	const prefix = "core-xray-x11-"
	if !strings.HasPrefix(workspace, prefix) {
		return false
	}
	revision := strings.TrimPrefix(workspace, prefix)
	if len(revision) < 7 || len(revision) > 40 {
		return false
	}
	for _, value := range revision {
		if !(value >= '0' && value <= '9') && !(value >= 'a' && value <= 'f') {
			return false
		}
	}
	return true
}

func openXrayResourceMarker(marker string) (*os.Root, error) {
	if !validXrayResourceMarkerPath(marker) {
		return nil, errors.New("资源标记不属于固定工作区的独立轮次")
	}
	directory := filepath.Dir(marker)
	canonical, err := filepath.EvalSymlinks(directory)
	if err != nil || canonical != directory {
		return nil, errors.New("资源标记目录不存在或包含符号链接")
	}
	info, err := os.Lstat(directory)
	if err != nil {
		return nil, errors.New("资源标记私有目录不可用")
	}
	owner, ok := sandbox.FileOwner(info)
	if !ok || owner != os.Geteuid() || !info.IsDir() || info.Mode().Perm() != 0o700 {
		return nil, errors.New("资源标记目录必须由本进程私有持有")
	}
	return os.OpenRoot(directory)
}
