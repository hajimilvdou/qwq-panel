// SPDX-License-Identifier: AGPL-3.0-only

//go:build e2e && linux

package e2e

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// ======================== 独立轮次的真实文件写入 ========================

func TestXrayResourceMarkerUsesPrivateRoundDirectory(t *testing.T) {
	for _, workspace := range []string{"core-xray-e2e", "core-xray-x11-3e9a854"} {
		t.Run(workspace, func(t *testing.T) {
			directory := filepath.Join(t.TempDir(), workspace, "out", "TestXrayResourceMarker.round")
			if err := os.MkdirAll(directory, 0o700); err != nil {
				t.Fatal(err)
			}
			marker := filepath.Join(directory, "resources.phase.json")
			t.Setenv("QWQ_E2E_RESOURCE_MARKER", marker)
			markXrayResourcePhase(t, "traffic", os.Getpid())
			assertXrayResourceMarker(t, marker, "traffic", []int{os.Getpid()})
			markXrayResourcePhase(t, "idle")
			assertXrayResourceMarker(t, marker, "idle", []int{})
		})
	}
}

func assertXrayResourceMarker(t *testing.T, marker, phase string, clients []int) {
	t.Helper()
	info, err := os.Lstat(marker)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		t.Fatal("资源阶段标记未作为私有普通文件原子提交")
	}
	raw, err := os.ReadFile(marker)
	if err != nil {
		t.Fatal(err)
	}
	var value struct {
		Phase   string `json:"phase"`
		Clients []int  `json:"client_pids"`
	}
	if err := json.Unmarshal(raw, &value); err != nil {
		t.Fatal(err)
	}
	if value.Phase != phase || value.Clients == nil || len(value.Clients) != len(clients) {
		t.Fatal("资源阶段与客户端身份没有完整替换")
	}
	for index, pid := range clients {
		if value.Clients[index] != pid {
			t.Fatal("资源阶段客户端身份发生漂移")
		}
	}
}

// ======================== 目录边界与真实链接拒绝 ========================

func TestXrayResourceMarkerRejectsOtherPaths(t *testing.T) {
	for _, marker := range []string{
		"relative/core-xray-e2e/out/TestXrayRound/resources.phase.json",
		"/tmp/other/out/TestXrayRound/resources.phase.json",
		"/tmp/core-xray-x11-not-a-revision/out/TestXrayRound/resources.phase.json",
		"/tmp/core-xray-x11-3E9A854/out/TestXrayRound/resources.phase.json",
		"/tmp/core-xray-e2e/elsewhere/TestXrayRound/resources.phase.json",
		"/tmp/core-xray-e2e/out/other/resources.phase.json",
		"/tmp/core-xray-e2e/out/TestXrayRound/other.json",
		"/tmp/core-xray-e2e/out/TestXrayRound/../resources.phase.json",
	} {
		if validXrayResourceMarkerPath(marker) {
			t.Fatal("资源标记接受了其他目录、文件名或非规范路径")
		}
	}
}

func TestXrayResourceMarkerRejectsPublicDirectoryAndSymlink(t *testing.T) {
	output := filepath.Join(t.TempDir(), "core-xray-x11-3e9a854", "out")
	directory := filepath.Join(output, "TestXrayMarker.actual")
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(directory, "resources.phase.json")
	if err := os.Chmod(directory, 0o755); err != nil {
		t.Fatal(err)
	}
	root, err := openXrayResourceMarker(marker)
	if root != nil {
		_ = root.Close()
		t.Fatal("公开目录被当作本轮私有资源目录")
	}
	if err == nil {
		t.Fatal("公开目录拒绝缺少明确错误")
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(output, "TestXrayMarker.link")
	if err := os.Symlink(directory, link); err != nil {
		t.Fatal(err)
	}
	root, err = openXrayResourceMarker(filepath.Join(link, "resources.phase.json"))
	if root != nil {
		_ = root.Close()
		t.Fatal("符号链接被当作本轮资源目录")
	}
	if err == nil {
		t.Fatal("符号链接拒绝缺少明确错误")
	}
}
