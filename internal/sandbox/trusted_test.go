// SPDX-License-Identifier: AGPL-3.0-only

//go:build unix

package sandbox

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// testTrust relaxes the production policy for an unprivileged test: the
// temporary root is owned by the test user and is where the walk stops.
func testTrust(root string) TrustPolicy {
	return TrustPolicy{UID: os.Getuid(), StopAt: root}
}

// currentIDs 把 agent 用户与插件组都映射成当前进程的 uid/gid，非 root 测试
// 也能完成 Fchown。
func currentIDs(string, string) (int, int, error) { return os.Getuid(), os.Getgid(), nil }

func TestCheckTrustedAncestry(t *testing.T) {
	root := t.TempDir()
	good := filepath.Join(root, "a", "b")
	if err := os.MkdirAll(good, 0o755); err != nil {
		t.Fatal(err)
	}
	tp := testTrust(root)
	r, err := tp.Open(good)
	if err != nil {
		t.Fatalf("Open(good) = %v", err)
	}
	_ = r.Close()

	// 属主错误：用"另一个 uid"作为可信属主来模拟，非 root 无法 chown。
	if _, err := (TrustPolicy{UID: os.Getuid() + 1, StopAt: root}).Open(good); err == nil ||
		!strings.Contains(err.Error(), "owned by") {
		t.Errorf("wrong owner: err = %v", err)
	}

	// 祖先 0777。
	loose := filepath.Join(root, "loose")
	if err := os.MkdirAll(filepath.Join(loose, "child"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(loose, 0o777); err != nil {
		t.Fatal(err)
	}
	if _, err := tp.Open(filepath.Join(loose, "child")); err == nil ||
		!strings.Contains(err.Error(), "writable") {
		t.Errorf("0777 ancestor: err = %v", err)
	}

	// 符号链接组件。
	link := filepath.Join(root, "link")
	if err := os.Symlink(good, link); err != nil {
		t.Fatal(err)
	}
	if _, err := tp.Open(link); err == nil || !strings.Contains(err.Error(), "real directory") {
		t.Errorf("symlink: err = %v", err)
	}

	// 不在 StopAt 之下时一路校验到 "/"，/tmp 一类的全局可写祖先必然失败。
	if _, err := (TrustPolicy{UID: os.Getuid(), StopAt: filepath.Join(root, "a")}).Open(filepath.Join(loose, "child")); err == nil {
		t.Error("a path outside StopAt passed the ancestry check")
	}
}

func TestRemoveAllInDoesNotFollowSymlinks(t *testing.T) {
	root := t.TempDir()
	victim := t.TempDir()
	canary := filepath.Join(victim, "canary")
	if err := os.WriteFile(canary, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victim, filepath.Join(root, "link")); err != nil {
		t.Fatal(err)
	}
	r, err := os.OpenRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Close() }()
	if ok, err := RemoveAllIn(r, "link"); err != nil || !ok {
		t.Fatalf("RemoveAllIn(link) = %v, %v", ok, err)
	}
	if ok, err := RemoveAllIn(r, "link"); err != nil || ok {
		t.Fatalf("RemoveAllIn(missing) = %v, %v", ok, err)
	}
	if _, err := os.Stat(canary); err != nil {
		t.Errorf("RemoveAllIn followed the symlink: %v", err)
	}
}

// TestInstallDoesNotChmodThroughSymlinkedCredDir: creds/ 被换成指向 victim
// 的链接时，Install 必须失败且 victim 的权限不变。
func TestInstallDoesNotChmodThroughSymlinkedCredDir(t *testing.T) {
	in, _, _ := installerFixture(t)
	victim := t.TempDir()
	if err := os.Chmod(victim, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(in.CredDir); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victim, in.CredDir); err != nil {
		t.Fatal(err)
	}
	token := []byte(strings.Repeat("ab", 32))
	if _, err := in.Install(context.Background(), alphaSpec(), token); err == nil {
		t.Error("Install succeeded through a symlinked credential directory")
	}
	fi, err := os.Stat(victim)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o755 {
		t.Errorf("victim mode = %o, want 755", fi.Mode().Perm())
	}
	if entries, _ := os.ReadDir(victim); len(entries) != 0 {
		t.Errorf("Install wrote into the victim: %v", entries)
	}
}

// TestRemoveRefusesSymlinkedRuntimePluginDir: plugin/ 是指向 victim 的链接，
// victim 里有 alpha/canary；Remove 失败且 canary 仍在。
func TestRemoveRefusesSymlinkedRuntimePluginDir(t *testing.T) {
	in, _, _ := installerFixture(t)
	victim := t.TempDir()
	canary := filepath.Join(victim, "alpha", "canary")
	if err := os.MkdirAll(filepath.Dir(canary), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(canary, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victim, filepath.Join(in.RuntimeBase, runtimeDirName, pluginDirName)); err != nil {
		t.Fatal(err)
	}
	if _, err := in.Remove(context.Background(), "alpha"); err == nil {
		t.Error("Remove succeeded through a symlinked plugin directory")
	}
	if _, err := os.Stat(canary); err != nil {
		t.Errorf("Remove deleted through the symlink: %v", err)
	}
}

// TestInstallRefusesUntrustedRuntime: /run/qwq 组可写（旧布局里归 qwq 且可被
// 替换）时 Install 直接拒绝。
func TestInstallRefusesUntrustedRuntime(t *testing.T) {
	in, fr, _ := installerFixture(t)
	if err := os.Chmod(filepath.Join(in.RuntimeBase, runtimeDirName), 0o770); err != nil {
		t.Fatal(err)
	}
	if _, err := in.Install(context.Background(), alphaSpec(), nil); err == nil {
		t.Error("Install accepted a group-writable runtime directory")
	}
	if fr.count() != 0 {
		t.Errorf("a rejected install reached the runner: %v", fr.calls)
	}
}

// TestInstallerCreatesHostDirWithPluginGroup: Install 以 fd 方式创建
// <run>/qwq/host/<id>，属主 agent、属组插件组、权限 2750（PRIV-04）。
// 查找函数换成当前用户与当前组，非 root 也能 Fchown 给自己。
func TestInstallerCreatesHostDirWithPluginGroup(t *testing.T) {
	in, _, _ := installerFixture(t)
	host := filepath.Join(in.RuntimeBase, runtimeDirName, hostDirName)
	var asked []string
	in.LookupIDs = func(user, group string) (int, int, error) {
		asked = append(asked, user, group)
		return os.Getuid(), os.Getgid(), nil
	}
	if _, err := in.Install(context.Background(), alphaSpec(), nil); err != nil {
		t.Fatalf("Install: %v", err)
	}
	if len(asked) != 2 || asked[0] != DefaultAgentUser || asked[1] != "qwq-p-alpha" {
		t.Errorf("LookupIDs asked %v", asked)
	}
	dir := filepath.Join(host, "alpha")
	fi, err := os.Lstat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !fi.IsDir() || fi.Mode()&os.ModeSetgid == 0 || fi.Mode().Perm() != 0o750 {
		t.Errorf("host dir mode = %v, want dg rwxr-x---", fi.Mode())
	}
	if _, err := in.Remove(context.Background(), "alpha"); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if _, err := os.Lstat(dir); !os.IsNotExist(err) {
		t.Errorf("Remove left the host dir: %v", err)
	}
}

// TestInstallerRefusesSymlinkedHostDir: qwq 在 host/ 下预置指向 root 目录的
// 链接时，Install 不得 chown 链接目标。
func TestInstallerRefusesSymlinkedHostDir(t *testing.T) {
	in, _, _ := installerFixture(t)
	host := filepath.Join(in.RuntimeBase, runtimeDirName, hostDirName)
	victim := t.TempDir()
	if err := os.Chmod(victim, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victim, filepath.Join(host, "alpha")); err != nil {
		t.Fatal(err)
	}
	if _, err := in.Install(context.Background(), alphaSpec(), nil); err == nil {
		t.Error("Install accepted a symlinked host dir")
	}
	if fi, _ := os.Stat(victim); fi.Mode().Perm() != 0o755 || fi.Mode()&os.ModeSetgid != 0 {
		t.Errorf("victim mode changed to %v", fi.Mode())
	}
}
