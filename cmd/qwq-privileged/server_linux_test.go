// SPDX-License-Identifier: AGPL-3.0-only

//go:build linux

package main

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/qwq-panel/qwq/internal/platform/problem"
	"github.com/qwq-panel/qwq/internal/sandbox"
)

// TestPublishRejectsSymlinkAndSpecialFiles covers the Linux-only entries a
// verified package must never contain: symlinks, FIFOs and control characters
// in a file name.
func TestPublishRejectsSymlinkAndSpecialFiles(t *testing.T) {
	h := newTestHost(t)

	symlinkTree := h.addStaged(t, map[string]stagedFile{"manifest.json": {"{}", 0o644}})
	if err := os.Symlink("/etc/passwd", filepath.Join(symlinkTree, "link")); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	resp := h.server.handle(context.Background(), h.publishRequest(symlinkTree, "alpha", "1.2.3"))
	if resp.OK || resp.Code != string(problem.ValidationFailed) {
		t.Errorf("symlink tree: response = %+v, want VALIDATION_FAILED", resp)
	}

	fifoTree := h.addStaged(t, map[string]stagedFile{"manifest.json": {"{}", 0o644}})
	if err := syscall.Mkfifo(filepath.Join(fifoTree, "fifo"), 0o600); err != nil {
		t.Fatalf("mkfifo: %v", err)
	}
	resp = h.server.handle(context.Background(), h.publishRequest(fifoTree, "beta", "2.0.0"))
	if resp.OK || resp.Code != string(problem.ValidationFailed) {
		t.Errorf("fifo tree: response = %+v, want VALIDATION_FAILED", resp)
	}

	unsafeTree := h.addStaged(t, map[string]stagedFile{"bad\nname": {"x", 0o644}})
	resp = h.server.handle(context.Background(), h.publishRequest(unsafeTree, "gamma", "3.0.0"))
	if resp.OK || resp.Code != string(problem.ValidationFailed) {
		t.Errorf("unsafe name: response = %+v, want VALIDATION_FAILED", resp)
	}
	for _, id := range []string{"alpha", "beta", "gamma"} {
		if _, err := os.Stat(filepath.Join(h.cfg.PluginsRoot, id)); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("a rejected publish created the %s version tree: %v", id, err)
		}
	}
}

// TestRemoveRefusesSwappedPluginsRoot: 插件根被换成指向 victim 的链接时，
// remove 不得经由它递归删除。
func TestRemoveRefusesSwappedPluginsRoot(t *testing.T) {
	h := newTestHost(t)
	victim := t.TempDir()
	canary := filepath.Join(victim, "etc", "systemd", "canary")
	if err := os.MkdirAll(filepath.Dir(canary), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(canary, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(h.cfg.PluginsRoot); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victim, h.cfg.PluginsRoot); err != nil {
		t.Fatal(err)
	}
	resp := h.server.handle(context.Background(), sandbox.HelperRequest{
		Op: sandbox.HelperOpRemove, ID: "etc", Version: "systemd", KeepUnit: true,
		Paths: []string{filepath.Join(h.cfg.PluginsRoot, "etc", "systemd")},
	})
	if resp.OK {
		t.Errorf("remove through a swapped plugins root succeeded: %+v", resp)
	}
	if _, err := os.Stat(canary); err != nil {
		t.Errorf("remove deleted through the swapped root: %v", err)
	}
}

// TestRemoveRefusesSymlinkedRuntimePluginDir: <run>/qwq/plugin 是指向 victim
// 的链接，victim 里有 ssh/canary；响应失败且 canary 仍在。
func TestRemoveRefusesSymlinkedRuntimePluginDir(t *testing.T) {
	h := newTestHost(t)
	victim := t.TempDir()
	canary := filepath.Join(victim, "ssh", "canary")
	if err := os.MkdirAll(filepath.Dir(canary), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(canary, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victim, filepath.Join(h.cfg.RuntimeBase, "qwq", "plugin")); err != nil {
		t.Fatal(err)
	}
	resp := h.server.handle(context.Background(), sandbox.HelperRequest{Op: sandbox.HelperOpRemove, ID: "ssh"})
	if resp.OK {
		t.Errorf("remove through a symlinked plugin dir succeeded: %+v", resp)
	}
	if _, err := os.Stat(canary); err != nil {
		t.Errorf("remove deleted through the symlink: %v", err)
	}
}

// TestPublishRefusesPluginsRootSwappedMidRequest: 打开插件根之后把它换成指向
// victim 的链接；victim 下不得出现任何新文件。
func TestPublishRefusesPluginsRootSwappedMidRequest(t *testing.T) {
	h := newTestHost(t)
	victim := t.TempDir()
	staged := h.addStaged(t, map[string]stagedFile{"manifest.json": {"{}", 0o644}})
	h.server.afterRootCheck = func() {
		if err := os.Rename(h.cfg.PluginsRoot, h.cfg.PluginsRoot+".old"); err != nil {
			t.Error(err)
		}
		if err := os.Symlink(victim, h.cfg.PluginsRoot); err != nil {
			t.Error(err)
		}
	}
	_ = h.server.handle(context.Background(), h.publishRequest(staged, "system", "ssh.service.d"))
	entries, err := os.ReadDir(victim)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Errorf("publish wrote through the swapped plugins root: %v", entries)
	}
}

// TestPublishRefusesUntrustedPluginsRoot: 组可写的插件根直接拒绝。
func TestPublishRefusesUntrustedPluginsRoot(t *testing.T) {
	h := newTestHost(t)
	staged := h.addStaged(t, map[string]stagedFile{"manifest.json": {"{}", 0o644}})
	if err := os.Chmod(h.cfg.PluginsRoot, 0o775); err != nil {
		t.Fatal(err)
	}
	resp := h.server.handle(context.Background(), h.publishRequest(staged, "alpha", "1.0.0"))
	if resp.OK || resp.Code != string(problem.Unavailable) {
		t.Errorf("response = %+v, want UNAVAILABLE", resp)
	}
}

// TestPublishPinsStagedHandle: 打开 staged 句柄之后把 stagedDir 换成指向
// secret 目录的链接；发布结果不得包含 secret（PRIV-02）。
func TestPublishPinsStagedHandle(t *testing.T) {
	h := newTestHost(t)
	secret := t.TempDir()
	if err := os.WriteFile(filepath.Join(secret, "id_rsa"), []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	staged := h.addStaged(t, map[string]stagedFile{"manifest.json": {"{}", 0o644}})
	h.server.afterOpenStaged = func() {
		if err := os.Rename(staged, staged+".old"); err != nil {
			t.Error(err)
		}
		if err := os.Symlink(secret, staged); err != nil {
			t.Error(err)
		}
	}
	resp := h.server.handle(context.Background(), h.publishRequest(staged, "alpha", "1.2.3"))
	if !resp.OK {
		return // 拒绝也是正确结果
	}
	versionDir := filepath.Join(h.cfg.PluginsRoot, "alpha", "1.2.3")
	if _, err := os.Lstat(filepath.Join(versionDir, "id_rsa")); err == nil {
		t.Error("publish copied the secret through the swapped staged dir")
	}
	if _, err := os.Lstat(filepath.Join(versionDir, "manifest.json")); err != nil {
		t.Errorf("publish did not copy the pinned tree: %v", err)
	}
}

// TestPublishRejectsHardlinkedFile: Nlink=2 的文件可能是硬链接来的 root 文件，
// 一律拒绝。复现不依赖 fs.protected_hardlinks：链接的是 staging 内自己的文件。
func TestPublishRejectsHardlinkedFile(t *testing.T) {
	h := newTestHost(t)
	staged := h.addStaged(t, map[string]stagedFile{"manifest.json": {"{}", 0o644}})
	if err := os.Link(filepath.Join(staged, "manifest.json"), filepath.Join(h.cfg.StagingRoot, "other")); err != nil {
		t.Fatal(err)
	}
	resp := h.server.handle(context.Background(), h.publishRequest(staged, "alpha", "1.2.3"))
	if resp.OK {
		t.Errorf("publish accepted a hard-linked file: %+v", resp)
	}
	if _, err := os.Stat(filepath.Join(h.cfg.PluginsRoot, "alpha", "1.2.3")); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("a rejected publish left a version tree: %v", err)
	}
}

// TestPublishDoesNotBlockOnSwappedFIFO: 校验之后被换成 FIFO 的条目不能让
// helper 永久阻塞在 open 上。这里直接对含 FIFO 的句柄调用 publishTree，模拟
// 校验与拷贝之间的替换。
func TestPublishDoesNotBlockOnSwappedFIFO(t *testing.T) {
	h := newTestHost(t)
	staged := h.addStaged(t, map[string]stagedFile{"manifest.json": {"{}", 0o644}})
	if err := syscall.Mkfifo(filepath.Join(staged, "fifo"), 0o600); err != nil {
		t.Fatalf("mkfifo: %v", err)
	}
	src, err := os.OpenRoot(staged)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = src.Close() }()
	plugins, err := os.OpenRoot(h.cfg.PluginsRoot)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = plugins.Close() }()
	done := make(chan error, 1)
	go func() { done <- publishTree(context.Background(), src, plugins, "alpha", "1.2.3", os.Getuid()) }()
	select {
	case err := <-done:
		if err == nil {
			t.Error("publishTree accepted a FIFO")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("publishTree blocked on a FIFO")
	}
}
