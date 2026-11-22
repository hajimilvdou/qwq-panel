// SPDX-License-Identifier: AGPL-3.0-only

package controller

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"syscall"
)

// ============================================================================
//  插件 KV 状态迁移（PLG-06）
// ----------------------------------------------------------------------------
//  旧版本把 <RunDir>/state/<id>/state.json 放在 tmpfs 上。启动时把仍然存在的
//  旧文件一次性搬到持久的 StateDir；新位置已有文件时以新文件为准，旧文件保留
//  不动，交给运维判断。迁移失败只记日志：状态还在旧位置，不会因此丢失。
// ============================================================================

// stateFileName is hostsvc's built-in state store file below a plugin's
// state directory.
const stateFileName = "state.json"

// migrateLegacyState moves every <legacy>/<id>/state.json to
// <stateDir>/<id>/state.json unless the new file already exists.
func migrateLegacyState(legacy, stateDir string, logger *slog.Logger) {
	entries, err := os.ReadDir(legacy)
	if errors.Is(err, fs.ErrNotExist) {
		return
	}
	if err != nil {
		logger.Warn("legacy plugin state could not be listed", "dir", legacy, "error", err)
		return
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		src := filepath.Join(legacy, e.Name(), stateFileName)
		dst := filepath.Join(stateDir, e.Name(), stateFileName)
		if _, err := os.Lstat(src); err != nil {
			continue
		}
		if _, err := os.Lstat(dst); err == nil {
			logger.Warn("legacy plugin state kept: the persistent state already exists",
				"plugin_id", e.Name(), "legacy", src)
			continue
		}
		if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
			logger.Warn("plugin state directory could not be created", "plugin_id", e.Name(), "error", err)
			continue
		}
		if err := moveFile(src, dst); err != nil {
			logger.Warn("legacy plugin state could not be migrated", "plugin_id", e.Name(), "error", err)
			continue
		}
		_ = os.Remove(filepath.Dir(src))
		logger.Info("migrated plugin state to persistent storage", "plugin_id", e.Name(), "path", dst)
	}
}

// moveFile renames src to dst, falling back to copy + fsync + rename + remove
// when they are on different filesystems (tmpfs /run to disk is the normal
// case). dst never appears half-written.
func moveFile(src, dst string) error {
	err := os.Rename(src, dst)
	if err == nil || !errors.Is(err, syscall.EXDEV) {
		return err
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()
	tmp := dst + ".migrating"
	out, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := out.Sync(); err != nil {
		_ = out.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := out.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, dst); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("publishing %s: %w", dst, err)
	}
	if d, err := os.Open(filepath.Dir(dst)); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return os.Remove(src)
}
