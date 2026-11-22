// SPDX-License-Identifier: AGPL-3.0-only

package coreproc

import (
	"context"
	"errors"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/qwq-panel/qwq/internal/sandbox"
)

// clearSocket 只移除本 UID 的私有失效 UDS；仍可连接的 socket 属于未接管进程。
func (m *Manager) clearSocket(parent context.Context) error {
	name := m.options.Socket
	info, err := os.Lstat(name)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil || info.Mode()&fs.ModeSocket == 0 || info.Mode().Perm() != 0o600 {
		return ErrStop
	}
	owner, ok := sandbox.FileOwner(info)
	if !ok || owner != os.Geteuid() {
		return ErrStop
	}
	directory := filepath.Dir(name)
	parentInfo, err := os.Lstat(directory)
	if err != nil || !parentInfo.IsDir() || parentInfo.Mode().Perm() != 0o700 || parentInfo.Mode()&fs.ModeSymlink != 0 {
		return ErrStop
	}
	root, err := (sandbox.TrustPolicy{UID: os.Geteuid(), StopAt: directory}).Open(directory)
	if err != nil {
		return ErrStop
	}
	defer root.Close()
	ctx, cancel := context.WithTimeout(parent, 200*time.Millisecond)
	defer cancel()
	connection, err := (&net.Dialer{}).DialContext(ctx, "unix", name)
	if err == nil {
		_ = connection.Close()
		return ErrAlreadyRunning
	}
	if !errors.Is(err, syscall.ECONNREFUSED) && !errors.Is(err, fs.ErrNotExist) {
		return ErrStop
	}
	after, err := root.Lstat(filepath.Base(name))
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil || !os.SameFile(info, after) {
		return ErrStop
	}
	if err := root.Remove(filepath.Base(name)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return ErrStop
	}
	return nil
}
