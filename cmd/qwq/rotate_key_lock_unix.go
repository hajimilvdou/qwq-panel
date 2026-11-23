// SPDX-License-Identifier: AGPL-3.0-only

//go:build unix

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// acquireKeyRotationLock takes an exclusive non-blocking flock on
// <DataDir>/keys/.lock so concurrent `qwq rotate-master-key` invocations cannot
// race on master.key or retired-*.key.
func acquireKeyRotationLock(dataDir string) (func(), error) {
	keysDir := filepath.Join(dataDir, "keys")
	if err := os.MkdirAll(keysDir, 0o700); err != nil {
		return nil, fmt.Errorf("create keys directory for lock: %w", err)
	}
	lockPath := filepath.Join(keysDir, ".lock")
	f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open rotation lock %s: %w", lockPath, err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("another rotate-master-key process holds %s: %w", lockPath, err)
	}
	return func() {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		_ = f.Close()
	}, nil
}
