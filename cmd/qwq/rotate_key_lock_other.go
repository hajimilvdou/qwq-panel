// SPDX-License-Identifier: AGPL-3.0-only

//go:build !unix

package main

import (
	"fmt"
	"os"
	"path/filepath"
)

func acquireKeyRotationLock(dataDir string) (func(), error) {
	keysDir := filepath.Join(dataDir, "keys")
	if err := os.MkdirAll(keysDir, 0o700); err != nil {
		return nil, fmt.Errorf("create keys directory for lock: %w", err)
	}
	lockPath := filepath.Join(keysDir, ".lock")
	f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("another rotate-master-key process holds %s: %w", lockPath, err)
	}
	return func() {
		_ = f.Close()
		_ = os.Remove(lockPath)
	}, nil
}
