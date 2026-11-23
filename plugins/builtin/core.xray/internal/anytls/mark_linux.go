// SPDX-License-Identifier: AGPL-3.0-only

//go:build linux

package anytls

import "syscall"

func init() {
	setsockoptIntBestEffort = func(fd uintptr, level, opt, value int) error {
		return syscall.SetsockoptInt(int(fd), level, opt, value)
	}
}
