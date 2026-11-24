// SPDX-License-Identifier: AGPL-3.0-only

//go:build linux

package anytls

import (
	"sync"
	"syscall"
)

var (
	anytlsMarkProbeOnce sync.Once
	anytlsMarkPermitted bool
)

func canUseLinuxSocketMark() bool {
	anytlsMarkProbeOnce.Do(func() {
		fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM|syscall.SOCK_CLOEXEC, 0)
		if err != nil {
			return
		}
		defer syscall.Close(fd)
		if syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_MARK, 0x5100) == nil {
			anytlsMarkPermitted = true
		}
	})
	return anytlsMarkPermitted
}

func init() {
	setsockoptIntBestEffort = func(fd uintptr, level, opt, value int) error {
		if level == syscall.SOL_SOCKET && opt == syscall.SO_MARK && !canUseLinuxSocketMark() {
			return nil
		}
		return syscall.SetsockoptInt(int(fd), level, opt, value)
	}
}
