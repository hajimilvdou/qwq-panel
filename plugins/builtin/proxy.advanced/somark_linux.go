// SPDX-License-Identifier: AGPL-3.0-only

//go:build linux

package main

import (
	"log/slog"
	"sync"
	"syscall"
)

var (
	proxySocketMarkOnce      sync.Once
	proxySocketMarkPermitted bool
)

func probeProxySocketMarkPermitted() bool {
	proxySocketMarkOnce.Do(func() {
		fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM|syscall.SOCK_CLOEXEC, 0)
		if err != nil {
			slog.Warn("proxy.advanced: SO_MARK probe could not open test socket; disabling sockopt.mark", "error", err)
			return
		}
		defer syscall.Close(fd)
		if err := syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_MARK, 0x5100); err != nil {
			slog.Warn("proxy.advanced: SO_MARK is not permitted in this sandbox; omitting sockopt.mark to keep traffic forwarding", "error", err)
			return
		}
		proxySocketMarkPermitted = true
	})
	return proxySocketMarkPermitted
}
