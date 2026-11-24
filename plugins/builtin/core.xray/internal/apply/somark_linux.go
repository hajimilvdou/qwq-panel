// SPDX-License-Identifier: AGPL-3.0-only

//go:build linux

package apply

import (
	"log/slog"
	"sync"
	"syscall"
)

var (
	socketMarkProbeOnce sync.Once
	socketMarkPermitted bool
)

// probeSocketMarkPermitted checks once whether the current sandbox process has
// kernel permission to set SO_MARK on outbound sockets (typically requires
// CAP_NET_ADMIN / CAP_NET_RAW). When EPERM is returned, RenderV2 omits
// sockopt.mark so proxy traffic forwards normally instead of 100% failing.
// SocketMarkPermitted reports whether the current sandbox process can set
// SO_MARK on outbound sockets.
func SocketMarkPermitted() bool {
	return probeSocketMarkPermitted()
}

func probeSocketMarkPermitted() bool {
	socketMarkProbeOnce.Do(func() {
		fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM|syscall.SOCK_CLOEXEC, 0)
		if err != nil {
			slog.Warn("core.xray: SO_MARK probe could not open test socket; disabling sockopt.mark", "error", err)
			return
		}
		defer syscall.Close(fd)
		if err := syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_MARK, 0x5100); err != nil {
			slog.Warn("core.xray: SO_MARK is not permitted in this sandbox; omitting sockopt.mark to keep traffic forwarding", "error", err)
			return
		}
		socketMarkPermitted = true
	})
	return socketMarkPermitted
}
