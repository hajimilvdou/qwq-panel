// SPDX-License-Identifier: AGPL-3.0-only

//go:build !linux

package apply

// SocketMarkPermitted reports whether the current sandbox process can set
// SO_MARK on outbound sockets.
func SocketMarkPermitted() bool {
	return probeSocketMarkPermitted()
}

func probeSocketMarkPermitted() bool {
	return false
}
