// SPDX-License-Identifier: AGPL-3.0-only

//go:build linux

package hostsvc

import (
	"errors"
	"fmt"
	"net"
	"syscall"
)

// soPeerPidfd is SO_PEERPIDFD, which returns a pidfd for the peer process.
// Linux 6.5 added it; older kernels return ENOPROTOOPT and the host falls back
// to SO_PEERCRED alone.
const soPeerPidfd = 0x4d

// peerHandle owns the pidfd that was captured together with SO_PEERCRED. The
// pidfd is held only while PeerVerifier runs, so a reused pid cannot pass the
// check under a different process.
type peerHandle struct {
	info  PeerInfo
	pidfd int
}

// close releases the pidfd, if any.
func (h *peerHandle) close() {
	if h.pidfd > 0 {
		_ = syscall.Close(h.pidfd)
	}
}

// readPeerCredentials reads SO_PEERCRED and, when the kernel supports it,
// SO_PEERPIDFD from a connected Unix socket.
func readPeerCredentials(conn net.Conn) (*peerHandle, error) {
	sc, ok := conn.(syscall.Conn)
	if !ok {
		return nil, errors.New("the connection is not a syscall.Conn")
	}
	raw, err := sc.SyscallConn()
	if err != nil {
		return nil, err
	}
	handle := &peerHandle{pidfd: -1}
	var credErr error
	err = raw.Control(func(fd uintptr) {
		ucred, err := syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
		if err != nil {
			credErr = err
			return
		}
		handle.info = PeerInfo{PID: int(ucred.Pid), UID: int(ucred.Uid), GID: int(ucred.Gid)}
		// SO_PEERPIDFD is best effort: SO_PEERCRED is already authoritative
		// for pid/uid/gid, the pidfd only removes the (tiny) PID reuse window.
		pidfd, err := syscall.GetsockoptInt(int(fd), syscall.SOL_SOCKET, soPeerPidfd)
		if err != nil {
			return
		}
		if pidfd > 0 {
			handle.pidfd = pidfd
			handle.info.PIDFD = true
		}
	})
	if err != nil {
		return nil, err
	}
	if credErr != nil {
		return nil, fmt.Errorf("SO_PEERCRED: %w", credErr)
	}
	return handle, nil
}
