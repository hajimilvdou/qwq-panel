// SPDX-License-Identifier: AGPL-3.0-only

//go:build linux

package hostsvc

import (
	"errors"
	"fmt"
	"net"
	"syscall"

	"golang.org/x/sys/unix"
)

// soPeerPidfd is SO_PEERPIDFD, which returns a pidfd for the peer process.
// Linux 6.5 added it; older kernels return ENOPROTOOPT/EOPNOTSUPP/EINVAL and
// the host falls back to SO_PEERCRED alone.
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
	if h.pidfd >= 0 {
		_ = syscall.Close(h.pidfd)
		h.pidfd = -1
	}
}

// verifyAlive performs a non-blocking poll on the pidfd as a post-verification
// liveness fence, ensuring the peer process did not exit (and have its PID
// recycled) before or during cgroup verification. Unlike pidfd_send_signal(0),
// polling a pidfd works across distinct unprivileged UIDs (e.g. qwq controller
// verifying a DynamicUser plugin) without returning EPERM.
func (h *peerHandle) verifyAlive() error {
	if h.pidfd < 0 {
		return nil
	}
	pfd := []unix.PollFd{{Fd: int32(h.pidfd), Events: unix.POLLIN}}
	for {
		n, err := unix.Poll(pfd, 0)
		if errors.Is(err, syscall.EINTR) {
			continue
		}
		if err != nil {
			return fmt.Errorf("pidfd liveness poll: %w", err)
		}
		if n > 0 && pfd[0].Revents&(unix.POLLIN|unix.POLLHUP|unix.POLLERR|unix.POLLNVAL) != 0 {
			return errors.New("pidfd liveness poll: peer process exited")
		}
		return nil
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
	var credErr, pidfdErr error
	err = raw.Control(func(fd uintptr) {
		ucred, err := syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
		if err != nil {
			credErr = err
			return
		}
		handle.info = PeerInfo{PID: int(ucred.Pid), UID: int(ucred.Uid), GID: int(ucred.Gid)}
		// Only ignore errors indicating the kernel lacks SO_PEERPIDFD support;
		// ESRCH (peer already exited) or other failures must fail closed to
		// prevent PID-reuse impersonation.
		pidfd, err := syscall.GetsockoptInt(int(fd), syscall.SOL_SOCKET, soPeerPidfd)
		if err != nil {
			if !errors.Is(err, syscall.ENOPROTOOPT) && !errors.Is(err, syscall.EOPNOTSUPP) && !errors.Is(err, syscall.EINVAL) {
				pidfdErr = err
			}
			return
		}
		if pidfd >= 0 {
			handle.pidfd = pidfd
			handle.info.PIDFD = true
		}
	})
	if err != nil {
		handle.close()
		return nil, err
	}
	if credErr != nil {
		handle.close()
		return nil, fmt.Errorf("SO_PEERCRED: %w", credErr)
	}
	if pidfdErr != nil {
		handle.close()
		return nil, fmt.Errorf("SO_PEERPIDFD: %w", pidfdErr)
	}
	return handle, nil
}
