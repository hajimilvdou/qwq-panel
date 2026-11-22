// SPDX-License-Identifier: AGPL-3.0-only
//go:build linux

package sandbox

import (
	"errors"
	"net"

	"golang.org/x/sys/unix"
)

// HelperPeerUID 只信任 Unix socket 内核凭据，拒绝消息内自报 UID。
func HelperPeerUID(connection net.Conn) (int, error) {
	local, ok := connection.(*net.UnixConn)
	if !ok {
		return 0, errors.New("sandbox: helper peer is not a Unix connection")
	}
	raw, err := local.SyscallConn()
	if err != nil {
		return 0, err
	}
	var credentials *unix.Ucred
	var credentialErr error
	if err := raw.Control(func(fd uintptr) {
		credentials, credentialErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil {
		return 0, err
	}
	if credentialErr != nil {
		return 0, credentialErr
	}
	return int(credentials.Uid), nil
}
