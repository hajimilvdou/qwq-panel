// SPDX-License-Identifier: AGPL-3.0-only

//go:build !linux

package hostsvc

import (
	"errors"
	"net"
)

// errPeerCredentialsUnsupported is returned by Serve on a platform without
// SO_PEERCRED. The host service refuses to listen rather than serve without
// peer authentication.
var errPeerCredentialsUnsupported = errors.New("hostsvc: SO_PEERCRED is only available on Linux")

// peerHandle is the platform-neutral placeholder of the Linux implementation.
type peerHandle struct {
	info PeerInfo
}

// close releases nothing on this platform.
func (h *peerHandle) close() {}

// verifyAlive is a no-op on non-Linux platforms where readPeerCredentials fails.
func (h *peerHandle) verifyAlive() error { return nil }

// readPeerCredentials fails: a host socket without kernel-verified peer
// identity would accept every local process.
func readPeerCredentials(net.Conn) (*peerHandle, error) {
	return nil, errPeerCredentialsUnsupported
}
