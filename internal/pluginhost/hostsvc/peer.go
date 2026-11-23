// SPDX-License-Identifier: AGPL-3.0-only

package hostsvc

import (
	"context"
	"errors"
	"fmt"
	"net"

	"google.golang.org/grpc/credentials"
)

// peerAuthInfo is the connection-level authentication result. gRPC copies it
// into peer.Peer.AuthInfo for every RPC on the connection, which is how the
// interceptor recovers the identity without trusting any message field.
type peerAuthInfo struct {
	credentials.CommonAuthInfo
	info PeerInfo
}

// AuthType implements credentials.AuthInfo.
func (a *peerAuthInfo) AuthType() string { return "unix-peercred" }

// peerCredentials authenticates a connection with the kernel-provided
// SO_PEERCRED of the Unix socket. gRPC calls ServerHandshake on the accepted
// connection before it reads the HTTP/2 preface, so a rejected peer never gets
// to send a byte; on error the connection is closed here and by gRPC.
type peerCredentials struct {
	verify PeerVerifier
}

// ClientHandshake implements credentials.TransportCredentials. The host
// service is server-only; the plugin SDK owns the client side.
func (c *peerCredentials) ClientHandshake(context.Context, string, net.Conn) (net.Conn, credentials.AuthInfo, error) {
	return nil, nil, errors.New("hostsvc: peer credentials are server-side only")
}

// ServerHandshake reads SO_PEERCRED (and SO_PEERPIDFD when available), asks the
// verifier whether the peer belongs to this instance, and returns the unchanged
// connection on success.
func (c *peerCredentials) ServerHandshake(rawConn net.Conn) (net.Conn, credentials.AuthInfo, error) {
	handle, err := readPeerCredentials(rawConn)
	if err != nil {
		_ = rawConn.Close()
		return nil, nil, fmt.Errorf("hostsvc: read peer credentials: %w", err)
	}
	// The pidfd, when the kernel supports it, makes the pid unforgeable for
	// the duration of Verify: PID reuse cannot swap the process under us.
	defer handle.close()
	if err := c.verify.Verify(handle.info.PID, handle.info.UID); err != nil {
		_ = rawConn.Close()
		return nil, nil, fmt.Errorf("hostsvc: rejected peer pid=%d uid=%d: %w", handle.info.PID, handle.info.UID, err)
	}
	if err := handle.verifyAlive(); err != nil {
		_ = rawConn.Close()
		return nil, nil, fmt.Errorf("hostsvc: peer exited during verification pid=%d uid=%d: %w", handle.info.PID, handle.info.UID, err)
	}
	return rawConn, &peerAuthInfo{
		CommonAuthInfo: credentials.CommonAuthInfo{SecurityLevel: credentials.PrivacyAndIntegrity},
		info:           handle.info,
	}, nil
}

// Info implements credentials.TransportCredentials.
func (c *peerCredentials) Info() credentials.ProtocolInfo {
	return credentials.ProtocolInfo{SecurityProtocol: "unix-peercred"}
}

// Clone implements credentials.TransportCredentials.
func (c *peerCredentials) Clone() credentials.TransportCredentials {
	clone := *c
	return &clone
}

// OverrideServerName implements credentials.TransportCredentials. There is no
// server name on a Unix socket; the peer is identified by SO_PEERCRED.
func (c *peerCredentials) OverrideServerName(string) error { return nil }
