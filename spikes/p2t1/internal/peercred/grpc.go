// SPDX-License-Identifier: AGPL-3.0-only

package peercred

import (
	"context"
	"errors"
	"net"
	"syscall"

	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
)

// CredConn is an accepted connection carrying the kernel-provided peer
// credentials of the other side.
type CredConn struct {
	net.Conn
	Cred Cred
}

// Close releases the pidfd and the connection.
func (c *CredConn) Close() error {
	c.Cred.Close()
	return c.Conn.Close()
}

// CredListener wraps a Unix listener so every accepted connection carries its
// peer credentials. Connections whose credentials cannot be read are refused.
type CredListener struct {
	net.Listener
}

// Accept implements net.Listener.
func (l CredListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	sc, ok := conn.(syscall.Conn)
	if !ok {
		_ = conn.Close()
		return nil, errors.New("unix connection is not a syscall.Conn")
	}
	cred, err := FromSyscallConn(sc)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	return &CredConn{Conn: conn, Cred: cred}, nil
}

// TransportCredentials is a gRPC TransportCredentials implementation that only
// exposes the peer credentials of the accepted Unix connection. It performs no
// encryption; authentication comes from the kernel. gRPC hands the AuthInfo of
// the server handshake to every RPC through peer.Peer.
type TransportCredentials struct{}

type credAuth struct{ cred Cred }

func (a credAuth) AuthType() string { return "unix-peercred" }

func (a credAuth) GetCommonAuthInfo() credentials.CommonAuthInfo {
	return credentials.CommonAuthInfo{SecurityLevel: credentials.PrivacyAndIntegrity}
}

// ClientHandshake implements credentials.TransportCredentials.
func (TransportCredentials) ClientHandshake(context.Context, string, net.Conn) (net.Conn, credentials.AuthInfo, error) {
	return nil, nil, errors.New("peercred credentials are server-side only")
}

// ServerHandshake implements credentials.TransportCredentials.
func (TransportCredentials) ServerHandshake(conn net.Conn) (net.Conn, credentials.AuthInfo, error) {
	cc, ok := conn.(*CredConn)
	if !ok {
		return nil, nil, errors.New("connection without peer credentials")
	}
	return conn, credAuth{cred: cc.Cred}, nil
}

// Info implements credentials.TransportCredentials.
func (TransportCredentials) Info() credentials.ProtocolInfo {
	return credentials.ProtocolInfo{SecurityProtocol: "unix-peercred", SecurityVersion: "1"}
}

// Clone implements credentials.TransportCredentials.
func (TransportCredentials) Clone() credentials.TransportCredentials { return TransportCredentials{} }

// OverrideServerName implements credentials.TransportCredentials.
func (TransportCredentials) OverrideServerName(string) error { return nil }

// FromContext returns the peer credentials attached to ctx by the server
// handshake.
func FromContext(ctx context.Context) (Cred, bool) {
	p, ok := peer.FromContext(ctx)
	if !ok || p.AuthInfo == nil {
		return Cred{}, false
	}
	a, ok := p.AuthInfo.(credAuth)
	if !ok {
		return Cred{}, false
	}
	return a.cred, true
}
