// SPDX-License-Identifier: Apache-2.0

package pluginsdk

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// PublicStreamSocketName is the Unix domain socket filename exposed for
// zero-buffered HTTP/SSE public route streaming without breaking the frozen
// Platform ABI v1 proto.
const PublicStreamSocketName = "public-stream.sock"

// EnvPublicStreamSocket optionally specifies a dedicated plugin-writable path
// for public-stream.sock (for example %t/qwq-plugin-stream-%i/public-stream.sock)
// so HostDir can remain 2750 agent-owned while SO_PEERCRED restricts peers to
// the host agent UID.
const EnvPublicStreamSocket = "QWQ_PUBLIC_STREAM_SOCKET"

// PublicHTTPStreamer may be implemented by plugin instances that need
// unbuffered SSE streaming or large (>4 MiB) streaming HTTP bodies on public
// routes (such as ai.relay).
type PublicHTTPStreamer interface {
	ServeHTTP(w http.ResponseWriter, r *http.Request)
}

// PublicStreamBridge serves a plugin's PublicHTTPStreamer over a private Unix
// domain socket bound to the instance lifecycle.
type PublicStreamBridge struct {
	mu       sync.Mutex
	ln       net.Listener
	srv      *http.Server
	sockPath string
}

// StartPublicStreamBridge listens on $QWQ_PUBLIC_STREAM_SOCKET when set, or
// falls back to public-stream.sock inside the directory containing
// hostSocketEnv. If verifyPeer is nil, the platform default peer verifier is
// applied (fail-closed SO_PEERCRED against hostSocketEnv on Linux).
func StartPublicStreamBridge(
	hostSocketEnv string,
	handler PublicHTTPStreamer,
	verifyPeer func(net.Conn) error,
) (*PublicStreamBridge, error) {
	streamSock := strings.TrimSpace(os.Getenv(EnvPublicStreamSocket))
	if streamSock == "" {
		if strings.TrimSpace(hostSocketEnv) == "" {
			return nil, nil
		}
		streamSock = filepath.Join(filepath.Dir(hostSocketEnv), PublicStreamSocketName)
	}
	return StartPublicStreamBridgeAt(streamSock, hostSocketEnv, handler, verifyPeer)
}

// StartPublicStreamBridgeAt listens on streamSocketPath and verifies incoming
// connections against hostSocketEnv (or verifyPeer when provided).
func StartPublicStreamBridgeAt(
	streamSocketPath string,
	hostSocketEnv string,
	handler PublicHTTPStreamer,
	verifyPeer func(net.Conn) error,
) (*PublicStreamBridge, error) {
	sockPath := strings.TrimSpace(streamSocketPath)
	if handler == nil || sockPath == "" {
		return nil, nil
	}
	if err := os.MkdirAll(filepath.Dir(sockPath), 0o711); err != nil {
		return nil, fmt.Errorf("prepare public stream uds dir %s: %w", filepath.Dir(sockPath), err)
	}
	_ = os.Remove(sockPath)

	rawLn, err := net.Listen("unix", sockPath)
	if err != nil {
		return nil, fmt.Errorf("listen public stream uds %s: %w", sockPath, err)
	}
	// When the socket lives outside the 2750 HostDir (e.g. a dedicated plugin
	// RuntimeDirectory owned by DynamicUser), chmod 0666 lets the qwq agent user
	// dial it while Linux SO_PEERCRED strictly enforces hostAgentUID.
	sockMode := os.FileMode(0o660)
	if strings.TrimSpace(hostSocketEnv) == "" || filepath.Clean(filepath.Dir(sockPath)) != filepath.Clean(filepath.Dir(hostSocketEnv)) {
		sockMode = 0o666
	}
	if err := os.Chmod(sockPath, sockMode); err != nil {
		_ = rawLn.Close()
		_ = os.Remove(sockPath)
		return nil, fmt.Errorf("chmod public stream uds: %w", err)
	}

	if verifyPeer == nil {
		verifyPeer = defaultPublicStreamPeerVerifier(hostSocketEnv)
	}
	if verifyPeer == nil && requirePublicStreamPeerVerification {
		_ = rawLn.Close()
		_ = os.Remove(sockPath)
		return nil, fmt.Errorf("public stream: peer verifier is required")
	}
	guardedLn := &peerVerifiedListener{
		Listener:   rawLn,
		verifyPeer: verifyPeer,
	}

	srv := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       90 * time.Second,
		MaxHeaderBytes:    32 << 10,
	}

	bridge := &PublicStreamBridge{
		ln:       guardedLn,
		srv:      srv,
		sockPath: sockPath,
	}
	go func() {
		_ = srv.Serve(guardedLn)
	}()
	return bridge, nil
}

// SocketPath returns the active Unix domain socket path of the bridge.
func (b *PublicStreamBridge) SocketPath() string {
	if b == nil {
		return ""
	}
	return b.sockPath
}

// Close gracefully stops the HTTP server and removes the socket file.
func (b *PublicStreamBridge) Close(ctx context.Context) error {
	if b == nil {
		return nil
	}
	b.mu.Lock()
	srv := b.srv
	sock := b.sockPath
	b.srv = nil
	b.mu.Unlock()
	if srv == nil {
		return nil
	}
	err := srv.Shutdown(ctx)
	_ = os.Remove(sock)
	return err
}

type peerVerifiedListener struct {
	net.Listener
	verifyPeer func(net.Conn) error
}

func (l *peerVerifiedListener) Accept() (net.Conn, error) {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		if l.verifyPeer == nil {
			if requirePublicStreamPeerVerification {
				_ = conn.Close()
				continue
			}
		} else if verr := l.verifyPeer(conn); verr != nil {
			_ = conn.Close()
			continue
		}
		return conn, nil
	}
}
