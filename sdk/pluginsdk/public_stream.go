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

// PublicStreamSocketName is the Unix domain socket filename created inside the
// plugin's private 2750 HostDir alongside host.sock for zero-buffered HTTP/SSE
// public route streaming without breaking the frozen Platform ABI v1 proto.
const PublicStreamSocketName = "public-stream.sock"

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

// StartPublicStreamBridge listens on public-stream.sock inside the directory
// containing hostSocketEnv. If verifyPeer is nil, the platform default peer
// verifier is applied when hostSocketEnv exists on disk.
func StartPublicStreamBridge(
	hostSocketEnv string,
	handler PublicHTTPStreamer,
	verifyPeer func(net.Conn) error,
) (*PublicStreamBridge, error) {
	if handler == nil || strings.TrimSpace(hostSocketEnv) == "" {
		return nil, nil
	}
	dir := filepath.Dir(hostSocketEnv)
	sockPath := filepath.Join(dir, PublicStreamSocketName)
	_ = os.Remove(sockPath)

	rawLn, err := net.Listen("unix", sockPath)
	if err != nil {
		return nil, fmt.Errorf("listen public stream uds %s: %w", sockPath, err)
	}
	if err := os.Chmod(sockPath, 0o660); err != nil {
		_ = rawLn.Close()
		_ = os.Remove(sockPath)
		return nil, fmt.Errorf("chmod public stream uds: %w", err)
	}

	if verifyPeer == nil {
		verifyPeer = defaultPublicStreamPeerVerifier(hostSocketEnv)
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
		if l.verifyPeer != nil {
			if verr := l.verifyPeer(conn); verr != nil {
				_ = conn.Close()
				continue
			}
		}
		return conn, nil
	}
}
