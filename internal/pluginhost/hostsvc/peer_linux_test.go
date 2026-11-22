// SPDX-License-Identifier: AGPL-3.0-only

//go:build linux

package hostsvc

import (
	"net"
	"os"
	"path/filepath"
	"testing"
)

// TestReadPeerCredentials exercises the SO_PEERCRED primitive directly: a
// connection from this process must be reported as this process.
func TestReadPeerCredentials(t *testing.T) {
	socket := filepath.Join(t.TempDir(), "peer.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer func() { _ = listener.Close() }()

	type result struct {
		handle *peerHandle
		err    error
	}
	accepted := make(chan result, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			accepted <- result{err: err}
			return
		}
		handle, err := readPeerCredentials(conn)
		accepted <- result{handle: handle, err: err}
		_ = conn.Close()
	}()
	client, err := net.Dial("unix", socket)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer func() { _ = client.Close() }()

	got := <-accepted
	if got.err != nil {
		t.Fatalf("readPeerCredentials: %v", got.err)
	}
	defer got.handle.close()
	if got.handle.info.PID != os.Getpid() {
		t.Errorf("peer pid = %d, want %d", got.handle.info.PID, os.Getpid())
	}
	if got.handle.info.UID != os.Getuid() {
		t.Errorf("peer uid = %d, want %d", got.handle.info.UID, os.Getuid())
	}
	if got.handle.info.GID != os.Getgid() {
		t.Errorf("peer gid = %d, want %d", got.handle.info.GID, os.Getgid())
	}
	// SO_PEERPIDFD is best effort (Linux >= 6.5). Log it so the report can
	// state whether the build kernel exercised the pidfd path.
	t.Logf("SO_PEERPIDFD available: %v", got.handle.info.PIDFD)
}
