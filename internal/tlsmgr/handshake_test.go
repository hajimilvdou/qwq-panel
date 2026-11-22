// SPDX-License-Identifier: AGPL-3.0-only

package tlsmgr

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/qwq-panel/qwq/internal/platform/clock"
)

// echoServer listens on loopback, completes one TLS handshake and echoes every
// byte back until the client closes. The returned channel reports the server's
// error (nil after a clean shutdown).
func echoServer(t *testing.T, cfg *tls.Config) (addr string, done <-chan error) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	ch := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			ch <- err
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(20 * time.Second))
		tc := tls.Server(conn, cfg)
		if err := tc.Handshake(); err != nil {
			ch <- fmt.Errorf("handshake: %w", err)
			return
		}
		_, err = io.Copy(tc, tc)
		ch <- err
	}()
	return ln.Addr().String(), ch
}

// dialTLS connects to addr and verifies the server against pool for the name
// localhost, as a browser on the host would after the operator compared the
// fingerprint.
func dialTLS(t *testing.T, addr string, pool *x509.CertPool) *tls.Conn {
	t.Helper()
	conn, err := tls.Dial("tcp", addr, &tls.Config{
		RootCAs:          pool,
		ServerName:       "localhost",
		NextProtos:       []string{"h2"},
		MinVersion:       tls.VersionTLS12,
		CurvePreferences: []tls.CurveID{tls.X25519, tls.CurveP256},
		// Certificates are dated by the test's fake clock, so validation has to
		// use that clock too instead of the machine's wall time.
		Time: func() time.Time { return testTime },
	})
	if err != nil {
		t.Fatalf("tls.Dial: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	_ = conn.SetDeadline(time.Now().Add(20 * time.Second))
	return conn
}

// certPool pins the manager's current certificate.
func certPool(t *testing.T, m *Manager) *x509.CertPool {
	t.Helper()
	c := m.current.Load()
	if c == nil {
		t.Fatal("no certificate is loaded")
	}
	pool := x509.NewCertPool()
	pool.AddCert(c.leaf)
	return pool
}

func assertEcho(t *testing.T, conn *tls.Conn, msg string) {
	t.Helper()
	if _, err := conn.Write([]byte(msg)); err != nil {
		t.Fatalf("write %q: %v", msg, err)
	}
	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read echo of %q: %v", msg, err)
	}
	if string(buf) != msg {
		t.Fatalf("echo %q, want %q", buf, msg)
	}
}

func TestTLSHandshakeAndReload(t *testing.T) {
	dir := t.TempDir()
	fake := clock.NewFake(testTime)
	m := newSelfSigned(t, dir, "127.0.0.1:0", nil, fake)

	addr, done := echoServer(t, m.TLSConfig())
	client := dialTLS(t, addr, certPool(t, m))

	state := client.ConnectionState()
	if state.Version < tls.VersionTLS12 {
		t.Fatalf("negotiated version %x, want TLS 1.2 or newer", state.Version)
	}
	if state.NegotiatedProtocol != "h2" {
		t.Fatalf("negotiated ALPN %q, want h2", state.NegotiatedProtocol)
	}
	if len(state.PeerCertificates) == 0 {
		t.Fatal("client received no certificate")
	}
	if got := fingerprint(state.PeerCertificates[0].Raw); got != m.Fingerprint() {
		t.Fatalf("client verified certificate %s, want %s", got, m.Fingerprint())
	}
	assertEcho(t, client, "first")

	// Replace the pair on disk and reload while the connection is open: the
	// established connection keeps working, and the next handshake uses the new
	// certificate.
	before := m.Fingerprint()
	certPEM, keyPEM, err := generateSelfSigned(fake.Now().Add(time.Hour), m.sans)
	if err != nil {
		t.Fatalf("generateSelfSigned: %v", err)
	}
	if err := saveSelfSigned(m.dir, certPEM, keyPEM, nil); err != nil {
		t.Fatalf("saveSelfSigned: %v", err)
	}
	if err := m.Reload(); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	if m.Fingerprint() == before {
		t.Fatal("Reload kept the old certificate")
	}
	assertEcho(t, client, "second")

	if err := client.Close(); err != nil {
		t.Fatalf("close client: %v", err)
	}
	if err := <-done; err != nil {
		t.Fatalf("server: %v", err)
	}

	// A new connection is verified against the reloaded certificate.
	addr2, done2 := echoServer(t, m.TLSConfig())
	client2 := dialTLS(t, addr2, certPool(t, m))
	if got := fingerprint(client2.ConnectionState().PeerCertificates[0].Raw); got != m.Fingerprint() {
		t.Fatalf("second connection used %s, want %s", got, m.Fingerprint())
	}
	assertEcho(t, client2, "third")
	if err := client2.Close(); err != nil {
		t.Fatalf("close second client: %v", err)
	}
	if err := <-done2; err != nil {
		t.Fatalf("second server: %v", err)
	}
}

func TestHandshakeRejectsUnknownName(t *testing.T) {
	m := newSelfSigned(t, t.TempDir(), "127.0.0.1:8443", nil, clock.NewFake(testTime))
	addr, done := echoServer(t, m.TLSConfig())

	// A client that does not trust the certificate fails verification, which is
	// what protects users who skip comparing the fingerprint.
	conn, err := tls.Dial("tcp", addr, &tls.Config{
		ServerName: "localhost",
		MinVersion: tls.VersionTLS12,
	})
	if err == nil {
		_ = conn.Close()
		t.Fatal("handshake succeeded without trusting the self-signed certificate")
	}
	// The server's own handshake fails too, because the client aborts it.
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("server did not finish after the client refused the certificate")
	}
}

func TestMaintainRenewsCertificate(t *testing.T) {
	fake := clock.NewFake(testTime)
	m := newSelfSigned(t, t.TempDir(), "127.0.0.1:8443", nil, fake)
	first := m.Fingerprint()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go m.Maintain(ctx)

	// Wait until Maintain has armed its timer before moving the clock.
	deadline := time.Now().Add(10 * time.Second)
	for fake.Waiters() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if fake.Waiters() == 0 {
		t.Fatal("Maintain armed no timer")
	}

	// Advance past the renewal threshold; the timer fires and the certificate is
	// replaced without a restart.
	fake.Advance(selfSignedValidity - renewBefore + time.Hour)
	for m.Fingerprint() == first && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if m.Fingerprint() == first {
		t.Fatal("Maintain did not renew the certificate")
	}
	st := m.Status(context.Background())
	if !st.Ready || st.Warn {
		t.Fatalf("status after renewal = %+v", st)
	}
}

func TestMaintainStopsWithContext(t *testing.T) {
	fake := clock.NewFake(testTime)
	m := newSelfSigned(t, t.TempDir(), "127.0.0.1:8443", nil, fake)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		m.Maintain(ctx)
		close(done)
	}()
	cancel()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("Maintain ignored a cancelled context")
	}
}

func TestReloadRejectsBrokenPair(t *testing.T) {
	dir := t.TempDir()
	m := newSelfSigned(t, dir, "127.0.0.1:8443", nil, clock.NewFake(testTime))
	before := m.Fingerprint()

	// A mismatched key and certificate must leave the running certificate alone.
	certPEM, _, err := generateSelfSigned(testTime.Add(2*time.Hour), m.sans)
	if err != nil {
		t.Fatalf("generateSelfSigned: %v", err)
	}
	if err := saveSelfSigned(m.dir, certPEM, nil, nil); err != nil {
		t.Fatalf("saveSelfSigned with an empty key: %v", err)
	}
	if err := m.Reload(); err == nil {
		t.Fatal("Reload accepted a certificate without a matching key")
	}
	if m.Fingerprint() != before {
		t.Fatal("a failed Reload changed the served certificate")
	}
}
