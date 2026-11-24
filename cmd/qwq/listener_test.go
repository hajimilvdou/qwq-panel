// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"testing"
	"time"
)

func TestSameListenAddrWildcardNormalization(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{
		{"0.0.0.0:8443", "[::]:8443", true},
		{":8443", "[::]:8443", true},
		{"0.0.0.0:8443", ":8443", true},
		{"127.0.0.1:8443", "127.0.0.1:8443", true},
		{"0.0.0.0:8443", "0.0.0.0:9443", false},
		{"127.0.0.1:8443", "0.0.0.0:8443", false},
		{"", ":8443", false},
	}
	for _, tc := range cases {
		if got := sameListenAddr(tc.a, tc.b); got != tc.want {
			t.Errorf("sameListenAddr(%q, %q) = %v, want %v", tc.a, tc.b, got, tc.want)
		}
	}
}

func TestLiveHTTPListenerReclaimRetiringWildcardPort(t *testing.T) {
	srv := &http.Server{Handler: http.NewServeMux()}
	live := newLiveHTTPListener(srv, false, nil)
	defer live.Close()

	// Pick two free ports via 127.0.0.1 first so the test does not collide with host ports.
	lnA, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve port A: %v", err)
	}
	portA := lnA.Addr().(*net.TCPAddr).Port
	_ = lnA.Close()

	lnB, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve port B: %v", err)
	}
	portB := lnB.Addr().(*net.TCPAddr).Port
	_ = lnB.Close()

	addrA := fmt.Sprintf("127.0.0.1:%d", portA)
	addrB := fmt.Sprintf("127.0.0.1:%d", portB)

	if _, err := live.Start(addrA); err != nil {
		t.Fatalf("Start(%s): %v", addrA, err)
	}
	if err := live.Rebind(addrB); err != nil {
		t.Fatalf("Rebind(%s): %v", addrB, err)
	}
	// Rapid A -> B -> A must reclaim retiring A before re-listening on A.
	if err := live.Rebind(addrA); err != nil {
		t.Fatalf("Rebind back to %s: %v", addrA, err)
	}
}

func TestLiveHTTPListenerSamePortHostSwitchAndAbortRollback(t *testing.T) {
	srv := &http.Server{Handler: http.NewServeMux()}
	live := newLiveHTTPListener(srv, false, nil)
	defer live.Close()

	// Reserve a free port on wildcard first to avoid colliding with host services.
	probe, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		t.Fatalf("reserve wildcard port: %v", err)
	}
	port := probe.Addr().(*net.TCPAddr).Port
	_ = probe.Close()

	loopbackAddr := fmt.Sprintf("127.0.0.1:%d", port)
	publicAddr := fmt.Sprintf("0.0.0.0:%d", port)

	if _, err := live.Start(loopbackAddr); err != nil {
		t.Fatalf("Start(%s): %v", loopbackAddr, err)
	}
	// Same-port loopback -> wildcard must succeed without EADDRINUSE.
	staged, err := live.PrepareBind(publicAddr)
	if err != nil {
		t.Fatalf("PrepareBind(%s) from %s failed: %v", publicAddr, loopbackAddr, err)
	}
	// Aborting must restore loopbackAddr so it remains active.
	staged.Abort()
	live.mu.Lock()
	curAfterAbort := live.currentReqAddr
	hasCur := live.current != nil
	live.mu.Unlock()
	if !hasCur || curAfterAbort != loopbackAddr {
		t.Fatalf("after Abort: hasCur=%v reqAddr=%q, want %q", hasCur, curAfterAbort, loopbackAddr)
	}

	// Commit same-port loopback -> wildcard -> loopback.
	if err := live.Rebind(publicAddr); err != nil {
		t.Fatalf("Rebind(%s): %v", publicAddr, err)
	}
	if err := live.Rebind(loopbackAddr); err != nil {
		t.Fatalf("Rebind back to %s: %v", loopbackAddr, err)
	}
}

func TestWrapListenerForSharedServerConcurrentTLSRebind(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte("ok"))
		}),
		TLSConfig: &tls.Config{
			MinVersion:   tls.VersionTLS12,
			Certificates: []tls.Certificate{cert},
			NextProtos:   []string{"h2", "http/1.1"},
		},
	}
	live := newLiveHTTPListener(srv, true, nil)
	live.retireGrace = 200 * time.Millisecond
	defer live.Close()

	addr1, err := live.Start("127.0.0.1:0")
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	if err := live.Rebind("127.0.0.1:0"); err != nil {
		t.Fatalf("Rebind: %v", err)
	}
	live.mu.Lock()
	addr2 := live.current.Addr()
	live.mu.Unlock()

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		Timeout: 3 * time.Second,
	}
	defer client.CloseIdleConnections()
	for _, a := range []net.Addr{addr1, addr2} {
		resp, err := client.Get("https://" + a.String())
		if err != nil {
			t.Fatalf("GET https://%s failed: %v", a.String(), err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("GET https://%s status = %d", a.String(), resp.StatusCode)
		}
	}
	if !IsLoopbackOnlyHost("127.0.0.1") || !IsLoopbackOnlyHost("::1") || !IsLoopbackOnlyHost("localhost") {
		t.Fatal("IsLoopbackOnlyHost missed loopback host")
	}
	if IsLoopbackOnlyHost("0.0.0.0") || IsLoopbackOnlyHost("::") {
		t.Fatal("IsLoopbackOnlyHost misclassified wildcard host")
	}
}
