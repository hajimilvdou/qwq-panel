// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"fmt"
	"net"
	"net/http"
	"testing"
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
