// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestBuildPinnedProbeTLSConfig(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	leafDER := srv.Certificate().Raw
	sum := sha256.Sum256(leafDER)
	pinHex := hex.EncodeToString(sum[:])

	// 1. Colon-separated uppercase fingerprint with sha256: prefix must match.
	colonPin := "SHA256:" + strings.ToUpper(pinHex[:2]) + ":" + strings.ToUpper(pinHex[2:])
	cfg, err := BuildPinnedProbeTLSConfig(colonPin, false)
	if err != nil {
		t.Fatalf("BuildPinnedProbeTLSConfig(valid): %v", err)
	}
	cli := &http.Client{Transport: &http.Transport{TLSClientConfig: cfg}}
	resp, err := cli.Get(srv.URL)
	if err != nil {
		t.Fatalf("pinned TLS handshake failed: %v", err)
	}
	_ = resp.Body.Close()

	// 2. Wrong pin must be rejected (MITM defense).
	badCfg, err := BuildPinnedProbeTLSConfig(strings.Repeat("a", 64), false)
	if err != nil {
		t.Fatalf("BuildPinnedProbeTLSConfig(wrong): %v", err)
	}
	badCli := &http.Client{Transport: &http.Transport{TLSClientConfig: badCfg}}
	if _, err := badCli.Get(srv.URL); err == nil {
		t.Fatal("expected TLS pin mismatch rejection")
	}

	// 3. Invalid pin length must return an error.
	if _, err := BuildPinnedProbeTLSConfig("deadbeef", false); err == nil {
		t.Fatal("expected invalid length error")
	}
}
