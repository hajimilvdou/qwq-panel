// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestNewPrivilegedHelper checks the states serve-controller can find at
// --privileged-socket. A non-root host always talks to the helper, even when
// the socket is not there yet (it may start later); only a root development
// host falls back to the in-process installer.
func TestNewPrivilegedHelper(t *testing.T) {
	logger := slog.New(slog.DiscardHandler)
	dir := t.TempDir()
	missing := filepath.Join(dir, "missing.sock")
	regular := filepath.Join(dir, "regular")
	if err := os.WriteFile(regular, []byte("not a socket"), 0o600); err != nil {
		t.Fatal(err)
	}
	socket := filepath.Join(dir, "helper.sock")
	ln, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }()

	// Non-root: a client for any configured path, an error for none.
	for _, path := range []string{missing, regular, socket} {
		helper, err := newPrivilegedHelper(path, 1000, logger)
		if err != nil || helper == nil || helper.Socket != path {
			t.Errorf("non-root newPrivilegedHelper(%s) = %+v, %v; want a client", path, helper, err)
		}
	}
	if helper, err := newPrivilegedHelper("", 1000, logger); err == nil || helper != nil {
		t.Errorf("non-root newPrivilegedHelper(empty) = %+v, %v; want an error", helper, err)
	}

	// Root development mode: only a real socket is used.
	for _, path := range []string{"", missing, regular} {
		if helper, err := newPrivilegedHelper(path, 0, logger); err != nil || helper != nil {
			t.Errorf("root newPrivilegedHelper(%q) = %+v, %v; want nil, nil", path, helper, err)
		}
	}
	helper, err := newPrivilegedHelper(socket, 0, logger)
	if err != nil || helper == nil || helper.Socket != socket {
		t.Fatalf("root newPrivilegedHelper(socket) = %+v, %v; want a client for %s", helper, err, socket)
	}
}

// TestServeControllerRejectsRelativePrivilegedSocket is a usage error before
// the configuration or the database is opened.
func TestServeControllerRejectsRelativePrivilegedSocket(t *testing.T) {
	var out, errb bytes.Buffer
	code := run([]string{
		"serve-controller",
		"--config", filepath.Join(t.TempDir(), "missing.json"),
		"--privileged-socket", "relative.sock",
	}, &out, &errb)
	if code != 2 {
		t.Fatalf("exit = %d, want 2 (stderr %q)", code, errb.String())
	}
	if !strings.Contains(errb.String(), "privileged-socket") {
		t.Fatalf("stderr = %q, want a --privileged-socket error", errb.String())
	}
}

// TestServeControllerRejectsRelativeStagingDir keeps the staging root and the
// helper's --staging-root from silently diverging.
func TestServeControllerRejectsRelativeStagingDir(t *testing.T) {
	var out, errb bytes.Buffer
	code := run([]string{
		"serve-controller",
		"--config", filepath.Join(t.TempDir(), "missing.json"),
		"--staging-dir", "relative/staging",
	}, &out, &errb)
	if code != 2 {
		t.Fatalf("exit = %d, want 2 (stderr %q)", code, errb.String())
	}
	if !strings.Contains(errb.String(), "staging-dir") {
		t.Fatalf("stderr = %q, want a --staging-dir error", errb.String())
	}
}
