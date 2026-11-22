// SPDX-License-Identifier: AGPL-3.0-only

package sandbox

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestCheckCompatPluginUnit(t *testing.T) {
	valid := []string{
		"qwq-plugin@noop.service",
		"qwq-plugin@noop.socket",
		"qwq-plugin@security.basic.service",
		"qwq-plugin@core.xray.socket",
		"qwq-plugin@a1-b2.c3.service",
	}
	for _, u := range valid {
		if err := CheckCompatPluginUnit(u); err != nil {
			t.Errorf("CheckCompatPluginUnit(%q) = %v, want nil", u, err)
		}
	}

	invalid := []string{
		"",
		"sshd.service",
		"qwq-controller.service",
		"qwq-privileged.service",
		"qwq-plugin@.service",
		"qwq-plugin@../evil.service",
		"qwq-plugin@noop.timer",
		"qwq-plugin@Noop.service",
		"--help",
		"qwq-plugin@noop.service --force",
	}
	for _, u := range invalid {
		if err := CheckCompatPluginUnit(u); err == nil {
			t.Errorf("CheckCompatPluginUnit(%q) = nil, want error", u)
		}
	}
}

func TestCompatUnitctlClientExchangeAndShow(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("AF_UNIX helper tests require Unix")
	}
	dir, err := os.MkdirTemp("/tmp", "qwq-cu-")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	sock := filepath.Join(dir, "compat.sock")

	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	var gotReqs []CompatUnitctlRequest
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 4; i++ {
			conn, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			var req CompatUnitctlRequest
			if rerr := ReadHelperJSON(conn, &req); rerr != nil {
				_ = conn.Close()
				return
			}
			gotReqs = append(gotReqs, req)
			resp := CompatUnitctlResponse{OK: true, Version: "test-v1", UID: 0}
			_ = WriteHelperJSON(conn, resp)
			_ = conn.Close()
		}
	}()

	const showOut = "MainPID=42\nControlGroup=/system.slice/qwq-plugin@noop.service\nActiveState=active\nSubState=running\nFragmentPath=/etc/systemd/system/qwq-plugin@noop.service\n"
	fakeShow := &fakeRunner{reply: func(string, []string) (string, error) { return showOut, nil }}
	c := NewCompatUnitctlClient(sock, fakeShow)

	p, err := c.Ping(context.Background())
	if err != nil || p.Version != "test-v1" || p.UID != 0 {
		t.Fatalf("Ping = %+v, %v", p, err)
	}
	if err := c.Start(context.Background(), "qwq-plugin@noop.service"); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if err := c.Stop(context.Background(), "qwq-plugin@noop.service"); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if err := c.Kill(context.Background(), "qwq-plugin@noop.service"); err != nil {
		t.Fatalf("Kill: %v", err)
	}
	<-done

	if len(gotReqs) != 4 || gotReqs[1].Action != CompatUnitctlOpStart || gotReqs[2].Action != CompatUnitctlOpStop || gotReqs[3].Action != CompatUnitctlOpKill {
		t.Fatalf("requests = %+v", gotReqs)
	}

	// Non-plugin units must be rejected client-side before dialing.
	if err := c.Start(context.Background(), "sshd.service"); err == nil || !strings.Contains(err.Error(), "refuses unit") {
		t.Fatalf("Start(sshd.service) = %v, want refusal", err)
	}

	// Show stays direct unprivileged systemctl show.
	st, err := c.Show(context.Background(), "qwq-plugin@noop.service")
	if err != nil || st.MainPID != 42 || st.ActiveState != "active" {
		t.Fatalf("Show = %+v, %v", st, err)
	}
}

func TestCompatPolkitInstalled(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("AF_UNIX socket check requires Unix")
	}
	dir, err := os.MkdirTemp("/tmp", "qwq-cm-")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })

	marker := filepath.Join(dir, "polkit-compat.json")
	sock := filepath.Join(dir, "compat.sock")

	if CompatPolkitInstalled(marker, sock) {
		t.Fatal("expected false when neither marker nor socket exists")
	}
	if err := os.WriteFile(marker, []byte(`{"patch":"qwq-compat-polkit"}`), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if CompatPolkitInstalled(marker, sock) {
		t.Fatal("expected false when socket is missing")
	}
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	if !CompatPolkitInstalled(marker, sock) {
		t.Fatal("expected true when safe marker and Unix socket both exist")
	}
	if err := os.Chmod(marker, 0o666); err != nil {
		t.Fatalf("Chmod: %v", err)
	}
	if CompatPolkitInstalled(marker, sock) {
		t.Fatal("expected false when marker is group/world writable")
	}
}
