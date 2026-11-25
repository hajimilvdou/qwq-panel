// SPDX-License-Identifier: AGPL-3.0-only

//go:build linux

package coreproc

import (
	"errors"
	"net"
	"os"
	"testing"
)

func fakeSocket(t *testing.T, fixture *processFixture) *net.UnixListener {
	t.Helper()
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: fixture.manager.options.Socket, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(fixture.manager.options.Socket, 0o600); err != nil {
		listener.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	return listener
}

func TestFakeProcessRefusesActiveUnmanagedSocket(t *testing.T) {
	fixture := fakeProcessFixture(t, "wait", nil)
	_ = fakeSocket(t, fixture)
	if err := fixture.manager.Start(t.Context(), fakeStartSpec(t)); !errors.Is(err, ErrAlreadyRunning) || fixture.commands.Load() != 0 {
		t.Fatal("manager replaced an active unmanaged socket")
	}
	if _, err := os.Lstat(fixture.manager.options.Socket); err != nil {
		t.Fatal("active socket was removed")
	}
}

func TestFakeProcessClearsOnlyPrivateStaleSocket(t *testing.T) {
	fixture := fakeProcessFixture(t, "wait", nil)
	listener := fakeSocket(t, fixture)
	listener.SetUnlinkOnClose(false)
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	if err := fixture.manager.Start(t.Context(), fakeStartSpec(t)); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(fixture.manager.options.Socket); !os.IsNotExist(err) {
		t.Fatal("private stale socket remained before start")
	}
}
