// SPDX-License-Identifier: AGPL-3.0-only

//go:build linux

package hostsvc

import (
	"errors"
	"os"
	"os/exec"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

func TestPeerHandleVerifyAlivePollSemantics(t *testing.T) {
	// 1. Live process (current process) must pass verifyAlive without EPERM.
	selfFD, err := unix.PidfdOpen(os.Getpid(), 0)
	if errors.Is(err, syscall.ENOSYS) {
		t.Skip("kernel does not support pidfd_open")
	}
	if err != nil {
		t.Fatalf("PidfdOpen(self): %v", err)
	}
	live := &peerHandle{pidfd: selfFD}
	defer live.close()
	if err := live.verifyAlive(); err != nil {
		t.Fatalf("verifyAlive on live process failed: %v", err)
	}

	// 2. Exited child process must be rejected by verifyAlive (POLLIN set).
	cmd := exec.Command("/bin/sh", "-c", "sleep 0.2")
	if err := cmd.Start(); err != nil {
		t.Fatalf("start child: %v", err)
	}
	childFD, err := unix.PidfdOpen(cmd.Process.Pid, 0)
	if err != nil {
		_ = cmd.Wait()
		t.Fatalf("PidfdOpen(child): %v", err)
	}
	dead := &peerHandle{pidfd: childFD}
	defer dead.close()

	if err := dead.verifyAlive(); err != nil {
		_ = cmd.Wait()
		t.Fatalf("verifyAlive on running child failed: %v", err)
	}
	if err := cmd.Wait(); err != nil {
		t.Fatalf("wait child: %v", err)
	}
	if err := dead.verifyAlive(); err == nil {
		t.Fatal("verifyAlive unexpectedly succeeded after child process exited")
	}
}
