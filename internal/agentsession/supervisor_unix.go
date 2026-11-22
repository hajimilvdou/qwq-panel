// SPDX-License-Identifier: AGPL-3.0-only

//go:build unix

package agentsession

import (
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"syscall"
	"time"
)

// resolveChildCredentials determines the non-root UID/GID for an external CLI
// child process. When the host runs as root (euid == 0) and no explicit
// RunAsUID/RunAsGID is configured, it automatically drops to the unprivileged
// `nobody` account (or 65534:65534) so an external CLI cannot read 0600
// root-owned host files even by absolute path.
func resolveChildCredentials(runAsUID, runAsGID *uint32) (*uint32, *uint32) {
	if runAsUID != nil && runAsGID != nil {
		return runAsUID, runAsGID
	}
	if os.Geteuid() != 0 {
		return nil, nil
	}
	uid := uint32(65534)
	gid := uint32(65534)
	if u, err := user.Lookup("nobody"); err == nil {
		if parsedUID, err := strconv.ParseUint(u.Uid, 10, 32); err == nil && parsedUID > 0 {
			uid = uint32(parsedUID)
		}
		if parsedGID, err := strconv.ParseUint(u.Gid, 10, 32); err == nil && parsedGID > 0 {
			gid = uint32(parsedGID)
		}
	}
	return &uid, &gid
}

func configureChildProcess(cmd *exec.Cmd, runAsUID, runAsGID *uint32) {
	uid, gid := resolveChildCredentials(runAsUID, runAsGID)
	attr := &syscall.SysProcAttr{
		Setpgid: true,
	}
	if uid != nil && gid != nil {
		attr.Credential = &syscall.Credential{
			Uid:    *uid,
			Gid:    *gid,
			Groups: []uint32{},
		}
	}
	cmd.SysProcAttr = attr
}

// chownIsolatedHome hands ownership of the ephemeral 0700 temp home tree to
// the dropped unprivileged UID/GID so the child can use its private HOME while
// remaining blocked from host 0600 files.
func chownIsolatedHome(root string, runAsUID, runAsGID *uint32) error {
	uid, gid := resolveChildCredentials(runAsUID, runAsGID)
	if uid == nil || gid == nil {
		return nil
	}
	// Ensure parent /tmp traversal works while keeping isolatedHome itself 0700
	// owned exclusively by the child UID/GID.
	return filepath.WalkDir(root, func(p string, _ os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		return os.Chown(p, int(*uid), int(*gid))
	})
}

func signalProcessGroup(pid int, kill bool) error {
	if pid <= 0 {
		return nil
	}
	sig := syscall.SIGTERM
	if kill {
		sig = syscall.SIGKILL
	}
	err := syscall.Kill(-pid, sig)
	if err == syscall.ESRCH {
		return nil
	}
	return err
}

// reapProcessGroup sends SIGKILL to the entire process group (-pid) and polls
// until the kernel confirms no member of the process group remains alive
// (ESRCH) or timeout expires. This guarantees surviving descendants are gone
// even when the main PID exited early.
func reapProcessGroup(pid int, timeout time.Duration) {
	if pid <= 0 {
		return
	}
	_ = signalProcessGroup(pid, true)
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if err := syscall.Kill(-pid, 0); err == syscall.ESRCH {
			return
		}
		_ = signalProcessGroup(pid, true)
		time.Sleep(15 * time.Millisecond)
	}
}
