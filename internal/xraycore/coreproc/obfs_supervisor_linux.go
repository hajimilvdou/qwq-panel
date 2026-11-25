// SPDX-License-Identifier: AGPL-3.0-only

//go:build linux

package coreproc

import (
	"os/exec"
	"syscall"
)

// ======================== Linux 父进程退出联动终止属性 ========================

func setPlatformProcessAttrs(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGTERM}
}
