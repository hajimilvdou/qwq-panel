// SPDX-License-Identifier: AGPL-3.0-only

//go:build !linux

package coreproc

import "os/exec"

// ======================== 非 Linux 平台进程属性占位 ========================

func setPlatformProcessAttrs(*exec.Cmd) {}
