// SPDX-License-Identifier: AGPL-3.0-only

//go:build !unix

package agentsession

import (
	"os/exec"
	"time"
)

func configureChildProcess(*exec.Cmd, *uint32, *uint32) {}

func chownIsolatedHome(string, *uint32, *uint32) error { return nil }

func signalProcessGroup(int, bool) error { return nil }

func reapProcessGroup(int, time.Duration) {}
