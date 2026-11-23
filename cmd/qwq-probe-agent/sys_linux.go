// SPDX-License-Identifier: AGPL-3.0-only
//go:build linux

package main

import (
	"bytes"
	"os"
	"syscall"
)

func readRootDiskUsage() (total, used uint64) {
	var st syscall.Statfs_t
	if err := syscall.Statfs("/", &st); err != nil {
		return 0, 0
	}
	bsize := uint64(st.Bsize)
	total = st.Blocks * bsize
	avail := st.Bfree * bsize
	if total >= avail {
		used = total - avail
	}
	return total, used
}

func readProcNetConns() (tcp, udp uint32) {
	tcp = countProcNetTable("/proc/net/tcp") + countProcNetTable("/proc/net/tcp6")
	udp = countProcNetTable("/proc/net/udp") + countProcNetTable("/proc/net/udp6")
	return tcp, udp
}

func countProcNetTable(path string) uint32 {
	raw, err := os.ReadFile(path)
	if err != nil || len(raw) == 0 {
		return 0
	}
	lines := bytes.Count(raw, []byte{'\n'})
	if lines <= 1 {
		return 0
	}
	return uint32(lines - 1)
}
