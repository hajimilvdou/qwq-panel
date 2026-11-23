// SPDX-License-Identifier: AGPL-3.0-only
//go:build !linux

package main

func readRootDiskUsage() (total, used uint64) {
	return 0, 0
}

func readProcNetConns() (tcp, udp uint32) {
	return 0, 0
}
