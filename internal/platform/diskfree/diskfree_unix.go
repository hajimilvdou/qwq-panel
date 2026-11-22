// SPDX-License-Identifier: AGPL-3.0-only

//go:build unix

// Package diskfree reports the free space of the filesystem that holds a
// directory. It backs the upload staging preflight (GW-07) and the
// pre-install disk capacity check (GAPS gap 4).
package diskfree

import "golang.org/x/sys/unix"

// Bytes reports the space available to unprivileged callers on the
// filesystem that holds dir.
func Bytes(dir string) (uint64, error) {
	var st unix.Statfs_t
	if err := unix.Statfs(dir, &st); err != nil {
		return 0, err
	}
	return uint64(st.Bavail) * uint64(st.Bsize), nil
}
