// SPDX-License-Identifier: AGPL-3.0-only

//go:build unix

package sandbox

import (
	"io/fs"
	"syscall"
)

// FileOwner 返回 fi 的属主 uid；拿不到 Stat_t 时 ok 为 false。
func FileOwner(fi fs.FileInfo) (uid int, ok bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return int(st.Uid), true
}

// FileLinks 返回 fi 的硬链接数与属主 uid；拿不到 Stat_t 时 ok 为 false。
func FileLinks(fi fs.FileInfo) (nlink uint64, uid int, ok bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, false
	}
	return uint64(st.Nlink), int(st.Uid), true
}
