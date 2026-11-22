// SPDX-License-Identifier: AGPL-3.0-only

//go:build !unix

package sandbox

import "io/fs"

// FileOwner 在没有 uid 的平台上一律失败：可信根只在 Linux 上有意义，
// 这里保证 fail-closed 而不是放行。
func FileOwner(fs.FileInfo) (int, bool) { return 0, false }

// FileLinks 在没有 inode 信息的平台上一律失败（fail-closed）。
func FileLinks(fs.FileInfo) (uint64, int, bool) { return 0, 0, false }
