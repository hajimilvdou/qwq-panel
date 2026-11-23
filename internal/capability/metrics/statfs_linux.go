// SPDX-License-Identifier: AGPL-3.0-only
//go:build linux

package metrics

import (
	"context"

	"golang.org/x/sys/unix"
)

func defaultStatFS(ctx context.Context, path string) (DiskUsage, error) {
	if err := ctx.Err(); err != nil {
		return DiskUsage{}, err
	}
	var stat unix.Statfs_t
	if err := unix.Statfs(path, &stat); err != nil {
		return DiskUsage{}, err
	}
	return diskUsageFromStatfs(stat.Blocks, stat.Bfree, stat.Bavail, int64(stat.Bsize))
}
