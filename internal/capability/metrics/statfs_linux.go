// SPDX-License-Identifier: AGPL-3.0-only
//go:build linux

package metrics

import (
	"context"
	"errors"
	"math"

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
	if stat.Bsize <= 0 || stat.Bfree > stat.Blocks || stat.Blocks > math.MaxUint64/uint64(stat.Bsize) {
		return DiskUsage{}, errors.New("metrics: statfs 数据无效或溢出")
	}
	return DiskUsage{TotalBytes: stat.Blocks * uint64(stat.Bsize), UsedBytes: (stat.Blocks - stat.Bfree) * uint64(stat.Bsize)}, nil
}
