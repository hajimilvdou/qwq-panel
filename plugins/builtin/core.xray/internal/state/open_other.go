// SPDX-License-Identifier: AGPL-3.0-only

//go:build !linux

package state

import "os"

// 非 Linux 平台不恢复运行快照；支持平台由部署契约限定。
func openSnapshotFile(*os.Root, string) (*os.File, error) { return nil, ErrCorrupt }
