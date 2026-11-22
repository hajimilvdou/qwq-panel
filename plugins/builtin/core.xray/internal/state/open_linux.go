// SPDX-License-Identifier: AGPL-3.0-only

package state

import (
	"os"
	"syscall"
)

func openSnapshotFile(root *os.Root, name string) (*os.File, error) {
	return root.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
}
