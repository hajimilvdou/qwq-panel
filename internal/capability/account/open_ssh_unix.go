// SPDX-License-Identifier: AGPL-3.0-only

//go:build unix

package account

import (
	"os"
	"syscall"
)

func openSSHDirNoFollow(root *os.Root) (*os.File, error) {
	return root.OpenFile(".ssh", os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
}
