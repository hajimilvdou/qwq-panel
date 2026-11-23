// SPDX-License-Identifier: AGPL-3.0-only

//go:build !unix

package account

import (
	"errors"
	"os"
)

func openSSHDirNoFollow(root *os.Root) (*os.File, error) {
	info, err := root.Lstat(".ssh")
	if err != nil {
		return nil, err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("account: .ssh is not a regular directory")
	}
	return root.Open(".ssh")
}
