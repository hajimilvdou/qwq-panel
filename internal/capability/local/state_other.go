// SPDX-License-Identifier: AGPL-3.0-only
//go:build !linux

package local

import (
	"context"
	"errors"
	"os"
)

func ownedFile(os.FileInfo, int) bool { return false }
func (FileState) Lock(context.Context) (func(), error) {
	return nil, errors.New("capability: Linux is required")
}
func (FileState) Read() ([]byte, bool, error) {
	return nil, false, errors.New("capability: Linux is required")
}
func (FileState) Commit([]byte) error { return errors.New("capability: Linux is required") }
