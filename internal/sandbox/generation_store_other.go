// SPDX-License-Identifier: AGPL-3.0-only

//go:build !linux

package sandbox

import (
	"context"
	"os"
)

// ======================== 非Linux平台失败安全，不模拟可信root记录 ========================

func generationRecordPlatformAvailable() bool { return false }

func openGenerationRecordFile(*os.Root, string) (*os.File, error) {
	return nil, ErrGenerationUnsupported
}

func lockGenerationRecordDirectory(context.Context, <-chan struct{}, *os.Root) (func() error, error) {
	return nil, ErrGenerationUnsupported
}
