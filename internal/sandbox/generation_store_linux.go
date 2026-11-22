// SPDX-License-Identifier: AGPL-3.0-only

//go:build linux

package sandbox

import (
	"context"
	"errors"
	"os"
	"time"

	"golang.org/x/sys/unix"
)

// ======================== Linux文件门禁：拒绝符号链接，跨实例发布共用同一目录锁 ========================

func generationRecordPlatformAvailable() bool { return true }

func openGenerationRecordFile(root *os.Root, name string) (*os.File, error) {
	return root.OpenFile(name, os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
}

func lockGenerationRecordDirectory(ctx context.Context, stopping <-chan struct{}, root *os.Root) (func() error, error) {
	file, err := root.Open(".")
	if err != nil {
		return nil, err
	}
	info, err := file.Stat()
	if err != nil || checkGenerationRecordDirectory(info) != nil {
		return nil, errors.Join(ErrGenerationRecord, err, file.Close())
	}
	timer := time.NewTimer(10 * time.Millisecond)
	defer timer.Stop()
	for {
		if err = generationRecordContextError(ctx, stopping); err != nil {
			break
		}
		err = unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			return func() error {
				return errors.Join(unix.Flock(int(file.Fd()), unix.LOCK_UN), file.Close())
			}, nil
		}
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if !errors.Is(err, unix.EWOULDBLOCK) && !errors.Is(err, unix.EAGAIN) {
			break
		}
		timer.Reset(10 * time.Millisecond)
		select {
		case <-ctx.Done():
			err = ctx.Err()
		case <-stopping:
			err = ErrGenerationStoreClosed
		case <-timer.C:
			continue
		}
		break
	}
	return nil, errors.Join(err, file.Close())
}
