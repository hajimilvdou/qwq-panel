// SPDX-License-Identifier: AGPL-3.0-only
//go:build linux

package local

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

func ownedFile(info os.FileInfo, uid int) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && int(stat.Uid) == uid
}

// ======================== 跨进程资源锁 ========================
func (s FileState) Lock(ctx context.Context) (func(), error) {
	if ctx == nil || !validName(s.LockName) {
		return nil, errors.New("capability: lock configuration is invalid")
	}
	root, err := s.Trust.Open(s.LockDirectory)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	file, err := root.OpenFile(s.LockName, os.O_CREATE|os.O_RDWR|unix.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, err
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || !ownedFile(info, s.Trust.UID) || info.Mode().Perm() != 0600 {
		file.Close()
		return nil, errors.New("capability: lock file is not trusted")
	}
	for {
		if err := ctx.Err(); err != nil {
			file.Close()
			return nil, err
		}
		err = unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			return func() { _ = unix.Flock(int(file.Fd()), unix.LOCK_UN); _ = file.Close() }, nil
		}
		if !errors.Is(err, unix.EWOULDBLOCK) && !errors.Is(err, unix.EAGAIN) && !errors.Is(err, unix.EINTR) {
			file.Close()
			return nil, err
		}
		timer := time.NewTimer(20 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			file.Close()
			return nil, ctx.Err()
		case <-timer.C:
		}
	}
}

func (s FileState) open() (*os.Root, error) {
	if !validName(s.Name) {
		return nil, errors.New("capability: state file name is invalid")
	}
	return s.Trust.Open(s.Directory)
}

// Read 拒绝 symlink、不可信属主和过大文件；不存在与读取失败分别返回。
func (s FileState) Read() ([]byte, bool, error) {
	root, err := s.open()
	if err != nil {
		return nil, false, err
	}
	defer root.Close()
	file, err := root.OpenFile(s.Name, os.O_RDONLY|unix.O_NOFOLLOW, 0)
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || !ownedFile(info, s.Trust.UID) || info.Mode().Perm()&0022 != 0 || (s.Mode != 0 && info.Mode().Perm() != s.Mode) || info.Size() > 512<<10 {
		return nil, false, errors.New("capability: state file is not trusted")
	}
	raw, err := io.ReadAll(io.LimitReader(file, (512<<10)+1))
	if err != nil || len(raw) > 512<<10 {
		clear(raw)
		return nil, false, errors.New("capability: state file could not be read")
	}
	return raw, true, nil
}

// Commit 用 fsync/rename/目录 fsync 提交状态。nil 只用于恢复此前不存在的文件。
func (s FileState) Commit(raw []byte) error {
	if len(raw) > 512<<10 || (s.Mode != 0 && s.Mode != 0600 && s.Mode != 0644) {
		return errors.New("capability: state exceeds the limit")
	}
	root, err := s.open()
	if err != nil {
		return err
	}
	defer root.Close()
	if raw == nil {
		if err := root.Remove(s.Name); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return syncDirectory(root)
	}
	if info, err := root.Lstat(s.Name); err == nil {
		if !info.Mode().IsRegular() || !ownedFile(info, s.Trust.UID) || info.Mode().Perm()&0022 != 0 {
			return errors.New("capability: existing state file is not trusted")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return err
	}
	name := "." + s.Name + "." + hex.EncodeToString(nonce[:]) + ".tmp"
	mode := s.Mode
	if mode == 0 {
		mode = 0644
	}
	file, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL|unix.O_NOFOLLOW, mode)
	if err != nil {
		return err
	}
	defer func() { _ = file.Close(); _ = root.Remove(name) }()
	if n, err := file.Write(raw); err != nil || n != len(raw) {
		return errors.New("capability: state write failed")
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := root.Rename(name, s.Name); err != nil {
		return err
	}
	return syncDirectory(root)
}

func syncDirectory(root *os.Root) error {
	file, err := root.Open(".")
	if err != nil {
		return err
	}
	defer file.Close()
	return file.Sync()
}
