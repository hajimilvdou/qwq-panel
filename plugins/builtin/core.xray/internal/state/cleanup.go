// SPDX-License-Identifier: AGPL-3.0-only

package state

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"strconv"
	"strings"
	"syscall"

	"github.com/qwq-panel/qwq/internal/sandbox"
)

// Prune 只保留当前指针对应的两份配置；调用方须先确认旧/候选进程已回收。
func (s *Store) Prune(ctx context.Context, expected *Metadata) error {
	unlock, err := s.lock(ctx)
	if err != nil {
		return err
	}
	defer unlock()
	current, err := Load(ctx, s.directory)
	if err != nil {
		return err
	}
	if !samePointers(current, expected) {
		return ErrConflict
	}
	keep := map[string]bool{}
	if current != nil {
		keep[strings.TrimPrefix(current.Current.Digest, "sha256:")] = true
		if current.Previous != nil {
			keep[strings.TrimPrefix(current.Previous.Digest, "sha256:")] = true
		}
	}
	root, err := s.privateRoot()
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer root.Close()
	for _, name := range []string{"runtime", "runtime/generations"} {
		info, err := root.Lstat(name)
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		if err != nil || !privateDirectory(info) {
			return ErrCorrupt
		}
	}
	directory, err := root.Open("runtime/generations")
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return ErrDirectory
	}
	defer directory.Close()
	for seen := 0; ; {
		if err := ctx.Err(); err != nil {
			return err
		}
		entries, err := directory.ReadDir(32)
		if err != nil && !errors.Is(err, io.EOF) {
			return ErrDirectory
		}
		seen += len(entries)
		if seen > 1024 {
			return ErrDirectory
		}
		for _, entry := range entries {
			if err := ctx.Err(); err != nil {
				return err
			}
			if keep[entry.Name()] {
				continue
			}
			if !ValidDigest("sha256:" + entry.Name()) {
				return ErrCorrupt
			}
			name := "runtime/generations/" + entry.Name()
			info, infoErr := root.Lstat(name)
			if infoErr != nil || !privateDirectory(info) {
				return ErrCorrupt
			}
			if err := root.RemoveAll(name); err != nil {
				return ErrWrite
			}
		}
		if errors.Is(err, io.EOF) {
			break
		}
	}
	if err := sandbox.SyncIn(root, "runtime/generations"); err != nil {
		return ErrWrite
	}
	return nil
}

// CleanWork 只清理明确 operation/attempt，其他操作的工作文件保持独立。
func (s *Store) CleanWork(ctx context.Context, owner string, attempt uint32) error {
	if !validOwner(owner, attempt) {
		return ErrOwner
	}
	unlock, err := s.lock(ctx)
	if err != nil {
		return err
	}
	defer unlock()
	root, err := s.privateRoot()
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer root.Close()
	for _, parent := range []string{"work", "work/" + owner} {
		info, err := root.Lstat(parent)
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		if err != nil || !privateDirectory(info) {
			return ErrCorrupt
		}
	}
	name := workDirectory(owner, attempt)
	info, err := root.Lstat(name)
	if !errors.Is(err, fs.ErrNotExist) {
		if err != nil || !privateDirectory(info) {
			return ErrCorrupt
		}
		if err := root.RemoveAll(name); err != nil {
			return ErrWrite
		}
	}
	if err := sandbox.SyncIn(root, "work/"+owner); err != nil {
		return ErrWrite
	}
	// 空 owner 及时回收；仍有其他 attempt 时保留，重试也能清理历史空目录。
	if err := root.Remove("work/" + owner); err != nil && !errors.Is(err, fs.ErrNotExist) {
		if errors.Is(err, syscall.ENOTEMPTY) {
			return nil
		}
		return ErrWrite
	}
	if err := sandbox.SyncIn(root, "work"); err != nil {
		return ErrWrite
	}
	return nil
}

func samePointers(a, b *Metadata) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	if a.Current == nil || b.Current == nil || a.Current.Digest != b.Current.Digest {
		return false
	}
	if a.Previous == nil || b.Previous == nil {
		return a.Previous == nil && b.Previous == nil
	}
	return a.Previous.Digest == b.Previous.Digest
}

// CleanAbandonedWork 仅在实例尚未接受写事务的恢复入口使用，回收旧 operation/attempt。
func (s *Store) CleanAbandonedWork(ctx context.Context) error {
	unlock, err := s.lock(ctx)
	if err != nil {
		return err
	}
	defer unlock()
	root, err := s.privateRoot()
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer root.Close()
	info, err := root.Lstat("work")
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil || !privateDirectory(info) {
		return ErrCorrupt
	}
	// ========================================================================
	// 两次有界遍历：先校验所有 owner/attempt，再清理；不把目录数量当作故障。
	// ========================================================================
	if err := walkWorkEntries(ctx, root, "work", func(entry fs.DirEntry) error {
		if !validOwner(entry.Name(), 1) {
			return ErrOwner
		}
		name := "work/" + entry.Name()
		info, err := root.Lstat(name)
		if err != nil || !privateDirectory(info) {
			return ErrCorrupt
		}
		return walkWorkEntries(ctx, root, name, func(attempt fs.DirEntry) error {
			value, err := strconv.ParseUint(attempt.Name(), 10, 32)
			if err != nil || value == 0 || strconv.FormatUint(value, 10) != attempt.Name() {
				return ErrOwner
			}
			info, err := root.Lstat(name + "/" + attempt.Name())
			if err != nil || !privateDirectory(info) {
				return ErrCorrupt
			}
			return nil
		})
	}); err != nil {
		return err
	}
	if err := walkWorkEntries(ctx, root, "work", func(entry fs.DirEntry) error {
		if !validOwner(entry.Name(), 1) {
			return ErrOwner
		}
		name := "work/" + entry.Name()
		info, err := root.Lstat(name)
		if err != nil || !privateDirectory(info) {
			return ErrCorrupt
		}
		if root.RemoveAll(name) != nil {
			return ErrWrite
		}
		return nil
	}); err != nil {
		return err
	}
	if sandbox.SyncIn(root, "work") != nil {
		return ErrWrite
	}
	return nil
}

// walkWorkEntries 只保存一小批目录项，owner 与 attempt 复用同一读取/取消边界。
func walkWorkEntries(ctx context.Context, root *os.Root, name string, visit func(fs.DirEntry) error) error {
	directory, err := root.Open(name)
	if err != nil {
		return ErrDirectory
	}
	defer directory.Close()
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		entries, err := directory.ReadDir(32)
		if err != nil && !errors.Is(err, io.EOF) {
			return ErrDirectory
		}
		for _, entry := range entries {
			if err := ctx.Err(); err != nil {
				return err
			}
			if err := visit(entry); err != nil {
				return err
			}
		}
		if errors.Is(err, io.EOF) {
			return nil
		}
	}
}
