// SPDX-License-Identifier: AGPL-3.0-only

package sandbox

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// ======================== 句柄相对IO：专用目录0700，记录必须root/0600/普通文件/nlink1 ========================

func checkGenerationRecordDirectory(info fs.FileInfo) error {
	uid, ok := FileOwner(info)
	if !ok || uid != 0 || info.Mode() != fs.ModeDir|0o700 {
		return ErrGenerationRecord
	}
	return nil
}

func checkGenerationRecordFile(info fs.FileInfo) error {
	links, uid, ok := FileLinks(info)
	if !ok || uid != 0 || links != 1 || info.Mode() != 0o600 || info.Size() <= 0 || info.Size() > MaxGenerationMessage {
		return ErrGenerationRecord
	}
	return nil
}

func openCheckedGenerationRecordRoot(directory string, opener func(string) (*os.Root, error)) (*os.Root, error) {
	root, err := opener(directory)
	if err != nil {
		return nil, err
	}
	info, err := root.Stat(".")
	if err == nil {
		err = checkGenerationRecordDirectory(info)
	}
	if err != nil {
		return nil, errors.Join(err, root.Close())
	}
	return root, nil
}

// prepareGenerationRecordRoot 只从已可信的现有祖先创建新目录；不修复不可信旧目录。
func prepareGenerationRecordRoot(directory string, opener func(string) (*os.Root, error)) (root *os.Root, err error) {
	root, err = openCheckedGenerationRecordRoot(directory, opener)
	if err == nil || !errors.Is(err, fs.ErrNotExist) {
		return root, err
	}
	ancestor := filepath.Dir(directory)
	for {
		_, inspectErr := os.Lstat(ancestor)
		if inspectErr == nil {
			break
		}
		if !errors.Is(inspectErr, fs.ErrNotExist) {
			return nil, inspectErr
		}
		next := filepath.Dir(ancestor)
		if next == ancestor {
			return nil, inspectErr
		}
		ancestor = next
	}
	parent, err := opener(ancestor)
	if err != nil {
		return nil, err
	}
	defer func() {
		if closeErr := parent.Close(); closeErr != nil {
			err = errors.Join(err, closeErr)
			if root != nil {
				err = errors.Join(err, root.Close())
				root = nil
			}
		}
	}()
	relative, err := filepath.Rel(ancestor, directory)
	if err != nil || !filepath.IsLocal(relative) {
		return nil, errors.Join(ErrGenerationRecord, err)
	}
	prefix := "."
	for _, part := range strings.Split(relative, string(os.PathSeparator)) {
		prefix = filepath.Join(prefix, part)
		info, inspectErr := parent.Lstat(prefix)
		if errors.Is(inspectErr, fs.ErrNotExist) {
			if err := MkdirAllIn(parent, prefix, 0o700); err != nil {
				return nil, err
			}
			if err := SyncIn(parent, filepath.Dir(prefix)); err != nil {
				return nil, err
			}
			info, inspectErr = parent.Lstat(prefix)
		}
		if inspectErr != nil {
			return nil, inspectErr
		}
		if checkGenerationRecordDirectory(info) != nil {
			return nil, ErrGenerationRecord
		}
	}
	return openCheckedGenerationRecordRoot(directory, opener)
}

// syncGenerationRecordAncestors 仅在startup补齐祖先目录项；上次mkdir/fsync失败留下的目录不能跳过。
func syncGenerationRecordAncestors(directory string, opener func(string) (*os.Root, error), stopAt string) error {
	stop := "/"
	if stopAt != "" {
		stop = filepath.Clean(stopAt)
	}
	for current := directory; ; current = filepath.Dir(current) {
		root, err := opener(current)
		if err != nil {
			return err
		}
		if err := errors.Join(SyncIn(root, "."), root.Close()); err != nil {
			return err
		}
		if current == stop || current == filepath.Dir(current) {
			return nil
		}
	}
}

func (store *GenerationRecordStore) readRecord(name string) (record generationStoredRecord, exists bool, err error) {
	before, err := store.root.Lstat(name)
	if errors.Is(err, fs.ErrNotExist) {
		return generationStoredRecord{}, false, nil
	}
	if err != nil {
		return generationStoredRecord{}, false, fmt.Errorf("%w: inspect: %w", ErrGenerationRecord, err)
	}
	if checkGenerationRecordFile(before) != nil {
		return generationStoredRecord{}, false, ErrGenerationRecord
	}
	file, err := openGenerationRecordFile(store.root, name)
	if err != nil {
		return generationStoredRecord{}, false, fmt.Errorf("%w: open: %w", ErrGenerationRecord, err)
	}
	defer func() { err = errors.Join(err, file.Close()) }()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(before, opened) || checkGenerationRecordFile(opened) != nil {
		return generationStoredRecord{}, false, errors.Join(ErrGenerationRecord, err)
	}
	raw, err := io.ReadAll(io.LimitReader(file, MaxGenerationMessage+1))
	defer clear(raw)
	if err != nil || int64(len(raw)) != opened.Size() || len(raw) > MaxGenerationMessage {
		return generationStoredRecord{}, false, errors.Join(ErrGenerationRecord, err)
	}
	after, err := file.Stat()
	if err != nil || !os.SameFile(opened, after) || checkGenerationRecordFile(after) != nil || after.Size() != int64(len(raw)) {
		return generationStoredRecord{}, false, errors.Join(ErrGenerationRecord, err)
	}
	record, err = decodeGenerationStoredRecord(raw)
	return record, err == nil, err
}

func (store *GenerationRecordStore) persistRecord(ctx context.Context, name string, record generationStoredRecord) error {
	if err := generationRecordContextError(ctx, store.stopping); err != nil {
		return err
	}
	raw, err := encodeGenerationStoredRecord(record)
	if err != nil {
		return err
	}
	defer clear(raw)
	if err := store.io.writeAtomic(store.root, name, raw, 0o600); err != nil {
		return fmt.Errorf("sandbox: publishing generation record: %w", err)
	}
	if err := generationRecordContextError(ctx, store.stopping); err != nil {
		return err
	}
	stored, exists, err := store.readRecord(name)
	if err != nil || !exists {
		return errors.Join(ErrGenerationRecord, err)
	}
	verified, err := encodeGenerationStoredRecord(stored)
	defer clear(verified)
	if err != nil || !bytes.Equal(raw, verified) {
		return errors.Join(ErrGenerationRecord, err)
	}
	return generationRecordContextError(ctx, store.stopping)
}

// syncReplay 重新确保持久目录，不能把上次rename后的fsync失败当成成功重放。
func (store *GenerationRecordStore) syncReplay(ctx context.Context) error {
	if err := generationRecordContextError(ctx, store.stopping); err != nil {
		return err
	}
	if err := store.io.syncDirectory(store.root, "."); err != nil {
		return fmt.Errorf("sandbox: confirming generation record durability: %w", err)
	}
	return generationRecordContextError(ctx, store.stopping)
}
