// SPDX-License-Identifier: AGPL-3.0-only

//go:build linux

package consumerfiles

import (
	"bytes"
	"context"
	"errors"
	"os"

	"golang.org/x/sys/unix"

	"github.com/qwq-panel/qwq/internal/prerequisites/fault"
)

// ======================== current 与不可覆盖许可快照共用一次性文件发布 ========================

// publishMetadata 只由持有绑定锁的调用使用；目录边核验由固定 path 提供。
// replace 仅供 current 使用；许可快照始终 NOREPLACE。返回值说明 rename 是否已提交。
func (s *Store) publishMetadata(ctx context.Context, parent *os.File, destination string, raw []byte, replace bool,
	checkPath func(context.Context) error) (committed bool, failure error) {
	name, err := randomName(".metadata-")
	if err != nil {
		return false, err
	}
	temporary, err := s.writeExclusive(ctx, parent, name, raw)
	if temporary == nil {
		return false, err
	}
	defer temporary.Close()
	defer func() {
		if !committed {
			if err := s.removeOwnedMetadata(parent, name, temporary); err != nil {
				failure = errors.Join(failure, err)
			}
		}
	}()
	if err != nil {
		return false, err
	}
	observed, err := s.readFile(ctx, parent, name, maxMetadataBytes, false)
	if err != nil {
		return false, err
	}
	if !bytes.Equal(observed, raw) {
		return false, fault.New("CONSUMER_FILES_UNSAFE", "消费者临时元数据在发布前变化")
	}
	fd, err := unix.Openat(int(parent.Fd()), name, fileOpen, 0)
	if err != nil {
		return false, fault.New("CONSUMER_FILES_UNSAFE", "消费者临时元数据文件关联变化")
	}
	check := os.NewFile(uintptr(fd), "consumer-metadata-check")
	actual, first := s.fileStat(check, maxMetadataBytes, false)
	intended, second := s.fileStat(temporary, maxMetadataBytes, false)
	_ = check.Close()
	if first != nil || second != nil || !sameInode(actual, intended) {
		return false, fault.New("CONSUMER_FILES_UNSAFE", "消费者临时元数据 inode 被替换")
	}
	if err := checkPath(ctx); err != nil {
		return false, err
	}
	if err := checkContext(ctx); err != nil {
		return false, err
	}
	if replace {
		err = unix.Renameat(int(parent.Fd()), name, int(parent.Fd()), destination)
	} else {
		err = unix.Renameat2(int(parent.Fd()), name, int(parent.Fd()), destination, unix.RENAME_NOREPLACE)
	}
	if err != nil {
		if !replace && errors.Is(err, unix.EEXIST) {
			return false, fault.New("CONSUMER_FILES_CONFLICT", "消费者许可快照已被并发占用")
		}
		return false, fileFailure("CONSUMER_FILES_IO", "消费者元数据原子发布失败", false)
	}
	committed = true
	// 提交后完成 fsync 与目录围栏；取消不能把已经发生的 rename 伪装成未生效。
	if err := syncFile(parent, true); err != nil {
		return true, err
	}
	if err := checkPath(context.WithoutCancel(ctx)); err != nil {
		return true, fileFailure("CONSUMER_FILES_UNSAFE", "已发布元数据的目录关联变化，需要对账", true)
	}
	return true, nil
}

// removeOwnedMetadata 只删除仍关联本调用 O_EXCL FD 的临时文件；未完成 owner 移交也可安全收尾。
func (s *Store) removeOwnedMetadata(parent *os.File, name string, wanted *os.File) error {
	fd, err := unix.Openat(int(parent.Fd()), name, fileOpen, 0)
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	if err != nil {
		return fault.New("CONSUMER_FILES_UNSAFE", "消费者临时元数据在清理前被替换")
	}
	check := os.NewFile(uintptr(fd), "consumer-metadata-cleanup")
	var actual, expected unix.Stat_t
	first, second := unix.Fstat(fd, &actual), unix.Fstat(int(wanted.Fd()), &expected)
	_ = check.Close()
	if first != nil || second != nil || actual.Mode&unix.S_IFMT != unix.S_IFREG || actual.Nlink != 1 ||
		actual.Dev != s.identity.Dev || !sameInode(actual, expected) {
		return fault.New("CONSUMER_FILES_UNSAFE", "消费者临时元数据的清理身份不符")
	}
	if err := unix.Unlinkat(int(parent.Fd()), name, 0); err != nil {
		return fileFailure("CONSUMER_FILES_IO", "消费者临时元数据清理失败", false)
	}
	return syncFile(parent, false)
}
