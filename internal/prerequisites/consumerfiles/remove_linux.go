// SPDX-License-Identifier: AGPL-3.0-only

//go:build linux

package consumerfiles

import (
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"os"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/qwq-panel/qwq/internal/prerequisites/fault"
	"github.com/qwq-panel/qwq/internal/tlsmgr"
)

// ======================== 受限、逐项核验的绑定材料清理 ========================

const maxRemoveEntries = 1024

// Remove 幂等清理单个绑定目录下的已知材料、许可快照与空目录，绝不跨出绑定目录。
// 任何软链接、异常属主/权限、硬链接或未知文件都会以 CONSUMER_FILES_UNSAFE 中止。
func (s *Store) Remove(ctx context.Context, bindingID string) error {
	if !bindingIDValid(bindingID) {
		return fault.New("CONSUMER_FILES_INVALID", "消费者绑定 ID 不是单个安全路径分量")
	}
	path, err := s.begin(ctx)
	if err != nil {
		return err
	}
	defer path.close()
	// 先取根 FD 外锁再逐层打开并取绑定内锁；与 openBinding(create=true) 锁序一致，无死锁。
	if err := lockBinding(ctx, path.files[0]); err != nil {
		return err
	}
	defer func() { _ = unix.Flock(int(path.files[0].Fd()), unix.LOCK_UN) }()
	for _, name := range []string{"tls", "bindings", bindingID} {
		if _, err := path.child(ctx, name, false); err != nil {
			if fault.Code(err) == "NOT_FOUND" {
				return nil
			}
			return err
		}
	}
	bindingsDir := path.files[len(path.files)-2]
	bindingDir := path.last()
	if err := lockBinding(ctx, bindingDir); err != nil {
		return err
	}
	defer func() { _ = unix.Flock(int(bindingDir.Fd()), unix.LOCK_UN) }()
	if err := path.check(ctx); err != nil {
		return err
	}
	entries, err := s.readBoundedNames(ctx, bindingDir)
	if err != nil {
		return err
	}
	for _, name := range entries {
		if name != currentName && name != "generations" {
			return fault.New("CONSUMER_FILES_UNSAFE", "消费者绑定目录包含未知条目")
		}
	}
	if err := s.removeVerifiedFile(ctx, bindingDir, currentName, maxMetadataBytes); err != nil {
		return err
	}
	if err := s.removeGenerations(ctx, bindingDir); err != nil {
		return err
	}
	if err := s.requireEmptyDirectory(ctx, bindingDir); err != nil {
		return err
	}
	if err := syncFile(bindingDir, false); err != nil {
		return err
	}
	if err := path.check(ctx); err != nil {
		return err
	}
	if err := unix.Unlinkat(int(bindingsDir.Fd()), bindingID, unix.AT_REMOVEDIR); err != nil {
		return fileFailure("CONSUMER_FILES_IO", "消费者绑定目录删除失败", false)
	}
	return syncFile(bindingsDir, true)
}

func (s *Store) removeGenerations(ctx context.Context, bindingDir *os.File) error {
	generations, err := s.openDirectory(ctx, bindingDir, "generations", false)
	if fault.Code(err) == "NOT_FOUND" {
		return nil
	}
	if err != nil {
		return err
	}
	defer generations.Close()
	names, err := s.readBoundedNames(ctx, generations)
	if err != nil {
		return err
	}
	for _, name := range names {
		if !isGenerationDirName(name) {
			return fault.New("CONSUMER_FILES_UNSAFE", "消费者 generations 目录包含未知条目")
		}
	}
	for _, name := range names {
		if err := s.removeGeneration(ctx, generations, name); err != nil {
			return err
		}
	}
	if err := s.requireEmptyDirectory(ctx, generations); err != nil {
		return err
	}
	if err := syncFile(generations, false); err != nil {
		return err
	}
	if err := s.directoryLink(bindingDir, "generations", generations); err != nil {
		return err
	}
	if err := unix.Unlinkat(int(bindingDir.Fd()), "generations", unix.AT_REMOVEDIR); err != nil {
		return fileFailure("CONSUMER_FILES_IO", "消费者 generations 目录删除失败", false)
	}
	return nil
}

func (s *Store) removeGeneration(ctx context.Context, generations *os.File, name string) error {
	generation, err := s.openDirectory(ctx, generations, name, false)
	if err != nil {
		return err
	}
	defer generation.Close()
	entries, err := s.readBoundedNames(ctx, generation)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if entry != chainName && entry != keyName && entry != materialName && entry != proofsName {
			return fault.New("CONSUMER_FILES_UNSAFE", "消费者 generation 目录包含未知条目")
		}
	}
	for _, item := range []struct {
		name  string
		limit int64
	}{
		{chainName, tlsmgr.MaxCertificatePEM},
		{keyName, tlsmgr.MaxPrivateKeyPEM},
		{materialName, maxMetadataBytes},
	} {
		if err := s.removeVerifiedFile(ctx, generation, item.name, item.limit); err != nil {
			return err
		}
	}
	if err := s.removeProofs(ctx, generation); err != nil {
		return err
	}
	if err := s.requireEmptyDirectory(ctx, generation); err != nil {
		return err
	}
	if err := syncFile(generation, false); err != nil {
		return err
	}
	if err := s.directoryLink(generations, name, generation); err != nil {
		return err
	}
	if err := unix.Unlinkat(int(generations.Fd()), name, unix.AT_REMOVEDIR); err != nil {
		return fileFailure("CONSUMER_FILES_IO", "消费者 generation 目录删除失败", false)
	}
	return nil
}

func (s *Store) removeProofs(ctx context.Context, generation *os.File) error {
	proofs, err := s.openDirectory(ctx, generation, proofsName, false)
	if fault.Code(err) == "NOT_FOUND" {
		return nil
	}
	if err != nil {
		return err
	}
	defer proofs.Close()
	names, err := s.readBoundedNames(ctx, proofs)
	if err != nil {
		return err
	}
	for _, name := range names {
		if !isProofFileName(name) {
			return fault.New("CONSUMER_FILES_UNSAFE", "消费者许可目录包含未知条目")
		}
	}
	for _, name := range names {
		if err := s.removeVerifiedFile(ctx, proofs, name, maxMetadataBytes); err != nil {
			return err
		}
	}
	if err := s.requireEmptyDirectory(ctx, proofs); err != nil {
		return err
	}
	if err := syncFile(proofs, false); err != nil {
		return err
	}
	if err := s.directoryLink(generation, proofsName, proofs); err != nil {
		return err
	}
	if err := unix.Unlinkat(int(generation.Fd()), proofsName, unix.AT_REMOVEDIR); err != nil {
		return fileFailure("CONSUMER_FILES_IO", "消费者许可目录删除失败", false)
	}
	return nil
}

// ======================== 单文件/空目录核验与名称白名单 ========================

func (s *Store) removeVerifiedFile(ctx context.Context, parent *os.File, name string, limit int64) error {
	if err := checkContext(ctx); err != nil {
		return err
	}
	fd, err := unix.Openat(int(parent.Fd()), name, fileOpen, 0)
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	if err != nil {
		return fault.New("CONSUMER_FILES_UNSAFE", "消费者材料文件无法以 NOFOLLOW 打开")
	}
	file := os.NewFile(uintptr(fd), "consumer-file-remove")
	stat, err := s.fileStat(file, limit, false)
	if err != nil {
		_ = file.Close()
		return err
	}
	var linked unix.Stat_t
	linkErr := unix.Fstatat(int(parent.Fd()), name, &linked, unix.AT_SYMLINK_NOFOLLOW)
	_ = file.Close()
	if linkErr != nil || linked.Mode&unix.S_IFMT != unix.S_IFREG || linked.Nlink != 1 ||
		linked.Dev != s.identity.Dev || linked.Mode&0o7777 != materialMode ||
		linked.Uid != s.identity.Uid || linked.Gid != s.identity.Gid || !sameInode(stat, linked) {
		return fault.New("CONSUMER_FILES_UNSAFE", "消费者材料文件在删除前被替换")
	}
	if err := unix.Unlinkat(int(parent.Fd()), name, 0); err != nil {
		return fileFailure("CONSUMER_FILES_IO", "消费者材料文件删除失败", false)
	}
	return nil
}

func (s *Store) readBoundedNames(ctx context.Context, dir *os.File) ([]string, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	fd, err := unix.Openat(int(dir.Fd()), ".", directoryOpen, 0)
	if err != nil {
		return nil, fileFailure("CONSUMER_FILES_IO", "无法读取消费者材料目录条目", false)
	}
	fresh := os.NewFile(uintptr(fd), "consumer-dir-list")
	defer fresh.Close()
	if _, err := s.directoryStat(fresh); err != nil {
		return nil, err
	}
	entries, err := fresh.ReadDir(maxRemoveEntries + 1)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, fileFailure("CONSUMER_FILES_IO", "消费者材料目录枚举失败", false)
	}
	if len(entries) > maxRemoveEntries {
		return nil, fault.New("CONSUMER_FILES_UNSAFE", "消费者材料目录条目数超过安全上限")
	}
	names := make([]string, len(entries))
	for index, entry := range entries {
		names[index] = entry.Name()
	}
	return names, nil
}

func (s *Store) requireEmptyDirectory(ctx context.Context, dir *os.File) error {
	if err := checkContext(ctx); err != nil {
		return err
	}
	fd, err := unix.Openat(int(dir.Fd()), ".", directoryOpen, 0)
	if err != nil {
		return fileFailure("CONSUMER_FILES_IO", "无法复核消费者材料目录已清空", false)
	}
	fresh := os.NewFile(uintptr(fd), "consumer-dir-empty")
	defer fresh.Close()
	if _, err := s.directoryStat(fresh); err != nil {
		return err
	}
	entries, err := fresh.ReadDir(1)
	if !errors.Is(err, io.EOF) || len(entries) != 0 {
		if err != nil && !errors.Is(err, io.EOF) {
			return fileFailure("CONSUMER_FILES_IO", "消费者材料目录清空检查失败", false)
		}
		return fault.New("CONSUMER_FILES_UNSAFE", "消费者材料目录存在未预期残留条目")
	}
	return nil
}

func isGenerationDirName(name string) bool {
	if !strings.HasPrefix(name, "g") || len(name) < 2 {
		return false
	}
	number, err := strconv.ParseUint(name[1:], 10, 64)
	return err == nil && number > 0 && generationName(number) == name
}

func isProofFileName(name string) bool {
	if len(name) != len("p-")+sha256.Size*2+len(".json") ||
		!strings.HasPrefix(name, "p-") || !strings.HasSuffix(name, ".json") {
		return false
	}
	return digestValid(name[len("p-") : len(name)-len(".json")])
}
