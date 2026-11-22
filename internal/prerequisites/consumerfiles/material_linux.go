// SPDX-License-Identifier: AGPL-3.0-only

//go:build linux

package consumerfiles

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"os"

	"golang.org/x/sys/unix"

	"github.com/qwq-panel/qwq/internal/prerequisites/fault"
	"github.com/qwq-panel/qwq/internal/tlsmgr"
)

// ======================== 单 inode、有界读取与完整 pair 核验 ========================

func (s *Store) fileStat(file *os.File, limit int64, allowUnlinked bool) (unix.Stat_t, error) {
	var stat unix.Stat_t
	if err := unix.Fstat(int(file.Fd()), &stat); err != nil {
		return stat, fileFailure("CONSUMER_FILES_IO", "消费者材料文件 FD 核验失败", false)
	}
	linksValid := stat.Nlink == 1 || (allowUnlinked && stat.Nlink == 0)
	if stat.Mode&unix.S_IFMT != unix.S_IFREG || !linksValid || stat.Dev != s.identity.Dev ||
		stat.Mode&0o7777 != materialMode || stat.Uid != s.identity.Uid || stat.Gid != s.identity.Gid ||
		stat.Size < 0 || stat.Size > limit {
		return stat, fault.New("CONSUMER_FILES_UNSAFE", "消费者材料文件的类型、链接数、属主、权限或长度不符")
	}
	return stat, nil
}

func (s *Store) readFile(ctx context.Context, parent *os.File, name string, limit int64, currentSnapshot bool) ([]byte, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	fd, err := unix.Openat(int(parent.Fd()), name, fileOpen, 0)
	if errors.Is(err, unix.ENOENT) {
		return nil, fault.New("NOT_FOUND", "消费者材料文件不存在")
	}
	if err != nil {
		return nil, fault.New("CONSUMER_FILES_UNSAFE", "消费者材料文件无法以 NOFOLLOW 打开")
	}
	file := os.NewFile(uintptr(fd), "consumer-material-read")
	defer file.Close()
	before, err := s.fileStat(file, limit, currentSnapshot)
	if err != nil {
		return nil, err
	}
	raw, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		clear(raw)
		return nil, fileFailure("CONSUMER_FILES_IO", "消费者材料文件读取失败", false)
	}
	after, err := s.fileStat(file, limit, currentSnapshot)
	// 原子替换 current 会令旧 FD 的 nlink 变为 0、ctime 更新；其已读快照仍可用。
	// generation 材料不允许这种例外，也不允许读取过程中发生原地写入。
	stable := before.Size == after.Size && before.Mtim == after.Mtim &&
		(before.Ctim == after.Ctim || (currentSnapshot && after.Nlink == 0))
	if err != nil || len(raw) > int(limit) || int64(len(raw)) != before.Size || !stable {
		clear(raw)
		return nil, fault.New("CONSUMER_FILES_UNSAFE", "消费者材料文件在读取期间变化或超过上限")
	}
	if err := checkContext(ctx); err != nil {
		clear(raw)
		return nil, err
	}
	return raw, nil
}

// readGenerationMaterial 只核同代材料，不产生许可；仅供 Stage 重用已发布材料或完整 Load 内部调用。
func (s *Store) readGenerationMaterial(ctx context.Context, generation *os.File, wanted Proof) (tlsmgr.Material, error) {
	if _, err := s.directoryStat(generation); err != nil {
		return tlsmgr.Material{}, err
	}
	raw, err := s.readFile(ctx, generation, materialName, maxMetadataBytes, false)
	if err != nil {
		return tlsmgr.Material{}, err
	}
	if err := decodeGeneration(raw, wanted); err != nil {
		return tlsmgr.Material{}, err
	}
	chain, err := s.readFile(ctx, generation, chainName, tlsmgr.MaxCertificatePEM, false)
	if err != nil {
		return tlsmgr.Material{}, err
	}
	key, err := s.readFile(ctx, generation, keyName, tlsmgr.MaxPrivateKeyPEM, false)
	if err != nil {
		return tlsmgr.Material{}, err
	}
	defer clear(key)
	if digest(chain) != wanted.FullchainSHA256 || digest(key) != wanted.PrivateKeySHA256 {
		return tlsmgr.Material{}, fault.New("CONSUMER_FILES_CONFLICT", "消费者材料摘要与宿主证明不符")
	}
	if err := validatePair(wanted.Binding, chain, key); err != nil {
		return tlsmgr.Material{}, err
	}
	if err := checkContext(ctx); err != nil {
		return tlsmgr.Material{}, err
	}
	return tlsmgr.NewMaterial(chain, key)
}

func (s *Store) readCurrent(ctx context.Context, binding *os.File, bindingID string) (*currentMetadata, error) {
	raw, err := s.readFile(ctx, binding, currentName, maxMetadataBytes, true)
	if fault.Code(err) == "NOT_FOUND" {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return decodeCurrent(raw, bindingID)
}

// Current 只返回本次 FD 快照中的文件事实；nil 只表示目录或 current.json 确实不存在。
func (s *Store) Current(ctx context.Context, bindingID string) (*Proof, error) {
	path, err := s.openBinding(ctx, bindingID, false)
	if fault.Code(err) == "NOT_FOUND" {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer path.close()
	metadata, err := s.readCurrent(ctx, path.last(), bindingID)
	if err != nil || metadata == nil {
		return nil, err
	}
	if err := path.check(ctx); err != nil {
		return nil, err
	}
	return copyProof(&metadata.Active), nil
}

// Load 必须接收来自宿主可信账本的 wanted，固定代目录 FD 后读取完整 pair。
// current.json 不参与材料选择；两份材料的摘要与完整 HostBinding 都必须相符。
func (s *Store) Load(ctx context.Context, wanted Proof) (tlsmgr.Material, error) {
	if err := validateProof(wanted); err != nil {
		return tlsmgr.Material{}, err
	}
	path, err := s.openBinding(ctx, wanted.Binding.ID, false)
	if err != nil {
		return tlsmgr.Material{}, err
	}
	defer path.close()
	if _, err := path.child(ctx, "generations", false); err != nil {
		return tlsmgr.Material{}, err
	}
	generation, err := path.child(ctx, generationName(wanted.Binding.Generation), false)
	if err != nil {
		return tlsmgr.Material{}, err
	}
	material, err := s.readMaterial(ctx, generation, wanted)
	if err != nil {
		return tlsmgr.Material{}, err
	}
	if err := path.check(ctx); err != nil {
		material.Clear()
		return tlsmgr.Material{}, err
	}
	return material, nil
}

// ======================== 新文件与新 generation 的一次性发布 ========================

func randomName(prefix string) (string, error) {
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return "", fileFailure("CONSUMER_FILES_IO", "消费者材料临时名称生成失败", false)
	}
	return prefix + hex.EncodeToString(nonce[:]), nil
}

func (s *Store) writeExclusive(ctx context.Context, parent *os.File, name string, raw []byte) (*os.File, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	fd, err := unix.Openat(int(parent.Fd()), name,
		unix.O_RDWR|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, materialMode)
	if err != nil {
		return nil, fileFailure("CONSUMER_FILES_IO", "消费者材料新文件独占创建失败", false)
	}
	file := os.NewFile(uintptr(fd), "consumer-material-write")
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Nlink != 1 ||
		stat.Uid != uint32(os.Geteuid()) || stat.Dev != s.identity.Dev || stat.Size != 0 {
		return file, fault.New("CONSUMER_FILES_UNSAFE", "消费者新材料文件不是 writer 持有的独占空文件")
	}
	if count, err := file.Write(raw); err != nil || count != len(raw) {
		return file, fileFailure("CONSUMER_FILES_IO", "消费者材料文件未完整写入", false)
	}
	if err := checkContext(ctx); err != nil {
		return file, err
	}
	if err := s.finishNewOwner(file, false); err != nil {
		return file, err
	}
	return file, nil
}

func (s *Store) writeStageFile(ctx context.Context, parent *os.File, name string, raw []byte) error {
	file, err := s.writeExclusive(ctx, parent, name, raw)
	if file != nil {
		defer file.Close()
	}
	if err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return fileFailure("CONSUMER_FILES_IO", "消费者材料新文件关闭失败", false)
	}
	return nil
}

func (s *Store) newStageDirectory(parent *os.File, name string) (result *os.File, failure error) {
	if err := unix.Mkdirat(int(parent.Fd()), name, directoryMode); err != nil {
		return nil, fileFailure("CONSUMER_FILES_IO", "消费者材料临时代目录创建失败", false)
	}
	defer func() {
		if result == nil {
			if err := unix.Unlinkat(int(parent.Fd()), name, unix.AT_REMOVEDIR); err != nil && !errors.Is(err, unix.ENOENT) {
				failure = errors.Join(failure, fileFailure("CONSUMER_FILES_IO", "消费者空临时代目录创建失败后清理失败", false))
			}
		}
	}()
	fd, err := unix.Openat(int(parent.Fd()), name, directoryOpen, 0)
	if err != nil {
		return nil, fault.New("CONSUMER_FILES_UNSAFE", "消费者材料临时代目录无法安全固定")
	}
	file := os.NewFile(uintptr(fd), "consumer-generation-stage")
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFDIR ||
		stat.Uid != uint32(os.Geteuid()) || stat.Dev != s.identity.Dev || stat.Nlink == 0 {
		_ = file.Close()
		return nil, fault.New("CONSUMER_FILES_UNSAFE", "消费者材料临时代目录未由当前 writer 持有")
	}
	if entries, err := file.ReadDir(1); !errors.Is(err, io.EOF) || len(entries) != 0 {
		_ = file.Close()
		return nil, fault.New("CONSUMER_FILES_UNSAFE", "消费者材料临时代目录不是新空目录")
	}
	if err := unix.Fchmod(fd, directoryMode); err != nil {
		_ = file.Close()
		return nil, fileFailure("CONSUMER_FILES_IO", "消费者材料临时代目录权限设置失败", false)
	}
	return file, nil
}

// cleanupStage 只删除本次随机临时代目录中的固定材料和首个许可，再移除空目录。
// 不遍历、不递归、不接受调用方路径；成功发布的 generation 永远不由这里删除。
func (s *Store) cleanupStage(parent *os.File, name string, directory *os.File, snapshotName string) error {
	for _, fileName := range []string{chainName, keyName, materialName} {
		if err := unix.Unlinkat(int(directory.Fd()), fileName, 0); err != nil && !errors.Is(err, unix.ENOENT) {
			return fileFailure("CONSUMER_FILES_IO", "消费者材料临时文件清理失败", false)
		}
	}
	if err := s.removeInitialProofs(directory, snapshotName); err != nil {
		return err
	}
	fd, err := unix.Openat(int(parent.Fd()), name, directoryOpen, 0)
	if err != nil {
		return fault.New("CONSUMER_FILES_UNSAFE", "消费者材料临时代目录在清理前被替换")
	}
	file := os.NewFile(uintptr(fd), "consumer-stage-cleanup-check")
	var actual, expected unix.Stat_t
	first, second := unix.Fstat(fd, &actual), unix.Fstat(int(directory.Fd()), &expected)
	_ = file.Close()
	if first != nil || second != nil || !sameInode(actual, expected) {
		return fault.New("CONSUMER_FILES_UNSAFE", "消费者材料临时代目录身份在清理前变化")
	}
	if err := unix.Unlinkat(int(parent.Fd()), name, unix.AT_REMOVEDIR); err != nil {
		return fileFailure("CONSUMER_FILES_IO", "消费者材料临时代目录清理失败", false)
	}
	return syncFile(parent, false)
}
