// SPDX-License-Identifier: AGPL-3.0-only

//go:build linux

package consumerfiles

import (
	"context"
	"errors"
	"os"

	"golang.org/x/sys/unix"

	"github.com/qwq-panel/qwq/internal/prerequisites/fault"
	"github.com/qwq-panel/qwq/internal/tlsmgr"
)

// ======================== 材料代与完整许可快照分别核验，磁盘记录不授予权限 ========================

func (s *Store) readMaterial(ctx context.Context, generation *os.File, wanted Proof) (tlsmgr.Material, error) {
	proofs, err := s.openDirectory(ctx, generation, proofsName, false)
	if err != nil {
		return tlsmgr.Material{}, err
	}
	defer proofs.Close()
	raw, err := s.readFile(ctx, proofs, proofSnapshotName(wanted), maxMetadataBytes, false)
	if err != nil {
		return tlsmgr.Material{}, err
	}
	if err := decodeProof(raw, wanted); err != nil {
		return tlsmgr.Material{}, err
	}
	material, err := s.readGenerationMaterial(ctx, generation, wanted)
	if err != nil {
		return tlsmgr.Material{}, err
	}
	if err := s.directoryLink(generation, proofsName, proofs); err != nil {
		material.Clear()
		return tlsmgr.Material{}, err
	}
	return material, nil
}

// ensureProof 由已持有绑定锁、且 path 末端已固定 proofs 目录的 Stage 调用。
// 同代新许可只新增完整 Proof，不改链、私钥或 material.json。
func (s *Store) ensureProof(ctx context.Context, path *directoryPath, wanted Proof) error {
	name := proofSnapshotName(wanted)
	raw, err := s.readFile(ctx, path.last(), name, maxMetadataBytes, false)
	if err == nil {
		if err := decodeProof(raw, wanted); err != nil {
			return err
		}
		if err := path.check(ctx); err != nil {
			return err
		}
		return syncFile(path.last(), true)
	}
	if fault.Code(err) != "NOT_FOUND" {
		return err
	}
	raw, err = encodeMetadata(proofMetadata{Version: metadataVersion, Proof: wanted})
	if err != nil {
		return err
	}
	_, err = s.publishMetadata(ctx, path.last(), name, raw, false, path.check)
	return err
}

// writeInitialProof 只用于尚未移交、尚未发布的临时代；首个许可随整代一次发布。
func (s *Store) writeInitialProof(ctx context.Context, generation *os.File, wanted Proof) error {
	proofs, err := s.openDirectory(ctx, generation, proofsName, true)
	if err != nil {
		return err
	}
	defer proofs.Close()
	raw, err := encodeMetadata(proofMetadata{Version: metadataVersion, Proof: wanted})
	if err != nil {
		return err
	}
	if err := s.writeStageFile(ctx, proofs, proofSnapshotName(wanted), raw); err != nil {
		return err
	}
	// 首个文件新增后同步其直接父目录；同步 generation 不能替代这一级目录项持久化。
	return syncFile(proofs, false)
}

// removeInitialProofs 只清理本次临时代内那个确定许可文件及空 proofs 目录，不递归。
// 初始化中途 owner 移交失败时，目录仍可由 writer 持有；已有正常代不会调用它。
func (s *Store) removeInitialProofs(generation *os.File, snapshotName string) error {
	fd, err := unix.Openat(int(generation.Fd()), proofsName, directoryOpen, 0)
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	if err != nil {
		return fault.New("CONSUMER_FILES_UNSAFE", "消费者首个许可目录无法安全清理")
	}
	proofs := os.NewFile(uintptr(fd), "consumer-initial-proof-cleanup")
	defer proofs.Close()
	var actual, linked unix.Stat_t
	if err := unix.Fstat(fd, &actual); err != nil {
		return fileFailure("CONSUMER_FILES_IO", "消费者首个许可目录清理核验失败", false)
	}
	ownerValid := (actual.Uid == s.identity.Uid && actual.Gid == s.identity.Gid) ||
		(actual.Uid == uint32(os.Geteuid()) && actual.Gid == uint32(os.Getegid()))
	if actual.Mode&unix.S_IFMT != unix.S_IFDIR || actual.Nlink == 0 || actual.Dev != s.identity.Dev ||
		actual.Mode&0o7777 != directoryMode || !ownerValid {
		return fault.New("CONSUMER_FILES_UNSAFE", "消费者首个许可目录的清理身份不符")
	}
	if err := unix.Unlinkat(fd, snapshotName, 0); err != nil && !errors.Is(err, unix.ENOENT) {
		return fileFailure("CONSUMER_FILES_IO", "消费者首个许可文件清理失败", false)
	}
	if err := unix.Fstatat(int(generation.Fd()), proofsName, &linked, unix.AT_SYMLINK_NOFOLLOW); err != nil ||
		linked.Mode&unix.S_IFMT != unix.S_IFDIR || !sameInode(actual, linked) {
		return fault.New("CONSUMER_FILES_UNSAFE", "消费者首个许可目录在清理前被替换")
	}
	if err := unix.Unlinkat(int(generation.Fd()), proofsName, unix.AT_REMOVEDIR); err != nil {
		return fileFailure("CONSUMER_FILES_IO", "消费者首个许可空目录清理失败", false)
	}
	return nil
}
