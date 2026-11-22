// SPDX-License-Identifier: AGPL-3.0-only

package state

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/qwq-panel/qwq/internal/sandbox"
	"github.com/qwq-panel/qwq/sdk/coreapi"
)

// Load 只读取已提交指针，并核对 current/previous 的私有文件和摘要。
// 没有 state.json 时没有已提交配置；孤立 generation 永远不会成为恢复来源。
func Load(ctx context.Context, dataDir string) (*Metadata, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if dataDir == "" {
		return nil, nil
	}
	if !filepath.IsAbs(dataDir) || filepath.Clean(dataDir) != dataDir {
		return nil, ErrCorrupt
	}
	info, err := os.Lstat(dataDir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil || !privateDirectory(info) {
		return nil, ErrCorrupt
	}
	root, err := (sandbox.TrustPolicy{UID: os.Geteuid(), StopAt: dataDir}).Open(dataDir)
	if err != nil {
		return nil, ErrCorrupt
	}
	defer root.Close()
	info, err = root.Lstat("runtime")
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil || !privateDirectory(info) {
		return nil, ErrCorrupt
	}
	file, err := readPrivateFile(root, "runtime/state.json", MaxMetadataBytes)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, ErrCorrupt
	}
	data, err := io.ReadAll(io.LimitReader(contextReader{ctx, file}, MaxMetadataBytes+1))
	_ = file.Close()
	defer clear(data)
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if err != nil || len(data) > MaxMetadataBytes {
		return nil, ErrCorrupt
	}
	var metadata Metadata
	if sandbox.DecodeHelperDocument(data, &metadata) != nil || metadata.Validate() != nil {
		return nil, ErrCorrupt
	}
	for _, generation := range []*Generation{metadata.Current, metadata.Previous} {
		if generation != nil {
			if err := verifyGeneration(ctx, root, generation); err != nil {
				return nil, err
			}
		}
	}
	return &metadata, nil
}

func verifyGeneration(ctx context.Context, root *os.Root, generation *Generation) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	name := "runtime/generations/" + strings.TrimPrefix(generation.Digest, "sha256:")
	for _, directory := range []string{"runtime", "runtime/generations", name} {
		info, err := root.Lstat(directory)
		if err != nil || !privateDirectory(info) {
			return ErrCorrupt
		}
	}
	file, err := readPrivateFile(root, name+"/config.json", coreapi.MaxSize)
	if err != nil {
		return ErrCorrupt
	}
	defer file.Close()
	hash := sha256.New()
	buffer := make([]byte, 32<<10)
	defer clear(buffer)
	size, err := io.CopyBuffer(hash, io.LimitReader(contextReader{ctx, file}, coreapi.MaxSize+1), buffer)
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if err != nil || size == 0 || size > coreapi.MaxSize || hex.EncodeToString(hash.Sum(nil)) != generation.Digest[7:] {
		return ErrCorrupt
	}
	return nil
}

// ======================== 私有句柄与有界读取 ========================
// 打开前后核对同一 inode；Linux 使用 NOFOLLOW/NONBLOCK，拒绝竞态替换的链接和 FIFO。
func readPrivateFile(root *os.Root, name string, limit int64) (*os.File, error) {
	before, err := root.Lstat(name)
	if err != nil {
		return nil, err
	}
	if !privateRegular(before, limit) {
		return nil, ErrCorrupt
	}
	file, err := openSnapshotFile(root, name)
	if err != nil {
		return nil, ErrCorrupt
	}
	after, err := file.Stat()
	if err != nil || !os.SameFile(before, after) || !privateRegular(after, limit) {
		_ = file.Close()
		return nil, ErrCorrupt
	}
	return file, nil
}

func privateRegular(info fs.FileInfo, limit int64) bool {
	if info == nil {
		return false
	}
	owner, ok := sandbox.FileOwner(info)
	return ok && owner == os.Geteuid() && info.Mode().IsRegular() && info.Mode().Perm() == 0o600 && info.Size() <= limit
}

func privateDirectory(info fs.FileInfo) bool {
	if info == nil {
		return false
	}
	owner, ok := sandbox.FileOwner(info)
	return ok && owner == os.Geteuid() && info.IsDir() && info.Mode()&fs.ModeSymlink == 0 && info.Mode().Perm() == 0o700
}

type contextReader struct {
	ctx context.Context
	io.Reader
}

func (r contextReader) Read(data []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.Reader.Read(data)
}
