// SPDX-License-Identifier: AGPL-3.0-only

package state

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/qwq-panel/qwq/internal/sandbox"
	"github.com/qwq-panel/qwq/sdk/coreapi"
)

var (
	ErrDirectory = errors.New("core state: private data directory is unavailable")
	ErrWrite     = errors.New("core state: private snapshot write failed")
	ErrOwner     = errors.New("core state: invalid work owner")
	ErrConflict  = errors.New("core state: committed pointers changed")
)

// Store 串行协调读、提交和回收；等待锁可取消，避免失效请求长期排队。
type Store struct {
	directory string
	gate      chan struct{}
	write     func(*os.Root, string, []byte, os.FileMode) error
}

// NewStore 不创建目录或文件；私有 DataDir 必须由宿主预先供给。
func NewStore(directory string) *Store {
	store := &Store{directory: directory, gate: make(chan struct{}, 1), write: sandbox.WriteFileAtomicIn}
	store.gate <- struct{}{}
	return store
}

// Work 仅携带私有候选的位置与摘要；owner/attempt 不能由其他包伪造。
type Work struct {
	Path    string `json:"-"`
	Digest  string `json:"config_digest"`
	owner   string
	attempt uint32
}

func (Work) String() string   { return "CoreWork{[PRIVATE]}" }
func (Work) GoString() string { return "CoreWork{[PRIVATE]}" }

// Committed 供真实运行恢复使用，拒绝缺少预演摘要的旧试验元数据。
func (s *Store) Committed(ctx context.Context) (*Metadata, error) {
	unlock, err := s.lock(ctx)
	if err != nil {
		return nil, err
	}
	defer unlock()
	metadata, err := Load(ctx, s.directory)
	if err != nil || metadata == nil {
		return metadata, err
	}
	for _, generation := range []*Generation{metadata.Current, metadata.Previous} {
		if generation != nil && generation.Summary == nil && generation.SummaryV2 == nil {
			return nil, ErrCorrupt
		}
	}
	return metadata, nil
}

// Stage 只在明确的 operation/attempt 私有目录中写候选，不移动提交指针。
func (s *Store) Stage(ctx context.Context, owner string, attempt uint32, data []byte) (Work, error) {
	unlock, err := s.lock(ctx)
	if err != nil {
		return Work{}, err
	}
	defer unlock()
	if !validOwner(owner, attempt) {
		return Work{}, ErrOwner
	}
	if len(data) == 0 || len(data) > coreapi.MaxSize || !json.Valid(data) {
		return Work{}, ErrWrite
	}
	root, err := s.privateRoot()
	if err != nil {
		return Work{}, ErrDirectory
	}
	defer root.Close()
	base := workDirectory(owner, attempt)
	for _, directory := range []string{"runtime", "runtime/generations", "work", "work/" + owner, base} {
		if err := ensurePrivateDirectory(root, directory); err != nil {
			return Work{}, ErrDirectory
		}
	}
	digest := sha256.Sum256(data)
	work := Work{Path: filepath.Join(s.directory, filepath.FromSlash(base), "config.json"), Digest: "sha256:" + hex.EncodeToString(digest[:]), owner: owner, attempt: attempt}
	if info, err := root.Lstat(base + "/config.json"); err == nil {
		if !privateRegular(info, coreapi.MaxSize) {
			return Work{}, ErrCorrupt
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return Work{}, ErrCorrupt
	}
	if err := s.write(root, base+"/config.json", data, 0o600); err != nil {
		return work, ErrWrite
	}
	return work, ctx.Err()
}

// Install 核对候选后创建不可变 generation；已存在的配置仅校验，永不覆盖。
func (s *Store) Install(ctx context.Context, work Work) error {
	unlock, err := s.lock(ctx)
	if err != nil {
		return err
	}
	defer unlock()
	if !validOwner(work.owner, work.attempt) || !ValidDigest(work.Digest) || work.Path != filepath.Join(s.directory, filepath.FromSlash(workDirectory(work.owner, work.attempt)), "config.json") {
		return ErrOwner
	}
	root, err := s.privateRoot()
	if err != nil {
		return ErrDirectory
	}
	defer root.Close()
	file, err := readPrivateFile(root, workDirectory(work.owner, work.attempt)+"/config.json", coreapi.MaxSize)
	if err != nil {
		return ErrCorrupt
	}
	data, err := io.ReadAll(io.LimitReader(contextReader{ctx, file}, coreapi.MaxSize+1))
	_ = file.Close()
	defer clear(data)
	if ctx.Err() != nil {
		return ctx.Err()
	}
	digest := sha256.Sum256(data)
	if err != nil || len(data) == 0 || len(data) > coreapi.MaxSize || work.Digest != "sha256:"+hex.EncodeToString(digest[:]) {
		return ErrCorrupt
	}
	name := generationDirectory(work.Digest)
	if err := ensurePrivateDirectory(root, name); err != nil {
		return ErrDirectory
	}
	if _, err := root.Lstat(name + "/config.json"); err == nil {
		return verifyGeneration(ctx, root, &Generation{Digest: work.Digest})
	} else if !errors.Is(err, fs.ErrNotExist) {
		return ErrCorrupt
	}
	if err := s.write(root, name+"/config.json", data, 0o600); err != nil {
		return ErrWrite
	}
	return ctx.Err()
}

// Commit 用一个 state.json 原子提交两个指针；失败结果由 Apply 事务补偿。
func (s *Store) Commit(ctx context.Context, metadata *Metadata) error {
	unlock, err := s.lock(ctx)
	if err != nil {
		return err
	}
	defer unlock()
	if metadata == nil || metadata.Validate() != nil || (metadata.Current.Summary == nil && metadata.Current.SummaryV2 == nil) ||
		(metadata.Previous != nil && metadata.Previous.Summary == nil && metadata.Previous.SummaryV2 == nil) {
		return ErrCorrupt
	}
	data, err := json.Marshal(metadata)
	if err != nil || len(data) > MaxMetadataBytes {
		return ErrWrite
	}
	defer clear(data)
	root, err := s.privateRoot()
	if err != nil {
		return ErrDirectory
	}
	defer root.Close()
	for _, generation := range []*Generation{metadata.Current, metadata.Previous} {
		if generation != nil {
			if err := verifyGeneration(ctx, root, generation); err != nil {
				return err
			}
		}
	}
	if info, err := root.Lstat("runtime/state.json"); err == nil {
		if !privateRegular(info, MaxMetadataBytes) {
			return ErrCorrupt
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return ErrCorrupt
	}
	if err := s.write(root, "runtime/state.json", data, 0o600); err != nil {
		return ErrWrite
	}
	return ctx.Err()
}

// Restore 恢复同一原子指针文件；nil 表示回到首次 Apply 前的未配置状态。
// 调用方须先回收候选进程，generation 的回收仍单独由 Prune 负责。
func (s *Store) Restore(ctx context.Context, metadata *Metadata) error {
	if metadata != nil {
		return s.Commit(ctx, metadata)
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
	info, err := root.Lstat("runtime")
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil || !privateDirectory(info) {
		return ErrCorrupt
	}
	info, err = root.Lstat("runtime/state.json")
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil || !privateRegular(info, MaxMetadataBytes) {
		return ErrCorrupt
	}
	if err := root.Remove("runtime/state.json"); err != nil {
		return ErrWrite
	}
	if err := sandbox.SyncIn(root, "runtime"); err != nil {
		return ErrWrite
	}
	return ctx.Err()
}

// GenerationPath 只从已验证摘要推导固定路径，不能接收任意文件名。
func (s *Store) GenerationPath(ctx context.Context, digest string) (string, error) {
	unlock, err := s.lock(ctx)
	if err != nil {
		return "", err
	}
	defer unlock()
	if !ValidDigest(digest) {
		return "", ErrCorrupt
	}
	root, err := s.privateRoot()
	if err != nil {
		return "", ErrDirectory
	}
	defer root.Close()
	if err := verifyGeneration(ctx, root, &Generation{Digest: digest}); err != nil {
		return "", err
	}
	return filepath.Join(s.directory, filepath.FromSlash(generationDirectory(digest)), "config.json"), nil
}

// ======================== 私有目录与可取消锁 ========================
func (s *Store) lock(ctx context.Context) (func(), error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-s.gate:
		if err := ctx.Err(); err != nil {
			s.gate <- struct{}{}
			return nil, err
		}
		return func() { s.gate <- struct{}{} }, nil
	}
}

func (s *Store) privateRoot() (*os.Root, error) {
	if !filepath.IsAbs(s.directory) || filepath.Clean(s.directory) != s.directory {
		return nil, ErrDirectory
	}
	info, err := os.Lstat(s.directory)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, fs.ErrNotExist
	}
	if err != nil || !privateDirectory(info) {
		return nil, ErrDirectory
	}
	root, err := (sandbox.TrustPolicy{UID: os.Geteuid(), StopAt: s.directory}).Open(s.directory)
	if err != nil {
		return nil, ErrDirectory
	}
	return root, nil
}

func ensurePrivateDirectory(root *os.Root, name string) error {
	info, err := root.Lstat(name)
	if errors.Is(err, fs.ErrNotExist) {
		if err := root.Mkdir(name, 0o700); err != nil && !errors.Is(err, fs.ErrExist) {
			return ErrDirectory
		}
		if err := sandbox.SyncIn(root, filepath.Dir(name)); err != nil {
			return ErrWrite
		}
		info, err = root.Lstat(name)
	}
	if err != nil || !privateDirectory(info) {
		return ErrDirectory
	}
	return nil
}

func validOwner(owner string, attempt uint32) bool {
	return len(owner) >= 1 && len(owner) <= 128 && safeToken(owner) && attempt >= 1
}

func workDirectory(owner string, attempt uint32) string {
	return "work/" + owner + "/" + strconv.FormatUint(uint64(attempt), 10)
}

func generationDirectory(digest string) string {
	return "runtime/generations/" + strings.TrimPrefix(digest, "sha256:")
}
