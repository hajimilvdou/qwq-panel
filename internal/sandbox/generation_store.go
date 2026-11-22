// SPDX-License-Identifier: AGPL-3.0-only

package sandbox

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
)

// ======================== root 私有记录组件：只持久化数据，不观察或停止进程 ========================

// DefaultGenerationRecordDirectory 仅供 root 启动配置；请求不能选择记录目录。
const DefaultGenerationRecordDirectory = "/var/lib/qwq-privileged/generation-stops"

const maxGenerationRecordInflight = 32

var (
	// ErrGenerationRecord 拒绝损坏、超限或权限不可信的记录，不回显私有正文。
	ErrGenerationRecord = errors.New("sandbox: invalid or untrusted generation record")
	// ErrGenerationBinding 表示全局 target_ref 已绑定其他元组或完成回执。
	ErrGenerationBinding = errors.New("sandbox: the generation target is permanently bound to another tuple")
	// ErrGenerationRecordMissing 禁止绕过 Bind 直接发布完成或退休记录。
	ErrGenerationRecordMissing = errors.New("sandbox: the generation binding is unavailable")
	// ErrGenerationStoreClosed 表示组件已关闭，不再接收操作。
	ErrGenerationStoreClosed = errors.New("sandbox: the generation record store is closed")
)

type generationRecordStoreIO struct {
	writeAtomic   func(*os.Root, string, []byte, fs.FileMode) error
	syncDirectory func(*os.Root, string) error
}

type generationRecordGate struct {
	token chan struct{}
	users int
}

// GenerationRecordStore 由 OpenGenerationRecordStore 创建并独占其目录句柄。
// 新绑定的调用方必须先强 Pin；本组件不会把 caller 的结构数据当成内核证明。
// 同一目录的多实例通过目录 flock 串行发布；所有记录永久保留，不做 TTL 或 GC。
type GenerationRecordStore struct {
	root      *os.Root
	io        generationRecordStoreIO
	mu        sync.Mutex
	gates     map[string]*generationRecordGate
	slots     chan struct{}
	stopping  chan struct{}
	active    sync.WaitGroup
	closed    bool
	closeOnce sync.Once
	closeErr  error
}

// OpenGenerationRecordStore 打开或创建专用0700目录，复用可信祖先与原子写入策略。
// directory 为空时使用固定默认值；非 Linux 平台失败安全。
func OpenGenerationRecordStore(directory string) (*GenerationRecordStore, error) {
	if !generationRecordPlatformAvailable() {
		return nil, ErrGenerationUnsupported
	}
	return newGenerationRecordStore(directory, OpenTrustedRoot, "")
}

func newGenerationRecordStore(directory string, opener func(string) (*os.Root, error), stopAt string) (*GenerationRecordStore, error) {
	if directory == "" {
		directory = DefaultGenerationRecordDirectory
	}
	if !filepath.IsAbs(directory) || filepath.Clean(directory) != directory {
		return nil, ErrGenerationRecord
	}
	root, err := prepareGenerationRecordRoot(directory, opener)
	if err != nil {
		return nil, err
	}
	if err := syncGenerationRecordAncestors(directory, opener, stopAt); err != nil {
		return nil, errors.Join(err, root.Close())
	}
	return &GenerationRecordStore{root: root,
		io:    generationRecordStoreIO{writeAtomic: WriteFileAtomicIn, syncDirectory: SyncIn},
		gates: make(map[string]*generationRecordGate), slots: make(chan struct{}, maxGenerationRecordInflight),
		stopping: make(chan struct{})}, nil
}

// Bind 永久保存同一 plugin/operation/proof；返回非nil见证表示准确完成重放。
// bound-only 记录不能证明完成；原对象丢失后的停止决策仍由未来强 Pin 调用方负责。
func (store *GenerationRecordStore) Bind(ctx context.Context, request GenerationStopRequest) (*GenerationCompletion, error) {
	if request.Validate() != nil {
		return nil, ErrGenerationDocument
	}
	name, err := generationRecordName(request.TargetRef)
	if err != nil {
		return nil, err
	}
	proofDigest, err := GenerationProofDigest(request.ID, request.Expected)
	if err != nil {
		return nil, err
	}
	var completed *GenerationCompletion
	err = store.withRecord(ctx, name, func(ctx context.Context) error {
		record, exists, err := store.readRecord(name)
		if err != nil {
			return err
		}
		if exists {
			if !record.matches(request, proofDigest) {
				return ErrGenerationBinding
			}
			if record.State != generationRecordBound {
				witness, err := record.replay(request)
				if err != nil {
					return err
				}
				completed = &witness
			}
			return store.syncReplay(ctx)
		}
		proof := request.Expected
		record = generationStoredRecord{Version: generationRecordVersion, State: generationRecordBound,
			Reference: GenerationRecordRef{ID: request.ID, OperationID: request.OperationID, TargetRef: request.TargetRef, ProofDigest: proofDigest},
			Expected:  &proof}
		return store.persistRecord(ctx, name, record)
	})
	if err != nil {
		return nil, err
	}
	return completed, nil
}

// Complete 仅接受已确认的完整见证；全元组和规范receipt均校验且durable后才返回。
// 重放须与原见证完全相同，不能通过换时间或换receipt覆盖已完成记录。
func (store *GenerationRecordStore) Complete(ctx context.Context, request GenerationStopRequest, completed GenerationCompletion) (GenerationCompletion, error) {
	if completed.ValidateFor(request) != nil {
		return GenerationCompletion{}, ErrGenerationDocument
	}
	name, err := generationRecordName(request.TargetRef)
	if err != nil {
		return GenerationCompletion{}, err
	}
	proofDigest, err := GenerationProofDigest(request.ID, request.Expected)
	if err != nil {
		return GenerationCompletion{}, err
	}
	err = store.withRecord(ctx, name, func(ctx context.Context) error {
		record, exists, err := store.readRecord(name)
		if err != nil {
			return err
		}
		if !exists {
			return ErrGenerationRecordMissing
		}
		if !record.matches(request, proofDigest) {
			return ErrGenerationBinding
		}
		if record.State != generationRecordBound {
			replayed, err := record.replay(request)
			if err != nil || replayed != completed {
				return ErrGenerationBinding
			}
			return store.syncReplay(ctx)
		}
		proof := request.Expected
		record = generationStoredRecord{Version: generationRecordVersion, State: generationRecordCompleted,
			Reference: completed.Reference, Expected: &proof, OriginalExited: completed.Observation.OriginalExited,
			OriginalCgroupEmpty: completed.Observation.OriginalCgroupEmpty, CompletedAt: completed.CompletedAt}
		return store.persistRecord(ctx, name, record)
	})
	if err != nil {
		return GenerationCompletion{}, err
	}
	return completed, nil
}

// Retire 只压缩匹配completed正文；最小永久guard保留引用、两flags和规范时间。
func (store *GenerationRecordStore) Retire(ctx context.Context, request GenerationRetireRequest) (GenerationRecordRef, error) {
	if request.Validate() != nil {
		return GenerationRecordRef{}, ErrGenerationDocument
	}
	name, err := generationRecordName(request.TargetRef)
	if err != nil {
		return GenerationRecordRef{}, err
	}
	err = store.withRecord(ctx, name, func(ctx context.Context) error {
		record, exists, err := store.readRecord(name)
		if err != nil {
			return err
		}
		if !exists {
			return ErrGenerationRecordMissing
		}
		if record.State == generationRecordBound {
			return ErrGenerationUnconfirmed
		}
		if record.Reference != request.Reference() {
			return ErrGenerationBinding
		}
		if record.State == generationRecordRetired {
			return store.syncReplay(ctx)
		}
		record.State, record.Expected = generationRecordRetired, nil
		return store.persistRecord(ctx, name, record)
	})
	if err != nil {
		return GenerationRecordRef{}, err
	}
	return request.Reference(), nil
}

// Close 拒绝新请求并取消门禁等待，待已进入的真实IO结束后关闭唯一目录句柄。
// 原有原子IO不可中途撤回；此处不使用后台goroutine伪造硬超时。
func (store *GenerationRecordStore) Close() error {
	if store == nil || store.root == nil {
		return nil
	}
	store.closeOnce.Do(func() {
		store.mu.Lock()
		store.closed = true
		close(store.stopping)
		store.mu.Unlock()
		store.active.Wait()
		store.closeErr = store.root.Close()
	})
	return store.closeErr
}

// ======================== 有界门禁：等待者计入32个在途，退出即回收map条目 ========================

func generationRecordContextError(ctx context.Context, stopping <-chan struct{}) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	select {
	case <-stopping:
		return ErrGenerationStoreClosed
	default:
		return nil
	}
}

func (store *GenerationRecordStore) acquire(ctx context.Context, name string) (func(), error) {
	select {
	case store.slots <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-store.stopping:
		return nil, ErrGenerationStoreClosed
	}
	store.mu.Lock()
	if store.closed {
		store.mu.Unlock()
		<-store.slots
		return nil, ErrGenerationStoreClosed
	}
	store.active.Add(1)
	gate := store.gates[name]
	if gate == nil {
		gate = &generationRecordGate{token: make(chan struct{}, 1)}
		store.gates[name] = gate
	}
	gate.users++
	store.mu.Unlock()
	locked := false
	var once sync.Once
	release := func() {
		once.Do(func() {
			if locked {
				<-gate.token
			}
			store.mu.Lock()
			gate.users--
			if gate.users == 0 {
				delete(store.gates, name)
			}
			store.mu.Unlock()
			<-store.slots
			store.active.Done()
		})
	}
	select {
	case gate.token <- struct{}{}:
		locked = true
	case <-ctx.Done():
		release()
		return nil, ctx.Err()
	case <-store.stopping:
		release()
		return nil, ErrGenerationStoreClosed
	}
	if err := generationRecordContextError(ctx, store.stopping); err != nil {
		release()
		return nil, err
	}
	return release, nil
}

func (store *GenerationRecordStore) withRecord(ctx context.Context, name string, operation func(context.Context) error) (err error) {
	if store == nil || store.root == nil {
		return ErrGenerationStoreClosed
	}
	if ctx == nil {
		ctx = context.Background()
	}
	release, err := store.acquire(ctx, name)
	if err != nil {
		return err
	}
	defer release()
	unlock, err := lockGenerationRecordDirectory(ctx, store.stopping, store.root)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, unlock()) }()
	if err = generationRecordContextError(ctx, store.stopping); err != nil {
		return err
	}
	err = operation(ctx)
	return errors.Join(err, generationRecordContextError(ctx, store.stopping))
}
