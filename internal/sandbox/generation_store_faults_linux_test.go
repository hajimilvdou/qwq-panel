// SPDX-License-Identifier: AGPL-3.0-only

//go:build linux

package sandbox

import (
	"bytes"
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/qwq-panel/qwq/internal/platform/ids"
)

// ======================== 门禁/IO故障：测试只阻塞调用接缝，不模拟可中断文件系统 ========================

func generationRecordBlockWrites(t *testing.T, store *GenerationRecordStore) (<-chan struct{}, func()) {
	t.Helper()
	entered := make(chan struct{}, 1)
	blocked := make(chan struct{})
	var once sync.Once
	release := func() { once.Do(func() { close(blocked) }) }
	writeAtomic := store.io.writeAtomic
	store.io.writeAtomic = func(root *os.Root, name string, raw []byte, mode fs.FileMode) error {
		select {
		case entered <- struct{}{}:
		default:
		}
		<-blocked
		return writeAtomic(root, name, raw, mode)
	}
	t.Cleanup(release)
	return entered, release
}

func generationRecordWaitEntered(t *testing.T, entered <-chan struct{}) {
	t.Helper()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("记录IO未进入受控故障接缝")
	}
}

func generationRecordWaitError(t *testing.T, done <-chan error) error {
	t.Helper()
	select {
	case err := <-done:
		return err
	case <-time.After(5 * time.Second):
		t.Fatal("记录操作未回收")
		return nil
	}
}

func generationRecordWaitSlots(t *testing.T, store *GenerationRecordStore, count int) {
	t.Helper()
	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for len(store.slots) != count {
		select {
		case <-ticker.C:
		case <-timer.C:
			t.Fatalf("在途门禁状态未达预期：got=%d want=%d", len(store.slots), count)
		}
	}
}

func generationRecordAssertReleased(t *testing.T, store *GenerationRecordStore) {
	t.Helper()
	store.mu.Lock()
	entries := len(store.gates)
	store.mu.Unlock()
	if entries != 0 || len(store.slots) != 0 {
		t.Fatalf("退出后门禁map/额度未回收：entries=%d slots=%d", entries, len(store.slots))
	}
}

func TestGenerationRecordStoreCanceledWaitersReleaseBoundedGate(t *testing.T) {
	store, _, _ := generationRecordTestStore(t)
	// 两个实际操作占满测试额度；生产默认仍为32。
	store.slots = make(chan struct{}, 2)
	request := generationProtocolStopFixture()
	entered, release := generationRecordBlockWrites(t, store)
	first := make(chan error, 1)
	go func() {
		_, err := store.Bind(t.Context(), request)
		first <- err
	}()
	generationRecordWaitEntered(t, entered)
	queuedCtx, cancelQueued := context.WithCancel(t.Context())
	defer cancelQueued()
	queued := make(chan error, 1)
	go func() {
		_, err := store.Bind(queuedCtx, request)
		queued <- err
	}()
	generationRecordWaitSlots(t, store, 2)
	quotaCtx, cancelQuota := context.WithCancel(t.Context())
	defer cancelQuota()
	other := request
	other.TargetRef = ids.New(nil).New(ids.Generation)
	quota := make(chan error, 1)
	go func() {
		_, err := store.Bind(quotaCtx, other)
		quota <- err
	}()
	cancelQuota()
	if err := generationRecordWaitError(t, quota); !errors.Is(err, context.Canceled) {
		t.Fatalf("额度等待不能取消：%v", err)
	}
	cancelQueued()
	if err := generationRecordWaitError(t, queued); !errors.Is(err, context.Canceled) {
		t.Fatalf("同ref门禁等待不能取消：%v", err)
	}
	release()
	if err := generationRecordWaitError(t, first); err != nil {
		t.Fatal(err)
	}
	generationRecordAssertReleased(t, store)
}

func TestGenerationRecordStoreCrossInstanceBindingAndLockCancel(t *testing.T) {
	firstStore, directory, trust := generationRecordTestStore(t)
	secondStore, err := newGenerationRecordStore(directory, trust.Open, trust.StopAt)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = secondStore.Close() })
	request := generationProtocolStopFixture()
	changed := request
	changed.Expected.KernelStartTicks++
	entered, release := generationRecordBlockWrites(t, firstStore)
	first := make(chan error, 1)
	go func() {
		_, err := firstStore.Bind(t.Context(), request)
		first <- err
	}()
	generationRecordWaitEntered(t, entered)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	second := make(chan error, 1)
	go func() {
		_, err := secondStore.Bind(ctx, changed)
		second <- err
	}()
	generationRecordWaitSlots(t, secondStore, 1)
	cancel()
	if err := generationRecordWaitError(t, second); !errors.Is(err, context.Canceled) {
		t.Fatalf("跨实例目录锁未阻止首次错绑定或不能取消：%v", err)
	}
	release()
	if err := generationRecordWaitError(t, first); err != nil {
		t.Fatal(err)
	}
	path := generationRecordTestPath(t, directory, request.TargetRef)
	before := generationRecordTestRead(t, path)
	if _, err := secondStore.Bind(t.Context(), changed); !errors.Is(err, ErrGenerationBinding) {
		t.Fatalf("另一个store覆盖了已持久首次绑定：%v", err)
	}
	if !bytes.Equal(before, generationRecordTestRead(t, path)) {
		t.Fatal("跨实例永久绑定正文被覆盖")
	}
	generationRecordAssertReleased(t, firstStore)
	generationRecordAssertReleased(t, secondStore)
}

func TestGenerationRecordStoreCancellationAfterIOPreservesDurableWitness(t *testing.T) {
	store, _, _ := generationRecordTestStore(t)
	request := generationProtocolStopFixture()
	completed := generationProtocolCompletionFixture(t)
	if _, err := store.Bind(t.Context(), request); err != nil {
		t.Fatal(err)
	}
	entered, release := generationRecordBlockWrites(t, store)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		witness, err := store.Complete(ctx, request, completed)
		if witness != (GenerationCompletion{}) {
			done <- errors.New("取消后仍返回成功witness")
			return
		}
		done <- err
	}()
	generationRecordWaitEntered(t, entered)
	cancel()
	// 接缝还未返回时不能把IO扔到后台、伪造完成；release后才允许真实原子写结束。
	select {
	case err := <-done:
		t.Fatalf("原子IO未结束便释放操作：%v", err)
	default:
	}
	release()
	if err := generationRecordWaitError(t, done); !errors.Is(err, context.Canceled) {
		t.Fatalf("IO后取消未传回调用方：%v", err)
	}
	if witness, err := store.Bind(t.Context(), request); err != nil || witness == nil || *witness != completed {
		t.Fatalf("取消后丢失实际耐久见证，可能诱发重复停止：%v", err)
	}
	generationRecordAssertReleased(t, store)
}

func TestGenerationRecordStoreCloseCancelsWaitersAndWaitsForOwnedIO(t *testing.T) {
	store, _, _ := generationRecordTestStore(t)
	request := generationProtocolStopFixture()
	entered, release := generationRecordBlockWrites(t, store)
	first := make(chan error, 1)
	go func() {
		_, err := store.Bind(t.Context(), request)
		first <- err
	}()
	generationRecordWaitEntered(t, entered)
	queued := make(chan error, 1)
	go func() {
		_, err := store.Bind(t.Context(), request)
		queued <- err
	}()
	generationRecordWaitSlots(t, store, 2)
	closed := make(chan error, 1)
	go func() { closed <- store.Close() }()
	select {
	case <-store.stopping:
	case <-time.After(5 * time.Second):
		t.Fatal("Close未取消门禁等待")
	}
	if err := generationRecordWaitError(t, queued); !errors.Is(err, ErrGenerationStoreClosed) {
		t.Fatalf("关闭时等待者仍可访问记录：%v", err)
	}
	select {
	case err := <-closed:
		t.Fatalf("真实IO持有句柄时提前Close：%v", err)
	default:
	}
	release()
	if err := generationRecordWaitError(t, first); !errors.Is(err, ErrGenerationStoreClosed) {
		t.Fatalf("关闭中的IO未返回关闭状态：%v", err)
	}
	if err := generationRecordWaitError(t, closed); err != nil {
		t.Fatal(err)
	}
	generationRecordAssertReleased(t, store)
}

func TestGenerationRecordStoreReplayCannotIgnoreDirectorySyncFailure(t *testing.T) {
	store, directory, _ := generationRecordTestStore(t)
	request := generationProtocolStopFixture()
	completed := generationProtocolCompletionFixture(t)
	if _, err := store.Bind(t.Context(), request); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Complete(t.Context(), request, completed); err != nil {
		t.Fatal(err)
	}
	path := generationRecordTestPath(t, directory, request.TargetRef)
	before := generationRecordTestRead(t, path)
	fault := errors.New("injected generation directory fsync failure")
	store.io.syncDirectory = func(*os.Root, string) error { return fault }
	if witness, err := store.Bind(t.Context(), request); !errors.Is(err, fault) || witness != nil {
		t.Fatalf("目录fsync失败仍承认完成重放：witness=%v err=%v", witness != nil, err)
	}
	if witness, err := store.Complete(t.Context(), request, completed); !errors.Is(err, fault) || witness != (GenerationCompletion{}) {
		t.Fatalf("目录fsync失败仍返回成功完成：%v", err)
	}
	if !bytes.Equal(before, generationRecordTestRead(t, path)) {
		t.Fatal("重放fsync失败覆盖了原完成见证")
	}
	generationRecordAssertReleased(t, store)
}

func TestGenerationRecordStoreConcurrentSameTupleBindsOnlyOnce(t *testing.T) {
	store, _, _ := generationRecordTestStore(t)
	request := generationProtocolStopFixture()
	var writes atomic.Int32
	writeAtomic := store.io.writeAtomic
	store.io.writeAtomic = func(root *os.Root, name string, raw []byte, mode fs.FileMode) error {
		writes.Add(1)
		return writeAtomic(root, name, raw, mode)
	}
	start := make(chan struct{})
	done := make(chan error, 12)
	for range 12 {
		go func() {
			<-start
			witness, err := store.Bind(t.Context(), request)
			if witness != nil {
				err = errors.New("并发首次Bind自行声称完成")
			}
			done <- err
		}()
	}
	close(start)
	for range 12 {
		if err := generationRecordWaitError(t, done); err != nil {
			t.Fatal(err)
		}
	}
	if writes.Load() != 1 {
		t.Fatalf("同元组并发重复发布：writes=%d", writes.Load())
	}
	generationRecordAssertReleased(t, store)
}

// ======================== 真实temp故障：部分写/file-sync不得发布，dir-sync失败不得承认完成 ========================

func TestGenerationRecordStoreAtomicFailuresKeepEvidenceAndCloseFiles(t *testing.T) {
	for _, phase := range []string{"short-write", "file-sync", "directory-sync"} {
		t.Run(phase, func(t *testing.T) {
			store, directory, _ := generationRecordTestStore(t)
			request := generationProtocolStopFixture()
			completed := generationProtocolCompletionFixture(t)
			if _, err := store.Bind(t.Context(), request); err != nil {
				t.Fatal(err)
			}
			path := generationRecordTestPath(t, directory, request.TargetRef)
			before := generationRecordTestRead(t, path)
			fault := errors.New("injected generation atomic IO failure")
			operations := defaultAtomicFileOperations()
			var temporary *os.File
			var events []string
			operations.write = func(file *os.File, raw []byte) (int, error) {
				temporary = file
				events = append(events, "write")
				if phase == "short-write" {
					return file.Write(raw[:len(raw)/2])
				}
				return file.Write(raw)
			}
			operations.syncFile = func(file *os.File) error {
				events = append(events, "file-sync")
				if phase == "file-sync" {
					return fault
				}
				return file.Sync()
			}
			operations.syncDirectory = func(root *os.Root, relative string) error {
				events = append(events, "directory-sync")
				if phase == "directory-sync" {
					return fault
				}
				return SyncIn(root, relative)
			}
			store.io.writeAtomic = func(root *os.Root, name string, raw []byte, mode fs.FileMode) error {
				return writeFileAtomicInWithOps(root, name, raw, mode, operations)
			}
			witness, err := store.Complete(t.Context(), request, completed)
			want := fault
			if phase == "short-write" {
				want = io.ErrShortWrite
			}
			if !errors.Is(err, want) || witness != (GenerationCompletion{}) {
				t.Fatalf("原子IO故障仍返回完成或吞掉原因：phase=%s err=%v", phase, err)
			}
			if temporary == nil {
				t.Fatal("没有使用真实临时文件验证故障")
			}
			if _, err := temporary.Stat(); err == nil {
				t.Fatal("错误路径遗留打开的临时文件句柄")
			}
			entries, err := os.ReadDir(directory)
			if err != nil {
				t.Fatal(err)
			}
			for _, entry := range entries {
				if strings.HasPrefix(entry.Name(), ".qwq-tmp-") {
					t.Fatal("原子错误路径遗留临时文件")
				}
			}
			if phase != "directory-sync" {
				if !bytes.Equal(before, generationRecordTestRead(t, path)) {
					t.Fatal("部分写或file-fsync失败覆盖了原bound guard")
				}
			} else {
				published := generationRecordTestRead(t, path)
				record, err := decodeGenerationStoredRecord(published)
				if err != nil || record.State != generationRecordCompleted {
					t.Fatal("rename后的目录fsync故障证据未保留")
				}
				store.io.syncDirectory = func(*os.Root, string) error { return fault }
				if replay, err := store.Bind(t.Context(), request); !errors.Is(err, fault) || replay != nil {
					t.Fatalf("未补齐目录fsync就承认发布见证：%v", err)
				}
				store.io.syncDirectory = SyncIn
				if replay, err := store.Bind(t.Context(), request); err != nil || replay == nil || *replay != completed {
					t.Fatalf("补齐fsync后不能准确恢复，可能重发停止：%v", err)
				}
				if !bytes.Equal(published, generationRecordTestRead(t, path)) {
					t.Fatal("fsync恢复重放覆盖了已发布见证")
				}
			}
			wantEvents := "write"
			if phase == "file-sync" {
				wantEvents = "write,file-sync"
			} else if phase == "directory-sync" {
				wantEvents = "write,file-sync,directory-sync"
			}
			if strings.Join(events, ",") != wantEvents {
				t.Fatalf("原子故障阶段顺序错误：got=%v want=%s", events, wantEvents)
			}
			generationRecordAssertReleased(t, store)
		})
	}
}

func TestGenerationRecordStoreStartupRechecksAncestorsAndClosesOnFailure(t *testing.T) {
	store, directory, trust := generationRecordTestStore(t)
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	fault := errors.New("injected trusted ancestor reopen failure")
	var opened []*os.Root
	opener := func(path string) (*os.Root, error) {
		if path == trust.StopAt {
			return nil, fault
		}
		root, err := trust.Open(path)
		if err == nil {
			opened = append(opened, root)
		}
		return root, err
	}
	if reopened, err := newGenerationRecordStore(directory, opener, trust.StopAt); !errors.Is(err, fault) || reopened != nil {
		if reopened != nil {
			_ = reopened.Close()
		}
		t.Fatalf("重开现有leaf时跳过祖先耐久检查：%v", err)
	}
	for _, root := range opened {
		if _, err := root.Stat("."); err == nil {
			t.Fatal("startup失败遗留自有root句柄")
		}
	}
	generationRecordAssertReleased(t, store)
}
