// SPDX-License-Identifier: AGPL-3.0-only

//go:build linux

package sandbox

import (
	"context"
	"errors"
	"os"
	"slices"
	"sync"
	"unsafe"
)

// ======================== helper 总 mmap 预算：并发停止也不能越过固定内存额度 ========================

const generationPerfMemoryLimit = 8 << 20

var generationPerfMemory = struct {
	sync.Mutex
	used int
}{}

func reserveGenerationPerfMemory(size int) (func(), error) {
	generationPerfMemory.Lock()
	defer generationPerfMemory.Unlock()
	if size <= 0 || size > generationPerfMemoryLimit-generationPerfMemory.used {
		return nil, ErrGenerationUnsupported
	}
	generationPerfMemory.used += size
	var once sync.Once
	return func() {
		once.Do(func() {
			generationPerfMemory.Lock()
			defer generationPerfMemory.Unlock()
			generationPerfMemory.used -= size
		})
	}, nil
}

// ======================== 全 CPU 生命周期：先证明 guard 活跃，再开始原组捕获 ========================

type generationPerfWatcher struct {
	mu       sync.Mutex
	layout   generationPerfLayout
	inode    uint64
	cgroup   string
	cpus     []int
	possible []int
	rings    []*generationPerfCPU
	release  func()
	zero     bool
	sealed   bool
	closed   bool
	failure  error
	closeErr error
}

func newGenerationPerfWatcher(ctx context.Context, group *pinnedGenerationCgroup, cgroup string) (watcher *generationPerfWatcher, err error) {
	if group == nil || group.inode == 0 || !validGenerationCgroupPath(cgroup) || unsafe.Sizeof(uintptr(0)) != 8 {
		return nil, ErrGenerationUnsupported
	}
	cpus, err := readGenerationPerfCPUs(ctx, "online")
	if err != nil {
		return nil, err
	}
	possible, err := readGenerationPerfCPUs(ctx, "possible")
	if err != nil {
		return nil, err
	}
	for _, cpu := range cpus {
		if _, found := slices.BinarySearch(possible, cpu); !found {
			return nil, ErrGenerationUnsupported
		}
	}
	layout, err := readGenerationPerfLayout(ctx)
	if err != nil {
		return nil, err
	}
	pageSize := os.Getpagesize()
	if pageSize < 4096 || pageSize > 65536 || pageSize&(pageSize-1) != 0 {
		return nil, ErrGenerationUnsupported
	}
	release, err := reserveGenerationPerfMemory(len(cpus) * (generationPerfDataPages + 1) * pageSize)
	if err != nil {
		return nil, err
	}
	watcher = &generationPerfWatcher{layout: layout, inode: group.inode, cgroup: cgroup, cpus: cpus, possible: possible, release: release}
	defer func() {
		if err != nil {
			err = errors.Join(err, watcher.Close())
			watcher = nil
		}
	}()
	for _, cpu := range cpus {
		ring, openErr := newGenerationPerfCPU(ctx, cpu, pageSize, layout)
		if ring != nil {
			watcher.rings = append(watcher.rings, ring)
		}
		if openErr != nil {
			return watcher, openErr
		}
	}
	if err = watcher.coverage(ctx); err != nil {
		return watcher, err
	}
	for _, ring := range watcher.rings {
		if err = ring.enable(ctx, true); err != nil {
			return watcher, err
		}
	}
	readings := make([]generationGuardReading, len(watcher.rings))
	for index, ring := range watcher.rings {
		if readings[index], err = ring.guardReading(ctx); err != nil {
			return watcher, err
		}
	}
	for index, ring := range watcher.rings {
		current, readErr := ring.guardReading(ctx)
		if readErr != nil {
			return watcher, readErr
		}
		if err = requireGenerationGuardAdvanced(readings[index], current); err != nil {
			return watcher, err
		}
	}
	// 保留并消费最早启动段；热插拔或失样本不能被“新 epoch”重置成干净状态。
	if err = watcher.consume(ctx); err != nil {
		return watcher, err
	}
	if err = watcher.coverage(ctx); err != nil {
		return watcher, err
	}
	for _, ring := range watcher.rings {
		if err = ring.prepareCapture(ctx, layout, group.inode); err != nil {
			return watcher, err
		}
		if err = ring.enable(ctx, false); err != nil {
			return watcher, err
		}
	}
	if err = watcher.coverage(ctx); err != nil {
		return watcher, err
	}
	return watcher, nil
}

func (watcher *generationPerfWatcher) coverage(ctx context.Context) error {
	online, err := readGenerationPerfCPUs(ctx, "online")
	if err != nil {
		return err
	}
	possible, err := readGenerationPerfCPUs(ctx, "possible")
	if err != nil {
		return err
	}
	if !slices.Equal(online, watcher.cpus) || !slices.Equal(possible, watcher.possible) || len(watcher.rings) != len(watcher.cpus) {
		return generationPerfRejected("CPU inventory changed or coverage is incomplete")
	}
	return nil
}

func (watcher *generationPerfWatcher) consume(ctx context.Context) error {
	for _, ring := range watcher.rings {
		zero, err := ring.consume(ctx, watcher.layout, watcher.inode, watcher.cgroup)
		if err != nil {
			return err
		}
		watcher.zero = watcher.zero || zero
	}
	return nil
}

func (watcher *generationPerfWatcher) validateArmed(ctx context.Context) error {
	if err := watcher.coverage(ctx); err != nil {
		return err
	}
	if err := watcher.consume(ctx); err != nil {
		return err
	}
	for _, ring := range watcher.rings {
		if _, err := ring.guardReading(ctx); err != nil {
			return err
		}
	}
	return nil
}

// ======================== 只在 tentative0 后关闭观察：等待子进程时永不反复 DISABLE ========================

func (watcher *generationPerfWatcher) empty(ctx context.Context) (bool, error) {
	watcher.mu.Lock()
	defer watcher.mu.Unlock()
	if watcher.closed {
		return false, ErrGenerationClosed
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if watcher.failure != nil {
		return false, watcher.failure
	}
	if watcher.sealed {
		return true, nil
	}
	if err := watcher.coverage(ctx); err != nil {
		watcher.failure = err
		return false, err
	}
	if err := watcher.consume(ctx); err != nil {
		watcher.failure = err
		return false, err
	}
	if !watcher.zero {
		return false, nil
	}
	var disableErrors []error
	// 所有 capture 先停；guard 最后停，仍覆盖逐 CPU 停止捕获的整个窗口。
	for _, guard := range []bool{false, true} {
		for _, ring := range watcher.rings {
			disableErrors = append(disableErrors, ring.disable(guard))
		}
	}
	if err := errors.Join(disableErrors...); err != nil {
		watcher.failure = err
		return false, err
	}
	if err := watcher.consume(ctx); err != nil {
		watcher.failure = err
		return false, err
	}
	for _, ring := range watcher.rings {
		if err := ring.verifyFinal(ctx); err != nil {
			watcher.failure = err
			return false, err
		}
	}
	if err := watcher.coverage(ctx); err != nil {
		watcher.failure = err
		return false, err
	}
	watcher.sealed = true
	return true, nil
}

func (watcher *generationPerfWatcher) Close() error {
	if watcher == nil {
		return nil
	}
	watcher.mu.Lock()
	defer watcher.mu.Unlock()
	if watcher.closed {
		return watcher.closeErr
	}
	watcher.closed = true
	var errs []error
	mapsReleased := true
	for _, ring := range watcher.rings {
		errs = append(errs, ring.Close())
		mapsReleased = mapsReleased && ring.mapping == nil
	}
	if mapsReleased && watcher.release != nil {
		watcher.release()
	}
	watcher.closeErr = errors.Join(errs...)
	return watcher.closeErr
}
