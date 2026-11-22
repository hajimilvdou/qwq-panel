// SPDX-License-Identifier: AGPL-3.0-only

package identity

import (
	"context"
	"errors"
	"runtime"
	"testing"
	"time"
)

// ======================== 实际哈希门禁：默认随 CPU 预算选择，显式配置保持 ========================

func TestHasherDefaultSingleCPUBudget(t *testing.T) {
	previous := runtime.GOMAXPROCS(1)
	t.Cleanup(func() { runtime.GOMAXPROCS(previous) })
	for _, concurrency := range []int{0, -1} {
		hasher := NewHasher(testParams(), concurrency)
		assertPasswordHashBudget(t, hasher, 1)
	}
}

func TestHasherDefaultMultiCPUBudget(t *testing.T) {
	previous := runtime.GOMAXPROCS(2)
	t.Cleanup(func() { runtime.GOMAXPROCS(previous) })
	assertPasswordHashBudget(t, NewHasher(testParams(), 0), 2)
}

func TestHasherExplicitConcurrencyPreservedOnSingleCPU(t *testing.T) {
	previous := runtime.GOMAXPROCS(1)
	t.Cleanup(func() { runtime.GOMAXPROCS(previous) })
	assertPasswordHashBudget(t, NewHasher(testParams(), 2), 2)
}

func TestIdentityDefaultHasherUsesCurrentCPUBudget(t *testing.T) {
	fixture := newFixture(t)
	previous := runtime.GOMAXPROCS(1)
	t.Cleanup(func() { runtime.GOMAXPROCS(previous) })
	for _, processors := range []int{1, 2} {
		runtime.GOMAXPROCS(processors)
		service, err := New(Options{DB: fixture.db, Clock: fixture.clk})
		if err != nil {
			t.Fatal(err)
		}
		assertPasswordHashBudget(t, service.hasher, processors)
	}
}

// assertPasswordHashBudget 同时检查槽位、满额取消与释放后的真实 Hash/Verify。
// 测试不改 argon2 参数或跳过哈希，避免把信号量形状当成业务验证。
func assertPasswordHashBudget(t *testing.T, hasher *Hasher, slots int) {
	t.Helper()
	if actual := cap(hasher.sem); actual != slots {
		t.Errorf("hash budget = %d, want %d", actual, slots)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	acquired := 0
	release := func() {
		for acquired > 0 {
			hasher.release()
			acquired--
		}
	}
	defer release()
	for range slots {
		if err := hasher.acquire(ctx); err != nil {
			t.Fatalf("acquire budget slot: %v", err)
		}
		acquired++
	}
	blocked, stop := context.WithTimeout(context.Background(), 30*time.Millisecond)
	_, err := hasher.Hash(blocked, testPassword)
	stop()
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("hash beyond budget = %v, want DeadlineExceeded", err)
	}
	release()
	encoded, err := hasher.Hash(context.Background(), testPassword)
	if err != nil {
		t.Fatalf("hash after release: %v", err)
	}
	result, err := hasher.Verify(context.Background(), encoded, testPassword)
	if err != nil || !result.OK {
		t.Fatalf("verify after release = %+v, error %v", result, err)
	}
}
