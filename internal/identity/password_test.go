// SPDX-License-Identifier: AGPL-3.0-only

package identity

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/qwq-panel/qwq/internal/platform/problem"
)

func TestDefaultParamsSane(t *testing.T) {
	p := DefaultParams()
	if err := p.valid(); err != nil {
		t.Fatalf("default params invalid: %v", err)
	}
	// 19 MiB, two iterations, one lane: the documented 1 vCPU choice.
	if p.Memory != 19*1024 || p.Iterations != 2 || p.Parallelism != 1 {
		t.Fatalf("unexpected default params: %+v", p)
	}
	if !strings.HasPrefix(DefaultParams().String(), "m=19456,t=2,p=1") {
		t.Fatalf("params string: %s", p.String())
	}
}

func TestHasherRoundTrip(t *testing.T) {
	h := NewHasher(testParams(), 2)
	ctx := context.Background()
	encoded, err := h.Hash(ctx, "hunter2-hunter2")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(encoded, "$argon2id$v=19$") {
		t.Fatalf("not a PHC string: %s", encoded)
	}
	res, err := h.Verify(ctx, encoded, "hunter2-hunter2")
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK || res.NeedsRehash {
		t.Fatalf("verify = %+v", res)
	}
	res, err = h.Verify(ctx, encoded, "hunter2-hunter3")
	if err != nil {
		t.Fatal(err)
	}
	if res.OK {
		t.Fatal("wrong password accepted")
	}
	if _, err := h.Verify(ctx, "not-a-hash", "x"); err == nil {
		t.Fatal("malformed hash accepted")
	}
}

func TestHasherNeedsRehashAfterParameterChange(t *testing.T) {
	ctx := context.Background()
	old := NewHasher(testParams(), 1)
	encoded, err := old.Hash(ctx, "hunter2-hunter2")
	if err != nil {
		t.Fatal(err)
	}
	stronger := testParams()
	stronger.Iterations = 2
	next := NewHasher(stronger, 1)
	res, err := next.Verify(ctx, encoded, "hunter2-hunter2")
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK || !res.NeedsRehash {
		t.Fatalf("verify = %+v, want OK and NeedsRehash", res)
	}
}

func TestHashSemaphoreBoundsConcurrency(t *testing.T) {
	h := NewHasher(testParams(), 1)
	ctx := context.Background()
	if err := h.acquire(ctx); err != nil { // occupy the only slot
		t.Fatal(err)
	}
	short, cancel := context.WithTimeout(ctx, 20*time.Millisecond)
	defer cancel()
	if _, err := h.Hash(short, "hunter2-hunter2"); err == nil {
		h.release()
		t.Fatal("hash ran while the semaphore was full")
	}
	h.release()
	if _, err := h.Hash(ctx, "hunter2-hunter2"); err != nil {
		t.Fatalf("hash after release: %v", err)
	}
}

// TestHasherAcquireBounded checks that a caller without a deadline does not
// queue forever behind a saturated semaphore: after the bounded wait it gets a
// retryable UNAVAILABLE instead of joining an unbounded line of logins.
func TestHasherAcquireBounded(t *testing.T) {
	h := NewHasher(testParams(), 1)
	if err := h.acquire(context.Background()); err != nil { // occupy the only slot
		t.Fatal(err)
	}
	defer h.release()

	start := time.Now()
	done := make(chan error, 1)
	go func() {
		_, err := h.Hash(context.Background(), "hunter2-hunter2")
		done <- err
	}()
	var err error
	select {
	case err = <-done:
	case <-time.After(hashQueueWait + 5*time.Second):
		t.Fatal("Hash is still queued behind a full semaphore: the wait is unbounded")
	}
	if waited := time.Since(start); waited < hashQueueWait {
		t.Fatalf("Hash gave up after %v, before the %v queue bound", waited, hashQueueWait)
	}
	if !problem.HasCode(err, problem.Unavailable) {
		t.Fatalf("Hash error = %v, want UNAVAILABLE", err)
	}
}

func TestHasherConcurrent(t *testing.T) {
	h := NewHasher(testParams(), 2)
	ctx := context.Background()
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			enc, err := h.Hash(ctx, "hunter2-hunter2")
			if err != nil {
				errs <- err
				return
			}
			res, err := h.Verify(ctx, enc, "hunter2-hunter2")
			if err != nil || !res.OK {
				errs <- fmt.Errorf("verify: %v ok=%v", err, res.OK)
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
}

func TestDummyVerify(t *testing.T) {
	h := NewHasher(testParams(), 2)
	if err := h.DummyVerify(context.Background()); err != nil {
		t.Fatal(err)
	}
	p, _, _, err := parsePHC(h.dummyHash)
	if err != nil {
		t.Fatalf("dummy hash is not a valid PHC string: %v", err)
	}
	if p != h.params {
		t.Fatalf("dummy hash params = %v, want the hasher's %v", p, h.params)
	}
}

// fillSemaphore takes every hashing slot of h and returns the release func.
func fillSemaphore(h *Hasher) func() {
	for range cap(h.sem) {
		h.sem <- struct{}{}
	}
	return func() {
		for range cap(h.sem) {
			<-h.sem
		}
	}
}

// TestDummyVerifyBurnsHashEveryCall proves every call queues for a real hash:
// with the semaphore full, the second call must wait and time out too.
func TestDummyVerifyBurnsHashEveryCall(t *testing.T) {
	h := NewHasher(testParams(), 1)
	if err := h.DummyVerify(context.Background()); err != nil {
		t.Fatal(err)
	}
	release := fillSemaphore(h)
	defer release()
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if err := h.DummyVerify(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("DummyVerify on a full semaphore = %v, want DeadlineExceeded", err)
	}
}

// TestDummyVerifyDoesNotCacheFailure: a first call that times out on a full
// semaphore must not poison the calls after the slots are released.
func TestDummyVerifyDoesNotCacheFailure(t *testing.T) {
	h := NewHasher(testParams(), 1)
	release := fillSemaphore(h)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if err := h.DummyVerify(ctx); err == nil {
		t.Fatal("DummyVerify on a full semaphore succeeded")
	}
	release()
	if err := h.DummyVerify(context.Background()); err != nil {
		t.Fatalf("DummyVerify after release = %v, want nil", err)
	}
	canceled, stop := context.WithCancel(context.Background())
	stop()
	_ = h.DummyVerify(canceled)
	if err := h.DummyVerify(context.Background()); err != nil {
		t.Fatalf("DummyVerify after a canceled call = %v, want nil", err)
	}
}

func TestNormalizeUsername(t *testing.T) {
	cases := []struct {
		in      string
		want    string
		wantErr bool
	}{
		{"Alice", "alice", false},
		{"  bob.smith  ", "bob.smith", false},
		{"a_b-c9", "a_b-c9", false},
		{"", "", true},
		{"-leading", "", true},
		{"has space", "", true},
		{"üser", "", true},
		{strings.Repeat("a", 65), "", true},
		{strings.Repeat("a", 64), strings.Repeat("a", 64), false},
	}
	for _, c := range cases {
		got, err := NormalizeUsername(c.in)
		if c.wantErr {
			if err == nil {
				t.Errorf("NormalizeUsername(%q) = %q, want error", c.in, got)
			}
			continue
		}
		if err != nil || got != c.want {
			t.Errorf("NormalizeUsername(%q) = %q, %v; want %q", c.in, got, err, c.want)
		}
	}
}

func TestPasswordPolicy(t *testing.T) {
	p := DefaultPasswordPolicy()
	if vs := p.Validate("alice", testPassword); len(vs) != 0 {
		t.Fatalf("strong passphrase rejected: %v", vs)
	}
	cases := []struct {
		username, password string
		wantCode           string
	}{
		{"alice", "short", "too_short"},
		{"alice", strings.Repeat("a", 300), "too_long"},
		{"alice", "onlylowercase", "too_weak"},
		{"alice", "abcdefghij12", "too_weak"}, // 12 chars, two classes
		{"alice", "alice-is-my-password", "contains_username"},
		{"alice", strings.Repeat("x", 24), "repeated"},
	}
	for _, c := range cases {
		vs := p.Validate(c.username, c.password)
		found := false
		for _, v := range vs {
			if v.Code == c.wantCode {
				found = true
			}
		}
		if !found {
			t.Errorf("Validate(%q) missing %q: %v", c.password, c.wantCode, vs)
		}
	}
	// Three character classes at 12 characters are enough.
	if vs := p.Validate("alice", "CorrectHorse1"); len(vs) != 0 {
		t.Fatalf("three-class password rejected: %v", vs)
	}
}
