// SPDX-License-Identifier: AGPL-3.0-only

//go:build linux

package coreproc

import (
	"context"
	"errors"
	"os/exec"
	"sync/atomic"
	"testing"
	"time"
)

// ============================================================================
// 真实 Manager/受跟踪 runner：取消返回前等待清理；超时仍保留原 slot 归属。
// ============================================================================

func fakeCanceledStartFixture(t *testing.T, holdCleanup bool) (*processFixture, error, bool, error) {
	t.Helper()
	fixture := fakeProcessFixture(t, "wait", nil)
	original := fixture.manager.options.Command
	entered, canceled, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
	allowFinish, controlDone := make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	fixture.manager.options.Command = func(ctx context.Context, _ string) (*exec.Cmd, error) {
		if calls.Add(1) != 1 {
			return nil, errors.New("a second factory entered before owned cleanup")
		}
		close(entered)
		<-ctx.Done()
		close(canceled)
		<-release
		return nil, ctx.Err()
	}
	request, cancelRequest := context.WithCancel(t.Context())
	defer cancelRequest()
	control, cancelControl := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancelControl()
	go func() {
		defer close(controlDone)
		defer close(release)
		defer cancelRequest()
		select {
		case <-entered:
		case <-control.Done():
			return
		}
		cancelRequest()
		select {
		case <-canceled:
		case <-control.Done():
			return
		}
		if holdCleanup {
			select {
			case <-allowFinish:
			case <-control.Done():
			}
			return
		}
		timer := time.NewTimer(100 * time.Millisecond)
		defer timer.Stop()
		select {
		case <-timer.C:
		case <-control.Done():
		}
	}()
	err := fixture.manager.Start(request, fakeStartSpec(t))
	fixture.manager.mu.Lock()
	slot := fixture.manager.current
	fixture.manager.mu.Unlock()
	done := slot != nil && slotDone(slot)
	var retryErr error
	if !done {
		retry, cancel := context.WithTimeout(t.Context(), time.Second)
		retryErr = fixture.manager.Start(retry, fakeStartSpec(t))
		cancel()
	}
	close(allowFinish)
	<-controlDone
	cleanup, stop := context.WithTimeout(t.Context(), 2*time.Second)
	if err := fixture.manager.Stop(cleanup); err != nil {
		t.Error(err)
	}
	stop()
	fixture.manager.options.Command = original
	return fixture, err, done, retryErr
}

func TestFakeCanceledStartWaitsForOwnedRunnerCleanup(t *testing.T) {
	fixture, err, done, _ := fakeCanceledStartFixture(t, false)
	if !errors.Is(err, context.Canceled) || !done {
		t.Fatalf("canceled Start returned before owned cleanup: error=%v done=%v", err, done)
	}
	// 原 runner 已退出后，可以启动下一真实短时 Go 子进程。
	if err := fixture.manager.Start(t.Context(), fakeStartSpec(t)); err != nil {
		t.Fatal(err)
	}
	fixture.waitReady(t)
	if err := fixture.manager.WaitHealthy(t.Context()); err != nil {
		t.Fatal(err)
	}
}

func TestFakeCanceledStartCleanupTimeoutKeepsOwnedSlot(t *testing.T) {
	_, err, done, retryErr := fakeCanceledStartFixture(t, true)
	if !errors.Is(err, context.Canceled) || !errors.Is(err, ErrStop) || done || !errors.Is(retryErr, ErrAlreadyRunning) {
		t.Fatalf("unconfirmed canceled Start lost its owned slot: error=%v done=%v retry=%v", err, done, retryErr)
	}
}
