// SPDX-License-Identifier: AGPL-3.0-only

//go:build e2e && linux

package e2e

import (
	"context"
	"os"
	"os/exec"
	"runtime"
	"slices"
	"syscall"
	"testing"
	"time"
)

// ======================== 真实非主线程 fork 与有界回收 ========================

func TestProcessChildrenIncludesLockedWorkerThread(t *testing.T) {
	type startedChild struct {
		thread int
		pid    int
		err    error
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	started := make(chan startedChild, 2)
	done := make(chan error, 2)
	t.Cleanup(func() {
		cancel()
		for range 2 {
			select {
			case err := <-done:
				if err != nil {
					t.Error("非主线程测试子进程异常退出")
				}
			case <-time.After(3 * time.Second):
				t.Error("非主线程测试子进程未回收")
			}
		}
	})
	// 两个工作线程同时保持锁定，至少一个不是线程组主线程。
	for range 2 {
		go func() {
			runtime.LockOSThread()
			defer runtime.UnlockOSThread()
			var completionErr error
			defer func() { done <- completionErr }()
			command := exec.CommandContext(ctx, "/bin/sleep", "10")
			command.Env = []string{"PATH=/usr/bin:/bin", "LANG=C"}
			command.WaitDelay = time.Second
			err := command.Start()
			result := startedChild{thread: syscall.Gettid(), err: err}
			if err == nil {
				result.pid = command.Process.Pid
			}
			started <- result
			if err == nil {
				if waitErr := command.Wait(); waitErr != nil && ctx.Err() == nil {
					completionErr = waitErr
				}
			}
		}()
	}
	workerPID := 0
	for range 2 {
		select {
		case child := <-started:
			if child.err != nil {
				t.Fatal("非主线程测试子进程启动失败")
			}
			if child.thread != os.Getpid() {
				workerPID = child.pid
			}
		case <-ctx.Done():
			t.Fatal("非主线程子进程确认超时")
		}
	}
	if workerPID == 0 {
		t.Fatal("未产生真实非主线程子进程")
	}
	children, err := processChildren(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(children, workerPID) {
		t.Fatal("子进程枚举漏掉了由真实 Go 工作线程创建的子进程")
	}
}
