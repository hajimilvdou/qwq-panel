// SPDX-License-Identifier: AGPL-3.0-only

//go:build linux

package coreproc

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// TestFakeCoreHelperProcess 是短时 Go 子进程，不是 Xray，也不监听网络。
func TestFakeCoreHelperProcess(t *testing.T) {
	mode := os.Getenv("QWQ_TEST_COREPROC_MODE")
	if mode == "" {
		return
	}
	ready := func() {
		if err := os.WriteFile(os.Getenv("QWQ_TEST_COREPROC_READY"), []byte("ready"), 0o600); err != nil {
			os.Exit(2)
		}
	}
	if mode == "exit" {
		ready()
		time.Sleep(250 * time.Millisecond)
		os.Exit(0)
	}
	if mode == "ignore-term" {
		signal.Ignore(syscall.SIGTERM)
		ready()
	} else {
		ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM)
		defer stop()
		ready()
		select {
		case <-ctx.Done():
		case <-time.After(5 * time.Second):
		}
		os.Exit(0)
	}
	// 独立安全时限，即使父测试异常退出，也不会遗留无限运行的夹具。
	time.Sleep(5 * time.Second)
	os.Exit(0)
}

type fakeStats struct {
	err        error
	closed     atomic.Int32
	onCounters func()
}

func (f *fakeStats) Get(context.Context, string) (int64, error) { return 0, f.err }
func (f *fakeStats) Counters(context.Context) (map[string]int64, error) {
	if f.onCounters != nil {
		f.onCounters()
	}
	return map[string]int64{"inbound>>>qwq-in-main>>>traffic>>>uplink": 0}, f.err
}
func (f *fakeStats) Close() error { f.closed.Add(1); return nil }

type processFixture struct {
	manager  *Manager
	cancel   context.CancelFunc
	exits    chan error
	commands atomic.Int32
	stats    *fakeStats
	ready    string
}

func fakeProcessFixture(t *testing.T, mode string, apiErr error) *processFixture {
	t.Helper()
	lifetime, cancel := context.WithCancel(t.Context())
	directory, err := os.MkdirTemp("", "coreproc-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	fixture := &processFixture{cancel: cancel, exits: make(chan error, 1), stats: &fakeStats{err: apiErr}, ready: filepath.Join(directory, "ready")}
	var tasks sync.WaitGroup
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	fixture.manager, err = New(Options{
		Socket: filepath.Join(directory, "api.sock"), StopGrace: 100 * time.Millisecond,
		Track: func(fn func(context.Context)) error {
			tasks.Add(1)
			go func() { defer tasks.Done(); fn(lifetime) }()
			return nil
		},
		Command: func(ctx context.Context, _ string) (*exec.Cmd, error) {
			fixture.commands.Add(1)
			command := exec.CommandContext(ctx, executable, "-test.run=^TestFakeCoreHelperProcess$")
			_ = os.Remove(fixture.ready)
			command.Env = []string{"QWQ_TEST_COREPROC_MODE=" + mode, "QWQ_TEST_COREPROC_READY=" + fixture.ready}
			return command, nil
		},
		API:    func(string) (Stats, error) { return fixture.stats, nil },
		OnExit: func(err error) { fixture.exits <- err },
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cancel()
		ctx, stop := context.WithTimeout(context.Background(), 2*time.Second)
		defer stop()
		if err := fixture.manager.Stop(ctx); err != nil {
			t.Error(err)
		}
		tasks.Wait()
	})
	return fixture
}

func (f *processFixture) waitReady(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	for {
		if _, err := os.Stat(f.ready); err == nil {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatal("fake helper did not confirm its signal setup")
		case <-time.After(5 * time.Millisecond):
		}
	}
}

func fakeStartSpec(t *testing.T) StartSpec {
	t.Helper()
	return StartSpec{ConfigPath: filepath.Join(t.TempDir(), "config.json"), Digest: "sha256:" + strings.Repeat("a", 64), InboundID: "main"}
}

// ======================== fake 程序与真实进程所有权 ========================
func TestFakeProcessExpiredSnapshotKeepsIndependentRunningFact(t *testing.T) {
	fixture := fakeProcessFixture(t, "wait", nil)
	if err := fixture.manager.Start(t.Context(), fakeStartSpec(t)); err != nil {
		t.Fatal(err)
	}
	fixture.waitReady(t)
	if err := fixture.manager.WaitHealthy(t.Context()); err != nil {
		t.Fatal(err)
	}
	expired, cancel := context.WithCancel(t.Context())
	cancel()
	observed := fixture.manager.Snapshot(expired)
	if observed.State != "RUNNING" || observed.APIState != "UNAVAILABLE" || observed.PID <= 0 {
		t.Fatal("expired API probe changed the independent running process fact")
	}
	if fresh := fixture.manager.Snapshot(t.Context()); fresh.State != "RUNNING" || fresh.APIState != "READY" {
		t.Fatal("a failed expired probe stopped the healthy managed process")
	}
}

func TestFakeProcessRequestContextDoesNotOwnRuntime(t *testing.T) {
	fixture := fakeProcessFixture(t, "wait", nil)
	ctx, cancel := context.WithCancel(t.Context())
	if err := fixture.manager.Start(ctx, fakeStartSpec(t)); err != nil {
		t.Fatal(err)
	}
	fixture.waitReady(t)
	if err := fixture.manager.WaitHealthy(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := fixture.manager.MarkCommitted(); err != nil {
		t.Fatal(err)
	}
	before := fixture.manager.Snapshot(t.Context())
	cancel()
	time.Sleep(30 * time.Millisecond)
	after := fixture.manager.Snapshot(t.Context())
	if after.State != "RUNNING" || after.APIState != "READY" || after.PID != before.PID || after.Epoch == "" {
		t.Fatal("request cancellation terminated the committed runtime")
	}
	if err := fixture.manager.Stop(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Kill(before.PID, 0); !errors.Is(err, syscall.ESRCH) {
		t.Fatal("managed process was not reaped")
	}
	if fixture.stats.closed.Load() != 1 {
		t.Fatal("owned API client was not closed exactly once")
	}
}

func TestFakeProcessLifetimeCancellationAndBoundedStop(t *testing.T) {
	fixture := fakeProcessFixture(t, "ignore-term", nil)
	if err := fixture.manager.Start(t.Context(), fakeStartSpec(t)); err != nil {
		t.Fatal(err)
	}
	fixture.waitReady(t)
	if err := fixture.manager.MarkCommitted(); err != nil {
		t.Fatal(err)
	}
	fixture.cancel()
	ctx, stop := context.WithTimeout(t.Context(), time.Second)
	defer stop()
	if err := fixture.manager.Stop(ctx); err != nil {
		t.Fatal("SDK lifetime cancellation did not reclaim the process")
	}
	select {
	case <-fixture.exits:
		t.Fatal("intentional lifetime stop triggered unexpected-exit recovery")
	default:
	}
}

func TestFakeProcessRefusesOverlapAndChangesEpoch(t *testing.T) {
	fixture := fakeProcessFixture(t, "wait", nil)
	spec := fakeStartSpec(t)
	if err := fixture.manager.Start(t.Context(), spec); err != nil {
		t.Fatal(err)
	}
	first := fixture.manager.Snapshot(t.Context())
	if err := fixture.manager.Start(t.Context(), spec); !errors.Is(err, ErrAlreadyRunning) || fixture.commands.Load() != 1 {
		t.Fatal("a second process overlapped the first")
	}
	if err := fixture.manager.Stop(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := fixture.manager.Start(t.Context(), spec); err != nil {
		t.Fatal(err)
	}
	second := fixture.manager.Snapshot(t.Context())
	if first.Epoch == second.Epoch || first.PID == second.PID {
		t.Fatal("restart reused process identity or statistics epoch")
	}
}

func TestFakeProcessAPIErrorIsNotHiddenByAliveProcess(t *testing.T) {
	fixture := fakeProcessFixture(t, "wait", errors.New("fake API diagnostic"))
	if err := fixture.manager.Start(t.Context(), fakeStartSpec(t)); err != nil {
		t.Fatal(err)
	}
	ctx, stop := context.WithTimeout(t.Context(), 40*time.Millisecond)
	defer stop()
	if err := fixture.manager.WaitHealthy(ctx); !errors.Is(err, ErrUnhealthy) {
		t.Fatal("API failure was hidden by a live PID")
	}
	snapshot := fixture.manager.Snapshot(t.Context())
	if snapshot.State != "RUNNING" || snapshot.APIState != "UNAVAILABLE" {
		t.Fatal("process and API states were conflated")
	}
}

func TestFakeProcessUnconfirmedStopRemainsStopping(t *testing.T) {
	fixture := fakeProcessFixture(t, "ignore-term", nil)
	fixture.manager.options.StopGrace = 500 * time.Millisecond
	spec := fakeStartSpec(t)
	if err := fixture.manager.Start(t.Context(), spec); err != nil {
		t.Fatal(err)
	}
	fixture.waitReady(t)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Millisecond)
	defer cancel()
	if err := fixture.manager.Stop(ctx); !errors.Is(err, ErrStop) {
		t.Fatal("short deadline unexpectedly confirmed process stop")
	}
	snapshot := fixture.manager.Snapshot(t.Context())
	if snapshot.State != "STOPPING" || snapshot.APIState != "UNAVAILABLE" {
		t.Fatal("unconfirmed process reclamation was reported as stopped/ready")
	}
	if err := fixture.manager.Start(t.Context(), spec); !errors.Is(err, ErrAlreadyRunning) {
		t.Fatal("unconfirmed old process allowed an overlapping start")
	}
}

func TestFakeProcessExitOnlyEscalatesCommittedGeneration(t *testing.T) {
	for _, committed := range []bool{false, true} {
		t.Run(map[bool]string{false: "candidate", true: "committed"}[committed], func(t *testing.T) {
			fixture := fakeProcessFixture(t, "exit", nil)
			if err := fixture.manager.Start(t.Context(), fakeStartSpec(t)); err != nil {
				t.Fatal(err)
			}
			if committed {
				if err := fixture.manager.MarkCommitted(); err != nil {
					t.Fatal(err)
				}
			}
			// race 子进程在退出时还会执行运行库的收尾，不能只等普通模式的 250ms。
			deadline := time.NewTimer(3 * time.Second)
			defer deadline.Stop()
			if committed {
				select {
				case err := <-fixture.exits:
					if !errors.Is(err, ErrExited) {
						t.Fatal("unexpected exit leaked an underlying diagnostic")
					}
				case <-deadline.C:
					t.Fatal("committed exit did not notify the fault domain")
				}
			} else {
				fixture.manager.mu.Lock()
				done := fixture.manager.current.done
				fixture.manager.mu.Unlock()
				select {
				case <-done:
				case <-deadline.C:
					t.Fatal("candidate process did not exit and release its runner")
				}
				select {
				case <-fixture.exits:
					t.Fatal("candidate exit prevented transaction rollback")
				default:
				}
			}
		})
	}
}
