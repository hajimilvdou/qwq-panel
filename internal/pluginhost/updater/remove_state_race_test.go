// SPDX-License-Identifier: AGPL-3.0-only

package updater

import (
	"context"
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/qwq-panel/qwq/internal/platform/problem"
	"github.com/qwq-panel/qwq/internal/storage"
)

// ============================================================================
// 原存储提交后日志提供真实交错点：SQL 已提交，卸载还没有清理活动缓存。
// ============================================================================

type purgeCommitGate struct {
	armed     atomic.Bool
	started   atomic.Bool
	committed chan struct{}
	otherTx   chan struct{}
	release   chan struct{}
}

func (*purgeCommitGate) Enabled(context.Context, slog.Level) bool { return true }
func (g *purgeCommitGate) WithAttrs([]slog.Attr) slog.Handler     { return g }
func (g *purgeCommitGate) WithGroup(string) slog.Handler          { return g }
func (g *purgeCommitGate) Handle(ctx context.Context, record slog.Record) error {
	if record.Message != "slow write transaction" || !g.started.Load() {
		return nil
	}
	if g.armed.Swap(false) {
		close(g.committed)
		select {
		case <-g.release:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	select {
	case g.otherTx <- struct{}{}:
	default:
	}
	return nil
}

func TestRemovePurgePreventsStateWriteAfterDatabaseCommit(t *testing.T) {
	gate := &purgeCommitGate{committed: make(chan struct{}), otherTx: make(chan struct{}, 1), release: make(chan struct{})}
	e := newEnvWithStorage(t, func(options *storage.Options) {
		options.SlowTx = time.Nanosecond
		options.Logger = slog.New(gate)
	})
	e.mustInstallV1("acme.demo")
	if err := e.u.SetEnabled(t.Context(), "acme.demo", false); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(gate.release) }) }
	var workers sync.WaitGroup
	t.Cleanup(func() {
		release()
		done := make(chan struct{})
		go func() {
			workers.Wait()
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("purge race workers did not stop")
		}
	})
	gate.armed.Store(true)
	gate.started.Store(true)
	removed := make(chan error, 1)
	workers.Add(1)
	go func() {
		defer workers.Done()
		removed <- e.u.Remove(ctx, RemoveRequest{PluginID: "acme.demo", PurgeData: true})
	}()
	select {
	case <-gate.committed:
	case <-ctx.Done():
		t.Fatal("the uninstall did not reach the actual commit window")
	}
	if got := purgeRowCount(t, e.db, "plugin_versions", "acme.demo"); got != 0 {
		t.Fatalf("uninstall has not committed: %d versions", got)
	}
	if _, active := e.u.Active("acme.demo"); !active {
		t.Fatal("the fixture did not hold the stale active cache window")
	}
	enabled := make(chan error, 1)
	workers.Add(1)
	go func() {
		defer workers.Done()
		enabled <- e.u.SetEnabled(ctx, "acme.demo", false)
	}()
	select {
	case <-gate.otherTx:
	case <-ctx.Done():
		t.Fatal("the parallel state write did not reach its transaction boundary")
	}
	release()
	select {
	case err := <-removed:
		if err != nil {
			t.Fatalf("purge: %v", err)
		}
	case <-ctx.Done():
		t.Fatal("purge did not finish")
	}
	select {
	case err := <-enabled:
		if !problem.HasCode(err, problem.NotFound) {
			t.Errorf("state write after purge commit=%v; want NOT_FOUND", err)
		}
	case <-ctx.Done():
		t.Fatal("the parallel state operation did not finish")
	}
	if got := purgeRowCount(t, e.db, "plugin_states", "acme.demo"); got != 0 {
		t.Errorf("parallel enable/disable recreated %d rows after purge", got)
	}
}
