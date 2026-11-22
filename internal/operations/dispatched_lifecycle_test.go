// SPDX-License-Identifier: AGPL-3.0-only

package operations

import (
	"context"
	"encoding/json"
	"sync"
	"testing"
	"time"

	"github.com/qwq-panel/qwq/internal/actor"
	"github.com/qwq-panel/qwq/internal/platform/ids"
	"github.com/qwq-panel/qwq/internal/storage"
)

// ======================== 复用真实 SQLite / RBAC 与已经运行的 executor ========================

func dispatchedLifecycleFixture(t *testing.T) (*dispatchedFixture, DispatchedContext) {
	t.Helper()
	f := newDispatchedFixture(t)
	f.start(t, f.human, PlacementController)
	accepted, err := f.env.svc.ResolveDispatched(f.env.ctx, f.exact, f.id)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(accepted.Clear)
	return f, accepted
}

func TestDispatchedJobContextUsesExecutorAfterRPCLifetimeEnds(t *testing.T) {
	f, accepted := dispatchedLifecycleFixture(t)
	rpc, cancelRPC := context.WithTimeout(f.env.ctx, time.Second)
	defer cancelRPC()
	worker, release, err := f.env.svc.DispatchedJobContext(rpc, accepted)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	deadline, bounded := worker.Deadline()
	rpcDeadline, _ := rpc.Deadline()
	if !bounded || !deadline.After(rpcDeadline) || deadline.After(time.Now().Add(accepted.Deadline.Sub(f.env.clock.Now()))) {
		t.Fatal("任务未继承原 executor 的独立硬期限")
	}
	cancelRPC()
	if worker.Err() != nil {
		t.Fatal("已经接受的原 job 被 RPC 返回后的取消截断")
	}
	release()
	release()
	if worker.Err() != context.Canceled {
		t.Fatal("任务上下文的幂等释放没有撤销所有子调用")
	}
	current, err := f.env.svc.ResolveDispatched(f.env.ctx, f.exact, f.id)
	current.Clear()
	if err != nil {
		t.Fatal("释放子任务意外取消了原 executor")
	}
}

// ======================== 原取消、宿主关闭、逻辑期限与入口期间撤权 ========================

func TestDispatchedJobContextInheritsCancellationStopAndEarlierDeadline(t *testing.T) {
	for _, reason := range []string{"executor", "stop", "deadline"} {
		t.Run(reason, func(t *testing.T) {
			f, accepted := dispatchedLifecycleFixture(t)
			if reason == "deadline" {
				f.env.clock.Advance(accepted.Deadline.Sub(f.env.clock.Now()) - 250*time.Millisecond)
			}
			worker, release, err := f.env.svc.DispatchedJobContext(f.env.ctx, accepted)
			if err != nil {
				t.Fatal(err)
			}
			defer release()
			switch reason {
			case "executor":
				f.env.svc.runMu.Lock()
				cancel := f.env.svc.running[f.id].cancel
				f.env.svc.runMu.Unlock()
				cancel()
			case "stop":
				f.env.svc.Stop()
			}
			select {
			case <-worker.Done():
			case <-time.After(2 * time.Second):
				t.Fatal("原 executor 取消、关闭或更早期限未终止子任务")
			}
		})
	}
}

func TestDispatchedJobContextRejectsExpiredCanceledAndRevokedEntry(t *testing.T) {
	for _, reason := range []string{"expired", "cancelled-input", "cancel-requested", "revoked-during-read"} {
		t.Run(reason, func(t *testing.T) {
			f, accepted := dispatchedLifecycleFixture(t)
			ctx := f.env.ctx
			switch reason {
			case "expired":
				f.env.clock.Advance(accepted.Deadline.Sub(f.env.clock.Now()) + time.Nanosecond)
			case "cancelled-input":
				cancelled, cancel := context.WithCancel(ctx)
				cancel()
				ctx = cancelled
			case "cancel-requested":
				_, err := f.env.svc.Cancel(ctx, CancelRequest{Actor: f.human, OperationID: f.id,
					Idempotency: Idempotency{Key: f.env.newKey(), Method: "POST", Route: "/fixture/cancel"}})
				if err != nil {
					t.Fatal(err)
				}
			case "revoked-during-read":
				f.rbac.mu.Lock()
				f.rbac.after = func(readCtx context.Context) error {
					return f.env.db.Update(readCtx, func(tx *storage.Tx) error {
						_, err := tx.ExecContext(readCtx, "UPDATE users SET role='viewer' WHERE user_id=?", f.human.ID)
						return err
					})
				}
				f.rbac.mu.Unlock()
			}
			worker, release, err := f.env.svc.DispatchedJobContext(ctx, accepted)
			if release != nil {
				release()
			}
			if err == nil || worker != nil {
				t.Fatal("已经取消、到期或读取期间撤权的意图仍取得任务生命周期")
			}
		})
	}
}

// ======================== DTO 与失效 proof 不能兑换新的执行上下文 ========================

func TestDispatchedJobContextRejectsForgedSnapshotsAndReplica(t *testing.T) {
	f, accepted := dispatchedLifecycleFixture(t)
	changes := []func(*DispatchedContext){
		func(value *DispatchedContext) { value.runtimeProof = nil },
		func(value *DispatchedContext) { value.Actor.ID = f.env.ids.New(ids.User) },
		func(value *DispatchedContext) { value.Actor.Kind = actor.System },
		func(value *DispatchedContext) { value.Actor.SessionID = f.human.SessionID },
		func(value *DispatchedContext) { value.Target.Subject += "/foreign" },
		func(value *DispatchedContext) { value.Args = json.RawMessage(`{"foreign":true}`) },
		func(value *DispatchedContext) { value.ArgsDigest = "foreign" },
		func(value *DispatchedContext) { value.Action.Source = HostSource },
		func(value *DispatchedContext) { value.Action.Mode = ModeInvoke },
		func(value *DispatchedContext) { value.Deadline = value.Deadline.Add(time.Minute) },
		func(value *DispatchedContext) { value.Limits.MaxRisk = RiskHigh },
		func(value *DispatchedContext) { value.Approved = !value.Approved },
		func(value *DispatchedContext) { value.ConfirmationActor = f.human },
	}
	for _, change := range changes {
		copy := accepted
		change(&copy)
		worker, release, err := f.env.svc.DispatchedJobContext(f.env.ctx, copy)
		if release != nil {
			release()
		}
		if err == nil || worker != nil {
			t.Fatal("可变 DTO、风险或来源字段替代了原私有 proof")
		}
	}
	encoded, err := json.Marshal(accepted)
	if err != nil {
		t.Fatal(err)
	}
	var restored DispatchedContext
	if err := json.Unmarshal(encoded, &restored); err != nil {
		t.Fatal(err)
	}
	if worker, release, err := f.env.svc.DispatchedJobContext(f.env.ctx, restored); err == nil || worker != nil {
		if release != nil {
			release()
		}
		t.Fatal("JSON 或存档元数据复活了运行许可")
	}
	replica, err := New(Options{DB: f.env.db, Clock: f.env.clock, Catalog: f.env.catalog, Authorizer: f.rbac,
		Policy: dispatchPolicies{backend: f.authz}})
	if err != nil {
		t.Fatal(err)
	}
	if worker, release, err := replica.DispatchedJobContext(f.env.ctx, accepted); err == nil || worker != nil {
		if release != nil {
			release()
		}
		t.Fatal("只有同一 SQLite RUNNING 行的副本取得了原 executor")
	}
}

func TestDispatchedJobContextRejectsReplacedOrUnbackedExecutor(t *testing.T) {
	f, accepted := dispatchedLifecycleFixture(t)
	f.env.svc.unregisterRunning(f.id)
	if !f.env.svc.registerRunning(f.id, func() {}) {
		t.Fatal("内部替换夹具未安装")
	}
	if worker, release, err := f.env.svc.DispatchedJobContext(f.env.ctx, accepted); err == nil || worker != nil {
		if release != nil {
			release()
		}
		t.Fatal("旧 proof 穿过了真实 executor 替换")
	}
	current, err := f.env.svc.ResolveDispatched(f.env.ctx, f.exact, f.id)
	if err != nil {
		t.Fatal(err)
	}
	defer current.Clear()
	if worker, release, err := f.env.svc.DispatchedJobContext(f.env.ctx, current); err == nil || worker != nil {
		if release != nil {
			release()
		}
		t.Fatal("只登记 cancel/done、没有实际 runCtx 的旧内部 wrapper 取得生命周期")
	}
}

func TestDispatchedJobContextRevokesCreatedScopeWhenExecutorEnds(t *testing.T) {
	f, accepted := dispatchedLifecycleFixture(t)
	worker, release, err := f.env.svc.DispatchedJobContext(f.env.ctx, accepted)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	f.env.svc.unregisterRunning(f.id)
	if worker.Err() != context.Canceled {
		t.Fatal("executor 已结束但此前派生的能力子任务仍能继续")
	}
}

// ======================== 并发仅派生受控子上下文，不修改共享 proof ========================

func TestDispatchedJobContextConcurrentDerivationAndRelease(t *testing.T) {
	f, accepted := dispatchedLifecycleFixture(t)
	var workers sync.WaitGroup
	for range 16 {
		workers.Go(func() {
			worker, release, err := f.env.svc.DispatchedJobContext(f.env.ctx, accepted)
			if err != nil {
				t.Error(err)
				return
			}
			var releasers sync.WaitGroup
			for range 2 {
				releasers.Go(release)
			}
			releasers.Wait()
			if worker.Err() != context.Canceled {
				t.Error("并发释放没有关闭子任务")
			}
		})
	}
	workers.Wait()
	current, err := f.env.svc.ResolveDispatched(f.env.ctx, f.exact, f.id)
	current.Clear()
	if err != nil {
		t.Fatal("并发子任务改写或取消了原执行许可")
	}
}
