// SPDX-License-Identifier: AGPL-3.0-only

package capability

import (
	"context"
	"encoding/json"
	"sync"
	"testing"
	"time"

	"github.com/qwq-panel/qwq/internal/operations"
	"github.com/qwq-panel/qwq/internal/platform/ids"
	"github.com/qwq-panel/qwq/internal/prerequisites/fault"
	"github.com/qwq-panel/qwq/internal/prerequisites/hostauth"
	"github.com/qwq-panel/qwq/internal/storage"
)

// ======================== 精确任务意图、撤权与关闭竞争 ========================

func TestTasksCancelRequiresExactCurrentTaskWrite(t *testing.T) {
	f := newTaskFixture(t)
	work := &heldTask{allow: make(chan struct{}), ready: make(chan struct{})}
	pool := f.pool(t, work, 1)
	ctx, args := f.testCall(t, "cert-cancel", "attempt-cancel")
	one, err := pool.Submit(ctx, TestTask, args.CertificateID, args.AttemptID, "absent")
	if err != nil {
		t.Fatal(err)
	}
	awaitTaskSignal(t, work.ready)
	query := f.start(t, "tasks.get", "plugins/tls.certificates/resources/tasks/"+one.Id, "absent", hostauth.TaskArgs{TaskID: one.Id})
	if _, err := pool.Cancel(query, one.Id); fault.Code(err) != "PERMISSION_DENIED" {
		t.Fatal("任务查询意图执行了取消")
	}
	if _, err := pool.Get(ctx, one.Id); err == nil {
		t.Fatal("原证书写意图被替换成任务查询意图")
	}
	wrong := f.start(t, "tasks.cancel", "plugins/tls.certificates/resources/tasks/other-task", "absent", hostauth.TaskArgs{TaskID: "other-task"})
	if _, err := pool.Cancel(wrong, one.Id); fault.Code(err) != "PERMISSION_DENIED" {
		t.Fatal("其他任务的取消意图停掉了当前任务")
	}
	cancel := f.start(t, "tasks.cancel", "plugins/tls.certificates/resources/tasks/"+one.Id, "absent", hostauth.TaskArgs{TaskID: one.Id})
	if _, err := pool.Cancel(cancel, one.Id); err != nil {
		t.Fatal(err)
	}
	drainTasks(t, pool, "")
	view, err := pool.Get(query, one.Id)
	if err != nil || view.Status != "cancelled" || view.Stage != "waiting_dns" || view.Percent != 10 || work.calls.Load() != 1 {
		t.Fatal("精确取消没有保留原任务的最终收据")
	}
}

func TestTasksOriginalOperationCancellationAndRoleRevocationStopNetworkWait(t *testing.T) {
	for _, trigger := range []string{"operation", "role"} {
		t.Run(trigger, func(t *testing.T) {
			f := newTaskFixture(t)
			work := &heldTask{allow: make(chan struct{}), ready: make(chan struct{})}
			pool := f.pool(t, work, 1)
			ctx, args := f.testCall(t, "cert-lifetime", "attempt-lifetime")
			one, err := pool.Submit(ctx, TestTask, args.CertificateID, args.AttemptID, "absent")
			if err != nil {
				t.Fatal(err)
			}
			awaitTaskSignal(t, work.ready)
			switch trigger {
			case "operation":
				invocation, err := f.authority.CurrentInvocation(ctx)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := f.host.Operations.Cancel(f.host.Context, operations.CancelRequest{Actor: f.host.Human, OperationID: invocation.OperationID,
					Idempotency: operations.Idempotency{Key: f.host.IDs.New(ids.Operation), Method: "POST", Route: "/fixture/cancel-original"}}); err != nil {
					t.Fatal(err)
				}
			case "role":
				if err := f.host.DB.Update(f.host.Context, func(tx *storage.Tx) error {
					_, err := tx.ExecContext(f.host.Context, "UPDATE users SET role='viewer', revision=revision+1 WHERE user_id=?", f.host.Human.ID)
					return err
				}); err != nil {
					t.Fatal(err)
				}
			}
			drainTasks(t, pool, "")
			record, _, found, err := pool.loadTask(f.host.Context, one.Id)
			if err != nil || !found || record.State != "cancelled" || record.Stage != "waiting_dns" || work.calls.Load() != 1 {
				t.Fatal("取消或撤权后网络等待任务没有结束并保存原收据")
			}
		})
	}
}

func TestTasksConcurrentCloseAndReplayNeverDuplicateOrLeakWorkers(t *testing.T) {
	f := newTaskFixture(t)
	work := &heldTask{allow: make(chan struct{}), ready: make(chan struct{})}
	pool := f.pool(t, work, 1)
	ctx, args := f.testCall(t, "cert-close-race", "attempt-close-race")
	one, err := pool.Submit(ctx, TestTask, args.CertificateID, args.AttemptID, "absent")
	if err != nil {
		t.Fatal(err)
	}
	awaitTaskSignal(t, work.ready)
	gate := make(chan struct{})
	var parallel sync.WaitGroup
	for index := range 8 {
		parallel.Add(1)
		go func() {
			defer parallel.Done()
			<-gate
			if index%2 == 0 {
				closeCtx, stop := context.WithTimeout(context.Background(), 5*time.Second)
				defer stop()
				if err := pool.Close(closeCtx); err != nil {
					t.Error(err)
				}
				return
			}
			view, err := pool.Submit(ctx, TestTask, args.CertificateID, args.AttemptID, "absent")
			if err != nil {
				if fault.Code(err) != "UNAVAILABLE" {
					t.Error("关闭竞争中出现非预期提交结果")
				}
			} else if view.Id != one.Id {
				t.Error("关闭竞争中产生另一任务")
			}
		}()
	}
	close(gate)
	parallel.Wait()
	drainTasks(t, pool, "")
	if _, err := pool.Submit(ctx, TestTask, args.CertificateID, args.AttemptID, "absent"); fault.Code(err) != "UNAVAILABLE" || work.calls.Load() != 1 {
		t.Fatal("关闭后仍提交任务或重复启动原worker")
	}
	pool.mu.Lock()
	active := len(pool.active)
	pool.mu.Unlock()
	if active != 0 {
		t.Fatal("并发关闭没有释放任务容量")
	}
}

func TestTasksPersistedRunningReceiptNeverRestartsWorkerAndRejectsCorruption(t *testing.T) {
	f := newTaskFixture(t)
	work := &heldTask{allow: make(chan struct{})}
	pool := f.pool(t, work, 1)
	ctx, args := f.testCall(t, "cert-old-receipt", "attempt-old-receipt")
	one, err := pool.Submit(ctx, TestTask, args.CertificateID, args.AttemptID, "absent")
	if err != nil {
		t.Fatal(err)
	}
	close(work.allow)
	drainTasks(t, pool, "")
	record, revision, found, err := pool.loadTask(f.host.Context, one.Id)
	if err != nil || !found {
		t.Fatal("缺少真实原任务收据")
	}
	record.State, record.Stage, record.Percent = "running", "issuing", 80
	revision, err = pool.saveTask(f.host.Context, record, revision)
	if err != nil {
		t.Fatal(err)
	}
	restarted := f.pool(t, work, 1, pool.repository)
	replayed, err := restarted.Submit(ctx, TestTask, args.CertificateID, args.AttemptID, "absent")
	if err != nil || replayed.Status != "outcome_unknown" || work.calls.Load() != 1 {
		t.Fatal("旧私有running行在无原worker时恢复了执行权限")
	}
	query := f.start(t, "tasks.get", "plugins/tls.certificates/resources/tasks/"+one.Id, "absent", hostauth.TaskArgs{TaskID: one.Id})
	for _, mutation := range []struct {
		name string
		edit func(*taskRecord)
	}{
		{"owner_route", func(value *taskRecord) {
			value.Origin.Subject = "plugins/tls.certificates/resources/certificates/other"
		}},
		{"version", func(value *taskRecord) { value.Version++ }},
		{"percent", func(value *taskRecord) { value.Percent = 101 }},
		{"stage", func(value *taskRecord) { value.Stage = "untrusted-detail" }},
		{"error_code", func(value *taskRecord) { value.ErrorCode = "untrusted\nerror" }},
	} {
		t.Run(mutation.name, func(t *testing.T) {
			changed := record
			mutation.edit(&changed)
			var err error
			revision, err = pool.saveTask(f.host.Context, changed, revision)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := restarted.Get(query, one.Id); fault.Code(err) != "STATE_INVALID" {
				t.Fatal("损坏收据被读取为有效任务")
			}
			revision, err = pool.saveTask(f.host.Context, record, revision)
			if err != nil {
				t.Fatal(err)
			}
		})
	}
	entry, found, err := pool.repository.Get(f.host.Context, taskKey(one.Id))
	if err != nil || !found {
		t.Fatal("旧收据fixture丢失")
	}
	defer clear(entry.Value)
	duplicate := append([]byte(`{"stage":"issuing",`), entry.Value[1:]...)
	if _, err := pool.repository.Put(f.host.Context, taskKey(one.Id), revision, duplicate); err != nil {
		t.Fatal(err)
	}
	if _, err := restarted.Get(query, one.Id); fault.Code(err) != "STATE_INVALID" || work.calls.Load() != 1 {
		t.Fatal("重复JSON成员被接纳或重启了原任务")
	}
	var public map[string]any
	raw, err := json.Marshal(replayed)
	if err != nil || json.Unmarshal(raw, &public) != nil || public["origin"] != nil || public["actor"] != nil || public["args"] != nil {
		t.Fatal("公开任务视图泄漏私有授权来源")
	}
}
