// SPDX-License-Identifier: AGPL-3.0-only

package capability

import (
	"context"
	"encoding/json"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/qwq-panel/qwq/internal/actor"
	"github.com/qwq-panel/qwq/internal/operations"
	"github.com/qwq-panel/qwq/internal/platform/clock"
	"github.com/qwq-panel/qwq/internal/platform/ids"
	"github.com/qwq-panel/qwq/internal/prerequisites/certificates"
	"github.com/qwq-panel/qwq/internal/prerequisites/fault"
	"github.com/qwq-panel/qwq/internal/prerequisites/hostauth"
	"github.com/qwq-panel/qwq/internal/prerequisites/store"
	"github.com/qwq-panel/qwq/internal/prerequisites/testsupport"
	"github.com/qwq-panel/qwq/internal/storage"
	"github.com/qwq-panel/qwq/internal/tlsmgr"
)

// ======================== 基础宿主直接复用共享真实身份与 SQLite ========================

type taskCatalog struct {
	mu      sync.Mutex
	actions map[string]operations.Action
}

func (c *taskCatalog) Action(id string) (operations.Action, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	value, ok := c.actions[id]
	return value, ok
}

type taskDispatch struct {
	started chan context.Context
	done    chan struct{}
}

func (*taskDispatch) Plan(context.Context, operations.PluginPlanRequest) (operations.Preview, error) {
	return operations.Preview{}, nil
}
func (*taskDispatch) Invoke(context.Context, operations.PluginInvokeRequest) (operations.PluginInvokeResponse, error) {
	return operations.PluginInvokeResponse{}, nil
}
func (d *taskDispatch) RunJob(ctx context.Context, _ operations.PluginRunJobRequest, _ func(operations.JobProgress) error) error {
	d.started <- ctx
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-d.done:
		return nil
	}
}
func (*taskDispatch) Cancel(context.Context, operations.PluginCancelRequest) error { return nil }

type taskFixture struct {
	host      *testsupport.HostFixture
	catalog   *taskCatalog
	dispatch  *taskDispatch
	authority *hostauth.Authority
	clock     *clock.Fake
}

func newTaskFixture(t *testing.T) *taskFixture {
	t.Helper()
	f := &taskFixture{catalog: &taskCatalog{actions: make(map[string]operations.Action)}, dispatch: &taskDispatch{started: make(chan context.Context, 8), done: make(chan struct{})}, clock: clock.NewFake(time.Now().UTC())}
	f.host = testsupport.NewHost(t, f.clock, f.catalog, f.dispatch)
	f.host.User(t, "task-admin", "admin")
	t.Cleanup(func() { close(f.dispatch.done) })
	var err error
	f.authority, err = hostauth.New(hostauth.Options{DB: f.host.DB, Secrets: f.host.Secrets, Authorizer: f.host.Authorizer, Operations: f.host.Operations, OwnerID: "installation", NodeID: "local", Clock: f.clock})
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *taskFixture) start(t *testing.T, operation, subject, expected string, args any) context.Context {
	t.Helper()
	return f.startAs(t, f.host.Human, operation, subject, expected, args)
}

func (f *taskFixture) startAs(t *testing.T, who actor.Actor, operation, subject, expected string, args any) context.Context {
	t.Helper()
	action := operations.Action{ID: "tls.certificates/" + operation, Summary: "实际任务回归", Effect: operations.EffectWrite, Risk: operations.RiskHigh, Mode: operations.ModeJob,
		Idempotent: true, Source: operations.PluginSource, PluginID: "tls.certificates", Placement: operations.PlacementController, Operation: operation, APIVersion: "1",
		Permission: "system.certificates:manage", Approval: operations.ApprovalConfirm, TimeoutMS: 30000, Capabilities: []operations.Capability{{Name: "system.certificates.manage", Scope: "self"}}}
	f.catalog.mu.Lock()
	f.catalog.actions[action.ID] = action
	f.catalog.mu.Unlock()
	raw, err := json.Marshal(args)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(raw)
	response, err := f.host.Operations.Run(f.host.Context, operations.RunRequest{Actor: who, Action: action.ID, Target: operations.Target{PluginID: "tls.certificates", Subject: subject}, Args: raw, ExpectedRevision: expected,
		Idempotency: operations.Idempotency{Key: f.host.IDs.New(ids.Operation), Method: "POST", Route: "/fixture/tasks"}})
	if err != nil {
		t.Fatal(err)
	}
	approval, err := f.host.Operations.GetApproval(f.host.Context, f.host.Human, response.Operation.ApprovalID)
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.host.Operations.Decide(f.host.Context, operations.DecisionRequest{Actor: f.host.Human, ApprovalID: approval.ID, Decision: operations.DecisionApprove, ExpectedRevision: approval.Revision,
		Idempotency: operations.Idempotency{Key: f.host.IDs.New(ids.Operation), Method: "POST", Route: "/fixture/approval"}})
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-f.dispatch.started:
	case <-time.After(5 * time.Second):
		t.Fatal("原 executor 未启动")
	}
	ctx, release, err := f.authority.BeginCapability(f.host.Context, hostauth.Invocation{PluginID: "tls.certificates", InstanceID: "default", OperationID: response.Operation.ID}, operation)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(release)
	return ctx
}

type heldTask struct {
	calls atomic.Int32
	allow chan struct{}
	ready chan struct{}
}

func (w *heldTask) RunTask(ctx context.Context, _ TaskKind, id, _, _ string, progress certificates.Progress) (certificates.View, error) {
	w.calls.Add(1)
	if err := progress("waiting_dns", 10); err != nil {
		return certificates.View{}, err
	}
	if w.ready != nil {
		close(w.ready)
	}
	select {
	case <-ctx.Done():
		return certificates.View{}, ctx.Err()
	case <-w.allow:
		return certificates.View{ID: id}, nil
	}
}

func (f *taskFixture) repository(t *testing.T) store.Repository {
	t.Helper()
	repository, err := store.NewEncrypted(store.EncryptedOptions{DB: f.host.DB, Secrets: f.host.Secrets, Namespace: "tasks"})
	if err != nil {
		t.Fatal(err)
	}
	return repository
}

func (f *taskFixture) pool(t *testing.T, work TaskExecutor, limit int, repositories ...store.Repository) *Tasks {
	t.Helper()
	var backend store.Repository
	if len(repositories) > 0 {
		backend = repositories[0]
	} else {
		backend = f.repository(t)
	}
	pool, err := NewTasks(TaskOptions{Authority: f.authority, Repository: backend, Executor: work, Clock: f.clock, MaxJobs: limit, MonitorInterval: 100 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		if err := pool.Close(ctx); err != nil && fault.Code(err) != "TASK_PERSISTENCE_FAILED" {
			t.Error(err)
		}
	})
	return pool
}

func taskTestArgs(id, attempt string) hostauth.TestCertificateArgs {
	return hostauth.TestCertificateArgs{CertificateID: id, AttemptID: attempt,
		Spec: certificates.Spec{SANs: []string{"a.example.test"}, Purpose: tlsmgr.TestServerTLS}}
}

func (f *taskFixture) testCall(t *testing.T, id, attempt string) (context.Context, hostauth.TestCertificateArgs) {
	t.Helper()
	args := taskTestArgs(id, attempt)
	return f.start(t, "certificates.test", "plugins/tls.certificates/resources/certificates/"+id, "absent", args), args
}

func drainTasks(t *testing.T, pool *Tasks, expectedCode string) {
	t.Helper()
	ctx, stop := context.WithTimeout(context.Background(), 5*time.Second)
	defer stop()
	err := pool.Wait(ctx)
	if expectedCode == "" && err != nil {
		t.Fatal(err)
	}
	if expectedCode != "" && fault.Code(err) != expectedCode {
		t.Fatalf("任务收尾未返回固定错误 %s", expectedCode)
	}
}

func awaitTaskSignal(t *testing.T, signal <-chan struct{}) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(5 * time.Second):
		t.Fatal("任务回归同步超时")
	}
}

func TestTasksUseOriginalExecutorAndDeduplicateBeforeStartingWorker(t *testing.T) {
	f := newTaskFixture(t)
	work := &heldTask{allow: make(chan struct{})}
	pool := f.pool(t, work, 1)
	args := taskTestArgs("cert-one", "attempt-one")
	ctx := f.start(t, "certificates.test", "plugins/tls.certificates/resources/certificates/cert-one", "absent", args)
	one, err := pool.Submit(ctx, TestTask, args.CertificateID, args.AttemptID, "absent")
	if err != nil {
		t.Fatal(err)
	}
	two, err := pool.Submit(ctx, TestTask, args.CertificateID, args.AttemptID, "absent")
	if err != nil || one.Id != two.Id {
		t.Fatal("相同原意图产生了不同任务")
	}
	if _, err := pool.Submit(context.Background(), TestTask, args.CertificateID, args.AttemptID, "absent"); err == nil {
		t.Fatal("Background 取得任务权限")
	}
	if _, err := pool.Submit(ctx, TestTask, args.CertificateID, "other-attempt", "absent"); err == nil {
		t.Fatal("替代 attempt 进入执行器")
	}
	close(work.allow)
	wait, stop := context.WithTimeout(context.Background(), 5*time.Second)
	defer stop()
	if err := pool.Wait(wait); err != nil {
		t.Fatal(err)
	}
	if work.calls.Load() != 1 {
		t.Fatal("相同原意图实际执行了多个 worker")
	}
	record, _, found, err := pool.loadTask(f.host.Context, one.Id)
	if err != nil || !found || record.State != "succeeded" || record.Percent != 100 {
		t.Fatalf("实际最终收据缺失：%v", err)
	}
}

func TestTasksBoundCapacityRevokeDuringNetworkAndCloseWorkers(t *testing.T) {
	f := newTaskFixture(t)
	work := &heldTask{allow: make(chan struct{})}
	pool := f.pool(t, work, 1)
	args := taskTestArgs("cert-one", "attempt-one")
	ctx := f.start(t, "certificates.test", "plugins/tls.certificates/resources/certificates/cert-one", "absent", args)
	one, err := pool.Submit(ctx, TestTask, args.CertificateID, args.AttemptID, "absent")
	if err != nil {
		t.Fatal(err)
	}
	other := args
	other.CertificateID = "cert-two"
	other.AttemptID = "attempt-two"
	second := f.start(t, "certificates.test", "plugins/tls.certificates/resources/certificates/cert-two", "absent", other)
	if _, err := pool.Submit(second, TestTask, other.CertificateID, other.AttemptID, "absent"); fault.Code(err) != "RESOURCE_EXHAUSTED" {
		t.Fatal("容量上限失效")
	}
	if err := f.host.DB.Update(f.host.Context, func(tx *storage.Tx) error {
		_, err := tx.ExecContext(f.host.Context, "UPDATE users SET disabled=1 WHERE user_id=?", f.host.Human.ID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	wait, stop := context.WithTimeout(context.Background(), 5*time.Second)
	defer stop()
	if err := pool.Wait(wait); err != nil {
		t.Fatal("网络等待期间撤权未取消任务")
	}
	record, _, found, err := pool.loadTask(f.host.Context, one.Id)
	if err != nil || !found || record.State != "cancelled" {
		t.Fatal("撤权结果未持久保存")
	}
	if err := pool.Close(wait); err != nil {
		t.Fatal(err)
	}
}
