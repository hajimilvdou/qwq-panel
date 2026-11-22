// SPDX-License-Identifier: AGPL-3.0-only

package operations

import (
	"context"
	"encoding/json"
	"sync/atomic"
	"testing"
	"time"

	"github.com/qwq-panel/qwq/internal/platform/problem"
	"github.com/qwq-panel/qwq/internal/storage"
)

func TestJobProgressAndResult(t *testing.T) {
	e := newTestEnv(t)
	e.dispatcher.jobFn = func(_ context.Context, _ PluginRunJobRequest, progress func(JobProgress) error) error {
		if err := progress(JobProgress{
			Percent: intPtr(10), Step: "prepare", StepIndex: 1, StepCount: 2, Message: "preparing",
			Changes: []ResourceChange{{Subject: "alerts/cpu", ChangedPointers: []string{"/threshold"}}},
		}); err != nil {
			return err
		}
		e.clock.Advance(time.Second) // let the throttled update through
		if err := progress(JobProgress{
			Percent: intPtr(90), Step: "finish", StepIndex: 2, StepCount: 2, Message: "finishing",
		}); err != nil {
			return err
		}
		return progress(JobProgress{Completed: true, Percent: intPtr(100), Result: json.RawMessage(`{"cleaned":3}`)})
	}
	if err := e.svc.Start(e.ctx); err != nil {
		t.Fatal(err)
	}
	defer e.svc.Stop()

	resp, err := e.run(humanActor(), actionJob, nodeTarget(), nil)
	if err != nil {
		t.Fatalf("submit job: %v", err)
	}
	if resp.Status != 202 || resp.Operation.Status != Pending {
		t.Fatalf("job submit = %d %s", resp.Status, resp.Operation.Status)
	}
	id := resp.Operation.ID
	e.waitFor("job to finish", func() bool {
		return e.operation(id).Status == Succeeded
	})
	op := e.operation(id)
	if op.Progress == nil || op.Progress.Percent == nil || *op.Progress.Percent != 100 {
		t.Fatalf("final progress = %+v", op.Progress)
	}
	if string(op.Result) != `{"cleaned":3}` {
		t.Fatalf("result = %s", op.Result)
	}
	// Plugin-owned changes became events with a namespaced subject.
	subject := "nodes/local/plugins/com.example.demo/instances/default/resources/alerts/cpu"
	changes := e.events("resource.changed", subject)
	if len(changes) != 1 {
		t.Fatalf("plugin resource events = %d, want 1", len(changes))
	}
	var payload resourceChanged
	if err := json.Unmarshal(changes[0].Payload, &payload); err != nil {
		t.Fatal(err)
	}
	if payload.OperationID != id || len(payload.ChangedPointers) != 1 || payload.ChangedPointers[0] != "/threshold" {
		t.Fatalf("change payload = %+v", payload)
	}
	// The attempt row records the successful execution.
	var status string
	if err := e.db.Reader().QueryRowContext(e.ctx,
		`SELECT status FROM operation_attempts WHERE operation_id = ? AND attempt = 1`, id).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != "succeeded" {
		t.Fatalf("attempt status = %q", status)
	}
}

func TestJobCancel(t *testing.T) {
	e := newTestEnv(t)
	e.dispatcher.jobFn = func(ctx context.Context, _ PluginRunJobRequest, progress func(JobProgress) error) error {
		if err := progress(JobProgress{Percent: intPtr(5)}); err != nil {
			return err
		}
		<-ctx.Done()
		return ctx.Err()
	}
	if err := e.svc.Start(e.ctx); err != nil {
		t.Fatal(err)
	}
	defer e.svc.Stop()

	resp, err := e.run(humanActor(), actionJob, nodeTarget(), nil)
	if err != nil {
		t.Fatal(err)
	}
	id := resp.Operation.ID
	e.waitFor("job running", func() bool { return e.operation(id).Status == Running })

	canceled, err := e.svc.Cancel(e.ctx, CancelRequest{
		Actor: humanActor(), OperationID: id, Reason: "stop it",
		Idempotency: Idempotency{Key: e.newKey(), Route: "/api/v1/operations/" + id + "/cancel"},
	})
	if err != nil {
		t.Fatalf("cancel: %v", err)
	}
	if canceled.Status != 202 || !canceled.Operation.CancelRequested {
		t.Fatalf("cancel = %d %+v", canceled.Status, canceled.Operation)
	}
	e.waitFor("plugin cancel", func() bool { return e.dispatcher.cancelCount() == 1 })
	e.waitFor("job canceled", func() bool {
		e.clock.Advance(3 * time.Second) // fire the cancellation grace timer
		return e.operation(id).Status == Canceled
	})
	if e.operation(id).Error == nil {
		t.Fatal("a canceled operation records why it stopped")
	}
}

func TestJobRetriesOnlyIdempotentOperations(t *testing.T) {
	t.Run("idempotent retries up to the limit", func(t *testing.T) {
		e := newTestEnv(t)
		e.dispatcher.jobFn = func(context.Context, PluginRunJobRequest, func(JobProgress) error) error {
			return problem.New(problem.Unavailable, "the node went away")
		}
		if err := e.svc.Start(e.ctx); err != nil {
			t.Fatal(err)
		}
		defer e.svc.Stop()
		resp, err := e.run(humanActor(), actionJob, nodeTarget(), nil)
		if err != nil {
			t.Fatal(err)
		}
		id := resp.Operation.ID
		e.waitFor("job to fail", func() bool { return e.operation(id).Status == Failed })
		op := e.operation(id)
		if op.Attempt != e.svc.cfg.MaxAttempts {
			t.Fatalf("attempt = %d, want %d", op.Attempt, e.svc.cfg.MaxAttempts)
		}
		var n int
		if err := e.db.Reader().QueryRowContext(e.ctx,
			`SELECT COUNT(*) FROM operation_attempts WHERE operation_id = ?`, id).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n != e.svc.cfg.MaxAttempts {
			t.Fatalf("attempt rows = %d, want %d", n, e.svc.cfg.MaxAttempts)
		}
	})
	t.Run("non-idempotent fails once", func(t *testing.T) {
		e := newTestEnv(t)
		e.dispatcher.jobFn = func(context.Context, PluginRunJobRequest, func(JobProgress) error) error {
			return problem.New(problem.Unavailable, "the node went away")
		}
		if err := e.svc.Start(e.ctx); err != nil {
			t.Fatal(err)
		}
		defer e.svc.Stop()
		resp, err := e.run(humanActor(), actionJobOnce, nodeTarget(), nil)
		if err != nil {
			t.Fatal(err)
		}
		id := resp.Operation.ID
		e.waitFor("job to fail", func() bool { return e.operation(id).Status == Failed })
		if op := e.operation(id); op.Attempt != 1 {
			t.Fatalf("attempt = %d, want 1", op.Attempt)
		}
	})
}

// TestRecover is the restart-recovery test: RUNNING operations are failed or
// retried, APPROVED and PENDING jobs are queued again.
func TestRecover(t *testing.T) {
	e := newTestEnv(t)
	ctx := context.Background()
	running, err := e.run(humanActor(), actionJob, nodeTarget(), nil)
	if err != nil {
		t.Fatal(err)
	}
	runningOnce, err := e.run(humanActor(), actionJobOnce, nodeTarget(), nil)
	if err != nil {
		t.Fatal(err)
	}
	pending, err := e.run(humanActor(), actionJob, nodeTarget(), nil)
	if err != nil {
		t.Fatal(err)
	}
	approved, err := e.run(humanActor(), actionPluginH, nodeTarget(), nil)
	if err != nil {
		t.Fatal(err)
	}
	setStatus := func(id, status string) {
		t.Helper()
		if err := e.db.Update(ctx, func(tx *storage.Tx) error {
			_, err := tx.ExecContext(ctx, `UPDATE operations SET status = ? WHERE operation_id = ?`, status, id)
			return err
		}); err != nil {
			t.Fatalf("set status: %v", err)
		}
	}
	setStatus(running.Operation.ID, string(Running))
	setStatus(runningOnce.Operation.ID, string(Running))
	setStatus(approved.Operation.ID, string(Approved))

	if err := e.svc.Start(ctx); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer e.svc.Stop()
	e.waitFor("recovered jobs", func() bool {
		ok := e.operation(running.Operation.ID).Status == Succeeded &&
			e.operation(pending.Operation.ID).Status == Succeeded &&
			e.operation(approved.Operation.ID).Status == Succeeded &&
			e.operation(runningOnce.Operation.ID).Status == Failed
		if !ok {
			for name, id := range map[string]string{
				"running": running.Operation.ID, "pending": pending.Operation.ID,
				"approved": approved.Operation.ID, "once": runningOnce.Operation.ID,
			} {
				op := e.operation(id)
				t.Logf("%s: %s attempt=%d error=%+v", name, op.Status, op.Attempt, op.Error)
			}
		}
		return ok
	})
	if op := e.operation(running.Operation.ID); op.Attempt != 2 {
		t.Fatalf("recovered idempotent attempt = %d, want 2", op.Attempt)
	}
	failed := e.operation(runningOnce.Operation.ID)
	if failed.Error == nil || failed.Error.Code != "UNAVAILABLE" {
		t.Fatalf("failed operation error = %+v", failed.Error)
	}
	if failed.Attempt != 1 {
		t.Fatalf("non-idempotent attempt = %d, want 1", failed.Attempt)
	}
}

// TestShutdownLeavesRunningJobForRecovery proves that a restart does not turn an
// interrupted job into a failure: the operation stays RUNNING and the next
// start retries the attempt.
func TestShutdownLeavesRunningJobForRecovery(t *testing.T) {
	e := newTestEnv(t)
	started := make(chan struct{}, 1)
	e.dispatcher.jobFn = func(ctx context.Context, _ PluginRunJobRequest, _ func(JobProgress) error) error {
		started <- struct{}{}
		<-ctx.Done()
		return ctx.Err()
	}
	if err := e.svc.Start(e.ctx); err != nil {
		t.Fatal(err)
	}
	resp, err := e.run(humanActor(), actionJob, nodeTarget(), nil)
	if err != nil {
		t.Fatal(err)
	}
	id := resp.Operation.ID
	<-started
	e.waitFor("running", func() bool { return e.operation(id).Status == Running })
	e.svc.Stop()
	if op := e.operation(id); op.Status != Running {
		t.Fatalf("after shutdown the operation is %s, want RUNNING", op.Status)
	}

	// A fresh service on the same database picks the attempt up again.
	e.dispatcher.mu.Lock()
	e.dispatcher.jobFn = nil
	e.dispatcher.mu.Unlock()
	svc2, err := New(Options{
		DB: e.db, Clock: e.clock, IDs: e.ids, Catalog: e.catalog, Dispatcher: e.dispatcher,
		Authorizer: e.authorizer, Policy: e.policy, Revisions: testRevisions{}, Notifier: e.notifier,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer svc2.Stop()
	if err := svc2.Start(e.ctx); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		op, err := loadOperation(e.ctx, e.db.Reader(), id)
		if err == nil && op.Status == Succeeded {
			if op.Attempt != 2 {
				t.Fatalf("attempt after recovery = %d, want 2", op.Attempt)
			}
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatal("the recovered job never finished")
}

// setStatus forces an operation's status, simulating a concurrent writer.
func (e *testEnv) setStatus(id string, status Status) {
	e.t.Helper()
	if err := e.db.Update(e.ctx, func(tx *storage.Tx) error {
		_, err := tx.ExecContext(e.ctx, `UPDATE operations SET status = ? WHERE operation_id = ?`, string(status), id)
		return err
	}); err != nil {
		e.t.Fatalf("set status: %v", err)
	}
}

// countJobRuns wires a jobFn that counts RunJob calls.
func (e *testEnv) countJobRuns() *atomic.Int32 {
	var n atomic.Int32
	e.dispatcher.jobFn = func(_ context.Context, _ PluginRunJobRequest, progress func(JobProgress) error) error {
		n.Add(1)
		return progress(JobProgress{Completed: true})
	}
	return &n
}

// TestRunJobSkipsCanceledBetweenLoadAndStart: a job canceled while queued is
// not streamed (OPS-03).
func TestRunJobSkipsCanceledBetweenLoadAndStart(t *testing.T) {
	e := newTestEnv(t)
	runs := e.countJobRuns()
	resp, err := e.run(humanActor(), actionJob, nodeTarget(), nil)
	if err != nil {
		t.Fatal(err)
	}
	id := resp.Operation.ID
	e.setStatus(id, Canceled)
	e.svc.runJob(e.ctx, id)
	if n := runs.Load(); n != 0 {
		t.Fatalf("RunJob calls = %d, want 0", n)
	}
}

// TestRunJobSkipsAlreadyRunning: a duplicate queue entry of a running job does
// not start a second stream (OPS-03).
func TestRunJobSkipsAlreadyRunning(t *testing.T) {
	e := newTestEnv(t)
	runs := e.countJobRuns()
	resp, err := e.run(humanActor(), actionJob, nodeTarget(), nil)
	if err != nil {
		t.Fatal(err)
	}
	id := resp.Operation.ID
	e.setStatus(id, Running)
	e.svc.runJob(e.ctx, id)
	if n := runs.Load(); n != 0 {
		t.Fatalf("RunJob calls = %d, want 0", n)
	}
}

// TestDeferredDispatchResumesAfterReady proves that a deferred start repairs the
// state without running anything: an operation recovered before the plugin
// runtime is ready stays queued and only runs after StartDispatch.
func TestDeferredDispatchResumesAfterReady(t *testing.T) {
	e := newTestEnv(t)
	started := make(chan struct{}, 1)
	e.dispatcher.jobFn = func(ctx context.Context, _ PluginRunJobRequest, _ func(JobProgress) error) error {
		started <- struct{}{}
		<-ctx.Done()
		return ctx.Err()
	}
	if err := e.svc.Start(e.ctx); err != nil {
		t.Fatal(err)
	}
	resp, err := e.run(humanActor(), actionJob, nodeTarget(), nil)
	if err != nil {
		t.Fatal(err)
	}
	id := resp.Operation.ID
	<-started
	e.waitFor("running", func() bool { return e.operation(id).Status == Running })
	e.svc.Stop()

	// Until the host is ready the dispatcher reports UNAVAILABLE, like a
	// plugin runtime that was not started yet.
	var ready atomic.Bool
	e.dispatcher.mu.Lock()
	e.dispatcher.jobFn = func(_ context.Context, _ PluginRunJobRequest, progress func(JobProgress) error) error {
		if !ready.Load() {
			return problem.New(problem.Unavailable, "runtime is not started")
		}
		return progress(JobProgress{Completed: true})
	}
	e.dispatcher.mu.Unlock()
	svc2, err := New(Options{
		DB: e.db, Clock: e.clock, IDs: e.ids, Catalog: e.catalog, Dispatcher: e.dispatcher,
		Authorizer: e.authorizer, Policy: e.policy, Revisions: testRevisions{}, Notifier: e.notifier,
		DeferDispatch: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer svc2.Stop()
	if err := svc2.Start(e.ctx); err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)
	if op := e.operation(id); op.Status != Pending {
		t.Fatalf("before StartDispatch the operation is %s, want PENDING", op.Status)
	}

	ready.Store(true)
	svc2.StartDispatch(e.ctx)
	e.waitFor("recovered job to succeed", func() bool { return e.operation(id).Status == Succeeded })
}
