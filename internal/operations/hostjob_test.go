// SPDX-License-Identifier: AGPL-3.0-only

package operations

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"
)

// hostJobAction is a mode=job host action: it owns its transactions and talks to
// the system, so it cannot run inside the executor's write transaction.
const hostJobAction = "test.job"

// errHostJob is the executor failure of TestHostJobFailureIsRecorded.
var errHostJob = errors.New("host job: the removal failed")

func (e *testEnv) registerHostJobAction() {
	e.catalog.actions[hostJobAction] = Action{
		ID: hostJobAction, Summary: "Host job", Effect: EffectWrite, Risk: RiskLow, Mode: ModeJob,
		Idempotent: true, Permission: "test:job", Source: HostSource, TimeoutMS: 5000,
	}
}

// TestHostJobRunsOnWorker (GAPS gap 7): the call answers 202, the executor runs
// on a job worker with no transaction, and the operation finishes SUCCEEDED with
// the executor's result.
func TestHostJobRunsOnWorker(t *testing.T) {
	e := newTestEnv(t)
	e.registerHostJobAction()
	ran := make(chan HostRequest, 1)
	e.svc.RegisterHostJob(hostJobAction, func(_ context.Context, req HostRequest) (json.RawMessage, error) {
		ran <- req
		return json.RawMessage(`{"done":true}`), nil
	})
	if err := e.svc.Start(e.ctx); err != nil {
		t.Fatal(err)
	}
	resp, err := e.run(humanActor(), hostJobAction, Target{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status != 202 || resp.OperationID == "" {
		t.Fatalf("response = %d %q, want 202 with an operation id", resp.Status, resp.OperationID)
	}
	select {
	case req := <-ran:
		if req.OperationID != resp.OperationID {
			t.Fatalf("executor saw operation %q, want %q", req.OperationID, resp.OperationID)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the host job never ran")
	}
	e.waitFor("host job finished", func() bool { return e.operation(resp.OperationID).Status == Succeeded })
	if op := e.operation(resp.OperationID); string(op.Result) != `{"done":true}` {
		t.Fatalf("result = %s", op.Result)
	}
}

// TestHostJobWithoutExecutor: a queued host job nobody registered fails with
// UNAVAILABLE instead of hanging.
func TestHostJobWithoutExecutor(t *testing.T) {
	e := newTestEnv(t)
	e.registerHostJobAction()
	if err := e.svc.Start(e.ctx); err != nil {
		t.Fatal(err)
	}
	resp, err := e.run(humanActor(), hostJobAction, Target{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	e.waitFor("host job failed", func() bool { return e.operation(resp.OperationID).Status == Failed })
}

// TestHostJobFailureIsRecorded: an executor error becomes the operation's error.
func TestHostJobFailureIsRecorded(t *testing.T) {
	e := newTestEnv(t)
	e.registerHostJobAction()
	e.svc.RegisterHostJob(hostJobAction, func(context.Context, HostRequest) (json.RawMessage, error) {
		return nil, errHostJob
	})
	if err := e.svc.Start(e.ctx); err != nil {
		t.Fatal(err)
	}
	resp, err := e.run(humanActor(), hostJobAction, Target{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	e.waitFor("host job failed", func() bool { return e.operation(resp.OperationID).Status == Failed })
	if op := e.operation(resp.OperationID); op.Error == nil {
		t.Fatal("the failure carried no error")
	}
}
