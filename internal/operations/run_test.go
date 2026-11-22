// SPDX-License-Identifier: AGPL-3.0-only

package operations

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/qwq-panel/qwq/internal/actor"
	"github.com/qwq-panel/qwq/internal/platform/problem"
	"github.com/qwq-panel/qwq/internal/storage"
)

type resourceChanged struct {
	Subject         string      `json:"subject"`
	Revision        string      `json:"revision"`
	Kind            string      `json:"kind"`
	Actor           actor.Actor `json:"actor"`
	OperationID     string      `json:"operation_id"`
	ChangedPointers []string    `json:"changed_pointers"`
}

type operationUpdated struct {
	OperationID    string `json:"operation_id"`
	Action         string `json:"action"`
	Status         string `json:"status"`
	PreviousStatus string `json:"previous_status"`
	Attempt        int    `json:"attempt"`
	Revision       string `json:"revision"`
}

// TestWriteCreatesOperationAndEvents is the contract test of ADR-0004 D1/D3:
// every modifying call creates an operation and emits resource.changed for the
// resource and operation.updated for the operation.
func TestWriteCreatesOperationAndEvents(t *testing.T) {
	e := newTestEnv(t)
	resp, err := e.run(humanActor(), actionWrite, Target{Subject: resourceSubject}, map[string]any{"value": "one"})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if resp.Status != 200 || resp.Outcome == nil {
		t.Fatalf("a synchronous write answers 200 with an outcome, got %d", resp.Status)
	}
	op := resp.Operation
	if op == nil || op.Status != Succeeded {
		t.Fatalf("operation = %+v", op)
	}
	if op.Actor.Kind != actor.Human || op.EffectiveRisk != RiskLow {
		t.Fatalf("operation actor/risk = %+v / %q", op.Actor, op.EffectiveRisk)
	}
	if len(op.Result) == 0 {
		t.Fatal("operation has no result")
	}

	// The resource change and the operation change are both in the journal.
	resourceEvents := e.events("resource.changed", resourceSubject)
	if len(resourceEvents) != 1 {
		t.Fatalf("resource.changed for the resource = %d, want 1", len(resourceEvents))
	}
	var changed resourceChanged
	if err := json.Unmarshal(resourceEvents[0].Payload, &changed); err != nil {
		t.Fatal(err)
	}
	if changed.OperationID != op.ID || changed.Actor.Kind != actor.Human || changed.Kind != "create" {
		t.Fatalf("resource.changed payload = %+v", changed)
	}
	if resourceEvents[0].OperationID != op.ID {
		t.Fatalf("journal operation_id = %q, want %q", resourceEvents[0].OperationID, op.ID)
	}
	if changed.Revision != strconv.FormatInt(resourceEvents[0].Seq, 10) {
		t.Fatalf("revision %q is not the event sequence %d", changed.Revision, resourceEvents[0].Seq)
	}

	opEvents := e.events("resource.changed", "operations/"+op.ID)
	if len(opEvents) != 3 { // create, running, succeeded
		t.Fatalf("resource.changed for the operation = %d, want 3", len(opEvents))
	}
	last := opEvents[len(opEvents)-1]
	var lastPayload resourceChanged
	if err := json.Unmarshal(last.Payload, &lastPayload); err != nil {
		t.Fatal(err)
	}
	if op.Revision != lastPayload.Revision || op.Revision != strconv.FormatInt(last.Seq, 10) {
		t.Fatalf("operation revision %q, payload %q, seq %d", op.Revision, lastPayload.Revision, last.Seq)
	}

	updated := e.events("operation.updated", "operations/"+op.ID)
	var statuses []string
	for _, ev := range updated {
		var p operationUpdated
		if err := json.Unmarshal(ev.Payload, &p); err != nil {
			t.Fatal(err)
		}
		if p.OperationID != op.ID || p.Action != actionWrite || p.Attempt != 1 || p.Revision == "" {
			t.Fatalf("operation.updated payload = %+v", p)
		}
		statuses = append(statuses, p.Status)
	}
	want := []string{"PENDING", "RUNNING", "SUCCEEDED"}
	if len(statuses) != len(want) {
		t.Fatalf("operation.updated statuses = %v, want %v", statuses, want)
	}
	for i := range want {
		if statuses[i] != want[i] {
			t.Fatalf("operation.updated statuses = %v, want %v", statuses, want)
		}
	}

	// Audit records the operation's creation and its completion.
	if n := e.countAudit(actionWrite); n < 2 {
		t.Fatalf("audit rows for %s = %d, want >= 2", actionWrite, n)
	}
	if e.countOperations() != 1 {
		t.Fatalf("operations = %d, want 1", e.countOperations())
	}
}

// TestConcurrentExpectedRevision is ADR-0004 acceptance 1: two requests with the
// same expected_revision cannot both win.
func TestConcurrentExpectedRevision(t *testing.T) {
	e := newTestEnv(t)
	if _, err := e.run(humanActor(), actionWrite, Target{Subject: resourceSubject}, map[string]any{"value": "one"}); err != nil {
		t.Fatal(err)
	}
	rev := e.resourceRevision(resourceSubject)

	type result struct {
		resp *Response
		err  error
	}
	results := make([]result, 2)
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			results[i].resp, results[i].err = e.runWithRevision(humanActor(), actionWrite, resourceSubject, rev, "two")
		}(i)
	}
	close(start)
	wg.Wait()

	successes, conflicts := 0, 0
	for _, r := range results {
		switch {
		case r.err == nil:
			successes++
		case problem.HasCode(r.err, problem.RevisionConflict):
			conflicts++
			var pe *problem.Error
			if !errors.As(r.err, &pe) {
				t.Fatalf("not a problem: %v", r.err)
			}
			if pe.CurrentRevision == "" || pe.CurrentRevision == rev {
				t.Fatalf("conflict must carry the new current revision, got %q (old %q)", pe.CurrentRevision, rev)
			}
		default:
			t.Fatalf("unexpected error: %v", r.err)
		}
	}
	if successes != 1 || conflicts != 1 {
		t.Fatalf("successes=%d conflicts=%d", successes, conflicts)
	}
}

// TestPlanPreconditionFailsAfterChange is ADR-0004 acceptance 4.
func TestPlanPreconditionFailsAfterChange(t *testing.T) {
	e := newTestEnv(t)
	if _, err := e.run(humanActor(), actionWrite, Target{Subject: resourceSubject}, map[string]any{"value": "one"}); err != nil {
		t.Fatal(err)
	}
	rev := e.resourceRevision(resourceSubject)
	plan, err := e.svc.CreatePlan(e.ctx, PlanRequest{
		Actor: humanActor(), Action: actionWrite, Target: Target{Subject: resourceSubject},
		Args:             mustJSON(t, map[string]any{"value": "planned"}),
		ExpectedRevision: rev,
	})
	if err != nil {
		t.Fatalf("create plan: %v", err)
	}
	if len(plan.Preconditions) != 1 || plan.Preconditions[0].Revision != rev || !plan.Executable {
		t.Fatalf("plan = %+v", plan)
	}
	// Someone else modifies the resource between plan and execute.
	if _, err := e.run(humanActor(), actionWrite, Target{Subject: resourceSubject}, map[string]any{"value": "changed"}); err != nil {
		t.Fatal(err)
	}
	_, err = e.svc.ExecutePlan(e.ctx, ExecutePlanRequest{
		Actor: humanActor(), PlanID: plan.ID,
		Idempotency: Idempotency{Key: e.newKey(), Route: "/api/v1/plans/" + plan.ID + "/execute"},
	})
	if !problem.HasCode(err, problem.PreconditionFailed) {
		t.Fatalf("execute = %v, want PRECONDITION_FAILED", err)
	}
	var pe *problem.Error
	if !errors.As(err, &pe) {
		t.Fatalf("not a problem: %v", err)
	}
	if len(pe.FailedPreconditions) != 1 {
		t.Fatalf("failed preconditions = %+v", pe.FailedPreconditions)
	}
	fp := pe.FailedPreconditions[0]
	if fp.Subject != resourceSubject || fp.ExpectedRevision != rev || fp.CurrentRevision == "" || fp.CurrentRevision == rev {
		t.Fatalf("failed precondition = %+v", fp)
	}
	stored, err := loadPlan(e.ctx, e.db.Reader(), plan.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.OperationID != "" {
		t.Fatal("a plan whose preconditions failed must stay executable")
	}
}

// TestChildOperationRiskEscalation covers ADR-0007 #5: a child inherits the
// parent's actor and needs its own approval when it is riskier.
func TestChildOperationRiskEscalation(t *testing.T) {
	e := newTestEnv(t)
	parent, err := e.run(humanActor(), actionWrite, Target{Subject: resourceSubject}, map[string]any{"value": "one"})
	if err != nil {
		t.Fatal(err)
	}
	if parent.Operation.Status != Succeeded {
		t.Fatalf("parent = %+v", parent.Operation)
	}
	child, err := e.runReq(actor.SystemActor("plugin"), RunRequest{
		Action: actionHigh, Target: Target{Subject: resourceSubject},
		Args:              mustJSON(t, map[string]any{"value": "two"}),
		ParentOperationID: parent.Operation.ID,
		Idempotency:       Idempotency{Key: e.newKey(), Route: "/api/v1/test/" + actionHigh},
	})
	if err != nil {
		t.Fatalf("child: %v", err)
	}
	if child.Operation.Status != AwaitingApproval {
		t.Fatalf("a riskier child must wait for approval, got %s", child.Operation.Status)
	}
	if child.Operation.Actor.Kind != actor.Human || child.Operation.Actor.ID != "usr_human" {
		t.Fatalf("child actor = %+v, want the parent's", child.Operation.Actor)
	}
	if child.Operation.ParentOperationID != parent.Operation.ID {
		t.Fatalf("parent link = %q", child.Operation.ParentOperationID)
	}

	// A child that is not riskier than its parent does not need approval.
	same, err := e.runReq(actor.SystemActor("plugin"), RunRequest{
		Action: actionWrite, Target: Target{Subject: resourceSubject},
		Args:              mustJSON(t, map[string]any{"value": "three"}),
		ParentOperationID: parent.Operation.ID,
		Idempotency:       Idempotency{Key: e.newKey(), Route: "/api/v1/test/" + actionWrite},
	})
	if err != nil {
		t.Fatal(err)
	}
	if same.Operation.Status != Succeeded {
		t.Fatalf("a child with the parent's risk must run, got %s", same.Operation.Status)
	}
}

func TestReadActionCreatesNoOperation(t *testing.T) {
	e := newTestEnv(t)
	e.dispatcher.invokeFn = func(context.Context, PluginInvokeRequest) (PluginInvokeResponse, error) {
		return PluginInvokeResponse{Result: json.RawMessage(`{"rows":3}`)}, nil
	}
	resp, err := e.svc.Run(e.ctx, RunRequest{
		Actor: aiActor(), Action: actionRead,
		Target: Target{NodeID: "local", PluginID: pluginID, InstanceID: "default"},
		Args:   mustJSON(t, map[string]any{}),
	})
	if err != nil {
		t.Fatalf("read action: %v", err)
	}
	if resp.Status != 200 || resp.Outcome == nil || resp.Outcome.OperationID != "" {
		t.Fatalf("read action response = %+v", resp)
	}
	if string(resp.Outcome.Result) != `{"rows":3}` {
		t.Fatalf("result = %s", resp.Outcome.Result)
	}
	if e.countOperations() != 0 {
		t.Fatalf("a read action created %d operations", e.countOperations())
	}
	if e.dispatcher.invokeCount() != 1 {
		t.Fatalf("dispatcher invokes = %d", e.dispatcher.invokeCount())
	}
}

func TestMissingIdempotencyKey(t *testing.T) {
	e := newTestEnv(t)
	_, err := e.svc.Run(e.ctx, RunRequest{
		Actor: humanActor(), Action: actionWrite, Target: Target{Subject: resourceSubject},
		Args: mustJSON(t, map[string]any{"value": "one"}),
	})
	if !problem.HasCode(err, problem.ValidationFailed) {
		t.Fatalf("got %v, want VALIDATION_FAILED", err)
	}
	var pe *problem.Error
	if !errors.As(err, &pe) || len(pe.Violations) != 1 || pe.Violations[0].Pointer != "/Idempotency-Key" {
		t.Fatalf("violations = %+v", pe)
	}
}

func TestLowRiskRunsAndNotifies(t *testing.T) {
	e := newTestEnv(t)
	if _, err := e.run(humanActor(), actionWrite, Target{Subject: resourceSubject}, map[string]any{"value": "one"}); err != nil {
		t.Fatal(err)
	}
	if e.notifier.count() != 1 {
		t.Fatalf("notified %d times, want 1", e.notifier.count())
	}
}

func TestListAndGet(t *testing.T) {
	e := newTestEnv(t)
	var ids []string
	for i := 0; i < 2; i++ {
		resp, err := e.run(humanActor(), actionWrite, Target{Subject: resourceSubject}, map[string]any{"value": "v"})
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, resp.Operation.ID)
	}
	pending, err := e.run(humanActor(), actionHigh, Target{Subject: resourceSubject}, map[string]any{"value": "high"})
	if err != nil {
		t.Fatal(err)
	}
	if pending.Operation.Status != AwaitingApproval {
		t.Fatalf("high risk = %s", pending.Operation.Status)
	}

	page, err := e.svc.List(e.ctx, humanActor(), ListFilter{Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Items) != 3 || page.Delta || page.Revision == "" {
		t.Fatalf("page = %+v", page)
	}
	if page.Items[0].ID != pending.Operation.ID {
		t.Fatalf("operations are not newest first: %s vs %s", page.Items[0].ID, pending.Operation.ID)
	}

	filtered, err := e.svc.List(e.ctx, humanActor(), ListFilter{Statuses: []Status{AwaitingApproval}})
	if err != nil {
		t.Fatal(err)
	}
	if len(filtered.Items) != 1 || filtered.Items[0].ID != pending.Operation.ID {
		t.Fatalf("status filter = %+v", filtered.Items)
	}

	first, err := e.svc.List(e.ctx, humanActor(), ListFilter{Limit: 2})
	if err != nil {
		t.Fatal(err)
	}
	if len(first.Items) != 2 || first.NextCursor == "" {
		t.Fatalf("first page = %+v", first)
	}
	second, err := e.svc.List(e.ctx, humanActor(), ListFilter{Limit: 2, Cursor: first.NextCursor})
	if err != nil {
		t.Fatal(err)
	}
	if len(second.Items) != 1 || second.NextCursor != "" {
		t.Fatalf("second page = %+v", second)
	}
	if second.Items[0].ID == first.Items[0].ID || second.Items[0].ID == first.Items[1].ID {
		t.Fatal("cursor returned a duplicate")
	}

	// Delta reads only return operations changed after the watermark.
	delta, err := e.svc.List(e.ctx, humanActor(), ListFilter{SinceRevision: first.Revision})
	if err != nil {
		t.Fatal(err)
	}
	if !delta.Delta || len(delta.Items) != 0 {
		t.Fatalf("delta = %+v (watermark %s)", delta, first.Revision)
	}

	// A delegation only sees its own operations.
	agentPage, err := e.svc.List(e.ctx, aiActor(), ListFilter{Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(agentPage.Items) != 0 {
		t.Fatalf("delegation sees %d foreign operations", len(agentPage.Items))
	}
	if _, err := e.svc.Get(e.ctx, aiActor(), ids[0]); !problem.HasCode(err, problem.NotFound) {
		t.Fatalf("foreign get = %v, want NOT_FOUND", err)
	}
	if _, err := e.svc.Get(e.ctx, humanActor(), ids[0]); err != nil {
		t.Fatalf("owner get: %v", err)
	}
}

// ---------------------------------------------------------------------------
// OPS-01：operation 一旦持久化即与请求 ctx 解耦
// ---------------------------------------------------------------------------

// onlyOperationID returns the ID of the single operation in the database.
func (e *testEnv) onlyOperationID() string {
	e.t.Helper()
	var id string
	if err := e.db.Reader().QueryRowContext(e.ctx, `SELECT operation_id FROM operations`).Scan(&id); err != nil {
		e.t.Fatalf("read operation id: %v", err)
	}
	return id
}

// TestRunPluginClientCancelStillRecordsOutcome: the client goes away after the
// plugin finished; the outcome and the plugin's resource changes still land.
func TestRunPluginClientCancelStillRecordsOutcome(t *testing.T) {
	e := newTestEnv(t)
	ctx, cancel := context.WithCancel(e.ctx)
	defer cancel()
	e.dispatcher.invokeFn = func(context.Context, PluginInvokeRequest) (PluginInvokeResponse, error) {
		cancel()
		return PluginInvokeResponse{
			Result:  json.RawMessage(`{"ok":true}`),
			Changes: []ResourceChange{{Subject: "alerts/cpu", ChangedPointers: []string{"/threshold"}}},
		}, nil
	}
	_, _ = e.svc.Run(ctx, RunRequest{
		Actor: humanActor(), Action: actionPlugin, Target: nodeTarget(), Args: mustJSON(t, map[string]any{}),
		Idempotency: Idempotency{Key: e.newKey(), Method: "POST", Route: "/api/v1/test/plugin"},
	})
	op := e.operation(e.onlyOperationID())
	if op.Status != Succeeded {
		t.Fatalf("status = %s, want SUCCEEDED", op.Status)
	}
	subject := "nodes/local/plugins/com.example.demo/instances/default/resources/alerts/cpu"
	if n := len(e.events("resource.changed", subject)); n != 1 {
		t.Fatalf("plugin resource events = %d, want 1", n)
	}
}

// TestRunPluginClientCancelDuringInvokeEndsTerminal: a client that leaves while
// the plugin runs does not leave the operation RUNNING.
func TestRunPluginClientCancelDuringInvokeEndsTerminal(t *testing.T) {
	e := newTestEnv(t)
	e.setAction(actionPlugin, func(a *Action) { a.TimeoutMS = 50 })
	ctx, cancel := context.WithCancel(e.ctx)
	defer cancel()
	e.dispatcher.invokeFn = func(runCtx context.Context, _ PluginInvokeRequest) (PluginInvokeResponse, error) {
		cancel()
		<-runCtx.Done()
		return PluginInvokeResponse{}, runCtx.Err()
	}
	_, _ = e.svc.Run(ctx, RunRequest{
		Actor: humanActor(), Action: actionPlugin, Target: nodeTarget(), Args: mustJSON(t, map[string]any{}),
		Idempotency: Idempotency{Key: e.newKey(), Method: "POST", Route: "/api/v1/test/plugin"},
	})
	op := e.operation(e.onlyOperationID())
	if !isTerminal(op.Status) {
		t.Fatalf("status = %s, want a terminal status", op.Status)
	}
}

// TestRecoverFailsPendingInvoke: an invoke accepted but never started is failed
// on restart, never executed behind the caller's back.
func TestRecoverFailsPendingInvoke(t *testing.T) {
	e := newTestEnv(t)
	resp, err := e.run(humanActor(), actionPluginH, nodeTarget(), nil)
	if err != nil {
		t.Fatal(err)
	}
	id := resp.Operation.ID
	if err := e.db.Update(e.ctx, func(tx *storage.Tx) error {
		_, err := tx.ExecContext(e.ctx, `UPDATE operations SET status = ? WHERE operation_id = ?`, string(Pending), id)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.Recover(e.ctx); err != nil {
		t.Fatalf("recover: %v", err)
	}
	if op := e.operation(id); op.Status != Failed {
		t.Fatalf("status = %s, want FAILED", op.Status)
	}
	if n := e.dispatcher.invokeCount(); n != 0 {
		t.Fatalf("invokes = %d, want 0", n)
	}
}

// TestSweepReapsOrphanRunning: a RUNNING operation with no executor past its
// deadline is failed by the sweeper.
func TestSweepReapsOrphanRunning(t *testing.T) {
	e := newTestEnv(t)
	resp, err := e.run(humanActor(), actionPluginH, nodeTarget(), nil)
	if err != nil {
		t.Fatal(err)
	}
	id := resp.Operation.ID
	if err := e.db.Update(e.ctx, func(tx *storage.Tx) error {
		_, err := tx.ExecContext(e.ctx, `UPDATE operations SET status = ?, started_at = ? WHERE operation_id = ?`,
			string(Running), storage.FormatTime(e.clock.Now()), id)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.Sweep(e.ctx); err != nil {
		t.Fatal(err)
	}
	if op := e.operation(id); op.Status != Running {
		t.Fatalf("a fresh RUNNING operation was reaped: %s", op.Status)
	}
	e.clock.Advance(time.Minute)
	if _, err := e.svc.Sweep(e.ctx); err != nil {
		t.Fatal(err)
	}
	op := e.operation(id)
	if op.Status != Failed || op.Error == nil || op.Error.Code != problem.Timeout {
		t.Fatalf("orphan = %s %+v, want FAILED/TIMEOUT", op.Status, op.Error)
	}
}
