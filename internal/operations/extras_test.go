// SPDX-License-Identifier: AGPL-3.0-only

package operations

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/qwq-panel/qwq/internal/actor"
	"github.com/qwq-panel/qwq/internal/platform/problem"
)

// TestPolicyMaxRiskRejects covers the delegation policy's max_risk: an effective
// risk above it is refused with PERMISSION_DENIED carrying effective_risk
// (ADR-0004 D6).
func TestPolicyMaxRiskRejects(t *testing.T) {
	e := newTestEnv(t)
	e.policy.set(aiActor(), Limits{MaxRisk: RiskLow})
	_, err := e.run(aiActor(), actionHigh, Target{Subject: resourceSubject}, map[string]any{"value": "x"})
	if !problem.HasCode(err, problem.PermissionDenied) {
		t.Fatalf("got %v, want PERMISSION_DENIED", err)
	}
	var pe *problem.Error
	if !asProblemError(err, &pe) || pe.EffectiveRisk != RiskHigh {
		t.Fatalf("problem = %+v, want effective_risk high", pe)
	}
	// A low risk action still runs.
	if _, err := e.run(aiActor(), actionWrite, Target{Subject: resourceSubject}, map[string]any{"value": "x"}); err != nil {
		t.Fatalf("low risk with max_risk=low: %v", err)
	}
}

// TestApprovalRequiredWhenPolicyFails covers on_approval_required=fail.
func TestApprovalRequiredWhenPolicyFails(t *testing.T) {
	e := newTestEnv(t)
	e.policy.set(aiActor(), Limits{AutoApproveMaxRisk: RiskLow, OnApprovalRequired: ApprovalFail})
	_, err := e.run(aiActor(), actionHigh, Target{Subject: resourceSubject}, map[string]any{"value": "x"})
	if !problem.HasCode(err, problem.ApprovalRequired) {
		t.Fatalf("got %v, want APPROVAL_REQUIRED", err)
	}
	var pe *problem.Error
	if !asProblemError(err, &pe) || pe.EffectiveRisk != RiskHigh {
		t.Fatalf("problem = %+v", pe)
	}
	if e.countOperations() != 0 {
		t.Fatalf("a refused approval queued %d operations", e.countOperations())
	}
}

// TestPluginInvokeEmitsEvents is the contract test for a plugin invocation: the
// operation resource, the operation.updated stream and the plugin-reported
// resource changes all reach the journal.
func TestPluginInvokeEmitsEvents(t *testing.T) {
	e := newTestEnv(t)
	e.dispatcher.invokeFn = func(context.Context, PluginInvokeRequest) (PluginInvokeResponse, error) {
		return PluginInvokeResponse{
			Result:  json.RawMessage(`{"ok":true}`),
			Changes: []ResourceChange{{Subject: "alerts/cpu", ChangedPointers: []string{"/threshold"}}},
		}, nil
	}
	resp, err := e.run(humanActor(), actionPlugin, nodeTarget(), map[string]any{})
	if err != nil {
		t.Fatalf("invoke: %v", err)
	}
	op := resp.Operation
	if op.Status != Succeeded {
		t.Fatalf("operation = %s", op.Status)
	}
	subject := "nodes/local/plugins/com.example.demo/instances/default/resources/alerts/cpu"
	events := e.events("resource.changed", subject)
	if len(events) != 1 {
		t.Fatalf("plugin resource events = %d, want 1", len(events))
	}
	var payload resourceChanged
	if err := json.Unmarshal(events[0].Payload, &payload); err != nil {
		t.Fatal(err)
	}
	if payload.OperationID != op.ID || payload.Actor.Kind != actor.Human {
		t.Fatalf("payload = %+v", payload)
	}
	updated := e.events("operation.updated", "operations/"+op.ID)
	if len(updated) < 3 {
		t.Fatalf("operation.updated events = %d, want at least 3", len(updated))
	}
	if len(e.events("resource.changed", "operations/"+op.ID)) != 3 {
		t.Fatalf("the operation resource must change on create, run and finish")
	}
}

func TestListApprovalsAndGet(t *testing.T) {
	e := newTestEnv(t)
	agentResp, err := e.run(aiActor(), actionHigh, Target{Subject: resourceSubject}, map[string]any{"value": "x"})
	if err != nil {
		t.Fatal(err)
	}
	humanResp, err := e.run(humanActor(), actionHigh, Target{Subject: resourceSubject}, map[string]any{"value": "y"})
	if err != nil {
		t.Fatal(err)
	}
	agentPage, err := e.svc.ListApprovals(e.ctx, aiActor(), ApprovalFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(agentPage.Items) != 1 || agentPage.Items[0].ID != agentResp.Operation.ApprovalID {
		t.Fatalf("delegation approvals = %+v", agentPage.Items)
	}
	humanPage, err := e.svc.ListApprovals(e.ctx, humanActor(), ApprovalFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(humanPage.Items) != 2 {
		t.Fatalf("human approvals = %d, want 2", len(humanPage.Items))
	}
	if _, err := e.svc.GetApproval(e.ctx, aiActor(), humanResp.Operation.ApprovalID); !problem.HasCode(err, problem.NotFound) {
		t.Fatalf("foreign approval = %v, want NOT_FOUND", err)
	}
	if approval, err := e.svc.GetApproval(e.ctx, aiActor(), agentResp.Operation.ApprovalID); err != nil || approval.ID == "" {
		t.Fatalf("own approval: %+v, %v", approval, err)
	}
	if _, err := e.decide(humanMFA(), agentResp.Operation.ApprovalID, DecisionApprove); err != nil {
		t.Fatalf("approve: %v", err)
	}
	approvedPage, err := e.svc.ListApprovals(e.ctx, humanActor(), ApprovalFilter{Status: ApprovalApproved})
	if err != nil {
		t.Fatal(err)
	}
	if len(approvedPage.Items) != 1 {
		t.Fatalf("approved approvals = %d, want 1", len(approvedPage.Items))
	}
	pendingPage, err := e.svc.ListApprovals(e.ctx, humanActor(), ApprovalFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(pendingPage.Items) != 1 {
		t.Fatalf("pending approvals = %d, want 1", len(pendingPage.Items))
	}
}

func TestWaitAndSubmit(t *testing.T) {
	e := newTestEnv(t)
	resp, err := e.run(humanActor(), actionWrite, Target{Subject: resourceSubject}, map[string]any{"value": "x"})
	if err != nil {
		t.Fatal(err)
	}
	op, err := e.svc.Wait(e.ctx, humanActor(), resp.Operation.ID, time.Second)
	if err != nil {
		t.Fatalf("wait: %v", err)
	}
	if op.Status != Succeeded {
		t.Fatalf("wait returned %s", op.Status)
	}
	if _, err := e.svc.Wait(e.ctx, aiActor(), resp.Operation.ID, time.Second); !problem.HasCode(err, problem.NotFound) {
		t.Fatalf("foreign wait = %v, want NOT_FOUND", err)
	}
	submitted, err := e.svc.Submit(e.ctx, RunRequest{
		Actor: humanActor(), Action: actionWrite, Target: Target{Subject: resourceSubject},
		Args:        mustJSON(t, map[string]any{"value": "y"}),
		Idempotency: Idempotency{Key: e.newKey(), Route: "/api/v1/test/write"},
	})
	if err != nil {
		t.Fatalf("submit: %v", err)
	}
	if submitted == nil || submitted.Status != Succeeded {
		t.Fatalf("submit = %+v", submitted)
	}
}

// TestJobProgressThrottling checks that progress writes are throttled but the
// terminal message is always written.
func TestJobProgressThrottling(t *testing.T) {
	e := newTestEnv(t)
	e.dispatcher.jobFn = func(_ context.Context, _ PluginRunJobRequest, progress func(JobProgress) error) error {
		for _, step := range []string{"a", "b", "c"} {
			if err := progress(JobProgress{Percent: intPtr(10), Step: step}); err != nil {
				return err
			}
		}
		return progress(JobProgress{Completed: true, Percent: intPtr(100), Step: "done"})
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
	e.waitFor("job", func() bool { return e.operation(id).Status == Succeeded })
	progressEvents := 0
	for _, ev := range e.events("operation.updated", "operations/"+id) {
		var payload struct {
			Status   string    `json:"status"`
			Progress *Progress `json:"progress"`
		}
		if err := json.Unmarshal(ev.Payload, &payload); err != nil {
			t.Fatal(err)
		}
		if payload.Status == string(Running) && payload.Progress != nil {
			progressEvents++
			if payload.Progress.Step != "a" {
				t.Fatalf("the first progress was replaced by %q", payload.Progress.Step)
			}
		}
	}
	if progressEvents != 1 {
		t.Fatalf("RUNNING progress events = %d, want 1 (throttled)", progressEvents)
	}
	if op := e.operation(id); op.Progress == nil || op.Progress.Step != "done" {
		t.Fatalf("final progress = %+v", op.Progress)
	}
}
