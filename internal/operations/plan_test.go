// SPDX-License-Identifier: AGPL-3.0-only

package operations

import (
	"context"
	"database/sql"
	"encoding/json"
	"testing"
	"time"

	"github.com/qwq-panel/qwq/internal/platform/problem"
)

// nodeTarget is the target of a node-placed plugin action.
func nodeTarget() Target {
	return Target{NodeID: "local", PluginID: pluginID, InstanceID: "default"}
}

func TestCreateAndExecutePlan(t *testing.T) {
	e := newTestEnv(t)
	if _, err := e.run(humanActor(), actionWrite, Target{Subject: resourceSubject}, map[string]any{"value": "one"}); err != nil {
		t.Fatal(err)
	}
	rev := e.resourceRevision(resourceSubject)
	plan, err := e.svc.CreatePlan(e.ctx, PlanRequest{
		Actor: humanActor(), Action: actionWrite, Target: Target{Subject: resourceSubject},
		Args: mustJSON(t, map[string]any{"value": "planned"}), ExpectedRevision: rev,
	})
	if err != nil {
		t.Fatalf("create plan: %v", err)
	}
	if plan.Executable != true || plan.RequiresApproval || plan.RequiresMFA {
		t.Fatalf("plan flags = %+v", plan)
	}
	if plan.ArgsDigest != digestOf(plan.Args) {
		t.Fatalf("args digest = %q", plan.ArgsDigest)
	}
	if !plan.ExpiresAt.After(plan.CreatedAt) {
		t.Fatalf("plan expiry = %v (created %v)", plan.ExpiresAt, plan.CreatedAt)
	}

	resp, err := e.svc.ExecutePlan(e.ctx, ExecutePlanRequest{
		Actor: humanActor(), PlanID: plan.ID,
		Idempotency: Idempotency{Key: e.newKey(), Route: "/api/v1/plans/" + plan.ID + "/execute"},
	})
	if err != nil {
		t.Fatalf("execute plan: %v", err)
	}
	if resp.Status != 200 || resp.Operation.Status != Succeeded {
		t.Fatalf("execute plan = %d %+v", resp.Status, resp.Operation)
	}
	if resp.Operation.PlanID != plan.ID {
		t.Fatalf("operation plan id = %q", resp.Operation.PlanID)
	}
	var value string
	if err := e.db.Reader().QueryRowContext(e.ctx,
		`SELECT value FROM test_resources WHERE subject = ?`, resourceSubject).Scan(&value); err != nil {
		t.Fatal(err)
	}
	if value != "planned" {
		t.Fatalf("value = %q", value)
	}

	// A plan executes at most once.
	_, err = e.svc.ExecutePlan(e.ctx, ExecutePlanRequest{
		Actor: humanActor(), PlanID: plan.ID,
		Idempotency: Idempotency{Key: e.newKey(), Route: "/api/v1/plans/" + plan.ID + "/execute"},
	})
	if !problem.HasCode(err, problem.StateConflict) {
		t.Fatalf("second execute = %v, want STATE_CONFLICT", err)
	}
}

func TestPlanExpired(t *testing.T) {
	e := newTestEnv(t)
	plan, err := e.svc.CreatePlan(e.ctx, PlanRequest{
		Actor: humanActor(), Action: actionWrite, Target: Target{Subject: resourceSubject},
		Args: mustJSON(t, map[string]any{"value": "x"}),
	})
	if err != nil {
		t.Fatal(err)
	}
	e.clock.Advance(16 * time.Minute)
	_, err = e.svc.ExecutePlan(e.ctx, ExecutePlanRequest{
		Actor: humanActor(), PlanID: plan.ID,
		Idempotency: Idempotency{Key: e.newKey(), Route: "/api/v1/plans/" + plan.ID + "/execute"},
	})
	if !problem.HasCode(err, problem.PlanExpired) {
		t.Fatalf("expired plan = %v, want PLAN_EXPIRED", err)
	}
}

func TestPlanBlockingViolations(t *testing.T) {
	e := newTestEnv(t)
	e.dispatcher.planFn = func(context.Context, PluginPlanRequest) (Preview, error) {
		return Preview{Violations: []problem.Violation{
			{Pointer: "/value", Code: "REQUIRED", Message: "value is required"},
		}}, nil
	}
	plan, err := e.svc.CreatePlan(e.ctx, PlanRequest{
		Actor: humanActor(), Action: actionPlugin, Target: nodeTarget(),
		Args: mustJSON(t, map[string]any{}),
	})
	if err != nil {
		t.Fatal(err)
	}
	if plan.Executable || len(plan.Violations) != 1 {
		t.Fatalf("plan = %+v", plan)
	}
	_, err = e.svc.ExecutePlan(e.ctx, ExecutePlanRequest{
		Actor: humanActor(), PlanID: plan.ID,
		Idempotency: Idempotency{Key: e.newKey(), Route: "/api/v1/plans/" + plan.ID + "/execute"},
	})
	if !problem.HasCode(err, problem.ValidationFailed) {
		t.Fatalf("execute = %v, want VALIDATION_FAILED", err)
	}
}

func TestPluginPlanPrefixesSubjects(t *testing.T) {
	e := newTestEnv(t)
	e.dispatcher.planFn = func(context.Context, PluginPlanRequest) (Preview, error) {
		return Preview{
			Changes: []PlannedChange{
				{Kind: "update", Subject: "alerts/cpu", Reversible: true, Description: "raise the alert"},
			},
			Preconditions: []Precondition{{Subject: "alerts/cpu", Revision: "9"}},
			Warnings:      []problem.Violation{{Pointer: "/threshold", Code: "DEPRECATED", Message: "old field"}},
		}, nil
	}
	full := "nodes/local/plugins/com.example.demo/instances/default/resources/alerts/cpu"
	plan, err := e.svc.CreatePlan(e.ctx, PlanRequest{
		Actor: humanActor(), Action: actionPlugin,
		Target: Target{NodeID: "local", PluginID: pluginID, InstanceID: "default", Subject: full},
		Args:   mustJSON(t, map[string]any{"threshold": 5}), ExpectedRevision: "9",
	})
	if err != nil {
		t.Fatalf("create plan: %v", err)
	}
	if len(plan.Changes) != 1 {
		t.Fatalf("changes = %+v", plan.Changes)
	}
	change := plan.Changes[0]
	if change.Subject != full || change.Source != string(PluginSource) || change.PluginID != pluginID {
		t.Fatalf("change = %+v", change)
	}
	if change.Description != "raise the alert" {
		t.Fatalf("plugin description lost: %+v", change)
	}
	if len(plan.Preconditions) != 0 {
		t.Fatalf("plugin preconditions must not appear as host preconditions: %+v", plan.Preconditions)
	}
	if len(plan.PluginPreconditions) != 1 || plan.PluginPreconditions[0].Subject != "alerts/cpu" ||
		plan.PluginPreconditions[0].Revision != "9" {
		t.Fatalf("plugin preconditions = %+v", plan.PluginPreconditions)
	}

	// Execution hands the relative precondition to the plugin.
	var got []Precondition
	e.dispatcher.invokeFn = func(_ context.Context, req PluginInvokeRequest) (PluginInvokeResponse, error) {
		got = append([]Precondition(nil), req.Preconditions...)
		return PluginInvokeResponse{Result: json.RawMessage(`{"ok":true}`)}, nil
	}
	if _, err := e.svc.ExecutePlan(e.ctx, ExecutePlanRequest{
		Actor: humanActor(), PlanID: plan.ID,
		Idempotency: Idempotency{Key: e.newKey(), Route: "/api/v1/plans/" + plan.ID + "/execute"},
	}); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if len(got) != 1 || got[0].Subject != "alerts/cpu" || got[0].Revision != "9" {
		t.Fatalf("plugin preconditions at execution = %+v", got)
	}
}

func TestPluginPlanRejectsBadSubject(t *testing.T) {
	e := newTestEnv(t)
	e.dispatcher.planFn = func(context.Context, PluginPlanRequest) (Preview, error) {
		return Preview{Changes: []PlannedChange{{Kind: "update", Subject: "../escape"}}}, nil
	}
	_, err := e.svc.CreatePlan(e.ctx, PlanRequest{
		Actor: humanActor(), Action: actionPlugin, Target: nodeTarget(),
		Args: mustJSON(t, map[string]any{}),
	})
	if !problem.HasCode(err, problem.PluginError) {
		t.Fatalf("got %v, want PLUGIN_ERROR", err)
	}
}

func TestHostPlannerIsUsed(t *testing.T) {
	e := newTestEnv(t)
	e.svc.RegisterHostPlanner(actionWrite, func(_ context.Context, _ *sql.Tx, req HostRequest) (Preview, error) {
		return Preview{
			Changes:       []PlannedChange{{Kind: "update", Subject: req.Target.Subject, Reversible: true}},
			Preconditions: []Precondition{{Subject: req.Target.Subject, Revision: "5"}},
		}, nil
	})
	plan, err := e.svc.CreatePlan(e.ctx, PlanRequest{
		Actor: humanActor(), Action: actionWrite, Target: Target{Subject: resourceSubject},
		Args: mustJSON(t, map[string]any{"value": "x"}),
	})
	if err != nil {
		t.Fatal(err)
	}
	if !plan.Plannable || len(plan.Changes) != 1 || plan.Changes[0].Source != string(HostSource) {
		t.Fatalf("plan = %+v", plan)
	}
	if len(plan.Preconditions) != 1 || plan.Preconditions[0].Revision != "5" {
		t.Fatalf("planner preconditions = %+v", plan.Preconditions)
	}
}

func TestPlanOwnership(t *testing.T) {
	e := newTestEnv(t)
	plan, err := e.svc.CreatePlan(e.ctx, PlanRequest{
		Actor: humanActor(), Action: actionWrite, Target: Target{Subject: resourceSubject},
		Args: mustJSON(t, map[string]any{"value": "x"}),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.GetPlan(e.ctx, aiActor(), plan.ID); !problem.HasCode(err, problem.NotFound) {
		t.Fatalf("foreign plan = %v, want NOT_FOUND", err)
	}
	if _, err := e.svc.GetPlan(e.ctx, humanActor(), plan.ID); err != nil {
		t.Fatalf("owner plan: %v", err)
	}
	if _, err := e.svc.ExecutePlan(e.ctx, ExecutePlanRequest{
		Actor: aiActor(), PlanID: plan.ID,
		Idempotency: Idempotency{Key: e.newKey(), Route: "/api/v1/plans/" + plan.ID + "/execute"},
	}); !problem.HasCode(err, problem.NotFound) {
		t.Fatalf("foreign execute = %v, want NOT_FOUND", err)
	}
}
