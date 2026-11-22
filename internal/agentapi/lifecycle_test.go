// SPDX-License-Identifier: AGPL-3.0-only

package agentapi

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/qwq-panel/qwq/internal/authz"
	"github.com/qwq-panel/qwq/internal/platform/problem"
)

func TestPlanExecuteWaitChain(t *testing.T) {
	e := newTestEnv(t)

	status, plan := e.post(t, "/api/v1/agent/plan", map[string]any{
		"action": actionScan,
		"args":   map[string]any{"scope": "cpu"},
		"target": nodeTarget(),
	})
	if status != http.StatusOK {
		t.Fatalf("plan: status %d: %v", status, plan)
	}
	planID := str(t, plan["plan_id"])
	if planID == "" {
		t.Fatal("plan_id is empty")
	}
	if plan["action"] != actionScan {
		t.Fatalf("action = %v", plan["action"])
	}
	if got := obj(t, plan["target"]); got["plugin_id"] != fixturePlugin || got["node_id"] != testNode {
		t.Fatalf("target = %v", got)
	}
	digest := str(t, plan["args_digest"])
	if !strings.HasPrefix(digest, "sha256:") || len(digest) != len("sha256:")+64 {
		t.Fatalf("args_digest = %q", digest)
	}
	if plan["plannable"] != true || plan["executable"] != true {
		t.Fatalf("plannable = %v, executable = %v", plan["plannable"], plan["executable"])
	}
	if plan["requires_approval"] != false {
		t.Fatalf("requires_approval = %v", plan["requires_approval"])
	}
	if plan["effective_risk"] != "low" {
		t.Fatalf("effective_risk = %v", plan["effective_risk"])
	}
	// arrays are always present, even when empty
	list(t, plan["changes"])
	list(t, plan["violations"])
	list(t, plan["warnings"])
	list(t, plan["preconditions"])
	changes := list(t, plan["changes"])
	if len(changes) != 1 {
		t.Fatalf("changes = %v", changes)
	}
	change := obj(t, changes[0])
	if change["source"] != "plugin" || change["kind"] != "update" {
		t.Fatalf("change = %v", change)
	}
	wantSubject := "nodes/" + testNode + "/plugins/" + fixturePlugin + "/instances/" + testInstance + "/resources/alerts/cpu"
	if change["subject"] != wantSubject {
		t.Fatalf("subject = %v, want %s", change["subject"], wantSubject)
	}

	// execute(plan_id) -> SUCCEEDED, then wait returns at once.
	out := e.execute(t, map[string]any{"plan_id": planID})
	opID := str(t, out["operation_id"])
	if out["status"] != "SUCCEEDED" {
		t.Fatalf("status = %v (%v)", out["status"], out)
	}
	if out["action"] != actionScan || out["effective_risk"] != "low" {
		t.Fatalf("outcome = %v", out)
	}
	status, waited := e.post(t, "/api/v1/agent/wait", map[string]any{
		"operation_id": opID, "timeout_seconds": 5,
	})
	if status != http.StatusOK {
		t.Fatalf("wait: status %d: %v", status, waited)
	}
	if waited["status"] != "SUCCEEDED" {
		t.Fatalf("wait status = %v", waited["status"])
	}
	if _, ok := waited["timed_out"]; ok {
		t.Fatalf("timed_out = %v", waited["timed_out"])
	}
	if waited["operation_id"] != opID {
		t.Fatalf("operation_id = %v", waited["operation_id"])
	}

	// A plan executes once.
	status, data := e.do(t, e.adminToken, "/api/v1/agent/execute", map[string]any{"plan_id": planID}, nil)
	if status != http.StatusConflict {
		t.Fatalf("second execute: status %d, want 409 (%s)", status, data)
	}
	if code, _, _ := problemOf(t, data); code != string(problem.StateConflict) {
		t.Fatalf("second execute: code %s", code)
	}

	// action + args works without a plan.
	out = e.execute(t, map[string]any{
		"action": actionScan, "args": map[string]any{"scope": "mem"}, "target": nodeTarget(),
	})
	if out["status"] != "SUCCEEDED" {
		t.Fatalf("direct execute: %v", out)
	}
	if out["operation_id"] == opID {
		t.Fatal("the direct execution reused the plan's operation")
	}
}

func TestExecuteIdempotentReplay(t *testing.T) {
	e := newTestEnv(t)
	headers := map[string]string{"Idempotency-Key": "tool-call-0123456789"}
	body := map[string]any{
		"action": actionScan, "args": map[string]any{"scope": "cpu"}, "target": nodeTarget(),
	}
	status, first := e.postAs(t, e.adminToken, "/api/v1/agent/execute", body, headers)
	if status != http.StatusOK {
		t.Fatalf("status %d: %v", status, first)
	}
	status, second := e.postAs(t, e.adminToken, "/api/v1/agent/execute", body, headers)
	if status != http.StatusOK {
		t.Fatalf("replay: status %d: %v", status, second)
	}
	if first["operation_id"] != second["operation_id"] {
		t.Fatalf("replay created a second operation: %v vs %v", first["operation_id"], second["operation_id"])
	}
	if got := e.dispatcher.invokeCount(); got != 1 {
		t.Fatalf("the action ran %d times, want 1", got)
	}

	// Reusing the key for another request is a client error.
	status, data := e.do(t, e.adminToken, "/api/v1/agent/execute", map[string]any{
		"action": actionScan, "args": map[string]any{"scope": "other"}, "target": nodeTarget(),
	}, headers)
	if status != http.StatusUnprocessableEntity {
		t.Fatalf("reused key: status %d, want 422 (%s)", status, data)
	}
	if code, _, _ := problemOf(t, data); code != string(problem.IdempotencyKeyReused) {
		t.Fatalf("reused key: code %s", code)
	}
}

func TestExecuteValidation(t *testing.T) {
	e := newTestEnv(t)
	target := nodeTarget()
	cases := []struct {
		name string
		body map[string]any
		want string // violation pointer
	}{
		{"both forms", map[string]any{"plan_id": "pln_x", "action": actionScan, "args": map[string]any{}, "target": target}, "/plan_id"},
		{"neither form", map[string]any{}, "/plan_id"},
		{"action without args", map[string]any{"action": actionScan, "target": target}, "/args"},
		{"plan with args", map[string]any{"plan_id": "pln_x", "args": map[string]any{}}, "/plan_id"},
		{"bad action", map[string]any{"action": "Not An Action", "args": map[string]any{}}, "/action"},
		{"bad plan id", map[string]any{"plan_id": "not a plan"}, "/plan_id"},
		{"revision without subject", map[string]any{
			"action": actionScan, "args": map[string]any{}, "target": target, "expected_revision": "42",
		}, "/target/subject"},
		{"unknown member", map[string]any{"action": actionScan, "args": map[string]any{}, "nope": 1}, "/nope"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			data := e.expectProblem(t, e.adminToken, "/api/v1/agent/execute",
				tc.body, http.StatusBadRequest, string(problem.ValidationFailed))
			_, _, violations := problemOf(t, data)
			if len(violations) == 0 {
				t.Fatalf("no violations: %s", data)
			}
			if got := obj(t, violations[0])["pointer"]; got != tc.want {
				t.Fatalf("pointer = %v, want %s (%s)", got, tc.want, data)
			}
		})
	}

	// An unknown action is NOT_FOUND, an out-of-policy action is PERMISSION_DENIED.
	e.expectProblem(t, e.adminToken, "/api/v1/agent/execute", map[string]any{
		"action": "com.example.demo/nope", "args": map[string]any{}, "target": target,
	}, http.StatusNotFound, string(problem.NotFound))
	e.expectProblem(t, e.adminToken, "/api/v1/agent/execute", map[string]any{
		"action": "host.users.create", "args": map[string]any{"username": "bob", "role": "viewer"},
	}, http.StatusForbidden, string(problem.PermissionDenied))
	// A viewer-owned delegation cannot execute a write action.
	e.expectProblem(t, e.viewerToken, "/api/v1/agent/execute", map[string]any{
		"action": actionScan, "args": map[string]any{}, "target": target,
	}, http.StatusForbidden, string(problem.PermissionDenied))
}

// TestExecuteRejectsActionOutsidePolicy is the failure scenario of an action
// allowlist that only filtered what the tools display: a delegation limited to
// report.read asks to execute scan.run, a low-risk write that its administrator
// owner may run and that would auto-execute. execute must refuse it before
// anything is recorded or dispatched, and the listed action must still run.
func TestExecuteRejectsActionOutsidePolicy(t *testing.T) {
	e := newTestEnv(t)
	policy := authz.DefaultPolicy()
	policy.Actions = []string{actionReport}
	_, token := e.createDelegation(e.adminUser.ID, policy)
	operationRows := func() int {
		t.Helper()
		var n int
		if err := e.db.Reader().QueryRowContext(e.ctx, `SELECT COUNT(*) FROM operations`).Scan(&n); err != nil {
			t.Fatalf("count operations: %v", err)
		}
		return n
	}

	before := operationRows()
	e.expectProblem(t, token, "/api/v1/agent/execute", map[string]any{
		"action": actionScan, "args": map[string]any{"scope": "cpu"}, "target": nodeTarget(),
	}, http.StatusForbidden, string(problem.PermissionDenied))
	if got := operationRows(); got != before {
		t.Fatalf("operations rows = %d after the refusal, want %d", got, before)
	}
	if got := e.dispatcher.invokeCount(); got != 0 {
		t.Fatalf("the refused action was dispatched %d times", got)
	}

	// The allowlist narrows the delegation; it does not lock it out.
	status, out := e.postAs(t, token, "/api/v1/agent/execute", map[string]any{
		"action": actionReport, "args": map[string]any{}, "target": nodeTarget(),
	}, nil)
	if status != http.StatusOK || out["status"] != "SUCCEEDED" {
		t.Fatalf("listed action: status %d, body %v", status, out)
	}
}

func TestPlanValidation(t *testing.T) {
	e := newTestEnv(t)
	e.expectProblem(t, e.adminToken, "/api/v1/agent/plan",
		map[string]any{"action": actionScan, "target": nodeTarget()},
		http.StatusBadRequest, string(problem.ValidationFailed))
	e.expectProblem(t, e.adminToken, "/api/v1/agent/plan",
		map[string]any{"action": actionScan, "args": map[string]any{}, "expected_revision": "7"},
		http.StatusBadRequest, string(problem.ValidationFailed))
	e.expectProblem(t, e.adminToken, "/api/v1/agent/plan",
		map[string]any{"action": "com.example.demo/nope", "args": map[string]any{}},
		http.StatusNotFound, string(problem.NotFound))
	// A node-placed plugin action needs its node and instance.
	e.expectProblem(t, e.adminToken, "/api/v1/agent/plan",
		map[string]any{"action": actionScan, "args": map[string]any{}},
		http.StatusBadRequest, string(problem.ValidationFailed))

	// High risk is plannable and needs approval, but planning changes nothing.
	status, plan := e.post(t, "/api/v1/agent/plan", map[string]any{
		"action": actionBaseline, "args": map[string]any{}, "target": nodeTarget(),
	})
	if status != http.StatusOK {
		t.Fatalf("status %d: %v", status, plan)
	}
	if plan["requires_approval"] != true {
		t.Fatalf("requires_approval = %v", plan["requires_approval"])
	}
	if plan["effective_risk"] != "high" {
		t.Fatalf("effective_risk = %v", plan["effective_risk"])
	}
	if plan["requires_mfa"] == true {
		t.Fatalf("requires_mfa = %v for a write action", plan["requires_mfa"])
	}
}

func TestHighRiskStopsAtApproval(t *testing.T) {
	e := newTestEnv(t)
	opID, approvalID := e.pendingApproval(t)

	// The operation is queued for a human; the AI can read it but not decide.
	op := e.operation(opID)
	if op.Status.String() != "AWAITING_APPROVAL" {
		t.Fatalf("status = %s", op.Status)
	}
	if op.ApprovalID != approvalID {
		t.Fatalf("approval_id = %q, want %q", op.ApprovalID, approvalID)
	}
	approval, err := e.ops.GetApproval(e.ctx, aiActor(e.adminDelegation, e.adminUser.ID), approvalID)
	if err != nil {
		t.Fatalf("get approval: %v", err)
	}
	if string(approval.Status) != "PENDING" {
		t.Fatalf("approval status = %s", approval.Status)
	}
	if e.authz.CanApprove(aiActor(e.adminDelegation, e.adminUser.ID)) {
		t.Fatal("a delegation may approve an operation")
	}
	// There is no agent route that decides an approval.
	for _, rt := range e.gw.Routes() {
		if strings.Contains(rt.Pattern, "/agent/") &&
			(strings.Contains(rt.Pattern, "approv") || strings.Contains(rt.Pattern, "decision")) {
			t.Fatalf("agent route %s decides approvals", rt.Pattern)
		}
	}

	// Waiting on an operation that is already awaiting approval waits for the
	// decision: it times out instead of returning at once.
	type waitResult struct {
		status int
		body   map[string]any
		err    error
	}
	results := make(chan waitResult, 1)
	go func() {
		status, data, err := e.sendJSON(e.adminToken, "/api/v1/agent/wait",
			map[string]any{"operation_id": opID, "timeout_seconds": 2}, nil)
		var body map[string]any
		if err == nil {
			err = json.Unmarshal(data, &body)
		}
		results <- waitResult{status: status, body: body, err: err}
	}()
	e.waitFor("the wait to start", func() bool {
		return e.h.waits.count(e.adminDelegation) == 1
	})
	// Move the fake clock in small steps, yielding in between: the handler arms
	// a new timer after every wake-up, so one big jump could land between two
	// polls and leave it waiting for a timer that already fired.
	deadline := time.Now().Add(10 * time.Second)
	var res waitResult
	for {
		e.clock.Advance(200 * time.Millisecond)
		select {
		case res = <-results:
		case <-time.After(15 * time.Millisecond):
			if time.Now().After(deadline) {
				t.Fatal("the wait did not return")
			}
			continue
		}
		break
	}
	if res.err != nil {
		t.Fatalf("wait: %v", res.err)
	}
	if res.status != http.StatusOK {
		t.Fatalf("wait: status %d: %v", res.status, res.body)
	}
	if res.body["timed_out"] != true {
		t.Fatalf("timed_out = %v (%v)", res.body["timed_out"], res.body)
	}
	if res.body["status"] != "AWAITING_APPROVAL" {
		t.Fatalf("status = %v", res.body["status"])
	}

	// Cancel ends the queued operation and its approval.
	status, out := e.post(t, "/api/v1/agent/cancel", map[string]any{
		"operation_id": opID, "reason": "no longer needed",
	})
	if status != http.StatusOK {
		t.Fatalf("cancel: status %d: %v", status, out)
	}
	if out["status"] != "CANCELED" {
		t.Fatalf("cancel status = %v", out["status"])
	}
	approval, err = e.ops.GetApproval(e.ctx, aiActor(e.adminDelegation, e.adminUser.ID), approvalID)
	if err != nil {
		t.Fatalf("get approval: %v", err)
	}
	if string(approval.Status) != "CANCELED" {
		t.Fatalf("approval status = %s, want CANCELED", approval.Status)
	}
}

func TestCancelOwnership(t *testing.T) {
	e := newTestEnv(t)

	// Finished operations cannot be canceled.
	opID := e.executedOperation(t)
	status, data := e.do(t, e.adminToken, "/api/v1/agent/cancel",
		map[string]any{"operation_id": opID}, nil)
	if status != http.StatusConflict {
		t.Fatalf("finished cancel: status %d, want 409 (%s)", status, data)
	}
	if code, _, _ := problemOf(t, data); code != string(problem.StateConflict) {
		t.Fatalf("finished cancel: code %s", code)
	}

	// Another delegation of the same owner created this operation; a delegation
	// can cancel only what it created, and gets 404 for the rest.
	status, out := e.postAs(t, e.adminTokenTwo, "/api/v1/agent/execute", map[string]any{
		"action": actionScan, "args": map[string]any{}, "target": nodeTarget(),
	}, nil)
	if status != http.StatusOK {
		t.Fatalf("second delegation execute: status %d: %v", status, out)
	}
	foreign := str(t, out["operation_id"])
	status, data = e.do(t, e.adminToken, "/api/v1/agent/cancel",
		map[string]any{"operation_id": foreign}, nil)
	if status != http.StatusNotFound {
		t.Fatalf("foreign cancel: status %d, want 404 (%s)", status, data)
	}
	if code, _, _ := problemOf(t, data); code != string(problem.NotFound) {
		t.Fatalf("foreign cancel: code %s", code)
	}
	// The owner still sees it.
	status, out = e.postAs(t, e.adminTokenTwo, "/api/v1/agent/cancel",
		map[string]any{"operation_id": foreign}, nil)
	if status != http.StatusConflict {
		t.Fatalf("owner cancel of a finished operation: status %d: %v", status, out)
	}

	e.expectProblem(t, e.adminToken, "/api/v1/agent/cancel",
		map[string]any{"operation_id": "not an id"}, http.StatusBadRequest, string(problem.ValidationFailed))
	e.expectProblem(t, e.adminToken, "/api/v1/agent/cancel",
		map[string]any{"operation_id": "op_missing"}, http.StatusNotFound, string(problem.NotFound))
	long := strings.Repeat("x", 501)
	e.expectProblem(t, e.adminToken, "/api/v1/agent/cancel",
		map[string]any{"operation_id": opID, "reason": long},
		http.StatusBadRequest, string(problem.ValidationFailed))
}

func TestWaitConcurrencyLimit(t *testing.T) {
	e := newTestEnv(t)
	opID, _ := e.pendingApproval(t)

	type result struct {
		status int
		body   map[string]any
		err    error
	}
	results := make(chan result, ConcurrentWaitsPerDelegation)
	for i := 0; i < ConcurrentWaitsPerDelegation; i++ {
		go func() {
			status, data, err := e.sendJSON(e.adminToken, "/api/v1/agent/wait",
				map[string]any{"operation_id": opID, "timeout_seconds": 1}, nil)
			var body map[string]any
			if err == nil {
				err = json.Unmarshal(data, &body)
			}
			results <- result{status: status, body: body, err: err}
		}()
	}
	e.waitFor("all waits to be admitted", func() bool {
		return e.h.waits.count(e.adminDelegation) == ConcurrentWaitsPerDelegation
	})

	// One more wait is refused with the documented limit.
	status, data := e.do(t, e.adminToken, "/api/v1/agent/wait",
		map[string]any{"operation_id": opID, "timeout_seconds": 1}, nil)
	if status != http.StatusTooManyRequests {
		t.Fatalf("fifth wait: status %d, want 429 (%s)", status, data)
	}
	var pl struct {
		Code  string `json:"code"`
		Limit struct {
			Name string `json:"name"`
			Max  int    `json:"max"`
		} `json:"limit"`
	}
	if err := json.Unmarshal(data, &pl); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if pl.Code != string(problem.RateLimited) {
		t.Fatalf("code = %s", pl.Code)
	}
	if pl.Limit.Name != "agent_concurrent_waits_per_delegation" || pl.Limit.Max != ConcurrentWaitsPerDelegation {
		t.Fatalf("limit = %+v", pl.Limit)
	}

	// Release the four waits by moving time past their timeout.
	deadline := time.Now().Add(10 * time.Second)
	for got := 0; got < ConcurrentWaitsPerDelegation; {
		e.clock.Advance(200 * time.Millisecond)
		select {
		case res := <-results:
			got++
			if res.err != nil {
				t.Fatalf("wait: %v", res.err)
			}
			if res.status != http.StatusOK {
				t.Fatalf("wait: status %d: %v", res.status, res.body)
			}
			if res.body["timed_out"] != true {
				t.Fatalf("timed_out = %v", res.body["timed_out"])
			}
		case <-time.After(20 * time.Millisecond):
		}
		if time.Now().After(deadline) {
			t.Fatal("the waits did not return")
		}
	}
	e.waitFor("the limiter to drain", func() bool { return e.h.waits.count(e.adminDelegation) == 0 })
}

func TestWaitValidation(t *testing.T) {
	e := newTestEnv(t)
	e.expectProblem(t, e.adminToken, "/api/v1/agent/wait",
		map[string]any{}, http.StatusBadRequest, string(problem.ValidationFailed))
	e.expectProblem(t, e.adminToken, "/api/v1/agent/wait",
		map[string]any{"operation_id": "op_x", "timeout_seconds": 60},
		http.StatusBadRequest, string(problem.ValidationFailed))
	e.expectProblem(t, e.adminToken, "/api/v1/agent/wait",
		map[string]any{"operation_id": "op_x", "timeout_seconds": 0},
		http.StatusBadRequest, string(problem.ValidationFailed))
	e.expectProblem(t, e.adminToken, "/api/v1/agent/wait",
		map[string]any{"operation_id": "op_missing"}, http.StatusNotFound, string(problem.NotFound))
}
