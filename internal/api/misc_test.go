// SPDX-License-Identifier: AGPL-3.0-only

package api_test

import (
	"net/http"
	"testing"
	"time"

	"github.com/qwq-panel/qwq/internal/platform/problem"
)

// TestNodesPluginsPlansAndOperations covers the read routes and the plan →
// execute → cancel path, plus the HTTP-level errors of the gateway.
func TestNodesPluginsPlansAndOperations(t *testing.T) {
	e := newEnv(t)
	a := e.setupAdmin(adminUser)

	// ---- nodes ----
	nodes := e.do(a.sign(http.MethodGet, "/api/v1/nodes", "")).expect(t, http.StatusOK)
	var nodePage struct {
		Items    []map[string]any `json:"items"`
		Revision string           `json:"revision"`
	}
	nodes.decode(t, &nodePage)
	if len(nodePage.Items) != 1 || mustString(t, nodePage.Items[0], "node_id") != "local" {
		t.Fatalf("nodes = %v", nodePage.Items)
	}
	if mustString(t, nodePage.Items[0], "status") != "online" {
		t.Fatalf("node status = %v", nodePage.Items[0]["status"])
	}
	node := e.do(a.sign(http.MethodGet, "/api/v1/nodes/local", "")).expect(t, http.StatusOK)
	var nodeBody map[string]any
	node.decode(t, &nodeBody)
	if mustString(t, nodeBody, "created_at") == "" || mustString(t, nodeBody, "revision") == "" {
		t.Fatalf("node = %v", nodeBody)
	}
	projectedNode := e.do(a.sign(http.MethodGet, "/api/v1/nodes/local?fields=/status", "")).expect(t, http.StatusOK)
	var nodeFields map[string]any
	projectedNode.decode(t, &nodeFields)
	if len(nodeFields) != 3 {
		t.Fatalf("projected node = %v", nodeFields)
	}
	e.do(a.sign(http.MethodGet, "/api/v1/nodes/other", "")).
		expectProblem(t, http.StatusNotFound, problem.NotFound)

	// ---- plugins: no runtime, so nothing is installed ----
	plugins := e.do(a.sign(http.MethodGet, "/api/v1/plugins", "")).expect(t, http.StatusOK)
	var pluginPage struct {
		Items    []any  `json:"items"`
		Revision string `json:"revision"`
	}
	plugins.decode(t, &pluginPage)
	if pluginPage.Items == nil || len(pluginPage.Items) != 0 {
		t.Fatalf("plugins = %v", pluginPage.Items)
	}
	e.do(a.sign(http.MethodGet, "/api/v1/plugins/com.example.monitor", "")).
		expectProblem(t, http.StatusNotFound, problem.NotFound)
	install := a.sign(http.MethodPost, "/api/v1/plugins",
		`{"plugin_id":"com.example.monitor","version":"1.0.0","accepted_capabilities":[]}`)
	install.Header.Set("Idempotency-Key", idempotencyKey(1))
	e.do(install).expectProblem(t, http.StatusServiceUnavailable, problem.PluginUnavailable)
	uninstall := a.sign(http.MethodDelete, "/api/v1/plugins/com.example.monitor?expected_revision=1", "")
	uninstall.Header.Set("Idempotency-Key", idempotencyKey(2))
	e.do(uninstall).expectProblem(t, http.StatusServiceUnavailable, problem.PluginUnavailable)

	// ---- plans ----
	planBody := `{"action":"host.users.create","args":{"username":"carol","role":"viewer"}}`
	created := e.do(a.sign(http.MethodPost, "/api/v1/plans", planBody)).expect(t, http.StatusCreated)
	if loc := created.header.Get("Location"); loc == "" {
		t.Fatal("plan has no Location")
	}
	var plan map[string]any
	created.decode(t, &plan)
	planID := mustString(t, plan, "plan_id")
	if plan["plannable"] != true || plan["executable"] != true || plan["requires_approval"] != true {
		t.Fatalf("plan flags = %v", plan)
	}
	if mustString(t, plan, "effective_risk") != "high" {
		t.Fatalf("effective_risk = %v", plan["effective_risk"])
	}
	changes, _ := plan["changes"].([]any)
	if len(changes) != 1 {
		t.Fatalf("changes = %v", changes)
	}
	change, _ := changes[0].(map[string]any)
	if mustString(t, change, "kind") != "create" || mustString(t, change, "subject") != "users" {
		t.Fatalf("change = %v", change)
	}
	if mustString(t, change, "source") != "host" {
		t.Fatalf("change source = %v", change["source"])
	}
	for _, key := range []string{"violations", "warnings", "preconditions"} {
		value, ok := plan[key].([]any)
		if !ok || value == nil {
			t.Fatalf("%s is not an array: %v", key, plan[key])
		}
	}
	got := e.do(a.sign(http.MethodGet, "/api/v1/plans/"+planID, "")).expect(t, http.StatusOK)
	var gotPlan map[string]any
	got.decode(t, &gotPlan)
	if mustString(t, gotPlan, "plan_id") != planID {
		t.Fatal("get plan returned another plan")
	}
	planFields := e.do(a.sign(http.MethodGet, "/api/v1/plans/"+planID+"?fields=/effective_risk", "")).expect(t, http.StatusOK)
	var projectedPlan map[string]any
	planFields.decode(t, &projectedPlan)
	if len(projectedPlan) != 3 {
		t.Fatalf("projected plan = %v", projectedPlan)
	}

	// Execute: the plan's action is risk high, so the operation waits.
	exec := a.sign(http.MethodPost, "/api/v1/plans/"+planID+"/execute", "")
	exec.Header.Set("Idempotency-Key", idempotencyKey(3))
	accepted := e.do(exec).expect(t, http.StatusAccepted)
	var operation map[string]any
	accepted.decode(t, &operation)
	operationID := mustString(t, operation, "operation_id")
	if mustString(t, operation, "status") != "AWAITING_APPROVAL" {
		t.Fatalf("operation = %v", operation["status"])
	}
	if accepted.header.Get("Location") != "/api/v1/operations/"+operationID {
		t.Fatalf("Location = %q", accepted.header.Get("Location"))
	}

	// A plan executes at most once.
	again := a.sign(http.MethodPost, "/api/v1/plans/"+planID+"/execute", "")
	again.Header.Set("Idempotency-Key", idempotencyKey(4))
	conflict := e.do(again).expectProblem(t, http.StatusConflict, problem.StateConflict)
	if conflict.OperationID != operationID {
		t.Fatalf("operation_id = %q, want %q", conflict.OperationID, operationID)
	}

	// ---- operations ----
	opsList := e.do(a.sign(http.MethodGet, "/api/v1/operations?status=AWAITING_APPROVAL&actor_kind=human", "")).
		expect(t, http.StatusOK)
	var opPage struct {
		Items      []map[string]any `json:"items"`
		NextCursor string           `json:"next_cursor"`
	}
	opsList.decode(t, &opPage)
	found := false
	for _, item := range opPage.Items {
		if mustString(t, item, "operation_id") == operationID {
			found = true
		}
	}
	if !found {
		t.Fatalf("operation %q not in %v", operationID, opPage.Items)
	}
	opBody := e.do(a.sign(http.MethodGet, "/api/v1/operations/"+operationID, "")).expect(t, http.StatusOK)
	var op map[string]any
	opBody.decode(t, &op)
	if mustString(t, op, "action") != "host.users.create" {
		t.Fatalf("operation action = %v", op["action"])
	}
	opFields := e.do(a.sign(http.MethodGet, "/api/v1/operations/"+operationID+"?fields=/status", "")).expect(t, http.StatusOK)
	var projectedOp map[string]any
	opFields.decode(t, &projectedOp)
	if mustString(t, projectedOp, "status") != "AWAITING_APPROVAL" {
		t.Fatalf("projected operation = %v", projectedOp)
	}
	if _, ok := projectedOp["action"]; ok {
		t.Fatalf("action was not projected away: %v", projectedOp)
	}
	e.do(a.sign(http.MethodGet, "/api/v1/operations/op_does_not_exist", "")).
		expectProblem(t, http.StatusNotFound, problem.NotFound)
	e.do(a.sign(http.MethodGet, "/api/v1/operations?status=NOPE", "")).
		expectProblem(t, http.StatusBadRequest, problem.ValidationFailed)

	// Cancel while it waits for approval; a second cancel is a state conflict.
	cancel := a.sign(http.MethodPost, "/api/v1/operations/"+operationID+"/cancel", "")
	cancel.Header.Set("Idempotency-Key", idempotencyKey(5))
	var canceled map[string]any
	e.do(cancel).expect(t, http.StatusOK).decode(t, &canceled)
	if mustString(t, canceled, "status") != "CANCELED" {
		t.Fatalf("cancel = %v", canceled["status"])
	}
	cancelAgain := a.sign(http.MethodPost, "/api/v1/operations/"+operationID+"/cancel", "")
	cancelAgain.Header.Set("Idempotency-Key", idempotencyKey(6))
	e.do(cancelAgain).expectProblem(t, http.StatusConflict, problem.StateConflict)

	// ---- approvals: the empty PENDING list is an array, not null ----
	approvals := e.do(a.sign(http.MethodGet, "/api/v1/approvals", "")).expect(t, http.StatusOK)
	var approvalPage struct {
		Items []any `json:"items"`
	}
	approvals.decode(t, &approvalPage)
	if approvalPage.Items == nil {
		t.Fatal("approvals items is null")
	}
	e.do(a.sign(http.MethodGet, "/api/v1/approvals?status=NOPE", "")).
		expectProblem(t, http.StatusBadRequest, problem.ValidationFailed)

	// ---- protocol errors ----
	notAllowed := e.do(a.sign(http.MethodPost, "/api/v1/nodes/local", "")).expect(t, http.StatusMethodNotAllowed)
	if got := notAllowed.header.Get("Allow"); got != "GET" {
		t.Fatalf("Allow = %q", got)
	}
	wrongType := a.sign(http.MethodPost, "/api/v1/users", `{"username":"dave","role":"viewer"}`)
	wrongType.Header.Set("Content-Type", "text/plain")
	wrongType.Header.Set("Idempotency-Key", idempotencyKey(7))
	e.do(wrongType).expectProblem(t, http.StatusUnsupportedMediaType, problem.UnsupportedMediaType)

	unknownPlan := a.sign(http.MethodPost, "/api/v1/plans",
		`{"action":"host.users.create","args":{},"nope":true}`)
	unknownPlan.Header.Set("Idempotency-Key", idempotencyKey(8))
	bad := e.do(unknownPlan).expectProblem(t, http.StatusBadRequest, problem.ValidationFailed)
	if len(bad.Violations) == 0 || bad.Violations[0].Pointer != "/nope" {
		t.Fatalf("violations = %+v", bad.Violations)
	}
	e.do(a.sign(http.MethodPost, "/api/v1/plans", `{"action":"host.users.create"}`)).
		expectProblem(t, http.StatusBadRequest, problem.ValidationFailed)
	e.do(a.sign(http.MethodPost, "/api/v1/plans", `{"action":"no.such.action","args":{}}`)).
		expectProblem(t, http.StatusNotFound, problem.NotFound)
}

// TestDecideApprovalMFABruteForceRateLimited: wrong mfa_code values on the
// decision route are 403 MFA_REQUIRED (the session stays valid) and the backoff
// stops guessing after the threshold, before the approval is even looked up.
func TestDecideApprovalMFABruteForceRateLimited(t *testing.T) {
	e := newEnv(t)
	a := e.setupAdmin(adminUser)
	post := func(n int) response {
		body := `{"decision":"approve","expected_revision":"1","mfa_code":"000000"}`
		req := a.sign(http.MethodPost, "/api/v1/approvals/apr_guess/decision", body)
		req.Header.Set("Idempotency-Key", idempotencyKey(n))
		return e.do(req)
	}
	for i := 1; i <= 3; i++ {
		post(i).expectProblem(t, http.StatusForbidden, problem.MFARequired)
	}
	if p := post(4).expectProblem(t, http.StatusTooManyRequests, problem.RateLimited); p.RetryAfter < 1 {
		t.Fatalf("retry_after = %d, want >= 1", p.RetryAfter)
	}
}

// TestSessionCookieMaxAgeIsAbsolute: the cookie lives as long as the absolute
// session deadline. The idle limit is enforced by the server on every request,
// so a cookie bound to it would log an active user out after 30 minutes.
func TestSessionCookieMaxAgeIsAbsolute(t *testing.T) {
	e := newEnv(t)
	a := e.setupAdmin(adminUser)
	want := int((12 * time.Hour) / time.Second)
	if got := a.raw.MaxAge; got < want-60 || got > want {
		t.Fatalf("Max-Age = %d, want about %d (absolute deadline)", got, want)
	}
}
