// SPDX-License-Identifier: AGPL-3.0-only

package agentapi

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/qwq-panel/qwq/internal/gateway"
	"github.com/qwq-panel/qwq/internal/platform/problem"
)

// deps returns the services of the env, for tests that build a second gateway.
func (e *testEnv) deps() Deps {
	return Deps{
		DB: e.db, Clock: e.clock, IDs: e.ids, Logger: slog.New(slog.DiscardHandler),
		Identity: e.ident, Authz: e.authz, Ops: e.ops, Catalog: e.cat, NodeID: testNode,
	}
}

func TestRegisterAddsSevenRoutes(t *testing.T) {
	e := newTestEnv(t)
	gw, err := gateway.New(gateway.Config{
		Clock: e.clock, IDs: e.ids, Logger: slog.New(slog.DiscardHandler),
		Auth: testAuthenticator{authz: e.authz},
	})
	if err != nil {
		t.Fatalf("gateway: %v", err)
	}
	if err := Register(gw, e.deps()); err != nil {
		t.Fatalf("register: %v", err)
	}
	want := map[string]bool{
		"/api/v1/agent/find_actions":    false,
		"/api/v1/agent/describe_action": false,
		"/api/v1/agent/read":            false,
		"/api/v1/agent/plan":            false,
		"/api/v1/agent/execute":         false,
		"/api/v1/agent/wait":            false,
		"/api/v1/agent/cancel":          false,
	}
	for _, rt := range gw.Routes() {
		if _, ok := want[rt.Pattern]; !ok {
			continue
		}
		if rt.Method != http.MethodPost {
			t.Errorf("%s: method %s, want POST", rt.Pattern, rt.Method)
		}
		if rt.Access != gateway.AccessDelegation {
			t.Errorf("%s: access %v, want AccessDelegation", rt.Pattern, rt.Access)
		}
		want[rt.Pattern] = true
	}
	for pattern, found := range want {
		if !found {
			t.Errorf("route %s is not registered", pattern)
		}
	}
	// Registering twice must fail: the tools own their paths.
	if err := Register(gw, e.deps()); err == nil {
		t.Fatal("a second Register succeeded")
	}
	if err := Register(nil, e.deps()); err == nil {
		t.Fatal("Register(nil) succeeded")
	}
	if err := Register(gw, Deps{}); err == nil {
		t.Fatal("Register accepted empty Deps")
	}
}

func TestAgentRoutesRejectForeignCredentials(t *testing.T) {
	e := newTestEnv(t)
	body := map[string]any{"query": "scan"}

	status, data := e.do(t, "", "/api/v1/agent/find_actions", body, nil)
	if status != http.StatusUnauthorized {
		t.Fatalf("no credentials: status %d, want 401 (%s)", status, data)
	}
	if code, _, _ := problemOf(t, data); code != string(problem.Unauthenticated) {
		t.Fatalf("no credentials: code %s", code)
	}

	// A service account authenticates, but /api/v1/agent/* is delegation-only.
	status, data = e.do(t, e.serviceToken(), "/api/v1/agent/find_actions", body, nil)
	if status != http.StatusForbidden {
		t.Fatalf("service token: status %d, want 403 (%s)", status, data)
	}
	if code, _, _ := problemOf(t, data); code != string(problem.PermissionDenied) {
		t.Fatalf("service token: code %s", code)
	}

	// An unknown delegation token is unauthenticated, not forbidden.
	status, data = e.do(t, "qwq_dlg_does_not_exist", "/api/v1/agent/find_actions", body, nil)
	if status != http.StatusUnauthorized {
		t.Fatalf("bogus token: status %d, want 401 (%s)", status, data)
	}

	// The tools are POST only.
	req, err := http.NewRequestWithContext(e.ctx, http.MethodGet, e.server.URL+"/api/v1/agent/find_actions", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+e.adminToken)
	resp, err := e.client.Do(req)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("GET: status %d, want 405", resp.StatusCode)
	}
}

func TestFindActionsFiltersAndValidates(t *testing.T) {
	e := newTestEnv(t)

	t.Run("best match first", func(t *testing.T) {
		status, out := e.post(t, "/api/v1/agent/find_actions", map[string]any{"query": "scan"})
		if status != http.StatusOK {
			t.Fatalf("status %d: %v", status, out)
		}
		if truncated := out["truncated"]; truncated != false {
			t.Fatalf("truncated = %v", truncated)
		}
		actions := list(t, out["actions"])
		if len(actions) != 1 {
			t.Fatalf("actions = %v, want the scan action", actions)
		}
		first := obj(t, actions[0])
		if got := first["id"]; got != actionScan {
			t.Fatalf("id = %v, want %s", got, actionScan)
		}
		if got := first["effect"]; got != "write" {
			t.Fatalf("effect = %v", got)
		}
		if got := first["risk"]; got != "low" {
			t.Fatalf("risk = %v", got)
		}
		if _, ok := first["summary"]; !ok {
			t.Fatal("summary is missing")
		}
		// ActionSummary is deliberately minimal.
		if len(first) != 4 {
			t.Fatalf("action has %d members, want 4: %v", len(first), first)
		}
	})

	t.Run("truncated flag", func(t *testing.T) {
		status, out := e.post(t, "/api/v1/agent/find_actions",
			map[string]any{"query": "host", "limit": 1})
		if status != http.StatusOK {
			t.Fatalf("status %d: %v", status, out)
		}
		if out["truncated"] != true {
			t.Fatalf("truncated = %v, want true", out["truncated"])
		}
		if got := len(list(t, out["actions"])); got != 1 {
			t.Fatalf("actions = %d, want 1", got)
		}
	})

	t.Run("scope filters", func(t *testing.T) {
		status, out := e.post(t, "/api/v1/agent/find_actions", map[string]any{
			"query": "report", "scope": map[string]any{"effect": "read"},
		})
		if status != http.StatusOK {
			t.Fatalf("status %d: %v", status, out)
		}
		if got := len(list(t, out["actions"])); got != 1 {
			t.Fatalf("actions = %d, want report.read", got)
		}
		// The effect filter excludes the write action.
		status, out = e.post(t, "/api/v1/agent/find_actions", map[string]any{
			"query": "scan", "scope": map[string]any{"effect": "read"},
		})
		if status != http.StatusOK {
			t.Fatalf("status %d: %v", status, out)
		}
		if got := len(list(t, out["actions"])); got != 0 {
			t.Fatalf("actions = %v, want none", out["actions"])
		}
		status, out = e.post(t, "/api/v1/agent/find_actions", map[string]any{
			"query": "report", "scope": map[string]any{"plugin_id": "com.other.plugin"},
		})
		if status != http.StatusOK {
			t.Fatalf("status %d: %v", status, out)
		}
		if got := len(list(t, out["actions"])); got != 0 {
			t.Fatalf("actions = %v, want none", out["actions"])
		}
	})

	t.Run("another node has no actions", func(t *testing.T) {
		status, out := e.post(t, "/api/v1/agent/find_actions", map[string]any{
			"query": "scan", "scope": map[string]any{"node_id": "node-2"},
		})
		if status != http.StatusOK {
			t.Fatalf("status %d: %v", status, out)
		}
		actions, ok := out["actions"].([]any)
		if !ok || len(actions) != 0 {
			t.Fatalf("actions = %v, want []", out["actions"])
		}
		if out["truncated"] != false {
			t.Fatalf("truncated = %v", out["truncated"])
		}
	})

	t.Run("human-only actions are never offered", func(t *testing.T) {
		status, out := e.post(t, "/api/v1/agent/find_actions", map[string]any{"query": "users"})
		if status != http.StatusOK {
			t.Fatalf("status %d: %v", status, out)
		}
		for _, raw := range list(t, out["actions"]) {
			id := str(t, obj(t, raw)["id"])
			if strings.HasPrefix(id, "host.users.") {
				t.Fatalf("delegation was offered %s", id)
			}
		}
	})

	t.Run("viewer only sees read actions", func(t *testing.T) {
		status, out := e.postAs(t, e.viewerToken, "/api/v1/agent/find_actions",
			map[string]any{"query": "report"}, nil)
		if status != http.StatusOK {
			t.Fatalf("status %d: %v", status, out)
		}
		if got := len(list(t, out["actions"])); got != 1 {
			t.Fatalf("actions = %d, want report.read", got)
		}
		status, out = e.postAs(t, e.viewerToken, "/api/v1/agent/find_actions",
			map[string]any{"query": "scan"}, nil)
		if status != http.StatusOK {
			t.Fatalf("status %d: %v", status, out)
		}
		if got := len(list(t, out["actions"])); got != 0 {
			t.Fatalf("viewer was offered %v", out["actions"])
		}
	})

	t.Run("validation", func(t *testing.T) {
		data := e.expectProblem(t, e.adminToken, "/api/v1/agent/find_actions",
			map[string]any{"query": ""}, http.StatusBadRequest, string(problem.ValidationFailed))
		_, _, violations := problemOf(t, data)
		if len(violations) != 1 || obj(t, violations[0])["pointer"] != "/query" {
			t.Fatalf("violations = %v", violations)
		}
		e.expectProblem(t, e.adminToken, "/api/v1/agent/find_actions",
			map[string]any{"query": "x", "limit": 50}, http.StatusBadRequest, string(problem.ValidationFailed))
		e.expectProblem(t, e.adminToken, "/api/v1/agent/find_actions",
			map[string]any{"query": "x", "scope": map[string]any{"effect": "nope"}},
			http.StatusBadRequest, string(problem.ValidationFailed))
		e.expectProblem(t, e.adminToken, "/api/v1/agent/find_actions",
			map[string]any{"query": "x", "scope": map[string]any{"node_id": "Bad Node"}},
			http.StatusBadRequest, string(problem.ValidationFailed))
		data = e.expectProblem(t, e.adminToken, "/api/v1/agent/find_actions",
			map[string]any{"query": "x", "unknown": 1}, http.StatusBadRequest, string(problem.ValidationFailed))
		_, _, violations = problemOf(t, data)
		if len(violations) != 1 || obj(t, violations[0])["code"] != "UNKNOWN_FIELD" {
			t.Fatalf("violations = %v", violations)
		}
		e.expectProblem(t, e.adminToken, "/api/v1/agent/find_actions",
			map[string]any{}, http.StatusBadRequest, string(problem.ValidationFailed))
	})
}

func TestDescribeActionHidesForeignActions(t *testing.T) {
	e := newTestEnv(t)

	status, out := e.post(t, "/api/v1/agent/describe_action", map[string]any{"id": actionScan})
	if status != http.StatusOK {
		t.Fatalf("status %d: %v", status, out)
	}
	action := obj(t, out["action"])
	if action["id"] != actionScan || action["source"] != "plugin" || action["risk"] != "low" {
		t.Fatalf("action = %v", action)
	}
	if action["declared_risk"] != "low" || action["effect"] != "write" {
		t.Fatalf("action = %v", action)
	}
	target := obj(t, out["target"])
	if target["node_id"] != true || target["plugin_id"] != true || target["instance_id"] != true {
		t.Fatalf("target = %v", target)
	}
	if _, ok := out["args_schema"]; !ok {
		t.Fatal("args_schema is missing")
	}
	if _, ok := out["result_schema"]; ok {
		t.Fatal("result_schema was returned without include_result_schema")
	}
	if _, ok := out["docs"]; ok {
		t.Fatal("docs were returned without include_docs")
	}

	status, out = e.post(t, "/api/v1/agent/describe_action", map[string]any{
		"id": actionScan, "include_result_schema": true, "include_docs": true,
	})
	if status != http.StatusOK {
		t.Fatalf("status %d: %v", status, out)
	}
	if _, ok := out["result_schema"]; !ok {
		t.Fatal("result_schema is missing")
	}
	mustContain(t, str(t, out["docs"]), "Bundled documentation")

	// An action outside the effective permission is indistinguishable from an
	// unknown one: same status, code and detail (the request ID differs, as on
	// every response).
	hidden := e.expectProblem(t, e.adminToken, "/api/v1/agent/describe_action",
		map[string]any{"id": "host.users.create"}, http.StatusNotFound, string(problem.NotFound))
	unknown := e.expectProblem(t, e.adminToken, "/api/v1/agent/describe_action",
		map[string]any{"id": "host.nope.nope"}, http.StatusNotFound, string(problem.NotFound))
	if detailOf(t, hidden) != detailOf(t, unknown) {
		t.Fatalf("hidden action answered %s, unknown %s", hidden, unknown)
	}

	status, _ = e.postAs(t, e.viewerToken, "/api/v1/agent/describe_action",
		map[string]any{"id": actionScan}, nil)
	if status != http.StatusNotFound {
		t.Fatalf("viewer describe write action: status %d, want 404", status)
	}
	status, out = e.postAs(t, e.viewerToken, "/api/v1/agent/describe_action",
		map[string]any{"id": actionReport}, nil)
	if status != http.StatusOK {
		t.Fatalf("viewer describe read action: status %d, %v", status, out)
	}

	data := e.expectProblem(t, e.adminToken, "/api/v1/agent/describe_action",
		map[string]any{"id": "Not An Action"}, http.StatusBadRequest, string(problem.ValidationFailed))
	_, _, violations := problemOf(t, data)
	if len(violations) != 1 || obj(t, violations[0])["pointer"] != "/id" {
		t.Fatalf("violations = %v", violations)
	}
}

func TestExpiredDelegationIsDenied(t *testing.T) {
	e := newTestEnv(t)

	// The delegation of the env lives 24 hours.
	e.advance(25 * time.Hour)

	status, data := e.do(t, e.adminToken, "/api/v1/agent/find_actions", map[string]any{"query": "scan"}, nil)
	if status != http.StatusForbidden {
		t.Fatalf("status %d, want 403 (%s)", status, data)
	}
	if code, _, _ := problemOf(t, data); code != string(problem.PermissionDenied) {
		t.Fatalf("code %s", code)
	}

	// The handler checks the delegation itself as well, so a route wired with a
	// weaker access policy still cannot use an expired token.
	_, err := e.h.delegationView(context.Background(), aiActor(e.adminDelegation, e.adminUser.ID))
	p, ok := asProblem(err)
	if !ok || p.Code != problem.PermissionDenied || !strings.Contains(p.Detail, "expired") {
		t.Fatalf("delegationView = %s", errString(err))
	}
}

func TestDelegationViewRejectsForeignOwner(t *testing.T) {
	e := newTestEnv(t)
	_, err := e.h.delegationView(context.Background(),
		aiActor(e.adminDelegation, e.viewerUser.ID))
	if p, ok := asProblem(err); !ok || p.Code != problem.PermissionDenied {
		t.Fatalf("delegationView = %s", errString(err))
	}
}

func TestDescribeActionSchemaIsJSON(t *testing.T) {
	// The response must be valid JSON with an object args_schema (the status is
	// covered above; this guards against accidentally returning a string).
	e := newTestEnv(t)
	status, data := e.do(t, e.adminToken, "/api/v1/agent/describe_action",
		map[string]any{"id": actionBaseline}, nil)
	if status != http.StatusOK {
		t.Fatalf("status %d: %s", status, data)
	}
	var out map[string]json.RawMessage
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	var schema map[string]any
	if err := json.Unmarshal(out["args_schema"], &schema); err != nil {
		t.Fatalf("args_schema is not an object: %v", err)
	}
	if schema["type"] != "object" {
		t.Fatalf("args_schema = %v", schema)
	}
}

func TestBodyLimits(t *testing.T) {
	e := newTestEnv(t)

	// The read route uses the 1 MiB default of x-qwq-limits.
	over := []byte(`{"subject":"users","pad":"` + strings.Repeat("x", 1<<20) + `"}`)
	status, data := e.doRaw(t, e.adminToken, "/api/v1/agent/read", over, nil)
	if status != http.StatusRequestEntityTooLarge {
		t.Fatalf("read over the limit: status %d, want 413 (%s)", status, data)
	}
	if code, _, _ := problemOf(t, data); code != string(problem.PayloadTooLarge) {
		t.Fatalf("read over the limit: code %s", code)
	}

	// plan overrides it to 4 MiB (x-qwq-limits on the operation): a body the
	// read route rejects reaches the handler and fails on the action instead.
	big := []byte(`{"action":"host.nope.nope","args":{"pad":"` + strings.Repeat("y", 2<<20) + `"}}`)
	status, data = e.doRaw(t, e.adminToken, "/api/v1/agent/plan", big, nil)
	if status != http.StatusNotFound {
		t.Fatalf("plan with a 2 MiB body: status %d, want 404 (%s)", status, data)
	}
}
