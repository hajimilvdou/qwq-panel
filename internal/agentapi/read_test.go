// SPDX-License-Identifier: AGPL-3.0-only

package agentapi

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/qwq-panel/qwq/internal/identity"
	"github.com/qwq-panel/qwq/internal/platform/problem"
)

func TestReadUserProjectionAndMissing(t *testing.T) {
	e := newTestEnv(t)

	status, out := e.post(t, "/api/v1/agent/read", map[string]any{
		"subject": "users/" + e.adminUser.ID,
		"fields":  []string{"/username", "/role", "/not_there"},
	})
	if status != http.StatusOK {
		t.Fatalf("status %d: %v", status, out)
	}
	if out["subject"] != "users/"+e.adminUser.ID {
		t.Fatalf("subject = %v", out["subject"])
	}
	rev := str(t, out["revision"])
	if rev == "" {
		t.Fatal("revision is empty")
	}
	values := obj(t, out["values"])
	if values["/username"] != "alice" || values["/role"] != "admin" {
		t.Fatalf("values = %v", values)
	}
	missing := list(t, out["missing"])
	if len(missing) != 1 || missing[0] != "/not_there" {
		t.Fatalf("missing = %v", missing)
	}
	if _, ok := values[""]; ok {
		t.Fatal("the whole document was returned for a projection")
	}

	// Without fields the whole resource comes back under "".
	status, out = e.post(t, "/api/v1/agent/read", map[string]any{"subject": "users/" + e.adminUser.ID})
	if status != http.StatusOK {
		t.Fatalf("status %d: %v", status, out)
	}
	whole := obj(t, obj(t, out["values"])[""])
	if whole["user_id"] != e.adminUser.ID || whole["username"] != "alice" {
		t.Fatalf("whole = %v", whole)
	}
	if whole["mfa_enabled"] != false || whole["disabled"] != false {
		t.Fatalf("whole = %v", whole)
	}
	if _, ok := whole["created_at"].(string); !ok {
		t.Fatalf("created_at = %v", whole["created_at"])
	}
}

func TestReadUsersPagination(t *testing.T) {
	e := newTestEnv(t)
	for i := 0; i < 24; i++ {
		e.createUser(fmt.Sprintf("user%02d", i), identity.RoleViewer)
	}
	total := 26 // alice, vera and the 24 seeded users

	seen := map[string]bool{}
	cursor := ""
	pages := 0
	for {
		body := map[string]any{"subject": "users", "limit": 10}
		if cursor != "" {
			body["cursor"] = cursor
		}
		status, out := e.post(t, "/api/v1/agent/read", body)
		if status != http.StatusOK {
			t.Fatalf("status %d: %v", status, out)
		}
		if out["subject"] != "users" {
			t.Fatalf("subject = %v", out["subject"])
		}
		items := list(t, out["items"])
		if len(items) == 0 {
			t.Fatal("a page has no items before the last page")
		}
		if len(items) > 10 {
			t.Fatalf("page has %d items, want at most 10", len(items))
		}
		for _, raw := range items {
			id := str(t, obj(t, raw)["user_id"])
			if seen[id] {
				t.Fatalf("user %s was returned twice", id)
			}
			seen[id] = true
		}
		next, _ := out["next_cursor"].(string)
		pages++
		if next == "" {
			if len(items) > 10 {
				t.Fatalf("last page has %d items", len(items))
			}
			break
		}
		cursor = next
		if pages > total {
			t.Fatal("pagination does not terminate")
		}
	}
	if len(seen) != total {
		t.Fatalf("saw %d users, want %d", len(seen), total)
	}
	if pages != 3 {
		t.Fatalf("pages = %d, want 3", pages)
	}

	// A collection answer carries items even when it is empty.
	e2 := newTestEnv(t)
	status, out := e2.post(t, "/api/v1/agent/read", map[string]any{"subject": "approvals"})
	if status != http.StatusOK {
		t.Fatalf("status %d: %v", status, out)
	}
	items, ok := out["items"].([]any)
	if !ok {
		t.Fatalf("items = %v, want []", out["items"])
	}
	if len(items) != 0 {
		t.Fatalf("items = %v, want []", items)
	}
}

func TestReadCollectionProjection(t *testing.T) {
	e := newTestEnv(t)
	status, out := e.post(t, "/api/v1/agent/read", map[string]any{
		"subject": "users", "limit": 1, "fields": []string{"/username"},
	})
	if status != http.StatusOK {
		t.Fatalf("status %d: %v", status, out)
	}
	item := obj(t, list(t, out["items"])[0])
	if _, ok := item["username"]; !ok {
		t.Fatalf("item = %v, username missing", item)
	}
	// identifier members are always kept so a client can merge the summary.
	if _, ok := item["user_id"]; !ok {
		t.Fatalf("item = %v, user_id missing", item)
	}
	if _, ok := item["role"]; ok {
		t.Fatalf("item = %v, role should be projected out", item)
	}
}

func TestReadUnchanged(t *testing.T) {
	e := newTestEnv(t)
	op := e.executedOperation(t)

	status, out := e.post(t, "/api/v1/agent/read", map[string]any{"subject": "operations/" + op})
	if status != http.StatusOK {
		t.Fatalf("status %d: %v", status, out)
	}
	rev := str(t, out["revision"])
	status, out = e.post(t, "/api/v1/agent/read", map[string]any{
		"subject": "operations/" + op, "since_revision": rev,
	})
	if status != http.StatusOK {
		t.Fatalf("status %d: %v", status, out)
	}
	if out["unchanged"] != true {
		t.Fatalf("unchanged = %v", out["unchanged"])
	}
	if _, ok := out["values"]; ok {
		t.Fatalf("values returned for an unchanged resource: %v", out)
	}
	if out["revision"] != rev {
		t.Fatalf("revision = %v, want %s", out["revision"], rev)
	}
}

func TestReadOperationsPlansAndApprovals(t *testing.T) {
	e := newTestEnv(t)
	op := e.executedOperation(t)

	status, out := e.post(t, "/api/v1/agent/read", map[string]any{"subject": "operations/" + op})
	if status != http.StatusOK {
		t.Fatalf("status %d: %v", status, out)
	}
	doc := obj(t, obj(t, out["values"])[""])
	if doc["operation_id"] != op || doc["status"] != "SUCCEEDED" {
		t.Fatalf("operation = %v", doc)
	}
	if doc["action"] != actionScan {
		t.Fatalf("action = %v", doc["action"])
	}

	// A plan created by this delegation is readable; another delegation's plan
	// is not (the service answers NOT_FOUND).
	status, plan := e.post(t, "/api/v1/agent/plan", map[string]any{
		"action": actionScan, "args": map[string]any{"scope": "cpu"}, "target": nodeTarget(),
	})
	if status != http.StatusOK {
		t.Fatalf("plan: status %d: %v", status, plan)
	}
	planID := str(t, plan["plan_id"])
	status, out = e.post(t, "/api/v1/agent/read", map[string]any{"subject": "plans/" + planID})
	if status != http.StatusOK {
		t.Fatalf("read plan: status %d: %v", status, out)
	}
	if got := obj(t, obj(t, out["values"])[""])["plan_id"]; got != planID {
		t.Fatalf("plan_id = %v", got)
	}
	status, _ = e.postAs(t, e.viewerToken, "/api/v1/agent/read",
		map[string]any{"subject": "plans/" + planID}, nil)
	if status != http.StatusNotFound {
		t.Fatalf("foreign plan: status %d, want 404", status)
	}

	// A high-risk execution queues an approval; it is visible to the AI that
	// requested it and to the approvals collection.
	_, approvalID := e.pendingApproval(t)
	status, out = e.post(t, "/api/v1/agent/read", map[string]any{"subject": "approvals/" + approvalID})
	if status != http.StatusOK {
		t.Fatalf("read approval: status %d: %v", status, out)
	}
	approval := obj(t, obj(t, out["values"])[""])
	if approval["approval_id"] != approvalID || approval["status"] != "PENDING" {
		t.Fatalf("approval = %v", approval)
	}
	status, out = e.post(t, "/api/v1/agent/read", map[string]any{"subject": "approvals"})
	if status != http.StatusOK {
		t.Fatalf("read approvals: status %d: %v", status, out)
	}
	found := false
	for _, raw := range list(t, out["items"]) {
		if obj(t, raw)["approval_id"] == approvalID {
			found = true
		}
	}
	if !found {
		t.Fatalf("approvals collection does not contain %s: %v", approvalID, out["items"])
	}
}

func TestReadDelegationRecord(t *testing.T) {
	e := newTestEnv(t)

	status, out := e.post(t, "/api/v1/agent/read",
		map[string]any{"subject": "delegations/" + e.adminDelegation})
	if status != http.StatusOK {
		t.Fatalf("status %d: %v", status, out)
	}
	doc := obj(t, obj(t, out["values"])[""])
	if doc["delegation_id"] != e.adminDelegation || doc["owner_id"] != e.adminUser.ID {
		t.Fatalf("delegation = %v", doc)
	}
	if doc["status"] != "active" {
		t.Fatalf("status = %v", doc["status"])
	}
	policy := obj(t, doc["policy"])
	if policy["auto_approve_max_risk"] != "low" {
		t.Fatalf("policy = %v", policy)
	}

	// A viewer-owned delegation may read its own record but not the admin's.
	status, _ = e.postAs(t, e.viewerToken, "/api/v1/agent/read",
		map[string]any{"subject": "delegations/" + e.viewerDelegation}, nil)
	if status != http.StatusOK {
		t.Fatalf("viewer own delegation: status %d, want 200", status)
	}
	status, _ = e.postAs(t, e.viewerToken, "/api/v1/agent/read",
		map[string]any{"subject": "delegations/" + e.adminDelegation}, nil)
	if status != http.StatusNotFound {
		t.Fatalf("viewer foreign delegation: status %d, want 404", status)
	}
}

func TestReadByteCap(t *testing.T) {
	e := newTestEnv(t)
	// The dispatcher returns a result far larger than one read response.
	big := `{"blob":"` + strings.Repeat("x", 40000) + `"}`
	e.dispatcher.mu.Lock()
	e.dispatcher.result = []byte(big)
	e.dispatcher.mu.Unlock()

	out := e.execute(t, map[string]any{
		"action": actionScan, "args": map[string]any{"scope": "cpu"}, "target": nodeTarget(),
	})
	opID := str(t, out["operation_id"])
	if out["status"] != "SUCCEEDED" {
		t.Fatalf("status = %v", out["status"])
	}

	status, data := e.do(t, e.adminToken, "/api/v1/agent/read",
		map[string]any{"subject": "operations/" + opID}, nil)
	if status != http.StatusOK {
		t.Fatalf("status %d: %s", status, data)
	}
	if len(data) > ReadResponseBytes {
		t.Fatalf("response is %d bytes, cap is %d", len(data), ReadResponseBytes)
	}
	var resp map[string]any
	if err := json.Unmarshal(data, &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	truncated, ok := resp["truncated"].(map[string]any)
	if !ok {
		t.Fatalf("truncated is missing: %s", data)
	}
	if truncated["reason"] != "max_bytes" {
		t.Fatalf("reason = %v", truncated["reason"])
	}
	if hint, _ := truncated["hint"].(string); hint == "" {
		t.Fatal("truncated.hint is empty")
	}

	// A narrow projection fits without truncation.
	status, out = e.post(t, "/api/v1/agent/read", map[string]any{
		"subject": "operations/" + opID, "fields": []string{"/status", "/action"},
	})
	if status != http.StatusOK {
		t.Fatalf("status %d: %v", status, out)
	}
	if _, ok := out["truncated"]; ok {
		t.Fatalf("a narrow projection was truncated: %v", out["truncated"])
	}
	values := obj(t, out["values"])
	if values["/status"] != "SUCCEEDED" || values["/action"] != actionScan {
		t.Fatalf("values = %v", values)
	}
}

func TestReadRejectsUnknownSubjects(t *testing.T) {
	e := newTestEnv(t)
	for _, subject := range []string{
		"plugins/com.example.demo",
		"nodes/" + testNode,
		"operations/op_missing",
		"users/usr_missing",
		"approvals/apv_missing",
		"plans",
		"delegations",
		"nodes/local/plugins/com.example.demo/instances/default/resources/alerts/cpu",
	} {
		status, data := e.do(t, e.adminToken, "/api/v1/agent/read",
			map[string]any{"subject": subject}, nil)
		if status != http.StatusNotFound {
			t.Fatalf("%s: status %d, want 404 (%s)", subject, status, data)
		}
		if code, _, _ := problemOf(t, data); code != string(problem.NotFound) {
			t.Fatalf("%s: code %s", subject, code)
		}
	}

	// viewer 委派不继承敏感 users 读取权限；拒绝详情不泄漏目标是否存在。
	status, out := e.postAs(t, e.viewerToken, "/api/v1/agent/read",
		map[string]any{"subject": "users/" + e.viewerUser.ID}, nil)
	if status != http.StatusNotFound || out["code"] != string(problem.NotFound) {
		t.Fatalf("viewer user: status %d: %v", status, out)
	}
	if _, exposed := out["values"]; exposed {
		t.Fatal("viewer delegation received a sensitive user projection")
	}

	// Request validation.
	data := e.expectProblem(t, e.adminToken, "/api/v1/agent/read",
		map[string]any{"subject": "Users/alice"}, http.StatusBadRequest, string(problem.ValidationFailed))
	_, _, violations := problemOf(t, data)
	if len(violations) != 1 || obj(t, violations[0])["pointer"] != "/subject" {
		t.Fatalf("violations = %v", violations)
	}
	e.expectProblem(t, e.adminToken, "/api/v1/agent/read",
		map[string]any{"subject": "users", "fields": []string{"/a/0"}},
		http.StatusBadRequest, string(problem.ValidationFailed))
	e.expectProblem(t, e.adminToken, "/api/v1/agent/read",
		map[string]any{"subject": "users", "fields": []string{"username"}},
		http.StatusBadRequest, string(problem.ValidationFailed))
	e.expectProblem(t, e.adminToken, "/api/v1/agent/read",
		map[string]any{"subject": "users", "limit": 1000},
		http.StatusBadRequest, string(problem.ValidationFailed))
	e.expectProblem(t, e.adminToken, "/api/v1/agent/read",
		map[string]any{"subject": "users", "cursor": "not-a-cursor!"},
		http.StatusBadRequest, string(problem.ValidationFailed))
	e.expectProblem(t, e.adminToken, "/api/v1/agent/read",
		map[string]any{"subject": "users", "since_revision": "bad revision"},
		http.StatusBadRequest, string(problem.ValidationFailed))
}

func TestReadFieldsCap(t *testing.T) {
	e := newTestEnv(t)
	fields := make([]string, 0, 40)
	for i := 0; i < 40; i++ {
		fields = append(fields, fmt.Sprintf("/f%d", i))
	}
	e.expectProblem(t, e.adminToken, "/api/v1/agent/read",
		map[string]any{"subject": "users", "fields": fields},
		http.StatusBadRequest, string(problem.ValidationFailed))
}
