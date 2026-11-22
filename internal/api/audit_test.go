// SPDX-License-Identifier: AGPL-3.0-only

package api_test

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/qwq-panel/qwq/internal/actor"
	"github.com/qwq-panel/qwq/internal/identity"
	"github.com/qwq-panel/qwq/internal/operations"
	"github.com/qwq-panel/qwq/internal/platform/problem"
	"github.com/qwq-panel/qwq/internal/storage"
)

// auditPage is the AuditPage schema of GET /api/v1/audit.
type auditPage struct {
	Items []struct {
		AuditID     string         `json:"audit_id"`
		At          string         `json:"at"`
		Action      string         `json:"action"`
		Subject     string         `json:"subject"`
		Outcome     string         `json:"outcome"`
		OperationID string         `json:"operation_id"`
		NodeID      string         `json:"node_id"`
		RequestID   string         `json:"request_id"`
		Actor       actor.Actor    `json:"actor"`
		Detail      map[string]any `json:"detail"`
	} `json:"items"`
	Meta struct {
		NextCursor string `json:"next_cursor"`
	} `json:"meta"`
}

// writeAuditRow appends one audit row directly, as the host does inside an
// operation or authentication transaction.
func (e *env) writeAuditRow(t *testing.T, rec operations.AuditRecord) {
	t.Helper()
	if err := e.c.DB().Update(t.Context(), func(tx *storage.Tx) error {
		return operations.Audit(t.Context(), tx, rec)
	}); err != nil {
		t.Fatalf("write audit row: %v", err)
	}
}

// TestAuditQuery covers the filters, the newest-first paging and the detail
// redaction whitelist (GAPS gap 7). Setup writes audit rows of its own, so the
// fixture uses action names and an actor ID nothing else writes, and time windows
// that exclude the setup rows.
func TestAuditQuery(t *testing.T) {
	e := newEnv(t)
	a := e.setupAdmin(adminUser)
	now := time.Now().UTC().Truncate(time.Millisecond)
	person := actor.Actor{Kind: actor.Human, ID: "usr_fixture"}
	e.writeAuditRow(t, operations.AuditRecord{
		Actor: person, Action: "test.audit.login", Subject: "users/" + a.userID,
		Outcome: operations.AuditSuccess, At: now.Add(-4 * time.Hour),
	})
	e.writeAuditRow(t, operations.AuditRecord{
		Actor: person, Action: "test.audit.create", Subject: "users/u_bob",
		Outcome: operations.AuditFailure, OperationID: "op_bob", NodeID: "local", RequestID: "req_bob",
		At: now.Add(-3 * time.Hour),
		Details: json.RawMessage(`{"username":"bob","event":"created","attempt":1,
			"password":"hunter2","token":"tok_live","api_key":"sk_live","secret_ref":"sec_1",
			"nested":{"password":"hunter2"}}`),
	})
	e.writeAuditRow(t, operations.AuditRecord{
		Actor: actor.SystemActor("identity"), Action: "test.audit.login",
		Outcome: operations.AuditDenied, At: now.Add(-2 * time.Hour),
	})
	// Two rows of one transaction share occurred_at: paging must not skip or
	// repeat them, which is why the cursor carries the audit ID too.
	for i := 0; i < 2; i++ {
		e.writeAuditRow(t, operations.AuditRecord{
			Actor: person, Action: "test.audit.tie", Outcome: operations.AuditSuccess,
			At: now.Add(-5 * time.Hour),
		})
	}

	get := func(query string) auditPage {
		t.Helper()
		var page auditPage
		e.do(a.sign(http.MethodGet, "/api/v1/audit"+query, "")).expect(t, http.StatusOK).decode(t, &page)
		return page
	}
	all := get("?from=" + now.Add(-6*time.Hour).Format(time.RFC3339) + "&to=" + now.Add(-time.Hour).Format(time.RFC3339))
	if len(all.Items) != 5 {
		t.Fatalf("items = %d, want 5", len(all.Items))
	}
	// Newest first, and the members of one entry are mapped.
	if all.Items[0].Outcome != operations.AuditDenied || all.Items[1].Action != "test.audit.create" ||
		all.Items[2].Action != "test.audit.login" {
		t.Fatalf("order = %+v", all.Items)
	}
	middle := all.Items[1]
	if middle.OperationID != "op_bob" || middle.NodeID != "local" || middle.RequestID != "req_bob" ||
		middle.Subject != "users/u_bob" || middle.Actor.ID != "usr_fixture" || middle.AuditID == "" || middle.At == "" {
		t.Fatalf("entry = %+v", middle)
	}
	// The whitelist keeps the non-secret facts and drops everything else.
	if len(middle.Detail) != 3 || middle.Detail["username"] != "bob" ||
		middle.Detail["event"] != "created" || middle.Detail["attempt"] != float64(1) {
		t.Fatalf("detail = %v, want only username/event/attempt", middle.Detail)
	}
	raw, err := json.Marshal(middle.Detail)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"hunter2", "tok_live", "sk_live", "sec_1", "nested", "password"} {
		if strings.Contains(string(raw), forbidden) {
			t.Fatalf("detail leaked %q: %s", forbidden, raw)
		}
	}

	for _, tc := range []struct {
		query string
		want  int
	}{
		{"?action=test.audit.login", 2},
		{"?action=test.audit.create", 1},
		{"?outcome=denied", 1},
		{"?subject=users/u_bob", 1},
		{"?operation_id=op_bob", 1},
		{"?actor=usr_fixture", 4},
		{"?from=" + now.Add(-5*time.Hour).Format(time.RFC3339) + "&to=" + now.Add(-150*time.Minute).Format(time.RFC3339), 4},
		{"?to=" + now.Add(-210*time.Minute).Format(time.RFC3339), 3},
		{"?action=test.audit.login&outcome=success", 1},
		{"?action=does.not.exist", 0},
	} {
		if page := get(tc.query); len(page.Items) != tc.want {
			t.Errorf("GET /audit%s = %d items, want %d", tc.query, len(page.Items), tc.want)
		}
	}

	// Paging: one row per page, the cursor walks newest to oldest without repeats.
	first := get("?action=test.audit.login&limit=1")
	if len(first.Items) != 1 || first.Meta.NextCursor == "" {
		t.Fatalf("first page = %+v", first)
	}
	second := get("?action=test.audit.login&limit=1&cursor=" + first.Meta.NextCursor)
	if len(second.Items) != 1 || second.Items[0].AuditID == first.Items[0].AuditID || second.Meta.NextCursor != "" {
		t.Fatalf("second page = %+v", second)
	}
	if second.Items[0].AuditID != all.Items[2].AuditID {
		t.Fatalf("paging skipped a row: %s", second.Items[0].AuditID)
	}
	// Rows with the same timestamp paginate one at a time.
	tieFirst := get("?action=test.audit.tie&limit=1")
	tieSecond := get("?action=test.audit.tie&limit=1&cursor=" + tieFirst.Meta.NextCursor)
	if len(tieFirst.Items) != 1 || len(tieSecond.Items) != 1 ||
		tieFirst.Items[0].AuditID == tieSecond.Items[0].AuditID || tieSecond.Meta.NextCursor != "" {
		t.Fatalf("tied rows paged badly: %+v / %+v", tieFirst, tieSecond)
	}
}

// TestAuditAccess: the audit log is administrator-only and human-only.
func TestAuditAccess(t *testing.T) {
	e := newEnv(t)
	a := e.setupAdmin(adminUser)
	for _, role := range []identity.Role{identity.RoleOperator, identity.RoleViewer} {
		other := e.signIn("audit-"+string(role), role)
		e.do(other.sign(http.MethodGet, "/api/v1/audit", "")).expectProblem(t, http.StatusForbidden, problem.PermissionDenied)
	}
	e.do(newRequest(http.MethodGet, "/api/v1/audit", "")).expectProblem(t, http.StatusUnauthorized, problem.Unauthenticated)
	p := &pluginTestEnv{env: e}
	token := p.serviceTokenWithRole(t, a, "admin")
	e.do(bearer(http.MethodGet, "/api/v1/audit", "", token)).expectProblem(t, http.StatusForbidden, problem.PermissionDenied)
}

// TestAuditValidation: malformed filters are 400, not an empty page.
func TestAuditValidation(t *testing.T) {
	e := newEnv(t)
	a := e.setupAdmin(adminUser)
	for _, query := range []string{
		"?outcome=bogus", "?from=yesterday", "?to=2026-13-01T00:00:00Z",
		"?limit=0", "?limit=201", "?limit=x", "?cursor=!!!",
	} {
		e.do(a.sign(http.MethodGet, "/api/v1/audit"+query, "")).expectProblem(t, http.StatusBadRequest, problem.ValidationFailed)
	}
}
