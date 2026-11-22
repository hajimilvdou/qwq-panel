// SPDX-License-Identifier: AGPL-3.0-only

package api_test

import (
	"net/http"
	"testing"

	"github.com/qwq-panel/qwq/internal/platform/problem"
)

// TestDelegations covers the catalog-exempt management routes: they call authz
// directly inside a write transaction and atomically persist an audit row and
// the token-free idempotent response.
func TestDelegations(t *testing.T) {
	e := newEnv(t)
	a := e.setupAdmin(adminUser)

	e.do(newRequest(http.MethodGet, "/api/v1/delegations", "")).
		expectProblem(t, http.StatusUnauthorized, problem.Unauthenticated)

	// Create: the token is returned once.
	body := `{"label":"claude desktop"}`
	create := a.sign(http.MethodPost, "/api/v1/delegations", body)
	create.Header.Set("Idempotency-Key", idempotencyKey(1))
	created := e.do(create).expect(t, http.StatusCreated)
	var delegation map[string]any
	created.decode(t, &delegation)
	token := mustString(t, delegation, "token")
	if len(token) < 10 || token[:8] != "qwq_dlg_" {
		t.Fatalf("token = %q", token)
	}
	if mustString(t, delegation, "status") != "active" {
		t.Fatalf("status = %v", delegation["status"])
	}
	id := mustString(t, delegation, "delegation_id")
	revision := mustString(t, delegation, "revision")
	policy, _ := delegation["policy"].(map[string]any)
	if mustString(t, policy, "auto_approve_max_risk") != "low" {
		t.Fatalf("default policy = %v", policy)
	}

	// Replaying the same key returns the delegation without the token.
	replay := a.sign(http.MethodPost, "/api/v1/delegations", body)
	replay.Header.Set("Idempotency-Key", idempotencyKey(1))
	replayed := e.do(replay).expect(t, http.StatusCreated)
	if replayed.header.Get("Idempotency-Replayed") != "true" {
		t.Fatal("replay did not set Idempotency-Replayed")
	}
	var replayBody map[string]any
	replayed.decode(t, &replayBody)
	if _, ok := replayBody["token"]; ok {
		t.Fatalf("replay leaked the token: %s", replayed.body)
	}
	if mustString(t, replayBody, "delegation_id") != id {
		t.Fatal("replay returned another delegation")
	}

	// The same key with another body is refused.
	other := a.sign(http.MethodPost, "/api/v1/delegations", `{"label":"other"}`)
	other.Header.Set("Idempotency-Key", idempotencyKey(1))
	e.do(other).expectProblem(t, http.StatusUnprocessableEntity, problem.IdempotencyKeyReused)

	// List and get never return the token.
	list := e.do(a.sign(http.MethodGet, "/api/v1/delegations", "")).expect(t, http.StatusOK)
	var page struct {
		Items []map[string]any `json:"items"`
	}
	list.decode(t, &page)
	if len(page.Items) != 1 || mustString(t, page.Items[0], "delegation_id") != id {
		t.Fatalf("delegations = %v", page.Items)
	}
	if _, ok := page.Items[0]["token"]; ok {
		t.Fatal("list leaked the token")
	}
	single := e.do(a.sign(http.MethodGet, "/api/v1/delegations/"+id, "")).expect(t, http.StatusOK)
	var got map[string]any
	single.decode(t, &got)
	if _, ok := got["token"]; ok {
		t.Fatal("get leaked the token")
	}
	e.do(a.sign(http.MethodGet, "/api/v1/delegations/dlg_does_not_exist", "")).
		expectProblem(t, http.StatusNotFound, problem.NotFound)

	// Suspend with the current revision.
	patch := a.sign(http.MethodPatch, "/api/v1/delegations/"+id,
		`{"expected_revision":"`+revision+`","status":"suspended"}`)
	patch.Header.Set("Idempotency-Key", idempotencyKey(2))
	var suspended map[string]any
	e.do(patch).expect(t, http.StatusOK).decode(t, &suspended)
	if mustString(t, suspended, "status") != "suspended" {
		t.Fatalf("suspended = %v", suspended["status"])
	}
	newRevision := mustString(t, suspended, "revision")

	// A stale revision is a conflict, not a silent overwrite.
	stale := a.sign(http.MethodPatch, "/api/v1/delegations/"+id,
		`{"expected_revision":"999999","status":"active"}`)
	stale.Header.Set("Idempotency-Key", idempotencyKey(3))
	conflict := e.do(stale).expectProblem(t, http.StatusConflict, problem.RevisionConflict)
	if conflict.CurrentRevision != newRevision {
		t.Fatalf("current_revision = %q, want %q", conflict.CurrentRevision, newRevision)
	}

	// Revoke: a stale expected_revision is refused, the current one deletes.
	staleDelete := a.sign(http.MethodDelete, "/api/v1/delegations/"+id+"?expected_revision=999999", "")
	staleDelete.Header.Set("Idempotency-Key", idempotencyKey(4))
	e.do(staleDelete).expectProblem(t, http.StatusConflict, problem.RevisionConflict)
	del := a.sign(http.MethodDelete, "/api/v1/delegations/"+id+"?expected_revision="+newRevision, "")
	del.Header.Set("Idempotency-Key", idempotencyKey(5))
	e.do(del).expect(t, http.StatusNoContent)
	e.do(a.sign(http.MethodGet, "/api/v1/delegations/"+id, "")).
		expectProblem(t, http.StatusNotFound, problem.NotFound)

	// A service account may not manage delegations (human session only).
	token = e.serviceToken(a)
	e.do(bearer(http.MethodPost, "/api/v1/delegations", `{"label":"machine"}`, token)).
		expectProblem(t, http.StatusForbidden, problem.PermissionDenied)
}
