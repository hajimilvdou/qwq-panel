// SPDX-License-Identifier: AGPL-3.0-only

package api_test

import (
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/qwq-panel/qwq/internal/identity"
	"github.com/qwq-panel/qwq/internal/platform/problem"
)

// providerBody is the AiProviderCreateRequest body of the tests.
func providerBody(name, baseURL, model string, isDefault bool) string {
	return fmt.Sprintf(`{"name":%q,"base_url":%q,"model":%q,"is_default":%v}`, name, baseURL, model, isDefault)
}

// createProvider posts one provider. The action is risk low, so it finishes
// synchronously and the outcome carries the provider.
func (e *env) createProvider(a auth, name, baseURL, model string, isDefault bool, key int) string {
	e.t.Helper()
	req := a.sign(http.MethodPost, "/api/v1/ai/providers", providerBody(name, baseURL, model, isDefault))
	req.Header.Set("Idempotency-Key", idempotencyKey(key))
	var out struct {
		Status string `json:"status"`
		Result struct {
			ProviderID string `json:"provider_id"`
		} `json:"result"`
	}
	e.do(req).expect(e.t, http.StatusOK).decode(e.t, &out)
	if out.Status != "SUCCEEDED" || out.Result.ProviderID == "" {
		e.t.Fatalf("create outcome = %+v", out)
	}
	return out.Result.ProviderID
}

// patchProvider applies one synchronous provider patch.
func (e *env) patchProvider(a auth, id, body string, key int) {
	e.t.Helper()
	req := a.sign(http.MethodPatch, "/api/v1/ai/providers/"+id, body)
	req.Header.Set("Idempotency-Key", idempotencyKey(key))
	e.do(req).expect(e.t, http.StatusOK)
}

// providerByID reads one provider from the caller's list.
func (e *env) providerByID(a auth, id string) map[string]any {
	e.t.Helper()
	var page struct {
		Items []map[string]any `json:"items"`
	}
	e.do(a.sign(http.MethodGet, "/api/v1/ai/providers", "")).expect(e.t, http.StatusOK).decode(e.t, &page)
	for _, p := range page.Items {
		if p["provider_id"] == id {
			return p
		}
	}
	e.t.Fatalf("provider %q not in %v", id, page.Items)
	return nil
}

// TestAIProviderRoutes: create, list (two projections), update and delete walk
// the whole public surface of GAP-2, including the human-only rule.
func TestAIProviderRoutes(t *testing.T) {
	e := newEnv(t)
	a := e.setupAdmin(adminUser)
	v := e.signIn("vera", identity.RoleViewer)

	id := e.createProvider(a, "Primary", "https://api.example.com/v1", "gpt-test", true, 1)
	admin := e.providerByID(a, id)
	if admin["name"] != "Primary" || admin["kind"] != "openai_compatible" ||
		admin["base_url"] != "https://api.example.com/v1" || admin["has_api_key"] != false ||
		admin["is_default"] != true || admin["revision"] == "" || admin["created_at"] == "" {
		t.Fatalf("admin projection = %v", admin)
	}

	// A viewer lists the same provider, without the address or the timestamps.
	view := e.providerByID(v, id)
	for _, hidden := range []string{"base_url", "kind", "revision", "created_at", "updated_at"} {
		if _, ok := view[hidden]; ok {
			t.Fatalf("viewer projection leaks %s: %v", hidden, view)
		}
	}
	if view["name"] != "Primary" || view["model"] != "gpt-test" || view["is_default"] != true {
		t.Fatalf("viewer projection = %v", view)
	}

	// Managing providers is administrator-only and human-only.
	req := v.sign(http.MethodPost, "/api/v1/ai/providers", providerBody("x", "https://x.example.com", "m", false))
	req.Header.Set("Idempotency-Key", idempotencyKey(2))
	e.do(req).expectProblem(t, http.StatusForbidden, problem.PermissionDenied)
	e.do(v.sign(http.MethodPost, "/api/v1/plans",
		`{"action":"host.ai_providers.create","args":{"name":"x","base_url":"https://x.example.com","model":"m"}}`)).
		expectProblem(t, http.StatusForbidden, problem.PermissionDenied)

	// Validation before the operation is queued.
	bad := a.sign(http.MethodPost, "/api/v1/ai/providers", `{"name":"","base_url":"ftp://x","model":""}`)
	bad.Header.Set("Idempotency-Key", idempotencyKey(3))
	p := e.do(bad).expectProblem(t, http.StatusBadRequest, problem.ValidationFailed)
	if len(p.Violations) == 0 {
		t.Fatal("no violations for an empty provider")
	}

	// The idempotent replay answers the same outcome.
	replay := a.sign(http.MethodPost, "/api/v1/ai/providers", providerBody("Primary", "https://api.example.com/v1", "gpt-test", true))
	replay.Header.Set("Idempotency-Key", idempotencyKey(1))
	if got := e.do(replay).expect(t, http.StatusOK); got.header.Get("Idempotency-Replayed") != "true" {
		t.Fatalf("replay headers = %v", got.header)
	}

	// Update: a stale revision is refused, the current one changes the name.
	rev := mustString(t, admin, "revision")
	stale := a.sign(http.MethodPatch, "/api/v1/ai/providers/"+id,
		`{"expected_revision":"1","name":"Renamed"}`)
	stale.Header.Set("Idempotency-Key", idempotencyKey(4))
	e.do(stale).expectProblem(t, http.StatusConflict, problem.RevisionConflict)
	e.patchProvider(a, id, fmt.Sprintf(`{"expected_revision":%q,"name":"Renamed","model":"gpt-next"}`, rev), 5)
	admin = e.providerByID(a, id)
	if admin["name"] != "Renamed" || admin["model"] != "gpt-next" || admin["revision"] == rev {
		t.Fatalf("after update = %v", admin)
	}

	// Delete is destructive: its approval needs a second factor.
	secret := e.beginTOTP(a)
	e.confirmTOTP(a, totpAt(secret, 0)).expect(t, http.StatusOK)
	rev = mustString(t, admin, "revision")
	del := a.sign(http.MethodDelete, "/api/v1/ai/providers/"+id+"?expected_revision="+rev, "")
	del.Header.Set("Idempotency-Key", idempotencyKey(6))
	var accepted struct {
		ApprovalID string `json:"approval_id"`
	}
	e.do(del).expect(t, http.StatusAccepted).decode(t, &accepted)
	appRev := mustString(t, e.approval(a, accepted.ApprovalID), "revision")
	e.decide(a, accepted.ApprovalID, "approve", appRev, idempotencyKey(7)).expectProblem(t, http.StatusForbidden, problem.MFARequired)
	approve := a.sign(http.MethodPost, "/api/v1/approvals/"+accepted.ApprovalID+"/decision",
		fmt.Sprintf(`{"decision":"approve","expected_revision":%q,"mfa_code":%q}`, appRev, totpAt(secret, 1)))
	approve.Header.Set("Idempotency-Key", idempotencyKey(8))
	e.do(approve).expect(t, http.StatusOK)
	var page struct {
		Items []any `json:"items"`
	}
	e.do(a.sign(http.MethodGet, "/api/v1/ai/providers", "")).expect(t, http.StatusOK).decode(t, &page)
	if len(page.Items) != 0 {
		t.Fatalf("providers after delete = %v", page.Items)
	}
}

// TestAIProviderDeleteDefaultRefused: the default provider cannot be deleted
// while another one exists, and the refusal is immediate.
func TestAIProviderDeleteDefaultRefused(t *testing.T) {
	e := newEnv(t)
	a := e.setupAdmin(adminUser)

	first := e.createProvider(a, "First", "https://first.example.com/v1", "m", true, 1)
	second := e.createProvider(a, "Second", "https://second.example.com/v1", "m", false, 3)
	if first == second {
		t.Fatal("duplicate provider id")
	}
	rev := mustString(t, e.providerByID(a, first), "revision")
	req := a.sign(http.MethodDelete, "/api/v1/ai/providers/"+first+"?expected_revision="+rev, "")
	req.Header.Set("Idempotency-Key", idempotencyKey(5))
	e.do(req).expectProblem(t, http.StatusConflict, problem.StateConflict)

	// An unknown provider is a 404 before any approval is queued.
	req = a.sign(http.MethodDelete, "/api/v1/ai/providers/aip_missing?expected_revision="+rev, "")
	req.Header.Set("Idempotency-Key", idempotencyKey(6))
	e.do(req).expectProblem(t, http.StatusNotFound, problem.NotFound)
}

// TestAIProviderAPIKeyRoutes: the key is write-only through the catalog-exempt
// route, lands nowhere but the secret row, and its changes publish
// resource.changed.
func TestAIProviderAPIKeyRoutes(t *testing.T) {
	e := newEnv(t)
	a := e.setupAdmin(adminUser)
	v := e.signIn("vera", identity.RoleViewer)
	id := e.createProvider(a, "Keyed", "https://api.example.com/v1", "m", false, 1)

	const key = "sk-http-0123456789abcdef"
	path := "/api/v1/ai/providers/" + id + "/api-key"

	// Viewers cannot touch the key.
	put := v.sign(http.MethodPut, path, fmt.Sprintf(`{"api_key":%q}`, key))
	put.Header.Set("Idempotency-Key", idempotencyKey(2))
	e.do(put).expectProblem(t, http.StatusForbidden, problem.PermissionDenied)
	e.do(v.sign(http.MethodDelete, path, "")).expectProblem(t, http.StatusForbidden, problem.PermissionDenied)

	// The administrator stores it; the frontend's Idempotency-Key is ignored on
	// this exempt route, and the answer never contains the key.
	put = a.sign(http.MethodPut, path, fmt.Sprintf(`{"api_key":%q}`, key))
	put.Header.Set("Idempotency-Key", idempotencyKey(3))
	if got := e.do(put).expect(t, http.StatusNoContent); len(got.body) != 0 {
		t.Fatalf("key response body = %s", got.body)
	}
	if e.providerByID(a, id)["has_api_key"] != true {
		t.Fatal("has_api_key is still false after storing a key")
	}
	// The plaintext is stored nowhere the host can show or replay.
	if hits := e.storedIn(key); len(hits) > 0 {
		t.Fatalf("the key leaked into %v", hits)
	}
	var auditCount int
	if err := e.c.DB().Reader().QueryRowContext(t.Context(),
		`SELECT COUNT(*) FROM audit_log WHERE action = 'ai_provider.api_key.set'`).Scan(&auditCount); err != nil {
		t.Fatalf("count audit: %v", err)
	}
	if auditCount != 1 {
		t.Fatalf("key audit rows = %d, want 1", auditCount)
	}

	// An unknown provider is 404; clearing removes the key.
	missing := a.sign(http.MethodPut, "/api/v1/ai/providers/aip_missing/api-key", fmt.Sprintf(`{"api_key":%q}`, key))
	e.do(missing).expectProblem(t, http.StatusNotFound, problem.NotFound)
	e.do(a.sign(http.MethodDelete, path, "")).expect(t, http.StatusNoContent)
	if e.providerByID(a, id)["has_api_key"] != false {
		t.Fatal("has_api_key is still true after clearing")
	}
	e.do(a.sign(http.MethodDelete, path, "")).expect(t, http.StatusNoContent)
}

// TestAIProviderTestRoute: the probe answers ok/latency/category only, goes
// through the outbound policy, and is administrator-only.
func TestAIProviderTestRoute(t *testing.T) {
	e := newEnv(t)
	a := e.setupAdmin(adminUser)
	v := e.signIn("vera", identity.RoleViewer)
	// A loopback address is refused by the default egress policy before the
	// request leaves: the fixed category is the deterministic answer.
	id := e.createProvider(a, "Loopback", "http://127.0.0.1:9", "m", false, 1)

	var out struct {
		OK       bool   `json:"ok"`
		Category string `json:"category"`
	}
	e.do(a.sign(http.MethodPost, "/api/v1/ai/providers/"+id+"/test", "")).expect(t, http.StatusOK).decode(t, &out)
	if out.OK || out.Category != "denied" {
		t.Fatalf("probe = %+v", out)
	}
	e.do(v.sign(http.MethodPost, "/api/v1/ai/providers/"+id+"/test", "")).
		expectProblem(t, http.StatusForbidden, problem.PermissionDenied)
	e.do(a.sign(http.MethodPost, "/api/v1/ai/providers/aip_missing/test", "")).
		expectProblem(t, http.StatusNotFound, problem.NotFound)
}

// TestAgentCoresRoute: the core list is open to any signed-in principal.
func TestAgentCoresRoute(t *testing.T) {
	e := newEnv(t)
	a := e.setupAdmin(adminUser)
	var out struct {
		Items []struct {
			Core      string `json:"core"`
			Available bool   `json:"available"`
			Reason    string `json:"reason"`
		} `json:"items"`
	}
	e.do(a.sign(http.MethodGet, "/api/v1/agent-cores", "")).expect(t, http.StatusOK).decode(t, &out)
	if len(out.Items) != 4 || out.Items[0].Core != "native" || !out.Items[0].Available || out.Items[0].Reason != "" {
		t.Fatalf("cores = %+v", out.Items)
	}
	for _, c := range out.Items[1:] {
		if c.Available || c.Reason == "" {
			t.Fatalf("external core = %+v", c)
		}
	}
}

// TestCreateAgentSessionProviderConfig: provider_id and base_url exclude each
// other; a provider-backed session is accepted, a malformed id is not.
func TestCreateAgentSessionProviderConfig(t *testing.T) {
	e := newEnv(t)
	a := e.setupAdmin(adminUser)
	id := e.createProvider(a, "Default", "https://api.example.com/v1", "m", true, 1)

	both := fmt.Sprintf(`{"config":{"provider_id":%q,"base_url":"https://x.example.com"}}`, id)
	e.do(a.sign(http.MethodPost, "/api/v1/agent-sessions", both)).
		expectProblem(t, http.StatusBadRequest, problem.ValidationFailed)

	only := fmt.Sprintf(`{"config":{"provider_id":%q}}`, id)
	e.do(a.sign(http.MethodPost, "/api/v1/agent-sessions", only)).expect(t, http.StatusCreated)

	// A well-formed id of a provider that does not exist is accepted at
	// creation; the send is what answers UNAVAILABLE.
	missing := fmt.Sprintf(`{"config":{"provider_id":"aip_%s"}}`, strings.Repeat("0", 26))
	e.do(a.sign(http.MethodPost, "/api/v1/agent-sessions", missing)).expect(t, http.StatusCreated)

	e.do(a.sign(http.MethodPost, "/api/v1/agent-sessions", `{"config":{"provider_id":"nope"}}`)).
		expectProblem(t, http.StatusBadRequest, problem.ValidationFailed)
}
