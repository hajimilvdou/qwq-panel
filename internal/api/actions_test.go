// SPDX-License-Identifier: AGPL-3.0-only

package api_test

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/qwq-panel/qwq/internal/identity"
	"github.com/qwq-panel/qwq/internal/platform/problem"
	"github.com/qwq-panel/qwq/sdk/manifest"
)

// TestActionsHumanCatalog 覆盖搜索、权限过滤、编码后的插件动作和详情 schema。
func TestActionsHumanCatalog(t *testing.T) {
	e := newEnv(t)
	a := e.setupAdmin(adminUser)
	m := &manifest.Manifest{ID: "acme.demo", Placement: "controller", Operations: []manifest.Operation{
		{Name: "status", Summary: "Read demo status", Effect: "read", Risk: "low", Mode: "invoke", Permission: "plugin.acme.demo:read", RequestSchema: "status.json"},
		{Name: "apply", Summary: "Apply demo settings", Effect: "write", Risk: "medium", Mode: "invoke", Permission: "plugin.acme.demo:update", RequestSchema: "apply.json"},
	}}
	if err := e.c.Catalog().SetPlugin(m, func(string) ([]byte, error) {
		return []byte(`{"type":"object","properties":{"name":{"type":"string"}}}`), nil
	}); err != nil {
		t.Fatal(err)
	}
	type action struct {
		ID            string          `json:"id"`
		RequestSchema json.RawMessage `json:"request_schema"`
	}
	var doc struct {
		Items     []action `json:"items"`
		Truncated bool     `json:"truncated"`
	}
	e.do(a.sign(http.MethodGet, "/api/v1/actions?plugin_id=acme.demo&limit=1", "")).expect(t, http.StatusOK).decode(t, &doc)
	if len(doc.Items) != 1 || !doc.Truncated {
		t.Fatalf("limited catalog = %+v", doc)
	}
	e.do(a.sign(http.MethodGet, "/api/v1/actions?q=status&plugin_id=acme.demo&effect=read", "")).expect(t, http.StatusOK).decode(t, &doc)
	if len(doc.Items) != 1 || doc.Items[0].ID != "acme.demo/status" || doc.Truncated {
		t.Fatalf("search = %+v", doc)
	}
	var detail action
	e.do(a.sign(http.MethodGet, "/api/v1/actions/"+url.PathEscape("acme.demo/status"), "")).expect(t, http.StatusOK).decode(t, &detail)
	if detail.ID != "acme.demo/status" || !strings.Contains(string(detail.RequestSchema), `"name"`) {
		t.Fatalf("detail = %+v", detail)
	}
	viewer := e.signIn("vera", identity.RoleViewer)
	e.do(viewer.sign(http.MethodGet, "/api/v1/actions?plugin_id=acme.demo", "")).expect(t, http.StatusOK).decode(t, &doc)
	if len(doc.Items) != 1 || doc.Items[0].ID != "acme.demo/status" {
		t.Fatalf("viewer catalog = %+v", doc)
	}
	for _, id := range []string{"acme.demo/apply", "acme.demo/missing"} {
		e.do(viewer.sign(http.MethodGet, "/api/v1/actions/"+url.PathEscape(id), "")).expectProblem(t, http.StatusNotFound, problem.NotFound)
	}
	// exempt 路由不会因为对人开放目录而出现。
	e.do(a.sign(http.MethodGet, "/api/v1/actions?q=changePassword", "")).expect(t, http.StatusOK).decode(t, &doc)
	for _, item := range doc.Items {
		if strings.Contains(item.ID, "password") {
			t.Fatalf("secret route leaked: %s", item.ID)
		}
	}
}

// TestActionsValidationAndAccess 验证只有人类会话可以读目录。
func TestActionsValidationAndAccess(t *testing.T) {
	e := newEnv(t)
	a := e.setupAdmin(adminUser)
	for _, query := range []string{"limit=0", "limit=51", "limit=x", "effect=invalid", "q=" + strings.Repeat("a", 201), "plugin_id=../bad"} {
		e.do(a.sign(http.MethodGet, "/api/v1/actions?"+query, "")).expectProblem(t, http.StatusBadRequest, problem.ValidationFailed)
	}
	e.do(newRequest(http.MethodGet, "/api/v1/actions", "")).expectProblem(t, http.StatusUnauthorized, problem.Unauthenticated)
	p := &pluginTestEnv{env: e}
	token := p.serviceTokenWithRole(t, a, "admin")
	e.do(bearer(http.MethodGet, "/api/v1/actions", "", token)).expectProblem(t, http.StatusForbidden, problem.PermissionDenied)
}
