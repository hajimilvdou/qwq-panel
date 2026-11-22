// SPDX-License-Identifier: AGPL-3.0-only

package api_test

import (
	"net/http"
	"strings"
	"testing"

	"github.com/qwq-panel/qwq/internal/identity"
	"github.com/qwq-panel/qwq/internal/platform/problem"
	"github.com/qwq-panel/qwq/sdk/manifest"
)

// TestWidgetReadRefreshFloor: the host holds a widget read to the refresh floor
// its manifest declares, per principal, and leaves other reads alone (GAPS gap 7).
// This host has no plugin dispatcher, so an allowed read answers 503 — the point
// is which calls the limiter refuses before the read runs.
func TestWidgetReadRefreshFloor(t *testing.T) {
	e := newEnv(t)
	a := e.setupAdmin(adminUser)
	m := &manifest.Manifest{
		ID: "acme.demo", Placement: "controller",
		Operations: []manifest.Operation{
			{Name: "status", Summary: "Read demo status", Effect: "read", Risk: "low", Mode: "invoke", Permission: "plugin.acme.demo:read"},
			{Name: "plain", Summary: "Read demo detail", Effect: "read", Risk: "low", Mode: "invoke", Permission: "plugin.acme.demo:read"},
		},
		UI: &manifest.UI{Widgets: []manifest.UIWidget{
			{ID: "card", Title: "Card", Kind: "stat", Operation: "status", RefreshSeconds: 60, Size: "s"},
		}},
	}
	if err := e.c.Catalog().SetPlugin(m, func(string) ([]byte, error) { return []byte(`{"type":"object"}`), nil }); err != nil {
		t.Fatal(err)
	}
	invoke := func(operation string) response {
		return e.do(a.sign(http.MethodPost, "/api/v1/plugins/acme.demo/operations/"+operation, `{"payload":{}}`))
	}
	if r := invoke("status"); r.status != http.StatusServiceUnavailable {
		t.Fatalf("first widget read = %d (%s)", r.status, r.body)
	}
	p := invoke("status").expectProblem(t, http.StatusTooManyRequests, problem.RateLimited)
	if p.RetryAfter < 1 || !strings.Contains(p.Detail, "widget") {
		t.Fatalf("throttled read = %+v", p)
	}
	// A read no widget is bound to is not held to any floor.
	for i := 0; i < 2; i++ {
		if r := invoke("plain"); r.status != http.StatusServiceUnavailable {
			t.Fatalf("plain read %d = %d (%s)", i, r.status, r.body)
		}
	}
	// Another principal has its own budget.
	other := e.signIn("widget-operator", identity.RoleOperator)
	r := e.do(other.sign(http.MethodPost, "/api/v1/plugins/acme.demo/operations/status", `{"payload":{}}`))
	if r.status != http.StatusServiceUnavailable {
		t.Fatalf("other principal = %d (%s)", r.status, r.body)
	}
}
