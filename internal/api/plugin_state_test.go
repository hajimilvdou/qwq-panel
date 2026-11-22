// SPDX-License-Identifier: AGPL-3.0-only

package api_test

import (
	"net/http"
	"strings"
	"testing"

	"github.com/qwq-panel/qwq/internal/api"
	"github.com/qwq-panel/qwq/internal/identity"
	"github.com/qwq-panel/qwq/internal/platform/problem"
)

// TestPluginEnableDisable (GAPS gap 7): both routes queue a job operation and
// answer 202 with the operation's Location.
func TestPluginEnableDisable(t *testing.T) {
	mgr := newFakePluginManager()
	e := newEnvWith(t, func(d *api.Deps) { d.Plugins = mgr })
	a := e.setupAdmin(adminUser)
	mgr.byID["acme.demo"] = api.Plugin{PluginID: "acme.demo", Name: "Demo", ActiveVersion: "1.0.0"}

	for _, verb := range []string{"enable", "disable"} {
		req := a.sign(http.MethodPost, "/api/v1/plugins/acme.demo/"+verb, "")
		req.Header.Set("Idempotency-Key", idempotencyKey(len(verb)))
		resp := e.do(req).expect(t, http.StatusAccepted)
		if loc := resp.header.Get("Location"); !strings.HasPrefix(loc, "/api/v1/operations/") {
			t.Fatalf("%s Location = %q", verb, loc)
		}
		var accepted struct {
			OperationID string `json:"operation_id"`
			ApprovalID  string `json:"approval_id"`
		}
		resp.decode(t, &accepted)
		if accepted.OperationID == "" || accepted.ApprovalID == "" {
			t.Fatalf("%s is risk high, so it needs an approval: %s", verb, resp.body)
		}
	}
	// A missing plugin is 404 before anything is queued.
	req := a.sign(http.MethodPost, "/api/v1/plugins/missing/disable", "")
	req.Header.Set("Idempotency-Key", idempotencyKey(9))
	e.do(req).expectProblem(t, http.StatusNotFound, problem.NotFound)

	viewer := e.signIn("enable-viewer", identity.RoleViewer)
	req = viewer.sign(http.MethodPost, "/api/v1/plugins/acme.demo/enable", "")
	req.Header.Set("Idempotency-Key", idempotencyKey(10))
	e.do(req).expectProblem(t, http.StatusForbidden, problem.PermissionDenied)
}

// TestPluginEnableWithoutManager: a host without an updater answers 503.
func TestPluginEnableWithoutManager(t *testing.T) {
	e := newEnv(t)
	a := e.setupAdmin(adminUser)
	for _, verb := range []string{"enable", "disable"} {
		req := a.sign(http.MethodPost, "/api/v1/plugins/acme.demo/"+verb, "")
		req.Header.Set("Idempotency-Key", idempotencyKey(1))
		e.do(req).expectProblem(t, http.StatusServiceUnavailable, problem.PluginUnavailable)
	}
}
