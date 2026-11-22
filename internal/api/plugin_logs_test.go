// SPDX-License-Identifier: AGPL-3.0-only

package api_test

import (
	"net/http"
	"testing"

	"github.com/qwq-panel/qwq/internal/api"
	"github.com/qwq-panel/qwq/internal/identity"
	"github.com/qwq-panel/qwq/internal/platform/problem"
)

// TestPluginLogs (GAPS gap 7): the route forwards cursor, stream and limit to the
// manager and returns the page; the journal is not a revisioned collection.
func TestPluginLogs(t *testing.T) {
	mgr := newFakePluginManager()
	e := newEnvWith(t, func(d *api.Deps) { d.Plugins = mgr })
	a := e.setupAdmin(adminUser)
	mgr.byID["acme.demo"] = api.Plugin{PluginID: "acme.demo", Name: "Demo", ActiveVersion: "1.0.0"}
	mgr.logPage = api.PluginLogPage{
		Items:      []api.PluginLogLine{{At: "2026-11-14T00:00:00Z", Stream: "stdout", Line: "hello"}},
		NextCursor: "c2",
		Truncated:  true,
	}
	var page struct {
		Items []struct {
			At     string `json:"at"`
			Stream string `json:"stream"`
			Line   string `json:"line"`
		} `json:"items"`
		NextCursor string `json:"next_cursor"`
		Truncated  bool   `json:"truncated"`
	}
	e.do(a.sign(http.MethodGet, "/api/v1/plugins/acme.demo/logs?stream=stderr&limit=10&cursor=c1", "")).
		expect(t, http.StatusOK).decode(t, &page)
	if len(page.Items) != 1 || page.Items[0].Line != "hello" || page.NextCursor != "c2" || !page.Truncated {
		t.Fatalf("page = %+v", page)
	}
	if mgr.logID != "acme.demo" || mgr.logCursor != "c1" || mgr.logStream != "stderr" || mgr.logLimit != 10 {
		t.Fatalf("manager saw %q %q %q %d", mgr.logID, mgr.logCursor, mgr.logStream, mgr.logLimit)
	}
	for _, query := range []string{"?stream=journal", "?since_revision=42", "?limit=0", "?limit=201"} {
		e.do(a.sign(http.MethodGet, "/api/v1/plugins/acme.demo/logs"+query, "")).
			expectProblem(t, http.StatusBadRequest, problem.ValidationFailed)
	}
	e.do(a.sign(http.MethodGet, "/api/v1/plugins/missing/logs", "")).
		expectProblem(t, http.StatusNotFound, problem.NotFound)
	// A viewer has no logs permission: it is not a read-class verb.
	viewer := e.signIn("logs-viewer", identity.RoleViewer)
	e.do(viewer.sign(http.MethodGet, "/api/v1/plugins/acme.demo/logs", "")).
		expectProblem(t, http.StatusForbidden, problem.PermissionDenied)
	// An operator may read logs.
	operator := e.signIn("logs-operator", identity.RoleOperator)
	e.do(operator.sign(http.MethodGet, "/api/v1/plugins/acme.demo/logs", "")).expect(t, http.StatusOK)
}

// TestPluginLogsWithoutManager: a host without an updater answers 503.
func TestPluginLogsWithoutManager(t *testing.T) {
	e := newEnv(t)
	a := e.setupAdmin(adminUser)
	e.do(a.sign(http.MethodGet, "/api/v1/plugins/acme.demo/logs", "")).
		expectProblem(t, http.StatusServiceUnavailable, problem.PluginUnavailable)
}
