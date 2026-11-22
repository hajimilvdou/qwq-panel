// SPDX-License-Identifier: AGPL-3.0-only

package api_test

import (
	"net/http"
	"testing"

	"github.com/qwq-panel/qwq/internal/api"
	"github.com/qwq-panel/qwq/internal/identity"
	"github.com/qwq-panel/qwq/internal/platform/problem"
)

// TestSystemInfo: every signed-in principal reads the overview, but the listener
// address and the data directory are administrator information (GAPS gap 7).
func TestSystemInfo(t *testing.T) {
	e := newEnv(t)
	a := e.setupAdmin(adminUser)
	admin := e.do(a.sign(http.MethodGet, "/api/v1/system", "")).expect(t, http.StatusOK).decodeMap(t)
	for _, key := range []string{"version", "role", "started_at", "tls", "listen", "data_dir", "plugins_enabled"} {
		if _, ok := admin[key]; !ok {
			t.Fatalf("admin system info lacks %q: %v", key, admin)
		}
	}
	if admin["role"] != "standalone" {
		t.Fatalf("role = %v", admin["role"])
	}
	tlsInfo, ok := admin["tls"].(map[string]any)
	if !ok || tlsInfo["mode"] == "" {
		t.Fatalf("tls = %v", admin["tls"])
	}
	viewer := e.signIn("system-viewer", identity.RoleViewer)
	out := e.do(viewer.sign(http.MethodGet, "/api/v1/system", "")).expect(t, http.StatusOK).decodeMap(t)
	if _, ok := out["listen"]; ok {
		t.Fatalf("listen leaked to a viewer: %v", out)
	}
	if _, ok := out["data_dir"]; ok {
		t.Fatalf("data_dir leaked to a viewer: %v", out)
	}
	if out["version"] != admin["version"] || out["role"] != admin["role"] {
		t.Fatalf("viewer system info = %v", out)
	}
	e.do(newRequest(http.MethodGet, "/api/v1/system", "")).expectProblem(t, http.StatusUnauthorized, problem.Unauthenticated)
}

// TestPluginRestart: the route restarts one plugin through the manager and
// answers with the refreshed plugin, so the UI can update its card.
func TestPluginRestart(t *testing.T) {
	mgr := newFakePluginManager()
	e := newEnvWith(t, func(d *api.Deps) { d.Plugins = mgr })
	a := e.setupAdmin(adminUser)
	mgr.byID["acme.demo"] = api.Plugin{PluginID: "acme.demo", Name: "Demo", ActiveVersion: "1.0.0"}

	post := func(target, body, key string) response {
		req := a.sign(http.MethodPost, target, body)
		if key != "" {
			req.Header.Set("Idempotency-Key", key)
		}
		return e.do(req)
	}
	post("/api/v1/plugins/acme.demo/restart", `{"reason":"after a config change"}`, "").
		expectProblem(t, http.StatusBadRequest, problem.ValidationFailed)
	var out map[string]any
	post("/api/v1/plugins/acme.demo/restart", `{"reason":"after a config change"}`, idempotencyKey(1)).
		expect(t, http.StatusOK).decode(t, &out)
	if out["plugin_id"] != "acme.demo" {
		t.Fatalf("restart result = %v", out)
	}
	if mgr.restartID != "acme.demo" || mgr.restartReason != "after a config change" {
		t.Fatalf("manager saw %q / %q", mgr.restartID, mgr.restartReason)
	}
	// An empty body is allowed: the reason is optional.
	post("/api/v1/plugins/acme.demo/restart", "", idempotencyKey(2)).expect(t, http.StatusOK)
	post("/api/v1/plugins/missing/restart", "", idempotencyKey(3)).
		expectProblem(t, http.StatusNotFound, problem.NotFound)
	// A viewer may not restart anything.
	viewer := e.signIn("restart-viewer", identity.RoleViewer)
	req := viewer.sign(http.MethodPost, "/api/v1/plugins/acme.demo/restart", "")
	req.Header.Set("Idempotency-Key", idempotencyKey(4))
	e.do(req).expectProblem(t, http.StatusForbidden, problem.PermissionDenied)
}

// TestPluginRestartWithoutManager: a host without an updater answers 503, not a
// claim that something restarted.
func TestPluginRestartWithoutManager(t *testing.T) {
	e := newEnv(t)
	a := e.setupAdmin(adminUser)
	req := a.sign(http.MethodPost, "/api/v1/plugins/acme.demo/restart", "")
	req.Header.Set("Idempotency-Key", idempotencyKey(1))
	e.do(req).expectProblem(t, http.StatusServiceUnavailable, problem.PluginUnavailable)
}
