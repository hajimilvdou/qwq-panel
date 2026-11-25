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

// TestPluginUninstallJob (GAPS gap 7): DELETE queues the uninstall job and
// answers 202; purging data needs a fresh second factor; dependents block it
// with 409 and are named in the problem.
func TestPluginUninstallJob(t *testing.T) {
	mgr := newFakePluginManager()
	e := newEnvWith(t, func(d *api.Deps) { d.Plugins = mgr })
	a := e.setupAdmin(adminUser)
	mgr.byID["acme.demo"] = api.Plugin{PluginID: "acme.demo", Name: "Demo", ActiveVersion: "1.0.0", Revision: 7}

	del := func(target, query, key string) response {
		req := a.sign(http.MethodDelete, "/api/v1/plugins/"+target+query, "")
		req.Header.Set("Idempotency-Key", key)
		return e.do(req)
	}
	del("acme.demo", "", idempotencyKey(1)).expectProblem(t, http.StatusBadRequest, problem.ValidationFailed)
	del("acme.demo", "?expected_revision=7&purge_data=maybe", idempotencyKey(2)).
		expectProblem(t, http.StatusBadRequest, problem.ValidationFailed)

	resp := del("acme.demo", "?expected_revision=7", idempotencyKey(3)).expect(t, http.StatusAccepted)
	if loc := resp.header.Get("Location"); !strings.HasPrefix(loc, "/api/v1/operations/") {
		t.Fatalf("Location = %q", loc)
	}
	var accepted struct {
		OperationID string `json:"operation_id"`
		ApprovalID  string `json:"approval_id"`
	}
	resp.decode(t, &accepted)
	if accepted.OperationID == "" || accepted.ApprovalID == "" {
		t.Fatalf("uninstall is risk high, so it needs an approval: %s", resp.body)
	}

	// 2FA is optional: an administrator without 2FA enabled can uninstall with
	// purge_data=true without being forced to enroll in TOTP.
	del("acme.demo", "?expected_revision=7&purge_data=true", idempotencyKey(4)).expect(t, http.StatusAccepted)

	// Once the administrator opts into 2FA, purge_data=true requires fresh MFA
	// or a current X-QWQ-MFA-Code header.
	secret, _ := e.enableTOTP(a.userID)
	del("acme.demo", "?expected_revision=7&purge_data=true", idempotencyKey(8)).
		expectProblem(t, http.StatusForbidden, problem.MFARequired)
	withCode := a.sign(http.MethodDelete, "/api/v1/plugins/acme.demo?expected_revision=7&purge_data=true", "")
	withCode.Header.Set("Idempotency-Key", idempotencyKey(9))
	withCode.Header.Set("X-QWQ-MFA-Code", totpAt(secret, 1))
	e.do(withCode).expect(t, http.StatusAccepted)

	// A plugin another one depends on cannot be removed.
	mgr.dependents = []string{"acme.other"}
	conflict := del("acme.demo", "?expected_revision=7", idempotencyKey(5)).
		expectProblem(t, http.StatusConflict, problem.StateConflict)
	if len(conflict.Dependents) != 1 || conflict.Dependents[0] != "acme.other" {
		t.Fatalf("dependents = %v", conflict.Dependents)
	}
	mgr.dependents = nil

	del("missing", "?expected_revision=0", idempotencyKey(6)).
		expectProblem(t, http.StatusNotFound, problem.NotFound)

	viewer := e.signIn("uninstall-viewer", identity.RoleViewer)
	req := viewer.sign(http.MethodDelete, "/api/v1/plugins/acme.demo?expected_revision=7", "")
	req.Header.Set("Idempotency-Key", idempotencyKey(7))
	e.do(req).expectProblem(t, http.StatusForbidden, problem.PermissionDenied)
}

// TestPluginUninstallWithoutManager: a host without an updater answers 503.
func TestPluginUninstallWithoutManager(t *testing.T) {
	e := newEnv(t)
	a := e.setupAdmin(adminUser)
	req := a.sign(http.MethodDelete, "/api/v1/plugins/acme.demo?expected_revision=0", "")
	req.Header.Set("Idempotency-Key", idempotencyKey(1))
	e.do(req).expectProblem(t, http.StatusServiceUnavailable, problem.PluginUnavailable)
}
