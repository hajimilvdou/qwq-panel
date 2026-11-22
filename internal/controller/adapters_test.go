// SPDX-License-Identifier: AGPL-3.0-only

package controller

import (
	"testing"
	"time"

	"github.com/qwq-panel/qwq/internal/actor"
	"github.com/qwq-panel/qwq/internal/authz"
	"github.com/qwq-panel/qwq/internal/identity"
	"github.com/qwq-panel/qwq/internal/operations"
	"github.com/qwq-panel/qwq/internal/platform/problem"
	"github.com/qwq-panel/qwq/internal/storage"
)

// TestAuthorizerAdapterEnforcesDelegationActions checks the production
// operations.Authorizer: it must hand the catalog action ID to authz, or the
// action allowlist of a delegation policy (ADR-0004 D6) cannot hold on the
// operation path. Both actions sit behind one permission, so only the allowlist
// can tell them apart.
func TestAuthorizerAdapterEnforcesDelegationActions(t *testing.T) {
	e := newAgentEnv(t)
	ctx := t.Context()
	const listed = "com.example.monitor/scan.run"
	var created authz.Created
	err := e.c.DB().Update(ctx, func(tx *storage.Tx) error {
		var err error
		created, err = e.c.Authorizer().CreateDelegation(ctx, tx, authz.CreateDelegationInput{
			Actor:  humanActor(e.admin),
			Label:  "monitor",
			Policy: authz.Policy{Actions: []string{listed}},
			TTL:    time.Hour,
		})
		return err
	})
	if err != nil {
		t.Fatalf("create delegation: %v", err)
	}
	ai := actor.Actor{Kind: actor.AIAgent, ID: created.ID, OnBehalfOf: e.admin.ID}
	adapter := authorizerAdapter{authz: e.c.Authorizer()}
	target := operations.Target{NodeID: "local"}

	scan := operations.Action{ID: listed, Permission: "com.example.monitor:scan"}
	if err := adapter.Authorize(ctx, ai, scan, target); err != nil {
		t.Fatalf("listed action denied: %v", err)
	}
	deep := operations.Action{ID: "com.example.monitor/scan.deep", Permission: "com.example.monitor:scan"}
	if err := adapter.Authorize(ctx, ai, deep, target); !problem.HasCode(err, problem.PermissionDenied) {
		t.Fatalf("unlisted action = %v, want PERMISSION_DENIED", err)
	}
}

// A plugin cannot make a write operation runnable by viewers by declaring a
// read-class permission, whatever its schema minor (ADR-0014).
func TestViewerCannotRunPluginWriteAction(t *testing.T) {
	c, _ := newVisibilityController(t)
	viewer := createVisibilityUser(t, c, "viewer", identity.RoleViewer)
	admin := createVisibilityUser(t, c, "admin", identity.RoleAdmin)
	adapter := authorizerAdapter{authz: c.Authorizer()}
	target := operations.Target{NodeID: "local"}

	write := operations.Action{ID: "acme/x.set", PluginID: "acme", Effect: "write", Permission: "acme:read"}
	if err := adapter.Authorize(t.Context(), viewer, write, target); !problem.HasCode(err, problem.PermissionDenied) {
		t.Fatalf("viewer write = %v, want PERMISSION_DENIED", err)
	}
	if err := adapter.Authorize(t.Context(), admin, write, target); err != nil {
		t.Fatalf("admin write: %v", err)
	}
	read := operations.Action{ID: "acme/x.get", PluginID: "acme", Effect: "read", Permission: "acme:read"}
	if err := adapter.Authorize(t.Context(), viewer, read, target); err != nil {
		t.Fatalf("viewer read: %v", err)
	}
}
