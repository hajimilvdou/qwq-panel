// SPDX-License-Identifier: AGPL-3.0-only

package agentapi

import (
	"context"
	"fmt"

	"github.com/qwq-panel/qwq/internal/actor"
	"github.com/qwq-panel/qwq/internal/authz"
	"github.com/qwq-panel/qwq/internal/catalog"
	"github.com/qwq-panel/qwq/internal/platform/problem"
)

// delegationView is the effective authority of one tool request: the stored
// delegation record and the current role of the human it acts for.
//
// openapi.yaml describes a delegation as "effective permission = the owner's
// role intersected with the delegation policy". internal/authz owns that
// computation; this type only reuses the exported pieces (authz.RoleAllows,
// authz.Policy.AllowsAction, authz.Policy.AllowsNode, authz.ParsePermission) to
// answer the questions the tools need before a write:
//
//   - which catalog actions may be offered (find_actions, describe_action);
//   - which host resource kinds may be read (read).
//
// For actions this is a display filter only, never the enforcement: plan and
// execute reach internal/operations, which runs authz.Authorize for every
// operation, and authz.authorizeDelegation enforces the same policy there (the
// action allowlist and the node scope) together with the owner's role and the
// rate limit.
type delegationView struct {
	record authz.Delegation
	role   authz.Role
}

// delegationView loads and validates the delegation of a. A missing,
// suspended, expired or owner-disabled delegation is PERMISSION_DENIED: the
// token authenticated, so this is not an authentication failure.
func (h *handlers) delegationView(ctx context.Context, a actor.Actor) (*delegationView, error) {
	d, err := h.authz.Delegation(ctx, a.ID)
	if err != nil {
		if problem.HasCode(err, problem.NotFound) {
			return nil, problem.New(problem.PermissionDenied, "The delegation does not exist.")
		}
		return nil, problem.From(err)
	}
	switch d.StatusAt(h.clock.Now().UTC()) {
	case authz.StatusSuspended:
		return nil, problem.New(problem.PermissionDenied, "The delegation is suspended.")
	case authz.StatusExpired:
		return nil, problem.New(problem.PermissionDenied, "The delegation has expired.")
	}
	if a.OnBehalfOf != "" && a.OnBehalfOf != d.OwnerID {
		return nil, problem.New(problem.PermissionDenied, "The delegation does not act for this user.")
	}
	role, disabled, err := h.identity.PrincipalRole(ctx, d.OwnerID)
	if err != nil {
		return nil, problem.Wrap(fmt.Errorf("agentapi: resolve the delegation owner: %w", err))
	}
	if disabled {
		return nil, problem.New(problem.PermissionDenied, "The delegation owner is not active.")
	}
	return &delegationView{record: d, role: authz.Role(role)}, nil
}

// allowsAction reports whether the delegation may plan and execute e, running
// on nodeID. The checks mirror authz.authorizeDelegation: a human-only
// permission is never delegated, the policy must list the action and the node,
// and the owner's role must grant the permission.
func (v *delegationView) allowsAction(e *catalog.Entry, nodeID string) bool {
	perm, err := authz.ParsePermission(e.Permission)
	if err != nil {
		// An action without a valid permission mapping cannot be authorized,
		// so it is not offered (operations denies it too).
		return false
	}
	if authz.IsHumanOnly(string(perm)) {
		return false
	}
	if !v.record.Policy.AllowsAction(e.ID) {
		return false
	}
	if !v.record.Policy.AllowsNode(nodeID) {
		return false
	}
	return authz.RoleAllows(v.role, perm)
}

// allowsRead reports whether the delegation may read host resources of a kind.
// Reading is not managing: the human-only rule of authz (which protects the
// approval and principal-management surface) does not apply here, because the
// read tool never changes state. The owner's role still decides, so an AI
// acting for a viewer cannot read the user directory.
func (v *delegationView) allowsRead(resource string) bool {
	perm, err := authz.ParsePermission(resource + ":read")
	if err != nil {
		return false
	}
	return authz.RoleAllows(v.role, perm)
}
