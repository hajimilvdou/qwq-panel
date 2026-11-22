// SPDX-License-Identifier: AGPL-3.0-only

package api

import (
	"net/http"
	"time"

	"github.com/qwq-panel/qwq/internal/actor"
	"github.com/qwq-panel/qwq/internal/authz"
	"github.com/qwq-panel/qwq/internal/gateway"
	"github.com/qwq-panel/qwq/internal/operations"
	"github.com/qwq-panel/qwq/internal/platform/problem"
	"github.com/qwq-panel/qwq/internal/storage"
)

// Delegation routes are catalog-exempt (x-qwq-action-exempt): only a human session
// may manage them, so they are not actions an AI operator can reach. The handlers
// therefore call authz directly inside a write transaction; authz appends the
// resource.changed event and the revision, and an audit row is written in the
// same transaction.

// delegationCreateRequest is the DelegationCreateRequest schema.
type delegationCreateRequest struct {
	Label      string        `json:"label"`
	Policy     *authz.Policy `json:"policy,omitempty"`
	TTLSeconds *int          `json:"ttl_seconds,omitempty"`
}

// delegationUpdateRequest is the DelegationUpdateRequest schema.
type delegationUpdateRequest struct {
	ExpectedRevision string        `json:"expected_revision"`
	Status           *string       `json:"status,omitempty"`
	Policy           *authz.Policy `json:"policy,omitempty"`
}

// ttl bounds of the DelegationCreateRequest schema.
const (
	minDelegationTTLSeconds = 300
	maxDelegationTTLSeconds = 7776000
)

// listDelegations returns a page of delegations. `owner=all` lists every owner
// and is reserved for administrators; `since_revision` yields a full snapshot
// with delta=false for the same reason as the user list.
func (a *api) listDelegations(w http.ResponseWriter, r *http.Request) {
	act, err := a.caller(r)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	if err := a.authorize(r.Context(), act, "host.delegations:read", ""); err != nil {
		a.fail(w, r, err)
		return
	}
	owner := r.URL.Query().Get("owner")
	if owner == "" {
		owner = "me"
	}
	switch owner {
	case "me":
	case "all":
		if err := a.requireAdmin(r.Context(), act); err != nil {
			a.fail(w, r, err)
			return
		}
	default:
		a.fail(w, r, problem.Validation(problem.Violation{
			In: "query", Pointer: "/owner", Code: "INVALID", Message: "owner must be me or all.",
		}))
		return
	}
	q, err := a.g.ListQuery(r)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	ownerID := act.ID
	if owner == "all" {
		ownerID = ""
	}
	delegations, err := a.d.Authz.ListDelegations(r.Context(), authz.ListDelegationsInput{
		OwnerID: ownerID,
		After:   q.Cursor,
		Limit:   pageLimit(q.Limit),
	})
	if err != nil {
		a.fail(w, r, err)
		return
	}
	delegations, next := nextCursor(delegations, q.Limit, func(d authz.Delegation) string { return d.ID })
	now := a.d.Clock.Now().UTC()
	items := make([]any, 0, len(delegations))
	for _, d := range delegations {
		items = append(items, newDelegationDTO(d, now))
	}
	a.writeList(w, r, listResponse{Items: items, NextCursor: next, Revision: a.watermark()}, q.Fields)
}

// createDelegation issues a token for an AI operator. The token is returned once.
func (a *api) createDelegation(w http.ResponseWriter, r *http.Request) {
	act, err := a.caller(r)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	if err := a.authorize(r.Context(), act, "host.delegations:create", ""); err != nil {
		a.fail(w, r, err)
		return
	}
	var req delegationCreateRequest
	if err := a.decodeJSON(r, &req); err != nil {
		a.fail(w, r, err)
		return
	}
	if req.Label == "" {
		a.fail(w, r, problem.Validation(problem.Violation{
			Pointer: "/label", Code: "REQUIRED", Message: "A label is required.",
		}))
		return
	}
	var ttl time.Duration
	if req.TTLSeconds != nil {
		s := *req.TTLSeconds
		if s < minDelegationTTLSeconds || s > maxDelegationTTLSeconds {
			a.fail(w, r, problem.Validation(problem.Violation{
				Pointer: "/ttl_seconds", Code: "OUT_OF_RANGE",
				Message: "ttl_seconds must be between 300 and 7776000.",
			}))
			return
		}
		ttl = time.Duration(s) * time.Second
	}
	policy := authz.DefaultPolicy()
	if req.Policy != nil {
		policy = *req.Policy
	}
	key, err := a.idempotency(r, req)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	response, err := a.catalogWrite(r, act, key, "host.delegations:create", http.StatusCreated, "token", func(tx *storage.Tx) (any, error) {
		created, err := a.d.Authz.CreateDelegation(r.Context(), tx, authz.CreateDelegationInput{
			Actor: act, Label: req.Label, Policy: policy, TTL: ttl,
		})
		if err != nil {
			return nil, err
		}
		if err := operations.Audit(r.Context(), tx, operations.AuditRecord{
			Actor: act, Action: "delegation.create", Subject: created.Subject(),
			Outcome: operations.AuditSuccess, TraceID: traceID(r),
			RequestID: requestID(r),
		}); err != nil {
			return nil, err
		}
		return delegationCreatedDTO{delegationDTO: newDelegationDTO(created.Delegation, tx.Now()), Token: created.Token}, nil
	})
	if err != nil {
		a.fail(w, r, err)
		return
	}
	a.writeCatalogResponse(w, r, response)
}

// getDelegation returns one delegation; the token is never included.
func (a *api) getDelegation(w http.ResponseWriter, r *http.Request) {
	act, err := a.caller(r)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	if err := a.authorize(r.Context(), act, "host.delegations:read", ""); err != nil {
		a.fail(w, r, err)
		return
	}
	d, err := a.visibleDelegation(r, act, r.PathValue("delegation_id"))
	if err != nil {
		a.fail(w, r, err)
		return
	}
	fields, err := a.fields(r)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	a.writeResource(w, r, http.StatusOK, newDelegationDTO(d, a.d.Clock.Now().UTC()), fields)
}

// updateDelegation suspends, resumes or narrows a delegation.
func (a *api) updateDelegation(w http.ResponseWriter, r *http.Request) {
	act, err := a.caller(r)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	if err := a.authorize(r.Context(), act, "host.delegations:update", ""); err != nil {
		a.fail(w, r, err)
		return
	}
	var req delegationUpdateRequest
	if err := a.decodeJSON(r, &req); err != nil {
		a.fail(w, r, err)
		return
	}
	revision, err := parseExpectedRevision(req.ExpectedRevision)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	if req.Status == nil && req.Policy == nil {
		a.fail(w, r, problem.Validation(problem.Violation{
			Pointer: "/", Code: "empty", Message: "At least one of status or policy is required.",
		}))
		return
	}
	var status *authz.Status
	if req.Status != nil {
		s := authz.Status(*req.Status)
		if !s.Valid() {
			a.fail(w, r, problem.Validation(problem.Violation{
				Pointer: "/status", Code: "INVALID", Message: "status must be active or suspended.",
			}))
			return
		}
		status = &s
	}
	key, err := a.idempotency(r, req)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	response, err := a.catalogWrite(r, act, key, "host.delegations:update", http.StatusOK, "", func(tx *storage.Tx) (any, error) {
		updated, err := a.d.Authz.UpdateDelegation(r.Context(), tx, authz.UpdateDelegationInput{
			Actor: act, DelegationID: r.PathValue("delegation_id"), ExpectedRevision: revision,
			Status: status, Policy: req.Policy,
		})
		if err != nil {
			return nil, err
		}
		if err := operations.Audit(r.Context(), tx, operations.AuditRecord{
			Actor: act, Action: "delegation.update", Subject: updated.Subject(),
			Outcome: operations.AuditSuccess, TraceID: traceID(r),
			RequestID: requestID(r),
		}); err != nil {
			return nil, err
		}
		return newDelegationDTO(updated, tx.Now()), nil
	})
	if err != nil {
		a.fail(w, r, err)
		return
	}
	a.writeCatalogResponse(w, r, response)
}

// deleteDelegation revokes a delegation; the token stops working immediately.
func (a *api) deleteDelegation(w http.ResponseWriter, r *http.Request) {
	act, err := a.caller(r)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	if err := a.authorize(r.Context(), act, "host.delegations:delete", ""); err != nil {
		a.fail(w, r, err)
		return
	}
	expected, err := gateway.ExpectedRevisionQuery(r)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	revision, err := parseExpectedRevision(expected)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	id := r.PathValue("delegation_id")
	key, err := a.idempotency(r, expected)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	response, err := a.catalogWrite(r, act, key, "host.delegations:delete", http.StatusNoContent, "", func(tx *storage.Tx) (any, error) {
		original, err := a.d.Authz.DelegationTx(r.Context(), tx, id)
		if err != nil {
			return nil, err
		}
		if rerr := a.d.Authz.RevokeDelegation(r.Context(), tx, authz.RevokeDelegationInput{
			Actor: act, DelegationID: id, ExpectedRevision: revision,
		}); rerr != nil {
			return nil, rerr
		}
		if err := operations.Audit(r.Context(), tx, operations.AuditRecord{
			Actor: act, Action: "delegation.revoke", Subject: "delegations/" + id,
			Outcome: operations.AuditSuccess, TraceID: traceID(r),
			RequestID: requestID(r),
		}); err != nil {
			return nil, err
		}
		return catalogOwnerFact{OwnerID: original.OwnerID}, nil
	})
	if err != nil {
		a.fail(w, r, err)
		return
	}
	a.writeCatalogResponse(w, r, response)
}

// visibleDelegation loads a delegation and hides it from a caller that is
// neither its owner nor an administrator.
func (a *api) visibleDelegation(r *http.Request, act actor.Actor, id string) (authz.Delegation, error) {
	d, err := a.d.Authz.Delegation(r.Context(), id)
	if err != nil {
		return authz.Delegation{}, err
	}
	if d.OwnerID == act.ID {
		return d, nil
	}
	role, disabled, err := a.d.Identity.PrincipalRole(r.Context(), act.ID)
	if err != nil {
		return authz.Delegation{}, problem.From(err)
	}
	if disabled || authz.Role(role) != authz.RoleAdmin {
		return authz.Delegation{}, problem.New(problem.NotFound, "The delegation does not exist.")
	}
	return d, nil
}

// principalScope is the idempotency scope of an actor, shaped like the operation
// manager's key scope.
func principalScope(a actor.Actor) string {
	return string(a.Kind) + ":" + a.ID + ":" + a.OnBehalfOf
}
