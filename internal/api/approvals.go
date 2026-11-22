// SPDX-License-Identifier: AGPL-3.0-only

package api

import (
	"net/http"

	"github.com/qwq-panel/qwq/internal/actor"
	"github.com/qwq-panel/qwq/internal/gateway"
	"github.com/qwq-panel/qwq/internal/operations"
	"github.com/qwq-panel/qwq/internal/platform/problem"
)

// approvalDecisionRequest is the ApprovalDecisionRequest schema.
type approvalDecisionRequest struct {
	Decision         string `json:"decision"`
	ExpectedRevision string `json:"expected_revision"`
	Comment          string `json:"comment"`
	MFACode          string `json:"mfa_code"`
}

// listApprovals returns a page of approvals. The default status is PENDING.
//
// A service account skips the RBAC check on purpose: host.approvals is human-only
// for writes, and the operation manager already narrows the listing to the
// approvals of the service account's own operations (openapi listApprovals).
func (a *api) listApprovals(w http.ResponseWriter, r *http.Request) {
	act, err := a.caller(r)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	if act.Kind != actor.Service {
		if err := a.authorize(r.Context(), act, "host.approvals:read", ""); err != nil {
			a.fail(w, r, err)
			return
		}
	}
	q, err := a.g.ListQuery(r)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	var status operations.ApprovalStatus
	if raw := r.URL.Query().Get("status"); raw != "" {
		status = operations.ApprovalStatus(raw)
		switch status {
		case operations.ApprovalPending, operations.ApprovalApproved, operations.ApprovalRejected,
			operations.ApprovalExpired, operations.ApprovalCanceled:
		default:
			a.fail(w, r, problem.Validation(problem.Violation{
				In: "query", Pointer: "/status", Code: "INVALID",
				Message: "status must be PENDING, APPROVED, REJECTED, EXPIRED or CANCELED.",
			}))
			return
		}
	}
	page, err := a.d.Ops.ListApprovals(r.Context(), act, operations.ApprovalFilter{
		Status:        status,
		SinceRevision: q.SinceRevision,
		Cursor:        q.Cursor,
		Limit:         q.Limit,
	})
	if err != nil {
		a.fail(w, r, err)
		return
	}
	items := make([]any, 0, len(page.Items))
	for i := range page.Items {
		items = append(items, page.Items[i])
	}
	a.writeList(w, r, listResponse{
		Items:      items,
		NextCursor: page.NextCursor,
		Revision:   page.Revision,
		Delta:      page.Delta,
		DeletedIDs: page.DeletedIDs,
	}, q.Fields)
}

// getApproval returns one approval with its confirmation-card data. Like the
// list, a service account sees only the approvals of its own operations. The
// card carries the plugin author's own text (approval_summary and
// approval_description) and the caller's permission_mode inside `facts`, so the
// operation manager's value is passed through as it is, without a DTO mapping
// (ADR-0010 §4); the fields are untrusted and the UI renders them as text.
func (a *api) getApproval(w http.ResponseWriter, r *http.Request) {
	act, err := a.caller(r)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	if act.Kind != actor.Service {
		if err := a.authorize(r.Context(), act, "host.approvals:read", ""); err != nil {
			a.fail(w, r, err)
			return
		}
	}
	approval, err := a.d.Ops.GetApproval(r.Context(), act, r.PathValue("approval_id"))
	if err != nil {
		a.fail(w, r, err)
		return
	}
	fields, err := a.fields(r)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	a.writeResource(w, r, http.StatusOK, approval, fields)
}

// decideApproval records a human decision. Only a browser session may decide
// (ADR-0004 D6); the operation manager enforces the second factor for
// destructive actions from Actor.MFA, which identity computes from the session.
func (a *api) decideApproval(w http.ResponseWriter, r *http.Request) {
	p, err := principal(r)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	act := p.Actor
	if !a.d.Authz.CanApprove(act) {
		a.fail(w, r, problem.New(problem.PermissionDenied,
			"Only a human browser session may decide an approval."))
		return
	}
	var req approvalDecisionRequest
	if err := a.decodeJSON(r, &req); err != nil {
		a.fail(w, r, err)
		return
	}
	if req.Decision != operations.DecisionApprove && req.Decision != operations.DecisionReject {
		a.fail(w, r, problem.Validation(problem.Violation{
			Pointer: "/decision", Code: "INVALID", Message: "decision must be approve or reject.",
		}))
		return
	}
	if _, err := parseExpectedRevision(req.ExpectedRevision); err != nil {
		a.fail(w, r, err)
		return
	}
	// A destructive approval asks for a fresh second factor; a code verified
	// here counts for this decision only.
	if act, err = a.secondFactor(r, act, req.MFACode); err != nil {
		a.fail(w, r, err)
		return
	}
	idem, err := a.idempotency(r, req)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	resp, err := a.d.Ops.Decide(r.Context(), operations.DecisionRequest{
		Actor:            act,
		ApprovalID:       r.PathValue("approval_id"),
		Decision:         req.Decision,
		Comment:          req.Comment,
		ExpectedRevision: req.ExpectedRevision,
		Idempotency:      idem,
		TraceID:          traceID(r),
		RequestID:        requestID(r),
	})
	if err != nil {
		a.fail(w, r, err)
		return
	}
	a.writeOperationResponse(w, resp)
}

// secondFactor marks act as holding a fresh second factor for this request
// when code is a current TOTP code of the user; an empty code leaves act as it
// is. identity consumes the code, so it cannot be replayed. The session itself
// is not promoted and no new cookie is issued: a session that passed the
// second factor recently already has act.MFA, which identity computes from the
// session (Session.MFAFresh).
func (a *api) secondFactor(r *http.Request, act actor.Actor, code string) (actor.Actor, error) {
	if err := checkMFACode(code); err != nil || code == "" {
		return act, err
	}
	if err := a.d.Identity.VerifySecondFactor(r.Context(), act.ID, code, gateway.ClientIP(r.Context())); err != nil {
		return act, err
	}
	act.MFA = true
	return act, nil
}

// checkMFACode validates an optional mfa_code request member.
func checkMFACode(code string) error {
	if code != "" && !isSixDigits(code) {
		return problem.Validation(problem.Violation{
			Pointer: "/mfa_code", Code: "INVALID", Message: "mfa_code is a six-digit TOTP code.",
		})
	}
	return nil
}

// isSixDigits reports whether s is a six-digit TOTP code.
func isSixDigits(s string) bool {
	if len(s) != 6 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}
