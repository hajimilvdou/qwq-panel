// SPDX-License-Identifier: AGPL-3.0-only

package api

import (
	"net/http"

	"github.com/qwq-panel/qwq/internal/operations"
	"github.com/qwq-panel/qwq/internal/platform/problem"
	"github.com/qwq-panel/qwq/internal/storage"
)

// The enrollment link route is catalog-exempt (x-qwq-action-exempt): it hands a
// one-time credential to a person, so only a human browser session with a fresh
// second factor may call it, and no AI operator reaches it through the action
// catalog. Like the delegation routes, the handler calls the domain inside a
// write transaction and writes the audit row in the same transaction. The token
// exists in clear in one place only, the response: never in an operation, an
// event, the audit log, a log line or a stored replay (AUTH-06).

// enrollmentTokenRequest is the EnrollmentTokenRequest schema.
type enrollmentTokenRequest struct {
	MFACode string `json:"mfa_code"`
}

// enrollmentTokenDTO is the EnrollmentToken schema.
type enrollmentTokenDTO struct {
	UserID          string `json:"user_id"`
	EnrollmentToken string `json:"enrollment_token"`
	ExpiresAt       string `json:"expires_at"`
}

// issueEnrollmentToken mints the one-time enrollment link of a user who has no
// password yet; identity refuses every other user. The token is returned once.
func (a *api) issueEnrollmentToken(w http.ResponseWriter, r *http.Request) {
	act, err := a.caller(r)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	if !a.d.Authz.CanManagePrincipals(act) {
		a.fail(w, r, problem.New(problem.PermissionDenied,
			"Only a human browser session may issue an enrollment link."))
		return
	}
	if err := a.authorize(r.Context(), act, "host.users:update", ""); err != nil {
		a.fail(w, r, err)
		return
	}
	var req enrollmentTokenRequest
	if err := a.decodeJSON(r, &req); err != nil {
		a.fail(w, r, err)
		return
	}
	if err := checkMFACode(req.MFACode); err != nil {
		a.fail(w, r, err)
		return
	}
	userID := r.PathValue("user_id")
	// The second factor is a credential, not part of the request: a retry with a
	// fresh code under the same key replays the first answer instead of failing
	// with IDEMPOTENCY_KEY_REUSED, like an approval decision.
	key, err := a.idempotency(r, userID)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	if replay, err := a.catalogReplay(r, act, key, "host.users:update"); err != nil {
		a.fail(w, r, err)
		return
	} else if replay != nil {
		// The stored answer carries no token, so a replay needs no second factor.
		a.writeCatalogResponse(w, r, replay)
		return
	}
	act, err = a.requireOptionalMFA(r, act, req.MFACode, "Issuing an enrollment link requires a fresh second factor.")
	if err != nil {
		a.fail(w, r, err)
		return
	}
	response, err := a.catalogWrite(r, act, key, "host.users:update", http.StatusOK, "enrollment_token", func(tx *storage.Tx) (any, error) {
		token, expires, err := a.d.Identity.NewEnrollmentToken(r.Context(), tx, userID)
		if err != nil {
			return nil, err
		}
		if err := operations.Audit(r.Context(), tx, operations.AuditRecord{
			Actor: act, Action: "enrollment_token.issue", Subject: "users/" + userID,
			Outcome: operations.AuditSuccess, TraceID: traceID(r),
			RequestID: requestID(r),
		}); err != nil {
			return nil, err
		}
		return enrollmentTokenDTO{UserID: userID, EnrollmentToken: token, ExpiresAt: ts(expires)}, nil
	})
	if err != nil {
		a.fail(w, r, err)
		return
	}
	a.writeCatalogResponse(w, r, response)
}
