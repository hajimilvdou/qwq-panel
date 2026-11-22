// SPDX-License-Identifier: AGPL-3.0-only

package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"

	"github.com/qwq-panel/qwq/internal/actor"
	"github.com/qwq-panel/qwq/internal/gateway"
	"github.com/qwq-panel/qwq/internal/identity"
	"github.com/qwq-panel/qwq/internal/operations"
	"github.com/qwq-panel/qwq/internal/platform/problem"
	"github.com/qwq-panel/qwq/internal/storage"
)

// ============================================================================
//  Account self-service (AUTH-07)
//
//  The signed-in user's own credentials: TOTP enrollment, password change and
//  the public redemption of an enrollment link. These routes are catalog-exempt
//  (x-qwq-action-exempt): they handle credentials of a person, so no AI
//  operator reaches them. Every credential guess is throttled in identity, and
//  every wrong answer on a valid session is a 403, never a 401 that would sign
//  the Shell out.
//
//  The profile carries no credential, so it is an ordinary operation
//  (host.account.update). Its permission is human-only and self-service: every
//  role may use it, no AI may, and it always changes the caller.
// ============================================================================

// totpEnrollmentDTO is the TotpEnrollment schema; the secret is shown once.
type totpEnrollmentDTO struct {
	Secret     string `json:"secret"`
	OTPAuthURL string `json:"otpauth_url"`
	ExpiresAt  string `json:"expires_at"`
}

// totpCodeRequest is the TotpCodeRequest schema.
type totpCodeRequest struct {
	Code string `json:"code"`
}

// totpConfirmedDTO is the TotpConfirmResult schema; the recovery codes are
// shown once.
type totpConfirmedDTO struct {
	RecoveryCodes []string   `json:"recovery_codes"`
	User          userDTO    `json:"user"`
	Session       sessionDTO `json:"session"`
}

// passwordChangeRequest is the PasswordChangeRequest schema.
type passwordChangeRequest struct {
	CurrentPassword string `json:"current_password"`
	NewPassword     string `json:"new_password"`
}

// actionAccountUpdate is the host action of PATCH /sessions/current/profile.
const actionAccountUpdate = "host.account.update"

// profileUpdateRequest is the ProfileUpdateRequest schema. Its members are
// also the arguments of host.account.update: they name no user, because the
// executor always changes the caller.
type profileUpdateRequest struct {
	DisplayName      *string `json:"display_name"`
	ExpectedRevision string  `json:"expected_revision"`
}

// validate applies the schema rules shared by the route and the preview.
func (p profileUpdateRequest) validate() error {
	if p.DisplayName == nil {
		return problem.Validation(problem.Violation{
			Pointer: "/display_name", Code: "REQUIRED", Message: "display_name is required.",
		})
	}
	if _, err := parseExpectedRevision(p.ExpectedRevision); err != nil {
		return err
	}
	return validateDisplayName(*p.DisplayName)
}

// checkAccountTarget keeps host.account.update on the caller. The route always
// targets the caller; a plan may name a subject, and another user's would have
// its revision compared (and reported in the conflict) instead of the caller's.
func checkAccountTarget(req operations.HostRequest) error {
	if s := req.Target.Subject; s != "" && s != "users/"+req.Actor.ID {
		return problem.Validation(problem.Violation{
			Pointer: "/target/subject", Code: "INVALID_SUBJECT",
			Message: "The account action only targets the caller's own user.",
		})
	}
	return nil
}

// enrollmentRedeemRequest is the EnrollmentRedeemRequest schema.
type enrollmentRedeemRequest struct {
	Token    string `json:"token"`
	Password string `json:"password"`
}

// beginTOTP starts (or restarts) a TOTP enrollment for the caller. Replacing a
// second factor that is already on needs a fresh one.
func (a *api) beginTOTP(w http.ResponseWriter, r *http.Request) {
	act, err := a.caller(r)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	u, err := a.d.Identity.User(r.Context(), act.ID)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	if u.MFAEnabled && !act.MFA {
		a.fail(w, r, problem.New(problem.MFARequired,
			"Replacing the second factor requires a fresh second factor."))
		return
	}
	enr, err := a.d.Identity.BeginTOTPEnrollment(r.Context(), act.ID)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	a.writeResource(w, r, http.StatusOK, totpEnrollmentDTO{
		Secret: enr.Secret, OTPAuthURL: enr.URL, ExpiresAt: ts(enr.ExpiresAt),
	}, nil)
}

// confirmTOTP confirms the pending secret with a code and returns the recovery
// codes. The session is not marked as having passed a second factor: the code
// only proves the secret this same session just created.
func (a *api) confirmTOTP(w http.ResponseWriter, r *http.Request) {
	act, err := a.caller(r)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	var req totpCodeRequest
	if err := a.decodeJSON(r, &req); err != nil {
		a.fail(w, r, err)
		return
	}
	u, err := a.d.Identity.User(r.Context(), act.ID)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	var (
		codes   []string
		updated identity.User
	)
	err = a.d.DB.Update(r.Context(), func(tx *storage.Tx) error {
		tx.SetOrigin(storage.Origin{Actor: act, TraceID: traceID(r), NodeID: a.d.NodeID})
		var ierr error
		codes, updated, ierr = a.d.Identity.EnableTOTP(r.Context(), tx, identity.EnableTOTPInput{
			UserID: act.ID, ExpectedRevision: u.Revision, Code: req.Code, Actor: act,
		})
		return ierr
	})
	if err != nil {
		a.fail(w, r, err)
		return
	}
	sess, err := a.currentSessionRow(r)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	a.writeResource(w, r, http.StatusOK, totpConfirmedDTO{
		RecoveryCodes: codes, User: newUserDTO(updated), Session: newSessionDTO(sess),
	}, nil)
}

// disableTOTP turns the caller's second factor off with a current code.
func (a *api) disableTOTP(w http.ResponseWriter, r *http.Request) {
	act, err := a.caller(r)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	var req totpCodeRequest
	if err := a.decodeJSON(r, &req); err != nil {
		a.fail(w, r, err)
		return
	}
	u, err := a.d.Identity.DisableOwnTOTP(r.Context(), act.ID, req.Code, gateway.ClientIP(r.Context()), act)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	a.writeResource(w, r, http.StatusOK, newUserDTO(u), nil)
}

// updateProfile renames the caller through host.account.update. The answer is
// the operation outcome; its result is the updated User.
func (a *api) updateProfile(w http.ResponseWriter, r *http.Request) {
	act, err := a.caller(r)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	var req profileUpdateRequest
	if err := a.decodeJSON(r, &req); err != nil {
		a.fail(w, r, err)
		return
	}
	if err := req.validate(); err != nil {
		a.fail(w, r, err)
		return
	}
	args, err := json.Marshal(req)
	if err != nil {
		a.fail(w, r, problem.Wrap(err))
		return
	}
	idem, err := a.idempotency(r, req)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	resp, err := a.d.Ops.Run(r.Context(), operations.RunRequest{
		Actor:            act,
		TraceID:          traceID(r),
		RequestID:        requestID(r),
		NodeID:           a.d.NodeID,
		Action:           actionAccountUpdate,
		Target:           operations.Target{Subject: "users/" + act.ID},
		Args:             args,
		ExpectedRevision: req.ExpectedRevision,
		Idempotency:      idem,
	})
	if err != nil {
		a.fail(w, r, err)
		return
	}
	a.writeOperationResponse(w, resp)
}

// executeAccountUpdate runs host.account.update inside the operation
// transaction. Only a person has an account to change, and the user is always
// the caller, never a member of the arguments.
func (a *api) executeAccountUpdate(ctx context.Context, tx *storage.Tx, req operations.HostRequest) (json.RawMessage, error) {
	if req.Actor.Kind != actor.Human {
		return nil, problem.New(problem.PermissionDenied, "Only a person can change their own account.")
	}
	if err := checkAccountTarget(req); err != nil {
		return nil, err
	}
	var args profileUpdateRequest
	if err := decodeArgs(req.Args, &args); err != nil {
		return nil, err
	}
	if err := args.validate(); err != nil {
		return nil, err
	}
	revision, err := parseExpectedRevision(args.ExpectedRevision)
	if err != nil {
		return nil, err
	}
	u, err := a.d.Identity.UpdateUser(ctx, tx, identity.UpdateUserInput{
		UserID:           req.Actor.ID,
		ExpectedRevision: revision,
		DisplayName:      args.DisplayName,
		Actor:            req.Actor,
	})
	if err != nil {
		return nil, err
	}
	return json.Marshal(newUserDTO(u))
}

// planAccountUpdate previews host.account.update.
func (a *api) planAccountUpdate(_ context.Context, _ *sql.Tx, req operations.HostRequest) (operations.Preview, error) {
	if err := checkAccountTarget(req); err != nil {
		return operations.Preview{}, err
	}
	var args profileUpdateRequest
	if err := decodeArgs(req.Args, &args); err != nil {
		return operations.Preview{}, err
	}
	if err := args.validate(); err != nil {
		return operations.Preview{}, err
	}
	after, err := json.Marshal(map[string]string{"display_name": *args.DisplayName})
	if err != nil {
		return operations.Preview{}, problem.Wrap(err)
	}
	return operations.Preview{
		Changes: []operations.PlannedChange{{
			Kind: "update", Subject: "users/" + req.Actor.ID, After: after, Reversible: true,
		}},
	}, nil
}

// changePassword replaces the caller's password; this session stays signed in
// and every other session of the user is revoked.
func (a *api) changePassword(w http.ResponseWriter, r *http.Request) {
	act, err := a.caller(r)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	var req passwordChangeRequest
	if err := a.decodeJSON(r, &req); err != nil {
		a.fail(w, r, err)
		return
	}
	if _, err := a.d.Identity.ChangePassword(r.Context(), identity.ChangePasswordInput{
		UserID:          act.ID,
		SessionID:       act.SessionID,
		CurrentPassword: req.CurrentPassword,
		NewPassword:     req.NewPassword,
		ClientIP:        gateway.ClientIP(r.Context()),
		UserAgent:       r.UserAgent(),
	}); err != nil {
		a.fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// redeemEnrollment sets a new user's first password from an enrollment link
// and signs them in exactly like setup does.
func (a *api) redeemEnrollment(w http.ResponseWriter, r *http.Request) {
	var req enrollmentRedeemRequest
	if err := a.decodeJSON(r, &req); err != nil {
		a.fail(w, r, err)
		return
	}
	res, err := a.d.Identity.RedeemEnrollment(r.Context(), identity.RedeemEnrollmentInput{
		Token:     req.Token,
		Password:  req.Password,
		ClientIP:  gateway.ClientIP(r.Context()),
		UserAgent: r.UserAgent(),
	})
	if err != nil {
		a.fail(w, r, err)
		return
	}
	a.g.SetSessionCookie(w, res.Token, a.sessionTTL(res.Session))
	a.writeResource(w, r, http.StatusCreated, newSessionDTO(res.Session), nil)
}
