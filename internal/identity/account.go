// SPDX-License-Identifier: AGPL-3.0-only

package identity

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/qwq-panel/qwq/internal/actor"
	"github.com/qwq-panel/qwq/internal/platform/problem"
	"github.com/qwq-panel/qwq/internal/storage"
)

// ============================================================================
//  Account self-service (AUTH-07)
//
//  The signed-in user manages their own credentials here: change the password,
//  turn the second factor off, and redeem an enrollment link into a first
//  password plus a session. Every guess at a credential is charged to the
//  progressive backoff before it is checked, so a stolen session cannot be
//  used to brute-force the password or the TOTP code behind it.
// ============================================================================

// passwordThrottlePrefix labels current-password guesses of a signed-in user;
// a valid username has no colon, so it cannot collide with the login budget.
const passwordThrottlePrefix = "password:"

// ChangePasswordInput replaces the caller's own password.
type ChangePasswordInput struct {
	UserID string
	// SessionID is the session that asks; it survives, every other session of
	// the user is revoked.
	SessionID       string
	CurrentPassword string
	NewPassword     string
	ClientIP        string
	UserAgent       string
}

// ChangePassword verifies the current password, applies the password policy to
// the new one and stores it. A wrong current password is PERMISSION_DENIED, not
// UNAUTHENTICATED: the session is still valid and must not be signed out.
func (s *Service) ChangePassword(ctx context.Context, in ChangePasswordInput) (User, error) {
	key := passwordThrottlePrefix + in.UserID
	if wait, ok := s.thr.Attempt(key, in.ClientIP); !ok {
		return User{}, rateLimited(wait)
	}
	u, err := s.User(ctx, in.UserID)
	if err != nil {
		return User{}, err
	}
	if u.Disabled {
		return User{}, unauthenticated()
	}
	encoded, err := s.passwordHash(ctx, u.ID)
	if err != nil {
		return User{}, err
	}
	verify, err := s.hasher.Verify(ctx, encoded, in.CurrentPassword)
	if err != nil {
		return User{}, fmt.Errorf("identity: verify password: %w", err)
	}
	if !verify.OK {
		s.auditRecord(ctx, AuditRecord{
			Action:    ActionPasswordChanged,
			Actor:     actor.Actor{Kind: actor.Human, ID: u.ID, SessionID: in.SessionID},
			Subject:   u.Subject(),
			Outcome:   OutcomeFailure,
			Reason:    "bad_password",
			ClientIP:  in.ClientIP,
			UserAgent: in.UserAgent,
		})
		return User{}, problem.New(problem.PermissionDenied, "The current password is wrong.")
	}
	hash, err := s.preparePassword(ctx, u.Username, in.NewPassword)
	if err != nil {
		return User{}, renamePointer(err, "/password", "/new_password")
	}
	var updated User
	err = s.update(ctx, func(tx *storage.Tx) error {
		cur, err := s.userTx(ctx, tx, u.ID)
		if err != nil {
			return err
		}
		now := tx.Now()
		if err := upsertPasswordTx(ctx, tx, cur.ID, hash, now); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx,
			`UPDATE sessions SET revoked_at = ? WHERE user_id = ? AND session_id <> ? AND revoked_at = ''`,
			formatTime(now), cur.ID, in.SessionID); err != nil {
			return fmt.Errorf("identity: revoke other sessions: %w", err)
		}
		updated, err = s.markUserChanged(ctx, tx, cur, nil, ActionPasswordChanged,
			actor.Actor{Kind: actor.Human, ID: cur.ID, SessionID: in.SessionID})
		return err
	})
	if err != nil {
		return User{}, err
	}
	s.thr.Reset(key, in.ClientIP)
	return updated, nil
}

// DisableOwnTOTP turns the caller's second factor off. The code is a current
// TOTP code or a recovery code; it shares the backoff of VerifySecondFactor, and
// a wrong one is MFA_REQUIRED (403) because the session itself is still valid.
func (s *Service) DisableOwnTOTP(ctx context.Context, userID, code, clientIP string, by actor.Actor) (User, error) {
	key := secondFactorThrottlePrefix + userID
	if wait, ok := s.thr.Attempt(key, clientIP); !ok {
		return User{}, rateLimited(wait)
	}
	trimmed := strings.TrimSpace(code)
	method := "recovery_code"
	if isTOTPShaped(trimmed) {
		method = "totp"
	}
	var updated User
	err := s.update(ctx, func(tx *storage.Tx) error {
		cur, err := s.userTx(ctx, tx, userID)
		if err != nil {
			return err
		}
		updated, err = s.DisableTOTP(ctx, tx, DisableTOTPInput{
			UserID: cur.ID, ExpectedRevision: cur.Revision, Method: method, Code: trimmed, Actor: by,
		})
		return err
	})
	if problem.HasCode(err, problem.ValidationFailed) {
		s.recordMFAFailure(ctx, User{ID: userID}, VerifyMFAInput{ClientIP: clientIP}, "disable_code")
		return User{}, problem.New(problem.MFARequired, "The second factor is invalid.")
	}
	if err != nil {
		return User{}, err
	}
	s.thr.Reset(key, clientIP)
	return updated, nil
}

// RedeemEnrollmentInput redeems an enrollment link.
type RedeemEnrollmentInput struct {
	Token     string
	Password  string
	ClientIP  string
	UserAgent string
}

// RedeemEnrollment sets the first password from an enrollment link and signs
// the user in, like setup does for the first administrator. A wrong, used or
// expired token is UNAUTHENTICATED.
func (s *Service) RedeemEnrollment(ctx context.Context, in RedeemEnrollmentInput) (LoginResult, error) {
	u, err := s.redeemEnrollmentToken(ctx, in.Token, in.Password, in.ClientIP)
	if err != nil {
		return LoginResult{}, err
	}
	sess, token, err := s.completeLogin(ctx, u, LoginInput{
		Username: u.Username, ClientIP: in.ClientIP, UserAgent: in.UserAgent,
	}, "", time.Time{})
	if err != nil {
		return LoginResult{}, err
	}
	return LoginResult{Session: sess, Token: token}, nil
}

// isTOTPShaped reports whether code looks like a TOTP code rather than a
// recovery code.
func isTOTPShaped(code string) bool {
	if len(code) != TOTPDigits {
		return false
	}
	for i := 0; i < len(code); i++ {
		if code[i] < '0' || code[i] > '9' {
			return false
		}
	}
	return true
}

// renamePointer moves the violations of a validation error from one request
// member to another, for routes whose body names the field differently.
func renamePointer(err error, from, to string) error {
	var pe *problem.Error
	if !errors.As(err, &pe) || pe.Code != problem.ValidationFailed {
		return err
	}
	out := *pe
	out.Violations = make([]problem.Violation, len(pe.Violations))
	for i, v := range pe.Violations {
		if v.Pointer == from {
			v.Pointer = to
		}
		out.Violations[i] = v
	}
	return &out
}
