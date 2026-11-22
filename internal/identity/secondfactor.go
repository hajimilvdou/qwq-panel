// SPDX-License-Identifier: AGPL-3.0-only

package identity

import (
	"context"

	"github.com/qwq-panel/qwq/internal/platform/problem"
	"github.com/qwq-panel/qwq/internal/storage"
)

// Throttle labels outside the username namespace (a valid username has no
// colon): the second factor of a signed-in user, and login attempts whose user
// name is not even valid.
const (
	secondFactorThrottlePrefix = "mfa:"
	invalidNameThrottlePrefix  = "invalid:"
)

// VerifySecondFactor checks a TOTP or recovery code for a user without creating
// a session. Destructive approvals use it to prove that the approver still
// holds the second factor; the code is consumed (the TOTP step counter is
// advanced, a recovery code is deleted), so replaying it fails.
//
// The method is intentionally separate from the login flow: approval is a
// confirmation of an already-authenticated session, not a new login, and the
// caller must not mint a session from it.
//
// Every attempt is charged to the progressive backoff of the user and clientIP
// before the code is checked, and only a correct code refunds it; a wrong code
// is audited and returns MFA_REQUIRED, not UNAUTHENTICATED, because the session
// itself is still valid.
func (s *Service) VerifySecondFactor(ctx context.Context, userID, code, clientIP string) error {
	if s.sealer == nil {
		return problem.New(problem.Unavailable, "Second factors are not configured on this host.")
	}
	if code == "" {
		return problem.New(problem.MFARequired, "A second factor is required.")
	}
	key := secondFactorThrottlePrefix + userID
	if wait, ok := s.thr.Attempt(key, clientIP); !ok {
		return rateLimited(wait)
	}
	u, err := s.User(ctx, userID)
	if err != nil {
		return err
	}
	if u.Disabled {
		return problem.New(problem.Unauthenticated, "The user is disabled.")
	}
	if !u.MFAEnabled {
		return problem.New(problem.MFARequired, "The user has no second factor.")
	}

	var ok bool
	err = s.update(ctx, func(tx *storage.Tx) error {
		now := tx.Now()
		var err error
		ok, _, err = s.verifySecondFactorTx(ctx, tx, u, "totp", code, now)
		if err != nil && !isNoRows(err) {
			return err
		}
		if ok {
			return nil
		}
		ok, _, err = s.verifySecondFactorTx(ctx, tx, u, "recovery_code", code, now)
		return err
	})
	if err != nil {
		return err
	}
	if !ok {
		s.recordMFAFailure(ctx, u, VerifyMFAInput{ClientIP: clientIP}, "approval_code")
		return problem.New(problem.MFARequired, "The second factor is invalid.")
	}
	s.thr.Reset(key, clientIP)
	return nil
}
