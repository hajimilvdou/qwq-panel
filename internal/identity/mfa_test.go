// SPDX-License-Identifier: AGPL-3.0-only

package identity

import (
	"strings"
	"testing"
	"time"

	"github.com/qwq-panel/qwq/internal/platform/problem"
	"github.com/qwq-panel/qwq/internal/storage"
)

func TestMFAEnrollmentAndLogin(t *testing.T) {
	f := newFixture(t)
	u := f.createUser("alice", testPassword, RoleAdmin)
	secret, codes := f.enableTOTP(u.ID)
	if len(codes) != RecoveryCodeCount {
		t.Fatalf("recovery codes = %d, want %d", len(codes), RecoveryCodeCount)
	}
	seen := map[string]bool{}
	for _, c := range codes {
		if seen[c] {
			t.Fatal("duplicate recovery code")
		}
		seen[c] = true
	}
	if got := f.user(u.ID); !got.MFAEnabled {
		t.Fatal("user does not report MFA enabled")
	}
	if f.audit.count(ActionMFAEnabled) != 1 {
		t.Fatalf("MFA enable audits = %d", f.audit.count(ActionMFAEnabled))
	}
	// The password step now returns a challenge instead of a session.
	res := f.login("alice", testPassword)
	if res.Authenticated() || res.MFA == nil {
		t.Fatalf("login with MFA enabled = %+v", res)
	}
	if len(res.MFA.Methods) != 2 || res.MFA.Methods[0] != "totp" || res.MFA.Methods[1] != "recovery_code" {
		t.Fatalf("methods = %v", res.MFA.Methods)
	}
	code := TOTPCode(secret, TOTPStep(f.clk.Now()))
	done, err := f.svc.VerifyMFA(f.ctx, VerifyMFAInput{
		ChallengeID: res.MFA.ID, Method: "totp", Code: code, ClientIP: "203.0.113.7",
	})
	if err != nil {
		t.Fatalf("verify MFA: %v", err)
	}
	if !done.Authenticated() || done.Session.MFAVerifiedAt.IsZero() {
		t.Fatalf("MFA result = %+v", done)
	}
	a, _, err := f.svc.AuthenticateSession(f.ctx, done.Token)
	if err != nil || !a.MFA {
		t.Fatalf("authenticated actor after MFA = %+v, %v", a, err)
	}
	// The challenge is single use.
	if _, err := f.svc.VerifyMFA(f.ctx, VerifyMFAInput{
		ChallengeID: res.MFA.ID, Method: "totp", Code: code, ClientIP: "203.0.113.7",
	}); !problem.HasCode(err, problem.Unauthenticated) {
		t.Fatalf("reused challenge: %v", err)
	}
	// Replaying the same TOTP step on a new challenge is refused.
	next := f.login("alice", testPassword)
	if _, err := f.svc.VerifyMFA(f.ctx, VerifyMFAInput{
		ChallengeID: next.MFA.ID, Method: "totp", Code: code, ClientIP: "203.0.113.7",
	}); !problem.HasCode(err, problem.Unauthenticated) {
		t.Fatalf("replayed TOTP accepted: %v", err)
	}
	// The next step works and the challenge survives the failed attempt.
	f.clk.Advance(TOTPPeriod * time.Second)
	fresh := TOTPCode(secret, TOTPStep(f.clk.Now()))
	if _, err := f.svc.VerifyMFA(f.ctx, VerifyMFAInput{
		ChallengeID: next.MFA.ID, Method: "totp", Code: fresh, ClientIP: "203.0.113.7",
	}); err != nil {
		t.Fatalf("second step rejected: %v", err)
	}
}

func TestMFARecoveryCode(t *testing.T) {
	f := newFixture(t)
	u := f.createUser("alice", testPassword, RoleAdmin)
	_, codes := f.enableTOTP(u.ID)
	res := f.login("alice", testPassword)
	done, err := f.svc.VerifyMFA(f.ctx, VerifyMFAInput{
		ChallengeID: res.MFA.ID, Method: "recovery_code", Code: codes[0], ClientIP: "203.0.113.7",
	})
	if err != nil || !done.Authenticated() {
		t.Fatalf("recovery code login: %+v %v", done, err)
	}
	if f.audit.count(ActionRecoveryUsed) != 1 {
		t.Fatalf("recovery audits = %d", f.audit.count(ActionRecoveryUsed))
	}
	// A recovery code is single use.
	next := f.login("alice", testPassword)
	if _, err := f.svc.VerifyMFA(f.ctx, VerifyMFAInput{
		ChallengeID: next.MFA.ID, Method: "recovery_code", Code: codes[0], ClientIP: "203.0.113.7",
	}); !problem.HasCode(err, problem.Unauthenticated) {
		t.Fatalf("reused recovery code accepted: %v", err)
	}
	// A code with different separators is the same code.
	if _, err := f.svc.VerifyMFA(f.ctx, VerifyMFAInput{
		ChallengeID: next.MFA.ID, Method: "recovery_code", Code: codes[1], ClientIP: "203.0.113.7",
	}); err != nil {
		t.Fatalf("second recovery code rejected: %v", err)
	}
}

func TestDisableTOTP(t *testing.T) {
	f := newFixture(t)
	u := f.createUser("alice", testPassword, RoleAdmin)
	secret, codes := f.enableTOTP(u.ID)
	if len(codes) == 0 {
		t.Fatal("no recovery codes")
	}
	rev := f.user(u.ID).Revision
	code := TOTPCode(secret, TOTPStep(f.clk.Now()))
	var updated User
	f.update(func(tx *storage.Tx) error {
		var err error
		updated, err = f.svc.DisableTOTP(f.ctx, tx, DisableTOTPInput{
			UserID: u.ID, ExpectedRevision: rev, Method: "totp", Code: code,
		})
		return err
	})
	if updated.MFAEnabled {
		t.Fatal("MFA still enabled after DisableTOTP")
	}
	if f.audit.count(ActionMFADisabled) != 1 {
		t.Fatalf("MFA disable audits = %d", f.audit.count(ActionMFADisabled))
	}
	// Login no longer asks for a second factor.
	if res := f.login("alice", testPassword); !res.Authenticated() {
		t.Fatal("login still requires a second factor")
	}
}

func TestMFAChallengeAttemptLimit(t *testing.T) {
	f := newFixture(t)
	u := f.createUser("alice", testPassword, RoleAdmin)
	secret, _ := f.enableTOTP(u.ID)
	res := f.login("alice", testPassword)
	// Reset the password throttle each round so this test only exercises the
	// per-challenge attempt counter.
	for i := 0; i < DefaultMaxMFAChallengeAttempts+1; i++ {
		f.svc.thr.Reset("alice", "203.0.113.7")
		if _, err := f.svc.VerifyMFA(f.ctx, VerifyMFAInput{
			ChallengeID: res.MFA.ID, Method: "totp", Code: "000000", ClientIP: "203.0.113.7",
		}); err == nil {
			t.Fatal("wrong code accepted")
		}
	}
	// Even the right code cannot reopen an exhausted challenge.
	f.svc.thr.Reset("alice", "203.0.113.7")
	f.clk.Advance(TOTPPeriod * time.Second)
	if _, err := f.svc.VerifyMFA(f.ctx, VerifyMFAInput{
		ChallengeID: res.MFA.ID, Method: "totp",
		Code: TOTPCode(secret, TOTPStep(f.clk.Now())), ClientIP: "203.0.113.7",
	}); !problem.HasCode(err, problem.Unauthenticated) {
		t.Fatalf("exhausted challenge accepted: %v", err)
	}
}

// TestLoginPendingMFAKeepsCharge covers a correct password without its second
// factor: the charge stays until the factor is answered, which also limits how
// fast challenges can be generated.
func TestLoginPendingMFAKeepsCharge(t *testing.T) {
	f := newFixture(t)
	u := f.createUser("alice", testPassword, RoleAdmin)
	secret, _ := f.enableTOTP(u.ID)
	var pending LoginResult
	for i := 0; i < DefaultThrottleOptions().Threshold; i++ {
		pending = f.login("alice", testPassword)
		if pending.MFA == nil {
			t.Fatalf("login %d did not return a challenge: %+v", i+1, pending)
		}
	}
	_, err := f.svc.Login(f.ctx, LoginInput{Username: "alice", Password: testPassword, ClientIP: "203.0.113.7"})
	if !problem.HasCode(err, problem.RateLimited) {
		t.Fatalf("challenge generation was not throttled: %v", err)
	}
	f.clk.Advance(2 * time.Second)
	done, err := f.svc.VerifyMFA(f.ctx, VerifyMFAInput{
		ChallengeID: pending.MFA.ID, Method: "totp",
		Code: TOTPCode(secret, TOTPStep(f.clk.Now())), ClientIP: "203.0.113.7",
	})
	if err != nil || !done.Authenticated() {
		t.Fatalf("verify MFA: %+v %v", done, err)
	}
	for k := range f.svc.thr.entries {
		if strings.HasPrefix(k, pairKeyPrefix) {
			t.Fatalf("completed authentication left %q", k)
		}
	}
}

// TestVerifyMFAChargesEachAttempt spends the budget with wrong codes. The login
// holds one charge, so the third submission finds the delay armed and is
// refused before the code is looked at.
func TestVerifyMFAChargesEachAttempt(t *testing.T) {
	f := newFixture(t)
	u := f.createUser("alice", testPassword, RoleAdmin)
	secret, _ := f.enableTOTP(u.ID)
	res := f.login("alice", testPassword)
	wrong := VerifyMFAInput{ChallengeID: res.MFA.ID, Method: "totp", Code: "000000", ClientIP: "203.0.113.7"}
	for i := 0; i < 2; i++ {
		if _, err := f.svc.VerifyMFA(f.ctx, wrong); !problem.HasCode(err, problem.Unauthenticated) {
			t.Fatalf("wrong code %d: %v", i+1, err)
		}
	}
	if _, err := f.svc.VerifyMFA(f.ctx, wrong); !problem.HasCode(err, problem.RateLimited) {
		t.Fatalf("third submission was not throttled: %v", err)
	}
	var attempts int
	if err := f.db.Reader().QueryRowContext(f.ctx, `SELECT attempts FROM mfa_challenges`).Scan(&attempts); err != nil {
		t.Fatal(err)
	}
	if attempts != 2 {
		t.Fatalf("challenge attempts = %d, want 2: the refused code must not be checked", attempts)
	}
	f.clk.Advance(2 * time.Second)
	if _, err := f.svc.VerifyMFA(f.ctx, VerifyMFAInput{
		ChallengeID: res.MFA.ID, Method: "totp",
		Code: TOTPCode(secret, TOTPStep(f.clk.Now())), ClientIP: "203.0.113.7",
	}); err != nil {
		t.Fatalf("right code after the delay: %v", err)
	}
}

func TestMFAElevationRotatesSession(t *testing.T) {
	f := newFixture(t)
	u := f.createUser("alice", testPassword, RoleAdmin)
	secret, _ := f.enableTOTP(u.ID)
	first := f.login("alice", testPassword)
	code := TOTPCode(secret, TOTPStep(f.clk.Now()))
	done, err := f.svc.VerifyMFA(f.ctx, VerifyMFAInput{
		ChallengeID: first.MFA.ID, Method: "totp", Code: code, ClientIP: "203.0.113.7",
	})
	if err != nil {
		t.Fatal(err)
	}
	// Elevate the existing session with a fresh challenge.
	f.clk.Advance(TOTPPeriod * time.Second)
	challenge := f.login("alice", testPassword)
	next := TOTPCode(secret, TOTPStep(f.clk.Now()))
	elevated, err := f.svc.VerifyMFA(f.ctx, VerifyMFAInput{
		ChallengeID: challenge.MFA.ID, Method: "totp", Code: next,
		ClientIP: "203.0.113.7", SessionToken: done.Token,
	})
	if err != nil {
		t.Fatalf("elevate: %v", err)
	}
	if elevated.Session.ID == done.Session.ID {
		t.Fatal("session ID was not rotated")
	}
	if !elevated.Session.CreatedAt.Equal(done.Session.CreatedAt) ||
		!elevated.Session.ExpiresAt.Equal(done.Session.ExpiresAt) {
		t.Fatal("rotation did not preserve the absolute deadline")
	}
	if _, _, err := f.svc.AuthenticateSession(f.ctx, done.Token); !problem.HasCode(err, problem.Unauthenticated) {
		t.Fatalf("old session survived rotation: %v", err)
	}
	if _, _, err := f.svc.AuthenticateSession(f.ctx, elevated.Token); err != nil {
		t.Fatalf("rotated session is not usable: %v", err)
	}
}

func TestEnableTOTPWithoutEnrollment(t *testing.T) {
	f := newFixture(t)
	u := f.createUser("alice", testPassword, RoleAdmin)
	f.try(func(tx *storage.Tx) error {
		_, _, err := f.svc.EnableTOTP(f.ctx, tx, EnableTOTPInput{
			UserID: u.ID, ExpectedRevision: u.Revision, Code: "123456",
		})
		return err
	}, problem.StateConflict)
}

func TestTOTPEnrollmentExpires(t *testing.T) {
	f := newFixture(t)
	u := f.createUser("alice", testPassword, RoleAdmin)
	enr, err := f.svc.BeginTOTPEnrollment(f.ctx, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	f.clk.Advance(DefaultTOTPEnrollmentTTL + time.Minute)
	secret, err := totpEncoding.DecodeString(enr.Secret)
	if err != nil {
		t.Fatal(err)
	}
	code := TOTPCode(secret, TOTPStep(f.clk.Now()))
	f.try(func(tx *storage.Tx) error {
		_, _, err := f.svc.EnableTOTP(f.ctx, tx, EnableTOTPInput{
			UserID: u.ID, ExpectedRevision: enr.Revision, Code: code,
		})
		return err
	}, problem.StateConflict)
}

// TestVerifyMFAIgnoresStaleOrForeignCookie: the challenge already proves the
// password and the second factor, so a revoked or foreign session cookie left
// in the browser is ignored and a fresh session is issued instead of a 401.
func TestVerifyMFAIgnoresStaleOrForeignCookie(t *testing.T) {
	f := newFixture(t)
	u := f.createUser("alice", testPassword, RoleAdmin)
	f.createUser("bob", testPassword, RoleAdmin)
	secret, _ := f.enableTOTP(u.ID)
	verify := func(token string) LoginResult {
		t.Helper()
		f.clk.Advance(TOTPPeriod * time.Second)
		ch := f.login("alice", testPassword)
		res, err := f.svc.VerifyMFA(f.ctx, VerifyMFAInput{
			ChallengeID: ch.MFA.ID, Method: "totp", Code: TOTPCode(secret, TOTPStep(f.clk.Now())),
			ClientIP: "203.0.113.7", SessionToken: token,
		})
		if err != nil {
			t.Fatalf("verify with cookie: %v", err)
		}
		if !res.Authenticated() || res.Session.User.ID != u.ID {
			t.Fatalf("result = %+v", res)
		}
		return res
	}
	revoked := verify("")
	if err := f.svc.Logout(f.ctx, revoked.Token); err != nil {
		t.Fatal(err)
	}
	if res := verify(revoked.Token); res.Session.ID == revoked.Session.ID {
		t.Fatal("revoked session was reused")
	}
	foreign := f.login("bob", testPassword)
	res := verify(foreign.Token)
	if res.Session.ID == foreign.Session.ID {
		t.Fatal("foreign session was elevated")
	}
	if _, _, err := f.svc.AuthenticateSession(f.ctx, foreign.Token); err != nil {
		t.Fatalf("foreign session was touched: %v", err)
	}
}
