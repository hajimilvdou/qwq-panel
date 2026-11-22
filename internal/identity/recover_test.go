// SPDX-License-Identifier: AGPL-3.0-only

package identity

import (
	"testing"
	"time"

	"github.com/qwq-panel/qwq/internal/platform/problem"
)

func TestResetAdmin(t *testing.T) {
	f := newFixture(t)
	admin := f.createUser("admin", testPassword, RoleAdmin)
	secret, _ := f.enableTOTP(admin.ID)
	res := f.login("admin", testPassword)
	code := TOTPCode(secret, TOTPStep(f.clk.Now()))
	done, err := f.svc.VerifyMFA(f.ctx, VerifyMFAInput{
		ChallengeID: res.MFA.ID, Method: "totp", Code: code, ClientIP: "203.0.113.7",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.ResetAdmin(f.ctx, ResetAdminInput{
		Username: "ADMIN", Password: "recovered-passphrase", Reason: "console recovery",
	}); err != nil {
		t.Fatalf("ResetAdmin: %v", err)
	}
	u := f.user(admin.ID)
	if u.MFAEnabled {
		t.Fatal("MFA still enabled after ResetAdmin")
	}
	if _, _, err := f.svc.AuthenticateSession(f.ctx, done.Token); !problem.HasCode(err, problem.Unauthenticated) {
		t.Fatal("session survived ResetAdmin")
	}
	if _, err := f.svc.Login(f.ctx, LoginInput{Username: "admin", Password: testPassword, ClientIP: "192.0.2.80"}); !problem.HasCode(err, problem.Unauthenticated) {
		t.Fatal("old password still works")
	}
	// The new password logs in without a second factor.
	if res := f.login("admin", "recovered-passphrase"); !res.Authenticated() {
		t.Fatalf("new password rejected: %+v", res)
	}
	if f.audit.count(ActionAdminRecovered) != 1 {
		t.Fatalf("recovery audits = %d", f.audit.count(ActionAdminRecovered))
	}
	if rec, ok := f.audit.last(ActionAdminRecovered); !ok || rec.Reason != "console recovery" {
		t.Fatalf("recovery audit = %+v", rec)
	}
}

func TestResetAdminRejectsOtherUsers(t *testing.T) {
	f := newFixture(t)
	f.createUser("admin", testPassword, RoleAdmin)
	op := f.createUserWithPassword("operator", testPassword, RoleOperator)
	if _, err := f.svc.ResetAdmin(f.ctx, ResetAdminInput{
		Username: "operator", Password: "replacement-passphrase",
	}); !problem.HasCode(err, problem.StateConflict) {
		t.Fatalf("ResetAdmin(operator) = %v, want STATE_CONFLICT", err)
	}
	if _, err := f.svc.ResetAdmin(f.ctx, ResetAdminInput{
		Username: "ghost", Password: "replacement-passphrase",
	}); !problem.HasCode(err, problem.NotFound) {
		t.Fatalf("ResetAdmin(ghost) = %v, want NOT_FOUND", err)
	}
	// The operator's password is untouched.
	hash, err := f.svc.PreparePassword(f.ctx, op.Username, "replacement-passphrase")
	if err != nil {
		t.Fatal(err)
	}
	_ = hash
	if _, err := f.svc.Login(f.ctx, LoginInput{Username: "operator", Password: testPassword, ClientIP: "192.0.2.90"}); err != nil {
		t.Fatalf("operator password changed: %v", err)
	}
}

func TestResetAdminValidatesPassword(t *testing.T) {
	f := newFixture(t)
	f.createUser("admin", testPassword, RoleAdmin)
	if _, err := f.svc.ResetAdmin(f.ctx, ResetAdminInput{
		Username: "admin", Password: "short",
	}); !problem.HasCode(err, problem.ValidationFailed) {
		t.Fatalf("weak password accepted: %v", err)
	}
	f.clk.Advance(time.Minute)
}
