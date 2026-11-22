// SPDX-License-Identifier: AGPL-3.0-only

package identity

import (
	"testing"

	"github.com/qwq-panel/qwq/internal/platform/problem"
)

const testClientIP = "198.51.100.77"

func TestVerifySecondFactorConsumesCodes(t *testing.T) {
	f := newFixture(t)
	u := f.createUser("alice", "Password123!", RoleAdmin)
	secret, codes := f.enableTOTP(u.ID)

	code := TOTPCode(secret, TOTPStep(f.clk.Now()))
	if err := f.svc.VerifySecondFactor(f.ctx, u.ID, code, testClientIP); err != nil {
		t.Fatalf("verify TOTP: %v", err)
	}
	if err := f.svc.VerifySecondFactor(f.ctx, u.ID, code, testClientIP); err == nil {
		t.Fatal("the same TOTP code was accepted twice")
	}
	if err := f.svc.VerifySecondFactor(f.ctx, u.ID, codes[0], testClientIP); err != nil {
		t.Fatalf("verify recovery code: %v", err)
	}
	if err := f.svc.VerifySecondFactor(f.ctx, u.ID, codes[0], testClientIP); err == nil {
		t.Fatal("the same recovery code was accepted twice")
	}
	if err := f.svc.VerifySecondFactor(f.ctx, u.ID, "000000", testClientIP); err == nil {
		t.Fatal("a wrong code was accepted")
	}
}

func TestVerifySecondFactorRejectsUserWithoutMFA(t *testing.T) {
	f := newFixture(t)
	u := f.createUser("bob", "Password123!", RoleAdmin)
	if err := f.svc.VerifySecondFactor(f.ctx, u.ID, "123456", testClientIP); err == nil {
		t.Fatal("verification succeeded without an enrolled second factor")
	}
}

// TestVerifySecondFactorThrottled: after three wrong codes even the right one
// is refused, every wrong code is audited, and a wrong code is MFA_REQUIRED.
func TestVerifySecondFactorThrottled(t *testing.T) {
	f := newFixture(t)
	u := f.createUser("carol", "Password123!", RoleAdmin)
	secret, _ := f.enableTOTP(u.ID)
	before := f.audit.count(ActionMFAFailed)
	for i := 0; i < DefaultThrottleOptions().Threshold; i++ {
		if err := f.svc.VerifySecondFactor(f.ctx, u.ID, "000000", testClientIP); !problem.HasCode(err, problem.MFARequired) {
			t.Fatalf("wrong code %d = %v, want MFA_REQUIRED", i+1, err)
		}
	}
	if got := f.audit.count(ActionMFAFailed) - before; got != DefaultThrottleOptions().Threshold {
		t.Fatalf("mfa failure audits = %d, want %d", got, DefaultThrottleOptions().Threshold)
	}
	code := TOTPCode(secret, TOTPStep(f.clk.Now()))
	if err := f.svc.VerifySecondFactor(f.ctx, u.ID, code, testClientIP); !problem.HasCode(err, problem.RateLimited) {
		t.Fatalf("right code after the threshold = %v, want RATE_LIMITED", err)
	}
}

// TestLoginRawNameCannotChargeSecondFactor: an invalid login username shaped
// like the second-factor throttle label must not spend that budget.
func TestLoginRawNameCannotChargeSecondFactor(t *testing.T) {
	f := newFixture(t)
	u := f.createUser("dave", "Password123!", RoleAdmin)
	secret, _ := f.enableTOTP(u.ID)
	for i := 0; i < 40; i++ {
		_, _ = f.svc.Login(f.ctx, LoginInput{Username: secondFactorThrottlePrefix + u.ID, Password: "x", ClientIP: testClientIP})
	}
	code := TOTPCode(secret, TOTPStep(f.clk.Now()))
	if err := f.svc.VerifySecondFactor(f.ctx, u.ID, code, "203.0.113.9"); err != nil {
		t.Fatalf("second factor after forged logins = %v, want nil", err)
	}
}
