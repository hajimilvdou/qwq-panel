// SPDX-License-Identifier: AGPL-3.0-only

package identity

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/qwq-panel/qwq/internal/actor"
	"github.com/qwq-panel/qwq/internal/platform/problem"
	"github.com/qwq-panel/qwq/internal/storage"
)

// ======================== 失效链接不能占用真实哈希槽 ========================

func TestSetupRejectsInvalidTokenBeforeHashing(t *testing.T) {
	for _, state := range []string{"missing", "unknown", "used", "expired", "superseded"} {
		t.Run(state, func(t *testing.T) {
			f := newFixture(t)
			token, _, err := f.svc.NewSetupToken(f.ctx)
			if err != nil {
				t.Fatal(err)
			}
			switch state {
			case "missing":
				token = ""
			case "unknown":
				token = strings.Repeat("A", 43)
			case "used":
				f.update(func(tx *storage.Tx) error {
					_, err := tx.ExecContext(f.ctx, `UPDATE one_time_tokens SET used_at = ? WHERE purpose = ? AND token_hash = ?`, formatTime(tx.Now()), purposeSetup, hashToken(token))
					return err
				})
			case "expired":
				f.clk.Advance(DefaultSetupTokenTTL + time.Second)
			case "superseded":
				if _, _, err := f.svc.NewSetupToken(f.ctx); err != nil {
					t.Fatal(err)
				}
			}
			release := fillSemaphore(f.svc.hasher)
			defer release()
			ctx, cancel := context.WithTimeout(f.ctx, 50*time.Millisecond)
			defer cancel()
			_, err = f.svc.CompleteSetup(ctx, CompleteSetupInput{SetupToken: token, Username: "admin", Password: testPassword})
			if !problem.HasCode(err, problem.Unauthenticated) {
				t.Fatalf("invalid setup token reached the occupied hasher: %v", err)
			}
			if initialized, err := f.svc.SetupInitialized(f.ctx); err != nil || initialized {
				t.Fatalf("rejected setup created an administrator: initialized=%v error=%v", initialized, err)
			}
		})
	}
}

func TestEnrollmentRejectsInvalidTokenBeforeHashing(t *testing.T) {
	for _, state := range []string{"used", "expired", "superseded", "wrong_purpose"} {
		t.Run(state, func(t *testing.T) {
			f := newFixture(t)
			u := f.createPendingUser("newbie")
			token, _, err := f.enrollmentToken(u.ID)
			if err != nil {
				t.Fatal(err)
			}
			switch state {
			case "used":
				f.update(func(tx *storage.Tx) error {
					_, err := tx.ExecContext(f.ctx, `UPDATE one_time_tokens SET used_at = ? WHERE purpose = ? AND token_hash = ?`, formatTime(tx.Now()), purposeEnroll, hashToken(token))
					return err
				})
			case "expired":
				f.clk.Advance(DefaultEnrollmentTokenTTL + time.Second)
			case "superseded":
				if _, _, err := f.enrollmentToken(u.ID); err != nil {
					t.Fatal(err)
				}
			case "wrong_purpose":
				token, _, err = f.svc.NewSetupToken(f.ctx)
				if err != nil {
					t.Fatal(err)
				}
			}
			release := fillSemaphore(f.svc.hasher)
			defer release()
			ctx, cancel := context.WithTimeout(f.ctx, 50*time.Millisecond)
			defer cancel()
			if _, err := f.svc.RedeemEnrollmentToken(ctx, token, testPassword); !problem.HasCode(err, problem.Unauthenticated) {
				t.Fatalf("invalid enrollment token reached the occupied hasher: %v", err)
			}
		})
	}
}

func TestValidOneTimeTokenStillWaitsForHasher(t *testing.T) {
	f := newFixture(t)
	token, _, err := f.svc.NewSetupToken(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	release := fillSemaphore(f.svc.hasher)
	ctx, cancel := context.WithTimeout(f.ctx, 50*time.Millisecond)
	_, err = f.svc.CompleteSetup(ctx, CompleteSetupInput{SetupToken: token, Username: "admin", Password: testPassword})
	cancel()
	release()
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("valid setup token bypassed the occupied hasher: %v", err)
	}
	if _, err := f.svc.CompleteSetup(f.ctx, CompleteSetupInput{SetupToken: token, Username: "admin", Password: testPassword}); err != nil {
		t.Fatalf("hash cancellation consumed the setup token: %v", err)
	}
}

// ======================== 首次密码权限与有界猜测节流 ========================

func TestEnrollmentCannotReplacePasswordSetByAdministrator(t *testing.T) {
	f := newFixture(t)
	admin := f.createUser("admin", testPassword, RoleAdmin)
	u := f.createPendingUser("newbie")
	other := f.createPendingUser("other")
	otherToken, _, err := f.enrollmentToken(other.ID)
	if err != nil {
		t.Fatal(err)
	}
	token, _, err := f.enrollmentToken(u.ID)
	if err != nil {
		t.Fatal(err)
	}
	hash, err := f.svc.PreparePassword(f.ctx, u.Username, testPassword)
	if err != nil {
		t.Fatal(err)
	}
	f.update(func(tx *storage.Tx) error {
		_, err := f.svc.ResetPassword(f.ctx, tx, ResetPasswordInput{UserID: u.ID, ExpectedRevision: u.Revision, PasswordHash: hash, Actor: actor.Actor{Kind: actor.Human, ID: admin.ID}})
		return err
	})
	if _, err := f.svc.RedeemEnrollmentToken(f.ctx, token, "attacker-controlled-passphrase"); !problem.HasCode(err, problem.Unauthenticated) {
		t.Fatalf("old first-password link replaced the administrator's password: %v", err)
	}
	if stored, err := f.svc.passwordHash(f.ctx, u.ID); err != nil || stored != hash {
		t.Fatalf("rejected enrollment changed the credential: %v", err)
	}
	if _, err := f.svc.RedeemEnrollmentToken(f.ctx, otherToken, testPassword); err != nil {
		t.Fatalf("password reset revoked another user's first-password link: %v", err)
	}
}

func TestOneTimeTokenEntryThrottle(t *testing.T) {
	for _, purpose := range []string{purposeSetup, purposeEnroll} {
		t.Run(purpose, func(t *testing.T) {
			f := newFixture(t)
			token := strings.Repeat("A", 43)
			attempt := func() error {
				if purpose == purposeSetup {
					_, err := f.svc.CompleteSetup(f.ctx, CompleteSetupInput{SetupToken: token, Username: "admin", Password: testPassword, ClientIP: "192.0.2.77"})
					return err
				}
				_, err := f.svc.RedeemEnrollment(f.ctx, RedeemEnrollmentInput{Token: token, Password: testPassword, ClientIP: "192.0.2.77"})
				return err
			}
			for range DefaultThrottleOptions().Threshold {
				if err := attempt(); !problem.HasCode(err, problem.Unauthenticated) {
					t.Fatalf("initial invalid token attempt: %v", err)
				}
			}
			if err := attempt(); !problem.HasCode(err, problem.RateLimited) {
				t.Fatalf("token guesses bypassed progressive backoff: %v", err)
			}
		})
	}
}

// ======================== 明确跨过哈希的事务前状态变更 ========================

// runAtHashBoundary 用真实 Hasher 的收发握手观测哈希已开始，并暂停其返回。
// 变更在此时提交，测试就不能把哈希前的拒绝误算为写事务中的再次核验。
func runAtHashBoundary(t *testing.T, f *fixture, run func(context.Context) error, change func()) error {
	t.Helper()
	original := f.svc.hasher.sem
	boundary := make(chan struct{})
	f.svc.hasher.sem = boundary
	ctx, cancel := context.WithTimeout(f.ctx, 5*time.Second)
	result := make(chan error, 1)
	var releaseOnce sync.Once
	acquired, collected := false, false
	release := func() {
		if acquired {
			releaseOnce.Do(func() { boundary <- struct{}{} })
		}
	}
	t.Cleanup(func() {
		cancel()
		release()
		if !collected {
			select {
			case <-result:
			case <-time.After(5 * time.Second):
				t.Error("one-time token worker did not finish during cleanup")
			}
		}
		f.svc.hasher.sem = original
	})
	go func() { result <- run(ctx) }()
	select {
	case <-boundary:
		acquired = true
	case err := <-result:
		collected = true
		t.Fatalf("the hash boundary was not exercised: %v", err)
	case <-ctx.Done():
		t.Fatal("one-time token request did not reach the hash boundary")
	}
	change()
	release()
	select {
	case err := <-result:
		collected = true
		return err
	case <-ctx.Done():
		t.Fatal("one-time token request did not finish after the state change")
		return ctx.Err()
	}
}

func TestEnrollmentRechecksStateAfterHashing(t *testing.T) {
	for _, state := range []string{"disabled", "password", "token_replaced", "expired"} {
		t.Run(state, func(t *testing.T) {
			f := newFixture(t)
			u := f.createPendingUser("newbie")
			token, _, err := f.enrollmentToken(u.ID)
			if err != nil {
				t.Fatal(err)
			}
			hash, err := f.svc.PreparePassword(f.ctx, u.Username, testPassword)
			if err != nil {
				t.Fatal(err)
			}
			err = runAtHashBoundary(t, f, func(ctx context.Context) error {
				_, err := f.svc.RedeemEnrollmentToken(ctx, token, "new-first-password-passphrase")
				return err
			}, func() {
				switch state {
				case "disabled":
					disabled := true
					f.update(func(tx *storage.Tx) error {
						_, err := f.svc.UpdateUser(f.ctx, tx, UpdateUserInput{UserID: u.ID, ExpectedRevision: u.Revision, Disabled: &disabled})
						return err
					})
				case "password":
					// 单独验证当前密码状态；不借管理员重置对 token 的撤销提前拒绝。
					f.update(func(tx *storage.Tx) error {
						return insertCredentialTx(f.ctx, tx, u.ID, credPassword, hash, "{}", 0, tx.Now())
					})
				case "token_replaced":
					if _, _, err := f.enrollmentToken(u.ID); err != nil {
						t.Fatal(err)
					}
				case "expired":
					f.clk.Advance(DefaultEnrollmentTokenTTL + time.Second)
				}
			})
			want := problem.Unauthenticated
			if state == "disabled" {
				want = problem.PermissionDenied
			}
			if !problem.HasCode(err, want) {
				t.Fatalf("enrollment ignored the state change during hashing: %v", err)
			}
			if state == "password" {
				if stored, err := f.svc.passwordHash(f.ctx, u.ID); err != nil || stored != hash {
					t.Fatalf("enrollment replaced the concurrent password: %v", err)
				}
			}
		})
	}
}

func TestSetupRechecksStateAfterHashing(t *testing.T) {
	for _, state := range []string{"initialized", "token_replaced"} {
		t.Run(state, func(t *testing.T) {
			f := newFixture(t)
			token, _, err := f.svc.NewSetupToken(f.ctx)
			if err != nil {
				t.Fatal(err)
			}
			hash, err := f.svc.PreparePassword(f.ctx, "owner", testPassword)
			if err != nil {
				t.Fatal(err)
			}
			err = runAtHashBoundary(t, f, func(ctx context.Context) error {
				_, err := f.svc.CompleteSetup(ctx, CompleteSetupInput{SetupToken: token, Username: "admin", Password: testPassword})
				return err
			}, func() {
				if state == "initialized" {
					f.update(func(tx *storage.Tx) error {
						_, err := f.svc.CreateUser(f.ctx, tx, CreateUserInput{Username: "owner", Role: RoleAdmin, PasswordHash: hash})
						return err
					})
				} else if _, _, err := f.svc.NewSetupToken(f.ctx); err != nil {
					t.Fatal(err)
				}
			})
			want := problem.Unauthenticated
			if state == "initialized" {
				want = problem.StateConflict
			}
			if !problem.HasCode(err, want) {
				t.Fatalf("setup ignored the state change during hashing: %v", err)
			}
		})
	}
}
