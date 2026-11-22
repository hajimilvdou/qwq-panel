// SPDX-License-Identifier: AGPL-3.0-only

package identity

import (
	"errors"
	"testing"
	"time"

	"github.com/qwq-panel/qwq/internal/actor"
	"github.com/qwq-panel/qwq/internal/platform/problem"
	"github.com/qwq-panel/qwq/internal/secrets"
	"github.com/qwq-panel/qwq/internal/storage"
)

func assertUserTOTPSecrets(t *testing.T, f *fixture, userID string, want int) {
	t.Helper()
	var count int
	if err := f.db.Reader().QueryRowContext(f.ctx,
		`SELECT COUNT(*) FROM secrets WHERE owner=? AND purpose=?`, "users/"+userID, PurposeTOTP).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != want {
		t.Fatalf("user TOTP ciphertext count=%d, want=%d", count, want)
	}
}

func TestTOTPEnrollmentRollbackAndCurrentCredentialScope(t *testing.T) {
	f := newFixture(t)
	u := f.createUser("alice", testPassword, RoleAdmin)
	other := f.createUser("bob", testPassword, RoleOperator)
	if _, err := f.svc.BeginTOTPEnrollment(f.ctx, u.ID); err != nil {
		t.Fatal(err)
	}
	assertUserTOTPSecrets(t, f, u.ID, 1)
	var original string
	if err := f.db.Reader().QueryRowContext(f.ctx,
		`SELECT secret FROM credentials WHERE user_id=? AND type='totp_pending'`, u.ID).Scan(&original); err != nil {
		t.Fatal(err)
	}
	f.update(func(tx *storage.Tx) error {
		_, err := tx.ExecContext(f.ctx, `CREATE TRIGGER test_reject_totp BEFORE INSERT ON credentials
			WHEN NEW.type='totp_pending' BEGIN SELECT RAISE(ABORT, 'TEST-ONLY-enrollment-failure'); END`)
		return err
	})
	if _, err := f.svc.BeginTOTPEnrollment(f.ctx, u.ID); err == nil {
		t.Fatal("the fixture did not reject the second enrollment")
	}
	assertUserTOTPSecrets(t, f, u.ID, 1)
	f.update(func(tx *storage.Tx) error {
		value, err := f.sealer.OpenCredential(f.ctx, tx, u.ID, PurposeTOTP, original)
		defer clear(value)
		if err != nil || len(value) == 0 {
			t.Fatal("enrollment rollback lost the original credential")
		}
		_, err = f.sealer.OpenCredential(f.ctx, tx, other.ID, PurposeTOTP, original)
		if !problem.HasCode(err, problem.NotFound) {
			t.Fatal("another user revealed the credential secret")
		}
		unattached, err := f.sealer.SealCredential(f.ctx, tx, u.ID, PurposeTOTP, []byte("TEST-ONLY-unattached-credential"))
		if err != nil {
			return err
		}
		_, err = f.sealer.OpenCredential(f.ctx, tx, u.ID, PurposeTOTP, unattached)
		if !problem.HasCode(err, problem.NotFound) {
			t.Fatal("an unbound secret passed the current credential member check")
		}
		return f.sealer.Delete(f.ctx, tx, secrets.Ref(unattached))
	})
}

func TestTOTPRebindAndDisableReclaimCiphertext(t *testing.T) {
	f := newFixture(t)
	u := f.createUser("alice", testPassword, RoleAdmin)
	oldSecret, _ := f.enableTOTP(u.ID)
	defer clear(oldSecret)
	enrollment, err := f.svc.BeginTOTPEnrollment(f.ctx, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	newSecret, err := totpEncoding.DecodeString(enrollment.Secret)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(newSecret)
	assertUserTOTPSecrets(t, f, u.ID, 2)
	code := TOTPCode(newSecret, TOTPStep(f.clk.Now()))
	f.try(func(tx *storage.Tx) error {
		_, _, err := f.svc.EnableTOTP(f.ctx, tx, EnableTOTPInput{
			UserID: u.ID, ExpectedRevision: enrollment.Revision, Code: code,
		})
		return err
	}, problem.MFARequired)
	assertUserTOTPSecrets(t, f, u.ID, 2)
	f.update(func(tx *storage.Tx) error {
		_, _, err := f.svc.EnableTOTP(f.ctx, tx, EnableTOTPInput{
			UserID: u.ID, ExpectedRevision: enrollment.Revision, Code: code,
			Actor: actor.Actor{Kind: actor.Human, ID: u.ID, MFA: true},
		})
		return err
	})
	assertUserTOTPSecrets(t, f, u.ID, 1)
	f.clk.Advance(TOTPPeriod * time.Second)
	f.update(func(tx *storage.Tx) error {
		_, err := f.svc.DisableTOTP(f.ctx, tx, DisableTOTPInput{
			UserID: u.ID, ExpectedRevision: f.user(u.ID).Revision,
			Method: "totp", Code: TOTPCode(newSecret, TOTPStep(f.clk.Now())),
		})
		return err
	})
	assertUserTOTPSecrets(t, f, u.ID, 0)
}

func TestTOTPExpiredPendingDeletionRecoveryAndLegacyOwner(t *testing.T) {
	for _, cleanup := range []string{"expire pending", "delete user", "recover admin"} {
		t.Run(cleanup, func(t *testing.T) {
			f := newFixture(t)
			u := f.createUser("alice", testPassword, RoleAdmin)
			secret, _ := f.enableTOTP(u.ID)
			defer clear(secret)
			if _, err := f.svc.BeginTOTPEnrollment(f.ctx, u.ID); err != nil {
				t.Fatal(err)
			}
			assertUserTOTPSecrets(t, f, u.ID, 2)
			switch cleanup {
			case "expire pending":
				f.clk.Advance(f.svc.totpEnrollTTL + time.Millisecond)
				if err := f.svc.Prune(f.ctx, f.clk.Now()); err != nil {
					t.Fatal(err)
				}
				assertUserTOTPSecrets(t, f, u.ID, 1)
			case "delete user":
				f.createUser("backup", testPassword, RoleAdmin)
				f.update(func(tx *storage.Tx) error {
					return f.svc.DeleteUser(f.ctx, tx, DeleteUserInput{UserID: u.ID, ExpectedRevision: f.user(u.ID).Revision})
				})
				assertUserTOTPSecrets(t, f, u.ID, 0)
			case "recover admin":
				if _, err := f.svc.ResetAdmin(f.ctx, ResetAdminInput{Username: u.Username, Password: "TEST-ONLY-recovered-password", Reason: "test recovery"}); err != nil {
					t.Fatal(err)
				}
				assertUserTOTPSecrets(t, f, u.ID, 0)
			}
		})
	}
	t.Run("legacy owner", func(t *testing.T) {
		f := newFixture(t)
		u := f.createUser("alice", testPassword, RoleAdmin)
		legacy, err := f.sealer.Seal(f.ctx, PurposeTOTP, []byte("TEST-ONLY-legacy-TOTP"))
		if err != nil {
			t.Fatal(err)
		}
		f.update(func(tx *storage.Tx) error {
			if err := insertCredentialTx(f.ctx, tx, u.ID, credTOTP, legacy, "{}", 0, tx.Now()); err != nil {
				return err
			}
			value, err := f.sealer.OpenCredential(f.ctx, tx, u.ID, PurposeTOTP, legacy)
			defer clear(value)
			if err != nil || string(value) != "TEST-ONLY-legacy-TOTP" {
				t.Fatal("a valid legacy credential could not be opened")
			}
			return deleteCredentialsTx(f.ctx, tx, u.ID, credTOTP)
		})
		_, err = f.sealer.RevealOwned(f.ctx, secrets.Ref(legacy), secrets.SystemOwner, PurposeTOTP)
		if !problem.HasCode(err, problem.NotFound) {
			t.Fatal("legacy credential deletion left ciphertext")
		}
	})
}

func TestCredentialDeletionRollsBackWithBusinessFailure(t *testing.T) {
	f := newFixture(t)
	u := f.createUser("alice", testPassword, RoleAdmin)
	secret, _ := f.enableTOTP(u.ID)
	defer clear(secret)
	rollback := errors.New("TEST-ONLY-business-rollback")
	if err := f.db.Update(f.ctx, func(tx *storage.Tx) error {
		if err := deleteCredentialsTx(f.ctx, tx, u.ID, credTOTP); err != nil {
			return err
		}
		return rollback
	}); !errors.Is(err, rollback) {
		t.Fatal("credential deletion did not roll back")
	}
	assertUserTOTPSecrets(t, f, u.ID, 1)
	if !f.user(u.ID).MFAEnabled {
		t.Fatal("failed deletion disabled the second factor")
	}
}
