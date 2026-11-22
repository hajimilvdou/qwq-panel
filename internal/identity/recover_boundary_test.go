// SPDX-License-Identifier: AGPL-3.0-only

package identity

import (
	"context"
	"testing"
	"time"

	"github.com/qwq-panel/qwq/internal/platform/problem"
	"github.com/qwq-panel/qwq/internal/storage"
)

// ======================== 禁用管理员的真实登录恢复 ========================

func TestResetAdminRestoresDisabledAccount(t *testing.T) {
	f := newFixture(t)
	admin := f.createUser("admin", testPassword, RoleAdmin)
	f.createUser("backup", testPassword, RoleAdmin)
	oldSession := f.login(admin.Username, testPassword)
	disabled := true
	f.update(func(tx *storage.Tx) error {
		_, err := f.svc.UpdateUser(f.ctx, tx, UpdateUserInput{
			UserID: admin.ID, ExpectedRevision: admin.Revision, Disabled: &disabled,
		})
		return err
	})
	before := f.user(admin.ID)
	f.clk.Advance(time.Second)

	u, err := f.svc.ResetAdmin(f.ctx, ResetAdminInput{
		Username: "ADMIN", Password: "fixture-recovered-passphrase", Reason: "fixture console recovery",
	})
	if err != nil {
		t.Fatalf("recover disabled administrator: %v", err)
	}
	if u.Disabled || u.Role != RoleAdmin || u.Revision <= before.Revision {
		t.Fatalf("recovery did not enable the current administrator: disabled=%v role=%s revision=%d", u.Disabled, u.Role, u.Revision)
	}
	if res := f.login(admin.Username, "fixture-recovered-passphrase"); !res.Authenticated() {
		t.Fatal("recovered administrator cannot log in")
	}
	if _, _, err := f.svc.AuthenticateSession(f.ctx, oldSession.Token); !problem.HasCode(err, problem.Unauthenticated) {
		t.Fatalf("old session survived administrator recovery: %v", err)
	}
	if f.audit.count(ActionAdminRecovered) != 1 {
		t.Fatal("administrator recovery did not record exactly one audit")
	}
}

// ======================== 哈希后再次核验，拒绝改写已降级的用户 ========================

func TestResetAdminRejectsRoleChangeAfterHashing(t *testing.T) {
	f := newFixture(t)
	admin := f.createUser("admin", testPassword, RoleAdmin)
	f.createUser("backup", testPassword, RoleAdmin)
	secret, _ := f.enableTOTP(admin.ID)
	defer clear(secret)
	originalHash, err := f.svc.passwordHash(f.ctx, admin.ID)
	if err != nil {
		t.Fatal(err)
	}
	var changed User
	err = runAtHashBoundary(t, f, func(ctx context.Context) error {
		_, err := f.svc.ResetAdmin(ctx, ResetAdminInput{
			Username: admin.Username, Password: "fixture-recovered-passphrase", Reason: "fixture role race",
		})
		return err
	}, func() {
		operator := RoleOperator
		f.update(func(tx *storage.Tx) error {
			var err error
			changed, err = f.svc.UpdateUser(f.ctx, tx, UpdateUserInput{
				UserID: admin.ID, ExpectedRevision: f.user(admin.ID).Revision, Role: &operator,
			})
			return err
		})
	})
	if !problem.HasCode(err, problem.StateConflict) {
		t.Fatalf("recovery ignored the role change during hashing: %v", err)
	}
	after := f.user(admin.ID)
	if after.Role != RoleOperator || !after.MFAEnabled || after.Revision != changed.Revision {
		t.Fatal("rejected recovery changed the demoted user's state")
	}
	if stored, err := f.svc.passwordHash(f.ctx, admin.ID); err != nil || stored != originalHash {
		t.Fatalf("rejected recovery changed the password: %v", err)
	}
	assertUserTOTPSecrets(t, f, admin.ID, 1)
	if f.audit.count(ActionAdminRecovered) != 0 {
		t.Fatal("rejected recovery wrote a success audit")
	}
}

// ======================== 启用失败必须回滚口令与第二因素，允许原意图重试 ========================

func TestResetAdminEnableFailureRollsBackCredentials(t *testing.T) {
	f := newFixture(t)
	admin := f.createUser("admin", testPassword, RoleAdmin)
	f.createUser("backup", testPassword, RoleAdmin)
	secret, _ := f.enableTOTP(admin.ID)
	defer clear(secret)
	disabled := true
	f.update(func(tx *storage.Tx) error {
		_, err := f.svc.UpdateUser(f.ctx, tx, UpdateUserInput{
			UserID: admin.ID, ExpectedRevision: f.user(admin.ID).Revision, Disabled: &disabled,
		})
		return err
	})
	before := f.user(admin.ID)
	originalHash, err := f.svc.passwordHash(f.ctx, admin.ID)
	if err != nil {
		t.Fatal(err)
	}
	f.update(func(tx *storage.Tx) error {
		_, err := tx.ExecContext(f.ctx, `CREATE TRIGGER fixture_reject_admin_enable
			BEFORE UPDATE OF disabled ON users BEGIN SELECT RAISE(ABORT, 'fixture-enable-failure'); END`)
		return err
	})
	input := ResetAdminInput{Username: admin.Username, Password: "fixture-recovered-passphrase", Reason: "fixture rollback"}
	if _, err := f.svc.ResetAdmin(f.ctx, input); err == nil {
		t.Fatal("recovery ignored the account enable failure")
	}
	after := f.user(admin.ID)
	if !after.Disabled || !after.MFAEnabled || after.Revision != before.Revision {
		t.Fatal("failed recovery partially changed the account")
	}
	if stored, err := f.svc.passwordHash(f.ctx, admin.ID); err != nil || stored != originalHash {
		t.Fatalf("failed recovery replaced the password: %v", err)
	}
	assertUserTOTPSecrets(t, f, admin.ID, 1)
	if f.audit.count(ActionAdminRecovered) != 0 {
		t.Fatal("failed recovery wrote a success audit")
	}
	f.update(func(tx *storage.Tx) error {
		_, err := tx.ExecContext(f.ctx, `DROP TRIGGER fixture_reject_admin_enable`)
		return err
	})
	if _, err := f.svc.ResetAdmin(f.ctx, input); err != nil {
		t.Fatalf("recovery retry after enable failure: %v", err)
	}
	if res := f.login(admin.Username, input.Password); !res.Authenticated() {
		t.Fatal("successful recovery retry did not restore login")
	}
}
