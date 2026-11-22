// SPDX-License-Identifier: AGPL-3.0-only

package identity

import (
	"errors"
	"testing"

	"github.com/qwq-panel/qwq/internal/platform/problem"
	"github.com/qwq-panel/qwq/internal/storage"
)

func (f *fixture) createUserWithPassword(username, password string, role Role) User {
	f.t.Helper()
	hash, err := f.svc.PreparePassword(f.ctx, username, password)
	if err != nil {
		f.t.Fatalf("prepare password: %v", err)
	}
	var u User
	f.update(func(tx *storage.Tx) error {
		res, err := f.svc.CreateUser(f.ctx, tx, CreateUserInput{Username: username, Role: role, PasswordHash: hash})
		u = res.User
		return err
	})
	return u
}

func TestCreateUserConflicts(t *testing.T) {
	f := newFixture(t)
	admin := f.createUser("admin", testPassword, RoleAdmin)
	hash, err := f.svc.PreparePassword(f.ctx, "other", testPassword)
	if err != nil {
		t.Fatal(err)
	}
	// The unique index is on the canonical form, so "ADMIN" collides.
	f.try(func(tx *storage.Tx) error {
		_, err := f.svc.CreateUser(f.ctx, tx, CreateUserInput{Username: "ADMIN", Role: RoleViewer, PasswordHash: hash})
		return err
	}, problem.StateConflict)
	f.try(func(tx *storage.Tx) error {
		_, err := f.svc.CreateUser(f.ctx, tx, CreateUserInput{Username: "bad name", Role: RoleViewer})
		return err
	}, problem.ValidationFailed)
	f.try(func(tx *storage.Tx) error {
		_, err := f.svc.CreateUser(f.ctx, tx, CreateUserInput{Username: "other", Role: "root"})
		return err
	}, problem.ValidationFailed)
	if u := f.user(admin.ID); u.Username != "admin" {
		t.Fatalf("admin = %+v", u)
	}
}

func TestUpdateUserAndRevisionConflict(t *testing.T) {
	f := newFixture(t)
	admin := f.createUser("admin", testPassword, RoleAdmin)
	op := f.createUserWithPassword("operator", testPassword, RoleOperator)
	display := "Ops One"
	role := RoleAdmin
	var updated User
	f.update(func(tx *storage.Tx) error {
		var err error
		updated, err = f.svc.UpdateUser(f.ctx, tx, UpdateUserInput{
			UserID: op.ID, ExpectedRevision: op.Revision, DisplayName: &display, Role: &role,
		})
		return err
	})
	if updated.DisplayName != display || updated.Role != RoleAdmin {
		t.Fatalf("updated = %+v", updated)
	}
	// A stale revision is a conflict carrying the current revision.
	err := f.db.Update(f.ctx, func(tx *storage.Tx) error {
		_, err := f.svc.UpdateUser(f.ctx, tx, UpdateUserInput{
			UserID: op.ID, ExpectedRevision: op.Revision, DisplayName: &display,
		})
		return err
	})
	if !problem.HasCode(err, problem.RevisionConflict) {
		t.Fatalf("stale update: %v, want REVISION_CONFLICT", err)
	}
	var pe *problem.Error
	if !asProblem(err, &pe) || pe.CurrentRevision != storage.Revision(updated.Revision) {
		t.Fatalf("conflict current_revision = %q, want %s", pe.CurrentRevision, storage.Revision(updated.Revision))
	}
	// A missing expected_revision is a validation error, not a wildcard.
	f.try(func(tx *storage.Tx) error {
		_, err := f.svc.UpdateUser(f.ctx, tx, UpdateUserInput{UserID: op.ID, DisplayName: &display})
		return err
	}, problem.ValidationFailed)
	// An empty patch is rejected.
	f.try(func(tx *storage.Tx) error {
		_, err := f.svc.UpdateUser(f.ctx, tx, UpdateUserInput{UserID: op.ID, ExpectedRevision: updated.Revision})
		return err
	}, problem.ValidationFailed)
	// A no-op patch does not burn a revision.
	same := updated.Revision
	f.update(func(tx *storage.Tx) error {
		_, err := f.svc.UpdateUser(f.ctx, tx, UpdateUserInput{
			UserID: op.ID, ExpectedRevision: same, DisplayName: &display, Role: &role,
		})
		return err
	})
	if got := f.user(op.ID); got.Revision != same {
		t.Fatalf("no-op patch bumped revision %d -> %d", same, got.Revision)
	}
	if f.audit.count(ActionUserUpdated) != 1 {
		t.Fatalf("update audits = %d, want 1", f.audit.count(ActionUserUpdated))
	}
	if u := f.user(admin.ID); u.Role != RoleAdmin {
		t.Fatal("unrelated user changed")
	}
}

func TestDisablingUserRevokesSessions(t *testing.T) {
	f := newFixture(t)
	f.createUser("admin", testPassword, RoleAdmin)
	op := f.createUserWithPassword("operator", testPassword, RoleOperator)
	res := f.login("operator", testPassword)
	disabled := true
	rev := f.user(op.ID).Revision
	f.update(func(tx *storage.Tx) error {
		_, err := f.svc.UpdateUser(f.ctx, tx, UpdateUserInput{
			UserID: op.ID, ExpectedRevision: rev, Disabled: &disabled,
		})
		return err
	})
	if _, _, err := f.svc.AuthenticateSession(f.ctx, res.Token); !problem.HasCode(err, problem.Unauthenticated) {
		t.Fatalf("session survived disabling: %v", err)
	}
	// Re-enabling restores login but not the old session.
	f.update(func(tx *storage.Tx) error {
		rev := f.user(op.ID).Revision
		enabled := false
		_, err := f.svc.UpdateUser(f.ctx, tx, UpdateUserInput{
			UserID: op.ID, ExpectedRevision: rev, Disabled: &enabled,
		})
		return err
	})
	if _, err := f.svc.Login(f.ctx, LoginInput{Username: "operator", Password: testPassword, ClientIP: "192.0.2.50"}); err != nil {
		t.Fatalf("login after re-enabling: %v", err)
	}
	if _, _, err := f.svc.AuthenticateSession(f.ctx, res.Token); !problem.HasCode(err, problem.Unauthenticated) {
		t.Fatal("revoked session came back")
	}
}

func TestLastAdministratorIsProtected(t *testing.T) {
	f := newFixture(t)
	admin := f.createUser("admin", testPassword, RoleAdmin)
	role := RoleOperator
	f.try(func(tx *storage.Tx) error {
		_, err := f.svc.UpdateUser(f.ctx, tx, UpdateUserInput{
			UserID: admin.ID, ExpectedRevision: admin.Revision, Role: &role,
		})
		return err
	}, problem.StateConflict)
	disabled := true
	f.try(func(tx *storage.Tx) error {
		_, err := f.svc.UpdateUser(f.ctx, tx, UpdateUserInput{
			UserID: admin.ID, ExpectedRevision: admin.Revision, Disabled: &disabled,
		})
		return err
	}, problem.StateConflict)
	f.try(func(tx *storage.Tx) error {
		return f.svc.DeleteUser(f.ctx, tx, DeleteUserInput{UserID: admin.ID, ExpectedRevision: admin.Revision})
	}, problem.StateConflict)
	// With a second administrator the demotion is allowed.
	f.createUserWithPassword("second", testPassword, RoleAdmin)
	f.update(func(tx *storage.Tx) error {
		_, err := f.svc.UpdateUser(f.ctx, tx, UpdateUserInput{
			UserID: admin.ID, ExpectedRevision: admin.Revision, Role: &role,
		})
		return err
	})
}

func TestDeleteUser(t *testing.T) {
	f := newFixture(t)
	f.createUser("admin", testPassword, RoleAdmin)
	victim := f.createUserWithPassword("victim", testPassword, RoleViewer)
	f.update(func(tx *storage.Tx) error {
		return f.svc.DeleteUser(f.ctx, tx, DeleteUserInput{UserID: victim.ID, ExpectedRevision: victim.Revision})
	})
	if _, err := f.svc.User(f.ctx, victim.ID); !problem.HasCode(err, problem.NotFound) {
		t.Fatalf("deleted user still readable: %v", err)
	}
	if _, err := f.svc.Login(f.ctx, LoginInput{Username: "victim", Password: testPassword, ClientIP: "192.0.2.60"}); !problem.HasCode(err, problem.Unauthenticated) {
		t.Fatalf("deleted user logged in: %v", err)
	}
	if f.audit.count(ActionUserDeleted) != 1 {
		t.Fatalf("delete audits = %d", f.audit.count(ActionUserDeleted))
	}
	// Sessions and credentials are gone with the row (ON DELETE CASCADE).
	var sessions int
	if err := f.db.Reader().QueryRowContext(f.ctx, `SELECT COUNT(*) FROM sessions WHERE user_id = ?`, victim.ID).Scan(&sessions); err != nil {
		t.Fatal(err)
	}
	if sessions != 0 {
		t.Fatalf("%d sessions survived the user", sessions)
	}
}

func TestResetPasswordRevokesSessions(t *testing.T) {
	f := newFixture(t)
	f.createUser("admin", testPassword, RoleAdmin)
	op := f.createUserWithPassword("operator", testPassword, RoleOperator)
	res := f.login("operator", testPassword)
	newHash, err := f.svc.PreparePassword(f.ctx, op.Username, "replacement-passphrase")
	if err != nil {
		t.Fatal(err)
	}
	f.update(func(tx *storage.Tx) error {
		rev := f.user(op.ID).Revision
		_, err := f.svc.ResetPassword(f.ctx, tx, ResetPasswordInput{
			UserID: op.ID, ExpectedRevision: rev, PasswordHash: newHash,
		})
		return err
	})
	if _, _, err := f.svc.AuthenticateSession(f.ctx, res.Token); !problem.HasCode(err, problem.Unauthenticated) {
		t.Fatal("session survived a password reset")
	}
	if _, err := f.svc.Login(f.ctx, LoginInput{Username: "operator", Password: testPassword, ClientIP: "192.0.2.70"}); !problem.HasCode(err, problem.Unauthenticated) {
		t.Fatal("old password still works")
	}
	if _, err := f.svc.Login(f.ctx, LoginInput{Username: "operator", Password: "replacement-passphrase", ClientIP: "192.0.2.71"}); err != nil {
		t.Fatalf("new password rejected: %v", err)
	}
	if f.audit.count(ActionPasswordReset) != 1 {
		t.Fatalf("reset audits = %d", f.audit.count(ActionPasswordReset))
	}
}

func TestPrincipalRole(t *testing.T) {
	f := newFixture(t)
	f.createUser("admin", testPassword, RoleAdmin)
	op := f.createUserWithPassword("operator", testPassword, RoleOperator)
	role, disabled, err := f.svc.PrincipalRole(f.ctx, op.ID)
	if err != nil || role != "operator" || disabled {
		t.Fatalf("PrincipalRole = %q %v %v", role, disabled, err)
	}
	disabledFlag := true
	f.update(func(tx *storage.Tx) error {
		_, err := f.svc.UpdateUser(f.ctx, tx, UpdateUserInput{
			UserID: op.ID, ExpectedRevision: f.user(op.ID).Revision, Disabled: &disabledFlag,
		})
		return err
	})
	role, disabled, err = f.svc.PrincipalRole(f.ctx, op.ID)
	if err != nil || !disabled || role != "operator" {
		t.Fatalf("PrincipalRole after disable = %q %v %v", role, disabled, err)
	}
	if _, _, err := f.svc.PrincipalRole(f.ctx, "usr_00000000000000000000000000"); !errors.Is(err, ErrPrincipalNotFound) {
		t.Fatalf("unknown principal: %v", err)
	}
}

func TestListUsers(t *testing.T) {
	f := newFixture(t)
	f.createUser("admin", testPassword, RoleAdmin)
	f.createUserWithPassword("op", testPassword, RoleOperator)
	f.createUserWithPassword("viewer", testPassword, RoleViewer)
	all, err := f.svc.ListUsers(f.ctx, ListUsersInput{})
	if err != nil || len(all) != 3 {
		t.Fatalf("ListUsers = %d, %v", len(all), err)
	}
	ops, err := f.svc.ListUsers(f.ctx, ListUsersInput{Role: RoleOperator})
	if err != nil || len(ops) != 1 || ops[0].Username != "op" {
		t.Fatalf("ListUsers(operator) = %+v, %v", ops, err)
	}
	page, err := f.svc.ListUsers(f.ctx, ListUsersInput{Limit: 2})
	if err != nil || len(page) != 2 {
		t.Fatalf("first page = %d, %v", len(page), err)
	}
	next, err := f.svc.ListUsers(f.ctx, ListUsersInput{After: page[len(page)-1].ID})
	if err != nil || len(next) != 1 {
		t.Fatalf("second page = %d, %v", len(next), err)
	}
}
