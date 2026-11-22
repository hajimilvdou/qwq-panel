// SPDX-License-Identifier: AGPL-3.0-only

package authz

import (
	"testing"

	"github.com/qwq-panel/qwq/internal/actor"
	"github.com/qwq-panel/qwq/internal/platform/problem"
	"github.com/qwq-panel/qwq/internal/storage"
)

func TestServiceAccountLifecycle(t *testing.T) {
	f := newFixture(t)
	adminID := f.user("root", "admin", false)
	admin := f.human(adminID)
	var created CreatedServiceAccount
	f.update(func(tx *storage.Tx) error {
		var err error
		created, err = f.z.CreateServiceAccount(f.ctx, tx, CreateServiceAccountInput{
			Actor: admin, Name: "backup-cron", Role: RoleOperator,
		})
		return err
	})
	if created.Token == "" || len(created.TokenPrefix) > 16 || created.Disabled {
		t.Fatalf("created service account = %+v", created)
	}
	a, err := f.z.AuthenticateBearer(f.ctx, created.Token)
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	if a.Kind != actor.Service || a.ID != created.ID {
		t.Fatalf("actor = %+v", a)
	}
	if a.IsHumanSession() || f.z.CanApprove(a) {
		t.Fatal("service account claims human authority")
	}
	// Operator role: plugin operations allowed, principals denied.
	if err := f.z.Authorize(f.ctx, a, "host.plugins:install", Resource{Name: "host.plugins"}); err != nil {
		t.Fatalf("service account denied a plugin operation: %v", err)
	}
	for _, perm := range []string{"host.users:read", "host.users:create", "host.delegations:create", "host.approvals:approve"} {
		if err := f.z.Authorize(f.ctx, a, perm, Resource{Name: permResource(perm)}); !problem.HasCode(err, problem.PermissionDenied) {
			t.Errorf("service account allowed %s: %v", perm, err)
		}
	}
	// Viewer role: reads only.
	var viewer CreatedServiceAccount
	f.update(func(tx *storage.Tx) error {
		var err error
		viewer, err = f.z.CreateServiceAccount(f.ctx, tx, CreateServiceAccountInput{
			Actor: admin, Name: "readonly-bot", Role: RoleViewer,
		})
		return err
	})
	va := f.agent(viewer.Token)
	if err := f.z.Authorize(f.ctx, va, "host.nodes:read", Resource{Name: "host.nodes"}); err != nil {
		t.Fatalf("viewer service account cannot read: %v", err)
	}
	if err := f.z.Authorize(f.ctx, va, "host.plugins:install", Resource{Name: "host.plugins"}); !problem.HasCode(err, problem.PermissionDenied) {
		t.Fatalf("viewer service account installed a plugin: %v", err)
	}
	// Disabling stops the token.
	f.update(func(tx *storage.Tx) error {
		_, err := tx.ExecContext(f.ctx, `UPDATE service_accounts SET disabled = 1 WHERE service_id = ?`, viewer.ID)
		return err
	})
	if _, err := f.z.AuthenticateBearer(f.ctx, viewer.Token); !problem.HasCode(err, problem.PermissionDenied) {
		t.Fatalf("disabled service account authenticated: %v", err)
	}
	// Revocation deletes it.
	f.update(func(tx *storage.Tx) error {
		return f.z.RevokeServiceAccount(f.ctx, tx, RevokeServiceAccountInput{
			Actor: admin, ServiceAccountID: created.ID, ExpectedRevision: created.Revision,
		})
	})
	if _, err := f.z.AuthenticateBearer(f.ctx, created.Token); !problem.HasCode(err, problem.Unauthenticated) {
		t.Fatalf("revoked service account authenticated: %v", err)
	}
}

func TestServiceAccountCreationRules(t *testing.T) {
	f := newFixture(t)
	ownerID := f.user("alice", "operator", false)
	// Only a human session may create service accounts.
	f.try(func(tx *storage.Tx) error {
		_, err := f.z.CreateServiceAccount(f.ctx, tx, CreateServiceAccountInput{
			Actor: actor.Actor{Kind: actor.AIAgent, ID: "dlg_x"}, Name: "x", Role: RoleViewer,
		})
		return err
	}, problem.PermissionDenied)
	// The role must be built in.
	f.try(func(tx *storage.Tx) error {
		_, err := f.z.CreateServiceAccount(f.ctx, tx, CreateServiceAccountInput{
			Actor: f.human(ownerID), Name: "bot", Role: "root",
		})
		return err
	}, problem.ValidationFailed)
	// The name must be unique and well formed.
	f.update(func(tx *storage.Tx) error {
		_, err := f.z.CreateServiceAccount(f.ctx, tx, CreateServiceAccountInput{
			Actor: f.human(ownerID), Name: "bot", Role: RoleViewer,
		})
		return err
	})
	f.try(func(tx *storage.Tx) error {
		_, err := f.z.CreateServiceAccount(f.ctx, tx, CreateServiceAccountInput{
			Actor: f.human(ownerID), Name: "BOT", Role: RoleViewer,
		})
		return err
	}, problem.StateConflict)
	f.try(func(tx *storage.Tx) error {
		_, err := f.z.CreateServiceAccount(f.ctx, tx, CreateServiceAccountInput{
			Actor: f.human(ownerID), Name: "bad name", Role: RoleViewer,
		})
		return err
	}, problem.ValidationFailed)
}
