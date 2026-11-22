// SPDX-License-Identifier: AGPL-3.0-only

package controller

import (
	"testing"

	"github.com/qwq-panel/qwq/internal/actor"
	"github.com/qwq-panel/qwq/internal/identity"
	"github.com/qwq-panel/qwq/internal/platform/problem"
	"github.com/qwq-panel/qwq/internal/storage"
)

// ======================== 真实身份后端与同一事务内的权限撤销 ========================

func TestAuthorizeHumanTxObservesCurrentTransaction(t *testing.T) {
	c, _ := newVisibilityController(t)
	for _, test := range []struct {
		name, mutation string
	}{
		{"role", "UPDATE users SET role='viewer' WHERE user_id=?"},
		{"disabled", "UPDATE users SET disabled=1 WHERE user_id=?"},
		{"removed", "DELETE FROM users WHERE user_id=?"},
	} {
		t.Run(test.name, func(t *testing.T) {
			who := createVisibilityUser(t, c, "permission-tx-"+test.name, identity.RoleAdmin)
			if err := c.DB().Update(t.Context(), func(tx *storage.Tx) error {
				if err := c.Authorizer().AuthorizeHumanTx(t.Context(), tx, who, "host.service_accounts:create"); err != nil {
					return err
				}
				if _, err := tx.ExecContext(t.Context(), test.mutation, who.ID); err != nil {
					return err
				}
				if err := c.Authorizer().AuthorizeHumanTx(t.Context(), tx, who, "host.service_accounts:create"); !problem.HasCode(err, problem.PermissionDenied) {
					t.Fatalf("同事务撤权未生效: %v", err)
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestAuthorizeHumanTxRejectsOtherKindsAndMissingTransaction(t *testing.T) {
	c, _ := newVisibilityController(t)
	who := createVisibilityUser(t, c, "permission-tx-human", identity.RoleAdmin)
	if err := c.Authorizer().AuthorizeHumanTx(t.Context(), nil, who, "host.service_accounts:create"); !problem.HasCode(err, problem.PermissionDenied) {
		t.Fatalf("缺事务取得权限: %v", err)
	}
	if err := c.DB().Update(t.Context(), func(tx *storage.Tx) error {
		for _, kind := range []actor.Kind{actor.System, actor.Service, actor.AIAgent} {
			other := who
			other.Kind = kind
			if err := c.Authorizer().AuthorizeHumanTx(t.Context(), tx, other, "host.service_accounts:create"); !problem.HasCode(err, problem.PermissionDenied) {
				t.Fatalf("非真人取得权限: %s %v", kind, err)
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
