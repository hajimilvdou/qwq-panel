// SPDX-License-Identifier: AGPL-3.0-only

package identity

import (
	"context"
	"fmt"

	"github.com/qwq-panel/qwq/internal/actor"
	"github.com/qwq-panel/qwq/internal/platform/problem"
	"github.com/qwq-panel/qwq/internal/storage"
)

// ResetAdminInput is the input of the host-local `qwq recover` reset.
type ResetAdminInput struct {
	// Username of an existing administrator (canonical or any case).
	Username string
	// Password is the new password; it is validated against the policy.
	Password string
	// Reason is recorded in the audit trail, e.g. "qwq recover on the console".
	Reason string
}

// ResetAdmin 为 root 本地恢复启用管理员、重置口令、清除第二因素并撤销会话。
// 哈希前和写事务内都核验当前角色；成功恢复写入原有审计记录（ARCH §4.1.1）。
//
// It intentionally does not touch delegations, which are owned by authz:
// `qwq recover` also calls authz.RevokeDelegationsOf(owner) so a stolen token
// cannot outlive the reset.
func (s *Service) ResetAdmin(ctx context.Context, in ResetAdminInput) (User, error) {
	u, err := s.UserByUsername(ctx, in.Username)
	if err != nil {
		return User{}, err
	}
	if err := checkAdminRecoveryRole(u); err != nil {
		return User{}, err
	}
	hash, err := s.preparePassword(ctx, u.Username, in.Password)
	if err != nil {
		return User{}, err
	}
	err = s.update(ctx, func(tx *storage.Tx) error {
		cur, err := s.userTx(ctx, tx, u.ID)
		if err != nil {
			return err
		}
		// 哈希等待期间角色可能变更；先重验，再修改口令和第二因素。
		if err := checkAdminRecoveryRole(cur); err != nil {
			return err
		}
		now := tx.Now()
		if err := upsertPasswordTx(ctx, tx, cur.ID, hash, now); err != nil {
			return err
		}
		if err := deleteCredentialsTx(ctx, tx, cur.ID, credTOTP, credTOTPPending, credRecovery); err != nil {
			return err
		}
		if err := revokeUserSessionsTx(ctx, tx, cur.ID, now); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM mfa_challenges WHERE user_id = ?`, cur.ID); err != nil {
			return fmt.Errorf("identity: clear challenges: %w", err)
		}
		seq, err := tx.Changed(ctx, storage.Change{Subject: cur.Subject(), Kind: storage.Updated})
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx,
			`UPDATE users SET disabled = 0, updated_at = ?, revision = ? WHERE user_id = ?`,
			formatTime(now), seq, cur.ID); err != nil {
			return fmt.Errorf("identity: enable recovered administrator: %w", err)
		}
		return s.auditTx(ctx, tx, AuditRecord{
			Action:  ActionAdminRecovered,
			Actor:   actor.SystemActor("recover"),
			Subject: cur.Subject(),
			Outcome: OutcomeSuccess,
			Reason:  in.Reason,
			Detail:  map[string]string{"mfa_disabled": "true", "sessions_revoked": "true"},
		})
	})
	if err != nil {
		return User{}, err
	}
	return s.User(ctx, u.ID)
}

// ======================== 哈希前预检与事务内重验共用角色规则 ========================

func checkAdminRecoveryRole(u User) error {
	if u.Role == RoleAdmin {
		return nil
	}
	return problem.New(problem.StateConflict, "The user is not an administrator.")
}
