// SPDX-License-Identifier: AGPL-3.0-only

// Package opstest seeds operation rows for tests of the packages that assemble
// the operation manager (controller, serve). It writes the table directly so a
// test can stage the state a crash leaves behind without running the approval
// flow.
package opstest

import (
	"context"
	"encoding/json"

	"github.com/qwq-panel/qwq/internal/operations"
	"github.com/qwq-panel/qwq/internal/storage"
)

// Seed describes one APPROVED operation: decided by a human, never started.
type Seed struct {
	ID      string
	Action  operations.Action
	ActorID string
	Args    json.RawMessage
}

// InsertApproved stores s as an operation that was approved but not started
// before a restart.
func InsertApproved(ctx context.Context, db *storage.DB, s Seed) error {
	meta, err := json.Marshal(s.Action)
	if err != nil {
		return err
	}
	args := s.Args
	if len(args) == 0 {
		args = json.RawMessage(`{}`)
	}
	return db.Update(ctx, func(tx *storage.Tx) error {
		now := storage.FormatTime(tx.Now())
		_, err := tx.ExecContext(ctx, `INSERT INTO operations (operation_id, action, action_meta, status,
			target, node_id, plugin_id, instance_id, actor_kind, actor_id, effective_risk, declared_risk,
			effect, mode, idempotent, args, args_digest, timeout_ms, created_at, updated_at, revision)
			VALUES (?, ?, ?, ?, '{}', 'local', ?, ?, 'human', ?, ?, ?, ?, ?, ?, ?, '', ?, ?, ?, 1)`,
			s.ID, s.Action.ID, string(meta), string(operations.Approved), s.Action.PluginID,
			instanceOf(s.Action), s.ActorID, s.Action.Risk, s.Action.Risk, s.Action.Effect, s.Action.Mode,
			s.Action.Idempotent, string(args), s.Action.TimeoutMS, now, now)
		return err
	})
}

// HostAction returns a high-risk host invocation of id.
func HostAction(id string) operations.Action {
	return operations.Action{
		ID: id, Effect: operations.EffectWrite, Risk: operations.RiskHigh,
		Mode: operations.ModeInvoke, Source: operations.HostSource, TimeoutMS: 30000,
	}
}

func instanceOf(a operations.Action) string {
	if a.Source == operations.PluginSource {
		return "default"
	}
	return ""
}
