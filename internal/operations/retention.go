// SPDX-License-Identifier: AGPL-3.0-only

package operations

import (
	"context"
	"time"

	"github.com/qwq-panel/qwq/internal/actor"
	"github.com/qwq-panel/qwq/internal/platform/problem"
	"github.com/qwq-panel/qwq/internal/storage"
)

// Retention windows of OPS-05, used when the configuration omits them. A
// finished operation carries its arguments and result (up to 4 MiB for a plugin
// route) and its approval copies the arguments again, so an installation that
// never deletes them grows without bound on a 1C1G host.
const (
	DefaultRetentionOperations = 90 * 24 * time.Hour
	DefaultRetentionAudit      = 365 * 24 * time.Hour
)

// Batch sizes of one Sweep: each is a single short transaction, so a host with
// years of backlog catches up over several ticks instead of blocking requests.
const (
	pruneOperationsBatch = 500
	pruneAuditBatch      = 1000
)

// Pruner removes another domain's expired rows. The operations sweeper owns the
// timer and calls it once per tick, so identity needs no ticker of its own
// (OPS-05 step 4).
type Pruner interface {
	Prune(ctx context.Context, now time.Time) error
}

// pruneOperations deletes finished operations older than the retention window,
// oldest first. Child rows go first: operation_attempts references operations,
// and approvals must not outlive the operation they decided. Every deletion is
// published as resource.changed(delete) so a delta client learns the ID is gone.
func (s *Service) pruneOperations(ctx context.Context, now time.Time) (int, error) {
	cutoff := storage.FormatTime(now.Add(-s.cfg.RetentionOperations))
	var ids []string
	err := s.db.Update(ctx, func(tx *storage.Tx) error {
		var err error
		ids, err = queryIDs(ctx, tx, `SELECT operation_id FROM operations
			WHERE finished_at <> '' AND finished_at <= ? ORDER BY finished_at LIMIT ?`,
			cutoff, pruneOperationsBatch)
		if err != nil || len(ids) == 0 {
			return err
		}
		args := make([]any, len(ids))
		for i, id := range ids {
			args[i] = id
		}
		tx.SetOrigin(s.origin(actor.SystemActor("operations"), "", "", s.nodeID))
		in := " IN (" + placeholders(len(ids)) + ")"
		for _, table := range []string{"operation_attempts", "approvals"} {
			if _, err := tx.ExecContext(ctx, `DELETE FROM `+table+` WHERE operation_id`+in, args...); err != nil {
				return err
			}
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM operations WHERE operation_id`+in, args...); err != nil {
			return err
		}
		for _, id := range ids {
			if _, err := tx.Changed(ctx, storage.Change{Subject: operationSubject(id), Kind: storage.Deleted}); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return 0, problem.Wrap(err)
	}
	return len(ids), nil
}

// pruneAudit deletes audit rows older than the audit window. Audit rows carry no
// revision and emit no event (they are a log, not a resource), so nothing is
// published here.
func (s *Service) pruneAudit(ctx context.Context, now time.Time) (int, error) {
	cutoff := storage.FormatTime(now.Add(-s.cfg.RetentionAudit))
	var pruned int
	err := s.db.Update(ctx, func(tx *storage.Tx) error {
		out, err := tx.ExecContext(ctx, `DELETE FROM audit_log WHERE audit_id IN (
			SELECT audit_id FROM audit_log WHERE occurred_at < ? ORDER BY occurred_at LIMIT ?)`,
			cutoff, pruneAuditBatch)
		if err != nil {
			return err
		}
		n, err := out.RowsAffected()
		pruned = int(n)
		return err
	})
	if err != nil {
		return 0, problem.Wrap(err)
	}
	return pruned, nil
}
