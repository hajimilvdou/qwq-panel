// SPDX-License-Identifier: AGPL-3.0-only

package operations

import (
	"context"
	"database/sql"
	"time"

	"github.com/qwq-panel/qwq/internal/actor"
	"github.com/qwq-panel/qwq/internal/platform/problem"
	"github.com/qwq-panel/qwq/internal/storage"
)

// SweepResult counts what one Sweep did.
type SweepResult struct {
	ExpiredApprovals int
	ExpiredPlans     int
	IdempotencyKeys  int
	ReapedOrphans    int
	PrunedOperations int
	PrunedAudit      int
}

// Recover repairs the state left by a crash: a RUNNING operation has no
// executor after a restart, so its attempt is failed and, when it is idempotent,
// a new attempt is queued (ADR-0007 #15). APPROVED operations were decided but
// never started, and PENDING jobs were accepted but never picked up; both are
// queued again. PENDING and AWAITING_APPROVAL operations stay as they are.
// It returns the operation IDs to resume after the transaction commits.
func (s *Service) Recover(ctx context.Context) ([]string, error) {
	system := actor.SystemActor("operations")
	var requeue []string
	err := s.db.Update(ctx, func(tx *storage.Tx) error {
		rows, err := tx.QueryContext(ctx, `SELECT operation_id FROM operations WHERE status IN (?, ?) ORDER BY operation_id`,
			string(Running), string(Approved))
		if err != nil {
			return err
		}
		var ids []string
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				rows.Close()
				return err
			}
			ids = append(ids, id)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		for _, id := range ids {
			op, err := loadOperation(ctx, tx, id)
			if err != nil {
				return err
			}
			tx.SetOrigin(s.origin(system, op.ID, op.TraceID, op.NodeID))
			switch op.Status {
			case Approved:
				requeue = append(requeue, op.ID)
			case Running:
				interrupted := problem.New(problem.Unavailable,
					"The host restarted while the operation was running.")
				if op.Meta.Idempotent && op.Attempt < s.cfg.MaxAttempts && !op.CancelRequested {
					if err := s.requeueAfterFailure(ctx, tx, op, interrupted); err != nil {
						return err
					}
					requeue = append(requeue, op.ID)
					continue
				}
				if op.CancelRequested {
					if err := s.failOperation(ctx, tx, op, Canceled, interrupted); err != nil {
						return err
					}
					continue
				}
				if err := s.failOperation(ctx, tx, op, Failed, interrupted); err != nil {
					return err
				}
			}
		}
		// 已接受但从未开始的 invoke：请求方没有拿到结果，自动执行不安全，按"未开始"失败收尾。
		if err := s.failPendingInvokes(ctx, tx, system); err != nil {
			return err
		}
		pending, err := tx.QueryContext(ctx, `SELECT operation_id FROM operations WHERE status = ? AND mode = ? ORDER BY operation_id`,
			string(Pending), ModeJob)
		if err != nil {
			return err
		}
		defer pending.Close()
		for pending.Next() {
			var id string
			if err := pending.Scan(&id); err != nil {
				return err
			}
			requeue = append(requeue, id)
		}
		return pending.Err()
	})
	if err != nil {
		return nil, problem.From(err)
	}
	return dedupe(requeue), nil
}

// failPendingInvokes fails every PENDING invoke left by a crash.
func (s *Service) failPendingInvokes(ctx context.Context, tx *storage.Tx, system actor.Actor) error {
	ids, err := queryIDs(ctx, tx, `SELECT operation_id FROM operations WHERE status = ? AND mode = ? ORDER BY operation_id`,
		string(Pending), ModeInvoke)
	if err != nil {
		return err
	}
	for _, id := range ids {
		op, err := loadOperation(ctx, tx, id)
		if err != nil {
			return err
		}
		tx.SetOrigin(s.origin(system, op.ID, op.TraceID, op.NodeID))
		if err := s.failOperation(ctx, tx, op, Failed,
			problem.New(problem.Unavailable, "The host restarted before the operation started.")); err != nil {
			return err
		}
	}
	return nil
}

// queryIDs collects the single string column of a query.
func queryIDs(ctx context.Context, tx *storage.Tx, query string, args ...any) ([]string, error) {
	rows, err := tx.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

// reapOrphans fails RUNNING operations whose deadline (plus the cancel grace)
// passed while no executor in this process holds them: their executor was lost
// and nobody else will ever finish them.
func (s *Service) reapOrphans(ctx context.Context, now time.Time) (int, error) {
	reaped := 0
	err := s.db.Update(ctx, func(tx *storage.Tx) error {
		ids, err := queryIDs(ctx, tx, `SELECT operation_id FROM operations WHERE status = ?`, string(Running))
		if err != nil {
			return err
		}
		for _, id := range ids {
			if s.isRunning(id) {
				continue
			}
			op, err := loadOperation(ctx, tx, id)
			if err != nil {
				return err
			}
			if op.StartedAt == nil || !op.StartedAt.Add(op.Timeout+2*s.cfg.JobCancelGrace).Before(now) {
				continue
			}
			tx.SetOrigin(s.origin(actor.SystemActor("operations"), op.ID, op.TraceID, op.NodeID))
			if err := s.failOperation(ctx, tx, op, Failed,
				problem.New(problem.Timeout, "The operation lost its executor.")); err != nil {
				return err
			}
			reaped++
		}
		return nil
	})
	return reaped, err
}

// requeueAfterFailure closes the failed attempt and puts the operation back to
// PENDING with the next attempt number.
func (s *Service) requeueAfterFailure(ctx context.Context, tx *storage.Tx, op *Operation, cause error) error {
	op.Error = s.problemOf(cause, op.RequestID, "/api/v1/operations/"+op.ID)
	if err := finishAttemptRow(ctx, tx, op, "failed"); err != nil {
		return err
	}
	previous := op.Status
	op.Attempt++
	op.Status = Pending
	op.Error = nil
	// A retry is not a state-machine transition: the next attempt starts at
	// PENDING again, which is what the event reports.
	return s.writeOperation(ctx, tx, op, previous, []string{"/status", "/attempt"})
}

// Sweep expires approvals whose deadline passed, prunes old plans and deletes
// expired idempotency keys (and keys left in progress by a crash). It also
// applies the retention windows to finished operations and audit rows, and runs
// the other domain's pruner on the same tick (OPS-05). It is safe to call
// concurrently with requests: every step is one short transaction.
func (s *Service) Sweep(ctx context.Context) (SweepResult, error) {
	var res SweepResult
	now := s.clock.Now().UTC().Truncate(time.Millisecond)
	cutoff := storage.FormatTime(now)

	var expired []string
	err := s.db.View(ctx, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, `SELECT approval_id FROM approvals
			WHERE status = ? AND expires_at <= ? ORDER BY expires_at LIMIT 100`,
			string(ApprovalPending), cutoff)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				return err
			}
			expired = append(expired, id)
		}
		return rows.Err()
	})
	if err != nil {
		return res, problem.Wrap(err)
	}
	for _, id := range expired {
		if err := s.expireApproval(ctx, id); err != nil {
			return res, err
		}
		res.ExpiredApprovals++
	}

	reaped, err := s.reapOrphans(ctx, now)
	if err != nil {
		return res, problem.From(err)
	}
	res.ReapedOrphans = reaped

	err = s.db.Update(ctx, func(tx *storage.Tx) error {
		// Keep expired plans for one more TTL so a client that already holds
		// the ID gets PLAN_EXPIRED instead of NOT_FOUND.
		planCutoff := storage.FormatTime(now.Add(-s.cfg.PlanTTL))
		out, err := tx.ExecContext(ctx, `DELETE FROM plans WHERE expires_at <= ?`, planCutoff)
		if err != nil {
			return err
		}
		if n, err := out.RowsAffected(); err == nil {
			res.ExpiredPlans = int(n)
		}
		// Expired keys and keys whose first request never finished (a crash).
		stale := storage.FormatTime(now.Add(-s.cfg.IdempotencyInProgressTTL))
		out, err = tx.ExecContext(ctx, `DELETE FROM idempotency_keys
			WHERE expires_at <= ? OR (state = 'in_progress' AND operation_id = '' AND created_at <= ?)`, cutoff, stale)
		if err != nil {
			return err
		}
		if n, err := out.RowsAffected(); err == nil {
			res.IdempotencyKeys = int(n)
		}
		return nil
	})
	if err != nil {
		return res, problem.From(err)
	}

	res.PrunedOperations, err = s.pruneOperations(ctx, now)
	if err != nil {
		return res, err
	}
	res.PrunedAudit, err = s.pruneAudit(ctx, now)
	if err != nil {
		return res, err
	}
	if s.pruner != nil {
		if err := s.pruner.Prune(ctx, now); err != nil {
			return res, problem.From(err)
		}
	}
	return res, nil
}

// sweepLoop runs Sweep on a clock-driven interval so tests can advance a fake
// clock and watch approvals expire.
func (s *Service) sweepLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-s.clock.After(s.cfg.SweepInterval):
			if _, err := s.Sweep(ctx); err != nil {
				s.log.WarnContext(ctx, "operations: sweep failed", "error", err)
			}
		}
	}
}

// dedupe removes repeated IDs while keeping the order.
func dedupe(ids []string) []string {
	if len(ids) < 2 {
		return ids
	}
	seen := make(map[string]bool, len(ids))
	out := ids[:0]
	for _, id := range ids {
		if seen[id] {
			continue
		}
		seen[id] = true
		out = append(out, id)
	}
	return out
}
