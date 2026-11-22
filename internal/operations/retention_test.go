// SPDX-License-Identifier: AGPL-3.0-only

package operations

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/qwq-panel/qwq/internal/storage"
)

// OPS-05: finished operations, their attempts and approvals, and old audit rows
// are pruned on the Sweep tick; nothing unfinished or inside the window goes.

const testRetention = 90 * 24 * time.Hour

// TestSweepPrunesFinishedOperations: a finished operation past the retention
// window is deleted with its child rows, and the deletion is published so a
// delta client receives it in deleted_ids.
func TestSweepPrunesFinishedOperations(t *testing.T) {
	e := newTestEnv(t)
	e.svc.cfg.RetentionOperations = testRetention
	resp, err := e.run(humanActor(), actionWrite, Target{Subject: resourceSubject}, map[string]any{"value": "old"})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Operation.Status != Succeeded {
		t.Fatalf("status = %s, want SUCCEEDED", resp.Operation.Status)
	}
	id := resp.Operation.ID
	e.insertAttempt(id)
	e.insertApproval(id)

	e.clock.Advance(testRetention + 24*time.Hour)
	swept, err := e.svc.Sweep(e.ctx)
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if swept.PrunedOperations != 1 {
		t.Fatalf("sweep = %+v, want one pruned operation", swept)
	}
	for _, table := range []string{"operations", "operation_attempts", "approvals"} {
		if n := e.countRows(table); n != 0 {
			t.Errorf("%s rows = %d, want 0", table, n)
		}
	}
	events := e.events("resource.changed", operationSubject(id))
	if len(events) == 0 {
		t.Fatal("the deletion published no resource.changed event")
	}
	var last struct {
		Kind string `json:"kind"`
	}
	if err := json.Unmarshal(events[len(events)-1].Payload, &last); err != nil {
		t.Fatalf("decode event: %v", err)
	}
	if last.Kind != string(storage.Deleted) {
		t.Fatalf("last event kind = %q, want delete", last.Kind)
	}
}

// TestSweepKeepsRunningOperations: an operation that never finished has no
// finished_at and is never pruned, and one that finished inside the window
// stays.
func TestSweepKeepsRunningOperations(t *testing.T) {
	e := newTestEnv(t)
	e.svc.cfg.RetentionOperations = testRetention
	if _, err := e.run(humanActor(), actionWrite, Target{Subject: resourceSubject}, map[string]any{"value": "old"}); err != nil {
		t.Fatal(err)
	}
	e.clock.Advance(testRetention + 24*time.Hour)
	// No worker runs in this environment, so the job stays accepted but unfinished.
	queued, err := e.run(humanActor(), actionJob, nodeTarget(), nil)
	if err != nil {
		t.Fatal(err)
	}
	recent, err := e.run(humanActor(), actionWrite, Target{Subject: resourceSubject}, map[string]any{"value": "new"})
	if err != nil {
		t.Fatal(err)
	}
	swept, err := e.svc.Sweep(e.ctx)
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if swept.PrunedOperations != 1 {
		t.Fatalf("sweep = %+v, want only the old operation pruned", swept)
	}
	if n := e.countRows("operations"); n != 2 {
		t.Fatalf("operations = %d, want 2", n)
	}
	for _, id := range []string{queued.Operation.ID, recent.Operation.ID} {
		if op := e.operation(id); op == nil {
			t.Fatalf("operation %s was pruned", id)
		}
	}
	if op := e.operation(queued.Operation.ID); op.FinishedAt != nil {
		t.Fatalf("queued operation finished: %+v", op)
	}
	if op := e.operation(recent.Operation.ID); op.Status != Succeeded {
		t.Fatalf("recent operation = %s, want SUCCEEDED", op.Status)
	}
}

// TestSweepPrunesAudit: audit rows older than the audit window are deleted in
// bounded batches, newer ones stay.
func TestSweepPrunesAudit(t *testing.T) {
	e := newTestEnv(t)
	e.svc.cfg.RetentionAudit = 365 * 24 * time.Hour
	now := e.clock.Now()
	e.writeAudit("test.old", now.Add(-366*24*time.Hour))
	e.writeAudit("test.recent", now)
	swept, err := e.svc.Sweep(e.ctx)
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if swept.PrunedAudit != 1 {
		t.Fatalf("sweep = %+v, want one pruned audit row", swept)
	}
	if n := e.countAudit("test.old"); n != 0 {
		t.Errorf("old audit rows = %d, want 0", n)
	}
	if n := e.countAudit("test.recent"); n != 1 {
		t.Errorf("recent audit rows = %d, want 1", n)
	}
	// Sweeping again does nothing.
	again, err := e.svc.Sweep(e.ctx)
	if err != nil || again.PrunedAudit != 0 {
		t.Fatalf("second sweep = %+v, %v", again, err)
	}
}

// TestSweepCallsRetentionPruner: the identity pruner runs on the same tick, so
// no second ticker exists (OPS-05 step 4).
func TestSweepCallsRetentionPruner(t *testing.T) {
	e := newTestEnv(t)
	pruner := &recordingPruner{}
	e.svc.pruner = pruner
	if _, err := e.svc.Sweep(e.ctx); err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if pruner.calls != 1 {
		t.Fatalf("prune calls = %d, want 1", pruner.calls)
	}
	if !pruner.at.Equal(e.clock.Now().UTC().Truncate(time.Millisecond)) {
		t.Fatalf("prune time = %s, want the sweep tick", pruner.at)
	}
}

type recordingPruner struct {
	calls int
	at    time.Time
}

func (p *recordingPruner) Prune(_ context.Context, now time.Time) error {
	p.calls++
	p.at = now
	return nil
}

// insertAttempt adds a second execution row of a finished operation; the first
// one is written by the run itself.
func (e *testEnv) insertAttempt(operationID string) {
	e.t.Helper()
	at := storage.FormatTime(e.clock.Now())
	e.execSQL(`INSERT INTO operation_attempts (operation_id, attempt, status, started_at, finished_at)
		VALUES (?, 2, 'succeeded', ?, ?)`, operationID, at, at)
}

// insertApproval adds a decided approval of a finished operation.
func (e *testEnv) insertApproval(operationID string) {
	e.t.Helper()
	at := storage.FormatTime(e.clock.Now())
	e.execSQL(`INSERT INTO approvals (approval_id, operation_id, status, facts, created_at, expires_at, revision)
		VALUES (?, ?, ?, '{}', ?, ?, 0)`, "apr_"+operationID, operationID, string(ApprovalApproved), at, at)
}

// writeAudit appends one audit row at an explicit time.
func (e *testEnv) writeAudit(action string, at time.Time) {
	e.t.Helper()
	if err := e.db.Update(e.ctx, func(tx *storage.Tx) error {
		return Audit(e.ctx, tx, AuditRecord{
			Actor: humanActor(), Action: action, Outcome: AuditSuccess, At: at,
		})
	}); err != nil {
		e.t.Fatalf("write audit: %v", err)
	}
}

// execSQL runs one write statement and fails the test on error.
func (e *testEnv) execSQL(query string, args ...any) {
	e.t.Helper()
	if err := e.db.Update(e.ctx, func(tx *storage.Tx) error {
		_, err := tx.ExecContext(e.ctx, query, args...)
		return err
	}); err != nil {
		e.t.Fatalf("exec %q: %v", query, err)
	}
}

// countRows counts a whole table.
func (e *testEnv) countRows(table string) int {
	e.t.Helper()
	var n int
	if err := e.db.Reader().QueryRowContext(e.ctx, `SELECT COUNT(*) FROM `+table).Scan(&n); err != nil {
		e.t.Fatalf("count %s: %v", table, err)
	}
	return n
}
