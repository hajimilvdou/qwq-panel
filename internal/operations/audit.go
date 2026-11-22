// SPDX-License-Identifier: AGPL-3.0-only

package operations

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/qwq-panel/qwq/internal/actor"
	"github.com/qwq-panel/qwq/internal/storage"
)

// Audit outcomes (proto AuditOutcome).
const (
	AuditSuccess = "success"
	AuditFailure = "failure"
	AuditDenied  = "denied"
)

// auditPrefix is the TypeID prefix of audit rows. internal/platform/ids does
// not name one because the audit log is the only owner (ADR-0008 §1).
const auditPrefix = "aud"

// AuditRecord is one entry of the audit log. Identity writes authentication
// events through Audit without creating an operation (ADR-0008 §2); the
// operations package writes the operation, approval and cancel entries itself.
type AuditRecord struct {
	Actor       actor.Actor
	Action      string
	Subject     string
	Outcome     string
	Details     json.RawMessage
	OperationID string
	NodeID      string
	TraceID     string
	RequestID   string
	// Source is host (default), plugin or node.
	Source string
	// At overrides the transaction timestamp (imports, tests).
	At time.Time
}

// Audit appends rec to audit_log inside tx. Audit rows carry no revision and
// emit no event: they are a log, not a resource.
func Audit(ctx context.Context, tx *storage.Tx, rec AuditRecord) error {
	if rec.Action == "" {
		return errors.New("operations: audit record without action")
	}
	switch rec.Outcome {
	case AuditSuccess, AuditFailure, AuditDenied:
	default:
		return fmt.Errorf("operations: audit outcome %q", rec.Outcome)
	}
	details := rec.Details
	if len(details) == 0 {
		details = json.RawMessage("{}")
	}
	if !json.Valid(details) {
		return errors.New("operations: audit details are not JSON")
	}
	source := rec.Source
	if source == "" {
		source = "host"
	}
	at := rec.At
	if at.IsZero() {
		at = tx.Now()
	}
	_, err := tx.ExecContext(ctx, `INSERT INTO audit_log
		(audit_id, occurred_at, actor_kind, actor_id, actor_on_behalf_of, source, action, subject,
		 outcome, operation_id, node_id, trace_id, request_id, details)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		tx.NewID(auditPrefix), storage.FormatTime(at), string(rec.Actor.Kind), rec.Actor.ID, rec.Actor.OnBehalfOf,
		source, rec.Action, rec.Subject, rec.Outcome, rec.OperationID, rec.NodeID, rec.TraceID, rec.RequestID,
		string(details))
	if err != nil {
		return fmt.Errorf("operations: audit: %w", err)
	}
	return nil
}

// audit writes rec inside the operation's transaction. Details are marshalled
// from v; a nil v writes {}.
func audit(ctx context.Context, tx *storage.Tx, rec AuditRecord, v any) error {
	if v != nil {
		b, err := json.Marshal(v)
		if err != nil {
			return err
		}
		rec.Details = b
	}
	return Audit(ctx, tx, rec)
}
