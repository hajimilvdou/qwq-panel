// SPDX-License-Identifier: AGPL-3.0-only

package operations

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/qwq-panel/qwq/internal/actor"
	"github.com/qwq-panel/qwq/internal/platform/problem"
	"github.com/qwq-panel/qwq/internal/storage"
)

// AuditFilter selects audit rows (GAPS gap 7). An empty member does not filter;
// From and To are inclusive bounds on occurred_at.
type AuditFilter struct {
	ActorID     string
	Action      string
	Subject     string
	Outcome     string
	OperationID string
	From        time.Time
	To          time.Time
	Cursor      string
	Limit       int
}

// AuditEntry is one audit row as the public API returns it. Detail has passed
// the redaction whitelist, so it never carries a credential.
type AuditEntry struct {
	AuditID     string          `json:"audit_id"`
	At          time.Time       `json:"at"`
	Actor       actor.Actor     `json:"actor"`
	Action      string          `json:"action"`
	Subject     string          `json:"subject"`
	Outcome     string          `json:"outcome"`
	OperationID string          `json:"operation_id,omitempty"`
	NodeID      string          `json:"node_id,omitempty"`
	RequestID   string          `json:"request_id,omitempty"`
	Detail      json.RawMessage `json:"detail,omitempty"`
}

// AuditPage is one page of audit rows, newest first.
type AuditPage struct {
	Items      []AuditEntry
	NextCursor string
}

// auditColumns are the columns ListAudit reads, in scan order.
const auditColumns = `audit_id, occurred_at, actor_kind, actor_id, actor_on_behalf_of,
	action, subject, outcome, operation_id, node_id, request_id, details`

// ListAudit returns one page of the audit log, newest first. Rows written in
// the same transaction share occurred_at, so the order and the cursor both use
// (occurred_at, audit_id): a timestamp alone would skip or repeat rows.
func (s *Service) ListAudit(ctx context.Context, f AuditFilter) (*AuditPage, error) {
	var (
		where []string
		args  []any
	)
	filter := func(clause, value string) {
		if value != "" {
			where = append(where, clause)
			args = append(args, value)
		}
	}
	filter("actor_id = ?", f.ActorID)
	filter("action = ?", f.Action)
	filter("subject = ?", f.Subject)
	filter("outcome = ?", f.Outcome)
	filter("operation_id = ?", f.OperationID)
	if !f.From.IsZero() {
		where = append(where, "occurred_at >= ?")
		args = append(args, storage.FormatTime(f.From))
	}
	if !f.To.IsZero() {
		where = append(where, "occurred_at <= ?")
		args = append(args, storage.FormatTime(f.To))
	}
	if f.Cursor != "" {
		at, id, err := decodeAuditCursor(f.Cursor)
		if err != nil {
			return nil, problem.Validation(problem.Violation{
				In: "query", Pointer: "/cursor", Code: "INVALID", Message: "Not a cursor.",
			})
		}
		where = append(where, "(occurred_at < ? OR (occurred_at = ? AND audit_id < ?))")
		args = append(args, at, at, id)
	}
	limit := clampLimit(f.Limit)
	query := `SELECT ` + auditColumns + ` FROM audit_log`
	if len(where) > 0 {
		query += " WHERE " + strings.Join(where, " AND ")
	}
	query += " ORDER BY occurred_at DESC, audit_id DESC LIMIT ?"
	args = append(args, limit+1)

	rows, err := s.db.Reader().QueryContext(ctx, query, args...)
	if err != nil {
		return nil, problem.Wrap(err)
	}
	defer rows.Close()
	page := &AuditPage{Items: []AuditEntry{}}
	for rows.Next() {
		var (
			e                    AuditEntry
			at                   string
			kind, id, onBehalfOf string
			details              string
		)
		if err := rows.Scan(&e.AuditID, &at, &kind, &id, &onBehalfOf, &e.Action, &e.Subject,
			&e.Outcome, &e.OperationID, &e.NodeID, &e.RequestID, &details); err != nil {
			return nil, problem.Wrap(err)
		}
		occurredAt, err := storage.ParseTime(at)
		if err != nil {
			return nil, problem.Wrap(err)
		}
		e.At = occurredAt
		e.Actor = actor.Actor{Kind: actor.Kind(kind), ID: id, OnBehalfOf: onBehalfOf}
		e.Detail = redactAuditDetail(details)
		page.Items = append(page.Items, e)
	}
	if err := rows.Err(); err != nil {
		return nil, problem.Wrap(err)
	}
	if len(page.Items) > limit {
		last := page.Items[limit-1]
		page.NextCursor = encodeAuditCursor(storage.FormatTime(last.At), last.AuditID)
		page.Items = page.Items[:limit]
	}
	return page, nil
}

// auditDetailKeys are the detail members the public API may show (GAPS gap 7).
// Many code paths write audit details, so this is a whitelist: a new member has
// to be reviewed before it becomes readable. Only scalar values pass — a nested
// object or array could carry a credential (a stored Problem, a target, an
// actor) and is dropped whole.
var auditDetailKeys = map[string]bool{
	"event": true, "status": true, "attempt": true, "effective_risk": true,
	"operation_id": true, "parent_operation_id": true, "requires_mfa": true,
	"expires_at": true, "decision": true, "code": true, "reason": true, "mode": true,
	"comment": true, "username": true, "role": true, "disabled": true,
	"mfa_disabled": true, "sessions_revoked": true,
}

// maxAuditDetailValue bounds one string member, the maxLength of the free text
// a person writes (approval comment, cancel reason).
const maxAuditDetailValue = 500

// redactAuditDetail projects stored details onto the whitelist. An empty or
// unreadable document yields no detail at all.
func redactAuditDetail(raw string) json.RawMessage {
	var in map[string]any
	if raw == "" || json.Unmarshal([]byte(raw), &in) != nil {
		return nil
	}
	out := make(map[string]any)
	for k, v := range in {
		if !auditDetailKeys[k] {
			continue
		}
		switch value := v.(type) {
		case string:
			if runes := []rune(value); len(runes) > maxAuditDetailValue {
				value = string(runes[:maxAuditDetailValue])
			}
			out[k] = value
		case bool, float64:
			out[k] = value
		}
	}
	if len(out) == 0 {
		return nil
	}
	b, err := json.Marshal(out)
	if err != nil {
		return nil
	}
	return b
}

// encodeAuditCursor hides the (occurred_at, audit_id) pair of the last row.
func encodeAuditCursor(at, id string) string { return encodeCursor(at + "|" + id) }

// decodeAuditCursor reads a cursor back and checks the timestamp, so a crafted
// cursor is a 400 rather than a silently empty page.
func decodeAuditCursor(cursor string) (string, string, error) {
	raw, err := decodeCursor(cursor)
	if err != nil {
		return "", "", err
	}
	at, id, ok := strings.Cut(raw, "|")
	if !ok || id == "" {
		return "", "", problem.New(problem.ValidationFailed, "Not a cursor.")
	}
	if _, err := storage.ParseTime(at); err != nil {
		return "", "", err
	}
	return at, id, nil
}
