// SPDX-License-Identifier: AGPL-3.0-only

package agentsession

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/qwq-panel/qwq/internal/actor"
	"github.com/qwq-panel/qwq/internal/operations"
	"github.com/qwq-panel/qwq/internal/platform/problem"
	"github.com/qwq-panel/qwq/internal/secrets"
	"github.com/qwq-panel/qwq/internal/storage"
)

// sessionSubjectPrefix is the resource.changed subject prefix of a session.
// The event visibility maps the family to the owner alone (gap 6), so a
// session's changes reach the global stream of its owner's subscribers only.
const sessionSubjectPrefix = "agent_sessions/"

// messagePrefix and callPrefix are TypeID prefixes owned by this package
// (internal/platform/ids only names the shared resources).
const (
	messagePrefix = "msg"
	callPrefix    = "call"
)

// retainToolCalls is the number of newest tool-call rows kept per session; the
// operations audit is the lasting record. Only finished rows are pruned.
const retainToolCalls = 500

// notFound is the NOT_FOUND of a session the caller may not see. The same
// answer covers "does not exist" and "belongs to another principal", so an
// identifier cannot be probed.
func notFound() error {
	return problem.New(problem.NotFound, "No such agent session.")
}

func sessionSubject(id string) string { return sessionSubjectPrefix + id }

// apiKeyPurpose is the secret purpose of a session's API key.
const apiKeyPurpose = "agent.native.api_key"

// apiKeyOwner is the secret owner of a session's API key: the session's own
// resource name. Deleting the session deletes everything stored under it, and
// the native core opens no secret stored under any other owner.
func apiKeyOwner(sessionID string) string { return sessionSubject(sessionID) }

// querier is the subset of *sql.DB and *storage.Tx the store needs.
type querier interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// sessionColumns is the SELECT list of loadSession/listSessions. The last
// subquery is last_message_preview: substr counts characters (not bytes), so
// the 120-character cut never splits a rune.
const sessionColumns = `
	s.session_id, s.plugin_id, s.owner_kind, s.owner_id, s.title, s.core,
	s.permission_mode, s.status, s.config_json, s.last_seq, s.created_at,
	s.updated_at, s.revision, s.api_key_ref,
	(SELECT COUNT(*) FROM agent_tool_calls tc
	   WHERE tc.session_id = s.session_id AND tc.status = 'awaiting_approval'),
	(SELECT MAX(m.created_at) FROM agent_messages m WHERE m.session_id = s.session_id),
	(SELECT substr(m.content, 1, 120) FROM agent_messages m
	   WHERE m.session_id = s.session_id ORDER BY m.seq DESC LIMIT 1)`

// scanSession reads one session row (with the three computed columns).
func scanSession(row interface{ Scan(...any) error }) (*Session, error) {
	var (
		rec       Session
		ownerKind string
		core      string
		mode      string
		status    string
		config    string
		createdAt string
		updatedAt string
		revision  int64
		apiKeyRef string
		pending   int
		lastMsgAt sql.NullString
		preview   sql.NullString
	)
	if err := row.Scan(&rec.ID, &rec.PluginID, &ownerKind, &rec.OwnerID, &rec.Title, &core,
		&mode, &status, &config, &rec.LastSeq, &createdAt, &updatedAt, &revision, &apiKeyRef,
		&pending, &lastMsgAt, &preview); err != nil {
		return nil, err
	}
	rec.OwnerKind = actor.Kind(ownerKind)
	rec.Core = CoreName(core)
	rec.PermissionMode = operations.PermissionMode(mode)
	rec.Status = Status(status)
	rec.Config = json.RawMessage(config)
	rec.APIKeyRef = secrets.Ref(apiKeyRef)
	rec.Pending = pending
	rec.Revision = strconv.FormatInt(revision, 10)
	if preview.Valid {
		rec.LastMessagePreview = preview.String
	}
	if lastMsgAt.Valid && lastMsgAt.String != "" {
		at, err := storage.ParseTime(lastMsgAt.String)
		if err != nil {
			return nil, fmt.Errorf("agentsession: last message time: %w", err)
		}
		rec.LastMessageAt = &at
	}
	created, err := storage.ParseTime(createdAt)
	if err != nil {
		return nil, fmt.Errorf("agentsession: created_at: %w", err)
	}
	rec.CreatedAt = created
	updated, err := storage.ParseTime(updatedAt)
	if err != nil {
		return nil, fmt.Errorf("agentsession: updated_at: %w", err)
	}
	rec.UpdatedAt = updated
	return &rec, nil
}

// loadSessionFor reads one session the owner may see; another principal's
// session is NOT_FOUND.
func loadSessionFor(ctx context.Context, q querier, owner actor.Actor, id string) (*Session, error) {
	row := q.QueryRowContext(ctx, `SELECT `+sessionColumns+` FROM agent_sessions s
		WHERE s.session_id = ? AND s.owner_kind = ? AND s.owner_id = ?`,
		id, string(owner.Kind), owner.ID)
	rec, err := scanSession(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, notFound()
	}
	if err != nil {
		return nil, fmt.Errorf("agentsession: load session: %w", err)
	}
	return rec, nil
}

// insertSession writes a new session row and its create event.
func (s *Service) insertSession(ctx context.Context, owner actor.Actor, rec *Session) error {
	return s.db.Update(ctx, func(tx *storage.Tx) error {
		var count int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM agent_sessions WHERE owner_kind = ? AND owner_id = ?`,
			string(owner.Kind), owner.ID).Scan(&count); err != nil {
			return fmt.Errorf("agentsession: count sessions: %w", err)
		}
		if count >= s.cfg.MaxSessionsPerOwner {
			return problem.New(problem.RateLimited, "You have reached the limit of %d agent sessions; delete one first.",
				s.cfg.MaxSessionsPerOwner)
		}
		tx.SetOrigin(storage.Origin{Actor: owner})
		rev, err := tx.Changed(ctx, storage.Change{Subject: sessionSubject(rec.ID), Kind: storage.Created})
		if err != nil {
			return err
		}
		rec.Revision = storage.Revision(rev)
		_, err = tx.ExecContext(ctx, `INSERT INTO agent_sessions
			(session_id, plugin_id, owner_kind, owner_id, title, core, permission_mode, status,
			 config_json, last_seq, created_at, updated_at, revision)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			rec.ID, rec.PluginID, string(owner.Kind), owner.ID, rec.Title, string(rec.Core),
			string(rec.PermissionMode), string(rec.Status), string(rec.Config), rec.LastSeq,
			storage.FormatTime(rec.CreatedAt), storage.FormatTime(rec.UpdatedAt), rev)
		if err != nil {
			return fmt.Errorf("agentsession: insert session: %w", err)
		}
		return operations.Audit(ctx, tx, operations.AuditRecord{
			Actor: owner, Action: "agent.session.create", Subject: sessionSubject(rec.ID),
			Outcome: operations.AuditSuccess,
			Details: auditDetails(map[string]any{"core": rec.Core, "permission_mode": rec.PermissionMode}),
		})
	})
}

// listSessions returns one page of the owner's sessions.
func (s *Service) listSessions(ctx context.Context, owner actor.Actor, f ListFilter) (*SessionPage, error) {
	where := []string{"s.owner_kind = ? AND s.owner_id = ?"}
	args := []any{string(owner.Kind), owner.ID}
	switch f.Status {
	case "":
	case StatusAttention:
		where = append(where, "s.status IN ('waiting_approval', 'failed')")
	default:
		st := Status(f.Status)
		if !st.Valid() {
			return nil, problem.Validation(problem.Violation{
				In: "query", Pointer: "/status", Code: "INVALID",
				Message: "status must be idle, running, waiting_approval, cancelled, failed or attention.",
			})
		}
		where = append(where, "s.status = ?")
		args = append(args, string(st))
	}
	if f.SinceRevision != "" {
		seq, err := strconv.ParseInt(f.SinceRevision, 10, 64)
		if err != nil {
			return nil, problem.Validation(problem.Violation{
				In: "query", Pointer: "/since_revision", Code: "INVALID", Message: "Not a revision.",
			})
		}
		where = append(where, "s.revision > ?")
		args = append(args, seq)
	}
	if f.Cursor != "" {
		where = append(where, "s.session_id < ?")
		args = append(args, f.Cursor)
	}
	limit := clampLimit(f.Limit, s.cfg.ListLimit)
	query := `SELECT ` + sessionColumns + ` FROM agent_sessions s WHERE ` + strings.Join(where, " AND ") +
		` ORDER BY s.session_id DESC LIMIT ?`
	args = append(args, limit+1)
	rows, err := s.db.Reader().QueryContext(ctx, query, args...)
	if err != nil {
		return nil, problem.Wrap(err)
	}
	defer rows.Close()
	page := &SessionPage{Items: []Session{}, Revision: storage.Revision(s.db.HeadSeq()), Delta: f.SinceRevision != ""}
	for rows.Next() {
		rec, err := scanSession(rows)
		if err != nil {
			return nil, problem.Wrap(err)
		}
		page.Items = append(page.Items, *rec)
	}
	if err := rows.Err(); err != nil {
		return nil, problem.Wrap(err)
	}
	if len(page.Items) > limit {
		page.Items = page.Items[:limit]
		page.NextCursor = page.Items[len(page.Items)-1].ID
	}
	return page, nil
}

// updateSession applies fn to the session row inside one transaction, bumps
// last_seq if asked, writes the update event and returns the new row.
func (s *Service) updateSession(ctx context.Context, owner actor.Actor, id string, lastSeq int64,
	pointers []string, fn func(*Session) error) (*Session, error) {
	var out *Session
	err := s.db.Update(ctx, func(tx *storage.Tx) error {
		cur, err := loadSessionFor(ctx, tx, owner, id)
		if err != nil {
			return err
		}
		prev := cur.Status
		tx.SetOrigin(storage.Origin{Actor: owner})
		if fn != nil {
			if err := fn(cur); err != nil {
				return err
			}
		}
		cur.UpdatedAt = tx.Now()
		rev, err := tx.Changed(ctx, storage.Change{
			Subject: sessionSubject(cur.ID), Kind: storage.Updated, Pointers: pointers,
		})
		if err != nil {
			return err
		}
		cur.Revision = storage.Revision(rev)
		if lastSeq > cur.LastSeq {
			cur.LastSeq = lastSeq
		}
		cfgText := "{}"
		if len(cur.Config) > 0 {
			cfgText = string(cur.Config)
		}
		_, err = tx.ExecContext(ctx, `UPDATE agent_sessions SET
			title = ?, permission_mode = ?, status = ?, config_json = ?, last_seq = ?, updated_at = ?, revision = ?
			WHERE session_id = ?`,
			cur.Title, string(cur.PermissionMode), string(cur.Status), cfgText, cur.LastSeq,
			storage.FormatTime(cur.UpdatedAt), rev, cur.ID)
		if err != nil {
			return fmt.Errorf("agentsession: update session: %w", err)
		}
		if err := appendStatusEvents(ctx, tx, cur.ID, prev, cur.Status, cur.LastSeq, rev); err != nil {
			return err
		}
		out = cur
		return nil
	})
	if err != nil {
		return nil, problem.From(err)
	}
	return out, nil
}

// storeAPIKey replaces (key != nil) or removes (key == nil) the session's API
// key in one transaction: the secret row, api_key_ref, the resource.changed
// event and the audit row commit together. A session owns at most one secret,
// so the old key is dropped through the owner namespace, never through the
// reference in the row: a planted reference cannot make this delete another
// owner's secret. Removing the key of a session without one writes nothing.
func (s *Service) storeAPIKey(ctx context.Context, owner actor.Actor, id string, key []byte) (*Session, error) {
	var out *Session
	err := s.db.Update(ctx, func(tx *storage.Tx) error {
		cur, err := loadSessionFor(ctx, tx, owner, id)
		if err != nil {
			return err
		}
		out = cur
		if key == nil && cur.APIKeyRef == "" {
			return nil
		}
		tx.SetOrigin(storage.Origin{Actor: owner})
		if _, err := s.secrets.DeleteOwner(ctx, tx, apiKeyOwner(cur.ID)); err != nil {
			return err
		}
		action := "agent.session.api_key.clear"
		cur.APIKeyRef = ""
		if key != nil {
			if cur.APIKeyRef, err = s.secrets.Put(ctx, tx, apiKeyOwner(cur.ID), apiKeyPurpose, key); err != nil {
				return err
			}
			action = "agent.session.api_key.set"
		}
		cur.UpdatedAt = tx.Now()
		rev, err := tx.Changed(ctx, storage.Change{
			Subject: sessionSubject(cur.ID), Kind: storage.Updated, Pointers: []string{"/has_api_key"},
		})
		if err != nil {
			return err
		}
		cur.Revision = storage.Revision(rev)
		if _, err := tx.ExecContext(ctx, `UPDATE agent_sessions SET api_key_ref = ?, updated_at = ?, revision = ?
			WHERE session_id = ?`, string(cur.APIKeyRef), storage.FormatTime(cur.UpdatedAt), rev, cur.ID); err != nil {
			return fmt.Errorf("agentsession: update api key: %w", err)
		}
		return operations.Audit(ctx, tx, operations.AuditRecord{
			Actor: owner, Action: action, Subject: sessionSubject(cur.ID), Outcome: operations.AuditSuccess,
		})
	})
	if err != nil {
		return nil, problem.From(err)
	}
	return out, nil
}

// sessionUpdatedPayload is the payload of agent.session.updated (gap 6). It is
// the session's state snapshot and never a title, message content or tool
// argument: the session SSE stays the channel for what the user wrote.
type sessionUpdatedPayload struct {
	SessionID        string `json:"session_id"`
	Status           Status `json:"status"`
	PreviousStatus   Status `json:"previous_status,omitempty"`
	PendingApprovals int    `json:"pending_approvals"`
	LastSeq          int64  `json:"last_seq"`
	LastMessageAt    string `json:"last_message_at,omitempty"`
	Revision         string `json:"revision"`
}

// sessionAttentionPayload is the payload of agent.session.attention (gap 6).
type sessionAttentionPayload struct {
	SessionID   string `json:"session_id"`
	Status      Status `json:"status"`
	ApprovalID  string `json:"approval_id,omitempty"`
	OperationID string `json:"operation_id,omitempty"`
	Revision    string `json:"revision"`
}

// appendStatusEvents writes the global-stream events of a committed status
// change (gap 6) inside the caller's transaction: agent.session.updated, plus
// agent.session.attention when the new status asks for the owner. rev is the
// session's new revision — the sequence of the change's resource.changed event
// — and both payloads name it, so the stream and the REST snapshot agree.
func appendStatusEvents(ctx context.Context, tx *storage.Tx, id string, prev, next Status, lastSeq, rev int64) error {
	if prev == next {
		return nil
	}
	var (
		pending   int
		lastMsgAt sql.NullString
	)
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM agent_tool_calls
		WHERE session_id = ? AND status = 'awaiting_approval'`, id).Scan(&pending); err != nil {
		return fmt.Errorf("agentsession: count pending approvals: %w", err)
	}
	if err := tx.QueryRowContext(ctx, `SELECT MAX(created_at) FROM agent_messages
		WHERE session_id = ?`, id).Scan(&lastMsgAt); err != nil {
		return fmt.Errorf("agentsession: session event time: %w", err)
	}
	updated := sessionUpdatedPayload{
		SessionID: id, Status: next, PreviousStatus: prev,
		PendingApprovals: pending, LastSeq: lastSeq, Revision: storage.Revision(rev),
	}
	if lastMsgAt.Valid && lastMsgAt.String != "" {
		at, err := storage.ParseTime(lastMsgAt.String)
		if err != nil {
			return fmt.Errorf("agentsession: session event time: %w", err)
		}
		updated.LastMessageAt = storage.FormatTime(at)
	}
	payload, err := json.Marshal(updated)
	if err != nil {
		return err
	}
	if _, err := tx.AppendEvent(ctx, storage.Event{
		Type: "agent.session.updated", SchemaVersion: "1", Subject: sessionSubject(id), Payload: payload,
	}); err != nil {
		return err
	}
	return appendAttentionEvent(ctx, tx, id, next, rev)
}

// appendAttentionEvent writes agent.session.attention when next asks for a
// human. The ids of a pause come from its awaiting tool call; a failure
// carries none.
func appendAttentionEvent(ctx context.Context, tx *storage.Tx, id string, next Status, rev int64) error {
	if next != StatusWaitingApproval && next != StatusFailed {
		return nil
	}
	att := sessionAttentionPayload{SessionID: id, Status: next, Revision: storage.Revision(rev)}
	if next == StatusWaitingApproval {
		var approvalID, operationID sql.NullString
		err := tx.QueryRowContext(ctx, `SELECT approval_id, operation_id FROM agent_tool_calls
			WHERE session_id = ? AND status = 'awaiting_approval' ORDER BY seq DESC LIMIT 1`,
			id).Scan(&approvalID, &operationID)
		switch {
		case err == nil:
			att.ApprovalID, att.OperationID = approvalID.String, operationID.String
		case errors.Is(err, sql.ErrNoRows):
			// No awaiting call (yet); the status alone still asks for a human.
		default:
			return fmt.Errorf("agentsession: session attention call: %w", err)
		}
	}
	payload, err := json.Marshal(att)
	if err != nil {
		return err
	}
	_, err = tx.AppendEvent(ctx, storage.Event{
		Type: "agent.session.attention", SchemaVersion: "1", Subject: sessionSubject(id), Payload: payload,
	})
	return err
}

// deleteSession removes the transcript and the session row, keeping an audit
// row in the same transaction (the operations audit is the lasting record).
func (s *Service) deleteSession(ctx context.Context, owner actor.Actor, id string) error {
	return s.db.Update(ctx, func(tx *storage.Tx) error {
		cur, err := loadSessionFor(ctx, tx, owner, id)
		if err != nil {
			return err
		}
		tx.SetOrigin(storage.Origin{Actor: owner})
		if _, err := tx.ExecContext(ctx, `DELETE FROM agent_tool_calls WHERE session_id = ?`, cur.ID); err != nil {
			return fmt.Errorf("agentsession: delete tool calls: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM agent_messages WHERE session_id = ?`, cur.ID); err != nil {
			return fmt.Errorf("agentsession: delete messages: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM agent_sessions WHERE session_id = ?`, cur.ID); err != nil {
			return fmt.Errorf("agentsession: delete session: %w", err)
		}
		// The API key goes with its session. Without a secret store SetAPIKey
		// cannot have stored one.
		if s.secrets != nil {
			if _, err := s.secrets.DeleteOwner(ctx, tx, apiKeyOwner(cur.ID)); err != nil {
				return err
			}
		}
		if _, err := tx.Changed(ctx, storage.Change{Subject: sessionSubject(cur.ID), Kind: storage.Deleted}); err != nil {
			return err
		}
		return operations.Audit(ctx, tx, operations.AuditRecord{
			Actor: owner, Action: "agent.session.delete", Subject: sessionSubject(cur.ID),
			Outcome: operations.AuditSuccess,
			Details: auditDetails(map[string]any{"core": cur.Core, "permission_mode": cur.PermissionMode}),
		})
	})
}

// insertMessage appends one message, prunes the oldest rows beyond retain and
// advances the session's last_seq/status in the same transaction. It returns
// the session revision after the write.
func (s *Service) insertMessage(ctx context.Context, owner actor.Actor, msg *Message, status Status, retain int) (string, error) {
	return s.insertMessageWithClientID(ctx, owner, msg, "", status, retain)
}

// messageByClientID returns the message a retried send already created.
func (s *Service) messageByClientID(ctx context.Context, sessionID, clientID string) (*Message, error) {
	if clientID == "" {
		return nil, nil
	}
	row := s.db.Reader().QueryRowContext(ctx, `SELECT seq, message_id, role, content, content_json,
		operation_id, approval_id, created_at FROM agent_messages
		WHERE session_id = ? AND client_message_id = ?`, sessionID, clientID)
	msg, err := scanMessage(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, problem.Wrap(err)
	}
	return msg, nil
}

// insertMessageWithClientID is insertMessage plus the client message id used
// for idempotent retries.
func (s *Service) insertMessageWithClientID(ctx context.Context, owner actor.Actor, msg *Message,
	clientID string, status Status, retain int) (string, error) {
	var revision string
	err := s.db.Update(ctx, func(tx *storage.Tx) error {
		tx.SetOrigin(storage.Origin{Actor: owner})
		// The stored status tells whether this write starts or ends a turn; a
		// row deleted in the meantime writes only the message.
		prev, prevSeq := Status(status), int64(0)
		err := tx.QueryRowContext(ctx, `SELECT status, last_seq FROM agent_sessions
			WHERE session_id = ?`, msg.SessionID).Scan(&prev, &prevSeq)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("agentsession: read session status: %w", err)
		}
		rev, err := tx.Changed(ctx, storage.Change{
			Subject: sessionSubject(msg.SessionID), Kind: storage.Updated, Pointers: []string{"/messages"},
		})
		if err != nil {
			return err
		}
		revision = storage.Revision(rev)
		var contentJSON any
		if len(msg.ContentJSON) > 0 {
			contentJSON = string(msg.ContentJSON)
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO agent_messages
			(session_id, seq, message_id, role, content, content_json, operation_id, approval_id,
			 client_message_id, created_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			msg.SessionID, msg.Seq, msg.MessageID, msg.Role, msg.Content, contentJSON,
			msg.OperationID, msg.ApprovalID, clientID, storage.FormatTime(msg.CreatedAt))
		if err != nil {
			return fmt.Errorf("agentsession: insert message: %w", err)
		}
		if retain > 0 {
			// Keep the newest retain messages by message sequence. Counting
			// events instead would be wrong: tool calls and turn boundaries
			// consume session sequences without adding a message.
			if _, err := tx.ExecContext(ctx, `DELETE FROM agent_messages
				WHERE session_id = ?1 AND seq NOT IN (
					SELECT seq FROM agent_messages WHERE session_id = ?1 ORDER BY seq DESC LIMIT ?2)`,
				msg.SessionID, retain); err != nil {
				return fmt.Errorf("agentsession: prune messages: %w", err)
			}
		}
		_, err = tx.ExecContext(ctx, `UPDATE agent_sessions SET
			last_seq = MAX(last_seq, ?), status = ?, updated_at = ?, revision = ?
			WHERE session_id = ?`,
			msg.Seq, string(status), storage.FormatTime(tx.Now()), rev, msg.SessionID)
		if err != nil {
			return fmt.Errorf("agentsession: touch session: %w", err)
		}
		return appendStatusEvents(ctx, tx, msg.SessionID, prev, status, max(prevSeq, msg.Seq), rev)
	})
	if err != nil {
		return "", problem.From(err)
	}
	return revision, nil
}

// scanMessage reads one agent_messages row.
func scanMessage(row interface{ Scan(...any) error }) (*Message, error) {
	var (
		msg         Message
		contentJSON sql.NullString
		createdAt   string
	)
	if err := row.Scan(&msg.Seq, &msg.MessageID, &msg.Role, &msg.Content, &contentJSON,
		&msg.OperationID, &msg.ApprovalID, &createdAt); err != nil {
		return nil, err
	}
	if contentJSON.Valid && contentJSON.String != "" {
		msg.ContentJSON = json.RawMessage(contentJSON.String)
	}
	at, err := storage.ParseTime(createdAt)
	if err != nil {
		return nil, fmt.Errorf("agentsession: message time: %w", err)
	}
	msg.CreatedAt = at
	return &msg, nil
}

// messages returns the newest limit messages with seq < before (before <= 0
// means the newest page), in chronological order. The limit is clamped by the
// page rules shared with the list routes (at most maxPageLimit).
func (s *Service) messages(ctx context.Context, sessionID string, before int64, limit int) ([]Message, error) {
	limit = clampLimit(limit, s.cfg.MaxHistory)
	query := `SELECT seq, message_id, role, content, content_json,
		operation_id, approval_id, created_at FROM agent_messages
		WHERE session_id = ?`
	args := []any{sessionID}
	if before > 0 {
		query += ` AND seq < ?`
		args = append(args, before)
	}
	query += ` ORDER BY seq DESC LIMIT ?`
	args = append(args, limit)
	rows, err := s.db.Reader().QueryContext(ctx, query, args...)
	if err != nil {
		return nil, problem.Wrap(err)
	}
	defer rows.Close()
	var out []Message
	for rows.Next() {
		msg, err := scanMessage(rows)
		if err != nil {
			return nil, problem.Wrap(err)
		}
		out = append(out, *msg)
	}
	if err := rows.Err(); err != nil {
		return nil, problem.Wrap(err)
	}
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out, nil
}

// insertToolCall records a proposed call. status is proposed; the result update
// comes later.
func (s *Service) insertToolCall(ctx context.Context, owner actor.Actor, call *ToolRecord) error {
	return s.db.Update(ctx, func(tx *storage.Tx) error {
		tx.SetOrigin(storage.Origin{Actor: owner})
		rev, err := tx.Changed(ctx, storage.Change{
			Subject: sessionSubject(call.SessionID), Kind: storage.Updated, Pointers: []string{"/tool_calls"},
		})
		if err != nil {
			return err
		}
		call.Revision = rev
		_, err = tx.ExecContext(ctx, `INSERT INTO agent_tool_calls
			(call_id, session_id, seq, action_id, args_json, operation_id, approval_id, status,
			 created_at, updated_at, revision)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			call.CallID, call.SessionID, call.Seq, call.Action, string(call.Args),
			call.OperationID, call.ApprovalID, string(call.Status),
			storage.FormatTime(call.CreatedAt), storage.FormatTime(call.UpdatedAt), rev)
		if err != nil {
			return fmt.Errorf("agentsession: insert tool call: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM agent_tool_calls
			WHERE session_id = ?1 AND status IN ('succeeded', 'failed', 'rejected', 'cancelled') AND seq NOT IN (
				SELECT seq FROM agent_tool_calls WHERE session_id = ?1 ORDER BY seq DESC LIMIT ?2)`,
			call.SessionID, retainToolCalls); err != nil {
			return fmt.Errorf("agentsession: prune tool calls: %w", err)
		}
		_, err = tx.ExecContext(ctx, `UPDATE agent_sessions SET
			last_seq = MAX(last_seq, ?), updated_at = ?, revision = ? WHERE session_id = ?`,
			call.Seq, storage.FormatTime(tx.Now()), rev, call.SessionID)
		if err != nil {
			return fmt.Errorf("agentsession: touch session: %w", err)
		}
		return nil
	})
}

// updateToolCall stores the outcome of a call.
func (s *Service) updateToolCall(ctx context.Context, owner actor.Actor, call *ToolRecord) error {
	return s.db.Update(ctx, func(tx *storage.Tx) error {
		tx.SetOrigin(storage.Origin{Actor: owner})
		rev, err := tx.Changed(ctx, storage.Change{
			Subject: sessionSubject(call.SessionID), Kind: storage.Updated, Pointers: []string{"/tool_calls"},
		})
		if err != nil {
			return err
		}
		call.Revision = rev
		call.UpdatedAt = tx.Now()
		var result, errJSON any
		if len(call.Result) > 0 {
			result = string(call.Result)
		}
		if call.Error != nil {
			b, err := json.Marshal(ErrorOf(call.Error))
			if err != nil {
				return err
			}
			errJSON = string(b)
		}
		_, err = tx.ExecContext(ctx, `UPDATE agent_tool_calls SET
			operation_id = ?, approval_id = ?, status = ?, result_json = ?, error_json = ?,
			updated_at = ?, revision = ? WHERE call_id = ? AND session_id = ?`,
			call.OperationID, call.ApprovalID, string(call.Status), result, errJSON,
			storage.FormatTime(call.UpdatedAt), rev, call.CallID, call.SessionID)
		if err != nil {
			return fmt.Errorf("agentsession: update tool call: %w", err)
		}
		_, err = tx.ExecContext(ctx, `UPDATE agent_sessions SET updated_at = ?, revision = ?
			WHERE session_id = ?`, storage.FormatTime(tx.Now()), rev, call.SessionID)
		if err != nil {
			return fmt.Errorf("agentsession: touch session: %w", err)
		}
		return nil
	})
}

// setSessionStatus updates only the session status (used when a turn starts,
// pauses or resumes); it emits the session update event.
func (s *Service) setSessionStatus(ctx context.Context, owner actor.Actor, id string, status Status, lastSeq int64) (string, error) {
	rec, err := s.updateSession(ctx, owner, id, lastSeq, []string{"/status"}, func(cur *Session) error {
		cur.Status = status
		return nil
	})
	if err != nil {
		return "", err
	}
	return rec.Revision, nil
}

// ToolRecord is one agent_tool_calls row.
type ToolRecord struct {
	CallID      string
	SessionID   string
	Seq         int64
	Action      string
	Args        json.RawMessage
	OperationID string
	ApprovalID  string
	Status      ToolStatus
	Result      json.RawMessage
	Error       *problem.Error
	CreatedAt   time.Time
	UpdatedAt   time.Time
	Revision    int64
}

// scanToolRecord reads one agent_tool_calls row.
func scanToolRecord(row interface{ Scan(...any) error }) (*ToolRecord, error) {
	var (
		rec     ToolRecord
		args    string
		status  string
		result  sql.NullString
		errJSON sql.NullString
		created string
		updated string
	)
	if err := row.Scan(&rec.CallID, &rec.SessionID, &rec.Seq, &rec.Action, &args,
		&rec.OperationID, &rec.ApprovalID, &status, &result, &errJSON, &created, &updated,
		&rec.Revision); err != nil {
		return nil, err
	}
	rec.Args = json.RawMessage(args)
	rec.Status = ToolStatus(status)
	if result.Valid && result.String != "" {
		rec.Result = json.RawMessage(result.String)
	}
	if errJSON.Valid && errJSON.String != "" {
		var info ErrorInfo
		if err := json.Unmarshal([]byte(errJSON.String), &info); err != nil {
			return nil, fmt.Errorf("agentsession: tool call error: %w", err)
		}
		rec.Error = info.Problem()
	}
	var err error
	if rec.CreatedAt, err = storage.ParseTime(created); err != nil {
		return nil, fmt.Errorf("agentsession: tool call created_at: %w", err)
	}
	if rec.UpdatedAt, err = storage.ParseTime(updated); err != nil {
		return nil, fmt.Errorf("agentsession: tool call updated_at: %w", err)
	}
	return &rec, nil
}

const toolColumns = `call_id, session_id, seq, action_id, args_json, operation_id, approval_id,
	status, result_json, error_json, created_at, updated_at, revision`

// loadToolCall reads one call of a session by ID.
func (s *Service) loadToolCall(ctx context.Context, sessionID, id string) (*ToolRecord, error) {
	row := s.db.Reader().QueryRowContext(ctx, `SELECT `+toolColumns+` FROM agent_tool_calls
		WHERE call_id = ? AND session_id = ?`, id, sessionID)
	rec, err := scanToolRecord(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, problem.New(problem.NotFound, "No such tool call.")
	}
	if err != nil {
		return nil, problem.Wrap(err)
	}
	return rec, nil
}

// toolCallsWithStatus lists a session's calls in the given states, oldest first.
func (s *Service) toolCallsWithStatus(ctx context.Context, sessionID string, statuses ...ToolStatus) ([]ToolRecord, error) {
	args := make([]any, 0, len(statuses)+1)
	args = append(args, sessionID)
	for _, status := range statuses {
		args = append(args, string(status))
	}
	placeholders := strings.TrimSuffix(strings.Repeat("?,", len(statuses)), ",")
	rows, err := s.db.Reader().QueryContext(ctx, `SELECT `+toolColumns+` FROM agent_tool_calls
		WHERE session_id = ? AND status IN (`+placeholders+`) ORDER BY seq`, args...)
	if err != nil {
		return nil, problem.Wrap(err)
	}
	defer rows.Close()
	var out []ToolRecord
	for rows.Next() {
		rec, err := scanToolRecord(rows)
		if err != nil {
			return nil, problem.Wrap(err)
		}
		out = append(out, *rec)
	}
	if err := rows.Err(); err != nil {
		return nil, problem.Wrap(err)
	}
	return out, nil
}

// runningTurns counts the owner's sessions with a turn running.
func (s *Service) runningTurns(ctx context.Context, owner actor.Actor) (int, error) {
	var n int
	err := s.db.Reader().QueryRowContext(ctx, `SELECT COUNT(*) FROM agent_sessions
		WHERE owner_kind = ? AND owner_id = ? AND status = 'running'`, string(owner.Kind), owner.ID).Scan(&n)
	if err != nil {
		return 0, problem.Wrap(err)
	}
	return n, nil
}

// busySessions lists the sessions of every owner that claim a turn is using
// them. Only Recover may look across owners.
func (s *Service) busySessions(ctx context.Context) ([]Session, error) {
	rows, err := s.db.Reader().QueryContext(ctx, `SELECT `+sessionColumns+` FROM agent_sessions s
		WHERE s.status IN ('running', 'waiting_approval')`)
	if err != nil {
		return nil, problem.Wrap(err)
	}
	defer rows.Close()
	var out []Session
	for rows.Next() {
		rec, err := scanSession(rows)
		if err != nil {
			return nil, problem.Wrap(err)
		}
		out = append(out, *rec)
	}
	if err := rows.Err(); err != nil {
		return nil, problem.Wrap(err)
	}
	return out, nil
}

// assistantMessageOf returns the newest assistant message that proposed
// callID, "" when retention pruned it.
func (s *Service) assistantMessageOf(ctx context.Context, sessionID, callID string) (string, error) {
	rows, err := s.db.Reader().QueryContext(ctx, `SELECT message_id, content_json FROM agent_messages
		WHERE session_id = ? AND role = 'assistant' AND content_json IS NOT NULL ORDER BY seq DESC`, sessionID)
	if err != nil {
		return "", problem.Wrap(err)
	}
	defer rows.Close()
	for rows.Next() {
		var (
			id  string
			raw string
			ac  assistantContent
		)
		if err := rows.Scan(&id, &raw); err != nil {
			return "", problem.Wrap(err)
		}
		if json.Unmarshal([]byte(raw), &ac) != nil {
			continue
		}
		for _, call := range ac.ToolCalls {
			if call.CallID == callID {
				return id, nil
			}
		}
	}
	if err := rows.Err(); err != nil {
		return "", problem.Wrap(err)
	}
	return "", nil
}

// toolMessageCallIDs returns the call ids that already have a tool message.
func (s *Service) toolMessageCallIDs(ctx context.Context, sessionID string) (map[string]bool, error) {
	rows, err := s.db.Reader().QueryContext(ctx, `SELECT content_json FROM agent_messages
		WHERE session_id = ? AND role = 'tool' AND content_json IS NOT NULL`, sessionID)
	if err != nil {
		return nil, problem.Wrap(err)
	}
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var raw sql.NullString
		if err := rows.Scan(&raw); err != nil {
			return nil, problem.Wrap(err)
		}
		if !raw.Valid || raw.String == "" {
			continue
		}
		var tc toolContent
		if err := json.Unmarshal([]byte(raw.String), &tc); err != nil {
			continue
		}
		if tc.CallID != "" {
			out[tc.CallID] = true
		}
	}
	if err := rows.Err(); err != nil {
		return nil, problem.Wrap(err)
	}
	return out, nil
}

// messageByID reads one message.
func (s *Service) messageByID(ctx context.Context, id string) (*Message, error) {
	row := s.db.Reader().QueryRowContext(ctx, `SELECT seq, message_id, role, content, content_json,
		operation_id, approval_id, created_at FROM agent_messages WHERE message_id = ?`, id)
	msg, err := scanMessage(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, problem.New(problem.NotFound, "No such message.")
	}
	if err != nil {
		return nil, problem.Wrap(err)
	}
	return msg, nil
}

// auditDetails marshals audit details, falling back to {} (the details are a
// log, never user-visible).
func auditDetails(v map[string]any) json.RawMessage {
	b, err := json.Marshal(v)
	if err != nil {
		return json.RawMessage("{}")
	}
	return b
}

// maxPageLimit is the largest page a list route returns (agent session list,
// transcript page).
const maxPageLimit = 200

// clampLimit applies the list limit defaults.
func clampLimit(limit, def int) int {
	if limit <= 0 {
		limit = def
	}
	if limit > maxPageLimit {
		limit = maxPageLimit
	}
	return limit
}
