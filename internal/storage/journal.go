// SPDX-License-Identifier: AGPL-3.0-only

package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/qwq-panel/qwq/internal/platform/ids"
)

// Event is a journal row. Field names follow the public Event schema.
type Event struct {
	Seq           int64
	EventID       string
	Type          string
	SchemaVersion string
	Subject       string
	OccurredAt    time.Time
	ActorKind     string
	ActorID       string
	OnBehalfOf    string
	NodeID        string
	TraceID       string
	OperationID   string
	Payload       json.RawMessage
}

// AppendEvent writes e to the journal inside the transaction and returns its
// sequence number. EventID and OccurredAt are assigned here; Seq is ignored.
// Empty actor, node, trace and operation fields are filled from the
// transaction's Origin. Resource changes use Changed instead.
func (tx *Tx) AppendEvent(ctx context.Context, e Event) (int64, error) {
	if e.Type == "" || e.SchemaVersion == "" || e.Subject == "" {
		return 0, errors.New("storage: event needs type, schema_version and subject")
	}
	o := tx.origin
	if e.ActorKind == "" && o.Actor.Kind != "" {
		e.ActorKind, e.ActorID, e.OnBehalfOf = string(o.Actor.Kind), o.Actor.ID, o.Actor.OnBehalfOf
	}
	if e.OperationID == "" {
		e.OperationID = o.OperationID
	}
	if e.TraceID == "" {
		e.TraceID = o.TraceID
	}
	if e.NodeID == "" {
		e.NodeID = o.NodeID
	}
	payload := e.Payload
	if len(payload) == 0 {
		payload = json.RawMessage("{}")
	}
	if !json.Valid(payload) {
		return 0, errors.New("storage: event payload is not valid JSON")
	}
	res, err := tx.ExecContext(ctx, `INSERT INTO event_journal
		(event_id, type, schema_version, subject, occurred_at, actor_kind, actor_id, on_behalf_of, node_id, trace_id, operation_id, payload)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		tx.NewID(ids.Event), e.Type, e.SchemaVersion, e.Subject, FormatTime(tx.now),
		e.ActorKind, e.ActorID, e.OnBehalfOf, e.NodeID, e.TraceID, e.OperationID, string(payload))
	if err != nil {
		return 0, fmt.Errorf("storage: append event: %w", err)
	}
	seq, err := res.LastInsertId()
	if err != nil {
		return 0, err
	}
	tx.lastSeq = seq
	return seq, nil
}

// EventsAfter returns up to limit events with seq > after, in order.
func (db *DB) EventsAfter(ctx context.Context, after int64, limit int) ([]Event, error) {
	if limit <= 0 || limit > 1000 {
		limit = 1000
	}
	rows, err := db.r.QueryContext(ctx, `SELECT seq, event_id, type, schema_version, subject, occurred_at,
		actor_kind, actor_id, on_behalf_of, node_id, trace_id, operation_id, payload
		FROM event_journal WHERE seq > ? ORDER BY seq LIMIT ?`, after, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Event
	for rows.Next() {
		var e Event
		var at, payload string
		if err := rows.Scan(&e.Seq, &e.EventID, &e.Type, &e.SchemaVersion, &e.Subject, &at,
			&e.ActorKind, &e.ActorID, &e.OnBehalfOf, &e.NodeID, &e.TraceID, &e.OperationID, &payload); err != nil {
			return nil, err
		}
		if e.OccurredAt, err = ParseTime(at); err != nil {
			return nil, fmt.Errorf("storage: event %d: %w", e.Seq, err)
		}
		e.Payload = json.RawMessage(payload)
		out = append(out, e)
	}
	return out, rows.Err()
}

// OldestSeq returns the smallest retained sequence, or 0 when the journal is
// empty. A client resuming from a Last-Event-ID below OldestSeq-1 has missed
// pruned events and must resynchronize.
func (db *DB) OldestSeq(ctx context.Context) (int64, error) {
	var s sql.NullInt64
	err := db.r.QueryRowContext(ctx, `SELECT MIN(seq) FROM event_journal`).Scan(&s)
	return s.Int64, err
}

// HeadSeq returns the highest committed sequence (0 when empty).
func (db *DB) HeadSeq() int64 { s, _ := db.mark.current(); return s }

// WaitAfter blocks until an event with seq > after has been committed or ctx
// ends, and returns the current head. It allocates nothing per waiter beyond
// the shared channel, so thousands of SSE clients cost one channel.
func (db *DB) WaitAfter(ctx context.Context, after int64) (int64, error) {
	for {
		head, ch := db.mark.current()
		if head > after {
			return head, nil
		}
		select {
		case <-ch:
		case <-ctx.Done():
			return head, ctx.Err()
		}
	}
}

// PruneEvents deletes events that are both older than minAge and outside the
// newest keep events (retention is the union, ADR-0008 §4). It deletes at most
// batch rows per call so the write lock is held briefly; it returns the count.
func (db *DB) PruneEvents(ctx context.Context, keep int64, minAge time.Duration, batch int) (int64, error) {
	if batch <= 0 {
		batch = 1000
	}
	var n int64
	err := db.Update(ctx, func(tx *Tx) error {
		cutoff := FormatTime(tx.now.Add(-minAge))
		res, err := tx.ExecContext(ctx, `DELETE FROM event_journal WHERE seq IN (
			SELECT seq FROM event_journal
			WHERE seq <= (SELECT COALESCE(MAX(seq), 0) FROM event_journal) - ? AND occurred_at < ?
			ORDER BY seq LIMIT ?)`, keep, cutoff, batch)
		if err != nil {
			return err
		}
		n, err = res.RowsAffected()
		return err
	})
	return n, err
}

// watermark publishes the committed journal head. Waiters share one channel
// that is closed and replaced whenever the head advances.
type watermark struct {
	mu   sync.Mutex
	head int64
	ch   chan struct{}
}

func (w *watermark) init() { w.ch = make(chan struct{}) }

func (w *watermark) current() (int64, <-chan struct{}) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.head, w.ch
}

func (w *watermark) advance(seq int64) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if seq <= w.head {
		return
	}
	w.head = seq
	close(w.ch)
	w.ch = make(chan struct{})
}
