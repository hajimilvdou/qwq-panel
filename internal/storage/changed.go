// SPDX-License-Identifier: AGPL-3.0-only

package storage

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/qwq-panel/qwq/internal/actor"
)

// Origin says who and what caused the writes of a transaction. operations.Run
// sets it at the start of every operation transaction; every event appended
// afterwards carries it (ADR-0004 D3, ADR-0008 §2).
type Origin struct {
	Actor       actor.Actor
	OperationID string
	TraceID     string
	NodeID      string
}

// SetOrigin sets the origin for the rest of the transaction.
func (tx *Tx) SetOrigin(o Origin) { tx.origin = o }

// Origin returns the transaction's origin.
func (tx *Tx) Origin() Origin { return tx.origin }

// ChangeKind is what happened to a subject.
type ChangeKind string

const (
	Created ChangeKind = "create"
	Updated ChangeKind = "update"
	Deleted ChangeKind = "delete"
)

// MaxChangedPointers bounds changed_pointers in one event (public schema).
const MaxChangedPointers = 256

// Change describes one modified resource.
type Change struct {
	Subject string // full subject, e.g. "users/usr_01…"
	Kind    ChangeKind
	// Pointers are the RFC 6901 pointers of the members that changed; empty
	// for create and delete, or when the whole resource changed.
	Pointers []string
}

// resourceChanged is the ResourceChangedPayload of the public API.
type resourceChanged struct {
	Subject                  string      `json:"subject"`
	Revision                 string      `json:"revision"`
	Kind                     ChangeKind  `json:"kind"`
	Actor                    actor.Actor `json:"actor"`
	OperationID              string      `json:"operation_id,omitempty"`
	ChangedPointers          []string    `json:"changed_pointers"`
	ChangedPointersTruncated bool        `json:"changed_pointers_truncated,omitempty"`
}

// Changed records a resource.changed event for c in the transaction and
// returns the subject's new revision: the event's sequence number
// (ADR-0008 §4). Callers store it in the resource row's revision column in the
// same transaction. Every write to a host resource must go through Changed;
// that is what keeps every open UI in sync (ADR-0004 D3).
func (tx *Tx) Changed(ctx context.Context, c Change) (int64, error) {
	switch c.Kind {
	case Created, Updated, Deleted:
	default:
		return 0, fmt.Errorf("storage: unknown change kind %q", c.Kind)
	}
	if c.Subject == "" {
		return 0, errors.New("storage: change without subject")
	}
	a := tx.origin.Actor
	if a.Kind == "" {
		a = actor.SystemActor("host")
	}
	p := resourceChanged{Subject: c.Subject, Kind: c.Kind, Actor: a, OperationID: tx.origin.OperationID,
		ChangedPointers: c.Pointers}
	if p.ChangedPointers == nil {
		p.ChangedPointers = []string{}
	}
	if len(p.ChangedPointers) > MaxChangedPointers {
		p.ChangedPointers, p.ChangedPointersTruncated = p.ChangedPointers[:MaxChangedPointers], true
	}
	draft, err := json.Marshal(p)
	if err != nil {
		return 0, err
	}
	seq, err := tx.AppendEvent(ctx, Event{Type: "resource.changed", SchemaVersion: "1", Subject: c.Subject, Payload: draft})
	if err != nil {
		return 0, err
	}
	// The revision is the event's own sequence, known only after the insert.
	p.Revision = fmt.Sprint(seq)
	final, err := json.Marshal(p)
	if err != nil {
		return 0, err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE event_journal SET payload = ? WHERE seq = ?`, string(final), seq); err != nil {
		return 0, fmt.Errorf("storage: set revision: %w", err)
	}
	return seq, nil
}

// Revision formats a stored revision for the public API.
func Revision(seq int64) string { return fmt.Sprint(seq) }
