// SPDX-License-Identifier: AGPL-3.0-only

// Package events tails the event journal and fans events out to subscribers.
//
// The journal (internal/storage) is the host's transactional outbox: an event
// becomes visible only after the transaction that wrote it committed, and its
// sequence number is the SSE id and Last-Event-ID (ADR-0008 §4). One Hub runs a
// single tail loop for every subscriber: it blocks in
// storage.DB.WaitAfter until the head moves, reads each new batch once and
// dispatches it, so a thousand connected Shells cost one journal reader
// instead of a thousand pollers (ARCH §4.2).
//
// Reliable events are delivered at least once: a subscriber passes the last
// sequence it processed and deduplicates by event_id. Each subscriber has a
// bounded buffer; a slow one is disconnected and must resynchronize instead of
// slowing the publisher. Realtime samples (metrics, presence) never enter the
// journal: Lossy is an in-memory, coalescing, fixed-capacity fanout for them
// (ARCH §4.2).
package events

import (
	"bytes"
	"encoding/json"
	"strconv"
	"strings"

	"github.com/qwq-panel/qwq/internal/actor"
	"github.com/qwq-panel/qwq/internal/storage"
)

// Delivery classes of the public Event schema.
const (
	// DeliveryReliable events are journaled and can be replayed.
	DeliveryReliable = "reliable"
	// DeliveryLossyRealtime events are in-memory samples with no replay.
	DeliveryLossyRealtime = "lossy_realtime"
)

// Resync reasons of the public StreamResync schema.
const (
	ReasonRetentionExceeded = "retention_exceeded"
	ReasonBufferOverflow    = "buffer_overflow"
	ReasonServerRestart     = "server_restart"
)

// Actor is the public Actor schema (display_name is filled in by the Shell
// from its user list, so the host does not repeat it on every event).
type Actor struct {
	Kind       string `json:"kind"`
	ID         string `json:"id"`
	OnBehalfOf string `json:"on_behalf_of,omitempty"`
}

// Event is one journal event in its public wire form (Event in the OpenAPI
// document). Sequence is a decimal string because a JavaScript client cannot
// hold a uint64 exactly (ADR-0006 D7).
//
// An Event is shared by every subscriber of a dispatch: Payload must not be
// modified after conversion.
type Event struct {
	EventID       string          `json:"event_id"`
	Sequence      string          `json:"sequence"`
	Type          string          `json:"type"`
	SchemaVersion string          `json:"schema_version"`
	Subject       string          `json:"subject"`
	OccurredAt    string          `json:"occurred_at"`
	Actor         Actor           `json:"actor"`
	NodeID        string          `json:"node_id,omitempty"`
	TraceID       string          `json:"trace_id,omitempty"`
	OperationID   string          `json:"operation_id,omitempty"`
	DeliveryClass string          `json:"delivery_class"`
	Payload       json.RawMessage `json:"payload"`

	// Seq is the numeric sequence, used for comparisons; it is not serialized.
	Seq int64 `json:"-"`
}

// Convert renders a journal row as an Event.
func Convert(e storage.Event) Event {
	payload := e.Payload
	if len(payload) == 0 {
		payload = json.RawMessage("{}")
	}
	// The SSE data field must be one line. Host payloads are compact, but a
	// plugin-supplied payload could carry whitespace.
	if bytes.ContainsAny(payload, "\r\n") {
		var buf bytes.Buffer
		if err := json.Compact(&buf, payload); err == nil {
			payload = json.RawMessage(buf.Bytes())
		}
	}
	return Event{
		EventID:       e.EventID,
		Sequence:      strconv.FormatInt(e.Seq, 10),
		Type:          e.Type,
		SchemaVersion: e.SchemaVersion,
		Subject:       e.Subject,
		OccurredAt:    storage.FormatTime(e.OccurredAt),
		Actor:         Actor{Kind: e.ActorKind, ID: e.ActorID, OnBehalfOf: e.OnBehalfOf},
		NodeID:        e.NodeID,
		TraceID:       e.TraceID,
		OperationID:   e.OperationID,
		DeliveryClass: DeliveryReliable,
		Payload:       payload,
		Seq:           e.Seq,
	}
}

// Filter selects events for one subscription. Both members are optional; the
// zero value matches every event.
type Filter struct {
	// Topics are event types matched exactly, or prefixes ending in ".*" that
	// match every type below that prefix (the `topics` parameter of
	// GET /api/v1/events). Empty = every type.
	Topics []string
	// SubjectPrefix restricts delivery to subjects with this prefix, e.g.
	// "nodes/local/plugins/". Empty = every subject. Host components that
	// watch one subtree use it; the public API does not expose it.
	SubjectPrefix string
}

// Match reports whether e passes the filter.
func (f Filter) Match(e Event) bool {
	if f.SubjectPrefix != "" && !strings.HasPrefix(e.Subject, f.SubjectPrefix) {
		return false
	}
	if len(f.Topics) == 0 {
		return true
	}
	for _, t := range f.Topics {
		if prefix, ok := strings.CutSuffix(t, ".*"); ok {
			if strings.HasPrefix(e.Type, prefix+".") {
				return true
			}
			continue
		}
		if e.Type == t {
			return true
		}
	}
	return false
}

// Visibility decides whether an actor may see an event. A nil Visibility
// denies every event, so a host that forgets to wire authorization leaks
// nothing; the real check (read permission on the subject) is supplied by
// internal/authz when the controller assembles the host.
type Visibility func(actor.Actor, Event) bool

// AllowAll grants every event. Tests and single-operator hosts use it;
// production must pass the authorization check instead.
func AllowAll(actor.Actor, Event) bool { return true }

// DenyAll denies every event, matching a nil Visibility.
func DenyAll(actor.Actor, Event) bool { return false }
