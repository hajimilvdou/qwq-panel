// SPDX-License-Identifier: AGPL-3.0-only

package agentsession

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/qwq-panel/qwq/internal/actor"
	"github.com/qwq-panel/qwq/internal/operations"
	"github.com/qwq-panel/qwq/internal/storage"
)

// ============================================================================
//  会话状态变化进入全局事件流（GAP-6）
// ============================================================================

// journal reads every committed journal event, oldest first.
func (h *testHost) journal() []storage.Event {
	h.t.Helper()
	events, err := h.db.EventsAfter(context.Background(), 0, 10000)
	if err != nil {
		h.t.Fatalf("EventsAfter: %v", err)
	}
	return events
}

// journalOfType filters the journal by event type.
func journalOfType(events []storage.Event, typ string) []storage.Event {
	var out []storage.Event
	for _, e := range events {
		if e.Type == typ {
			out = append(out, e)
		}
	}
	return out
}

// updatedWire decodes an agent.session.updated payload.
type updatedWire struct {
	SessionID        string `json:"session_id"`
	Status           Status `json:"status"`
	PreviousStatus   Status `json:"previous_status"`
	PendingApprovals int    `json:"pending_approvals"`
	LastSeq          int64  `json:"last_seq"`
	LastMessageAt    string `json:"last_message_at"`
	Revision         string `json:"revision"`
}

// attentionWire decodes an agent.session.attention payload.
type attentionWire struct {
	SessionID   string `json:"session_id"`
	Status      Status `json:"status"`
	ApprovalID  string `json:"approval_id"`
	OperationID string `json:"operation_id"`
	Revision    string `json:"revision"`
}

// hasResourceRevision reports whether a resource.changed event of subject
// carries rev as its revision.
func hasResourceRevision(events []storage.Event, subject, rev string) bool {
	for _, e := range events {
		if e.Type != "resource.changed" || e.Subject != subject {
			continue
		}
		var rc struct {
			Revision string `json:"revision"`
		}
		if json.Unmarshal(e.Payload, &rc) == nil && rc.Revision == rev {
			return true
		}
	}
	return false
}

// TestGlobalSessionEventsLifecycle covers the gap-6 broadcast of one plain
// turn: agent.session.updated on both status transitions, no attention event,
// revision shared with the commit's resource.changed, and no title or
// transcript text in any payload.
func TestGlobalSessionEventsLifecycle(t *testing.T) {
	h := newTestHost(t, func(o *Options) { o.Cores = []Core{&echoCore{text: "secret answer"}} })
	rec := h.create(ownerHuman, CreateRequest{
		Title: "secret title", Core: CoreNative, PermissionMode: operations.PermissionSafe,
	})
	sent := h.send(ownerHuman, rec.ID, "secret question")
	h.waitTurn(rec.ID)

	events := h.journal()
	updates := journalOfType(events, "agent.session.updated")
	if len(updates) != 2 {
		t.Fatalf("updated events = %d, want 2 (all: %v)", len(updates), journalTypes(events))
	}
	subject := "agent_sessions/" + rec.ID

	var first updatedWire
	if err := json.Unmarshal(updates[0].Payload, &first); err != nil {
		t.Fatalf("updated payload: %v", err)
	}
	if first.SessionID != rec.ID || first.Status != StatusRunning || first.PreviousStatus != StatusIdle {
		t.Fatalf("first transition = %+v", first)
	}
	if first.LastSeq != sent.Message.Seq || first.PendingApprovals != 0 || first.LastMessageAt == "" || first.Revision == "" {
		t.Fatalf("first snapshot = %+v", first)
	}
	if updates[0].Subject != subject || updates[0].ActorKind != string(actor.Human) || updates[0].ActorID != ownerHuman.ID {
		t.Fatalf("first envelope = %+v", updates[0])
	}
	if !hasResourceRevision(events, subject, first.Revision) {
		t.Fatalf("updated revision %q is not a resource.changed revision of %s", first.Revision, subject)
	}

	var second updatedWire
	if err := json.Unmarshal(updates[1].Payload, &second); err != nil {
		t.Fatalf("updated payload: %v", err)
	}
	if second.Status != StatusIdle || second.PreviousStatus != StatusRunning {
		t.Fatalf("second transition = %+v", second)
	}

	// A clean turn never asks for attention.
	if got := journalOfType(events, "agent.session.attention"); len(got) != 0 {
		t.Fatalf("attention events = %+v", got)
	}
	// The payloads carry no title, no message text and no arguments.
	for _, e := range append(updates, journalOfType(events, "agent.session.attention")...) {
		if s := string(e.Payload); strings.Contains(s, "secret") {
			t.Fatalf("payload leaks user text: %s", s)
		}
	}

	// Delete keeps the standard resource.changed (kind delete) and adds no
	// session event of its own.
	if err := h.svc.Delete(context.Background(), ownerHuman, rec.ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	deletes := 0
	for _, e := range journalOfType(h.journal(), "resource.changed") {
		if e.Subject != subject {
			continue
		}
		var rc struct {
			Kind string `json:"kind"`
		}
		if json.Unmarshal(e.Payload, &rc) == nil && rc.Kind == "delete" {
			deletes++
		}
	}
	if deletes != 1 {
		t.Fatalf("delete resource.changed events = %d, want 1", deletes)
	}
	if got := journalOfType(h.journal(), "agent.session.updated"); len(got) != 2 {
		t.Fatalf("delete added a session event: %v", journalTypes(got))
	}
}

// TestGlobalSessionAttentionOnWaitingApproval covers the attention event of
// the waiting_approval transition: same revision as the updated event of the
// commit, the approval and operation ids of the paused call, and the pending
// count on the snapshot.
func TestGlobalSessionAttentionOnWaitingApproval(t *testing.T) {
	h := newTestHost(t, func(o *Options) {
		o.Cores = []Core{&toolCore{action: "host.users.create", args: json.RawMessage(`{}`)}}
		o.Runner = &fakeRunner{fn: func(context.Context, ToolCall) (ToolResult, error) {
			return ToolResult{Status: ToolAwaitingApproval, Approval: &ApprovalInfo{
				ApprovalID: "apv_1", OperationID: "op_1", Summary: "s",
			}}, nil
		}}
	})
	rec := h.create(ownerHuman, defaultCreate())
	h.send(ownerHuman, rec.ID, "please")
	h.waitStatus(ownerHuman, rec.ID, StatusWaitingApproval)

	events := h.journal()
	attention := journalOfType(events, "agent.session.attention")
	if len(attention) != 1 {
		t.Fatalf("attention events = %v", journalTypes(events))
	}
	var att attentionWire
	if err := json.Unmarshal(attention[0].Payload, &att); err != nil {
		t.Fatalf("attention payload: %v", err)
	}
	if att.SessionID != rec.ID || att.Status != StatusWaitingApproval || att.ApprovalID != "apv_1" ||
		att.OperationID != "op_1" || att.Revision == "" {
		t.Fatalf("attention = %+v", att)
	}

	var paused updatedWire
	found := false
	for _, e := range journalOfType(events, "agent.session.updated") {
		var p updatedWire
		if json.Unmarshal(e.Payload, &p) == nil && p.Status == StatusWaitingApproval {
			paused, found = p, true
		}
	}
	if !found {
		t.Fatal("no updated event for the waiting_approval transition")
	}
	if paused.PreviousStatus != StatusRunning || paused.PendingApprovals != 1 {
		t.Fatalf("waiting snapshot = %+v", paused)
	}
	// One commit, one revision: attention and updated name the same one.
	if att.Revision != paused.Revision {
		t.Fatalf("attention revision %q, updated revision %q", att.Revision, paused.Revision)
	}
}

// TestGlobalSessionAttentionOnFailed covers the attention event of a failing
// turn: status failed and no approval id.
func TestGlobalSessionAttentionOnFailed(t *testing.T) {
	h := newTestHost(t, func(o *Options) {
		o.Cores = []Core{&scriptCore{name: "native", run: func(context.Context, Turn, Emit) error { return errTest }}}
	})
	rec := h.create(ownerHuman, defaultCreate())
	h.send(ownerHuman, rec.ID, "go")
	h.waitStatus(ownerHuman, rec.ID, StatusFailed)

	attention := journalOfType(h.journal(), "agent.session.attention")
	if len(attention) != 1 {
		t.Fatalf("attention events = %d, want 1", len(attention))
	}
	var att attentionWire
	if err := json.Unmarshal(attention[0].Payload, &att); err != nil {
		t.Fatalf("attention payload: %v", err)
	}
	if att.Status != StatusFailed || att.ApprovalID != "" || att.OperationID != "" {
		t.Fatalf("failed attention = %+v", att)
	}
}

// journalTypes renders the event type sequence for a failure message.
func journalTypes(events []storage.Event) []string {
	out := make([]string, 0, len(events))
	for _, e := range events {
		out = append(out, e.Type)
	}
	return out
}
