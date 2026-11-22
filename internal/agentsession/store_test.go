// SPDX-License-Identifier: AGPL-3.0-only

package agentsession

import (
	"context"
	"encoding/json"
	"log/slog"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/qwq-panel/qwq/internal/actor"
	"github.com/qwq-panel/qwq/internal/operations"
	"github.com/qwq-panel/qwq/internal/platform/problem"
	"github.com/qwq-panel/qwq/internal/storage"
)

// TestCreateGetListOwnership covers session creation, the owner predicate and
// the list filters.
func TestCreateGetListOwnership(t *testing.T) {
	h := newTestHost(t)
	ctx := context.Background()

	first := h.create(ownerHuman, CreateRequest{Title: "  First session  "})
	if first.Title != "First session" {
		t.Fatalf("title = %q", first.Title)
	}
	if first.PluginID != PluginID || first.Core != CoreNative || first.PermissionMode != operations.PermissionSafe {
		t.Fatalf("defaults = %+v", first)
	}
	if first.Status != StatusIdle || first.Revision == "" || first.LastSeq != 0 {
		t.Fatalf("new session = %+v", first)
	}
	second := h.create(ownerHuman, CreateRequest{Title: "Second"})

	// Ownership: another person and a service account get NOT_FOUND.
	for _, other := range []actor.Actor{ownerOther, ownerService} {
		if _, err := h.svc.Get(ctx, other, first.ID); !problem.HasCode(err, problem.NotFound) {
			t.Fatalf("Get as %s = %v, want NOT_FOUND", other.Kind, err)
		}
	}
	if _, err := h.svc.Messages(ctx, ownerOther, first.ID, 0); !problem.HasCode(err, problem.NotFound) {
		t.Fatalf("Messages as another owner = %v", err)
	}

	page, err := h.svc.List(ctx, ownerHuman, ListFilter{})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(page.Items) != 2 || page.Items[0].ID != second.ID || page.Items[1].ID != first.ID {
		t.Fatalf("list order = %+v", page.Items)
	}
	if page.Delta || page.NextCursor != "" {
		t.Fatalf("page = %+v", page)
	}

	// The service account's own sessions are invisible to the human.
	if _, err := h.svc.Create(ctx, ownerService, CreateRequest{Title: "CI"}); err != nil {
		t.Fatalf("Create as service: %v", err)
	}
	servicePage, err := h.svc.List(ctx, ownerService, ListFilter{})
	if err != nil || len(servicePage.Items) != 1 {
		t.Fatalf("service list = %+v, %v", servicePage, err)
	}
	humanPage, _ := h.svc.List(ctx, ownerHuman, ListFilter{})
	if len(humanPage.Items) != 2 {
		t.Fatalf("human list = %d sessions, want 2", len(humanPage.Items))
	}

	// status=attention selects waiting_approval and failed.
	if _, err := h.svc.updateSession(ctx, ownerHuman, first.ID, 0, []string{"/status"}, func(cur *Session) error {
		cur.Status = StatusWaitingApproval
		return nil
	}); err != nil {
		t.Fatalf("set status: %v", err)
	}
	att, err := h.svc.List(ctx, ownerHuman, ListFilter{Status: StatusAttention})
	if err != nil || len(att.Items) != 1 || att.Items[0].ID != first.ID {
		t.Fatalf("attention = %+v, %v", att, err)
	}
	if _, err := h.svc.List(ctx, ownerHuman, ListFilter{Status: "nope"}); !problem.HasCode(err, problem.ValidationFailed) {
		t.Fatalf("invalid status filter = %v", err)
	}
	// The filter is applied before pagination and paging uses session_id.
	one, err := h.svc.List(ctx, ownerHuman, ListFilter{Limit: 1})
	if err != nil || len(one.Items) != 1 || one.NextCursor != one.Items[0].ID {
		t.Fatalf("limit page = %+v, %v", one, err)
	}
	rest, err := h.svc.List(ctx, ownerHuman, ListFilter{Cursor: one.NextCursor})
	if err != nil || len(rest.Items) != 1 || rest.Items[0].ID == one.Items[0].ID {
		t.Fatalf("cursor page = %+v, %v", rest, err)
	}
}

// TestCreateValidation covers the session defaults and the rejected inputs.
func TestCreateValidation(t *testing.T) {
	h := newTestHost(t)
	ctx := context.Background()

	cases := []struct {
		name string
		req  CreateRequest
		code problem.Code
	}{
		{"unknown core", CreateRequest{Core: "gpt"}, problem.ValidationFailed},
		{"unknown mode", CreateRequest{PermissionMode: "yolo"}, problem.ValidationFailed},
		{"plaintext key", CreateRequest{Config: json.RawMessage(`{"api_key":"sk-live"}`)}, problem.ValidationFailed},
		{"bad base url", CreateRequest{Config: json.RawMessage(`{"base_url":"ftp://x"}`)}, problem.ValidationFailed},
		{"bad key ref", CreateRequest{Config: json.RawMessage(`{"base_url":"https://x.test","api_key_secret":"nope"}`)}, problem.ValidationFailed},
		{"secret reference", CreateRequest{Config: json.RawMessage(`{"base_url":"https://x.test","api_key_secret":"sec_0123456789abcdefghjkmnpqrs"}`)}, problem.ValidationFailed},
		{"secret reference on a CLI core", CreateRequest{Core: CoreCodex, Config: json.RawMessage(`{"api_key_secret":"sec_0123456789abcdefghjkmnpqrs"}`)}, problem.ValidationFailed},
		{"bad timeout", CreateRequest{Config: json.RawMessage(`{"timeout_seconds":9999}`)}, problem.ValidationFailed},
		{"not an object", CreateRequest{Config: json.RawMessage(`[1]`)}, problem.ValidationFailed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := h.svc.Create(ctx, ownerHuman, tc.req); !problem.HasCode(err, tc.code) {
				t.Fatalf("Create(%s) = %v, want %s", tc.name, err, tc.code)
			}
		})
	}
	// A config cannot name a secret, whatever the reference points to: the
	// answer sends the client to the api-key route instead (AGT-02).
	_, err := h.svc.Create(ctx, ownerHuman, CreateRequest{
		Config: json.RawMessage(`{"api_key_secret":"sec_0123456789abcdefghjkmnpqrs"}`),
	})
	if p := problem.From(err); p == nil || len(p.Violations) != 1 || p.Violations[0].Pointer != "/config/api_key_secret" ||
		!strings.Contains(p.Violations[0].Message, "/api-key") {
		t.Fatalf("api_key_secret = %+v", p)
	}

	// An AI agent (delegation) cannot own a session.
	if _, err := h.svc.Create(ctx, ownerAgent, CreateRequest{}); !problem.HasCode(err, problem.PermissionDenied) {
		t.Fatalf("Create as ai_agent = %v", err)
	}
	// A native config without secrets is accepted.
	rec, err := h.svc.Create(ctx, ownerHuman, CreateRequest{
		Config: json.RawMessage(`{"base_url":"https://api.example.test/v1","model":"m","timeout_seconds":30}`),
	})
	if err != nil {
		t.Fatalf("Create(native config): %v", err)
	}
	if string(rec.Config) == "" {
		t.Fatal("config was not kept")
	}
}

// TestUpdateModeAndRevision covers the title/mode patch, the expected revision
// and the fact that an AI agent cannot change a session.
func TestUpdateModeAndRevision(t *testing.T) {
	h := newTestHost(t)
	ctx := context.Background()
	rec := h.create(ownerHuman, defaultCreate())

	title := "Renamed"
	updated, err := h.svc.Update(ctx, ownerHuman, rec.ID, UpdateRequest{
		Title: &title, PermissionMode: operations.PermissionFull, ExpectedRevision: rec.Revision,
	})
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	if updated.Title != title || updated.PermissionMode != operations.PermissionFull {
		t.Fatalf("updated = %+v", updated)
	}
	if updated.Revision == rec.Revision {
		t.Fatal("revision did not change")
	}

	// A stale revision is a conflict carrying the current one.
	_, err = h.svc.Update(ctx, ownerHuman, rec.ID, UpdateRequest{Title: &title, ExpectedRevision: rec.Revision})
	if p := problem.From(err); !problem.HasCode(err, problem.RevisionConflict) || p.CurrentRevision != updated.Revision {
		t.Fatalf("stale update = %v (current %q)", err, updated.Revision)
	}
	// Unknown mode and empty patch are rejected.
	if _, err := h.svc.Update(ctx, ownerHuman, rec.ID, UpdateRequest{PermissionMode: "yolo", ExpectedRevision: updated.Revision}); !problem.HasCode(err, problem.ValidationFailed) {
		t.Fatalf("bad mode = %v", err)
	}
	if _, err := h.svc.Update(ctx, ownerHuman, rec.ID, UpdateRequest{ExpectedRevision: updated.Revision}); !problem.HasCode(err, problem.ValidationFailed) {
		t.Fatalf("empty patch = %v", err)
	}
	// Another owner sees NOT_FOUND; an AI agent is refused outright.
	other := "x"
	if _, err := h.svc.Update(ctx, ownerOther, rec.ID, UpdateRequest{Title: &other, ExpectedRevision: updated.Revision}); !problem.HasCode(err, problem.NotFound) {
		t.Fatalf("other owner update = %v", err)
	}
	if _, err := h.svc.Update(ctx, ownerAgent, rec.ID, UpdateRequest{Title: &other, ExpectedRevision: updated.Revision}); !problem.HasCode(err, problem.PermissionDenied) {
		t.Fatalf("ai agent update = %v", err)
	}
	// The list's since_revision filter sees the new revision.
	page, err := h.svc.List(ctx, ownerHuman, ListFilter{SinceRevision: rec.Revision})
	if err != nil || len(page.Items) != 1 || !page.Delta {
		t.Fatalf("delta list = %+v, %v", page, err)
	}
}

// TestSeqMonotonicAndRetention checks that session sequences only grow and that
// the transcript is pruned to the configured retention while tool calls stay.
func TestSeqMonotonicAndRetention(t *testing.T) {
	h := newTestHost(t, func(o *Options) {
		o.Cores = []Core{&echoCore{text: "answer"}}
		o.Config.RetainMessages = 5
	})
	ctx := context.Background()
	rec := h.create(ownerHuman, defaultCreate())

	var seqs []int64
	for i := 0; i < 3; i++ {
		res := h.send(ownerHuman, rec.ID, "question")
		seqs = append(seqs, res.Message.Seq)
		h.waitTurn(rec.ID)
	}
	if !slices.IsSorted(seqs) || seqs[0] == seqs[1] {
		t.Fatalf("user seqs = %v", seqs)
	}
	msgs, err := h.svc.Messages(ctx, ownerHuman, rec.ID, 0)
	if err != nil {
		t.Fatalf("Messages: %v", err)
	}
	// Three turns produce six messages; only the newest five are retained.
	if len(msgs) != 5 {
		t.Fatalf("retained = %d messages, want 5 (%+v)", len(msgs), msgs)
	}
	if msgs[len(msgs)-1].Role != RoleAssistant {
		t.Fatalf("last message = %+v", msgs[len(msgs)-1])
	}
	// Sequence numbers remain unique and monotonic across the pruned window.
	for i := 1; i < len(msgs); i++ {
		if msgs[i].Seq <= msgs[i-1].Seq {
			t.Fatalf("messages out of order: %+v", msgs)
		}
	}
	sess, err := h.svc.Get(ctx, ownerHuman, rec.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if sess.LastSeq < msgs[len(msgs)-1].Seq || sess.LastSeq <= seqs[len(seqs)-1] {
		t.Fatalf("last_seq = %d, last message = %d, user seqs = %v", sess.LastSeq, msgs[len(msgs)-1].Seq, seqs)
	}

	// A tool call and its approval association are not pruned by the message
	// retention (design §2).
	call := &ToolRecord{
		CallID: "call_keep", SessionID: rec.ID, Seq: sess.LastSeq + 1,
		Action: "host.users.create", Args: json.RawMessage(`{"username":"bob"}`),
		Status: ToolAwaitingApproval, ApprovalID: "apv_keep",
		CreatedAt: sess.UpdatedAt, UpdatedAt: sess.UpdatedAt,
	}
	if err := h.svc.insertToolCall(ctx, ownerHuman, call); err != nil {
		t.Fatalf("insertToolCall: %v", err)
	}
	pending, err := h.svc.PendingApprovals(ctx, ownerHuman, rec.ID)
	if err != nil || len(pending) != 1 || pending[0].CallID != "call_keep" {
		t.Fatalf("pending = %+v, %v", pending, err)
	}
}

// TestDeleteRemovesSessionAndKeepsAudit checks the delete path, the audit row
// and the closed SSE stream.
func TestDeleteRemovesSessionAndKeepsAudit(t *testing.T) {
	h := newTestHost(t)
	ctx := context.Background()
	rec := h.create(ownerHuman, defaultCreate())
	sub := h.subscribe(ownerHuman, rec.ID)

	if err := h.svc.Delete(ctx, ownerOther, rec.ID); !problem.HasCode(err, problem.NotFound) {
		t.Fatalf("delete by another owner = %v", err)
	}
	if err := h.svc.Delete(ctx, ownerHuman, rec.ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := h.svc.Get(ctx, ownerHuman, rec.ID); !problem.HasCode(err, problem.NotFound) {
		t.Fatalf("Get after delete = %v", err)
	}
	var audits int
	if err := h.db.Reader().QueryRowContext(ctx,
		`SELECT COUNT(*) FROM audit_log WHERE action = 'agent.session.delete'`).Scan(&audits); err != nil {
		t.Fatalf("audit count: %v", err)
	}
	if audits != 1 {
		t.Fatalf("audit rows = %d, want 1", audits)
	}
	// The subscriber was closed and marked overflowed so its handler resyncs.
	select {
	case _, ok := <-sub.Events:
		if ok {
			t.Fatal("subscriber received an event after the session was deleted")
		}
	default:
		t.Fatal("subscriber was not closed")
	}
	if !sub.Overflowed() {
		t.Fatal("closed subscription is not marked overflowed")
	}
}

// TestReopenDatabaseRestoresSessions checks that a restart keeps sessions,
// sequences and messages.
func TestReopenDatabaseRestoresSessions(t *testing.T) {
	h := newTestHost(t, func(o *Options) { o.Cores = []Core{&echoCore{text: "persisted"}} })
	ctx := context.Background()
	rec := h.create(ownerHuman, defaultCreate())
	h.send(ownerHuman, rec.ID, "remember this")
	h.waitTurn(rec.ID)
	before, err := h.svc.Get(ctx, ownerHuman, rec.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	h.svc.Close()
	if err := h.db.Close(); err != nil {
		t.Fatalf("close db: %v", err)
	}

	// Reopen the same file with a new service.
	db, err := openExisting(t, h.dir)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer db.Close()
	svc, err := New(Options{DB: db, Cores: []Core{&echoCore{}}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer svc.Close()
	after, err := svc.Get(ctx, ownerHuman, rec.ID)
	if err != nil {
		t.Fatalf("Get after reopen: %v", err)
	}
	if after.LastSeq != before.LastSeq || after.Status != before.Status || after.Revision != before.Revision {
		t.Fatalf("reopened session = %+v, before %+v", after, before)
	}
	msgs, err := svc.Messages(ctx, ownerHuman, rec.ID, 0)
	if err != nil || len(msgs) != 2 {
		t.Fatalf("messages after reopen = %+v, %v", msgs, err)
	}
	// The event ring lived in memory: after a restart a client that asks for the
	// beginning must resync instead of believing it has the whole stream.
	sub, err := svc.Subscribe(ctx, ownerHuman, rec.ID, 0)
	if err != nil || !sub.Resync {
		t.Fatalf("subscribe after reopen = %+v, %v", sub, err)
	}
	sub.Close()
	// A new send continues the sequence, not restarts it.
	res, err := svc.Send(ctx, ownerHuman, rec.ID, SendRequest{Content: "again"})
	if err != nil {
		t.Fatalf("Send after reopen: %v", err)
	}
	if res.Message.Seq <= before.LastSeq {
		t.Fatalf("seq = %d, want > %d", res.Message.Seq, before.LastSeq)
	}
}

// TestClientMessageIDIsIdempotent checks the send retry guard.
func TestClientMessageIDIsIdempotent(t *testing.T) {
	h := newTestHost(t, func(o *Options) { o.Cores = []Core{&echoCore{}} })
	ctx := context.Background()
	rec := h.create(ownerHuman, defaultCreate())
	first, err := h.svc.Send(ctx, ownerHuman, rec.ID, SendRequest{Content: "once", ClientMessageID: "client-1"})
	if err != nil {
		t.Fatalf("Send: %v", err)
	}
	h.waitTurn(rec.ID)
	second, err := h.svc.Send(ctx, ownerHuman, rec.ID, SendRequest{Content: "once", ClientMessageID: "client-1"})
	if err != nil {
		t.Fatalf("retried Send: %v", err)
	}
	if second.Message.Seq != first.Message.Seq || second.Message.MessageID != first.Message.MessageID {
		t.Fatalf("retry = %+v, first = %+v", second.Message, first.Message)
	}
	msgs, err := h.svc.Messages(ctx, ownerHuman, rec.ID, 0)
	if err != nil {
		t.Fatalf("Messages: %v", err)
	}
	if len(msgs) != 2 {
		t.Fatalf("messages = %d, want 2 (one user and one assistant)", len(msgs))
	}
	if _, err := h.svc.Send(ctx, ownerHuman, rec.ID, SendRequest{Content: "x", ClientMessageID: "bad id!"}); !problem.HasCode(err, problem.ValidationFailed) {
		t.Fatalf("bad client id = %v", err)
	}
}

// openExisting opens an existing database file for the reopen test.
func openExisting(t *testing.T, dir string) (*storage.DB, error) {
	t.Helper()
	return storage.Open(context.Background(), storage.Options{
		Path:   filepath.Join(dir, "qwq.db"),
		Logger: slog.New(slog.DiscardHandler),
	})
}
