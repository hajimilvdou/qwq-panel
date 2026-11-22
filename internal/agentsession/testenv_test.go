// SPDX-License-Identifier: AGPL-3.0-only

package agentsession

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/qwq-panel/qwq/internal/actor"
	"github.com/qwq-panel/qwq/internal/operations"
	"github.com/qwq-panel/qwq/internal/platform/clock"
	"github.com/qwq-panel/qwq/internal/platform/ids"
	"github.com/qwq-panel/qwq/internal/platform/problem"
	"github.com/qwq-panel/qwq/internal/secrets"
	"github.com/qwq-panel/qwq/internal/storage"
)

// Test fixtures. The owner IDs need no format: this package treats them as
// opaque principal identifiers.
var (
	ownerHuman   = actor.Actor{Kind: actor.Human, ID: "usr_alice", SessionID: "ses_alice"}
	ownerOther   = actor.Actor{Kind: actor.Human, ID: "usr_bob", SessionID: "ses_bob"}
	ownerService = actor.Actor{Kind: actor.Service, ID: "svc_ci", OnBehalfOf: "usr_alice"}
	ownerAgent   = actor.Actor{Kind: actor.AIAgent, ID: "dlg_ai", OnBehalfOf: "usr_alice"}
)

// testHost is one service on a real SQLite database.
type testHost struct {
	t     *testing.T
	dir   string
	db    *storage.DB
	svc   *Service
	clock clock.Clock
	ids   *ids.Generator
}

// newTestHost opens a database and a service. The caller may tune Options; DB,
// Clock and IDs are filled.
func newTestHost(t *testing.T, tune ...func(*Options)) *testHost {
	t.Helper()
	dir := t.TempDir()
	db, err := storage.Open(context.Background(), storage.Options{
		Path:   filepath.Join(dir, "qwq.db"),
		Logger: slog.New(slog.DiscardHandler),
	})
	if err != nil {
		t.Fatalf("storage.Open: %v", err)
	}
	clk := clock.System{}
	gen := ids.New(clk.Now)
	opts := Options{DB: db, Clock: clk, IDs: gen, Logger: slog.New(slog.DiscardHandler)}
	for _, fn := range tune {
		fn(&opts)
	}
	svc, err := New(opts)
	if err != nil {
		db.Close()
		t.Fatalf("agentsession.New: %v", err)
	}
	h := &testHost{t: t, dir: dir, db: db, svc: svc, clock: clk, ids: gen}
	t.Cleanup(func() {
		svc.Close()
		db.Close()
	})
	return h
}

// setAPIKey stores the session's API key and fails on error.
func (h *testHost) setAPIKey(owner actor.Actor, sessionID, key string) *Session {
	h.t.Helper()
	rec, err := h.svc.SetAPIKey(context.Background(), owner, sessionID, key)
	if err != nil {
		h.t.Fatalf("SetAPIKey: %v", err)
	}
	return rec
}

// secretCount counts the secret rows of one owner.
func (h *testHost) secretCount(owner string) int {
	h.t.Helper()
	var n int
	if err := h.db.Reader().QueryRowContext(context.Background(),
		`SELECT COUNT(*) FROM secrets WHERE owner = ?`, owner).Scan(&n); err != nil {
		h.t.Fatalf("count secrets: %v", err)
	}
	return n
}

// putSecret stores a value under owner and purpose, the way another subsystem
// of the host would, and returns its reference.
func (h *testHost) putSecret(store *secrets.Store, owner, purpose, value string) secrets.Ref {
	h.t.Helper()
	var ref secrets.Ref
	err := h.db.Update(context.Background(), func(tx *storage.Tx) error {
		var err error
		ref, err = store.Put(context.Background(), tx, owner, purpose, []byte(value))
		return err
	})
	if err != nil {
		h.t.Fatalf("put secret: %v", err)
	}
	return ref
}

// exec runs one statement in a write transaction. Tests use it to plant rows
// the public API refuses to write.
func (h *testHost) exec(query string, args ...any) {
	h.t.Helper()
	err := h.db.Update(context.Background(), func(tx *storage.Tx) error {
		_, err := tx.ExecContext(context.Background(), query, args...)
		return err
	})
	if err != nil {
		h.t.Fatalf("exec %q: %v", query, err)
	}
}

// create makes a session owned by owner.
func (h *testHost) create(owner actor.Actor, req CreateRequest) *Session {
	h.t.Helper()
	rec, err := h.svc.Create(context.Background(), owner, req)
	if err != nil {
		h.t.Fatalf("Create: %v", err)
	}
	return rec
}

// send sends one message and fails on error.
func (h *testHost) send(owner actor.Actor, sessionID, content string) *SendResult {
	h.t.Helper()
	res, err := h.svc.Send(context.Background(), owner, sessionID, SendRequest{Content: content})
	if err != nil {
		h.t.Fatalf("Send: %v", err)
	}
	return res
}

// waitTurn waits for the current turn.
func (h *testHost) waitTurn(sessionID string) {
	h.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := h.svc.WaitTurn(ctx, sessionID); err != nil {
		h.t.Fatalf("WaitTurn: %v", err)
	}
}

// waitStatus polls until the session reaches status.
func (h *testHost) waitStatus(owner actor.Actor, sessionID string, status Status) *Session {
	h.t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		rec, err := h.svc.Get(context.Background(), owner, sessionID)
		if err != nil {
			h.t.Fatalf("Get: %v", err)
		}
		if rec.Status == status {
			return rec
		}
		time.Sleep(2 * time.Millisecond)
	}
	h.t.Fatalf("session %s never reached %s", sessionID, status)
	return nil
}

// subscribe opens a live subscription (no backlog).
func (h *testHost) subscribe(owner actor.Actor, sessionID string) *Subscription {
	h.t.Helper()
	sub, err := h.svc.Subscribe(context.Background(), owner, sessionID, -1)
	if err != nil {
		h.t.Fatalf("Subscribe: %v", err)
	}
	h.t.Cleanup(sub.Close)
	return sub
}

// drain collects the events currently buffered on a subscription.
func drain(sub *Subscription) []Event {
	var out []Event
	for {
		select {
		case e, ok := <-sub.Events:
			if !ok {
				return out
			}
			out = append(out, e)
		default:
			return out
		}
	}
}

// eventsOfType filters events by type.
func eventsOfType(events []Event, typ string) []Event {
	var out []Event
	for _, e := range events {
		if e.Type == typ {
			out = append(out, e)
		}
	}
	return out
}

// requireEvents fails when the expected event type is missing.
func requireEvents(t *testing.T, events []Event, typ string, want int) {
	t.Helper()
	if got := len(eventsOfType(events, typ)); got != want {
		t.Fatalf("%s events = %d, want %d (all: %+v)", typ, got, want, eventTypes(events))
	}
}

// eventTypes renders the event type sequence for a failure message.
func eventTypes(events []Event) []string {
	out := make([]string, 0, len(events))
	for _, e := range events {
		out = append(out, e.Type)
	}
	return out
}

// sortedSeqs reports whether seq strictly increases.
func sortedSeqs(events []Event) bool {
	for i := 1; i < len(events); i++ {
		if events[i].Seq <= events[i-1].Seq {
			return false
		}
	}
	return true
}

// scriptCore is a Core whose behavior is a function.
type scriptCore struct {
	name string
	run  func(ctx context.Context, turn Turn, emit Emit) error
}

func (c *scriptCore) Name() string { return c.name }

func (c *scriptCore) Run(ctx context.Context, turn Turn, emit Emit) error {
	if c.run != nil {
		return c.run(ctx, turn, emit)
	}
	if err := emit(Event{Type: EventMessageDelta, Delta: "ok"}); err != nil {
		return err
	}
	return emit(Event{Type: EventMessageCompleted})
}

// echoCore answers with a fixed text and records the last turn it saw.
type echoCore struct {
	mu       sync.Mutex
	text     string
	last     Turn
	lastMode operations.PermissionMode
	runs     int
}

func (c *echoCore) Name() string { return "native" }

func (c *echoCore) Run(ctx context.Context, turn Turn, emit Emit) error {
	mode, _ := operations.PermissionModeFromContext(ctx)
	c.mu.Lock()
	c.last = turn
	c.lastMode = mode
	c.runs++
	text := c.text
	c.mu.Unlock()
	if text == "" {
		text = "hello"
	}
	if err := emit(Event{Type: EventMessageDelta, Delta: text}); err != nil {
		return err
	}
	return emit(Event{Type: EventMessageCompleted})
}

func (c *echoCore) snapshot() (Turn, int, operations.PermissionMode) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.last, c.runs, c.lastMode
}

// toolCore proposes one tool call on its first run and answers with text on the
// following runs. It is the deterministic stand-in for the native core in the
// approval tests.
type toolCore struct {
	mu     sync.Mutex
	action string
	args   json.RawMessage
	last   Turn
	runs   int
}

func (c *toolCore) Name() string { return "native" }

func (c *toolCore) Run(ctx context.Context, turn Turn, emit Emit) error {
	c.mu.Lock()
	c.last = turn
	c.runs++
	run := c.runs
	c.mu.Unlock()
	if run > 1 {
		if err := emit(Event{Type: EventMessageDelta, Delta: "done"}); err != nil {
			return err
		}
		return emit(Event{Type: EventMessageCompleted})
	}
	nextID := turn.NextCallID
	if nextID == nil {
		nextID = func() string { return "call_test_1" }
	}
	callID := nextID()
	call := MessageToolCall{CallID: callID, Action: c.action, Arguments: c.args}
	if err := emit(Event{Type: EventMessageCompleted, ToolCalls: []MessageToolCall{call}}); err != nil {
		return err
	}
	if err := emit(Event{Type: EventToolCall, CallID: callID, Action: c.action, Args: c.args}); err != nil {
		return err
	}
	res, err := turn.Runner.RunTool(ctx, ToolCall{
		CallID: callID, SessionID: turn.SessionID, PermissionMode: turn.PermissionMode,
		Action: c.action, Args: c.args,
	})
	if err != nil {
		return err
	}
	if res.Status == ToolAwaitingApproval {
		if res.Approval == nil || res.Approval.ApprovalID == "" {
			return problem.New(problem.Internal, "test runner asked for approval without an id")
		}
		if err := emit(Event{
			Type: EventApprovalRequired, CallID: callID, Action: c.action, Args: c.args,
			ApprovalID: res.Approval.ApprovalID, OperationID: res.Approval.OperationID,
			Summary: res.Approval.Summary, Description: res.Approval.Description,
			Risk: res.Approval.Risk, Approval: res.Approval.Approval, Deadline: res.Approval.Deadline,
		}); err != nil {
			return err
		}
		return ErrWaitingApproval
	}
	return emit(Event{
		Type: EventToolResult, CallID: callID, Action: c.action, Status: string(res.Status),
		Result: res.Result, Error: ErrorOf(res.Error), OperationID: res.OperationID, ApprovalID: res.ApprovalID,
	})
}

func (c *toolCore) runCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.runs
}

func (c *toolCore) snapshot() (Turn, int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.last, c.runs
}

// fakeRunner records calls and answers through fn (default: success).
type fakeRunner struct {
	mu    sync.Mutex
	calls []ToolCall
	modes []operations.PermissionMode
	fn    func(ctx context.Context, call ToolCall) (ToolResult, error)
}

func (r *fakeRunner) RunTool(ctx context.Context, call ToolCall) (ToolResult, error) {
	r.mu.Lock()
	r.calls = append(r.calls, call)
	mode, _ := operations.PermissionModeFromContext(ctx)
	r.modes = append(r.modes, mode)
	fn := r.fn
	r.mu.Unlock()
	if fn != nil {
		return fn(ctx, call)
	}
	return ToolResult{Status: ToolSucceeded, Result: json.RawMessage(`{"ok":true}`)}, nil
}

func (r *fakeRunner) snapshot() ([]ToolCall, []operations.PermissionMode) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.calls), slices.Clone(r.modes)
}

// fakeBridge answers an approval from a channel.
type fakeBridge struct {
	mu     sync.Mutex
	waited []string
	reply  chan ApprovalDecision
}

func newFakeBridge() *fakeBridge {
	return &fakeBridge{reply: make(chan ApprovalDecision, 4)}
}

func (b *fakeBridge) Wait(ctx context.Context, approvalID string) (ApprovalDecision, error) {
	b.mu.Lock()
	b.waited = append(b.waited, approvalID)
	b.mu.Unlock()
	select {
	case d := <-b.reply:
		return d, nil
	case <-ctx.Done():
		return ApprovalDecision{}, ctx.Err()
	}
}

func (b *fakeBridge) waitCount() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.waited)
}

// testTools is a small catalog: one read and one write action.
func testTools() []ToolSpec {
	return []ToolSpec{
		{Action: "host.users.list", Summary: "List users", Effect: operations.EffectRead, Risk: "low", Approval: "auto",
			Parameters: json.RawMessage(`{"type":"object","additionalProperties":false}`)},
		{Action: "host.users.create", Summary: "Create a user", Effect: operations.EffectWrite, Risk: "high",
			Approval: "confirm", Description: "Creates a panel user.", Parameters: json.RawMessage(`{"type":"object"}`)},
	}
}

// defaultCreate is the request used by most tests.
func defaultCreate() CreateRequest {
	return CreateRequest{Title: "Test", Core: CoreNative, PermissionMode: operations.PermissionSafe}
}

// requireCode fails when err is not a *problem.Error with code.
func requireCode(t *testing.T, err error, code problem.Code) {
	t.Helper()
	if err == nil {
		t.Fatalf("want %s, got nil", code)
	}
	if !problem.HasCode(err, code) {
		t.Fatalf("want %s, got %v", code, err)
	}
}

// requireStatus fails when the session's status differs.
func requireStatus(t *testing.T, svc *Service, owner actor.Actor, id string, want Status) {
	t.Helper()
	rec, err := svc.Get(context.Background(), owner, id)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if rec.Status != want {
		t.Fatalf("status = %s, want %s", rec.Status, want)
	}
}

// mustJSON marshals a test value.
func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}

// errTest is a sentinel error for the scripts.
var errTest = errors.New("test error")
