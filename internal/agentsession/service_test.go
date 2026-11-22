// SPDX-License-Identifier: AGPL-3.0-only

package agentsession

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/qwq-panel/qwq/internal/actor"
	"github.com/qwq-panel/qwq/internal/operations"
	"github.com/qwq-panel/qwq/internal/platform/problem"
	"github.com/qwq-panel/qwq/internal/storage"
)

// TestSendEmitsAndPersists covers the happy path: a user message starts one
// turn, the core streams and completes a message, and the transcript is stored
// with increasing sequences.
func TestSendEmitsAndPersists(t *testing.T) {
	core := &echoCore{text: "hi there"}
	h := newTestHost(t, func(o *Options) {
		o.Cores = []Core{core}
		o.Catalog = StaticCatalog{Tools: testTools()}
	})
	ctx := context.Background()
	rec := h.create(ownerHuman, defaultCreate())
	sub := h.subscribe(ownerHuman, rec.ID)

	res := h.send(ownerHuman, rec.ID, "hello")
	h.waitTurn(rec.ID)
	if res.Message.Role != RoleUser || res.Message.Seq != 1 {
		t.Fatalf("send result = %+v", res)
	}

	events := drain(sub)
	requireEvents(t, events, EventMessageDelta, 1)
	requireEvents(t, events, EventMessageCompleted, 1)
	requireEvents(t, events, EventTurnCompleted, 1)
	if !sortedSeqs(events) {
		t.Fatalf("event sequences are not increasing: %+v", events)
	}
	last := events[len(events)-1]
	if last.Type != EventTurnCompleted || last.Status != string(StatusIdle) {
		t.Fatalf("last event = %+v", last)
	}
	if events[0].Seq != res.Message.Seq+1 {
		t.Fatalf("first seq = %d, want %d", events[0].Seq, res.Message.Seq+1)
	}

	msgs, err := h.svc.Messages(ctx, ownerHuman, rec.ID, 0)
	if err != nil {
		t.Fatalf("Messages: %v", err)
	}
	if len(msgs) != 2 || msgs[0].Role != RoleUser || msgs[1].Role != RoleAssistant {
		t.Fatalf("messages = %+v", msgs)
	}
	if msgs[1].Content != "hi there" || msgs[1].MessageID == "" {
		t.Fatalf("assistant message = %+v", msgs[1])
	}
	sess, _ := h.svc.Get(ctx, ownerHuman, rec.ID)
	if sess.Status != StatusIdle || sess.LastSeq != last.Seq {
		t.Fatalf("session = %+v, last event seq %d", sess, last.Seq)
	}

	// The mode reached the core context and the mode decides the tool list.
	turn, runs, mode := core.snapshot()
	if runs != 1 || mode != operations.PermissionSafe {
		t.Fatalf("core runs = %d, mode = %q", runs, mode)
	}
	if len(turn.Tools) != len(testTools()) {
		t.Fatalf("tools in safe mode = %+v", turn.Tools)
	}
	if len(turn.Messages) != 1 || turn.Messages[0].Content != "hello" {
		t.Fatalf("history = %+v", turn.Messages)
	}
}

// TestConcurrentSendConflict checks the one-turn-per-session rule.
func TestConcurrentSendConflict(t *testing.T) {
	gate := make(chan struct{})
	h := newTestHost(t, func(o *Options) {
		o.Cores = []Core{&scriptCore{name: "native", run: func(ctx context.Context, turn Turn, emit Emit) error {
			<-gate
			return emit(Event{Type: EventTurnCompleted, Status: string(StatusIdle)})
		}}}
	})
	ctx := context.Background()
	rec := h.create(ownerHuman, defaultCreate())
	if _, err := h.svc.Send(ctx, ownerHuman, rec.ID, SendRequest{Content: "first"}); err != nil {
		t.Fatalf("first Send: %v", err)
	}
	_, err := h.svc.Send(ctx, ownerHuman, rec.ID, SendRequest{Content: "second"})
	if !problem.HasCode(err, problem.StateConflict) {
		t.Fatalf("concurrent Send = %v, want STATE_CONFLICT", err)
	}
	close(gate)
	h.waitTurn(rec.ID)
	if _, err := h.svc.Send(ctx, ownerHuman, rec.ID, SendRequest{Content: "third"}); err != nil {
		t.Fatalf("Send after the turn: %v", err)
	}
	h.waitTurn(rec.ID)
}

// TestCancelRunningTurn checks the cooperative cancel path.
func TestCancelRunningTurn(t *testing.T) {
	var runs int32
	var mu sync.Mutex
	h := newTestHost(t, func(o *Options) {
		o.Cores = []Core{&scriptCore{name: "native", run: func(ctx context.Context, turn Turn, emit Emit) error {
			mu.Lock()
			runs++
			first := runs == 1
			mu.Unlock()
			if !first {
				return emit(Event{Type: EventTurnCompleted, Status: string(StatusIdle)})
			}
			<-ctx.Done()
			return ctx.Err()
		}}}
	})
	ctx := context.Background()
	rec := h.create(ownerHuman, defaultCreate())
	sub := h.subscribe(ownerHuman, rec.ID)
	h.send(ownerHuman, rec.ID, "long task")

	recAfter, err := h.svc.Cancel(ctx, ownerHuman, rec.ID, "user changed their mind")
	if err != nil {
		t.Fatalf("Cancel: %v", err)
	}
	if recAfter.Status != StatusRunning {
		t.Fatalf("status right after Cancel = %s, want running (cooperative)", recAfter.Status)
	}
	h.waitTurn(rec.ID)
	requireStatus(t, h.svc, ownerHuman, rec.ID, StatusCancelled)

	events := drain(sub)
	requireEvents(t, events, EventTurnCompleted, 1)
	done := eventsOfType(events, EventTurnCompleted)[0]
	if done.Status != string(StatusCancelled) {
		t.Fatalf("turn.completed = %+v", done)
	}
	// A cancelled session can start a new turn.
	if _, err := h.svc.Send(ctx, ownerHuman, rec.ID, SendRequest{Content: "again"}); err != nil {
		t.Fatalf("Send after cancel: %v", err)
	}
	h.waitTurn(rec.ID)
}

// TestReadOnlyFiltersToolsAndMode checks the permission-mode ceiling.
func TestReadOnlyFiltersToolsAndMode(t *testing.T) {
	core := &echoCore{}
	h := newTestHost(t, func(o *Options) {
		o.Cores = []Core{core}
		o.Catalog = StaticCatalog{Tools: testTools()}
	})
	ctx := context.Background()

	rec := h.create(ownerHuman, CreateRequest{PermissionMode: operations.PermissionReadOnly})
	h.send(ownerHuman, rec.ID, "read only")
	h.waitTurn(rec.ID)
	turn, _, mode := core.snapshot()
	if mode != operations.PermissionReadOnly {
		t.Fatalf("core mode = %q", mode)
	}
	if len(turn.Tools) != 1 || turn.Tools[0].Action != "host.users.list" {
		t.Fatalf("read_only tools = %+v", turn.Tools)
	}

	// Switching the mode applies to the next turn.
	safe := h.create(ownerHuman, defaultCreate())
	h.send(ownerHuman, safe.ID, "first")
	h.waitTurn(safe.ID)
	title := "read only now"
	updated, err := h.svc.Update(ctx, ownerHuman, safe.ID, UpdateRequest{
		Title: &title, PermissionMode: operations.PermissionReadOnly,
		ExpectedRevision: h.mustGet(ownerHuman, safe.ID).Revision,
	})
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	_ = updated
	h.send(ownerHuman, safe.ID, "second")
	h.waitTurn(safe.ID)
	turn, _, mode = core.snapshot()
	if mode != operations.PermissionReadOnly {
		t.Fatalf("mode after update = %q", mode)
	}
	if len(turn.Tools) != 1 || turn.Tools[0].Effect != operations.EffectRead {
		t.Fatalf("tools after read_only = %+v", turn.Tools)
	}
}

// TestRunnerSeesSessionMode checks that the mode travels both on the tool call
// and on its context, for every mode.
func TestRunnerSeesSessionMode(t *testing.T) {
	for _, mode := range []operations.PermissionMode{
		operations.PermissionSafe, operations.PermissionFull, operations.PermissionCustom,
	} {
		t.Run(string(mode), func(t *testing.T) {
			runner := &fakeRunner{}
			core := &toolCore{action: "host.users.create", args: json.RawMessage(`{"username":"bob"}`)}
			h := newTestHost(t, func(o *Options) {
				o.Cores = []Core{core}
				o.Catalog = StaticCatalog{Tools: testTools()}
				o.Runner = runner
			})
			rec := h.create(ownerHuman, CreateRequest{PermissionMode: mode})
			h.send(ownerHuman, rec.ID, "create bob")
			h.waitTurn(rec.ID)

			calls, modes := runner.snapshot()
			if len(calls) != 1 {
				t.Fatalf("runner calls = %d", len(calls))
			}
			if modes[0] != mode || calls[0].PermissionMode != mode {
				t.Fatalf("runner mode = %q / call mode = %q, want %q", modes[0], calls[0].PermissionMode, mode)
			}
			if calls[0].Actor.Kind != ownerHuman.Kind || calls[0].Actor.ID != ownerHuman.ID {
				t.Fatalf("runner actor = %+v, want the session owner %+v", calls[0].Actor, ownerHuman)
			}
			msgs, err := h.svc.Messages(context.Background(), ownerHuman, rec.ID, 0)
			if err != nil {
				t.Fatalf("Messages: %v", err)
			}
			var sawTool bool
			for _, m := range msgs {
				if m.Role == RoleTool && m.ContentJSON != nil {
					sawTool = true
				}
			}
			if !sawTool {
				t.Fatalf("no tool message in %+v", msgs)
			}
		})
	}
}

// TestApprovalApproveResumes covers approval_required -> approve -> a new turn
// that continues with the tool result in its history.
func TestApprovalApproveResumes(t *testing.T) {
	runner := &fakeRunner{fn: func(ctx context.Context, call ToolCall) (ToolResult, error) {
		return ToolResult{
			Status: ToolAwaitingApproval,
			Approval: &ApprovalInfo{
				ApprovalID: "apv_1", OperationID: "op_1", Summary: "Create a user",
				Description: "Creates a panel user.", Risk: "high", Approval: "confirm",
			},
		}, nil
	}}
	bridge := newFakeBridge()
	core := &toolCore{action: "host.users.create", args: json.RawMessage(`{"username":"bob"}`)}
	h := newTestHost(t, func(o *Options) {
		o.Cores = []Core{core}
		o.Catalog = StaticCatalog{Tools: testTools()}
		o.Runner = runner
		o.Approvals = bridge
	})
	ctx := context.Background()
	rec := h.create(ownerHuman, defaultCreate())
	sub := h.subscribe(ownerHuman, rec.ID)
	h.send(ownerHuman, rec.ID, "create bob")
	h.waitTurn(rec.ID)

	requireStatus(t, h.svc, ownerHuman, rec.ID, StatusWaitingApproval)
	waitFor(t, func() bool { return bridge.waitCount() == 1 })
	pending, err := h.svc.PendingApprovals(ctx, ownerHuman, rec.ID)
	if err != nil || len(pending) != 1 {
		t.Fatalf("pending = %+v, %v", pending, err)
	}
	if pending[0].ApprovalID != "apv_1" || pending[0].Summary != "Create a user" || pending[0].Description == "" {
		t.Fatalf("pending approval = %+v", pending[0])
	}
	// A send while waiting for the decision is a conflict.
	if _, err := h.svc.Send(ctx, ownerHuman, rec.ID, SendRequest{Content: "hurry"}); !problem.HasCode(err, problem.StateConflict) {
		t.Fatalf("send while waiting = %v", err)
	}

	bridge.reply <- ApprovalDecision{
		Decision: DecisionApprove, Comment: "ok",
		Status: ToolSucceeded, Result: json.RawMessage(`{"user_id":"usr_new"}`),
	}
	h.waitStatus(ownerHuman, rec.ID, StatusIdle)
	waitFor(t, func() bool { return core.runCount() == 2 })
	h.waitTurn(rec.ID)
	requireStatus(t, h.svc, ownerHuman, rec.ID, StatusIdle)

	events := drain(sub)
	requireEvents(t, events, EventApprovalRequired, 1)
	requireEvents(t, events, EventApprovalDecided, 1)
	requireEvents(t, events, EventToolResult, 1)
	requireEvents(t, events, EventTurnCompleted, 2)
	decided := eventsOfType(events, EventApprovalDecided)[0]
	if decided.Decision != DecisionApprove || decided.Comment != "ok" {
		t.Fatalf("approval_decided = %+v", decided)
	}
	result := eventsOfType(events, EventToolResult)[0]
	if result.Status != string(ToolSucceeded) || result.OperationID != "op_1" {
		t.Fatalf("tool_result = %+v", result)
	}
	turns := eventsOfType(events, EventTurnCompleted)
	if turns[0].Status != string(StatusWaitingApproval) || turns[1].Status != string(StatusIdle) {
		t.Fatalf("turn.completed sequence = %+v", turns)
	}

	// The tool call is persisted with its operation and the transcript pairs
	// the call with its result.
	call, err := h.svc.loadToolCall(ctx, rec.ID, pending[0].CallID)
	if err != nil {
		t.Fatalf("loadToolCall: %v", err)
	}
	if call.Status != ToolSucceeded || call.ApprovalID != "apv_1" || call.OperationID != "op_1" {
		t.Fatalf("tool call row = %+v", call)
	}
	msgs, err := h.svc.Messages(ctx, ownerHuman, rec.ID, 0)
	if err != nil {
		t.Fatalf("Messages: %v", err)
	}
	var toolMsgs int
	var assistantWithCalls bool
	for _, m := range msgs {
		switch {
		case m.Role == RoleTool && m.ContentJSON != nil:
			toolMsgs++
		case m.Role == RoleAssistant && m.ContentJSON != nil:
			assistantWithCalls = true
		}
	}
	if toolMsgs != 1 || !assistantWithCalls {
		t.Fatalf("transcript pairing = tool %d, assistant calls %v (%+v)", toolMsgs, assistantWithCalls, msgs)
	}
	// The resumed turn sees the tool result.
	turn, _ := core.snapshot()
	var sawTool bool
	for _, m := range turn.Messages {
		if m.Role == RoleTool {
			sawTool = true
		}
	}
	if !sawTool {
		t.Fatalf("resumed history has no tool message: %+v", turn.Messages)
	}
}

// TestApprovalRejectEndsTurn covers the rejecting decision.
func TestApprovalRejectEndsTurn(t *testing.T) {
	runner := &fakeRunner{fn: func(ctx context.Context, call ToolCall) (ToolResult, error) {
		return ToolResult{
			Status:   ToolAwaitingApproval,
			Approval: &ApprovalInfo{ApprovalID: "apv_2", Summary: "Create a user", Risk: "high"},
		}, nil
	}}
	bridge := newFakeBridge()
	core := &toolCore{action: "host.users.create", args: json.RawMessage(`{"username":"bob"}`)}
	h := newTestHost(t, func(o *Options) {
		o.Cores = []Core{core}
		o.Catalog = StaticCatalog{Tools: testTools()}
		o.Runner = runner
		o.Approvals = bridge
	})
	rec := h.create(ownerHuman, defaultCreate())
	sub := h.subscribe(ownerHuman, rec.ID)
	h.send(ownerHuman, rec.ID, "create bob")
	h.waitTurn(rec.ID)
	waitFor(t, func() bool { return bridge.waitCount() == 1 })

	bridge.reply <- ApprovalDecision{Decision: DecisionReject, Comment: "not now", Status: ToolRejected}
	h.waitStatus(ownerHuman, rec.ID, StatusIdle)
	h.waitTurn(rec.ID)

	events := drain(sub)
	requireEvents(t, events, EventApprovalDecided, 1)
	requireEvents(t, events, EventToolResult, 1)
	requireEvents(t, events, EventTurnCompleted, 2)
	if eventsOfType(events, EventApprovalDecided)[0].Decision != DecisionReject {
		t.Fatalf("decision = %+v", eventsOfType(events, EventApprovalDecided)[0])
	}
	if eventsOfType(events, EventToolResult)[0].Status != string(ToolRejected) {
		t.Fatalf("tool result = %+v", eventsOfType(events, EventToolResult)[0])
	}
	if core.runCount() != 1 {
		t.Fatalf("core runs after reject = %d, want 1", core.runCount())
	}
	pending, err := h.svc.PendingApprovals(context.Background(), ownerHuman, rec.ID)
	if err != nil || len(pending) != 0 {
		t.Fatalf("pending after reject = %+v, %v", pending, err)
	}
}

// TestReadOnlyCancelsPendingApproval checks that narrowing the mode rejects a
// pending write call (design §6).
func TestReadOnlyCancelsPendingApproval(t *testing.T) {
	runner := &fakeRunner{fn: func(ctx context.Context, call ToolCall) (ToolResult, error) {
		return ToolResult{
			Status:   ToolAwaitingApproval,
			Approval: &ApprovalInfo{ApprovalID: "apv_3", Summary: "Create a user", Risk: "high"},
		}, nil
	}}
	h := newTestHost(t, func(o *Options) {
		o.Cores = []Core{&toolCore{action: "host.users.create", args: json.RawMessage(`{"username":"bob"}`)}}
		o.Catalog = StaticCatalog{Tools: testTools()}
		o.Runner = runner
	})
	ctx := context.Background()
	rec := h.create(ownerHuman, defaultCreate())
	sub := h.subscribe(ownerHuman, rec.ID)
	h.send(ownerHuman, rec.ID, "create bob")
	h.waitTurn(rec.ID)
	requireStatus(t, h.svc, ownerHuman, rec.ID, StatusWaitingApproval)

	cur := h.mustGet(ownerHuman, rec.ID)
	if _, err := h.svc.Update(ctx, ownerHuman, rec.ID, UpdateRequest{
		PermissionMode: operations.PermissionReadOnly, ExpectedRevision: cur.Revision,
	}); err != nil {
		t.Fatalf("Update: %v", err)
	}
	requireStatus(t, h.svc, ownerHuman, rec.ID, StatusCancelled)
	pending, err := h.svc.PendingApprovals(ctx, ownerHuman, rec.ID)
	if err != nil || len(pending) != 0 {
		t.Fatalf("pending after read_only = %+v, %v", pending, err)
	}
	events := drain(sub)
	requireEvents(t, events, EventToolResult, 1)
	requireEvents(t, events, EventTurnCompleted, 2)
	turns := eventsOfType(events, EventTurnCompleted)
	if turns[0].Status != string(StatusWaitingApproval) || turns[1].Status != string(StatusCancelled) {
		t.Fatalf("turn.completed sequence = %+v", turns)
	}
	if eventsOfType(events, EventToolResult)[0].Status != string(ToolCancelled) {
		t.Fatalf("tool result = %+v", eventsOfType(events, EventToolResult)[0])
	}
}

// TestCancelWaitingApproval checks that cancelling a paused turn clears it.
func TestCancelWaitingApproval(t *testing.T) {
	bridge := newFakeBridge()
	h := newTestHost(t, func(o *Options) {
		o.Cores = []Core{&toolCore{action: "host.users.create", args: json.RawMessage(`{"username":"bob"}`)}}
		o.Catalog = StaticCatalog{Tools: testTools()}
		o.Runner = &fakeRunner{fn: func(ctx context.Context, call ToolCall) (ToolResult, error) {
			return ToolResult{Status: ToolAwaitingApproval, Approval: &ApprovalInfo{ApprovalID: "apv_4"}}, nil
		}}
		o.Approvals = bridge
	})
	ctx := context.Background()
	rec := h.create(ownerHuman, defaultCreate())
	h.send(ownerHuman, rec.ID, "create bob")
	h.waitTurn(rec.ID)
	waitFor(t, func() bool { return bridge.waitCount() == 1 })

	if _, err := h.svc.Cancel(ctx, ownerHuman, rec.ID, "no"); err != nil {
		t.Fatalf("Cancel: %v", err)
	}
	requireStatus(t, h.svc, ownerHuman, rec.ID, StatusCancelled)
	if pending, _ := h.svc.PendingApprovals(ctx, ownerHuman, rec.ID); len(pending) != 0 {
		t.Fatalf("pending after Cancel = %+v", pending)
	}
}

// TestSendValidationAndPreflight covers the errors answered before a turn runs.
func TestSendValidationAndPreflight(t *testing.T) {
	h := newTestHost(t)
	ctx := context.Background()

	unconfigured := h.create(ownerHuman, defaultCreate())
	if _, err := h.svc.Send(ctx, ownerHuman, unconfigured.ID, SendRequest{Content: "hi"}); !problem.HasCode(err, problem.Unavailable) {
		t.Fatalf("unconfigured native send = %v, want UNAVAILABLE", err)
	}
	if _, err := h.svc.Send(ctx, ownerHuman, unconfigured.ID, SendRequest{Content: "  "}); !problem.HasCode(err, problem.ValidationFailed) {
		t.Fatalf("empty content = %v", err)
	}
	if _, err := h.svc.Send(ctx, ownerHuman, unconfigured.ID, SendRequest{Content: string(make([]byte, maxUserBytes+1))}); !problem.HasCode(err, problem.ValidationFailed) {
		t.Fatalf("oversized content = %v", err)
	}
	msgs, err := h.svc.Messages(ctx, ownerHuman, unconfigured.ID, 0)
	if err != nil || len(msgs) != 0 {
		t.Fatalf("messages after rejected sends = %+v, %v", msgs, err)
	}

	cli := h.create(ownerHuman, CreateRequest{Core: CoreClaudeCode})
	if _, err := h.svc.Send(ctx, ownerHuman, cli.ID, SendRequest{Content: "hi"}); !problem.HasCode(err, problem.Unavailable) {
		t.Fatalf("CLI core send = %v, want UNAVAILABLE", err)
	}
	// The AI actor can neither send to nor cancel another principal's session.
	if _, err := h.svc.Send(ctx, ownerAgent, unconfigured.ID, SendRequest{Content: "hi"}); !problem.HasCode(err, problem.PermissionDenied) {
		t.Fatalf("ai agent send = %v", err)
	}
	if _, err := h.svc.Cancel(ctx, ownerAgent, unconfigured.ID, ""); !problem.HasCode(err, problem.PermissionDenied) {
		t.Fatalf("ai agent cancel = %v", err)
	}
}

// TestSubscribeReplayAndResync covers the SSE ring semantics.
func TestSubscribeReplayAndResync(t *testing.T) {
	h := newTestHost(t, func(o *Options) {
		o.Cores = []Core{&echoCore{}}
		o.Config.RingSize = 2
	})
	rec := h.create(ownerHuman, defaultCreate())
	sub := h.subscribe(ownerHuman, rec.ID)
	h.send(ownerHuman, rec.ID, "hello")
	h.waitTurn(rec.ID)
	events := drain(sub)
	if len(events) < 3 {
		t.Fatalf("events = %+v", events)
	}
	// Reconnect after the first event: the rest is replayed from the ring.
	replay, err := h.svc.Subscribe(context.Background(), ownerHuman, rec.ID, events[0].Seq)
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	defer replay.Close()
	if replay.Resync {
		t.Fatalf("unexpected resync: %+v", replay)
	}
	if len(replay.Replay) != len(events)-1 {
		t.Fatalf("replayed %d events, want %d", len(replay.Replay), len(events)-1)
	}
	if replay.Replay[0].Seq != events[1].Seq {
		t.Fatalf("replay starts at %d, want %d", replay.Replay[0].Seq, events[1].Seq)
	}
	// A position outside the retained window resyncs instead of replaying.
	// (The user message consumed seq 1, so position 1 cannot be an event.)
	old, err := h.svc.Subscribe(context.Background(), ownerHuman, rec.ID, 1)
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	defer old.Close()
	if !old.Resync || old.Reason != "out_of_window" || len(old.Replay) != 0 {
		t.Fatalf("old position = %+v", old)
	}
	if old.Head != events[len(events)-1].Seq {
		t.Fatalf("head = %d, want %d", old.Head, events[len(events)-1].Seq)
	}
	// A fresh subscription starts live (no backlog).
	live, err := h.svc.Subscribe(context.Background(), ownerHuman, rec.ID, -1)
	if err != nil || len(live.Replay) != 0 || live.Resync {
		t.Fatalf("fresh subscription = %+v, %v", live, err)
	}
	live.Close()
	// Another principal cannot subscribe.
	if _, err := h.svc.Subscribe(context.Background(), ownerOther, rec.ID, -1); !problem.HasCode(err, problem.NotFound) {
		t.Fatalf("subscribe as another owner = %v", err)
	}
}

// TestSubscriberOverflow checks that a slow SSE consumer gets a resync signal.
func TestSubscriberOverflow(t *testing.T) {
	h := newTestHost(t, func(o *Options) {
		o.Cores = []Core{&echoCore{}}
		o.Config.SubscriberBuffer = 1
	})
	rec := h.create(ownerHuman, defaultCreate())
	sub := h.subscribe(ownerHuman, rec.ID)
	h.send(ownerHuman, rec.ID, "hello")
	h.waitTurn(rec.ID)
	<-sub.Events // the buffered event
	select {
	case _, ok := <-sub.Events:
		if ok {
			t.Fatal("expected the stream to be closed after the overflow")
		}
	case <-time.After(time.Second):
		t.Fatal("subscriber was not closed")
	}
	if !sub.Overflowed() {
		t.Fatal("overflow was not reported")
	}
}

// TestCloseStopsTurns checks that Close cancels the running work.
func TestCloseStopsTurns(t *testing.T) {
	h := newTestHost(t, func(o *Options) {
		o.Cores = []Core{&scriptCore{name: "native", run: func(ctx context.Context, turn Turn, emit Emit) error {
			<-ctx.Done()
			return ctx.Err()
		}}}
	})
	rec := h.create(ownerHuman, defaultCreate())
	h.send(ownerHuman, rec.ID, "long")
	h.svc.Close()
	if _, err := h.svc.Get(context.Background(), ownerHuman, rec.ID); err != nil {
		t.Fatalf("Get after Close: %v", err)
	}
}

// mustGet loads a session and fails on error.
func (h *testHost) mustGet(owner actor.Actor, id string) *Session {
	h.t.Helper()
	rec, err := h.svc.Get(context.Background(), owner, id)
	if err != nil {
		h.t.Fatalf("Get: %v", err)
	}
	return rec
}

// TestSetAPIKeyScopedToSession covers the api-key write path (AGT-02): the key
// is encrypted under the session's own namespace and opens nowhere else, a
// replaced key leaves exactly one secret, nobody but the owner can touch it,
// and every change is audited without the key or its reference.
func TestSetAPIKeyScopedToSession(t *testing.T) {
	h, store := newNativeHost(t)
	ctx := context.Background()
	rec := h.create(ownerHuman, defaultCreate())
	sibling := h.create(ownerHuman, defaultCreate())
	if rec.HasAPIKey() {
		t.Fatal("a new session has an API key")
	}
	const purpose = "agent.native.api_key"
	namespace := "agent_sessions/" + rec.ID

	// Surrounding whitespace of a paste is dropped; the key opens only in the
	// session's own namespace under the API-key purpose.
	set := h.setAPIKey(ownerHuman, rec.ID, "  sk-first\n")
	if !set.HasAPIKey() || set.Revision == rec.Revision {
		t.Fatalf("session after SetAPIKey = %+v", set)
	}
	key, err := store.RevealOwned(ctx, set.APIKeyRef, namespace, purpose)
	if err != nil || string(key.Bytes()) != "sk-first" {
		t.Fatalf("RevealOwned = %q, %v", key.Bytes(), err)
	}
	if _, err := store.RevealOwned(ctx, set.APIKeyRef, "agent_sessions/"+sibling.ID, purpose); !problem.HasCode(err, problem.NotFound) {
		t.Fatalf("the key opened for another session: %v", err)
	}
	if got := h.mustGet(ownerHuman, rec.ID); got.APIKeyRef != set.APIKeyRef || got.Revision != set.Revision {
		t.Fatalf("stored session = %+v, want %+v", got, set)
	}

	// A replaced key is gone in the same transaction.
	replaced := h.setAPIKey(ownerHuman, rec.ID, "sk-second")
	if replaced.APIKeyRef == set.APIKeyRef || replaced.Revision == set.Revision {
		t.Fatalf("session after the second SetAPIKey = %+v", replaced)
	}
	if _, err := store.RevealOwned(ctx, set.APIKeyRef, namespace, purpose); !problem.HasCode(err, problem.NotFound) {
		t.Fatalf("the replaced key survived: %v", err)
	}
	if n := h.secretCount(namespace); n != 1 {
		t.Fatalf("secrets of the session = %d, want 1", n)
	}

	// Refused requests write nothing, and a refusal never echoes the key.
	for _, tc := range []struct {
		name  string
		owner actor.Actor
		key   string
		code  problem.Code
	}{
		{"another owner", ownerOther, "sk-other", problem.NotFound},
		{"an AI agent", ownerAgent, "sk-agent", problem.PermissionDenied},
		{"empty", ownerHuman, " \t ", problem.ValidationFailed},
		{"header injection", ownerHuman, "sk-x\r\nX-Injected: canary", problem.ValidationFailed},
		{"inner space", ownerHuman, "sk-x canary", problem.ValidationFailed},
		{"too long", ownerHuman, strings.Repeat("k", maxAPIKeyBytes+1), problem.ValidationFailed},
	} {
		_, err := h.svc.SetAPIKey(ctx, tc.owner, rec.ID, tc.key)
		if !problem.HasCode(err, tc.code) {
			t.Fatalf("SetAPIKey(%s) = %v, want %s", tc.name, err, tc.code)
		}
		if p := problem.From(err); strings.Contains(fmt.Sprintf("%+v", *p), "canary") {
			t.Fatalf("SetAPIKey(%s) echoed the key: %+v", tc.name, *p)
		}
	}
	if _, err := h.svc.ClearAPIKey(ctx, ownerOther, rec.ID); !problem.HasCode(err, problem.NotFound) {
		t.Fatalf("ClearAPIKey by another owner = %v", err)
	}
	if _, err := h.svc.ClearAPIKey(ctx, ownerAgent, rec.ID); !problem.HasCode(err, problem.PermissionDenied) {
		t.Fatalf("ClearAPIKey by an AI agent = %v", err)
	}
	if got := h.mustGet(ownerHuman, rec.ID); got.APIKeyRef != replaced.APIKeyRef || got.Revision != replaced.Revision {
		t.Fatalf("a refused request changed the session: %+v", got)
	}

	// Clearing removes the secret; clearing again changes nothing.
	cleared, err := h.svc.ClearAPIKey(ctx, ownerHuman, rec.ID)
	if err != nil || cleared.HasAPIKey() || cleared.Revision == replaced.Revision {
		t.Fatalf("ClearAPIKey = %+v, %v", cleared, err)
	}
	if n := h.secretCount(namespace); n != 0 {
		t.Fatalf("secrets after ClearAPIKey = %d, want 0", n)
	}
	again, err := h.svc.ClearAPIKey(ctx, ownerHuman, rec.ID)
	if err != nil || again.Revision != cleared.Revision {
		t.Fatalf("second ClearAPIKey = %+v, %v (revision before %s)", again, err, cleared.Revision)
	}

	// Two sets and one clear are audited, without the key or its reference.
	rows, err := h.db.Reader().QueryContext(ctx, `SELECT action, details FROM audit_log
		WHERE subject = ? AND action LIKE 'agent.session.api_key.%'`, namespace)
	if err != nil {
		t.Fatalf("audit query: %v", err)
	}
	defer rows.Close()
	actions := map[string]int{}
	for rows.Next() {
		var action, details string
		if err := rows.Scan(&action, &details); err != nil {
			t.Fatalf("audit scan: %v", err)
		}
		if strings.Contains(details, "sk-") || strings.Contains(details, "sec_") {
			t.Fatalf("audit details leak the key: %s", details)
		}
		actions[action]++
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("audit rows: %v", err)
	}
	if actions["agent.session.api_key.set"] != 2 || actions["agent.session.api_key.clear"] != 1 || len(actions) != 2 {
		t.Fatalf("audit actions = %v", actions)
	}

	// A host without a secret store cannot keep a key at all.
	bare := newTestHost(t)
	bareRec := bare.create(ownerHuman, defaultCreate())
	if _, err := bare.svc.SetAPIKey(ctx, ownerHuman, bareRec.ID, "sk-nowhere"); !problem.HasCode(err, problem.Unavailable) {
		t.Fatalf("SetAPIKey without a secret store = %v", err)
	}
}

// TestDeleteRemovesAPIKeySecret checks that deleting a session deletes its key
// in the same transaction, and nothing but its key.
func TestDeleteRemovesAPIKeySecret(t *testing.T) {
	h, store := newNativeHost(t)
	ctx := context.Background()
	const purpose = "agent.native.api_key"
	doomed := h.setAPIKey(ownerHuman, h.create(ownerHuman, defaultCreate()).ID, "sk-delete-me")
	kept := h.setAPIKey(ownerHuman, h.create(ownerHuman, defaultCreate()).ID, "sk-keep-me")

	// A refused delete leaves the key in place.
	if err := h.svc.Delete(ctx, ownerOther, doomed.ID); !problem.HasCode(err, problem.NotFound) {
		t.Fatalf("delete by another owner = %v", err)
	}
	if n := h.secretCount("agent_sessions/" + doomed.ID); n != 1 {
		t.Fatalf("secrets after a refused delete = %d, want 1", n)
	}

	if err := h.svc.Delete(ctx, ownerHuman, doomed.ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if n := h.secretCount("agent_sessions/" + doomed.ID); n != 0 {
		t.Fatalf("secrets of the deleted session = %d, want 0", n)
	}
	if _, err := store.RevealOwned(ctx, doomed.APIKeyRef, "agent_sessions/"+doomed.ID, purpose); !problem.HasCode(err, problem.NotFound) {
		t.Fatalf("the deleted session's key still opens: %v", err)
	}
	key, err := store.RevealOwned(ctx, kept.APIKeyRef, "agent_sessions/"+kept.ID, purpose)
	if err != nil || string(key.Bytes()) != "sk-keep-me" {
		t.Fatalf("another session's key = %q, %v", key.Bytes(), err)
	}
}

// waitFor polls a predicate with a deadline.
func waitFor(t *testing.T, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if ok() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("condition not reached")
}

// restart opens a second service on the host's database, the state a new
// process finds. The first service is left alone: the planted rows say what the
// crash left behind.
func (h *testHost) restart(tune ...func(*Options)) *Service {
	h.t.Helper()
	opts := Options{DB: h.db, Clock: h.clock, IDs: h.ids, Logger: slog.New(slog.DiscardHandler)}
	for _, fn := range tune {
		fn(&opts)
	}
	svc, err := New(opts)
	if err != nil {
		h.t.Fatalf("New: %v", err)
	}
	h.t.Cleanup(svc.Close)
	return svc
}

// plantInterruptedTurn writes what a crash during a tool call leaves behind.
func (h *testHost) plantInterruptedTurn(sessionID string, status Status, toolStatus ToolStatus) {
	h.t.Helper()
	now := storage.FormatTime(time.Now().UTC())
	content := `{"tool_calls":[{"call_id":"call_planted_0001","action":"host.users.create","arguments":{}}]}`
	h.exec(`INSERT INTO agent_messages (session_id, seq, message_id, role, content, created_at)
		VALUES (?, 1, ?, 'user', 'go', ?)`, sessionID, "msg_u_"+sessionID, now)
	h.exec(`INSERT INTO agent_messages (session_id, seq, message_id, role, content, content_json, created_at)
		VALUES (?, 2, ?, 'assistant', '', ?, ?)`, sessionID, "msg_a_"+sessionID, content, now)
	h.exec(`INSERT INTO agent_tool_calls (call_id, session_id, seq, action_id, args_json, operation_id, status,
		created_at, updated_at, revision) VALUES ('call_planted_0001', ?, 3, 'host.users.create', '{}', 'op_9', ?, ?, ?, 1)`,
		sessionID, string(toolStatus), now, now)
	h.exec(`UPDATE agent_sessions SET status = ?, last_seq = 3 WHERE session_id = ?`, string(status), sessionID)
}

// TestRecoverRunningBecomesFailed: a turn that died with the process ends as
// failed and its open call gets a result, so the transcript stays paired.
func TestRecoverRunningBecomesFailed(t *testing.T) {
	h := newTestHost(t, func(o *Options) { o.Cores = []Core{&echoCore{}} })
	ctx := context.Background()
	rec := h.create(ownerHuman, defaultCreate())
	h.plantInterruptedTurn(rec.ID, StatusRunning, ToolProposed)

	svc := h.restart(func(o *Options) { o.Cores = []Core{&echoCore{}} })
	if err := svc.Recover(ctx); err != nil {
		t.Fatalf("Recover: %v", err)
	}
	requireStatus(t, svc, ownerHuman, rec.ID, StatusFailed)
	call, err := svc.loadToolCall(ctx, rec.ID, "call_planted_0001")
	if err != nil {
		t.Fatal(err)
	}
	if call.Status != ToolFailed || call.Error == nil || !strings.Contains(call.Error.Detail, "check operation_id") {
		t.Fatalf("call = %+v", call)
	}
	have, err := svc.toolMessageCallIDs(ctx, rec.ID)
	if err != nil || !have["call_planted_0001"] {
		t.Fatalf("tool messages = %v, %v", have, err)
	}
	if _, err := svc.Send(ctx, ownerHuman, rec.ID, SendRequest{Content: "again"}); err != nil {
		t.Fatalf("Send after recovery: %v", err)
	}
}

// TestRecoverKeepsReportedRunningCall: a call whose job was reported as running
// already has its result; recovery must not rewrite it as failed.
func TestRecoverKeepsReportedRunningCall(t *testing.T) {
	h := newTestHost(t)
	ctx := context.Background()
	rec := h.create(ownerHuman, defaultCreate())
	h.plantInterruptedTurn(rec.ID, StatusRunning, ToolRunning)
	h.exec(`INSERT INTO agent_messages (session_id, seq, message_id, role, content, content_json, created_at)
		VALUES (?, 4, 'msg_t_1', 'tool', '', '{"call_id":"call_planted_0001","status":"running"}', ?)`,
		rec.ID, storage.FormatTime(time.Now().UTC()))

	svc := h.restart()
	if err := svc.Recover(ctx); err != nil {
		t.Fatalf("Recover: %v", err)
	}
	requireStatus(t, svc, ownerHuman, rec.ID, StatusFailed)
	call, err := svc.loadToolCall(ctx, rec.ID, "call_planted_0001")
	if err != nil || call.Status != ToolRunning {
		t.Fatalf("call = %+v, %v", call, err)
	}
}

// TestRecoverWaitingApprovalResumesWaiter: a decision made across a restart
// still reaches the paused session and the turn continues.
func TestRecoverWaitingApprovalResumesWaiter(t *testing.T) {
	runner := &fakeRunner{fn: func(context.Context, ToolCall) (ToolResult, error) {
		return ToolResult{Status: ToolAwaitingApproval, Approval: &ApprovalInfo{ApprovalID: "apv_1", OperationID: "op_1"}}, nil
	}}
	h := newTestHost(t, func(o *Options) {
		o.Cores = []Core{&toolCore{action: "host.users.create", args: json.RawMessage(`{"name":"a"}`)}}
		o.Catalog = StaticCatalog{Tools: testTools()}
		o.Runner = runner
		o.Approvals = newFakeBridge()
	})
	ctx := context.Background()
	rec := h.create(ownerHuman, defaultCreate())
	h.send(ownerHuman, rec.ID, "create a")
	h.waitTurn(rec.ID)
	requireStatus(t, h.svc, ownerHuman, rec.ID, StatusWaitingApproval)
	h.svc.Close()

	bridge := newFakeBridge()
	bridge.reply <- ApprovalDecision{Decision: DecisionApprove, Status: ToolSucceeded, Result: json.RawMessage(`{"ok":true}`)}
	core := &toolCore{action: "host.users.create", runs: 1}
	svc := h.restart(func(o *Options) {
		o.Cores = []Core{core}
		o.Catalog = StaticCatalog{Tools: testTools()}
		o.Runner = runner
		o.Approvals = bridge
	})
	requireStatus(t, svc, ownerHuman, rec.ID, StatusWaitingApproval)
	if err := svc.Recover(ctx); err != nil {
		t.Fatalf("Recover: %v", err)
	}
	waitFor(t, func() bool { return core.runCount() == 2 })
	if err := svc.WaitTurn(ctx, rec.ID); err != nil {
		t.Fatal(err)
	}
	requireStatus(t, svc, ownerHuman, rec.ID, StatusIdle)
	bridge.mu.Lock()
	defer bridge.mu.Unlock()
	if bridge.waited[0] != "apv_1" {
		t.Fatalf("waited = %v", bridge.waited)
	}
	calls, err := svc.toolCallsWithStatus(ctx, rec.ID, ToolSucceeded)
	if err != nil || len(calls) != 1 || calls[0].OperationID != "op_1" {
		t.Fatalf("calls = %+v, %v", calls, err)
	}
}

// TestCancelStaleBusySession: a busy row without a turn or a waiter can still
// be cancelled, which is the way out when recovery could not handle it.
func TestCancelStaleBusySession(t *testing.T) {
	h := newTestHost(t)
	ctx := context.Background()
	rec := h.create(ownerHuman, defaultCreate())
	h.plantInterruptedTurn(rec.ID, StatusRunning, ToolProposed)

	svc := h.restart()
	out, err := svc.Cancel(ctx, ownerHuman, rec.ID, "")
	if err != nil {
		t.Fatalf("Cancel: %v", err)
	}
	if out.Status != StatusCancelled {
		t.Fatalf("status = %s", out.Status)
	}
	requireStatus(t, svc, ownerHuman, rec.ID, StatusCancelled)
	call, err := svc.loadToolCall(ctx, rec.ID, "call_planted_0001")
	if err != nil || call.Status != ToolCancelled {
		t.Fatalf("call = %+v, %v", call, err)
	}
}

// TestCloseDuringTurnPersistsStatus: a graceful shutdown lets the turn write its
// final status instead of leaving a running row behind.
func TestCloseDuringTurnPersistsStatus(t *testing.T) {
	started := make(chan struct{})
	core := &scriptCore{name: "native", run: func(ctx context.Context, _ Turn, _ Emit) error {
		close(started)
		<-ctx.Done()
		return ctx.Err()
	}}
	h := newTestHost(t, func(o *Options) { o.Cores = []Core{core} })
	rec := h.create(ownerHuman, defaultCreate())
	sub := h.subscribe(ownerHuman, rec.ID)
	h.send(ownerHuman, rec.ID, "wait")
	<-started
	h.svc.Close()

	got, err := loadSessionFor(context.Background(), h.db.Reader(), ownerHuman, rec.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != StatusCancelled {
		t.Fatalf("status = %s", got.Status)
	}
	// The subscriber saw the final event before its stream closed.
	var last Event
	for e := range sub.Events {
		last = e
	}
	if last.Type != EventTurnCompleted {
		t.Fatalf("last event = %+v", last)
	}
	if _, err := h.svc.Send(context.Background(), ownerHuman, rec.ID, SendRequest{Content: "late"}); !problem.HasCode(err, problem.Unavailable) {
		t.Fatalf("Send after Close = %v", err)
	}
}

// cancellingBridge is a fake bridge that can also withdraw the host operation.
// With final set, the operation counts as already finished: CancelApproval
// answers err and every later Wait reports final.
type cancellingBridge struct {
	*fakeBridge
	err      error
	final    *ApprovalDecision
	mu       sync.Mutex
	calls    []string
	finished bool
}

func (b *cancellingBridge) CancelApproval(_ context.Context, owner actor.Actor, sessionID, operationID, _ string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.calls = append(b.calls, owner.ID+"/"+sessionID+"/"+operationID)
	b.finished = b.final != nil
	return b.err
}

func (b *cancellingBridge) Wait(ctx context.Context, approvalID string) (ApprovalDecision, error) {
	b.mu.Lock()
	finished := b.finished
	b.mu.Unlock()
	if finished {
		return *b.final, nil
	}
	return b.fakeBridge.Wait(ctx, approvalID)
}

// pausedHost starts one session that waits for approval apv_w of operation op_w.
func pausedHost(t *testing.T, bridge ApprovalBridge) (*testHost, *Session, *Subscription) {
	t.Helper()
	runner := &fakeRunner{fn: func(context.Context, ToolCall) (ToolResult, error) {
		return ToolResult{
			Status: ToolAwaitingApproval, OperationID: "op_w",
			Approval: &ApprovalInfo{ApprovalID: "apv_w", OperationID: "op_w"},
		}, nil
	}}
	h := newTestHost(t, func(o *Options) {
		o.Cores = []Core{&toolCore{action: "host.users.create", args: json.RawMessage(`{"name":"a"}`)}}
		o.Catalog = StaticCatalog{Tools: testTools()}
		o.Runner = runner
		o.Approvals = bridge
	})
	rec := h.create(ownerHuman, defaultCreate())
	sub := h.subscribe(ownerHuman, rec.ID)
	h.send(ownerHuman, rec.ID, "create a")
	h.waitTurn(rec.ID)
	requireStatus(t, h.svc, ownerHuman, rec.ID, StatusWaitingApproval)
	return h, rec, sub
}

// TestReadOnlySwitchCancelsHostApproval: "no more writes" also withdraws the
// operation behind the approval card, not only the local wait.
func TestReadOnlySwitchCancelsHostApproval(t *testing.T) {
	bridge := &cancellingBridge{fakeBridge: newFakeBridge()}
	h, rec, sub := pausedHost(t, bridge)
	if _, err := h.svc.Update(context.Background(), ownerHuman, rec.ID, UpdateRequest{
		PermissionMode: operations.PermissionReadOnly,
	}); err != nil {
		t.Fatalf("Update: %v", err)
	}
	requireStatus(t, h.svc, ownerHuman, rec.ID, StatusCancelled)
	bridge.mu.Lock()
	defer bridge.mu.Unlock()
	if want := ownerHuman.ID + "/" + rec.ID + "/op_w"; len(bridge.calls) != 1 || bridge.calls[0] != want {
		t.Fatalf("calls = %v, want %s", bridge.calls, want)
	}
	results := eventsOfType(drain(sub), EventToolResult)
	if len(results) != 1 || results[0].Status != string(ToolCancelled) {
		t.Fatalf("tool results = %+v", results)
	}
}

// TestCancelAndDeleteWithdrawHostApproval covers the other two callers.
func TestCancelAndDeleteWithdrawHostApproval(t *testing.T) {
	bridge := &cancellingBridge{fakeBridge: newFakeBridge()}
	h, rec, _ := pausedHost(t, bridge)
	out, err := h.svc.Cancel(context.Background(), ownerHuman, rec.ID, "stop")
	if err != nil || out.Status != StatusCancelled {
		t.Fatalf("Cancel = %+v, %v", out, err)
	}

	bridge2 := &cancellingBridge{fakeBridge: newFakeBridge()}
	h2, rec2, _ := pausedHost(t, bridge2)
	if err := h2.svc.Delete(context.Background(), ownerHuman, rec2.ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	for _, b := range []*cancellingBridge{bridge, bridge2} {
		b.mu.Lock()
		if len(b.calls) != 1 {
			t.Errorf("calls = %v", b.calls)
		}
		b.mu.Unlock()
	}
}

// TestWithdrawConflictRecordsRealOutcome: when the operation already ended the
// transcript must say what really happened, not "cancelled".
func TestWithdrawConflictRecordsRealOutcome(t *testing.T) {
	bridge := &cancellingBridge{
		fakeBridge: newFakeBridge(), err: problem.New(problem.StateConflict, "finished"),
		final: &ApprovalDecision{Decision: DecisionApprove, Status: ToolSucceeded, Result: json.RawMessage(`{"done":true}`)},
	}
	h, rec, sub := pausedHost(t, bridge)
	out, err := h.svc.Cancel(context.Background(), ownerHuman, rec.ID, "")
	if err != nil || out.Status != StatusCancelled {
		t.Fatalf("Cancel = %+v, %v", out, err)
	}
	results := eventsOfType(drain(sub), EventToolResult)
	if len(results) != 1 || results[0].Status != string(ToolSucceeded) || string(results[0].Result) != `{"done":true}` {
		t.Fatalf("tool results = %+v", results)
	}
}

// TestBroadcastClipsResult: subscribers and the ring get the same bounded
// values as the database.
func TestBroadcastClipsResult(t *testing.T) {
	huge := `{"a":"` + strings.Repeat("x", maxResultBytes) + `"}`
	hugeArgs := json.RawMessage(`{"a":"` + strings.Repeat("y", MaxToolArgsBytes) + `"}`)
	runner := &fakeRunner{fn: func(context.Context, ToolCall) (ToolResult, error) {
		return ToolResult{Status: ToolSucceeded, Result: json.RawMessage(huge)}, nil
	}}
	h := newTestHost(t, func(o *Options) {
		o.Cores = []Core{&toolCore{action: "host.users.list", args: hugeArgs}}
		o.Catalog = StaticCatalog{Tools: testTools()}
		o.Runner = runner
	})
	rec := h.create(ownerHuman, defaultCreate())
	sub := h.subscribe(ownerHuman, rec.ID)
	h.send(ownerHuman, rec.ID, "go")
	h.waitTurn(rec.ID)
	events := drain(sub)
	result := eventsOfType(events, EventToolResult)[0]
	if len(result.Result) > maxResultBytes {
		t.Fatalf("broadcast result = %d bytes", len(result.Result))
	}
	call := eventsOfType(events, EventToolCall)[0]
	if len(call.Args) > 128 {
		t.Fatalf("broadcast args = %d bytes", len(call.Args))
	}
	completed := eventsOfType(events, EventMessageCompleted)[0]
	if len(completed.ToolCalls[0].Arguments) > 128 {
		t.Fatalf("message args = %d bytes", len(completed.ToolCalls[0].Arguments))
	}
}

// TestRingByteLimit: the replay ring is bounded by bytes as well as by count,
// and always keeps the newest event.
func TestRingByteLimit(t *testing.T) {
	rt := &sessionRuntime{subs: map[*subscriber]struct{}{}}
	big := strings.Repeat("x", 300<<10)
	for i := 1; i <= 10; i++ {
		rt.broadcastLocked(Event{Seq: int64(i), Delta: big}, 256)
	}
	if rt.ringBytes > maxRingBytes || len(rt.ring) != 3 || rt.ring[2].Seq != 10 {
		t.Fatalf("ring = %d events, %d bytes", len(rt.ring), rt.ringBytes)
	}
	rt.broadcastLocked(Event{Seq: 11, Delta: strings.Repeat("y", 2<<20)}, 256)
	if len(rt.ring) != 1 || rt.ring[0].Seq != 11 {
		t.Fatalf("ring = %d events", len(rt.ring))
	}
}

// TestToolCallRetention: only finished rows are pruned, newest 500 per session.
func TestToolCallRetention(t *testing.T) {
	h := newTestHost(t)
	ctx := context.Background()
	rec := h.create(ownerHuman, defaultCreate())
	now := storage.FormatTime(time.Now().UTC())
	h.exec(`WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM n WHERE i < 520)
		INSERT INTO agent_tool_calls (call_id, session_id, seq, action_id, args_json, status, created_at, updated_at, revision)
		SELECT 'call_old_' || i, ?1, i, 'a', '{}', CASE i WHEN 1 THEN 'awaiting_approval' ELSE 'succeeded' END, ?2, ?2, 1 FROM n`,
		rec.ID, now)
	call := &ToolRecord{
		CallID: "call_new", SessionID: rec.ID, Seq: 521, Action: "a", Args: json.RawMessage("{}"),
		Status: ToolProposed, CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}
	if err := h.svc.insertToolCall(ctx, ownerHuman, call); err != nil {
		t.Fatalf("insertToolCall: %v", err)
	}
	var total, open int
	if err := h.db.Reader().QueryRowContext(ctx, `SELECT COUNT(*), SUM(status = 'awaiting_approval')
		FROM agent_tool_calls WHERE session_id = ?`, rec.ID).Scan(&total, &open); err != nil {
		t.Fatal(err)
	}
	if total != retainToolCalls+1 || open != 1 {
		t.Fatalf("total = %d, open = %d", total, open)
	}
}

// TestOwnerSessionLimit: the session count is per owner.
func TestOwnerSessionLimit(t *testing.T) {
	h := newTestHost(t, func(o *Options) { o.Config.MaxSessionsPerOwner = 2 })
	h.create(ownerHuman, defaultCreate())
	h.create(ownerHuman, defaultCreate())
	_, err := h.svc.Create(context.Background(), ownerHuman, defaultCreate())
	requireCode(t, err, problem.RateLimited)
	h.create(ownerOther, defaultCreate())
}

// TestOwnerRunningLimit: concurrent turns are limited per owner.
func TestOwnerRunningLimit(t *testing.T) {
	release := make(chan struct{})
	core := &scriptCore{name: "native", run: func(ctx context.Context, _ Turn, emit Emit) error {
		select {
		case <-release:
		case <-ctx.Done():
		}
		return emit(Event{Type: EventMessageCompleted, Delta: "ok"})
	}}
	h := newTestHost(t, func(o *Options) {
		o.Cores = []Core{core}
		o.Config.MaxRunningPerOwner = 1
	})
	ctx := context.Background()
	first := h.create(ownerHuman, defaultCreate())
	second := h.create(ownerHuman, defaultCreate())
	h.send(ownerHuman, first.ID, "one")
	_, err := h.svc.Send(ctx, ownerHuman, second.ID, SendRequest{Content: "two"})
	requireCode(t, err, problem.StateConflict)
	close(release)
	h.waitTurn(first.ID)
	h.send(ownerHuman, second.ID, "two")
	h.waitTurn(second.ID)
}

// TestOwnerTurnRate: the per-minute bucket covers every session of the owner.
func TestOwnerTurnRate(t *testing.T) {
	h := newTestHost(t, func(o *Options) {
		o.Cores = []Core{&echoCore{}}
		o.Config.TurnsPerMinute = 2
	})
	rec := h.create(ownerHuman, defaultCreate())
	for i := 0; i < 2; i++ {
		h.send(ownerHuman, rec.ID, "hi")
		h.waitTurn(rec.ID)
	}
	_, err := h.svc.Send(context.Background(), ownerHuman, rec.ID, SendRequest{Content: "more"})
	requireCode(t, err, problem.RateLimited)
	other := h.create(ownerOther, defaultCreate())
	h.send(ownerOther, other.ID, "hi")
}

// TestIdleRuntimeEvicted: an idle runtime is released, a watched one is not.
func TestIdleRuntimeEvicted(t *testing.T) {
	h := newTestHost(t)
	rec := h.create(ownerHuman, defaultCreate())
	watched := h.create(ownerHuman, defaultCreate())
	sub := h.subscribe(ownerHuman, watched.ID)
	present := func(id string) bool {
		h.svc.mu.Lock()
		defer h.svc.mu.Unlock()
		return h.svc.sessions[id] != nil
	}
	now := time.Now()
	h.svc.sweepRuntimes(now)
	if !present(rec.ID) {
		t.Fatal("a recently used runtime was evicted")
	}
	h.svc.sweepRuntimes(now.Add(runtimeIdleTTL + time.Minute))
	if present(rec.ID) || !present(watched.ID) {
		t.Fatalf("after sweep: idle present = %v, watched present = %v", present(rec.ID), present(watched.ID))
	}
	sub.Close()
	h.svc.sweepRuntimes(now.Add(runtimeIdleTTL + time.Minute))
	if present(watched.ID) {
		t.Fatal("the runtime survived its last subscriber")
	}
	// An evicted session comes back from the database.
	requireStatus(t, h.svc, ownerHuman, rec.ID, StatusIdle)
}
