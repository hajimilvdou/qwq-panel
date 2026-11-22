// SPDX-License-Identifier: AGPL-3.0-only

package agentsession

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/qwq-panel/qwq/internal/platform/problem"
)

// fakeProvider serves scripted responses and records every request.
type fakeProvider struct {
	replies []ProviderResponse
	errs    []error
	reqs    []ProviderRequest
	calls   int
	onCall  func(int)
}

// Complete implements Provider.
func (p *fakeProvider) Complete(ctx context.Context, req ProviderRequest) (ProviderResponse, error) {
	if p.onCall != nil {
		p.onCall(p.calls)
	}
	p.reqs = append(p.reqs, req)
	idx := p.calls
	p.calls++
	if idx < len(p.errs) && p.errs[idx] != nil {
		return ProviderResponse{}, p.errs[idx]
	}
	if idx >= len(p.replies) {
		return ProviderResponse{}, errors.New("fakeProvider: no scripted reply")
	}
	return p.replies[idx], nil
}

// fakeTools is a ToolRegistry over a fixed set with a scripted executor.
type fakeTools struct {
	defs      []ToolDef
	run       func(ctx context.Context, call ModelToolCall) (ToolOutcome, error)
	executed  []ModelToolCall
	specCalls []string
}

// Tools implements ToolRegistry.
func (t *fakeTools) Tools() []ToolDef { return t.defs }

// Spec implements ToolRegistry.
func (t *fakeTools) Spec(name string) (ToolDef, bool) {
	t.specCalls = append(t.specCalls, name)
	for _, def := range t.defs {
		if def.Name == name {
			return def, true
		}
	}
	return ToolDef{}, false
}

// Execute implements ToolRegistry.
func (t *fakeTools) Execute(ctx context.Context, call ModelToolCall) (ToolOutcome, error) {
	t.executed = append(t.executed, call)
	if t.run == nil {
		return ToolOutcome{Status: ToolSucceeded}, nil
	}
	return t.run(ctx, call)
}

// loopRecorder collects the events of one turn.
type loopRecorder struct {
	events  []LoopEvent
	failAt  int
	failErr error
}

func (r *loopRecorder) emit(e LoopEvent) error {
	r.events = append(r.events, e)
	if r.failErr != nil && len(r.events) == r.failAt {
		return r.failErr
	}
	return nil
}

// toolDefs builds two fake tool definitions.
func toolDefs() []ToolDef {
	return []ToolDef{
		{Name: "host.users.list", Action: "host.users.list", Description: "list users"},
		{Name: "host.users.create", Action: "host.users.create", Description: "create a user"},
	}
}

// requireEventTypes asserts the exact event sequence.
func requireEventTypes(t *testing.T, events []LoopEvent, want ...LoopEventType) {
	t.Helper()
	got := make([]LoopEventType, 0, len(events))
	for _, e := range events {
		got = append(got, e.Type)
	}
	if len(got) != len(want) {
		t.Fatalf("event types = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("event %d = %q, want %q (all: %v)", i, got[i], want[i], got)
		}
	}
}

// TestRunLoopSingleStepText covers the text-only turn.
func TestRunLoopSingleStepText(t *testing.T) {
	provider := &fakeProvider{replies: []ProviderResponse{{Content: "hello"}}}
	rec := &loopRecorder{}
	seed := []ModelMessage{
		{Role: LoopRoleSystem, Content: "be nice"},
		{Role: LoopRoleUser, Content: "hi"},
	}
	result, err := RunLoop(context.Background(), provider, nil, nil, rec.emit, LoopOptions{Messages: seed})
	if err != nil {
		t.Fatalf("RunLoop: %v", err)
	}
	if result.Status != LoopCompleted || result.Steps != 1 || result.Text != "hello" {
		t.Fatalf("result = %+v", result)
	}
	requireEventTypes(t, rec.events, LoopEventDelta, LoopEventAssistant, LoopEventDone)
	if rec.events[0].Delta != "hello" || rec.events[1].Content != "hello" {
		t.Fatalf("events = %+v", rec.events)
	}
	if got := len(provider.reqs[0].Messages); got != 2 {
		t.Fatalf("provider messages = %d, want 2", got)
	}
	if len(provider.reqs[0].Tools) != 0 {
		t.Fatalf("provider tools = %+v, want none", provider.reqs[0].Tools)
	}
	// The final transcript carries the assistant answer.
	if last := result.Messages[len(result.Messages)-1]; last.Role != LoopRoleAssistant || last.Content != "hello" {
		t.Fatalf("final message = %+v", last)
	}
}

// TestRunLoopMultiStepTools covers a tool step that is fed back to the model.
func TestRunLoopMultiStepTools(t *testing.T) {
	provider := &fakeProvider{replies: []ProviderResponse{
		{Content: "checking", ToolCalls: []ModelToolCall{{CallID: "c1", Name: "host.users.list", Arguments: json.RawMessage(`{"limit":5}`)}}},
		{Content: "there are three"},
	}}
	tools := &fakeTools{defs: toolDefs(), run: func(_ context.Context, call ModelToolCall) (ToolOutcome, error) {
		return ToolOutcome{Status: ToolSucceeded, Result: json.RawMessage(`{"users":3}`)}, nil
	}}
	rec := &loopRecorder{}
	result, err := RunLoop(context.Background(), provider, tools, nil, rec.emit, LoopOptions{
		Messages: []ModelMessage{{Role: LoopRoleUser, Content: "count"}},
	})
	if err != nil {
		t.Fatalf("RunLoop: %v", err)
	}
	if result.Status != LoopCompleted || result.Steps != 2 || result.Text != "there are three" {
		t.Fatalf("result = %+v", result)
	}
	if len(tools.executed) != 1 || tools.executed[0].CallID != "c1" {
		t.Fatalf("executed = %+v", tools.executed)
	}
	if string(tools.executed[0].Arguments) != `{"limit":5}` {
		t.Fatalf("arguments = %s", tools.executed[0].Arguments)
	}
	requireEventTypes(t, rec.events,
		LoopEventDelta, LoopEventAssistant, LoopEventToolCall, LoopEventToolResult,
		LoopEventDelta, LoopEventAssistant, LoopEventDone)
	// The second request pairs the assistant call with its tool result.
	second := provider.reqs[1].Messages
	if len(second) != 3 {
		t.Fatalf("second request messages = %+v", second)
	}
	if second[1].Role != LoopRoleAssistant || len(second[1].ToolCalls) != 1 {
		t.Fatalf("assistant message = %+v", second[1])
	}
	if second[2].Role != LoopRoleTool || second[2].ToolCallID != "c1" || second[2].Content != `{"users":3}` {
		t.Fatalf("tool message = %+v", second[2])
	}
	if len(provider.reqs[0].Tools) != 2 {
		t.Fatalf("tools offered = %+v", provider.reqs[0].Tools)
	}
}

// TestRunLoopToolErrorBackfilled checks that a failed tool is reported to the
// model instead of ending the turn.
func TestRunLoopToolErrorBackfilled(t *testing.T) {
	provider := &fakeProvider{replies: []ProviderResponse{
		{ToolCalls: []ModelToolCall{{CallID: "c1", Name: "host.users.create", Arguments: json.RawMessage(`{}`)}}},
		{Content: "could not create"},
	}}
	tools := &fakeTools{defs: toolDefs(), run: func(context.Context, ModelToolCall) (ToolOutcome, error) {
		return ToolOutcome{Status: ToolFailed, Error: problem.New(problem.Internal, "the host refused")}, nil
	}}
	rec := &loopRecorder{}
	result, err := RunLoop(context.Background(), provider, tools, nil, rec.emit, LoopOptions{})
	if err != nil {
		t.Fatalf("RunLoop: %v", err)
	}
	if result.Status != LoopCompleted || len(tools.executed) != 1 {
		t.Fatalf("result = %+v", result)
	}
	toolMessage := provider.reqs[1].Messages[1]
	if toolMessage.Role != LoopRoleTool || !strings.Contains(toolMessage.Content, "the host refused") {
		t.Fatalf("tool message = %+v", toolMessage)
	}
	if got := rec.events[2]; got.Type != LoopEventToolResult || got.Outcome.Status != ToolFailed {
		t.Fatalf("tool result event = %+v", got)
	}
}

// TestRunLoopExecuteErrorBackfilled checks that an executor error becomes a
// tool result instead of a panic or a dead turn.
func TestRunLoopExecuteErrorBackfilled(t *testing.T) {
	provider := &fakeProvider{replies: []ProviderResponse{
		{ToolCalls: []ModelToolCall{{CallID: "c1", Name: "host.users.list", Arguments: json.RawMessage(`{}`)}}},
		{Content: "ok"},
	}}
	tools := &fakeTools{defs: toolDefs(), run: func(context.Context, ModelToolCall) (ToolOutcome, error) {
		return ToolOutcome{}, problem.New(problem.Unavailable, "the runner is gone")
	}}
	rec := &loopRecorder{}
	if _, err := RunLoop(context.Background(), provider, tools, nil, rec.emit, LoopOptions{}); err != nil {
		t.Fatalf("RunLoop: %v", err)
	}
	backfilled := provider.reqs[1].Messages[1]
	if !strings.Contains(backfilled.Content, "the runner is gone") {
		t.Fatalf("backfilled = %q", backfilled.Content)
	}
}

// TestRunLoopInvalidArguments checks the strict JSON parse: the tool never
// runs and the model is told why.
func TestRunLoopInvalidArguments(t *testing.T) {
	provider := &fakeProvider{replies: []ProviderResponse{
		{ToolCalls: []ModelToolCall{{CallID: "c1", Name: "host.users.list", Arguments: json.RawMessage(`{"limit":`)}}},
		{Content: "fixed"},
	}}
	tools := &fakeTools{defs: toolDefs()}
	rec := &loopRecorder{}
	result, err := RunLoop(context.Background(), provider, tools, nil, rec.emit, LoopOptions{})
	if err != nil {
		t.Fatalf("RunLoop: %v", err)
	}
	if len(tools.executed) != 0 {
		t.Fatalf("executed = %+v", tools.executed)
	}
	if result.Status != LoopCompleted {
		t.Fatalf("status = %q", result.Status)
	}
	var sawRejected bool
	for _, e := range rec.events {
		if e.Type == LoopEventToolResult && e.Outcome != nil && e.Outcome.Error != nil &&
			e.Outcome.Error.Code == problem.ValidationFailed {
			sawRejected = true
		}
	}
	if !sawRejected {
		t.Fatalf("no validation failure event: %+v", rec.events)
	}
	if got := provider.reqs[1].Messages[1]; got.Role != LoopRoleTool || !strings.Contains(got.Content, "not JSON") {
		t.Fatalf("tool message = %+v", got)
	}
}

// TestRunLoopUnknownTool 核验未知名称只形成失败结果，模型收到成对结果后继续回答。
func TestRunLoopUnknownTool(t *testing.T) {
	provider := &fakeProvider{replies: []ProviderResponse{
		{ToolCalls: []ModelToolCall{{CallID: "c1", Name: "nope", Arguments: json.RawMessage(`{}`)}}},
		{Content: "sorry"},
	}}
	tools := &fakeTools{defs: toolDefs()}
	rec := &loopRecorder{}
	result, err := RunLoop(context.Background(), provider, tools, nil, rec.emit, LoopOptions{})
	if err != nil || result.Status != LoopCompleted || result.Steps != 2 {
		t.Fatalf("unknown tool did not resume with its result: %+v, %v", result, err)
	}
	if len(tools.executed) != 0 {
		t.Fatalf("executed an unknown tool: %+v", tools.executed)
	}
	requireEventTypes(t, rec.events, LoopEventAssistant, LoopEventToolCall, LoopEventToolResult,
		LoopEventDelta, LoopEventAssistant, LoopEventDone)
	failed := rec.events[2]
	if failed.Outcome == nil || failed.Outcome.Status != ToolFailed || failed.Outcome.Error == nil ||
		failed.Outcome.Error.Code != problem.Unavailable || failed.Call.CallID != "c1" {
		t.Fatalf("unknown tool result = %+v", failed)
	}
	if provider.calls != 2 {
		t.Fatalf("model calls = %d, want 2", provider.calls)
	}
	second := provider.reqs[1].Messages
	if len(second) != 2 || len(second[0].ToolCalls) != 1 || second[0].ToolCalls[0].CallID != "c1" ||
		second[1].Role != LoopRoleTool || second[1].ToolCallID != "c1" || !strings.Contains(second[1].Content, "unknown tool") {
		t.Fatalf("unknown call lost its paired result: %+v", second)
	}
}

// TestRunLoopStepLimit checks the bounded loop.
func TestRunLoopStepLimit(t *testing.T) {
	provider := &fakeProvider{replies: []ProviderResponse{
		{ToolCalls: []ModelToolCall{{CallID: "c1", Name: "host.users.list", Arguments: json.RawMessage(`{}`)}}},
		{ToolCalls: []ModelToolCall{{CallID: "c2", Name: "host.users.list", Arguments: json.RawMessage(`{}`)}}},
	}}
	tools := &fakeTools{defs: toolDefs()}
	rec := &loopRecorder{}
	result, err := RunLoop(context.Background(), provider, tools, nil, rec.emit, LoopOptions{MaxSteps: 2})
	if !errors.Is(err, ErrLoopStepLimit) {
		t.Fatalf("err = %v, want ErrLoopStepLimit", err)
	}
	if result.Status != LoopStepLimit || result.Steps != 2 {
		t.Fatalf("result = %+v", result)
	}
	if len(tools.executed) != 2 || provider.calls != 2 {
		t.Fatalf("executed = %d, model calls = %d", len(tools.executed), provider.calls)
	}
	last := rec.events[len(rec.events)-1]
	if last.Type != LoopEventError || last.Err == nil || last.Err.Code != problem.Unavailable {
		t.Fatalf("last event = %+v", last)
	}
}

// TestRunLoopCancelBeforeStart checks the context bound.
func TestRunLoopCancelBeforeStart(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	provider := &fakeProvider{replies: []ProviderResponse{{Content: "never"}}}
	rec := &loopRecorder{}
	result, err := RunLoop(ctx, provider, nil, nil, rec.emit, LoopOptions{})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	if provider.calls != 0 {
		t.Fatalf("model calls = %d", provider.calls)
	}
	if result.Steps != 0 || len(rec.events) != 0 {
		t.Fatalf("result = %+v events = %+v", result, rec.events)
	}
}

// TestRunLoopCancelDuringTool checks that a cancellation inside a tool stops
// the loop before the next model request.
func TestRunLoopCancelDuringTool(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	provider := &fakeProvider{replies: []ProviderResponse{
		{ToolCalls: []ModelToolCall{{CallID: "c1", Name: "host.users.list", Arguments: json.RawMessage(`{}`)}}},
		{Content: "must not be requested"},
	}}
	tools := &fakeTools{defs: toolDefs(), run: func(context.Context, ModelToolCall) (ToolOutcome, error) {
		cancel()
		return ToolOutcome{Status: ToolSucceeded}, nil
	}}
	rec := &loopRecorder{}
	result, err := RunLoop(ctx, provider, tools, nil, rec.emit, LoopOptions{})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	if provider.calls != 1 {
		t.Fatalf("model calls = %d, want 1", provider.calls)
	}
	if result.Steps != 1 {
		t.Fatalf("steps = %d", result.Steps)
	}
}

// TestRunLoopProviderError checks that a provider failure is returned and
// published as an error event.
func TestRunLoopProviderError(t *testing.T) {
	boom := problem.New(problem.Timeout, "the model was slow")
	provider := &fakeProvider{errs: []error{boom}}
	rec := &loopRecorder{}
	_, err := RunLoop(context.Background(), provider, nil, nil, rec.emit, LoopOptions{})
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v", err)
	}
	if len(rec.events) != 1 || rec.events[0].Type != LoopEventError || rec.events[0].Err == nil {
		t.Fatalf("events = %+v", rec.events)
	}
}

// TestRunLoopEmitError checks that a failing host stream aborts the turn.
func TestRunLoopEmitError(t *testing.T) {
	streamErr := errors.New("stream closed")
	provider := &fakeProvider{replies: []ProviderResponse{{Content: "hello"}}}
	rec := &loopRecorder{failAt: 1, failErr: streamErr}
	_, err := RunLoop(context.Background(), provider, nil, nil, rec.emit, LoopOptions{})
	if !errors.Is(err, streamErr) {
		t.Fatalf("err = %v, want the emit error", err)
	}
}

// TestRunLoopGateDeny checks that a denied call is never executed and the model
// learns about the refusal.
func TestRunLoopGateDeny(t *testing.T) {
	provider := &fakeProvider{replies: []ProviderResponse{
		{ToolCalls: []ModelToolCall{{CallID: "c1", Name: "host.users.create", Arguments: json.RawMessage(`{}`)}}},
		{Content: "understood"},
	}}
	tools := &fakeTools{defs: toolDefs()}
	gate := GateFunc(func(context.Context, ToolDef, ModelToolCall) (GateDecision, error) {
		return GateDecision{Kind: GateDeny, Reason: "read-only session"}, nil
	})
	rec := &loopRecorder{}
	result, err := RunLoop(context.Background(), provider, tools, gate, rec.emit, LoopOptions{})
	if err != nil {
		t.Fatalf("RunLoop: %v", err)
	}
	if len(tools.executed) != 0 {
		t.Fatalf("denied call executed: %+v", tools.executed)
	}
	if result.Status != LoopCompleted {
		t.Fatalf("status = %q", result.Status)
	}
	var denied *LoopEvent
	for i := range rec.events {
		if rec.events[i].Type == LoopEventToolResult {
			denied = &rec.events[i]
		}
	}
	if denied == nil || denied.Outcome.Status != ToolRejected || denied.Outcome.Error.Code != problem.PermissionDenied {
		t.Fatalf("deny event = %+v", denied)
	}
	if got := provider.reqs[1].Messages[1]; !strings.Contains(got.Content, "read-only session") {
		t.Fatalf("tool message = %q", got.Content)
	}
}

// TestRunLoopGateApproval checks that an approval pauses before any execution
// and is returned to the host.
func TestRunLoopGateApproval(t *testing.T) {
	provider := &fakeProvider{replies: []ProviderResponse{
		{ToolCalls: []ModelToolCall{{CallID: "c1", Name: "host.users.create", Arguments: json.RawMessage(`{"name":"a"}`)}}},
	}}
	tools := &fakeTools{defs: toolDefs()}
	gate := GateFunc(func(_ context.Context, _ ToolDef, call ModelToolCall) (GateDecision, error) {
		if call.CallID != "c1" {
			t.Fatalf("gate call = %+v", call)
		}
		return GateDecision{
			Kind:     GateApproval,
			Approval: &ApprovalRequest{ApprovalID: "apr_1", Summary: "create user a", Risk: "high"},
		}, nil
	})
	rec := &loopRecorder{}
	result, err := RunLoop(context.Background(), provider, tools, gate, rec.emit, LoopOptions{})
	if !errors.Is(err, ErrLoopApproval) {
		t.Fatalf("err = %v, want ErrLoopApproval", err)
	}
	if result.Status != LoopPaused || result.Pending == nil || result.Pending.Call.CallID != "c1" {
		t.Fatalf("result = %+v", result)
	}
	if result.Pending.Approval == nil || result.Pending.Approval.ApprovalID != "apr_1" {
		t.Fatalf("approval = %+v", result.Pending.Approval)
	}
	if len(tools.executed) != 0 {
		t.Fatalf("paused call executed: %+v", tools.executed)
	}
	last := rec.events[len(rec.events)-1]
	if last.Type != LoopEventApproval || last.Approval == nil || last.Approval.ApprovalID != "apr_1" {
		t.Fatalf("last event = %+v", last)
	}
	if provider.calls != 1 {
		t.Fatalf("model calls = %d", provider.calls)
	}
	// No tool result is fabricated for a paused call.
	for _, e := range rec.events {
		if e.Type == LoopEventToolResult {
			t.Fatalf("unexpected tool result for a paused call: %+v", e)
		}
	}
}

// TestRunLoopApprovalFromTool checks the host-runner approval path: the tool
// executed nothing and the loop pauses with the host's approval identity.
func TestRunLoopApprovalFromTool(t *testing.T) {
	provider := &fakeProvider{replies: []ProviderResponse{
		{ToolCalls: []ModelToolCall{{CallID: "c1", Name: "host.users.create", Arguments: json.RawMessage(`{}`)}}},
	}}
	tools := &fakeTools{defs: toolDefs(), run: func(context.Context, ModelToolCall) (ToolOutcome, error) {
		return ToolOutcome{
			Status:   ToolAwaitingApproval,
			Approval: &ApprovalRequest{ApprovalID: "apr_9", OperationID: "op_1", Summary: "approve?"},
		}, nil
	}}
	rec := &loopRecorder{}
	result, err := RunLoop(context.Background(), provider, tools, nil, rec.emit, LoopOptions{})
	if !errors.Is(err, ErrLoopApproval) {
		t.Fatalf("err = %v, want ErrLoopApproval", err)
	}
	if result.Pending == nil || result.Pending.Approval.ApprovalID != "apr_9" {
		t.Fatalf("pending = %+v", result.Pending)
	}
	last := rec.events[len(rec.events)-1]
	if last.Type != LoopEventApproval || last.Approval.OperationID != "op_1" {
		t.Fatalf("last event = %+v", last)
	}
}

// TestRunLoopApprovalWithoutID checks the fail-closed approval contract.
func TestRunLoopApprovalWithoutID(t *testing.T) {
	provider := &fakeProvider{replies: []ProviderResponse{
		{ToolCalls: []ModelToolCall{{CallID: "c1", Name: "host.users.create", Arguments: json.RawMessage(`{}`)}}},
	}}
	tools := &fakeTools{defs: toolDefs(), run: func(context.Context, ModelToolCall) (ToolOutcome, error) {
		return ToolOutcome{Status: ToolAwaitingApproval, Approval: &ApprovalRequest{}}, nil
	}}
	_, err := RunLoop(context.Background(), provider, tools, nil, nil, LoopOptions{})
	if err == nil || !strings.Contains(err.Error(), "approval") {
		t.Fatalf("err = %v", err)
	}
	if problem.From(err).Code != problem.Internal {
		t.Fatalf("code = %q", problem.From(err).Code)
	}
}

// TestRunLoopCallIDs checks the call-id normalization.
func TestRunLoopCallIDs(t *testing.T) {
	provider := &fakeProvider{replies: []ProviderResponse{
		{ToolCalls: []ModelToolCall{
			{Name: "host.users.list", Arguments: json.RawMessage(`{}`)},
			{Name: "host.users.list", Arguments: json.RawMessage(`{}`)},
		}},
		{Content: "done"},
	}}
	tools := &fakeTools{defs: toolDefs()}
	next := 0
	result, err := RunLoop(context.Background(), provider, tools, nil, nil, LoopOptions{
		NextCallID: func() string {
			next++
			return "call_" + string(rune('0'+next))
		},
	})
	if err != nil {
		t.Fatalf("RunLoop: %v", err)
	}
	if result.Status != LoopCompleted {
		t.Fatalf("status = %q", result.Status)
	}
	if len(tools.executed) != 2 || tools.executed[0].CallID == tools.executed[1].CallID {
		t.Fatalf("executed = %+v", tools.executed)
	}
	// Without a minting function a missing id is an internal error.
	provider = &fakeProvider{replies: []ProviderResponse{
		{ToolCalls: []ModelToolCall{{Name: "host.users.list", Arguments: json.RawMessage(`{}`)}}},
	}}
	_, err = RunLoop(context.Background(), provider, tools, nil, nil, LoopOptions{})
	if err == nil || problem.From(err).Code != problem.Internal {
		t.Fatalf("err = %v", err)
	}
}

// TestSanitizeHistory covers the tool-call pairing invariant.
func TestSanitizeHistory(t *testing.T) {
	cases := []struct {
		name string
		in   []ModelMessage
		want []string
	}{
		{
			name: "complete pair kept",
			in: []ModelMessage{
				{Role: LoopRoleUser, Content: "hi"},
				{Role: LoopRoleAssistant, ToolCalls: []ModelToolCall{{CallID: "c1", Name: "t"}}},
				{Role: LoopRoleTool, ToolCallID: "c1", Content: "ok"},
			},
			want: []string{"user:hi", "assistant:", "tool:c1:ok"},
		},
		{
			name: "incomplete step dropped",
			in: []ModelMessage{
				{Role: LoopRoleUser, Content: "hi"},
				{Role: LoopRoleAssistant, ToolCalls: []ModelToolCall{{CallID: "c1", Name: "t"}}},
				{Role: LoopRoleUser, Content: "next"},
			},
			want: []string{"user:hi", "user:next"},
		},
		{
			name: "orphan tool dropped",
			in: []ModelMessage{
				{Role: LoopRoleUser, Content: "hi"},
				{Role: LoopRoleTool, ToolCallID: "c9", Content: "orphan"},
			},
			want: []string{"user:hi"},
		},
		{
			name: "half pair dropped with its results",
			in: []ModelMessage{
				{Role: LoopRoleAssistant, ToolCalls: []ModelToolCall{{CallID: "c1"}, {CallID: "c2"}}},
				{Role: LoopRoleTool, ToolCallID: "c1", Content: "one"},
			},
			want: []string{},
		},
		{
			name: "empty text messages dropped",
			in: []ModelMessage{
				{Role: LoopRoleSystem, Content: "sys"},
				{Role: LoopRoleUser, Content: ""},
				{Role: LoopRoleAssistant, Content: ""},
			},
			want: []string{"system:sys"},
		},
		{
			name: "empty tool output is named",
			in: []ModelMessage{
				{Role: LoopRoleAssistant, ToolCalls: []ModelToolCall{{CallID: "c1"}}},
				{Role: LoopRoleTool, ToolCallID: "c1"},
			},
			want: []string{"assistant:", "tool:c1:(no output)"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := SanitizeHistory(tc.in)
			out := make([]string, 0, len(got))
			for _, msg := range got {
				switch msg.Role {
				case LoopRoleTool:
					out = append(out, msg.Role+":"+msg.ToolCallID+":"+msg.Content)
				case LoopRoleAssistant:
					out = append(out, msg.Role+":"+msg.Content)
				default:
					out = append(out, msg.Role+":"+msg.Content)
				}
			}
			if strings.Join(out, "|") != strings.Join(tc.want, "|") {
				t.Fatalf("got %v, want %v", out, tc.want)
			}
		})
	}
}

// TestNormalizeCallsAlwaysMints: with a minting function the model's id is
// never used, whatever it looks like.
func TestNormalizeCallsAlwaysMints(t *testing.T) {
	next := 0
	mint := func() string {
		next++
		return fmt.Sprintf("call_host_%d", next)
	}
	in := []ModelToolCall{
		{CallID: "0", Name: "a"},
		{CallID: "0", Name: "b"},
		{CallID: strings.Repeat("x", 4096), Name: "c"},
		{CallID: "", Name: "d"},
	}
	out, err := normalizeCalls(in, mint)
	if err != nil {
		t.Fatalf("normalizeCalls: %v", err)
	}
	for i, call := range out {
		if want := fmt.Sprintf("call_host_%d", i+1); call.CallID != want {
			t.Fatalf("call %d id = %q, want %q", i, call.CallID, want)
		}
		if string(call.Arguments) != "{}" {
			t.Fatalf("call %d arguments = %s", i, call.Arguments)
		}
	}
	if _, err := normalizeCalls(in[:1], func() string { return "" }); problem.From(err).Code != problem.Internal {
		t.Fatalf("empty mint: %v", err)
	}
	// Library mode keeps a usable model id and refuses the others.
	if out, err := normalizeCalls([]ModelToolCall{{CallID: "c-1:a.b_2"}}, nil); err != nil || out[0].CallID != "c-1:a.b_2" {
		t.Fatalf("library mode: %+v, %v", out, err)
	}
	for _, bad := range [][]ModelToolCall{
		{{CallID: ""}},
		{{CallID: "a b"}},
		{{CallID: strings.Repeat("x", 129)}},
		{{CallID: "same"}, {CallID: "same"}},
	} {
		if _, err := normalizeCalls(bad, nil); problem.From(err).Code != problem.Internal {
			t.Fatalf("library mode accepted %+v: %v", bad, err)
		}
	}
}

// TestRunLoopRepeatedModelIDsAcrossSteps: a provider that numbers its calls per
// message reuses "0" on every step; each step still pairs with its own result.
func TestRunLoopRepeatedModelIDsAcrossSteps(t *testing.T) {
	provider := &fakeProvider{replies: []ProviderResponse{
		{ToolCalls: []ModelToolCall{{CallID: "0", Name: "host.users.list", Arguments: json.RawMessage(`{}`)}}},
		{ToolCalls: []ModelToolCall{{CallID: "0", Name: "host.users.list", Arguments: json.RawMessage(`{}`)}}},
		{Content: "done"},
	}}
	tools := &fakeTools{defs: toolDefs()}
	next := 0
	result, err := RunLoop(context.Background(), provider, tools, nil, nil, LoopOptions{
		NextCallID: func() string {
			next++
			return fmt.Sprintf("call_host_%d", next)
		},
	})
	if err != nil {
		t.Fatalf("RunLoop: %v", err)
	}
	if result.Status != LoopCompleted || len(tools.executed) != 2 {
		t.Fatalf("status = %q, executed = %+v", result.Status, tools.executed)
	}
	if tools.executed[0].CallID == tools.executed[1].CallID {
		t.Fatalf("the two steps share id %q", tools.executed[0].CallID)
	}
	last := provider.reqs[2].Messages
	if len(last) != 4 || last[0].ToolCalls[0].CallID != last[1].ToolCallID ||
		last[2].ToolCalls[0].CallID != last[3].ToolCallID {
		t.Fatalf("transcript = %+v", last)
	}
}

// TestRunLoopRejectsHugeArguments: an oversized call fails without running and
// its body is not resent to the model on the next step.
func TestRunLoopRejectsHugeArguments(t *testing.T) {
	huge := json.RawMessage(`{"a":"` + strings.Repeat("x", MaxToolArgsBytes) + `"}`)
	provider := &fakeProvider{replies: []ProviderResponse{
		{ToolCalls: []ModelToolCall{{CallID: "c1", Name: "host.users.list", Arguments: huge}}},
		{Content: "sorry"},
	}}
	tools := &fakeTools{defs: toolDefs()}
	rec := &loopRecorder{}
	if _, err := RunLoop(context.Background(), provider, tools, nil, rec.emit, LoopOptions{}); err != nil {
		t.Fatalf("RunLoop: %v", err)
	}
	if len(tools.executed) != 0 {
		t.Fatalf("executed = %d calls", len(tools.executed))
	}
	var outcome *ToolOutcome
	for _, e := range rec.events {
		if e.Type == LoopEventToolResult {
			outcome = e.Outcome
		}
	}
	if outcome == nil || outcome.Status != ToolFailed || outcome.Error.Code != problem.ValidationFailed {
		t.Fatalf("outcome = %+v", outcome)
	}
	for _, msg := range provider.reqs[1].Messages {
		for _, call := range msg.ToolCalls {
			if len(call.Arguments) > 128 {
				t.Fatalf("the oversized arguments went back to the model (%d bytes)", len(call.Arguments))
			}
		}
	}
}
