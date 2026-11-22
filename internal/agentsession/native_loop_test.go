// SPDX-License-Identifier: AGPL-3.0-only

package agentsession

import (
	"context"
	"encoding/json"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/qwq-panel/qwq/internal/operations"
	"github.com/qwq-panel/qwq/internal/platform/problem"
)

// TestOpenAIProviderComplete checks the protocol adapter: what is serialized to
// the endpoint and how a tool-call answer is mapped back to the loop.
func TestOpenAIProviderComplete(t *testing.T) {
	model := newModelServer(t, toolCallReply("call_1", "host_users_create", `{"name":"a"}`))
	core := NewNativeCore(NativeOptions{Client: model.srv.Client()})
	provider := &openAIProvider{core: core, cfg: &nativeConfig{BaseURL: model.srv.URL, Model: "test-model"}}

	resp, err := provider.Complete(context.Background(), ProviderRequest{
		Messages: []ModelMessage{
			{Role: LoopRoleSystem, Content: "sys"},
			{Role: LoopRoleUser, Content: "create a"},
		},
		Tools: []ToolDef{{
			Name: "host_users_create", Action: "host.users.create", Description: "Create a user",
			Parameters: json.RawMessage(`{"type":"object"}`),
		}},
	})
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if resp.Content != "" {
		t.Fatalf("content = %q", resp.Content)
	}
	if len(resp.ToolCalls) != 1 {
		t.Fatalf("tool calls = %+v", resp.ToolCalls)
	}
	call := resp.ToolCalls[0]
	if call.CallID != "call_1" || call.Name != "host_users_create" || string(call.Arguments) != `{"name":"a"}` {
		t.Fatalf("call = %+v", call)
	}

	req := model.request(0)
	if req["model"] != "test-model" {
		t.Fatalf("model = %v", req["model"])
	}
	if req["tool_choice"] != "auto" {
		t.Fatalf("tool_choice = %v", req["tool_choice"])
	}
	tools, _ := req["tools"].([]any)
	if len(tools) != 1 || toolFunctionName(t, tools[0]) != "host_users_create" {
		t.Fatalf("tools = %+v", tools)
	}
	msgs, _ := req["messages"].([]any)
	if len(msgs) != 2 {
		t.Fatalf("messages = %+v", msgs)
	}
	if first, _ := msgs[0].(map[string]any); first["role"] != RoleSystem || first["content"] != "sys" {
		t.Fatalf("system message = %+v", first)
	}
}

// TestOpenAIProviderKeepsInvalidArguments checks that the adapter never
// silently repairs a model answer: the loop validates and reports it.
func TestOpenAIProviderKeepsInvalidArguments(t *testing.T) {
	body := `{"choices":[{"message":{"role":"assistant","tool_calls":[` +
		`{"id":"c1","type":"function","function":{"name":"host_users_list","arguments":"{\"limit\":"}}]}}]}`
	model := newModelServer(t, modelReply{body: body})
	core := NewNativeCore(NativeOptions{Client: model.srv.Client()})
	provider := &openAIProvider{core: core, cfg: &nativeConfig{BaseURL: model.srv.URL, Model: "m"}}
	resp, err := provider.Complete(context.Background(), ProviderRequest{})
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if len(resp.ToolCalls) != 1 || json.Valid(resp.ToolCalls[0].Arguments) {
		t.Fatalf("tool calls = %+v", resp.ToolCalls)
	}
}

// TestNativeToolsExecute checks the operation-path adapter.
func TestNativeToolsExecute(t *testing.T) {
	var got ToolCall
	runner := &fakeRunner{fn: func(_ context.Context, call ToolCall) (ToolResult, error) {
		got = call
		return ToolResult{
			Status: ToolSucceeded, Result: json.RawMessage(`{"id":1}`), OperationID: "op_1",
		}, nil
	}}
	names := newToolNames(testTools())
	tools := &nativeTools{
		names: names, runner: runner,
		turn: Turn{SessionID: "sess_1", PermissionMode: operations.PermissionSafe},
	}
	name := names.name("host.users.create")
	def, ok := tools.Spec(name)
	if !ok || def.Action != "host.users.create" || def.Name != name {
		t.Fatalf("spec = %+v, %v", def, ok)
	}
	out, err := tools.Execute(context.Background(), ModelToolCall{
		CallID: "call_1", Name: name, Arguments: json.RawMessage(`{"name":"a"}`),
	})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if out.Status != ToolSucceeded || out.OperationID != "op_1" || string(out.Result) != `{"id":1}` {
		t.Fatalf("outcome = %+v", out)
	}
	if got.Action != "host.users.create" || got.CallID != "call_1" || got.SessionID != "sess_1" {
		t.Fatalf("runner call = %+v", got)
	}
	if string(got.Args) != `{"name":"a"}` || got.PermissionMode != operations.PermissionSafe {
		t.Fatalf("runner call = %+v", got)
	}

	// An unknown function name is a tool error, never an execution.
	out, err = tools.Execute(context.Background(), ModelToolCall{CallID: "c2", Name: "nope"})
	if err != nil || out.Status != ToolFailed || out.Error == nil || out.Error.Code != problem.Unavailable {
		t.Fatalf("unknown tool outcome = %+v, %v", out, err)
	}
	// A host without a runner answers with a clear tool error.
	bare := &nativeTools{names: names}
	out, err = bare.Execute(context.Background(), ModelToolCall{CallID: "c3", Name: name})
	if err != nil || out.Status != ToolFailed || out.Error == nil || out.Error.Code != problem.Unavailable {
		t.Fatalf("no-runner outcome = %+v, %v", out, err)
	}
}

// TestNativeToolsApproval checks that a runner approval becomes the loop's
// approval request, and that an approval without an id fails closed.
func TestNativeToolsApproval(t *testing.T) {
	deadline := timeForTest()
	names := newToolNames(testTools())
	runner := &fakeRunner{fn: func(context.Context, ToolCall) (ToolResult, error) {
		return ToolResult{
			Status: ToolAwaitingApproval, OperationID: "op_1",
			Approval: &ApprovalInfo{
				ApprovalID: "apr_1", OperationID: "op_1", Summary: "Create a user?",
				Description: "Creates a panel user.", Risk: "high", Approval: "confirm", Deadline: &deadline,
			},
		}, nil
	}}
	tools := &nativeTools{names: names, runner: runner, turn: Turn{SessionID: "s"}}
	out, err := tools.Execute(context.Background(), ModelToolCall{
		CallID: "c1", Name: names.name("host.users.create"), Arguments: json.RawMessage(`{}`),
	})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if out.Approval == nil || out.Approval.ApprovalID != "apr_1" || out.Approval.OperationID != "op_1" {
		t.Fatalf("approval = %+v", out.Approval)
	}
	if out.Approval.Summary != "Create a user?" || out.Approval.Approval != "confirm" {
		t.Fatalf("approval text = %+v", out.Approval)
	}

	// A runner that forgets the approval id must not produce an undecidable pause.
	bad := &nativeTools{names: names, runner: &fakeRunner{fn: func(context.Context, ToolCall) (ToolResult, error) {
		return ToolResult{Status: ToolAwaitingApproval, Approval: &ApprovalInfo{}}, nil
	}}}
	if _, err := bad.Execute(context.Background(), ModelToolCall{
		CallID: "c2", Name: names.name("host.users.create"), Arguments: json.RawMessage(`{}`),
	}); err == nil || problem.From(err).Code != problem.Internal {
		t.Fatalf("err = %v", err)
	}
}

// TestNativeGatePermissionModes covers the host-side dangerous list.
func TestNativeGatePermissionModes(t *testing.T) {
	names := newToolNames(testTools())
	tools := &nativeTools{names: names}
	readName := names.name("host.users.list")
	writeName := names.name("host.users.create")
	readDef, _ := tools.Spec(readName)
	writeDef, _ := tools.Spec(writeName)

	cases := []struct {
		name string
		mode operations.PermissionMode
		def  ToolDef
		want GateDecisionKind
	}{
		{"read_only allows read", operations.PermissionReadOnly, readDef, GateAllow},
		{"read_only denies write", operations.PermissionReadOnly, writeDef, GateDeny},
		{"safe allows write", operations.PermissionSafe, writeDef, GateAllow},
		{"full allows write", operations.PermissionFull, writeDef, GateAllow},
		{"custom allows write", operations.PermissionCustom, writeDef, GateAllow},
		{"empty mode defaults to safe", "", writeDef, GateAllow},
		{"unknown mode denies write", operations.PermissionMode("bogus"), writeDef, GateDeny},
		{"unknown mode allows read", operations.PermissionMode("bogus"), readDef, GateAllow},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gate := nativeGate{tools: tools, mode: tc.mode}
			decision, err := gate.Check(context.Background(), tc.def, ModelToolCall{Name: tc.def.Name})
			if err != nil {
				t.Fatalf("Check: %v", err)
			}
			if decision.Kind != tc.want {
				t.Fatalf("decision = %+v, want %q", decision, tc.want)
			}
			if tc.want == GateDeny && decision.Reason == "" {
				t.Fatalf("deny has no reason")
			}
		})
	}

	// An unknown tool is denied even when the mode would allow it.
	gate := nativeGate{tools: tools, mode: operations.PermissionFull}
	decision, err := gate.Check(context.Background(), ToolDef{Name: "nope"}, ModelToolCall{Name: "nope"})
	if err != nil || decision.Kind != GateDeny {
		t.Fatalf("decision = %+v, %v", decision, err)
	}

	// A read tool declared high risk counts as dangerous in read_only.
	dangerous := ToolSpec{Action: "host.secrets.read", Effect: operations.EffectRead, Risk: operations.RiskHigh}
	if !nativeDangerous(dangerous) {
		t.Fatal("high-risk read tool classified as safe")
	}
	if nativeDangerous(ToolSpec{Action: "host.users.list", Effect: operations.EffectRead, Risk: operations.RiskLow}) {
		t.Fatal("low-risk read tool classified as dangerous")
	}
}

// TestNativeCoreUsesInjectedGate checks the service wiring: a host gate can
// refuse a call before the runner, and the turn still ends normally.
func TestNativeCoreUsesInjectedGate(t *testing.T) {
	runner := &fakeRunner{fn: func(context.Context, ToolCall) (ToolResult, error) {
		t.Error("the runner was called although the gate denied the call")
		return ToolResult{Status: ToolSucceeded}, nil
	}}
	h, _ := newNativeHost(t, func(o *Options) {
		o.Catalog = StaticCatalog{Tools: testTools()}
		o.Runner = runner
		o.Native.Gate = GateFunc(func(context.Context, ToolDef, ModelToolCall) (GateDecision, error) {
			return GateDecision{Kind: GateDeny, Reason: "blocked by the host policy"}, nil
		})
	})
	model := newModelServer(t,
		toolCallReply("call_1", "host_users_create", `{"name":"a"}`),
		modelReply{content: "the host refused"},
	)
	rec := h.create(ownerHuman, CreateRequest{
		Core: CoreNative, PermissionMode: operations.PermissionSafe,
		Config: nativeConfigJSON(model.srv.URL, "m"),
	})
	sub := h.subscribe(ownerHuman, rec.ID)
	h.send(ownerHuman, rec.ID, "create a")
	h.waitTurn(rec.ID)
	requireStatus(t, h.svc, ownerHuman, rec.ID, StatusIdle)

	events := drain(sub)
	results := eventsOfType(events, EventToolResult)
	if len(results) != 1 || results[0].Status != string(ToolRejected) {
		t.Fatalf("tool results = %+v", results)
	}
	if results[0].Error == nil || results[0].Error.Code != problem.PermissionDenied {
		t.Fatalf("tool result error = %+v", results[0].Error)
	}
	if calls, _ := runner.snapshot(); len(calls) != 0 {
		t.Fatalf("runner calls = %+v", calls)
	}
}

// TestNativeCoreStepLimitMessage checks that the product's step-limit sentence
// is still produced by the adapter after the loop refactor.
func TestNativeCoreStepLimitMessage(t *testing.T) {
	h, _ := newNativeHost(t, func(o *Options) {
		o.Catalog = StaticCatalog{Tools: testTools()}
		o.Runner = &fakeRunner{}
	})
	model := newModelServer(t, toolCallReply("call_1", "host_users_list", `{}`))
	cfg, _ := json.Marshal(map[string]any{
		"base_url": model.srv.URL, "model": "m", "max_steps": 1,
	})
	rec := h.create(ownerHuman, CreateRequest{Core: CoreNative, Config: cfg})
	sub := h.subscribe(ownerHuman, rec.ID)
	h.send(ownerHuman, rec.ID, "loop")
	h.waitTurn(rec.ID)
	events := drain(sub)
	errEvent := eventsOfType(events, EventError)
	if len(errEvent) != 1 || errEvent[0].Code != string(problem.Unavailable) {
		t.Fatalf("error event = %+v", errEvent)
	}
	if !strings.Contains(errEvent[0].Detail, "step limit") {
		t.Fatalf("detail = %q", errEvent[0].Detail)
	}
}

// TestNativeCoreInvalidArgumentsPersist checks the persistence contract: the
// tool call is announced before a malformed call is rejected, so the service
// can store the failed result instead of failing the turn on a missing row.
func TestNativeCoreInvalidArgumentsPersist(t *testing.T) {
	runner := &fakeRunner{fn: func(context.Context, ToolCall) (ToolResult, error) {
		t.Error("a call with malformed arguments reached the runner")
		return ToolResult{Status: ToolSucceeded}, nil
	}}
	h, _ := newNativeHost(t, func(o *Options) {
		o.Catalog = StaticCatalog{Tools: testTools()}
		o.Runner = runner
	})
	model := newModelServer(t,
		toolCallReply("call_1", "host_users_create", `{"name":`),
		modelReply{content: "my arguments were broken"},
	)
	rec := h.create(ownerHuman, CreateRequest{Core: CoreNative, Config: nativeConfigJSON(model.srv.URL, "m")})
	sub := h.subscribe(ownerHuman, rec.ID)
	h.send(ownerHuman, rec.ID, "create a")
	h.waitTurn(rec.ID)
	requireStatus(t, h.svc, ownerHuman, rec.ID, StatusIdle)

	events := drain(sub)
	if len(eventsOfType(events, EventToolCall)) != 1 {
		t.Fatalf("tool call events = %+v", eventsOfType(events, EventToolCall))
	}
	results := eventsOfType(events, EventToolResult)
	if len(results) != 1 || results[0].Status != string(ToolFailed) {
		t.Fatalf("tool results = %+v", results)
	}
	if results[0].Error == nil || results[0].Error.Code != problem.ValidationFailed {
		t.Fatalf("tool result error = %+v", results[0].Error)
	}
	if msgs, err := h.svc.Messages(context.Background(), ownerHuman, rec.ID, 0); err != nil || len(msgs) != 4 {
		t.Fatalf("messages = %+v, %v", msgs, err)
	}
}

// timeForTest returns a fixed deadline for the approval adapter test.
func timeForTest() time.Time {
	return time.Unix(1_700_000_000, 0).UTC()
}

// TestNativeShortCallIDWriteTool: a provider's 13-character id (Ollama) must
// not reach the operation layer, whose idempotency key needs 16 characters.
func TestNativeShortCallIDWriteTool(t *testing.T) {
	runner := &fakeRunner{}
	h, _ := newNativeHost(t, func(o *Options) {
		o.Catalog = StaticCatalog{Tools: testTools()}
		o.Runner = runner
	})
	model := newModelServer(t,
		toolCallReply("call_abcd1234", "host_users_create", `{"name":"a"}`),
		modelReply{content: "created"},
	)
	rec := h.create(ownerHuman, CreateRequest{Core: CoreNative, Config: nativeConfigJSON(model.srv.URL, "m")})
	h.send(ownerHuman, rec.ID, "create a")
	h.waitTurn(rec.ID)
	requireStatus(t, h.svc, ownerHuman, rec.ID, StatusIdle)

	calls, _ := runner.snapshot()
	if len(calls) != 1 {
		t.Fatalf("runner calls = %+v", calls)
	}
	if !regexp.MustCompile(`^[A-Za-z0-9_.:-]{16,128}$`).MatchString(calls[0].CallID) {
		t.Fatalf("call id %q is not a valid idempotency key", calls[0].CallID)
	}
}
