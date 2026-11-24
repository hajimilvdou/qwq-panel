// SPDX-License-Identifier: AGPL-3.0-only

package agentsession

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"time"

	"github.com/qwq-panel/qwq/internal/platform/problem"
)

// This file is the provider-neutral agent loop. It owns the parts of a turn
// that are the same for every backend: the transcript, the bounded step loop,
// tool-call parsing, the permission gate before each execution, feeding tool
// results back to the model, and the event order a host persists.
//
// It is deliberately not a framework: a provider adapts one model protocol
// (native.go does OpenAI chat completions), a ToolRegistry adapts the host's
// tool catalog, and a Gate decides allow/deny/approval. The loop never touches
// the network, the database, the operation layer, a CLI or a UI. The structure
// borrows from opencode (session/runner/llm.ts: one turn -> many bounded steps,
// a sanitized transcript and a step limit that ends with a text-only answer)
// and from piagent (policy decisions live in a gate that runs before any tool
// side effect, and tool visibility is not authorization). See
// docs/design/agent-core-references.md.

// Defaults of the loop.
const (
	// DefaultLoopSteps bounds a turn when LoopOptions.MaxSteps is unset. The
	// native core keeps the product limit of eight steps (ADR-0010 §5).
	DefaultLoopSteps = 8
	// MaxLoopToolBytes bounds the text of one tool outcome that is fed back to
	// the model, so a large result cannot push the pairing out of the context.
	MaxLoopToolBytes = 32 << 10
	// MaxToolArgsBytes bounds the arguments of one tool call. A larger call
	// fails without running and is stored as a summary (truncatedArgs).
	MaxToolArgsBytes = 64 << 10
	// maxLoopToolNameBytes 限制未知名称在消息历史中的副本，不改变原名称的查找授权。
	maxLoopToolNameBytes = 128
)

// Roles of the provider-neutral transcript. The values are the same strings the
// session transcript uses, so an adapter can copy them without a mapping.
const (
	LoopRoleSystem    = "system"
	LoopRoleUser      = "user"
	LoopRoleAssistant = "assistant"
	LoopRoleTool      = "tool"
)

// ModelMessage is one transcript entry the loop builds for a provider. A tool
// call lives on the assistant message and is answered by one tool message whose
// ToolCallID equals the call's CallID: that pairing is the invariant the model
// protocol requires, and SanitizeHistory enforces it.
type ModelMessage struct {
	Role             string
	Content          string
	ReasoningContent string
	ThinkingBlocks   []AnthropicThinkingBlock
	ToolCalls        []ModelToolCall
	ToolCallID       string
}

// ModelToolCall is one tool call proposed by the model, already mapped to the
// host's function name for that tool (the registry owns the name mapping).
type ModelToolCall struct {
	CallID    string
	Name      string
	Arguments json.RawMessage
}

// ToolDef is one tool offered to the model: the function name, the description
// and the JSON schema the provider serializes, plus an opaque host action id
// that comes back on events so the host can record what ran.
type ToolDef struct {
	Name        string
	Description string
	Parameters  json.RawMessage
	// Action is the host's identifier of the tool. The loop never interprets
	// it; it is passed through so an event can name the host action.
	Action string
}

// ProviderRequest is everything a provider needs for one completion.
type ProviderRequest struct {
	Messages []ModelMessage
	Tools    []ToolDef
}

// ProviderResponse is one completion: text, tool calls, or both.
type ProviderResponse struct {
	Content          string
	ReasoningContent string
	ThinkingBlocks   []AnthropicThinkingBlock
	ToolCalls        []ModelToolCall
}

// toolCallIDRemapper is optionally implemented by providers (such as Anthropic
// extended thinking) that track provider-specific metadata keyed by tool call ID
// and need to follow RunLoop's host-minted IDs after normalizeCalls.
type toolCallIDRemapper interface {
	RemapToolCallIDs(orig, normalized []ModelToolCall)
}

// Provider adapts one model protocol to the loop. Complete performs exactly one
// model request; streaming, retries, timeouts and credentials belong to the
// adapter. A returned error aborts the turn.
type Provider interface {
	Complete(ctx context.Context, req ProviderRequest) (ProviderResponse, error)
}

// ToolRegistry is the host's tool catalog for one turn. Tools is what the model
// may see; Spec resolves a proposed call before the gate runs; Execute performs
// one call through the host's operation path.
type ToolRegistry interface {
	Tools() []ToolDef
	Spec(name string) (ToolDef, bool)
	Execute(ctx context.Context, call ModelToolCall) (ToolOutcome, error)
}

// ToolOutcome is the result of one tool execution. Approval is set when the
// host executed nothing because a human decision is required; the loop then
// pauses instead of feeding a fabricated result back to the model.
type ToolOutcome struct {
	Status      ToolStatus
	Result      json.RawMessage
	Error       *problem.Error
	OperationID string
	ApprovalID  string
	Approval    *ApprovalRequest
}

// ApprovalRequest is the provider-neutral shape of an approval a tool call is
// waiting for. It is what the session publishes as approval_required.
type ApprovalRequest struct {
	ApprovalID  string
	OperationID string
	Summary     string
	Description string
	Risk        string
	Approval    string
	Deadline    *time.Time
}

// GateDecisionKind is the verdict of a Gate.
type GateDecisionKind string

const (
	// GateAllow: execute the tool.
	GateAllow GateDecisionKind = "allow"
	// GateDeny: refuse the call. The loop records a rejected tool result and
	// feeds it back, so the model can continue with a different plan.
	GateDeny GateDecisionKind = "deny"
	// GateApproval: the call needs a human decision. The loop emits the
	// approval event and returns ErrLoopApproval without executing anything.
	GateApproval GateDecisionKind = "approval"
)

// GateDecision is the host's answer for one proposed call.
type GateDecision struct {
	Kind GateDecisionKind
	// Reason explains a deny or an approval to the model and to the user.
	Reason string
	// Approval carries the host's approval identity for GateApproval.
	Approval *ApprovalRequest
}

// Gate decides what may run before any side effect. It is the host's policy
// seam: permission mode, dangerous-action lists, protected paths, robot rules.
// The loop never hardcodes a policy; a nil Gate allows every call.
type Gate interface {
	Check(ctx context.Context, tool ToolDef, call ModelToolCall) (GateDecision, error)
}

// GateFunc adapts a function to Gate.
type GateFunc func(ctx context.Context, tool ToolDef, call ModelToolCall) (GateDecision, error)

// Check implements Gate.
func (f GateFunc) Check(ctx context.Context, tool ToolDef, call ModelToolCall) (GateDecision, error) {
	return f(ctx, tool, call)
}

// LoopEventType is the kind of one loop event. The host maps these to its own
// session events; the loop never decides how an event is persisted.
type LoopEventType string

const (
	// LoopEventDelta carries assistant text. A streaming provider emits many;
	// a non-streaming provider emits one with the whole message.
	LoopEventDelta LoopEventType = "delta"
	// LoopEventAssistant marks the end of one assistant message. Calls is set
	// when the message proposes tools, which is the boundary a host needs to
	// persist the assistant message before its tool results exist.
	LoopEventAssistant LoopEventType = "assistant"
	// LoopEventToolCall announces one parsed call, including an unavailable name,
	// before the gate and before any side effect.
	LoopEventToolCall LoopEventType = "tool_call"
	// LoopEventToolResult reports one outcome, including a denied or malformed
	// call that was never executed.
	LoopEventToolResult LoopEventType = "tool_result"
	// LoopEventApproval reports a call that needs a human decision.
	LoopEventApproval LoopEventType = "approval"
	// LoopEventDone marks a turn that ended with a text answer.
	LoopEventDone LoopEventType = "done"
	// LoopEventError reports a terminal loop error. The host usually has the
	// returned error already and may ignore this event.
	LoopEventError LoopEventType = "error"
)

// LoopEvent is one event of a running turn.
type LoopEvent struct {
	Type             LoopEventType
	Step             int
	Delta            string
	Content          string
	ReasoningContent string
	ThinkingBlocks   []AnthropicThinkingBlock
	Calls            []ModelToolCall
	Call             *ModelToolCall
	Tool             *ToolDef
	Outcome          *ToolOutcome
	// Approval is set on LoopEventApproval.
	Approval *ApprovalRequest
	// Err is set on LoopEventError.
	Err *problem.Error
}

// LoopEmit publishes one event. An error aborts the turn, which is how a host
// stops the loop when its own stream is gone.
type LoopEmit func(LoopEvent) error

// LoopOptions configures one RunLoop call.
type LoopOptions struct {
	// Messages is the initial transcript, oldest first, including the system
	// message the provider should see. It is sanitized before the first
	// request, so a pruned or interrupted history can never produce an invalid
	// tool-call pairing.
	Messages []ModelMessage
	// MaxSteps bounds the number of model requests of this turn.
	MaxSteps int
	// NextCallID mints the identifier of every call. A nil function keeps the
	// model's own id and makes a missing, malformed or repeated one an internal
	// error, exactly like a model protocol that cannot pair its results.
	NextCallID func() string
}

// LoopStatus is how a RunLoop ended.
type LoopStatus string

const (
	// LoopCompleted: the model answered with text only.
	LoopCompleted LoopStatus = "completed"
	// LoopPaused: an approval is required; nothing was executed for that call
	// and the host has to decide before the turn can continue.
	LoopPaused LoopStatus = "paused"
	// LoopStepLimit: the turn used all its steps while the model kept calling
	// tools.
	LoopStepLimit LoopStatus = "step_limit"
)

// LoopResult is the outcome of one turn.
type LoopResult struct {
	Status LoopStatus
	// Steps is the number of model requests performed.
	Steps int
	// Text is the last assistant text of a completed turn.
	Text string
	// Messages is the final transcript, including the tool results this turn
	// produced. A host that pauses and resumes can reuse it as the next seed.
	Messages []ModelMessage
	// Pending is the call and approval a paused turn is waiting for.
	Pending *LoopPending
}

// LoopPending is the call a paused turn waits for.
type LoopPending struct {
	Call     ModelToolCall
	Tool     ToolDef
	Approval *ApprovalRequest
}

// ErrLoopApproval is returned with LoopResult.Status == LoopPaused after the
// approval event was emitted and before the tool was executed.
var ErrLoopApproval = errors.New("agentsession: the agent loop is waiting for an approval decision")

// ErrLoopStepLimit is returned when the turn used all its steps.
var ErrLoopStepLimit = errors.New("agentsession: the agent loop reached its step limit")

// RunLoop runs one turn: up to MaxSteps model requests, each proposing zero or
// more tool calls that pass the gate before the registry executes them, with
// every outcome fed back into the transcript. It stops on a text-only answer
// (LoopCompleted), on a call that needs a human decision (LoopPaused with
// ErrLoopApproval), on the step limit (ErrLoopStepLimit), on a provider, gate or
// emit error, or when ctx is cancelled.
func RunLoop(ctx context.Context, provider Provider, tools ToolRegistry, gate Gate,
	emit LoopEmit, opts LoopOptions) (LoopResult, error) {
	messages := SanitizeHistory(opts.Messages)
	result := LoopResult{Messages: messages}
	if provider == nil {
		return result, problem.New(problem.Internal, "The agent loop has no model provider.")
	}
	if emit == nil {
		emit = func(LoopEvent) error { return nil }
	}
	if gate == nil {
		gate = GateFunc(func(context.Context, ToolDef, ModelToolCall) (GateDecision, error) {
			return GateDecision{Kind: GateAllow}, nil
		})
	}
	if tools == nil {
		tools = emptyTools{}
	}
	steps := opts.MaxSteps
	if steps <= 0 {
		steps = DefaultLoopSteps
	}
	defs := tools.Tools()

	publish := func(e LoopEvent) error {
		if err := emit(e); err != nil {
			return err
		}
		return ctx.Err()
	}

	for step := 1; step <= steps; step++ {
		if err := ctx.Err(); err != nil {
			return result, err
		}
		response, err := provider.Complete(ctx, ProviderRequest{
			Messages: cloneMessages(messages),
			Tools:    defs,
		})
		if err != nil {
			return result, loopProviderError(ctx, emit, err)
		}
		result.Steps = step
		origCalls := response.ToolCalls
		calls, err := normalizeCalls(response.ToolCalls, opts.NextCallID)
		if err != nil {
			return result, err
		}
		if remapper, ok := provider.(toolCallIDRemapper); ok && len(origCalls) > 0 {
			remapper.RemapToolCallIDs(origCalls, calls)
		}
		if response.Content != "" {
			if err := publish(LoopEvent{Type: LoopEventDelta, Step: step, Delta: response.Content}); err != nil {
				return result, err
			}
		}
		if err := publish(LoopEvent{
			Type: LoopEventAssistant, Step: step, Content: response.Content, ReasoningContent: response.ReasoningContent, ThinkingBlocks: response.ThinkingBlocks, Calls: calls,
		}); err != nil {
			return result, err
		}
		messages = append(messages, ModelMessage{
			Role: LoopRoleAssistant, Content: response.Content, ReasoningContent: response.ReasoningContent, ThinkingBlocks: response.ThinkingBlocks, ToolCalls: boundedCalls(calls),
		})
		if len(calls) == 0 {
			result.Status = LoopCompleted
			result.Text = response.Content
			result.Messages = messages
			if err := publish(LoopEvent{Type: LoopEventDone, Step: step, Content: response.Content}); err != nil {
				return result, err
			}
			return result, nil
		}

		for _, call := range calls {
			if err := ctx.Err(); err != nil {
				return result, err
			}
			call := call
			def, known := tools.Spec(call.Name)
			if !known {
				def = ToolDef{Name: call.Name}
			}
			// Announce the call before validating it: the host persists the
			// proposal first and the outcome second, and a result without a
			// call cannot be stored.
			if err := publish(LoopEvent{
				Type: LoopEventToolCall, Step: step, Call: &call, Tool: &def,
			}); err != nil {
				return result, err
			}
			// --- 未知名称只形成失败结果，不进入权限门禁或执行器；同批其他调用继续 ---
			var validationErr error
			if !known {
				validationErr = problem.New(problem.Unavailable, "The model called an unknown tool.")
			} else if reason := argumentsProblem(call.Arguments); reason != "" {
				validationErr = problem.New(problem.ValidationFailed, "%s", reason)
			}
			if validationErr != nil {
				outcome := ToolOutcome{Status: ToolFailed, Error: problem.From(validationErr)}
				if err := publish(LoopEvent{
					Type: LoopEventToolResult, Step: step, Call: &call, Tool: &def, Outcome: &outcome,
				}); err != nil {
					return result, err
				}
				messages = append(messages, toolMessage(call, outcome))
				continue
			}

			decision, err := gate.Check(ctx, def, call)
			if err != nil {
				return result, err
			}
			switch decision.Kind {
			case GateDeny:
				outcome := ToolOutcome{
					Status: ToolRejected,
					Error:  problem.New(problem.PermissionDenied, "%s", firstNonEmpty(decision.Reason, "The host denied the tool call.")),
				}
				if err := publish(LoopEvent{
					Type: LoopEventToolResult, Step: step, Call: &call, Tool: &def, Outcome: &outcome,
				}); err != nil {
					return result, err
				}
				messages = append(messages, toolMessage(call, outcome))
				continue
			case GateApproval:
				approval := decision.Approval
				if approval == nil {
					approval = &ApprovalRequest{Summary: decision.Reason}
				}
				if err := publish(LoopEvent{
					Type: LoopEventApproval, Step: step, Call: &call, Tool: &def, Approval: approval,
				}); err != nil {
					return result, err
				}
				result.Status = LoopPaused
				result.Messages = messages
				result.Pending = &LoopPending{Call: call, Tool: def, Approval: approval}
				return result, ErrLoopApproval
			case GateAllow:
				// Continue to execution.
			default:
				return result, problem.New(problem.Internal,
					"The permission gate returned an unknown decision.")
			}

			outcome, err := tools.Execute(ctx, call)
			if err != nil {
				if ctxErr := ctx.Err(); ctxErr != nil {
					return result, ctxErr
				}
				// An execution error is still a tool outcome: the model is told
				// what happened instead of the turn dying with a panic or a
				// half-written transcript.
				outcome = ToolOutcome{Status: ToolFailed, Error: problem.From(err)}
			}
			if outcome.Status == ToolAwaitingApproval || outcome.Approval != nil {
				approval := outcome.Approval
				if approval == nil || approval.ApprovalID == "" {
					return result, problem.New(problem.Internal,
						"The tool runner asked for an approval without an approval id.")
				}
				if err := publish(LoopEvent{
					Type: LoopEventApproval, Step: step, Call: &call, Tool: &def, Approval: approval,
				}); err != nil {
					return result, err
				}
				result.Status = LoopPaused
				result.Messages = messages
				result.Pending = &LoopPending{Call: call, Tool: def, Approval: approval}
				return result, ErrLoopApproval
			}
			if !outcome.Status.Valid() {
				outcome.Status = ToolFailed
			}
			if err := publish(LoopEvent{
				Type: LoopEventToolResult, Step: step, Call: &call, Tool: &def, Outcome: &outcome,
			}); err != nil {
				return result, err
			}
			messages = append(messages, toolMessage(call, outcome))
		}
	}

	result.Status = LoopStepLimit
	result.Messages = messages
	_ = emit(LoopEvent{
		Type: LoopEventError,
		Step: steps,
		Err:  problem.New(problem.Unavailable, "The agent loop reached its tool-call step limit."),
	})
	return result, ErrLoopStepLimit
}

// emptyTools is the registry of a turn that offers no tools.
type emptyTools struct{}

// Tools implements ToolRegistry.
func (emptyTools) Tools() []ToolDef { return nil }

// Spec implements ToolRegistry.
func (emptyTools) Spec(string) (ToolDef, bool) { return ToolDef{}, false }

// Execute implements ToolRegistry.
func (emptyTools) Execute(context.Context, ModelToolCall) (ToolOutcome, error) {
	return ToolOutcome{Status: ToolRejected}, nil
}

// loopProviderError reports a provider failure without hiding a cancellation:
// a cancelled context is returned as is, because the host maps it to its own
// cancelled status and must not see it as a model error.
func loopProviderError(ctx context.Context, emit LoopEmit, err error) error {
	if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr
	}
	if emit != nil {
		_ = emit(LoopEvent{Type: LoopEventError, Err: problem.From(err)})
	}
	return err
}

// modelCallIDRe is what a model's own call id must look like when the loop runs
// without a minting function.
var modelCallIDRe = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,128}$`)

// normalizeCalls validates the calls of one assistant message: an empty
// argument object becomes {}, and every call gets a host-minted id. A model's
// id is untrusted: providers send ids too short for an idempotency key, or
// repeat them on every step, while the id is a host-wide primary key. Only the
// library mode (nextID == nil) keeps it, after validating it.
func normalizeCalls(calls []ModelToolCall, nextID func() string) ([]ModelToolCall, error) {
	if len(calls) == 0 {
		return nil, nil
	}
	out := make([]ModelToolCall, 0, len(calls))
	seen := make(map[string]bool, len(calls))
	for _, call := range calls {
		if len(call.Arguments) == 0 {
			call.Arguments = json.RawMessage("{}")
		}
		if nextID != nil {
			if call.CallID = nextID(); call.CallID == "" {
				return nil, problem.New(problem.Internal, "The host could not mint a call id.")
			}
		} else if seen[call.CallID] || !modelCallIDRe.MatchString(call.CallID) {
			return nil, problem.New(problem.Internal, "The model called a tool without a usable call id.")
		}
		seen[call.CallID] = true
		out = append(out, call)
	}
	return out, nil
}

// argumentsProblem says why a call's arguments cannot be executed, "" when they
// can.
func argumentsProblem(args json.RawMessage) string {
	switch {
	case len(args) > MaxToolArgsBytes:
		return "The model returned tool arguments larger than 64 KiB."
	case !json.Valid(args):
		return "The model returned tool arguments that are not JSON."
	}
	return ""
}

// truncatedArgs is the bounded stand-in of oversized arguments.
func truncatedArgs(n int) json.RawMessage {
	return json.RawMessage(fmt.Sprintf(`{"truncated":true,"bytes":%d}`, n))
}

// boundedCalls is the copy of a step's calls that stays in the transcript, so an
// oversized call is not resent to the model on every following step.
func boundedCalls(calls []ModelToolCall) []ModelToolCall {
	out := slices.Clone(calls)
	for i := range out {
		out[i].Name = clipText(out[i].Name, maxLoopToolNameBytes)
		if len(out[i].Arguments) > MaxToolArgsBytes {
			out[i].Arguments = truncatedArgs(len(out[i].Arguments))
		}
	}
	return out
}

// toolMessage is the transcript entry the model reads as the answer of one
// call. A tool error is text, never an empty content: the protocol requires a
// non-empty string for some providers and the model must learn what happened.
func toolMessage(call ModelToolCall, outcome ToolOutcome) ModelMessage {
	return ModelMessage{
		Role:       LoopRoleTool,
		ToolCallID: call.CallID,
		Content:    toolOutcomeText(outcome),
	}
}

// toolOutcomeText is the tool message the model sees.
func toolOutcomeText(outcome ToolOutcome) string {
	if outcome.Error != nil {
		if outcome.Error.Detail != "" {
			return clipText(outcome.Error.Detail, MaxLoopToolBytes)
		}
		return string(outcome.Error.Code)
	}
	if len(outcome.Result) == 0 {
		return "(no output)"
	}
	return clipText(string(outcome.Result), MaxLoopToolBytes)
}

// SanitizeHistory rebuilds the model context from a stored or resumed
// transcript. An assistant message with tool calls is only kept when every call
// has a following tool result; otherwise the step (and the orphan results) is
// dropped, so a pruned, paused or cancelled history can never produce a request
// whose tool pairing is invalid. Orphan tool results are dropped; empty text
// messages are dropped because some providers reject them.
//
// opencode does the same in its model-request projection and piagent compacts
// tool results by keeping the pairing intact; see
// docs/design/agent-core-references.md.
func SanitizeHistory(in []ModelMessage) []ModelMessage {
	out := make([]ModelMessage, 0, len(in))
	for i := 0; i < len(in); i++ {
		msg := in[i]
		switch msg.Role {
		case LoopRoleSystem, LoopRoleUser:
			if msg.Content != "" {
				out = append(out, ModelMessage{Role: msg.Role, Content: msg.Content})
			}
		case LoopRoleAssistant:
			if len(msg.ToolCalls) == 0 {
				if msg.Content != "" {
					out = append(out, ModelMessage{Role: LoopRoleAssistant, Content: msg.Content, ThinkingBlocks: msg.ThinkingBlocks})
				}
				continue
			}
			results := make(map[string]ModelMessage, len(msg.ToolCalls))
			j := i + 1
			for ; j < len(in) && in[j].Role == LoopRoleTool; j++ {
				result := in[j]
				if result.ToolCallID == "" {
					continue
				}
				if _, ok := results[result.ToolCallID]; ok {
					continue
				}
				results[result.ToolCallID] = result
			}
			complete := true
			for _, call := range msg.ToolCalls {
				if _, ok := results[call.CallID]; !ok {
					complete = false
					break
				}
			}
			if !complete {
				i = j - 1
				continue
			}
			out = append(out, ModelMessage{
				Role: LoopRoleAssistant, Content: msg.Content, ReasoningContent: msg.ReasoningContent, ThinkingBlocks: msg.ThinkingBlocks, ToolCalls: msg.ToolCalls,
			})
			for _, call := range msg.ToolCalls {
				result := results[call.CallID]
				if result.Content == "" {
					result.Content = "(no output)"
				}
				out = append(out, ModelMessage{
					Role: LoopRoleTool, ToolCallID: call.CallID, Content: result.Content,
				})
			}
			i = j - 1
		case LoopRoleTool:
			// Orphan tool result: never sent without its assistant call.
		}
	}
	return out
}

// cloneMessages copies the slice so a provider cannot mutate the loop's
// transcript through the request it receives.
func cloneMessages(in []ModelMessage) []ModelMessage {
	if len(in) == 0 {
		return nil
	}
	out := make([]ModelMessage, len(in))
	copy(out, in)
	return out
}
