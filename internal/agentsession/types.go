// SPDX-License-Identifier: AGPL-3.0-only

// Package agentsession is the backend of the host's native agent plugin
// (ADR-0010 §5, docs/design/agent-sessions.md).
//
// A session is private chat state of one owner. Each session has a permission
// mode (ADR-0010 §2.1) that only the user may change: it is stored in the
// session row and put on the context of every tool call with
// operations.WithPermissionMode, never read from a request body inside a turn.
// A core (the built-in OpenAI-compatible `native` core today, an external CLI
// later) proposes tool calls; every call goes through Runner, which the host
// wires to operations.Run. The runner returns ToolApprovalRequired when the
// operation needs a human decision; the session then pauses, publishes
// approval_required and resumes or terminates once ApprovalBridge reports the
// decision. Only a human browser session can decide an approval — this package
// never decides one itself.
//
// The transcript is bounded: messages are pruned to the newest N (200 by
// default) while tool calls and their approval association are kept. SSE
// clients replay from an in-memory ring; a reconnecting client that falls out
// of the window gets `resync` and reloads the session snapshot.
package agentsession

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/qwq-panel/qwq/internal/actor"
	"github.com/qwq-panel/qwq/internal/operations"
	"github.com/qwq-panel/qwq/internal/platform/problem"
	"github.com/qwq-panel/qwq/internal/secrets"
)

// Status is the lifecycle state of a session (docs/design/agent-sessions.md §2).
type Status string

const (
	// StatusIdle: no turn is running; a message may be sent.
	StatusIdle Status = "idle"
	// StatusRunning: one turn is running.
	StatusRunning Status = "running"
	// StatusWaitingApproval: the turn paused on a human approval.
	StatusWaitingApproval Status = "waiting_approval"
	// StatusCancelled: the last turn was cancelled; a new message may start one.
	StatusCancelled Status = "cancelled"
	// StatusFailed: the last turn failed; a new message may start one.
	StatusFailed Status = "failed"
)

// Valid reports whether s is a known status.
func (s Status) Valid() bool {
	switch s {
	case StatusIdle, StatusRunning, StatusWaitingApproval, StatusCancelled, StatusFailed:
		return true
	}
	return false
}

// Busy reports whether a turn is using the session. A busy session refuses
// Send with STATE_CONFLICT.
func (s Status) Busy() bool { return s == StatusRunning || s == StatusWaitingApproval }

// StatusAttention is the pseudo-status of the `?status=attention` filter: the
// sessions a floating window has to show (waiting_approval or failed).
const StatusAttention = "attention"

// CoreName names a session core (the model backend of one session).
type CoreName string

const (
	// CoreNative is the host's built-in OpenAI-compatible core.
	CoreNative CoreName = "native"
	// CoreClaudeCode, CoreCodex and CoreOpencode are external CLI cores. The
	// adapter contract exists (CLIAdapter) but A3 has not wired real
	// processes yet: Send answers UNAVAILABLE for them.
	CoreClaudeCode CoreName = "claude-code"
	CoreCodex      CoreName = "codex"
	CoreOpencode   CoreName = "opencode"
)

// Valid reports whether c is a known core name.
func (c CoreName) Valid() bool {
	switch c {
	case CoreNative, CoreClaudeCode, CoreCodex, CoreOpencode:
		return true
	}
	return false
}

// PluginID is the built-in agent plugin (ADR-0010 §5).
const PluginID = "agent.native"

// Message roles.
const (
	RoleUser      = "user"
	RoleAssistant = "assistant"
	RoleSystem    = "system"
	RoleTool      = "tool"
)

// Session is one agent session (OpenAPI AgentSession).
type Session struct {
	ID             string                    `json:"session_id"`
	PluginID       string                    `json:"plugin_id"`
	Title          string                    `json:"title"`
	Core           CoreName                  `json:"core"`
	PermissionMode operations.PermissionMode `json:"permission_mode"`
	Status         Status                    `json:"status"`
	Config         json.RawMessage           `json:"config"`
	LastSeq        int64                     `json:"last_seq"`
	Pending        int                       `json:"pending_approvals"`
	LastMessageAt  *time.Time                `json:"last_message_at,omitempty"`
	// LastMessagePreview is the plain-text head of the newest transcript entry,
	// at most 120 characters (gap 6). It is untrusted (model or plugin output)
	// and computed on read; the transcript itself stays the source of truth.
	LastMessagePreview string    `json:"last_message_preview,omitempty"`
	CreatedAt          time.Time `json:"created_at"`
	UpdatedAt          time.Time `json:"updated_at"`
	Revision           string    `json:"revision"`

	// OwnerKind and OwnerID are the access-control predicate of the session and
	// are not part of the public schema.
	OwnerKind actor.Kind `json:"-"`
	OwnerID   string     `json:"-"`
	// APIKeyRef is the secret reference of the native core's API key, "" when
	// the session has none. It never leaves the host: the public schema only
	// has has_api_key, and only the native core receives it (Turn.APIKeyRef).
	APIKeyRef secrets.Ref `json:"-"`
}

// HasAPIKey reports whether the owner stored an API key for the native core
// (OpenAPI AgentSession.has_api_key).
func (s *Session) HasAPIKey() bool { return s.APIKeyRef != "" }

// Message is one persisted transcript entry (OpenAPI AgentSessionMessage).
// ContentJSON carries the structured fragment of a tool call or tool result;
// Content is what a plain-text client renders.
type Message struct {
	Seq         int64           `json:"seq"`
	MessageID   string          `json:"message_id"`
	Role        string          `json:"role"`
	Content     string          `json:"content"`
	ContentJSON json.RawMessage `json:"content_json,omitempty"`
	OperationID string          `json:"operation_id,omitempty"`
	ApprovalID  string          `json:"approval_id,omitempty"`
	CreatedAt   time.Time       `json:"created_at"`

	// SessionID is the owning session; it is not repeated in every message of
	// the API schema.
	SessionID string `json:"-"`
}

// MessageToolCall is one proposed call inside an assistant message. It is the
// content_json fragment that lets a later turn rebuild the model context.
type MessageToolCall struct {
	CallID    string          `json:"call_id"`
	Action    string          `json:"action"`
	Arguments json.RawMessage `json:"arguments"`
}

// assistantContent is the content_json of an assistant message with tool calls.
type assistantContent struct {
	ToolCalls []MessageToolCall `json:"tool_calls"`
}

// ErrorInfo is the wire and storage form of an error inside an event or a tool
// result. The full problem document belongs to the HTTP layer; a session event
// only needs the stable code and a human-readable detail.
type ErrorInfo struct {
	Code   problem.Code `json:"code"`
	Detail string       `json:"detail,omitempty"`
}

// ErrorOf converts a host error to its event form.
func ErrorOf(err *problem.Error) *ErrorInfo {
	if err == nil {
		return nil
	}
	return &ErrorInfo{Code: err.Code, Detail: clipText(err.Detail, 2000)}
}

// Problem converts the event form back to a host error.
func (e *ErrorInfo) Problem() *problem.Error {
	if e == nil {
		return nil
	}
	return &problem.Error{Code: e.Code, Detail: e.Detail}
}

// toolContent is the content_json of a tool message.
type toolContent struct {
	CallID      string          `json:"call_id"`
	Action      string          `json:"action,omitempty"`
	Status      string          `json:"status"`
	Result      json.RawMessage `json:"result,omitempty"`
	Error       *ErrorInfo      `json:"error,omitempty"`
	OperationID string          `json:"operation_id,omitempty"`
	ApprovalID  string          `json:"approval_id,omitempty"`
}

// ToolStatus is the state of one tool call (docs/design/agent-sessions.md §2).
type ToolStatus string

const (
	ToolProposed         ToolStatus = "proposed"
	ToolRunning          ToolStatus = "running"
	ToolAwaitingApproval ToolStatus = "awaiting_approval"
	ToolSucceeded        ToolStatus = "succeeded"
	ToolFailed           ToolStatus = "failed"
	ToolRejected         ToolStatus = "rejected"
	ToolCancelled        ToolStatus = "cancelled"
)

// Valid reports whether s is a known tool status.
func (s ToolStatus) Valid() bool {
	switch s {
	case ToolProposed, ToolRunning, ToolAwaitingApproval, ToolSucceeded, ToolFailed, ToolRejected, ToolCancelled:
		return true
	}
	return false
}

// ToolCall is one proposed tool execution handed to a Runner. Actor is the
// session owner the agent acts for; Runner must not trust anything else.
type ToolCall struct {
	CallID         string
	SessionID      string
	Seq            int64
	Actor          actor.Actor
	PermissionMode operations.PermissionMode
	Action         string
	Args           json.RawMessage
}

// ToolResult is what a Runner reports for one tool call.
type ToolResult struct {
	Status      ToolStatus
	OperationID string
	ApprovalID  string
	Result      json.RawMessage
	Error       *problem.Error
	// Approval is set when Status is ToolAwaitingApproval: the confirmation-card
	// text of the operation (ADR-0010 §4) and its deadline.
	Approval *ApprovalInfo
}

// ApprovalInfo is the host's approval request a tool call is waiting for.
type ApprovalInfo struct {
	ApprovalID  string     `json:"approval_id"`
	OperationID string     `json:"operation_id,omitempty"`
	Summary     string     `json:"summary,omitempty"`
	Description string     `json:"description,omitempty"`
	Risk        string     `json:"risk,omitempty"`
	Approval    string     `json:"approval,omitempty"`
	Deadline    *time.Time `json:"deadline,omitempty"`
}

// PendingApproval is one awaiting tool call enriched with the catalog text for
// the approval list (OpenAPI AgentSessionApproval).
type PendingApproval struct {
	CallID      string          `json:"call_id"`
	ApprovalID  string          `json:"approval_id"`
	OperationID string          `json:"operation_id,omitempty"`
	Action      string          `json:"action"`
	Args        json.RawMessage `json:"args,omitempty"`
	Summary     string          `json:"summary,omitempty"`
	Description string          `json:"description,omitempty"`
	Risk        string          `json:"risk,omitempty"`
	Approval    string          `json:"approval,omitempty"`
	Status      ToolStatus      `json:"status"`
	Deadline    *time.Time      `json:"deadline,omitempty"`
	CreatedAt   time.Time       `json:"created_at"`
}

// ToolSpec is one action the session may offer to its core, filtered by the
// session's permission mode before it reaches the core.
type ToolSpec struct {
	Action  string
	Summary string
	// Description is the plugin author's approval description (untrusted text,
	// ADR-0010 §4); empty for host actions.
	Description string
	Effect      string
	Risk        string
	Approval    string
	Permission  string
	Parameters  json.RawMessage
}

// Runner executes one tool call through the host operation path. The host
// wires the production implementation to operations.Run (internal/controller
// or a later integration step); this package only defines the contract and a
// fake for tests.
type Runner interface {
	RunTool(ctx context.Context, call ToolCall) (ToolResult, error)
}

// RunnerFunc adapts a function to Runner.
type RunnerFunc func(ctx context.Context, call ToolCall) (ToolResult, error)

// RunTool implements Runner.
func (f RunnerFunc) RunTool(ctx context.Context, call ToolCall) (ToolResult, error) {
	return f(ctx, call)
}

// ApprovalDecision is the host's answer to an approval a session asked for.
// Status is the final state of the tool call (typically succeeded, failed or
// rejected); Result carries the operation outcome when the host executed it.
type ApprovalDecision struct {
	Decision string // approve | reject
	Comment  string
	Status   ToolStatus
	Result   json.RawMessage
	Error    *problem.Error
}

// Approval decision values.
const (
	DecisionApprove = "approve"
	DecisionReject  = "reject"
)

// ApprovalBridge lets a paused session learn the human decision on an approval.
// The host wires it to the operation manager (the only component that may see
// an approval); this package never decides one. A nil bridge leaves a paused
// session waiting until the user sends a new message or cancels.
type ApprovalBridge interface {
	Wait(ctx context.Context, approvalID string) (ApprovalDecision, error)
}

// ApprovalCanceller withdraws the host operation behind an approval the session
// no longer waits for. A bridge may implement it; without it the approval card
// stays decidable. An operation that already ended answers STATE_CONFLICT.
type ApprovalCanceller interface {
	CancelApproval(ctx context.Context, owner actor.Actor, sessionID, operationID, reason string) error
}

// Turn is what a Core receives for one run. Messages is the recent history in
// chronological order and already sanitized for tool-call pairing; Tools is
// the catalog filtered by the permission mode.
type Turn struct {
	SessionID      string
	PermissionMode operations.PermissionMode
	Messages       []Message
	Tools          []ToolSpec
	Config         json.RawMessage
	// APIKeyRef is the session's API key reference, "" without a key. Only the
	// native core resolves it, with secrets.RevealOwned under the session's own
	// namespace, so it can never open another secret; a core never forwards it.
	APIKeyRef secrets.Ref
	// Runner executes the calls the core proposes; a nil Runner makes the core
	// answer UNAVAILABLE.
	Runner Runner
	// NextCallID mints the identifier of a proposed call. The service supplies
	// it so calls are unique within the host.
	NextCallID func() string
}

// Emit publishes one event. The service persists what the event implies and
// fans it out to SSE subscribers; an error aborts the turn.
type Emit func(Event) error

// Core is one replaceable agent backend (docs/design/agent-sessions.md §4).
type Core interface {
	Name() string
	Run(ctx context.Context, turn Turn, emit Emit) error
}

// ErrWaitingApproval is returned by a Core after it emitted approval_required
// and the runner needs a human decision. The session then pauses instead of
// treating the turn as failed.
var ErrWaitingApproval = errors.New("agentsession: waiting for an approval decision")

// Event types (docs/design/agent-sessions.md §5).
const (
	EventMessageDelta     = "message.delta"
	EventMessageCompleted = "message.completed"
	EventToolCall         = "tool_call"
	EventToolResult       = "tool_result"
	EventApprovalRequired = "approval_required"
	EventApprovalDecided  = "approval_decided"
	EventTurnCompleted    = "turn.completed"
	EventError            = "error"
)

// Event is one session event. It is published as the `data:` line of an SSE
// frame whose `id:` is Seq.
type Event struct {
	Type        string          `json:"type"`
	Seq         int64           `json:"seq"`
	SessionID   string          `json:"session_id,omitempty"`
	MessageID   string          `json:"message_id,omitempty"`
	Delta       string          `json:"delta,omitempty"`
	CallID      string          `json:"call_id,omitempty"`
	Action      string          `json:"action,omitempty"`
	Args        json.RawMessage `json:"args,omitempty"`
	Risk        string          `json:"risk,omitempty"`
	Approval    string          `json:"approval,omitempty"`
	Status      string          `json:"status,omitempty"`
	Result      json.RawMessage `json:"result,omitempty"`
	Error       *ErrorInfo      `json:"error,omitempty"`
	ApprovalID  string          `json:"approval_id,omitempty"`
	OperationID string          `json:"operation_id,omitempty"`
	Summary     string          `json:"summary,omitempty"`
	Description string          `json:"description,omitempty"`
	Deadline    *time.Time      `json:"deadline,omitempty"`
	Decision    string          `json:"decision,omitempty"`
	Comment     string          `json:"comment,omitempty"`
	Code        string          `json:"code,omitempty"`
	Detail      string          `json:"detail,omitempty"`
	// ToolCalls accompanies message.completed for an assistant message that
	// proposes calls; it is how the history keeps the model context valid.
	ToolCalls []MessageToolCall `json:"tool_calls,omitempty"`
	At        time.Time         `json:"at,omitempty"`
}

// SessionPage is one page of the session list (OpenAPI AgentSessionList).
type SessionPage struct {
	Items      []Session `json:"items"`
	NextCursor string    `json:"next_cursor,omitempty"`
	Revision   string    `json:"revision"`
	Delta      bool      `json:"delta"`
	DeletedIDs []string  `json:"-"`
}

// ListFilter filters the session list. Status is a Status, StatusAttention, or
// empty for every session.
type ListFilter struct {
	Status        string
	SinceRevision string
	Cursor        string
	Limit         int
}

// CreateRequest is the body of POST /api/v1/agent-sessions.
type CreateRequest struct {
	Title          string
	Core           CoreName
	PermissionMode operations.PermissionMode
	Config         json.RawMessage
}

// UpdateRequest is the body of PATCH /api/v1/agent-sessions/{id}.
type UpdateRequest struct {
	Title            *string
	PermissionMode   operations.PermissionMode
	ExpectedRevision string
}

// SendRequest is the body of POST /api/v1/agent-sessions/{id}/messages.
type SendRequest struct {
	Content         string
	ClientMessageID string
}

// SendResult is the answer of a Send: the persisted user message and the
// session state right after the turn was started.
type SendResult struct {
	Session Session `json:"session"`
	Message Message `json:"message"`
}
