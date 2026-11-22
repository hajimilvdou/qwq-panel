// SPDX-License-Identifier: AGPL-3.0-only

package operations

import (
	"encoding/json"
	"time"

	"github.com/qwq-panel/qwq/internal/actor"
	"github.com/qwq-panel/qwq/internal/platform/problem"
)

// Status is the operation lifecycle state (ADR-0004 D7).
type Status string

// States, in the order of the ADR-0004 D7 diagram.
const (
	Pending          Status = "PENDING"
	AwaitingApproval Status = "AWAITING_APPROVAL"
	Approved         Status = "APPROVED"
	Rejected         Status = "REJECTED"
	Expired          Status = "EXPIRED"
	Running          Status = "RUNNING"
	Succeeded        Status = "SUCCEEDED"
	Failed           Status = "FAILED"
	Canceled         Status = "CANCELED"
)

// Valid reports whether s is a known state.
func (s Status) Valid() bool {
	switch s {
	case Pending, AwaitingApproval, Approved, Rejected, Expired, Running, Succeeded, Failed, Canceled:
		return true
	}
	return false
}

// String returns the wire value.
func (s Status) String() string { return string(s) }

// allowedTransition is the ADR-0004 D7 state machine. Anything else is a
// STATE_CONFLICT.
func allowedTransition(from, to Status) bool {
	switch from {
	case Pending:
		return to == AwaitingApproval || to == Running || to == Canceled || to == Failed
	case AwaitingApproval:
		return to == Approved || to == Rejected || to == Expired || to == Canceled
	case Approved:
		return to == Running || to == Canceled || to == Failed
	case Running:
		return to == Succeeded || to == Failed || to == Canceled
	}
	return false
}

// Target says where an action runs (OpenAPI Target).
type Target struct {
	NodeID     string `json:"node_id,omitempty"`
	PluginID   string `json:"plugin_id,omitempty"`
	InstanceID string `json:"instance_id,omitempty"`
	Subject    string `json:"subject,omitempty"`
}

// Progress is the latest progress report of a job (OpenAPI OperationProgress
// plus the step position of proto JobProgress, ADR-0007 #9).
type Progress struct {
	Percent   *int   `json:"percent,omitempty"`
	Step      string `json:"step,omitempty"`
	StepIndex int    `json:"step_index,omitempty"`
	StepCount int    `json:"step_count,omitempty"`
	Message   string `json:"message,omitempty"`
}

// Operation is the unified record of a state change (OpenAPI Operation). The
// unexported execution state is not part of the public schema; it is loaded so
// that an operation can be re-executed after a plan or an approval without
// consulting the catalog again.
type Operation struct {
	ID                string           `json:"operation_id"`
	Action            string           `json:"action"`
	Status            Status           `json:"status"`
	Target            Target           `json:"target"`
	Actor             actor.Actor      `json:"actor"`
	EffectiveRisk     string           `json:"effective_risk"`
	PlanID            string           `json:"plan_id,omitempty"`
	ApprovalID        string           `json:"approval_id,omitempty"`
	ParentOperationID string           `json:"parent_operation_id,omitempty"`
	Attempt           int              `json:"attempt"`
	CancelRequested   bool             `json:"cancel_requested,omitempty"`
	Progress          *Progress        `json:"progress,omitempty"`
	Result            json.RawMessage  `json:"result,omitempty"`
	Error             *problem.Problem `json:"error,omitempty"`
	UIRoute           string           `json:"ui_route,omitempty"`
	CreatedAt         time.Time        `json:"created_at"`
	UpdatedAt         time.Time        `json:"updated_at"`
	FinishedAt        *time.Time       `json:"finished_at,omitempty"`
	Revision          string           `json:"revision"`

	// Execution state, private to this package.
	Meta             Action          `json:"-"`
	Args             json.RawMessage `json:"-"`
	ArgsDigest       string          `json:"-"`
	ExpectedRevision string          `json:"-"`
	Preconditions    []Precondition  `json:"-"`
	Permission       string          `json:"-"`
	DeclaredRisk     string          `json:"-"`
	Effect           string          `json:"-"`
	Mode             string          `json:"-"`
	Idempotent       bool            `json:"-"`
	Timeout          time.Duration   `json:"-"`
	RequestID        string          `json:"-"`
	TraceID          string          `json:"-"`
	NodeID           string          `json:"-"`
	StartedAt        *time.Time      `json:"-"`
	// PermissionMode is the caller's mode at creation; a child operation
	// inherits it (ADR-0011 §5). Empty (rows before the column) means safe.
	PermissionMode PermissionMode `json:"-"`
	// invokedBy is the calling plugin of a plugin-to-plugin child; it is
	// written to the creation audit row only.
	invokedBy *PluginInstanceRef
}

// PluginInstanceRef names the plugin instance that asked for a child
// operation. The host fills it from the caller's verified identity.
type PluginInstanceRef struct {
	PluginID   string `json:"plugin_id"`
	InstanceID string `json:"instance_id"`
}

// Outcome is the compact view of an operation for synchronous answers and agent
// tools (OpenAPI OperationOutcome).
type Outcome struct {
	OperationID     string           `json:"operation_id"`
	Action          string           `json:"action"`
	Status          Status           `json:"status"`
	EffectiveRisk   string           `json:"effective_risk,omitempty"`
	ApprovalID      string           `json:"approval_id,omitempty"`
	CancelRequested bool             `json:"cancel_requested,omitempty"`
	Progress        *Progress        `json:"progress,omitempty"`
	Result          json.RawMessage  `json:"result,omitempty"`
	Error           *problem.Problem `json:"error,omitempty"`
	TimedOut        bool             `json:"timed_out,omitempty"`
	Revision        string           `json:"revision"`
}

// Outcome renders the compact view of op.
func (op *Operation) Outcome() *Outcome {
	if op == nil {
		return nil
	}
	return &Outcome{
		OperationID:     op.ID,
		Action:          op.Action,
		Status:          op.Status,
		EffectiveRisk:   op.EffectiveRisk,
		ApprovalID:      op.ApprovalID,
		CancelRequested: op.CancelRequested,
		Progress:        op.Progress,
		Result:          op.Result,
		Error:           op.Error,
		Revision:        op.Revision,
	}
}

// PlannedChange is one change a plan would make (OpenAPI PlannedChange, proto
// PlannedChange). Kind is create, update or delete; Description is the plugin's
// one-line text for the confirmation card (ADR-0007 #10) and is not part of the
// published OpenAPI schema yet.
type PlannedChange struct {
	Kind        string          `json:"kind"`
	Subject     string          `json:"subject"`
	Pointer     string          `json:"pointer,omitempty"`
	Before      json.RawMessage `json:"before,omitempty"`
	After       json.RawMessage `json:"after,omitempty"`
	Reversible  bool            `json:"reversible"`
	Source      string          `json:"source"`
	PluginID    string          `json:"plugin_id,omitempty"`
	Description string          `json:"description,omitempty"`
}

// Precondition is one revision that must still hold at execution (OpenAPI
// Precondition, proto Precondition). Plugin-side entries carry relative
// subjects.
type Precondition struct {
	Subject  string `json:"subject"`
	Revision string `json:"revision"`
}

// Plan is a side-effect free preview bound to a later execution (OpenAPI Plan,
// ADR-0004 D7).
type Plan struct {
	ID               string              `json:"plan_id"`
	Action           string              `json:"action"`
	Target           Target              `json:"target"`
	Args             json.RawMessage     `json:"args,omitempty"`
	ArgsDigest       string              `json:"args_digest"`
	Plannable        bool                `json:"plannable"`
	Changes          []PlannedChange     `json:"changes"`
	ChangesTruncated bool                `json:"changes_truncated,omitempty"`
	Violations       []problem.Violation `json:"violations"`
	Warnings         []problem.Violation `json:"warnings"`
	Preconditions    []Precondition      `json:"preconditions"`
	EffectiveRisk    string              `json:"effective_risk"`
	RequiresApproval bool                `json:"requires_approval"`
	RequiresMFA      bool                `json:"requires_mfa,omitempty"`
	Executable       bool                `json:"executable"`
	OperationID      string              `json:"operation_id,omitempty"`
	CreatedAt        time.Time           `json:"created_at"`
	ExpiresAt        time.Time           `json:"expires_at"`
	Revision         string              `json:"revision"`

	// Private to this package: the relative plugin-side preconditions and the
	// principal that owns the plan.
	PluginPreconditions []Precondition `json:"-"`
	Meta                Action         `json:"-"`
	Owner               actor.Actor    `json:"-"`
	RequestID           string         `json:"-"`
	TraceID             string         `json:"-"`
}

// ApprovalStatus is the state of one approval request (OpenAPI ApprovalStatus).
type ApprovalStatus string

// Approval states.
const (
	ApprovalPending  ApprovalStatus = "PENDING"
	ApprovalApproved ApprovalStatus = "APPROVED"
	ApprovalRejected ApprovalStatus = "REJECTED"
	ApprovalExpired  ApprovalStatus = "EXPIRED"
	ApprovalCanceled ApprovalStatus = "CANCELED"
)

// actionMeta is the ActionMeta schema of the public API: the catalog metadata
// of an action as stored in approval facts. Risk is the effective risk, and
// Approval is the level that governs the operation (declared, or derived from
// the effect for a plugin operation; empty for host actions).
type actionMeta struct {
	ID                  string `json:"id"`
	Summary             string `json:"summary"`
	Effect              string `json:"effect"`
	Risk                string `json:"risk"`
	DeclaredRisk        string `json:"declared_risk"`
	Mode                string `json:"mode"`
	Idempotent          bool   `json:"idempotent"`
	Plannable           bool   `json:"plannable"`
	Undo                string `json:"undo,omitempty"`
	UIRoute             string `json:"ui_route,omitempty"`
	Permission          string `json:"permission,omitempty"`
	TimeoutMS           int    `json:"timeout_ms,omitempty"`
	Source              Source `json:"source"`
	PluginID            string `json:"plugin_id,omitempty"`
	Placement           string `json:"placement,omitempty"`
	Approval            string `json:"approval,omitempty"`
	ApprovalSummary     string `json:"approval_summary,omitempty"`
	ApprovalDescription string `json:"approval_description,omitempty"`
	// Reachability: the action can cut the administrator off (ADR-0016).
	Reachability bool `json:"reachability,omitempty"`
}

func (a Action) meta(effectiveRisk string) actionMeta {
	return actionMeta{
		ID: a.ID, Summary: a.Summary, Effect: a.Effect, Risk: effectiveRisk, DeclaredRisk: a.Risk,
		Mode: a.Mode, Idempotent: a.Idempotent, Plannable: a.Plannable, Undo: a.Undo,
		UIRoute: a.UIRoute, Permission: a.Permission, TimeoutMS: a.TimeoutMS,
		Source: a.Source, PluginID: a.PluginID, Placement: a.Placement,
		Approval: a.ApprovalLevel(), ApprovalSummary: a.ApprovalSummary,
		ApprovalDescription: a.ApprovalDescription, Reachability: a.Reachability,
	}
}

// ApprovalFacts is what the host knows about an operation on its own; it is
// rendered first on the confirmation card (OpenAPI ApprovalFacts, ADR-0004 D6).
// ApprovalSummary and ApprovalDescription are the plugin author's text for the
// card, kept here as well so the UI can render the "from plugin" block without
// reaching into the action metadata; both are empty for host actions.
type ApprovalFacts struct {
	Action               actionMeta      `json:"action"`
	Args                 json.RawMessage `json:"args"`
	ArgsDigest           string          `json:"args_digest,omitempty"`
	Target               Target          `json:"target"`
	NodeName             string          `json:"node_name,omitempty"`
	RequiredCapabilities []Capability    `json:"required_capabilities"`
	Effect               string          `json:"effect"`
	DeclaredRisk         string          `json:"declared_risk"`
	EffectiveRisk        string          `json:"effective_risk"`
	Reversible           bool            `json:"reversible"`
	Undo                 string          `json:"undo,omitempty"`
	RequestedBy          actor.Actor     `json:"requested_by"`
	ApprovalSummary      string          `json:"approval_summary,omitempty"`
	ApprovalDescription  string          `json:"approval_description,omitempty"`
	// PermissionMode is the mode the calling session or delegation ran with
	// (ADR-0010 §2.1), so the approver can see why the decision was asked for.
	PermissionMode PermissionMode `json:"permission_mode,omitempty"`
}

// PluginPreview is the untrusted part of a plan, shown as "from plugin".
type PluginPreview struct {
	Changes  []PlannedChange     `json:"changes"`
	Warnings []problem.Violation `json:"warnings"`
}

// Approval is a request for a human decision on one operation (OpenAPI
// Approval).
type Approval struct {
	ID            string         `json:"approval_id"`
	OperationID   string         `json:"operation_id"`
	PlanID        string         `json:"plan_id,omitempty"`
	Status        ApprovalStatus `json:"status"`
	Facts         ApprovalFacts  `json:"facts"`
	PluginPreview *PluginPreview `json:"plugin_preview,omitempty"`
	RequiresMFA   bool           `json:"requires_mfa"`
	DecidedBy     *actor.Actor   `json:"decided_by,omitempty"`
	DecidedAt     *time.Time     `json:"decided_at,omitempty"`
	Comment       string         `json:"comment,omitempty"`
	CreatedAt     time.Time      `json:"created_at"`
	ExpiresAt     time.Time      `json:"expires_at"`
	Revision      string         `json:"revision"`
}

// ListFilter filters operations (OpenAPI listOperations parameters).
type ListFilter struct {
	Statuses      []Status
	ActorKind     actor.Kind
	NodeID        string
	PluginID      string
	SinceRevision string
	Cursor        string
	Limit         int
}

// OperationPage is one page of operations (OpenAPI OperationList + ListMeta).
type OperationPage struct {
	Items      []Operation `json:"items"`
	NextCursor string      `json:"next_cursor,omitempty"`
	Revision   string      `json:"revision"`
	Delta      bool        `json:"delta"`
	DeletedIDs []string    `json:"deleted_ids,omitempty"`
}

// ApprovalFilter filters approvals (OpenAPI listApprovals parameters).
type ApprovalFilter struct {
	Status        ApprovalStatus // default PENDING
	SinceRevision string
	Cursor        string
	Limit         int
}

// ApprovalPage is one page of approvals (OpenAPI ApprovalList).
type ApprovalPage struct {
	Items      []Approval `json:"items"`
	NextCursor string     `json:"next_cursor,omitempty"`
	Revision   string     `json:"revision"`
	Delta      bool       `json:"delta"`
	DeletedIDs []string   `json:"deleted_ids,omitempty"`
}

// Response is the HTTP-shaped outcome of a mutating call. Body is the exact
// JSON that was sent (or will be sent) for this request, so an idempotent
// replay returns the original response; Status is the suggested HTTP status.
// When Replayed is true the caller must send Status and Body as they are.
type Response struct {
	Status      int
	Body        json.RawMessage
	Replayed    bool
	OperationID string
	Operation   *Operation
	Outcome     *Outcome
	Approval    *Approval
}

// Idempotency identifies a mutating request (OpenAPI Idempotency-Key). Scope is
// principal + Method + Route. Fingerprint may be supplied by the gateway (a
// digest of the raw body plus the sorted query); when empty the package derives
// one from the canonical request it is about to perform.
type Idempotency struct {
	Key         string
	Method      string
	Route       string
	Fingerprint string
}
