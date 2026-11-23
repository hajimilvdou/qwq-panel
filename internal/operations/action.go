// SPDX-License-Identifier: AGPL-3.0-only

package operations

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/qwq-panel/qwq/internal/actor"
	"github.com/qwq-panel/qwq/internal/platform/problem"
	"github.com/qwq-panel/qwq/internal/storage"
)

// Source says whether an action is defined by the host or by a plugin.
type Source string

const (
	HostSource   Source = "host"
	PluginSource Source = "plugin"
)

// Effects (OpenAPI Effect, proto OperationEffect).
const (
	EffectRead        = "read"
	EffectWrite       = "write"
	EffectDestructive = "destructive"
)

// Risk levels (OpenAPI RiskLevel, proto RiskLevel).
const (
	RiskLow    = "low"
	RiskMedium = "medium"
	RiskHigh   = "high"
)

// Modes (OpenAPI Mode, proto OperationMode).
const (
	ModeInvoke = "invoke"
	ModeJob    = "job"
)

// Approval levels a plugin operation may declare (OpenAPI ApprovalLevel,
// ADR-0010 §2). The empty value means the author declared none.
const (
	// ApprovalAuto asks for nothing beyond the host's own hard rules.
	ApprovalAuto = "auto"
	// ApprovalConfirm asks for a human decision on every call.
	ApprovalConfirm = "confirm"
	// ApprovalAIConfirm asks for a human decision only when an AI agent or a
	// delegation calls the operation.
	ApprovalAIConfirm = "ai_confirm"
)

// placements of a plugin action (ADR-0002).
const (
	PlacementNode       = "node"
	PlacementController = "controller"
)

// Capability is one capability an action may use (proto Capability).
type Capability struct {
	Name  string `json:"name"`
	Scope string `json:"scope"`
}

// Action is the catalog metadata of one action (ADR-0004 D5). It is the same
// information the public ActionMeta schema and the plugin manifest carry; Risk
// is the declared risk, EffectiveRisk applies the capability floor.
type Action struct {
	ID           string       `json:"id"`
	Summary      string       `json:"summary"`
	Effect       string       `json:"effect"`
	Risk         string       `json:"risk"`
	Mode         string       `json:"mode"`
	Idempotent   bool         `json:"idempotent"`
	Plannable    bool         `json:"plannable"`
	Capabilities []Capability `json:"capabilities,omitempty"`
	Undo         string       `json:"undo,omitempty"`
	UIRoute      string       `json:"ui_route,omitempty"`
	Permission   string       `json:"permission,omitempty"`
	TimeoutMS    int          `json:"timeout_ms,omitempty"`
	Source       Source       `json:"source"`
	PluginID     string       `json:"plugin_id,omitempty"`
	Placement    string       `json:"placement,omitempty"`
	Operation    string       `json:"operation,omitempty"`
	APIVersion   string       `json:"api_version,omitempty"`

	// Approval is the level the plugin declared for this operation, or "" when
	// it declared none (ADR-0010 §1). ApprovalSummary and ApprovalDescription
	// are the confirmation-card title and body written by the plugin author;
	// both are untrusted text and empty for host actions.
	Approval            string `json:"approval,omitempty"`
	ApprovalSummary     string `json:"approval_summary,omitempty"`
	ApprovalDescription string `json:"approval_description,omitempty"`

	// Reachability marks an action that can cut the administrator off from the
	// server or the panel (ADR-0016). It is the manifest declaration, the
	// capability-derived forcing, or the x-qwq-reachability extension of a host
	// route; EffectiveRisk and ApprovalLevel apply the floor it implies.
	Reachability bool `json:"reachability,omitempty"`

	// ArgsSchema 是插件的请求 schema；Run 在创建时先校验参数。仅声明了操作级
	// 秘密能力的 operation/plan 保存私有快照，以便派发时核验原敏感字段成员；
	// 公开 Action JSON 始终不输出它，也不在派发时改用当前目录的 schema。
	ArgsSchema json.RawMessage `json:"-"`
}

// normalized returns a copy with the defaults of the catalog applied. Unknown
// values stay as they are so that the caller sees a validation error instead of
// a silently downgraded risk.
func (a Action) normalized(defaultTimeout time.Duration) Action {
	if a.Effect == "" {
		a.Effect = EffectWrite
	}
	if a.Risk == "" {
		// Missing risk metadata must never look harmless (ADR-0004 D6).
		a.Risk = RiskMedium
	}
	if a.Mode == "" {
		a.Mode = ModeInvoke
	}
	if a.Source == "" {
		a.Source = HostSource
	}
	if a.TimeoutMS <= 0 {
		a.TimeoutMS = int(defaultTimeout / time.Millisecond)
	}
	return a
}

// Timeout is the execution deadline of the action.
func (a Action) Timeout(fallback time.Duration) time.Duration {
	if a.TimeoutMS <= 0 {
		return fallback
	}
	return time.Duration(a.TimeoutMS) * time.Millisecond
}

// EffectiveRisk is max(declared risk, capability floor, destructive=high,
// reachability floor=high) (ADR-0004 D6, ADR-0007 #4, ADR-0016).
func (a Action) EffectiveRisk() string {
	r := riskRank(RiskFloor(a.Risk, a.Effect, a.Capabilities))
	if a.Reachability {
		r = max(r, riskRank(RiskHigh))
	}
	return riskLevel(r)
}

// ApprovalLevel returns the level that governs the operation: the declared one,
// the ADR-0010 §2 default derived from the effect when a plugin declared none,
// or "" for a host action, which keeps the host's own risk rule. An unknown
// declared value falls back to the derived level, so a typo can never make an
// operation quieter than its effect implies. A reachability action is at least
// ai_confirm (ADR-0016): the plugin cannot declare it below the floor.
func (a Action) ApprovalLevel() string {
	level := ""
	switch a.Approval {
	case ApprovalAuto, ApprovalConfirm, ApprovalAIConfirm:
		level = a.Approval
	default:
		if a.Source == PluginSource {
			level = derivedApproval(a.Effect)
		}
	}
	if a.Reachability && approvalRank(level) < approvalRank(ApprovalAIConfirm) {
		return ApprovalAIConfirm
	}
	return level
}

// approvalRank orders the approval levels by how much they ask: auto asks
// nothing beyond the host rules, ai_confirm asks an AI caller, confirm asks
// every call. "" (a host action's own policy) ranks below auto, so the
// reachability floor raises it too.
func approvalRank(level string) int {
	switch level {
	case ApprovalConfirm:
		return 3
	case ApprovalAIConfirm:
		return 2
	case ApprovalAuto:
		return 1
	default:
		return 0
	}
}

// derivedApproval is the ADR-0010 §2 default: read → auto, write and
// destructive → confirm.
func derivedApproval(effect string) string {
	if effect == EffectRead {
		return ApprovalAuto
	}
	return ApprovalConfirm
}

// validate rejects metadata a catalog must not produce.
func (a Action) validate() error {
	if a.ID == "" {
		return fmt.Errorf("operations: action without id")
	}
	switch a.Effect {
	case EffectRead, EffectWrite, EffectDestructive:
	default:
		return fmt.Errorf("operations: action %q has unknown effect %q", a.ID, a.Effect)
	}
	switch a.Risk {
	case RiskLow, RiskMedium, RiskHigh:
	default:
		return fmt.Errorf("operations: action %q has unknown risk %q", a.ID, a.Risk)
	}
	switch a.Mode {
	case ModeInvoke, ModeJob:
	default:
		return fmt.Errorf("operations: action %q has unknown mode %q", a.ID, a.Mode)
	}
	switch a.Source {
	case HostSource:
		if a.PluginID != "" || a.Operation != "" || a.Placement != "" {
			return fmt.Errorf("operations: host action %q carries plugin fields", a.ID)
		}
		// mode=invoke runs a HostHandler inside the write transaction
		// (ADR-0008 §3); mode=job runs a HostJobHandler on a worker outside any
		// transaction, for work that owns its transactions and talks to the
		// system (the plugin uninstall of GAPS gap 7).
	case PluginSource:
		if a.PluginID == "" || a.Operation == "" {
			return fmt.Errorf("operations: plugin action %q needs plugin_id and operation", a.ID)
		}
		switch a.Placement {
		case PlacementNode, PlacementController:
		default:
			return fmt.Errorf("operations: plugin action %q has unknown placement %q", a.ID, a.Placement)
		}
	default:
		return fmt.Errorf("operations: action %q has unknown source %q", a.ID, a.Source)
	}
	if a.TimeoutMS < 0 || a.TimeoutMS > maxTimeoutMS {
		return fmt.Errorf("operations: action %q has timeout outside 1..%d ms", a.ID, maxTimeoutMS)
	}
	switch a.Approval {
	case "", ApprovalAuto, ApprovalConfirm, ApprovalAIConfirm:
	default:
		return fmt.Errorf("operations: action %q has unknown approval %q", a.ID, a.Approval)
	}
	return nil
}

// maxTimeoutMS is the cap of the public ActionMeta schema.
const maxTimeoutMS = 300000

// RiskFloor returns the effective risk from a declared risk, the action's
// effect and the capabilities it may use. It has the same shape as
// catalog.RiskFloor so the catalog can display the number this package enforces
// (ADR-0004 D6).
func RiskFloor(declared, effect string, caps []Capability) string {
	r := riskRank(declared)
	if effect == EffectDestructive {
		r = max(r, riskRank(RiskHigh))
	}
	for _, c := range caps {
		r = max(r, riskRank(capabilityFloor(c.Name)))
	}
	return riskLevel(r)
}

// capabilityFloor is the lowest risk of an action that uses a capability
// (ADR-0004 D6). Unknown capabilities are medium: a plugin cannot lower its
// risk by inventing a name that looks harmless (ADR-0007 #4).
func capabilityFloor(name string) string {
	switch {
	case name == "secret.reveal", strings.HasPrefix(name, "secret.reveal."):
		return RiskHigh
	case name == "network.egress", strings.HasPrefix(name, "network.egress."):
		return RiskHigh
	case name == "network.proxy", strings.HasPrefix(name, "network.proxy."):
		// Opening the host network namespace to a plugin data plane is high
		// sensitivity: the install wizard gives it a consent line. This is the
		// risk floor only; it does not make the operation reachability-changing
		// (a proxy data plane does not cut the management channel), so
		// ReachabilityCapabilityPrefixes is deliberately unchanged.
		return RiskHigh
	case name == "network.listen", strings.HasPrefix(name, "network.listen."):
		return RiskHigh
	case name == "tls.consume", strings.HasPrefix(name, "tls.consume."):
		return RiskHigh
	case strings.HasPrefix(name, "system."):
		return RiskHigh
	case strings.HasPrefix(name, "state."):
		return RiskLow
	case strings.HasPrefix(name, "events."):
		return RiskLow
	case name == "metrics.read", strings.HasPrefix(name, "metrics.read."):
		return RiskLow
	default:
		return RiskMedium
	}
}

// CapabilitySensitive reports whether a capability needs its own consent line
// in the install wizard (ARCH §10.3 高敏): the high-sensitivity capabilities
// are exactly those whose use pins an action's risk floor at high, so the
// wizard and the runtime agree on what is dangerous.
func CapabilitySensitive(name string) bool {
	return capabilityFloor(name) == RiskHigh
}

// ReachabilityCapabilityPrefixes are the capability name families whose use can
// cut the administrator off from the server or the panel (ADR-0016): the host's
// own firewall table, the sshd drop-in, host network configuration, the panel
// listener and its TLS material. They are matched as a name prefix on a dot
// boundary. The list is the single source of the capability-derived forcing;
// the reachability ADR enumerates it.
var ReachabilityCapabilityPrefixes = []string{
	"system.firewall",
	"system.sshd",
	"system.account",
	"system.ban",
	"system.network",
	"system.panel",
	"system.tls",
}

// ForcedReachability reports whether an operation must be treated as
// reachability-changing even without a manifest declaration (ADR-0016): it is
// not a read and it may use a lockout capability. A read cannot cut anyone off,
// so it never forces the flag.
func ForcedReachability(effect string, caps []Capability) bool {
	if effect == EffectRead {
		return false
	}
	for _, c := range caps {
		for _, prefix := range ReachabilityCapabilityPrefixes {
			if c.Name == prefix || strings.HasPrefix(c.Name, prefix+".") {
				return true
			}
		}
	}
	return false
}

func riskRank(risk string) int {
	switch risk {
	case RiskLow:
		return 1
	case RiskMedium:
		return 2
	case RiskHigh:
		return 3
	default:
		// An unknown or missing level is medium: metadata mistakes must never
		// look harmless (ADR-0004 D6).
		return 2
	}
}

func riskLevel(rank int) string {
	switch {
	case rank <= 1:
		return RiskLow
	case rank == 2:
		return RiskMedium
	default:
		return RiskHigh
	}
}

// NeedsApproval reports whether an operation with this effective risk must wait
// for a human decision (ADR-0004 D6). read actions never do.
func (l Limits) NeedsApproval(effect, effectiveRisk string) bool {
	if effect == EffectRead {
		return false
	}
	switch l.AutoApproveMaxRisk {
	case AutoApproveNone:
		return true
	case RiskMedium:
		return riskRank(effectiveRisk) > riskRank(RiskMedium)
	case RiskHigh:
		return false
	default:
		// Empty or unknown means the ADR default: low risk runs.
		return riskRank(effectiveRisk) > riskRank(RiskLow)
	}
}

// Approval policy values (OpenAPI DelegationPolicy).
const (
	AutoApproveNone = "none"
	ApprovalQueue   = "queue"
	ApprovalFail    = "fail"
)

// Limits is the part of the caller's policy that decides whether an action may
// run at all and whether it needs approval. It is derived from the delegation
// policy for AI agents and from the user's role for people.
type Limits struct {
	// MaxRisk is the highest effective risk the caller may use; empty is no cap.
	MaxRisk string
	// AutoApproveMaxRisk is the highest effective risk that runs without
	// approval: none or low (default low).
	AutoApproveMaxRisk string
	// OnApprovalRequired is queue (default) or fail.
	OnApprovalRequired string
	// PermissionMode is the mode of the calling session or delegation
	// (ADR-0010 §2.1); empty means safe. It is never read from a request body,
	// so an AI client cannot widen its own permissions.
	PermissionMode PermissionMode
}

// Mode returns the effective permission mode: safe when unset or unknown.
func (l Limits) Mode() PermissionMode { return l.PermissionMode.normalized() }

// Catalog resolves action metadata by ID. internal/catalog implements it; the
// adapter lives in internal/controller.
type Catalog interface {
	Action(id string) (Action, bool)
}

// Authorizer decides whether an actor may perform an action with the given
// target: RBAC, delegation policy and service-account grants. It returns nil or
// a *problem.Error (PERMISSION_DENIED, APPROVAL_REQUIRED, MFA_REQUIRED).
// internal/authz implements it.
type Authorizer interface {
	Authorize(ctx context.Context, a actor.Actor, act Action, target Target) error
}

// Policy returns the execution limits of an actor (ADR-0004 D6).
type Policy interface {
	Limits(ctx context.Context, a actor.Actor, act Action, target Target) (Limits, error)
}

// Revisions resolves the current revision of a host resource by its full
// subject (ADR-0008 §4). The package that owns the resource implements it; nil
// means host-side preconditions cannot be checked by this package and the host
// action must check them itself.
type Revisions interface {
	// CurrentRevision returns "" when the resource does not exist.
	CurrentRevision(ctx context.Context, tx *storage.Tx, subject string) (string, error)
}

// HostHandler executes a host action inside the operation's write transaction
// (ADR-0008 §2, §3). It must call tx.Changed for every resource it modifies and
// must not call plugins or the network.
type HostHandler func(ctx context.Context, tx *storage.Tx, req HostRequest) (json.RawMessage, error)

// HostJobHandler executes a mode=job host action on a job worker, outside any
// database transaction. It exists for work that owns its own transactions and
// talks to the system (the plugin uninstall of GAPS gap 7): holding the write
// transaction across a systemd call would block every other writer. It must
// still be idempotent — a crash leaves the operation PENDING/RUNNING and the
// next start runs it again — and must record its own resource.changed events.
type HostJobHandler func(ctx context.Context, req HostRequest) (json.RawMessage, error)

// HostPlanner previews a host action inside a read transaction. Returning an
// error fails the plan request; validation problems belong in Violations.
type HostPlanner func(ctx context.Context, tx *sql.Tx, req HostRequest) (Preview, error)

// HostRequest is what a host action sees about its operation.
type HostRequest struct {
	Actor            actor.Actor
	OperationID      string
	Attempt          int
	TraceID          string
	RequestID        string
	Locale           string
	Action           Action
	Target           Target
	Args             json.RawMessage
	ExpectedRevision string
	// 当次真人证明只由同步执行器填入；JSON、插件和恢复路径无法构造。
	interactive *interactiveHostSession
}

// Preview is the structured, side-effect free result of planning an action
// (ADR-0004 D7). Preconditions of plugin actions carry relative subjects.
type Preview struct {
	Changes       []PlannedChange
	Violations    []problem.Violation
	Warnings      []problem.Violation
	Preconditions []Precondition
}

// Dispatcher hands an operation to a plugin instance (ADR-0008 §8). P1 uses a
// fake; P2 replaces it with the Supervisor. Every call happens outside a host
// write transaction.
type Dispatcher interface {
	// Plan previews an operation without side effects.
	Plan(ctx context.Context, req PluginPlanRequest) (Preview, error)
	// Invoke runs a mode=invoke operation and returns its result and the
	// plugin-owned resources it changed.
	Invoke(ctx context.Context, req PluginInvokeRequest) (PluginInvokeResponse, error)
	// RunJob runs a mode=job operation. The dispatcher sends zero or more
	// progress reports on progress and exactly one terminal one, sequentially
	// from one goroutine, and returns after that. Cancellation, timeout and a
	// broken stream cancel ctx (ADR-0007 #15); a plugin-reported failure is
	// returned as an error carrying *problem.Error. A non-nil error returned by
	// progress aborts the job and is returned as is.
	RunJob(ctx context.Context, req PluginRunJobRequest, progress func(JobProgress) error) error
	// Cancel asks a running job to stop. It is best effort: the job still ends
	// when the stream returns or the context ends.
	Cancel(ctx context.Context, req PluginCancelRequest) error
}

// PluginPlanRequest is one PlanOperation call.
type PluginPlanRequest struct {
	Actor       actor.Actor
	OperationID string
	TraceID     string
	RequestID   string
	Locale      string
	NodeID      string
	PluginID    string
	InstanceID  string
	Placement   string
	Operation   string
	APIVersion  string
	Payload     json.RawMessage
}

// PluginInvokeRequest is one InvokeRequest call.
type PluginInvokeRequest struct {
	Actor         actor.Actor
	OperationID   string
	Attempt       int
	TraceID       string
	RequestID     string
	Locale        string
	NodeID        string
	PluginID      string
	InstanceID    string
	Placement     string
	Operation     string
	APIVersion    string
	Payload       json.RawMessage
	Preconditions []Precondition

	// ParentOperationID is set for a plugin-to-plugin child operation; the
	// dispatcher then only routes to a running target (ADR-0011 §1).
	ParentOperationID string
}

// PluginInvokeResponse is the outcome of Invoke; Changes are plugin-owned
// resources with relative subjects (ADR-0007 #2).
type PluginInvokeResponse struct {
	Result  json.RawMessage
	Changes []ResourceChange
}

// PluginRunJobRequest is one RunJob call.
type PluginRunJobRequest struct {
	Actor         actor.Actor
	OperationID   string
	Attempt       int
	TraceID       string
	RequestID     string
	Locale        string
	NodeID        string
	PluginID      string
	InstanceID    string
	Placement     string
	Operation     string
	APIVersion    string
	Payload       json.RawMessage
	Preconditions []Precondition

	// ParentOperationID is set for a plugin-to-plugin child operation; the
	// dispatcher then only routes to a running target (ADR-0011 §1).
	ParentOperationID string
}

// PluginCancelRequest asks a plugin to stop a running job.
type PluginCancelRequest struct {
	OperationID string
	NodeID      string
	PluginID    string
	InstanceID  string
	Placement   string
	Operation   string
	APIVersion  string
}

// ResourceChange is a change to a plugin-owned resource (proto ResourceChange).
type ResourceChange struct {
	Subject         string // relative subject
	Revision        string // plugin revision; empty when deleted
	ChangedPointers []string
	Deleted         bool
}

// JobProgress is one message of a RunJob stream (proto JobProgress).
type JobProgress struct {
	Percent   *int
	Step      string
	StepIndex int
	StepCount int
	Message   string
	Result    json.RawMessage
	Completed bool
	Error     error
	Changes   []ResourceChange
}

// Notifier is told about operations that finished without approval: ADR-0004
// D6 says low risk runs and then notifies. The gateway implements it; Notify
// must not block.
type Notifier interface {
	Notify(ctx context.Context, op *Operation)
}

// isTerminal reports whether no further transition is possible.
func isTerminal(s Status) bool {
	switch s {
	case Succeeded, Failed, Canceled, Rejected, Expired:
		return true
	}
	return false
}

// validateTarget rejects a target that does not match the action's placement.
func validateTarget(act Action, t Target) error {
	fail := func(msg string, args ...any) error {
		return problem.Validation(problem.Violation{
			Pointer: "/target",
			Code:    "INVALID_TARGET",
			Message: fmt.Sprintf(msg, args...),
		})
	}
	if t.Subject != "" {
		if err := validateFullSubject(t.Subject); err != nil {
			return fail("subject is not a canonical resource name")
		}
	}
	if act.Source == HostSource {
		if t.PluginID != "" || t.InstanceID != "" || t.NodeID != "" {
			return fail("host action %q takes only a subject", act.ID)
		}
		return nil
	}
	if t.PluginID == "" {
		return fail("plugin action %q needs target.plugin_id", act.ID)
	}
	if t.PluginID != act.PluginID {
		return fail("target.plugin_id does not match the action")
	}
	if act.Placement == PlacementNode {
		if t.NodeID == "" {
			return fail("node placement needs target.node_id")
		}
		if t.InstanceID == "" {
			return fail("node placement needs target.instance_id")
		}
	} else {
		if t.InstanceID != "" {
			return fail("controller placement has no instance")
		}
	}
	return nil
}
