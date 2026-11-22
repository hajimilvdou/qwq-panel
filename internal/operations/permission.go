// SPDX-License-Identifier: AGPL-3.0-only

package operations

import (
	"context"
	"fmt"

	"github.com/qwq-panel/qwq/internal/actor"
	"github.com/qwq-panel/qwq/internal/platform/problem"
)

// permissionModeKey is the context key of a session's permission mode.
type permissionModeKey struct{}

// WithPermissionMode returns a context carrying mode. It exists for callers
// whose policy cannot be read from the actor record: an agent session is not a
// delegation, so the session service puts the mode on the context of every tool
// call it makes (ADR-0010 §2.1). The value is decided by the host from the
// session row, never parsed from a request body, so an AI client cannot widen
// its own permissions with it.
func WithPermissionMode(ctx context.Context, mode PermissionMode) context.Context {
	return context.WithValue(ctx, permissionModeKey{}, mode)
}

// PermissionModeFromContext returns the mode stored by WithPermissionMode. The
// second result is false when no mode was set; the caller decides the default
// (safe). Limits.Mode normalizes the value, so an unknown mode still means safe.
func PermissionModeFromContext(ctx context.Context) (PermissionMode, bool) {
	mode, ok := ctx.Value(permissionModeKey{}).(PermissionMode)
	return mode, ok
}

// PermissionMode is the user-selected permission mode of an agent session or a
// delegation (ADR-0010 §2.1). It is a ceiling on what the session may do:
//
//   - a plugin's approval level can never widen it, and an AI client can never
//     change it, because the mode comes from the session/delegation record
//     (through Policy) and is never read from a request body;
//   - the host's hard rules (a destructive effect above all) still apply in
//     every mode, so the mode only ever removes the *plugin-level* and
//     risk-based approvals. It never raises a delegation's MaxRisk cap.
//
// An external CLI agent maps the mode to its own flags, but the host never
// trusts that mapping: the mode of the session/delegation and the rules below
// decide. The planned adapters are Claude Code (plan / default /
// bypassPermissions, per-item allow-deny for custom), Codex (suggest /
// auto-edit / full-auto, per-item approval policy) and opencode (plan / build);
// they belong to the agent plugin (P6) and are not part of this package.
type PermissionMode string

const (
	// PermissionReadOnly allows reads and plans only: a write operation is
	// refused instead of being queued for approval.
	PermissionReadOnly PermissionMode = "read_only"
	// PermissionSafe asks the user for every operation a plugin marked confirm
	// or ai_confirm, every destructive operation and every operation whose
	// effective risk is high. It is the default.
	PermissionSafe PermissionMode = "safe"
	// PermissionFull skips the plugin-level approvals and the high-risk rule.
	// An irreversible destructive operation still asks, and so do the host's
	// own panel/SSH lockout guards (ADR-0009); none of the latter exist yet.
	PermissionFull PermissionMode = "full"
	// PermissionCustom is the per-item mode. Until per-item overrides exist it
	// behaves exactly like PermissionSafe; the overrides will live next to the
	// session record, never in a request.
	PermissionCustom PermissionMode = "custom"
)

// DefaultPermissionMode is safe (ADR-0010 §2.1).
const DefaultPermissionMode = PermissionSafe

// normalized returns the effective mode. An empty or unknown value is safe, so
// bad or missing policy data can never grant more than the default.
func (m PermissionMode) normalized() PermissionMode {
	switch m {
	case PermissionReadOnly, PermissionFull, PermissionCustom:
		return m
	default:
		return DefaultPermissionMode
	}
}

// Valid reports whether m is one of the four modes; the empty value is valid
// and means the default.
func (m PermissionMode) Valid() bool {
	switch m {
	case "", PermissionReadOnly, PermissionSafe, PermissionFull, PermissionCustom:
		return true
	}
	return false
}

// ApprovalDecision is the ADR-0010 policy outcome for one call: whether the
// call is refused, whether it must wait for a human decision, and why. Reason
// is a stable identifier for logs, tests and audit rows; it is not part of the
// public API.
type ApprovalDecision struct {
	Denied       bool
	NeedApproval bool
	Reason       string
}

// Reasons a call is refused or queued for approval.
const (
	reasonReadOnly    = "permission_mode.read_only"
	reasonDestructive = "effect.destructive"
	reasonHighRisk    = "risk.high"
	reasonConfirm     = "approval.confirm"
	reasonAIConfirm   = "approval.ai_confirm"
	reasonPolicy      = "policy.risk"
)

// DecideApproval applies the two-dimensional approval policy: the caller's
// permission mode (ADR-0010 §2.1) and the operation's approval level (§2),
// inside the host hard rules (§3) that neither of them may relax. The decision
// is only part of the answer: a caller whose delegation policy is
// on_approval_required=fail turns NeedApproval into APPROVAL_REQUIRED, and an
// approval may additionally demand MFA.
func (a Action) DecideApproval(who actor.Actor, effectiveRisk string, l Limits) ApprovalDecision {
	mode := l.Mode()
	if mode == PermissionReadOnly {
		if a.Effect == EffectRead {
			return ApprovalDecision{}
		}
		return ApprovalDecision{Denied: true, Reason: reasonReadOnly}
	}
	// Host hard rules: no declaration and no mode relaxes these.
	if a.Effect == EffectDestructive {
		return ApprovalDecision{NeedApproval: true, Reason: reasonDestructive}
	}
	if mode == PermissionFull {
		// full drops the plugin-level approvals and the high-risk rule of a
		// plugin action; the destructive check above already ran. A host action
		// keeps the high-risk rule in every mode (ADR-0010 §2.1, §3).
		if a.Source != PluginSource && riskRank(effectiveRisk) >= riskRank(RiskHigh) {
			return ApprovalDecision{NeedApproval: true, Reason: reasonHighRisk}
		}
		return ApprovalDecision{}
	}
	if riskRank(effectiveRisk) >= riskRank(RiskHigh) {
		return ApprovalDecision{NeedApproval: true, Reason: reasonHighRisk}
	}
	switch a.ApprovalLevel() {
	case ApprovalConfirm:
		return ApprovalDecision{NeedApproval: true, Reason: reasonConfirm}
	case ApprovalAIConfirm:
		if who.Kind == actor.AIAgent {
			return ApprovalDecision{NeedApproval: true, Reason: reasonAIConfirm}
		}
		// A person or a service account keeps the host's own rule.
	}
	return policyApproval(a.Effect, effectiveRisk, l)
}

// policyApproval is the pre-ADR-0010 risk rule (ADR-0004 D6). It still governs
// host actions (which declare no level), auto operations, and people or service
// accounts calling an ai_confirm operation.
func policyApproval(effect, effectiveRisk string, l Limits) ApprovalDecision {
	if l.NeedsApproval(effect, effectiveRisk) {
		return ApprovalDecision{NeedApproval: true, Reason: reasonPolicy}
	}
	return ApprovalDecision{}
}

// permissionModeDenied is the PERMISSION_DENIED of a read_only session that
// tries to run a write operation (ADR-0010 §2.1). It is a refusal, not an
// approval request: nothing is queued.
func permissionModeDenied(act Action, mode PermissionMode) *problem.Error {
	return &problem.Error{
		Code:   problem.PermissionDenied,
		Detail: fmt.Sprintf("The session's permission mode %q refuses %s operations.", mode, act.Effect),
	}
}
