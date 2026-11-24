// SPDX-License-Identifier: AGPL-3.0-only

package agentsession

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"

	"github.com/qwq-panel/qwq/internal/operations"
	"github.com/qwq-panel/qwq/internal/platform/problem"
)

const maxExternalApprovalsPerTurn = 16

// ExternalApprovalKind classifies a permission prompt emitted by an external
// agent subprocess (Codex, OpenCode, DSH / ACP).
type ExternalApprovalKind string

const (
	ApprovalKindShell      ExternalApprovalKind = "shell"
	ApprovalKindPatch      ExternalApprovalKind = "patch"
	ApprovalKindExternal   ExternalApprovalKind = "external_tool"
	ApprovalKindPermission ExternalApprovalKind = "permission"
)

// ExternalApprovalRequest is the normalized form of:
//   - Codex:    execCommandApproval / applyPatchApproval
//   - OpenCode: permission.asked
//   - DSH/ACP:  session/request_permission
type ExternalApprovalRequest struct {
	CallID      string
	Kind        ExternalApprovalKind
	Action      string
	Summary     string
	Description string
	Risk        string
	Args        json.RawMessage
	Destructive bool
}

// ExternalApprovalVerdict is returned back to the child agent.
type ExternalApprovalVerdict string

const (
	VerdictAccept  ExternalApprovalVerdict = "accept"
	VerdictDecline ExternalApprovalVerdict = "decline"
	VerdictCancel  ExternalApprovalVerdict = "cancel"
)

// ExternalApprovalOutcome carries both the verdict and the human comment.
type ExternalApprovalOutcome struct {
	Verdict    ExternalApprovalVerdict
	ApprovalID string
	Comment    string
}

// HostApprovalMinter creates a real host approval record (backed by
// operations) for an external agent permission request so the human decides it
// through the single authoritative POST /api/v1/approvals/{id}/decision route.
type HostApprovalMinter interface {
	MintApproval(ctx context.Context, sessionID string, req ExternalApprovalRequest) (approvalID, operationID string, err error)
}

// ApprovalRouter bridges external agent approval requests onto qwq's single
// host-authoritative policy & human approval workflow.
type ApprovalRouter struct {
	turn     Turn
	planMode bool
	emit     Emit
	minter   HostApprovalMinter
	bridge   ApprovalBridge

	mu          sync.Mutex
	mintedCount int
}

// NewApprovalRouter creates one router bound to a session turn.
func NewApprovalRouter(turn Turn, planMode bool, emit Emit, minter HostApprovalMinter, bridge ApprovalBridge) *ApprovalRouter {
	return &ApprovalRouter{
		turn:     turn,
		planMode: planMode,
		emit:     emit,
		minter:   minter,
		bridge:   bridge,
	}
}

// Decide enforces qwq's permission ceiling and routes human confirmation.
//
// Rules (ADR-0010 §2.1 & §3):
//  1. read_only or plan_mode ALWAYS declines mutating/shell external prompts.
//  2. full mode may auto-accept non-destructive, non-high-risk prompts ONLY
//     when explicitly marked non-destructive; destructive/high-risk ALWAYS asks.
//  3. safe / custom ALWAYS asks a human through HostApprovalMinter + ApprovalBridge.
//  4. Missing minter or bridge fails closed (VerdictDecline), never self-approves.
func (r *ApprovalRouter) Decide(ctx context.Context, req ExternalApprovalRequest) ExternalApprovalOutcome {
	// Always mint a host-unique call ID when supplied by Service so untrusted
	// child CLIs cannot trigger PK collisions in agent_tool_calls.
	if r.turn.NextCallID != nil {
		req.CallID = r.turn.NextCallID()
	}
	if req.Action == "" {
		req.Action = "external." + string(req.Kind)
	}
	if len(req.Args) == 0 {
		req.Args = json.RawMessage(`{}`)
	}

	// Hard ceiling #1: read_only and plan_mode never allow shell/patch mutation.
	if r.turn.PermissionMode == operations.PermissionReadOnly || r.planMode {
		r.emitDenied(req, "Session is in read-only or plan mode; mutating external actions are refused.")
		return ExternalApprovalOutcome{
			Verdict: VerdictDecline,
			Comment: "Denied by qwq host: read_only / plan_mode active.",
		}
	}

	// Hard ceiling #2: destructive or high-risk operations can NEVER skip human
	// approval, and dangerous shell/patch mutations are promoted to Destructive
	// so MintExternalApproval enforces MFA.
	dangerous := isDangerousShellRequest(req) || isDangerousPatchRequest(req)
	if dangerous {
		req.Destructive = true
		req.Risk = "high"
	}
	highRisk := req.Destructive || strings.EqualFold(req.Risk, "high")
	if r.turn.PermissionMode == operations.PermissionFull && !highRisk {
		return ExternalApprovalOutcome{
			Verdict: VerdictAccept,
			Comment: "Allowed under full mode (non-destructive).",
		}
	}

	// Fail closed when host approval plumbing is absent.
	if r.minter == nil || r.bridge == nil {
		r.emitDenied(req, "Host approval router is not wired; external action denied fail-closed.")
		return ExternalApprovalOutcome{
			Verdict: VerdictDecline,
			Comment: "Host approval bridge unavailable (fail-closed).",
		}
	}

	r.mu.Lock()
	if r.mintedCount >= maxExternalApprovalsPerTurn {
		r.mu.Unlock()
		r.emitDenied(req, "Per-turn external approval limit reached; further permission prompts are declined.")
		return ExternalApprovalOutcome{
			Verdict: VerdictDecline,
			Comment: "Per-turn external approval limit reached.",
		}
	}
	r.mintedCount++
	r.mu.Unlock()

	aprID, opID, err := r.minter.MintApproval(ctx, r.turn.SessionID, req)
	if err != nil || aprID == "" {
		r.emitDenied(req, fmt.Sprintf("Failed to create host approval: %v", err))
		return ExternalApprovalOutcome{
			Verdict: VerdictDecline,
			Comment: "Failed to mint host approval.",
		}
	}

	cancelMinted := func(reason string) {
		if opID == "" {
			return
		}
		if canceller, ok := r.bridge.(ApprovalCanceller); ok {
			_ = canceller.CancelApproval(context.WithoutCancel(ctx), r.turn.Owner, r.turn.SessionID, opID, reason)
		}
	}

	if r.emit != nil {
		if emitErr := r.emit(Event{
			Type:        EventApprovalRequired,
			SessionID:   r.turn.SessionID,
			CallID:      req.CallID,
			Action:      req.Action,
			Args:        req.Args,
			ApprovalID:  aprID,
			OperationID: opID,
			Risk:        req.Risk,
			Approval:    "confirm",
			Summary:     req.Summary,
			Description: req.Description,
		}); emitErr != nil {
			cancelMinted("Failed to publish external approval prompt to session stream.")
			return ExternalApprovalOutcome{
				Verdict:    VerdictDecline,
				ApprovalID: aprID,
				Comment:    "Failed to publish approval prompt (fail-closed).",
			}
		}
	}

	dec, err := r.bridge.Wait(ctx, aprID)
	if err != nil {
		cancelMinted("External agent turn ended before approval decision.")
		if r.emit != nil {
			_ = r.emit(Event{
				Type:        EventToolResult,
				SessionID:   r.turn.SessionID,
				CallID:      req.CallID,
				Action:      req.Action,
				Status:      string(ToolCancelled),
				ApprovalID:  aprID,
				OperationID: opID,
				Error:       ErrorOf(problem.From(err)),
			})
		}
		return ExternalApprovalOutcome{Verdict: VerdictCancel, ApprovalID: aprID, Comment: "Approval cancelled."}
	}

	if r.emit != nil {
		_ = r.emit(Event{
			Type:       EventApprovalDecided,
			SessionID:  r.turn.SessionID,
			CallID:     req.CallID,
			ApprovalID: aprID,
			Decision:   dec.Decision,
			Comment:    dec.Comment,
		})
	}
	if dec.Decision == DecisionApprove {
		return ExternalApprovalOutcome{Verdict: VerdictAccept, ApprovalID: aprID, Comment: dec.Comment}
	}
	return ExternalApprovalOutcome{Verdict: VerdictDecline, ApprovalID: aprID, Comment: dec.Comment}
}

func (r *ApprovalRouter) emitDenied(req ExternalApprovalRequest, reason string) {
	if r.emit == nil {
		return
	}
	_ = r.emit(Event{
		Type:      EventToolResult,
		SessionID: r.turn.SessionID,
		CallID:    req.CallID,
		Action:    req.Action,
		Status:    string(ToolRejected),
		Error:     &ErrorInfo{Code: problem.PermissionDenied, Detail: reason},
	})
}

// isDangerousShellRequest catches obvious lockout/destructive shell commands
// (SSH lockout, firewall flush, rm -rf /) so even full mode forces confirmation + MFA.
func isDangerousShellRequest(req ExternalApprovalRequest) bool {
	if req.Kind != ApprovalKindShell && req.Kind != ApprovalKindPermission {
		return false
	}
	body := strings.ToLower(req.Summary + " " + req.Description + " " + string(req.Args))
	for _, pat := range []string{
		"rm -rf /",
		"rm -fr /",
		"iptables -f",
		"nft flush ruleset",
		"ufw reset",
		"sshd_config",
		"authorized_keys",
		"/etc/passwd",
		"/etc/shadow",
		"/etc/sudoers",
		"/var/lib/qwq",
		"passwd",
		"shutdown",
		"reboot",
		"mkfs",
	} {
		if strings.Contains(body, pat) {
			return true
		}
	}
	return false
}

// isDangerousPatchRequest catches file edits targeting SSH/auth/qwq host state
// so MintExternalApproval promotes them to Destructive (MFA required).
func isDangerousPatchRequest(req ExternalApprovalRequest) bool {
	if req.Kind != ApprovalKindPatch && req.Kind != ApprovalKindPermission {
		return false
	}
	body := strings.ToLower(req.Summary + " " + req.Description + " " + string(req.Args))
	for _, pat := range []string{
		"/etc/ssh/",
		"sshd_config",
		"authorized_keys",
		"/etc/passwd",
		"/etc/shadow",
		"/etc/sudoers",
		"/var/lib/qwq",
		"/etc/qwq",
	} {
		if strings.Contains(body, pat) {
			return true
		}
	}
	return false
}
