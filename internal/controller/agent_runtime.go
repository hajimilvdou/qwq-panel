// SPDX-License-Identifier: AGPL-3.0-only

package controller

// This file is the production wiring of the native agent plugin to the single
// operation path (ADR-0010 §5, docs/design/agent-sessions.md §11.3-§11.4).
//
// AgentRunner executes one tool call through operations.Run. The actor of the
// call is the AI actor of the session, never the owner: ID is
// "session:<session_id>" and OnBehalfOf is the session owner, so the operation,
// the approval card and the audit rows say that an AI acted for that person.
// The owner's RBAC authority is applied by authorizerAdapter (adapters.go); the
// runner never invents a principal.
//
// AgentApprovals bridges the approval a paused session waits for. It reads the
// operation manager and can withdraw an operation of its own session, never
// decide one: the human decision itself is made by the public
// POST /api/v1/approvals/{id}/decision route, and this package has no path that
// could approve something (ADR-0010 §5).
//
// AgentToolCatalog adapts internal/catalog to agentsession.ToolCatalog. It maps
// the catalog entries (catalog.Entries) to the tool specs a session offers its
// core; the session service filters them by permission mode.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"time"

	"github.com/qwq-panel/qwq/internal/actor"
	"github.com/qwq-panel/qwq/internal/agentsession"
	"github.com/qwq-panel/qwq/internal/authz"
	"github.com/qwq-panel/qwq/internal/catalog"
	"github.com/qwq-panel/qwq/internal/operations"
	"github.com/qwq-panel/qwq/internal/platform/clock"
	"github.com/qwq-panel/qwq/internal/platform/ids"
	"github.com/qwq-panel/qwq/internal/platform/problem"
)

// Defaults of the agent operation wiring.
const (
	// agentToolRoute is the idempotency scope of a session's tool calls. There
	// is no HTTP route with this path; the value names the caller in the
	// idempotency table, exactly like a route does for a gateway request.
	agentToolRoute = "/api/v1/agent-sessions/tool"

	// defaultApprovalPoll is the approval polling interval. The design asks for
	// 500 ms to 1 s; a little jitter keeps many paused sessions from hitting
	// the database in lockstep.
	defaultApprovalPoll = 700 * time.Millisecond
	minApprovalPoll     = 10 * time.Millisecond
	maxApprovalPoll     = 2 * time.Second

	// approvalOperationWait bounds how long the bridge follows an approved
	// operation that is still RUNNING (a job). After that the session gets a
	// running tool result instead of hanging the turn.
	approvalOperationWait = 30 * time.Second
)

// AgentRunner executes the tool calls a session's core proposes.
type AgentRunner struct {
	// Ops is the single operation path; it owns authorization, the approval
	// policy and the audit rows.
	Ops *operations.Service
	// Catalog supplies the confirmation-card text and the placement of plugin
	// actions. It may be nil, which only loses the card enrichment.
	Catalog *catalog.Catalog
	// NodeID is the node this host manages ("local" for a standalone host).
	NodeID string
	// Clock, IDs and Logger are defaults shared with the controller. Clock is
	// currently unused by the runner itself but keeps the wiring uniform with
	// the rest of the host services.
	Clock  clock.Clock
	IDs    *ids.Generator
	Logger *slog.Logger
}

// RunTool implements agentsession.Runner. Every call goes through
// operations.Run as the session's AI actor; nothing is executed here.
func (r *AgentRunner) RunTool(ctx context.Context, call agentsession.ToolCall) (agentsession.ToolResult, error) {
	switch {
	case r == nil || r.Ops == nil:
		return agentToolFailure(problem.New(problem.Unavailable,
			"No operation manager is configured for agent tool calls.")), nil
	case call.CallID == "":
		return agentToolFailure(problem.New(problem.Internal,
			"The agent tool call has no call id.")), nil
	case call.SessionID == "":
		return agentToolFailure(problem.New(problem.Internal,
			"The agent tool call has no session id.")), nil
	case call.Action == "":
		return agentToolFailure(problem.New(problem.ValidationFailed,
			"The agent tool call has no action.")), nil
	case call.Actor.ID == "":
		return agentToolFailure(problem.New(problem.Unauthenticated,
			"The agent session has no owner.")), nil
	}
	// The service puts the mode on the context of every call; a direct caller
	// that only filled ToolCall.PermissionMode still gets the same policy. The
	// mode is host data (the session row), never a request body value.
	if call.PermissionMode != "" {
		if _, ok := operations.PermissionModeFromContext(ctx); !ok {
			ctx = operations.WithPermissionMode(ctx, call.PermissionMode)
		}
	}

	ai := actor.Actor{
		Kind:           actor.AIAgent,
		ID:             operations.SessionActorID(call.SessionID),
		OnBehalfOf:     call.Actor.ID,
		OnBehalfOfKind: call.Actor.Kind,
	}
	target := r.target(call.Action)
	req := operations.RunRequest{
		Actor:     ai,
		TraceID:   agentTraceID(call.CallID),
		RequestID: call.CallID,
		NodeID:    r.nodeID(),
		Action:    call.Action,
		Target:    target,
		Args:      call.Args,
		Idempotency: operations.Idempotency{
			Key:         call.CallID,
			Method:      http.MethodPost,
			Route:       agentToolRoute,
			Fingerprint: agentToolFingerprint(call, target),
		},
	}
	resp, err := r.Ops.Run(ctx, req)
	if err != nil {
		// A cancelled call must end the turn, not become a tool result the
		// model keeps working with.
		if ctxErr := ctx.Err(); ctxErr != nil {
			return agentsession.ToolResult{}, ctxErr
		}
		return agentToolFailure(problem.From(err)), nil
	}
	return r.result(ctx, ai, resp), nil
}

// result maps the operation manager's answer to the session contract.
func (r *AgentRunner) result(ctx context.Context, ai actor.Actor, resp *operations.Response) agentsession.ToolResult {
	if resp == nil {
		return agentToolFailure(problem.New(problem.Internal,
			"The operation manager returned no response for the tool call."))
	}
	if resp.Operation != nil {
		if resp.Operation.Status == operations.AwaitingApproval {
			return r.awaiting(ctx, ai, resp.Operation)
		}
		return agentToolResult(resp.Operation)
	}
	if resp.Outcome != nil {
		return agentToolOutcome(resp.Outcome)
	}
	// An idempotent replay whose operation row was pruned has only its stored
	// body; parse it so a repeated call still answers the same way.
	var op operations.Operation
	if err := json.Unmarshal(resp.Body, &op); err == nil && op.ID != "" && op.Status.Valid() {
		if op.Status == operations.AwaitingApproval {
			return r.awaiting(ctx, ai, &op)
		}
		return agentToolResult(&op)
	}
	var out operations.Outcome
	if err := json.Unmarshal(resp.Body, &out); err == nil && out.Status.Valid() {
		return agentToolOutcome(&out)
	}
	return agentToolFailure(problem.New(problem.Internal,
		"The operation response for the tool call could not be read."))
}

// awaiting builds the paused tool result and the confirmation-card data. A
// missing approval id would make the session wait for nothing, so it is a
// failure instead.
func (r *AgentRunner) awaiting(ctx context.Context, ai actor.Actor, op *operations.Operation) agentsession.ToolResult {
	if op.ApprovalID == "" {
		return agentToolFailure(problem.New(problem.Internal,
			"The operation is awaiting an approval but has no approval id."))
	}
	return agentsession.ToolResult{
		Status:      agentsession.ToolAwaitingApproval,
		OperationID: op.ID,
		ApprovalID:  op.ApprovalID,
		Approval:    r.approvalInfo(ctx, ai, op),
	}
}

// approvalInfo is the confirmation card of op (ADR-0010 §4): the catalog's text
// and risk plus the deadline recorded on the approval. A failure to read the
// approval does not fail the call: the session still has to pause, it just has
// no deadline to show.
func (r *AgentRunner) approvalInfo(ctx context.Context, ai actor.Actor, op *operations.Operation) *agentsession.ApprovalInfo {
	info := &agentsession.ApprovalInfo{
		ApprovalID:  op.ApprovalID,
		OperationID: op.ID,
		Risk:        op.EffectiveRisk,
	}
	if r.Catalog != nil {
		if entry, ok := r.Catalog.Get(op.Action); ok && entry != nil {
			info.Summary = entry.Summary
			info.Description = entry.ApprovalDescription
			info.Risk = entry.Risk
			info.Approval = entry.Approval
		}
	}
	// A host action carries no plugin text; fall back to the metadata recorded
	// on the operation, which survives a catalog change.
	if info.Summary == "" {
		info.Summary = op.Meta.Summary
	}
	if info.Approval == "" {
		info.Approval = op.Meta.ApprovalLevel()
	}
	approval, err := r.Ops.GetApproval(ctx, ai, op.ApprovalID)
	if err != nil {
		r.logger().WarnContext(ctx, "agent tool: read approval for the confirmation card",
			"approval_id", op.ApprovalID, "error", err)
		return info
	}
	deadline := approval.ExpiresAt
	info.Deadline = &deadline
	if info.Summary == "" {
		info.Summary = approval.Facts.ApprovalSummary
	}
	if info.Description == "" {
		info.Description = approval.Facts.ApprovalDescription
	}
	if info.Risk == "" {
		info.Risk = approval.Facts.EffectiveRisk
	}
	if info.Approval == "" {
		info.Approval = approval.Facts.Action.Approval
	}
	return info
}

// target returns the operation target of an action. A host action takes no
// target fields at all (operations rejects a node id on a host action). A plugin
// action names its package; node placement also names this host's local plugin
// instance. ToolCall has no per-call target fields, so a session can never pick
// another node.
func (r *AgentRunner) target(action string) operations.Target {
	if r.Catalog == nil {
		return operations.Target{}
	}
	entry, ok := r.Catalog.Get(action)
	if !ok || entry == nil || entry.Source != catalog.Plugin {
		return operations.Target{}
	}
	target := operations.Target{PluginID: entry.PluginID}
	if entry.Placement == operations.PlacementNode {
		target.NodeID = r.nodeID()
		target.InstanceID = DefaultInstanceID
	}
	return target
}

func (r *AgentRunner) nodeID() string {
	if r.NodeID != "" {
		return r.NodeID
	}
	return "local"
}

func (r *AgentRunner) logger() *slog.Logger {
	if r.Logger != nil {
		return r.Logger
	}
	return slog.New(slog.DiscardHandler)
}

// AgentApprovals implements agentsession.ApprovalBridge. It polls the operation
// manager for the human decision and never decides one itself.
type AgentApprovals struct {
	Ops      *operations.Service
	Clock    clock.Clock
	Logger   *slog.Logger
	Interval time.Duration
}

// Wait blocks until the approval is decided, expires or the context ends.
func (a *AgentApprovals) Wait(ctx context.Context, approvalID string) (agentsession.ApprovalDecision, error) {
	var none agentsession.ApprovalDecision
	switch {
	case a == nil || a.Ops == nil:
		return none, problem.New(problem.Unavailable,
			"No operation manager is configured for agent approvals.")
	case approvalID == "":
		return none, problem.New(problem.Internal, "The agent approval id is empty.")
	}
	system := actor.SystemActor("agent.approvals")
	for {
		approval, err := a.Ops.GetApproval(ctx, system, approvalID)
		if err != nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return none, ctxErr
			}
			return none, err
		}
		switch approval.Status {
		case operations.ApprovalApproved:
			return a.approved(ctx, system, approval)
		case operations.ApprovalRejected:
			return agentsession.ApprovalDecision{
				Decision: agentsession.DecisionReject,
				Comment:  approval.Comment,
				Status:   agentsession.ToolRejected,
				Error: problem.New(problem.PermissionDenied,
					"The user rejected this operation."),
			}, nil
		case operations.ApprovalExpired:
			return agentExpiredDecision(), nil
		case operations.ApprovalCanceled:
			return agentCanceledDecision(), nil
		case operations.ApprovalPending:
			// The sweeper expires approvals on its own interval; a session
			// should not wait for it once the deadline has passed.
			if !approval.ExpiresAt.After(a.now()) {
				return agentExpiredDecision(), nil
			}
		default:
			return none, problem.New(problem.Internal,
				"The approval has an unknown status.")
		}
		select {
		case <-ctx.Done():
			return none, ctx.Err()
		case <-a.clock().After(agentApprovalJitter(a.interval())):
		}
	}
}

// approved follows the operation after the human decided: the decision is
// committed before the action runs, so the bridge has to wait for the outcome
// (a host action finishes synchronously, a job may still be running).
func (a *AgentApprovals) approved(ctx context.Context, system actor.Actor,
	approval *operations.Approval) (agentsession.ApprovalDecision, error) {
	var none agentsession.ApprovalDecision
	deadline := a.now().Add(approvalOperationWait)
	for {
		op, err := a.Ops.Get(ctx, system, approval.OperationID)
		if err != nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return none, ctxErr
			}
			return none, err
		}
		if agentOperationTerminal(op.Status) {
			return agentDecision(approval.Comment, op), nil
		}
		if !a.now().Before(deadline) {
			// Still running: report it as running instead of failing a turn
			// that was legitimately approved.
			return agentDecision(approval.Comment, op), nil
		}
		select {
		case <-ctx.Done():
			return none, ctx.Err()
		case <-a.clock().After(agentApprovalJitter(a.interval())):
		}
	}
}

// CancelApproval implements agentsession.ApprovalCanceller: it withdraws the
// operation as the same AI actor that created it, so a session can only ever
// reach its own operations.
func (a *AgentApprovals) CancelApproval(ctx context.Context, owner actor.Actor, sessionID, operationID, reason string) error {
	if a == nil || a.Ops == nil {
		return problem.New(problem.Unavailable, "No operation manager is configured for agent approvals.")
	}
	_, err := a.Ops.Cancel(ctx, operations.CancelRequest{
		Actor: actor.Actor{
			Kind:           actor.AIAgent,
			ID:             operations.SessionActorID(sessionID),
			OnBehalfOf:     owner.ID,
			OnBehalfOfKind: owner.Kind,
		},
		OperationID: operationID,
		Reason:      reason,
		TraceID:     agentTraceID(operationID),
		RequestID:   operationID,
		Idempotency: operations.Idempotency{
			Key: "agentcancel:" + operationID, Method: http.MethodPost, Route: agentToolRoute + "/cancel",
		},
	})
	return err
}

func (a *AgentApprovals) interval() time.Duration {
	switch {
	case a.Interval <= 0:
		return defaultApprovalPoll
	case a.Interval < minApprovalPoll:
		return minApprovalPoll
	case a.Interval > maxApprovalPoll:
		return maxApprovalPoll
	default:
		return a.Interval
	}
}

func (a *AgentApprovals) clock() clock.Clock {
	if a.Clock != nil {
		return a.Clock
	}
	return clock.System{}
}

func (a *AgentApprovals) now() time.Time { return a.clock().Now().UTC() }

// agentApprovalJitter spreads the pollers: interval plus up to half an interval.
func agentApprovalJitter(interval time.Duration) time.Duration {
	extra := interval / 2
	if extra <= 0 {
		return interval
	}
	return interval + time.Duration(rand.Int64N(int64(extra)+1))
}

// AgentToolCatalog adapts the host action catalog to agentsession.ToolCatalog.
type AgentToolCatalog struct {
	Catalog *catalog.Catalog
	// HostAction reports whether a host action has an executor on the
	// operation manager. The catalog also carries host actions that are served
	// outside the operation surface (the plugin install routes), and offering
	// one to a core would only produce a failed call. Nil offers every host
	// action, which is what a test or a host with its own executor wants.
	HostAction func(id string) bool
}

// Actions implements agentsession.ToolCatalog.
func (a AgentToolCatalog) Actions(context.Context) []agentsession.ToolSpec {
	if a.Catalog == nil {
		return nil
	}
	entries := a.Catalog.Entries()
	out := make([]agentsession.ToolSpec, 0, len(entries))
	for _, entry := range entries {
		// A human-only permission (ADR-0004 D6) is never offered: the model
		// does not even learn that the action exists.
		if entry == nil || authz.IsHumanOnly(entry.Permission) {
			continue
		}
		if entry.Source == catalog.Host {
			// A host read action is served by its GET route and operations.Run
			// refuses it; a host write action without a handler cannot run
			// either.
			if entry.Effect == operations.EffectRead {
				continue
			}
			if a.HostAction != nil && !a.HostAction(entry.ID) {
				continue
			}
		}
		out = append(out, agentsession.ToolSpec{
			Action:      entry.ID,
			Summary:     entry.Summary,
			Description: entry.ApprovalDescription,
			Effect:      entry.Effect,
			Risk:        entry.Risk,
			Approval:    entry.Approval,
			Permission:  entry.Permission,
			Parameters:  entry.ArgsSchema,
		})
	}
	return out
}

// agentToolResult maps one operation record to the session contract.
func agentToolResult(op *operations.Operation) agentsession.ToolResult {
	out := op.Outcome()
	res := agentsession.ToolResult{
		OperationID: op.ID,
		ApprovalID:  op.ApprovalID,
		Result:      agentJSON(out),
		Status:      agentToolStatus(op.Status),
	}
	switch res.Status {
	case agentsession.ToolFailed, agentsession.ToolRejected, agentsession.ToolCancelled:
		res.Error = agentOperationError(op.Error, op.ID, op.Status)
	}
	return res
}

// agentToolOutcome maps the compact outcome of a read or a terminal operation.
func agentToolOutcome(out *operations.Outcome) agentsession.ToolResult {
	res := agentsession.ToolResult{
		OperationID: out.OperationID,
		ApprovalID:  out.ApprovalID,
		Result:      agentJSON(out),
		Status:      agentToolStatus(out.Status),
	}
	switch res.Status {
	case agentsession.ToolFailed, agentsession.ToolRejected, agentsession.ToolCancelled:
		res.Error = agentOperationError(out.Error, out.OperationID, out.Status)
	}
	return res
}

// agentToolStatus maps an operation state to a tool status. A non-terminal
// operation (a job that was started) is `running`: the session keeps the
// operation id and the model can report that it is still in progress.
func agentToolStatus(status operations.Status) agentsession.ToolStatus {
	switch status {
	case operations.Succeeded:
		return agentsession.ToolSucceeded
	case operations.Failed, operations.Expired:
		return agentsession.ToolFailed
	case operations.Rejected:
		return agentsession.ToolRejected
	case operations.Canceled:
		return agentsession.ToolCancelled
	case operations.AwaitingApproval:
		return agentsession.ToolAwaitingApproval
	default:
		return agentsession.ToolRunning
	}
}

// agentOperationError turns the wire error of an operation into the tool error.
// A failed state without an error still gets a stable code and detail; no
// internal cause or stack is ever exposed (problem.Problem never carries one).
func agentOperationError(p *problem.Problem, operationID string, status operations.Status) *problem.Error {
	if p != nil {
		return &problem.Error{
			Code:            p.Code,
			Detail:          p.Detail,
			OperationID:     firstNonEmpty(p.OperationID, operationID),
			EffectiveRisk:   p.EffectiveRisk,
			RetryAfterSec:   p.RetryAfter,
			PluginCode:      p.PluginCode,
			CurrentRevision: p.CurrentRevision,
		}
	}
	switch status {
	case operations.Failed:
		return &problem.Error{Code: problem.Internal, OperationID: operationID,
			Detail: "The operation failed."}
	case operations.Rejected:
		return &problem.Error{Code: problem.PermissionDenied, OperationID: operationID,
			Detail: "The operation was rejected."}
	case operations.Expired:
		return &problem.Error{Code: problem.StateConflict, OperationID: operationID,
			Detail: "The approval expired before a decision; ask for a new operation."}
	case operations.Canceled:
		return &problem.Error{Code: problem.StateConflict, OperationID: operationID,
			Detail: "The operation was canceled before it finished."}
	}
	return nil
}

// agentToolFailure is a tool result that never reached the operation path or
// that the operation path refused.
func agentToolFailure(p *problem.Error) agentsession.ToolResult {
	if p == nil {
		p = problem.New(problem.Internal, "The agent tool call failed.")
	}
	return agentsession.ToolResult{Status: agentsession.ToolFailed, Error: p}
}

// agentDecision is the bridge's answer for an approved operation.
func agentDecision(comment string, op *operations.Operation) agentsession.ApprovalDecision {
	res := agentToolResult(op)
	return agentsession.ApprovalDecision{
		Decision: agentsession.DecisionApprove,
		Comment:  comment,
		Status:   res.Status,
		Result:   res.Result,
		Error:    res.Error,
	}
}

func agentExpiredDecision() agentsession.ApprovalDecision {
	return agentsession.ApprovalDecision{
		Decision: agentsession.DecisionReject,
		Status:   agentsession.ToolFailed,
		Error: problem.New(problem.StateConflict,
			"The approval expired before it was decided; ask for a new operation."),
	}
}

func agentCanceledDecision() agentsession.ApprovalDecision {
	return agentsession.ApprovalDecision{
		Decision: agentsession.DecisionReject,
		Status:   agentsession.ToolRejected,
		Error: problem.New(problem.StateConflict,
			"The approval was canceled before it was decided."),
	}
}

// agentOperationTerminal reports whether no further transition is possible.
func agentOperationTerminal(status operations.Status) bool {
	switch status {
	case operations.Succeeded, operations.Failed, operations.Canceled,
		operations.Rejected, operations.Expired:
		return true
	}
	return false
}

// agentTraceID derives a W3C trace id from the call so every retry of the same
// call correlates in the logs. A missing call id (never produced by the session
// service) falls back to a random one.
func agentTraceID(callID string) string {
	if callID == "" {
		return ids.TraceID()
	}
	sum := sha256.Sum256([]byte("qwq:agent-tool:" + callID))
	return hex.EncodeToString(sum[:16])
}

// agentToolFingerprint identifies the content of a call for idempotency: the
// same key with different arguments must be rejected, not replayed. The session
// row and the call id are included so two sessions never share a fingerprint.
func agentToolFingerprint(call agentsession.ToolCall, target operations.Target) string {
	raw, err := json.Marshal(struct {
		SessionID string            `json:"session_id"`
		CallID    string            `json:"call_id"`
		Action    string            `json:"action"`
		Args      json.RawMessage   `json:"args,omitempty"`
		Target    operations.Target `json:"target"`
	}{call.SessionID, call.CallID, call.Action, call.Args, target})
	if err != nil {
		// The model may return malformed arguments; they are still a distinct
		// call, so hash the fields without re-encoding them.
		sum := sha256.Sum256([]byte(call.SessionID + "\x00" + call.CallID + "\x00" +
			call.Action + "\x00" + string(call.Args)))
		return hex.EncodeToString(sum[:])
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// agentJSON marshals a host value; a failure becomes null rather than a panic.
func agentJSON(v any) json.RawMessage {
	if v == nil {
		return nil
	}
	raw, err := json.Marshal(v)
	if err != nil {
		return nil
	}
	return raw
}

// firstNonEmpty returns the first non-empty argument.
func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}
