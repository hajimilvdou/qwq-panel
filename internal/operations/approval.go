// SPDX-License-Identifier: AGPL-3.0-only

package operations

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/qwq-panel/qwq/internal/actor"
	"github.com/qwq-panel/qwq/internal/platform/problem"
	"github.com/qwq-panel/qwq/internal/storage"
)

// ExternalApprovalAction and ExternalApprovalPermission identify host approval
// cards minted for external CLI agent permission prompts (Codex, OpenCode,
// DSH/ACP) so they flow through POST /api/v1/approvals/{id}/decision.
const (
	ExternalApprovalAction     = "host.agent.external_approval"
	ExternalApprovalPermission = "host.agent_external_approval:approve"
)

// ExternalApprovalInput describes an external CLI permission prompt to persist
// as a real pending operation + approval record.
type ExternalApprovalInput struct {
	Actor          actor.Actor
	ExternalAction string
	Summary        string
	Description    string
	Risk           string
	Destructive    bool
	Args           json.RawMessage
	PermissionMode PermissionMode
	TraceID        string
	RequestID      string
}

// MintExternalApproval persists an AWAITING_APPROVAL operation and its paired
// PENDING approval card for an external CLI permission request so a human
// administrator can decide it via POST /api/v1/approvals/{id}/decision.
func (s *Service) MintExternalApproval(ctx context.Context, req ExternalApprovalInput) (approvalID, operationID string, err error) {
	if req.Actor.ID == "" || req.Actor.Valid() != nil {
		return "", "", problem.New(problem.Unauthenticated, "The external approval request has no valid actor.")
	}
	risk := strings.ToLower(strings.TrimSpace(req.Risk))
	switch risk {
	case RiskLow, RiskMedium, RiskHigh:
	default:
		risk = RiskHigh
	}
	effect := EffectWrite
	if req.Destructive {
		effect = EffectDestructive
		risk = RiskHigh
	}
	payloadObj := map[string]any{
		"external_action": strings.TrimSpace(req.ExternalAction),
	}
	if len(req.Args) > 0 && json.Valid(req.Args) {
		payloadObj["args"] = json.RawMessage(req.Args)
	}
	argsBytes, err := json.Marshal(payloadObj)
	if err != nil {
		return "", "", problem.Wrap(err)
	}
	args, err := canonicalObject(argsBytes)
	if err != nil {
		return "", "", problem.Wrap(err)
	}
	summary := clipText(strings.TrimSpace(req.Summary), 200)
	if summary == "" {
		summary = "External agent action requires administrator confirmation"
	}
	desc := clipText(strings.TrimSpace(req.Description), 1000)

	act := Action{
		ID:                  ExternalApprovalAction,
		Summary:             summary,
		Effect:              effect,
		Risk:                risk,
		Mode:                ModeInvoke,
		Permission:          ExternalApprovalPermission,
		Source:              HostSource,
		Approval:            ApprovalConfirm,
		ApprovalSummary:     summary,
		ApprovalDescription: desc,
	}
	w := &writeRequest{
		req: RunRequest{
			Actor:     req.Actor,
			TraceID:   req.TraceID,
			RequestID: req.RequestID,
			NodeID:    s.nodeID,
			Action:    ExternalApprovalAction,
			Args:      args,
		},
		act:           act,
		args:          args,
		digest:        digestOf(args),
		effectiveRisk: risk,
		needApproval:  true,
		mode:          req.PermissionMode.normalized(),
	}
	op := s.newOperation(w)
	approval := s.newApproval(op, w)
	op.ApprovalID = approval.ID

	err = s.db.Update(ctx, func(tx *storage.Tx) error {
		tx.SetOrigin(s.origin(op.Actor, op.ID, op.TraceID, op.NodeID))
		if err := s.insertOperation(ctx, tx, op); err != nil {
			return err
		}
		if err := s.transition(ctx, tx, op, AwaitingApproval); err != nil {
			return err
		}
		return s.insertApproval(ctx, tx, op, approval)
	})
	if err != nil {
		return "", "", problem.From(err)
	}
	s.notify(ctx, op)
	return approval.ID, op.ID, nil
}

// Approval decisions (OpenAPI ApprovalDecisionRequest).
const (
	DecisionApprove = "approve"
	DecisionReject  = "reject"
)

// DecisionRequest decides one approval. The gateway verifies mfa_code and sets
// Actor.MFA before calling: this package never sees the TOTP secret.
type DecisionRequest struct {
	Actor            actor.Actor
	ApprovalID       string
	Decision         string
	Comment          string
	ExpectedRevision string
	Idempotency      Idempotency
	TraceID          string
	RequestID        string
}

// Decide records an approval decision. Only a human browser session may decide
// one, whatever the policy says (ADR-0004 D6, acceptance 3).
func (s *Service) Decide(ctx context.Context, req DecisionRequest) (*Response, error) {
	if !req.Actor.IsHumanSession() {
		denied := &problem.Error{
			Code:   problem.PermissionDenied,
			Detail: "Only a human browser session may decide an approval.",
		}
		// A delegation or service account trying to approve is a security event
		// worth recording (ADR-0004 acceptance 3).
		s.auditDeniedByID(ctx, req.Actor, "approval.decide", req.ApprovalID, req.TraceID, req.RequestID, denied)
		return nil, denied
	}
	switch req.Decision {
	case DecisionApprove, DecisionReject:
	default:
		return nil, problem.Validation(violation("/decision", "INVALID", "decision must be approve or reject."))
	}
	if req.Idempotency.Key == "" {
		return nil, missingIdempotencyKey()
	}
	claim, replay, err := s.claimIdempotency(ctx, req.Actor, req.Idempotency,
		fingerprintOf("approval.decision", req.ApprovalID, req.Decision, req.ExpectedRevision, req.Comment))
	if err != nil {
		return nil, err
	}
	if replay != nil {
		s.hydrateReplay(ctx, replay)
		return replay, nil
	}
	resp, decideErr := s.decide(ctx, req)
	s.finishIdempotency(ctx, claim, resp, decideErr, req.RequestID, req.Idempotency.Route)
	return resp, decideErr
}

func (s *Service) decide(ctx context.Context, req DecisionRequest) (*Response, error) {
	approval, err := loadApproval(ctx, s.db.Reader(), req.ApprovalID)
	if err != nil {
		return nil, err
	}
	op, err := loadOperation(ctx, s.db.Reader(), approval.OperationID)
	if err != nil {
		return nil, err
	}
	now := s.clock.Now().UTC().Truncate(time.Millisecond)
	if approval.Status != ApprovalPending {
		return nil, &problem.Error{
			Code:        problem.StateConflict,
			Detail:      "The approval was already decided.",
			OperationID: op.ID,
		}
	}
	if !approval.ExpiresAt.After(now) {
		// Expire it now so the next reader sees the truth, then report the
		// conflict (OpenAPI: an already expired approval is STATE_CONFLICT).
		_ = s.expireApproval(ctx, approval.ID)
		return nil, &problem.Error{
			Code:        problem.StateConflict,
			Detail:      "The approval expired before the decision.",
			OperationID: op.ID,
		}
	}
	if req.ExpectedRevision != "" && req.ExpectedRevision != approval.Revision {
		return nil, problem.Conflict(approval.Revision)
	}
	// The approver must hold the operation's permission too (ADR-0004 D6);
	// otherwise anyone able to click could approve anything.
	if err := s.authorize(ctx, req.Actor, op.Meta, op.Target); err != nil {
		s.auditDenied(ctx, req.Actor, "approval.decide", approvalSubject(approval.ID), op, req.TraceID, req.RequestID, err)
		return nil, withOperationID(err, op.ID)
	}
	if approval.RequiresMFA && !req.Actor.MFA {
		mfaErr := &problem.Error{
			Code:        problem.MFARequired,
			Detail:      "This approval requires a second factor.",
			OperationID: op.ID,
		}
		s.auditDenied(ctx, req.Actor, "approval.decide", approvalSubject(approval.ID), op, req.TraceID, req.RequestID, mfaErr)
		return nil, mfaErr
	}

	err = s.db.Update(ctx, func(tx *storage.Tx) error {
		cur, err := loadApproval(ctx, tx, approval.ID)
		if err != nil {
			return err
		}
		if cur.Status != ApprovalPending {
			return &problem.Error{Code: problem.StateConflict, Detail: "The approval was already decided.", OperationID: op.ID}
		}
		op, err = loadOperation(ctx, tx, cur.OperationID)
		if err != nil {
			return err
		}
		if op.Status != AwaitingApproval {
			return &problem.Error{Code: problem.StateConflict, Detail: "The operation is not awaiting approval.", OperationID: op.ID}
		}
		tx.SetOrigin(s.origin(req.Actor, op.ID, req.TraceID, op.NodeID))
		decidedAt := tx.Now()
		cur.DecidedBy = &req.Actor
		cur.DecidedAt = &decidedAt
		cur.Comment = clipText(req.Comment, 500)
		next := ApprovalApproved
		to := Approved
		if req.Decision == DecisionReject {
			next, to = ApprovalRejected, Rejected
		}
		cur.Status = next
		if err := s.writeApproval(ctx, tx, cur); err != nil {
			return err
		}
		if err := s.transition(ctx, tx, op, to); err != nil {
			return err
		}
		outcome := AuditSuccess
		if req.Decision == DecisionReject {
			outcome = AuditFailure
		}
		return audit(ctx, tx, AuditRecord{
			Actor: req.Actor, Action: "approval." + req.Decision, Subject: approvalSubject(cur.ID),
			Outcome: outcome, OperationID: op.ID, NodeID: op.NodeID, TraceID: req.TraceID,
			RequestID: req.RequestID,
		}, map[string]any{"operation_id": op.ID, "comment": cur.Comment, "decision": req.Decision})
	})
	if err != nil {
		return nil, problem.From(err)
	}

	if req.Decision == DecisionApprove {
		// Run after the decision is committed: a failing action must not undo
		// the human's decision, it ends FAILED with its own error.
		if err := s.executeApproved(ctx, op, req.Actor); err != nil {
			s.log.WarnContext(ctx, "operations: approved operation failed",
				"operation_id", op.ID, "error", err)
		}
	}
	current, err := loadApproval(ctx, s.db.Reader(), req.ApprovalID)
	if err != nil {
		return nil, err
	}
	if latest, err := loadOperation(ctx, s.db.Reader(), op.ID); err == nil {
		op = latest
	}
	resp := &Response{
		Status: 200, Body: responseJSON(current), OperationID: op.ID, Operation: op, Approval: current,
	}
	s.notify(ctx, op)
	return resp, nil
}

// GetApproval returns one approval the caller may see.
func (s *Service) GetApproval(ctx context.Context, a actor.Actor, id string) (*Approval, error) {
	approval, err := loadApproval(ctx, s.db.Reader(), id)
	if err != nil {
		return nil, err
	}
	if !canReadAll(a) {
		op, err := loadOperation(ctx, s.db.Reader(), approval.OperationID)
		if err != nil {
			return nil, err
		}
		if !samePrincipal(a, op.Actor) {
			return nil, notFound("approval")
		}
	}
	return approval, nil
}

// ListApprovals returns one page of approvals. The default status is PENDING
// (OpenAPI listApprovals).
func (s *Service) ListApprovals(ctx context.Context, a actor.Actor, f ApprovalFilter) (*ApprovalPage, error) {
	status := f.Status
	if status == "" {
		status = ApprovalPending
	}
	var (
		where []string
		args  []any
	)
	where = append(where, "status = ?")
	args = append(args, string(status))
	if f.SinceRevision != "" {
		seq, err := revisionInt(f.SinceRevision)
		if err != nil {
			return nil, problem.Validation(problem.Violation{
				Pointer: "/since_revision", In: "query", Code: "INVALID", Message: "Not a revision.",
			})
		}
		where = append(where, "revision > ?")
		args = append(args, seq)
	}
	if !canReadAll(a) {
		where = append(where, `operation_id IN (
			SELECT operation_id FROM operations
			WHERE actor_kind = ? AND actor_id = ? AND actor_on_behalf_of = ?)`)
		args = append(args, string(a.Kind), a.ID, a.OnBehalfOf)
	}
	if f.Cursor != "" {
		after, err := decodeCursor(f.Cursor)
		if err != nil {
			return nil, problem.Validation(problem.Violation{
				Pointer: "/cursor", In: "query", Code: "INVALID", Message: "Not a cursor.",
			})
		}
		where = append(where, "approval_id < ?")
		args = append(args, after)
	}
	limit := clampLimit(f.Limit)
	query := `SELECT ` + approvalColumns + ` FROM approvals WHERE ` +
		strings.Join(where, " AND ") + ` ORDER BY approval_id DESC LIMIT ?`
	args = append(args, limit+1)
	rows, err := s.db.Reader().QueryContext(ctx, query, args...)
	if err != nil {
		return nil, problem.Wrap(err)
	}
	defer rows.Close()
	items := make([]Approval, 0, limit)
	for rows.Next() {
		approval, err := scanApproval(rows)
		if err != nil {
			return nil, problem.Wrap(err)
		}
		items = append(items, *approval)
	}
	if err := rows.Err(); err != nil {
		return nil, problem.Wrap(err)
	}
	page := &ApprovalPage{Revision: s.pageRevision(), Delta: f.SinceRevision != ""}
	if len(items) > limit {
		items = items[:limit]
		page.NextCursor = encodeCursor(items[len(items)-1].ID)
	}
	page.Items = items
	return page, nil
}

// writeApproval updates the approval row and emits its resource.changed event.
func (s *Service) writeApproval(ctx context.Context, tx *storage.Tx, approval *Approval) error {
	rev, err := tx.Changed(ctx, storage.Change{
		Subject: approvalSubject(approval.ID), Kind: storage.Updated, Pointers: []string{"/status"},
	})
	if err != nil {
		return err
	}
	approval.Revision = storage.Revision(rev)
	return updateApprovalRow(ctx, tx, approval)
}

// expireApproval marks the approval expired and the operation EXPIRED. The
// system actor is recorded: no person decided it (ADR-0004 D7).
func (s *Service) expireApproval(ctx context.Context, id string) error {
	system := actor.SystemActor("operations")
	return s.withApprovalAs(ctx, system, id, func(ctx context.Context, tx *storage.Tx, approval *Approval, op *Operation) error {
		if approval.Status != ApprovalPending {
			return nil
		}
		approval.Status = ApprovalExpired
		if err := s.writeApproval(ctx, tx, approval); err != nil {
			return err
		}
		if op.Status == AwaitingApproval {
			if err := s.transition(ctx, tx, op, Expired); err != nil {
				return err
			}
		}
		return audit(ctx, tx, AuditRecord{
			Actor: system, Action: "approval.expire", Subject: approvalSubject(approval.ID),
			Outcome: AuditFailure, OperationID: op.ID, NodeID: op.NodeID, TraceID: op.TraceID,
			RequestID: op.RequestID,
		}, map[string]any{"operation_id": op.ID, "expires_at": approval.ExpiresAt})
	})
}

// withApprovalAs loads an approval and its operation in a write transaction and
// sets the origin to a.
func (s *Service) withApprovalAs(ctx context.Context, a actor.Actor, id string,
	fn func(context.Context, *storage.Tx, *Approval, *Operation) error) error {
	return s.db.Update(ctx, func(tx *storage.Tx) error {
		approval, err := loadApproval(ctx, tx, id)
		if err != nil {
			return err
		}
		op, err := loadOperation(ctx, tx, approval.OperationID)
		if err != nil {
			return err
		}
		tx.SetOrigin(s.origin(a, op.ID, op.TraceID, op.NodeID))
		return fn(ctx, tx, approval, op)
	})
}

// auditDeniedByID loads the approval and its operation and records a refused
// attempt. Load errors are ignored: the denial is what matters.
func (s *Service) auditDeniedByID(ctx context.Context, a actor.Actor, action, approvalID, traceID, requestID string, cause error) {
	approval, err := loadApproval(ctx, s.db.Reader(), approvalID)
	if err != nil {
		return
	}
	op, err := loadOperation(ctx, s.db.Reader(), approval.OperationID)
	if err != nil {
		return
	}
	s.auditDenied(ctx, a, action, approvalSubject(approval.ID), op, traceID, requestID, cause)
}

// auditDenied records a refused approval attempt in its own transaction, since
// the caller's transaction rolls back.
func (s *Service) auditDenied(ctx context.Context, a actor.Actor, action, subject string, op *Operation,
	traceID, requestID string, cause error) {
	_ = s.db.Update(ctx, func(tx *storage.Tx) error {
		return audit(ctx, tx, AuditRecord{
			Actor: a, Action: action, Subject: subject, Outcome: AuditDenied,
			OperationID: op.ID, NodeID: op.NodeID, TraceID: traceID, RequestID: requestID,
		}, map[string]any{"operation_id": op.ID, "code": string(problem.From(cause).Code)})
	})
}

// missingIdempotencyKey is the 400 of a mutating call without a key.
func missingIdempotencyKey() error {
	return &problem.Error{
		Code:   problem.ValidationFailed,
		Detail: "The request needs an Idempotency-Key header.",
		Violations: []problem.Violation{
			{Pointer: "/Idempotency-Key", In: "header", Code: "REQUIRED", Message: "An Idempotency-Key header is required."},
		},
	}
}
