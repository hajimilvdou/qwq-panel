// SPDX-License-Identifier: AGPL-3.0-only

package operations

import (
	"context"

	"github.com/qwq-panel/qwq/internal/actor"
	"github.com/qwq-panel/qwq/internal/platform/problem"
	"github.com/qwq-panel/qwq/internal/storage"
)

// CancelRequest cancels an operation (OpenAPI cancelOperation). There is no
// expected_revision: progress updates change the revision constantly and cancel
// must not race with them.
type CancelRequest struct {
	Actor       actor.Actor
	OperationID string
	Reason      string
	Idempotency Idempotency
	TraceID     string
	RequestID   string
}

// Cancel stops an operation. PENDING, AWAITING_APPROVAL and APPROVED become
// CANCELED at once (200); a RUNNING operation only records the request
// (cancel_requested=true, 202) and ends as CANCELED when it stops, or as
// SUCCEEDED/FAILED if it could not stop in time.
func (s *Service) Cancel(ctx context.Context, req CancelRequest) (*Response, error) {
	if req.Actor.ID == "" || req.Actor.Valid() != nil {
		return nil, problem.New(problem.Unauthenticated, "The request has no valid actor.")
	}
	if req.Idempotency.Key == "" {
		return nil, missingIdempotencyKey()
	}
	// 幂等回放也必须受当前权限约束，不能借已接受的旧响应绕过撤权。
	op, err := loadOperation(ctx, s.db.Reader(), req.OperationID)
	if err != nil {
		return nil, err
	}
	if err := s.authorizeCancellation(ctx, req.Actor, op); err != nil {
		return nil, err
	}
	claim, replay, err := s.claimIdempotency(ctx, req.Actor, req.Idempotency,
		fingerprintOf("cancel", req.OperationID, req.Reason))
	if err != nil {
		return nil, err
	}
	if replay != nil {
		s.hydrateReplay(ctx, replay)
		return replay, nil
	}
	resp, cancelErr := s.cancelOperation(ctx, req)
	s.finishIdempotency(ctx, claim, resp, cancelErr, req.RequestID, req.Idempotency.Route)
	return resp, cancelErr
}

func (s *Service) cancelOperation(ctx context.Context, req CancelRequest) (*Response, error) {
	op, err := loadOperation(ctx, s.db.Reader(), req.OperationID)
	if err != nil {
		return nil, err
	}
	if !canRead(req.Actor, op) {
		return nil, notFound("operation")
	}
	if isTerminal(op.Status) {
		return nil, &problem.Error{
			Code:        problem.StateConflict,
			Detail:      "The operation already finished.",
			OperationID: op.ID,
		}
	}
	reason := clipText(req.Reason, 500)
	canceledAtOnce := false
	err = s.db.Update(ctx, func(tx *storage.Tx) error {
		cur, err := loadOperation(ctx, tx, op.ID)
		if err != nil {
			return err
		}
		tx.SetOrigin(s.origin(req.Actor, cur.ID, req.TraceID, cur.NodeID))
		if isTerminal(cur.Status) {
			return &problem.Error{
				Code:        problem.StateConflict,
				Detail:      "The operation already finished.",
				OperationID: cur.ID,
			}
		}
		op = cur
		if cur.Status == Running {
			cur.CancelRequested = true
			if err := s.writeOperation(ctx, tx, cur, cur.Status, []string{"/cancel_requested"}); err != nil {
				return err
			}
			return audit(ctx, tx, AuditRecord{
				Actor: req.Actor, Action: "operation.cancel", Subject: operationSubject(cur.ID),
				Outcome: AuditSuccess, OperationID: cur.ID, NodeID: cur.NodeID, TraceID: req.TraceID,
				RequestID: req.RequestID,
			}, map[string]any{"reason": reason, "mode": "requested"})
		}
		if err := s.transition(ctx, tx, cur, Canceled); err != nil {
			return err
		}
		canceledAtOnce = true
		// A queued approval dies with the operation (ApprovalStatus CANCELED).
		if cur.ApprovalID != "" {
			approval, err := loadApproval(ctx, tx, cur.ApprovalID)
			switch {
			case err == nil && approval.Status == ApprovalPending:
				approval.Status = ApprovalCanceled
				if err := s.writeApproval(ctx, tx, approval); err != nil {
					return err
				}
			case problem.HasCode(err, problem.NotFound):
				// The approval was pruned; nothing to cancel.
			case err != nil:
				return err
			}
		}
		return audit(ctx, tx, AuditRecord{
			Actor: req.Actor, Action: "operation.cancel", Subject: operationSubject(cur.ID),
			Outcome: AuditSuccess, OperationID: cur.ID, NodeID: cur.NodeID, TraceID: req.TraceID,
			RequestID: req.RequestID,
		}, map[string]any{"reason": reason, "mode": "canceled"})
	})
	if err != nil {
		return nil, problem.From(err)
	}
	if !canceledAtOnce {
		// Ask the plugin to stop; the worker turns the result into CANCELED.
		s.cancelRunning(ctx, op)
	}
	current, err := loadOperation(ctx, s.db.Reader(), op.ID)
	if err != nil {
		return nil, err
	}
	s.ResultRedactor(ctx, req.Actor)(current)
	status := 200
	if current.Status == Running {
		status = 202
	}
	resp := &Response{
		Status: status, Body: responseJSON(current), OperationID: current.ID, Operation: current,
	}
	return resp, nil
}
