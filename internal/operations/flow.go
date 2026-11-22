// SPDX-License-Identifier: AGPL-3.0-only

package operations

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/qwq-panel/qwq/internal/actor"
	"github.com/qwq-panel/qwq/internal/platform/problem"
	"github.com/qwq-panel/qwq/internal/storage"
)

// operationUpdatedPayload is the payload of the operation.updated event
// (OpenAPI OperationUpdatedPayload): what follow mode and the task drawer need,
// without the result.
type operationUpdatedPayload struct {
	OperationID    string           `json:"operation_id"`
	Action         string           `json:"action"`
	Status         Status           `json:"status"`
	PreviousStatus Status           `json:"previous_status,omitempty"`
	Attempt        int              `json:"attempt"`
	Actor          actor.Actor      `json:"actor"`
	Target         Target           `json:"target"`
	EffectiveRisk  string           `json:"effective_risk,omitempty"`
	ApprovalID     string           `json:"approval_id,omitempty"`
	Progress       *Progress        `json:"progress,omitempty"`
	UIRoute        string           `json:"ui_route,omitempty"`
	Error          *problem.Problem `json:"error,omitempty"`
	Revision       string           `json:"revision"`
}

// insertOperation writes a new operation as PENDING, its create event, its
// PENDING operation.updated event and the audit row. The caller sets the
// transaction origin first.
func (s *Service) insertOperation(ctx context.Context, tx *storage.Tx, op *Operation) error {
	op.Status = Pending
	op.CreatedAt = tx.Now()
	op.UpdatedAt = op.CreatedAt
	rev, err := tx.Changed(ctx, storage.Change{Subject: operationSubject(op.ID), Kind: storage.Created})
	if err != nil {
		return err
	}
	op.Revision = storage.Revision(rev)
	if err := insertOperationRow(ctx, tx, op); err != nil {
		return err
	}
	if err := s.appendOperationUpdated(ctx, tx, op, ""); err != nil {
		return err
	}
	details := map[string]any{
		"event": "created", "status": op.Status, "target": op.Target,
		"effective_risk": op.EffectiveRisk, "attempt": op.Attempt,
	}
	if op.ParentOperationID != "" {
		details["parent_operation_id"] = op.ParentOperationID
	}
	if op.invokedBy != nil {
		// The actor is the parent's (ADR-0011 §3); this is who asked for it.
		details["invoked_by"] = op.invokedBy
	}
	return audit(ctx, tx, AuditRecord{
		Actor: op.Actor, Action: op.Action, Subject: operationSubject(op.ID), Outcome: AuditSuccess,
		OperationID: op.ID, NodeID: op.NodeID, TraceID: op.TraceID, RequestID: op.RequestID,
	}, details)
}

// writeOperation persists the mutable columns of op, emitting the operation's
// resource.changed event (whose sequence becomes its revision) and the
// operation.updated event.
func (s *Service) writeOperation(ctx context.Context, tx *storage.Tx, op *Operation, previous Status, pointers []string) error {
	op.UpdatedAt = tx.Now()
	if op.StartedAt == nil && (op.Status == Running || isTerminal(op.Status)) {
		t := op.UpdatedAt
		op.StartedAt = &t
	}
	if isTerminal(op.Status) && op.FinishedAt == nil {
		t := op.UpdatedAt
		op.FinishedAt = &t
	}
	rev, err := tx.Changed(ctx, storage.Change{
		Subject: operationSubject(op.ID), Kind: storage.Updated, Pointers: pointers,
	})
	if err != nil {
		return err
	}
	op.Revision = storage.Revision(rev)
	if err := updateOperationRow(ctx, tx, op); err != nil {
		return err
	}
	if err := s.appendOperationUpdated(ctx, tx, op, previous); err != nil {
		return err
	}
	if isTerminal(op.Status) {
		if err := finishAttemptRow(ctx, tx, op, strings.ToLower(string(op.Status))); err != nil {
			return err
		}
	}
	return nil
}

// appendOperationUpdated writes the operation.updated event.
func (s *Service) appendOperationUpdated(ctx context.Context, tx *storage.Tx, op *Operation, previous Status) error {
	payload := operationUpdatedPayload{
		OperationID: op.ID, Action: op.Action, Status: op.Status, PreviousStatus: previous,
		Attempt: op.Attempt, Actor: op.Actor, Target: op.Target, EffectiveRisk: op.EffectiveRisk,
		ApprovalID: op.ApprovalID, Progress: op.Progress, UIRoute: op.UIRoute, Error: op.Error,
		Revision: op.Revision,
	}
	if payload.PreviousStatus == payload.Status {
		payload.PreviousStatus = ""
	}
	b, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	_, err = tx.AppendEvent(ctx, storage.Event{
		Type: "operation.updated", SchemaVersion: "1", Subject: operationSubject(op.ID), Payload: b,
	})
	return err
}

// transition moves op to to, or fails with STATE_CONFLICT (ADR-0004 D7).
func (s *Service) transition(ctx context.Context, tx *storage.Tx, op *Operation, to Status) error {
	if !allowedTransition(op.Status, to) {
		return stateConflict(op, op.Status, to)
	}
	previous := op.Status
	op.Status = to
	return s.writeOperation(ctx, tx, op, previous, []string{"/status"})
}

// enterRunning moves the operation to RUNNING and opens an attempt row.
func (s *Service) enterRunning(ctx context.Context, tx *storage.Tx, op *Operation) error {
	if err := s.transition(ctx, tx, op, Running); err != nil {
		return err
	}
	return startAttemptRow(ctx, tx, op)
}

// finishOperation records a terminal state. cause, when not nil, is rendered
// into the operation's error field.
func (s *Service) finishOperation(ctx context.Context, tx *storage.Tx, op *Operation, to Status, cause error) error {
	if !isTerminal(to) {
		return fmt.Errorf("operations: %s is not terminal", to)
	}
	if prev := op.Status; !allowedTransition(prev, to) && prev != to {
		return stateConflict(op, prev, to)
	}
	previous := op.Status
	op.Status = to
	if cause != nil {
		op.Error = s.problemOf(cause, op.RequestID, "/api/v1/operations/"+op.ID)
	}
	if err := s.writeOperation(ctx, tx, op, previous, []string{"/status", "/result", "/error"}); err != nil {
		return err
	}
	if to != Succeeded {
		return nil
	}
	return audit(ctx, tx, AuditRecord{
		Actor: op.Actor, Action: op.Action, Subject: operationSubject(op.ID), Outcome: AuditSuccess,
		OperationID: op.ID, NodeID: op.NodeID, TraceID: op.TraceID, RequestID: op.RequestID,
	}, map[string]any{"event": "finished", "status": op.Status, "attempt": op.Attempt})
}

// problemOf renders any error as a stored Problem. Errors that are not host
// errors become INTERNAL and their text is never stored.
func (s *Service) problemOf(err error, requestID, instance string) *problem.Problem {
	if err == nil {
		return nil
	}
	p := problem.From(err).Problem(requestID, instance)
	return &p
}

// failOperation records a terminal failure together with its audit row.
func (s *Service) failOperation(ctx context.Context, tx *storage.Tx, op *Operation, to Status, cause error) error {
	if err := s.finishOperation(ctx, tx, op, to, cause); err != nil {
		return err
	}
	outcome := AuditFailure
	if to == Canceled {
		outcome = AuditSuccess
	}
	return audit(ctx, tx, AuditRecord{
		Actor: op.Actor, Action: op.Action, Subject: operationSubject(op.ID), Outcome: outcome,
		OperationID: op.ID, NodeID: op.NodeID, TraceID: op.TraceID, RequestID: op.RequestID,
	}, map[string]any{"event": "finished", "status": op.Status, "attempt": op.Attempt, "error": op.Error})
}

// checkExpectedRevision enforces the optimistic concurrency guard of the
// subject the operation modifies (ADR-0004 D2). It runs inside the operation's
// transaction, so the check and the write cannot be separated. Plugin subjects
// are checked by the plugin itself (proto Precondition).
func (s *Service) checkExpectedRevision(ctx context.Context, tx *storage.Tx, op *Operation) error {
	if op.ExpectedRevision == "" || op.Target.Subject == "" || s.revisions == nil {
		return nil
	}
	if op.Meta.Source == PluginSource {
		return nil
	}
	current, err := s.currentRevision(ctx, tx, op.Target.Subject)
	if err != nil {
		return err
	}
	if current != op.ExpectedRevision {
		return problem.Conflict(current)
	}
	return nil
}

// applyChanges records plugin-owned resource changes with full subjects
// (ADR-0007 #2). A malformed relative subject is a plugin error, not a host
// bug.
func (s *Service) applyChanges(ctx context.Context, tx *storage.Tx, op *Operation, changes []ResourceChange) error {
	for _, c := range changes {
		full, err := prefixPluginSubject(op.Meta.Placement, op.Target.NodeID, op.Meta.PluginID, op.Target.InstanceID, c.Subject)
		if err != nil {
			return problem.FromPlugin("INVALID_SUBJECT", "The plugin reported an invalid subject.", false, nil)
		}
		kind := storage.Updated
		if c.Deleted {
			kind = storage.Deleted
		}
		if _, err := tx.Changed(ctx, storage.Change{Subject: full, Kind: kind, Pointers: c.ChangedPointers}); err != nil {
			return err
		}
	}
	return nil
}

// pluginSubjectPrefix is the instance namespace of a plugin's resources
// (ADR-0007 #2).
func pluginSubjectPrefix(act Action, target Target) string {
	switch act.Placement {
	case PlacementNode:
		return "nodes/" + target.NodeID + "/plugins/" + act.PluginID + "/instances/" + target.InstanceID + "/resources/"
	case PlacementController:
		return "plugins/" + act.PluginID + "/resources/"
	default:
		return ""
	}
}

// pluginRelativeSubjectFor strips the instance namespace from a full subject so
// it can be sent to a plugin (proto uses relative subjects). It also validates
// the remaining relative subject.
func pluginRelativeSubjectFor(act Action, target Target, full string) (string, bool) {
	prefix := pluginSubjectPrefix(act, target)
	if prefix == "" || len(full) <= len(prefix) || full[:len(prefix)] != prefix {
		return "", false
	}
	rel := full[len(prefix):]
	if err := validateRelativeSubject(rel); err != nil {
		return "", false
	}
	return rel, true
}

// hostRequest is what a host action sees about its operation.
func (s *Service) hostRequest(op *Operation) HostRequest {
	return HostRequest{
		Actor: op.Actor, OperationID: op.ID, Attempt: op.Attempt, TraceID: op.TraceID,
		RequestID: op.RequestID, Action: op.Meta, Target: op.Target, Args: op.Args,
		ExpectedRevision: op.ExpectedRevision,
	}
}

// invokeRequest builds the plugin-side request of an invoke operation.
func (s *Service) invokeRequest(op *Operation) PluginInvokeRequest {
	return PluginInvokeRequest{
		Actor: op.Actor, OperationID: op.ID, ParentOperationID: op.ParentOperationID,
		Attempt: op.Attempt, TraceID: op.TraceID,
		RequestID: op.RequestID, NodeID: op.Target.NodeID, PluginID: op.Meta.PluginID,
		InstanceID: op.Target.InstanceID, Placement: op.Meta.Placement, Operation: op.Meta.Operation,
		APIVersion: op.Meta.APIVersion, Payload: op.Args, Preconditions: op.Preconditions,
	}
}

// dispatchRequest builds the plugin-side request of an operation that runs
// after an approval. The preconditions captured at creation (including a plan's
// plugin-side ones) travel with the operation, so approving and executing use
// exactly the same guard (ADR-0004 D7).
func (s *Service) dispatchRequest(op *Operation) PluginInvokeRequest {
	return s.invokeRequest(op)
}

// notify tells the Notifier about an operation that ran without approval
// (ADR-0004 D6: low risk runs and then notifies). Notify must not block.
func (s *Service) notify(ctx context.Context, op *Operation) {
	if s.notifier == nil || op == nil || op.ApprovalID != "" || op.Effect == EffectRead {
		return
	}
	if !isTerminal(op.Status) {
		return
	}
	s.notifier.Notify(ctx, op)
}

// errNoHandler is a host action without an executor.
var errNoHandler = errors.New("operations: host action has no handler")

// errNoRevisions is returned when host preconditions exist but the controller
// did not provide a revision resolver: silently skipping a precondition would
// break ADR-0004 D7.
var errNoRevisions = errors.New("operations: host preconditions need a revisions resolver")
