// SPDX-License-Identifier: AGPL-3.0-only

package operations

import (
	"context"
	"encoding/json"
	"time"

	"github.com/qwq-panel/qwq/internal/actor"
	"github.com/qwq-panel/qwq/internal/platform/ids"
	"github.com/qwq-panel/qwq/internal/platform/problem"
	"github.com/qwq-panel/qwq/internal/storage"
)

// RunRequest is one write through the single path (ADR-0004 D1). The gateway
// fills it from the HTTP request; an AI agent goes through the same struct, so
// people and agents cannot diverge.
type RunRequest struct {
	Actor     actor.Actor
	TraceID   string
	RequestID string
	// NodeID is the node of the request; empty means this host's node.
	NodeID string
	// Locale is the actor's UI language (BCP 47) for localized plugin text.
	Locale string
	Action string
	Target Target
	// Args are the action arguments (the request body, or the path parameters
	// and body flattened by the gateway). Secrets appear as references.
	Args json.RawMessage
	// ExpectedRevision is the optimistic concurrency guard of Target.Subject
	// (ADR-0004 D2).
	ExpectedRevision string
	Idempotency      Idempotency
	// ParentOperationID makes this a child operation (ADR-0007 #5): it inherits
	// the parent's actor and permission mode, and needs its own approval if it
	// is riskier. The caller must have verified that the parent may be used.
	ParentOperationID string
	// InvokedBy names the plugin instance of a plugin-to-plugin call; it is
	// recorded in the audit row (ADR-0011 §3).
	InvokedBy *PluginInstanceRef
}

// MaxCallDepth bounds a chain of child operations, counting the root
// (ADR-0011 §7): it stops A->B->A loops.
const MaxCallDepth = 3

// writeRequest is a validated Run on its way through the write path.
type writeRequest struct {
	req           RunRequest
	act           Action
	args          json.RawMessage
	digest        string
	effectiveRisk string
	needApproval  bool
	// mode is the caller's permission mode; it is recorded on the approval card
	// so the UI can show why a decision was asked for (ADR-0010 §2.1).
	mode   PermissionMode
	parent *Operation
	plan   *Plan
	// claim is the request's idempotency key; it is bound to the operation in
	// the transaction that creates it (OPS-02).
	claim *idemClaim
}

// Run creates the operation for req and executes it as far as the policy
// allows: synchronously for host actions that need no approval, in the
// background for jobs, and after the dispatcher answers for plugin invocations.
func (s *Service) Run(ctx context.Context, req RunRequest) (*Response, error) {
	act, err := s.action(req.Action)
	if err != nil {
		return nil, err
	}
	if req.Actor.ID == "" || req.Actor.Valid() != nil {
		return nil, problem.New(problem.Unauthenticated, "The request has no valid actor.")
	}
	if req.NodeID == "" {
		req.NodeID = s.nodeID
	}
	if act.Placement == PlacementNode && req.Target.NodeID == "" {
		req.Target.NodeID = s.nodeID
	}
	if err := validateTarget(act, req.Target); err != nil {
		return nil, err
	}
	if act.Source == PluginSource && req.ExpectedRevision != "" {
		if req.Target.Subject == "" {
			return nil, problem.Validation(violation("/expected_revision", "SUBJECT_REQUIRED",
				"expected_revision needs a target subject."))
		}
		if _, ok := pluginRelativeSubjectFor(act, req.Target, req.Target.Subject); !ok {
			return nil, problem.Validation(violation("/target/subject", "INVALID_SUBJECT",
				"The subject is not one of the plugin instance's resources."))
		}
	}
	args, err := canonicalObject(req.Args)
	if err != nil {
		return nil, problem.Validation(violation("/args", "INVALID_JSON", "Arguments must be a JSON object."))
	}
	if err := validateArgs(act, args); err != nil {
		return nil, err
	}
	effectiveRisk := act.EffectiveRisk()

	// A child runs as its parent's actor (ADR-0007 #5, ADR-0011 §3), so RBAC
	// and the delegation policy below judge that actor.
	parent, err := s.parentOperation(ctx, req)
	if err != nil {
		return nil, err
	}
	if parent != nil {
		req.Actor = parent.Actor
	}
	if err := s.authorize(ctx, req.Actor, act, req.Target); err != nil {
		return nil, err
	}
	limits, err := s.limits(ctx, req.Actor, act, req.Target)
	if err != nil {
		return nil, err
	}
	if parent != nil {
		// ADR-0011 §5: the parent's mode carries over and is never widened.
		limits.PermissionMode = stricterMode(limits.Mode(), parent.PermissionMode.normalized())
	}
	if limits.MaxRisk != "" && riskRank(effectiveRisk) > riskRank(limits.MaxRisk) {
		return nil, riskCapError(effectiveRisk)
	}
	// ADR-0010 §2.1: read_only refuses writes outright, so nothing is queued.
	decision := act.DecideApproval(req.Actor, effectiveRisk, limits)
	if decision.Denied {
		return nil, permissionModeDenied(act, limits.Mode())
	}

	sensitive, err := s.argumentsSensitive(act, args)
	if err != nil {
		return nil, err
	}
	if act.Effect == EffectRead {
		if sensitive {
			return nil, problem.New(problem.ValidationFailed, "Read actions cannot accept new secret material.")
		}
		if act.Mode != ModeJob {
			return s.runRead(ctx, req, act, args, effectiveRisk)
		}
	}
	if req.Idempotency.Key == "" {
		// 修改与显式持久 job 共用幂等、任务预算和当前授权；同步只读调用
		// 保持原 200/no-record 轮询路径，不在此处分配幂等记录。
		return nil, missingIdempotencyKey()
	}

	needApproval := decision.NeedApproval
	recordedRisk := effectiveRisk
	if parent != nil {
		if riskRank(effectiveRisk) > riskRank(parent.EffectiveRisk) {
			// The child may not ride on the parent's approval.
			needApproval = true
		}
		// ADR-0011 §5: the record shows the riskier of the two; the decision
		// above used the target's own risk.
		recordedRisk = maxRisk(effectiveRisk, parent.EffectiveRisk)
	}
	if needApproval && limits.OnApprovalRequired == ApprovalFail {
		return nil, &problem.Error{
			Code:          problem.ApprovalRequired,
			Detail:        "This action needs a human approval and the caller's policy does not queue them.",
			EffectiveRisk: effectiveRisk,
		}
	}

	fingerprint := runFingerprint(req, act, args)
	if sensitive {
		// 指纹使用稳定的专用密钥，避免把弱密码的可枚举摘要写入数据库。
		input := append([]byte(fingerprint+"\x00"), args...)
		fingerprint = s.argumentProtector.Fingerprint("plugins/"+act.PluginID+"/"+act.ID, input)
		clear(input)
	}
	claim, replay, err := s.claimIdempotency(ctx, req.Actor, req.Idempotency, fingerprint)
	if err != nil {
		return nil, err
	}
	if replay != nil {
		s.hydrateReplay(ctx, replay)
		return replay, nil
	}
	args, cleanup, err := s.protectArguments(ctx, act, args, sensitive)
	if err != nil {
		s.releaseIdempotency(context.WithoutCancel(ctx), claim)
		return nil, err
	}
	req.Args = args
	w := &writeRequest{
		req: req, act: act, args: args, digest: digestOf(args), effectiveRisk: recordedRisk,
		needApproval: needApproval, mode: limits.Mode(), parent: parent, claim: claim,
	}
	resp, runErr := s.runWrite(ctx, w)
	if (resp == nil || resp.Operation == nil) && (runErr == nil || problem.From(runErr).OperationID == "") {
		s.discardArguments(ctx, cleanup)
	}
	s.finishIdempotency(ctx, claim, resp, runErr, req.RequestID, req.Idempotency.Route)
	return resp, runErr
}

// Submit is Run for callers that only need the operation record (the agent
// execute tool).
func (s *Service) Submit(ctx context.Context, req RunRequest) (*Operation, error) {
	resp, err := s.Run(ctx, req)
	if err != nil {
		return nil, err
	}
	return resp.Operation, nil
}

// runRead executes a plugin read action. reads do not create operation records
// (OpenAPI OperationOutcome: operation_id is empty for effect=read plugin
// actions) and ignore idempotency keys.
func (s *Service) runRead(ctx context.Context, req RunRequest, act Action, args []byte, effectiveRisk string) (*Response, error) {
	if act.Source != PluginSource {
		return nil, problem.New(problem.ValidationFailed,
			"Host read actions are served by their GET route, not by the operation surface.")
	}
	if s.dispatcher == nil {
		return nil, problem.New(problem.Unavailable, "No plugin dispatcher is configured.")
	}
	op := s.newOperation(&writeRequest{req: req, act: act, args: args, digest: digestOf(args), effectiveRisk: effectiveRisk})
	runCtx, cancel := context.WithTimeout(ctx, op.Timeout)
	defer cancel()
	res, err := s.dispatcher.Invoke(runCtx, s.invokeRequest(op))
	if err != nil {
		return nil, problem.From(err)
	}
	if len(res.Changes) > 0 {
		err := s.db.Update(ctx, func(tx *storage.Tx) error {
			tx.SetOrigin(s.origin(op.Actor, "", op.TraceID, op.NodeID))
			return s.applyChanges(ctx, tx, op, res.Changes)
		})
		if err != nil {
			return nil, problem.From(err)
		}
	}
	out := &Outcome{OperationID: "", Action: act.ID, Status: Succeeded, EffectiveRisk: effectiveRisk, Result: res.Result}
	return &Response{Status: 200, Body: responseJSON(out), Outcome: out}, nil
}

// runWrite creates the operation and runs it as far as possible.
func (s *Service) runWrite(ctx context.Context, w *writeRequest) (*Response, error) {
	// A mode=job host action owns its transactions, so it is queued for a worker
	// even when no approval is needed (GAPS gap 7).
	if w.act.Source == HostSource && w.act.Mode != ModeJob && !w.needApproval {
		return s.createAndRunHost(ctx, w)
	}
	op, approval, err := s.createOperation(ctx, w)
	if err != nil {
		return nil, err
	}
	if approval != nil {
		// Queued for a human decision (OpenAPI 202 + Operation).
		return newResponse(op), nil
	}
	// The operation exists now; its outcome must be readable even when the
	// client has already gone away.
	ctx = context.WithoutCancel(ctx)
	if err := s.executeCreated(ctx, op); err != nil {
		return nil, withOperationID(err, op.ID)
	}
	if op.Mode == ModeJob {
		// A queued job (plugin or host) answers with the record it was
		// accepted as: a worker may already have moved it on, and the client
		// follows it by ID.
		return newResponse(op), nil
	}
	current, err := loadOperation(ctx, s.db.Reader(), op.ID)
	if err != nil {
		return nil, withOperationID(err, op.ID)
	}
	s.notify(ctx, current)
	return finishedResponse(current), nil
}

// createOperation persists a new operation (and its approval when one is
// needed) in one short write transaction.
func (s *Service) createOperation(ctx context.Context, w *writeRequest) (*Operation, *Approval, error) {
	op := s.newOperation(w)
	var approval *Approval
	err := s.db.Update(ctx, func(tx *storage.Tx) error {
		tx.SetOrigin(s.origin(op.Actor, op.ID, op.TraceID, op.NodeID))
		if err := s.insertOperation(ctx, tx, op); err != nil {
			return err
		}
		if err := bindIdempotency(ctx, tx, w.claim, op.ID); err != nil {
			return err
		}
		if w.plan != nil {
			// A stale plan must not even queue an approval (ADR-0004 D7).
			if err := s.checkPlanPreconditions(ctx, tx, w.plan); err != nil {
				return err
			}
		}
		if w.needApproval {
			approval = s.newApproval(op, w)
			op.ApprovalID = approval.ID
			if err := s.transition(ctx, tx, op, AwaitingApproval); err != nil {
				return err
			}
			if err := s.insertApproval(ctx, tx, op, approval); err != nil {
				return err
			}
		}
		if w.plan != nil {
			if err := bindPlanOperation(ctx, tx, w.plan.ID, op.ID); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return nil, nil, problem.From(err)
	}
	return op, approval, nil
}

// createAndRunHost is the synchronous host path: the domain rows, the operation
// rows, the events and the audit row are written in one transaction
// (ADR-0008 §2). A handler failure rolls all of it back, so a failed request
// leaves no half-applied change and no operation.
func (s *Service) createAndRunHost(ctx context.Context, w *writeRequest) (*Response, error) {
	op := s.newOperation(w)
	err := s.db.Update(ctx, func(tx *storage.Tx) error {
		tx.SetOrigin(s.origin(op.Actor, op.ID, op.TraceID, op.NodeID))
		if err := s.insertOperation(ctx, tx, op); err != nil {
			return err
		}
		if err := bindIdempotency(ctx, tx, w.claim, op.ID); err != nil {
			return err
		}
		if w.plan != nil {
			if err := s.checkPlanPreconditions(ctx, tx, w.plan); err != nil {
				return err
			}
		}
		if w.plan != nil {
			if err := bindPlanOperation(ctx, tx, w.plan.ID, op.ID); err != nil {
				return err
			}
		}
		if err := s.checkExpectedRevision(ctx, tx, op); err != nil {
			return err
		}
		handler, ok := s.hostAction(op.Action)
		if !ok || handler.handler == nil {
			return errNoHandler
		}
		if err := s.enterRunning(ctx, tx, op); err != nil {
			return err
		}
		interactiveCtx, release := s.interactiveHostContext(ctx, op, op.Actor)
		defer release()
		result, err := handler.handler(interactiveCtx, tx, s.interactiveHostRequest(interactiveCtx, op))
		if err != nil {
			return err
		}
		if len(result) > 0 {
			op.Result = result
		}
		return s.finishOperation(ctx, tx, op, Succeeded, nil)
	})
	if err != nil {
		s.log.WarnContext(ctx, "operation rejected", "action", op.Action, "error", err, "operation_id", op.ID)
		return nil, problem.From(err)
	}
	s.notify(ctx, op)
	return finishedResponse(op), nil
}

// newOperation builds the in-memory record of a request. The ID is created
// here so that events and audit rows can reference it before the insert.
func (s *Service) newOperation(w *writeRequest) *Operation {
	nodeID := w.req.Target.NodeID
	if nodeID == "" {
		nodeID = w.req.NodeID
	}
	if nodeID == "" {
		nodeID = s.nodeID
	}
	op := &Operation{
		ID:                s.ids.New(ids.Operation),
		Action:            w.act.ID,
		Target:            w.req.Target,
		Actor:             w.req.Actor,
		EffectiveRisk:     w.effectiveRisk,
		DeclaredRisk:      w.act.Risk,
		Effect:            w.act.Effect,
		Mode:              w.act.Mode,
		Idempotent:        w.act.Idempotent,
		Permission:        w.act.Permission,
		UIRoute:           w.act.UIRoute,
		Args:              w.args,
		ArgsDigest:        w.digest,
		ExpectedRevision:  w.req.ExpectedRevision,
		Attempt:           1,
		Timeout:           w.act.Timeout(s.defaultTimeout(w.act.Mode)),
		RequestID:         w.req.RequestID,
		TraceID:           w.req.TraceID,
		NodeID:            nodeID,
		Meta:              w.act,
		ParentOperationID: w.req.ParentOperationID,
		PermissionMode:    w.mode,
		invokedBy:         w.req.InvokedBy,
	}
	if w.plan != nil {
		op.PlanID = w.plan.ID
		op.Preconditions = append([]Precondition(nil), w.plan.PluginPreconditions...)
	} else if w.req.ExpectedRevision != "" && w.act.Source == PluginSource {
		if rel, ok := pluginRelativeSubjectFor(w.act, w.req.Target, w.req.Target.Subject); ok {
			op.Preconditions = []Precondition{{Subject: rel, Revision: w.req.ExpectedRevision}}
		}
	}
	return op
}

// parentOperation loads the parent of a child operation and checks that the
// caller is allowed to use it.
func (s *Service) parentOperation(ctx context.Context, req RunRequest) (*Operation, error) {
	if req.ParentOperationID == "" {
		return nil, nil
	}
	parent, err := loadOperation(ctx, s.db.Reader(), req.ParentOperationID)
	if err != nil {
		return nil, err
	}
	if !samePrincipal(req.Actor, parent.Actor) && req.Actor.Kind != actor.System {
		return nil, problem.New(problem.PermissionDenied,
			"The parent operation belongs to another actor.")
	}
	depth, err := s.chainDepth(ctx, parent)
	if err != nil {
		return nil, err
	}
	if depth+1 > MaxCallDepth {
		return nil, problem.New(problem.PermissionDenied,
			"The call chain is deeper than %d operations.", MaxCallDepth)
	}
	return parent, nil
}

// chainDepth counts op and its ancestors. The walk stops past MaxCallDepth, so
// a corrupt (cyclic) chain cannot loop.
func (s *Service) chainDepth(ctx context.Context, op *Operation) (int, error) {
	depth := 1
	for cur := op; cur.ParentOperationID != "" && depth <= MaxCallDepth; depth++ {
		next, err := loadOperation(ctx, s.db.Reader(), cur.ParentOperationID)
		if err != nil {
			return 0, err
		}
		cur = next
	}
	return depth, nil
}

// stricterMode returns the more restrictive of two normalized modes:
// read_only, then safe/custom, then full.
func stricterMode(a, b PermissionMode) PermissionMode {
	rank := func(m PermissionMode) int {
		switch m {
		case PermissionReadOnly:
			return 3
		case PermissionFull:
			return 1
		default:
			return 2
		}
	}
	if rank(b) > rank(a) {
		return b
	}
	return a
}

// maxRisk returns the higher of two risks.
func maxRisk(a, b string) string {
	if riskRank(b) > riskRank(a) {
		return b
	}
	return a
}

// newApproval builds the confirmation card data: what the host knows, plus the
// plan's plugin-provided preview when there is one (ADR-0004 D6). The plugin's
// own confirmation text and the caller's permission mode travel with the card
// (ADR-0010 §4); both are plain data, the UI renders them as untrusted text.
func (s *Service) newApproval(op *Operation, w *writeRequest) *Approval {
	now := s.clock.Now().UTC().Truncate(time.Millisecond)
	caps := op.Meta.Capabilities
	if caps == nil {
		caps = []Capability{}
	}
	approval := &Approval{
		ID:          s.ids.New(ids.Approval),
		OperationID: op.ID,
		Status:      ApprovalPending,
		Facts: ApprovalFacts{
			Action:               op.Meta.meta(op.EffectiveRisk),
			Args:                 op.Args,
			ArgsDigest:           op.ArgsDigest,
			Target:               op.Target,
			RequiredCapabilities: caps,
			Effect:               op.Effect,
			DeclaredRisk:         op.DeclaredRisk,
			EffectiveRisk:        op.EffectiveRisk,
			Reversible:           op.Meta.Undo != "",
			Undo:                 op.Meta.Undo,
			RequestedBy:          op.Actor,
			ApprovalSummary:      op.Meta.ApprovalSummary,
			ApprovalDescription:  op.Meta.ApprovalDescription,
			PermissionMode:       w.mode.normalized(),
		},
		// Destructive approvals need a second factor (ADR-0004 D6).
		RequiresMFA: op.Effect == EffectDestructive,
		CreatedAt:   now,
		ExpiresAt:   expiresAt(now, s.cfg.ApprovalTTL),
	}
	if w.plan != nil {
		approval.PlanID = w.plan.ID
		if len(w.plan.Changes) > 0 || len(w.plan.Warnings) > 0 {
			approval.PluginPreview = &PluginPreview{Changes: w.plan.Changes, Warnings: w.plan.Warnings}
		}
	}
	return approval
}

// insertApproval writes the approval resource and its audit row.
func (s *Service) insertApproval(ctx context.Context, tx *storage.Tx, op *Operation, approval *Approval) error {
	rev, err := tx.Changed(ctx, storage.Change{Subject: approvalSubject(approval.ID), Kind: storage.Created})
	if err != nil {
		return err
	}
	approval.Revision = storage.Revision(rev)
	if err := insertApprovalRow(ctx, tx, approval); err != nil {
		return err
	}
	return audit(ctx, tx, AuditRecord{
		Actor: op.Actor, Action: "approval.request", Subject: approvalSubject(approval.ID),
		Outcome: AuditSuccess, OperationID: op.ID, NodeID: op.NodeID, TraceID: op.TraceID,
		RequestID: op.RequestID,
	}, map[string]any{
		"operation_id": op.ID, "effective_risk": op.EffectiveRisk,
		"requires_mfa": approval.RequiresMFA, "expires_at": approval.ExpiresAt,
	})
}

// checkPlanPreconditions compares the host-side preconditions of a plan with
// the current revisions inside the operation's transaction (ADR-0004 D7).
func (s *Service) checkPlanPreconditions(ctx context.Context, tx *storage.Tx, plan *Plan) error {
	if len(plan.Preconditions) == 0 {
		return nil
	}
	if s.revisions == nil {
		return problem.Wrap(errNoRevisions)
	}
	failed := make([]problem.FailedPrecondition, 0, len(plan.Preconditions))
	for _, p := range plan.Preconditions {
		current, err := s.revisions.CurrentRevision(ctx, tx, p.Subject)
		if err != nil {
			return problem.Wrap(err)
		}
		if current != p.Revision {
			failed = append(failed, problem.FailedPrecondition{
				Subject: p.Subject, ExpectedRevision: p.Revision, CurrentRevision: current,
			})
		}
	}
	if len(failed) > 0 {
		return &problem.Error{
			Code:                problem.PreconditionFailed,
			Detail:              "The plan's preconditions no longer hold; create a new plan.",
			FailedPreconditions: failed,
		}
	}
	return nil
}

// runFingerprint is the idempotency fingerprint of a Run request.
func runFingerprint(req RunRequest, act Action, args []byte) string {
	if req.Idempotency.Fingerprint != "" {
		return req.Idempotency.Fingerprint
	}
	return fingerprintOf("run", act.ID, json.RawMessage(args), req.Target, req.ExpectedRevision)
}

// riskCapError is the PERMISSION_DENIED of a delegation whose max_risk is lower
// than the action's effective risk (ADR-0004 D6).
func riskCapError(effectiveRisk string) *problem.Error {
	return &problem.Error{
		Code:          problem.PermissionDenied,
		Detail:        "The caller's policy does not allow operations of this risk.",
		EffectiveRisk: effectiveRisk,
	}
}

// withOperationID attaches the operation ID to an error's Problem so the
// client can follow it.
func withOperationID(err error, id string) error {
	if err == nil || id == "" {
		return err
	}
	p := problem.From(err)
	if p.OperationID == "" {
		p.OperationID = id
	}
	return p
}
