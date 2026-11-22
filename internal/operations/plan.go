// SPDX-License-Identifier: AGPL-3.0-only

package operations

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"

	"github.com/qwq-panel/qwq/internal/actor"
	"github.com/qwq-panel/qwq/internal/platform/ids"
	"github.com/qwq-panel/qwq/internal/platform/problem"
	"github.com/qwq-panel/qwq/internal/storage"
)

// PlanRequest is one CreatePlan call (OpenAPI PlanRequest). Plans are
// side-effect free and exempt from idempotency keys.
type PlanRequest struct {
	Actor            actor.Actor
	TraceID          string
	RequestID        string
	Locale           string
	NodeID           string
	Action           string
	Args             json.RawMessage
	Target           Target
	ExpectedRevision string
}

// ExecutePlanRequest executes a plan that was created earlier
// (OpenAPI executePlan).
type ExecutePlanRequest struct {
	Actor       actor.Actor
	PlanID      string
	NodeID      string
	TraceID     string
	RequestID   string
	Locale      string
	Idempotency Idempotency
}

// CreatePlan validates the arguments, asks the plugin's PlanOperation (or the
// host action's planner) for a preview, computes the effective risk and records
// the preconditions (ADR-0004 D7).
func (s *Service) CreatePlan(ctx context.Context, req PlanRequest) (*Plan, error) {
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
	args, err := canonicalObject(req.Args)
	if err != nil {
		return nil, problem.Validation(violation("/args", "INVALID_JSON", "Arguments must be a JSON object."))
	}
	if err := validateArgs(act, args); err != nil {
		return nil, err
	}
	effectiveRisk := act.EffectiveRisk()

	if err := s.authorize(ctx, req.Actor, act, req.Target); err != nil {
		return nil, err
	}
	limits, err := s.limits(ctx, req.Actor, act, req.Target)
	if err != nil {
		return nil, err
	}
	if limits.MaxRisk != "" && riskRank(effectiveRisk) > riskRank(limits.MaxRisk) {
		return nil, riskCapError(effectiveRisk)
	}
	// A plan is a preview, so a read_only session may still create one for a
	// write action; the execution path refuses it instead (ADR-0010 §2.1).
	decision := act.DecideApproval(req.Actor, effectiveRisk, limits)

	hostPreconds, pluginPreconds, err := s.planPreconditions(act, req)
	if err != nil {
		return nil, err
	}

	sensitive, err := s.argumentsSensitive(act, args)
	if err != nil {
		return nil, err
	}
	args, cleanup, err := s.protectArguments(ctx, act, args, sensitive)
	if err != nil {
		return nil, err
	}
	retained := false
	defer func() {
		if !retained {
			s.discardArguments(ctx, cleanup)
		}
	}()
	req.Args = args
	digest := digestOf(args)
	preview, plannable, err := s.preview(ctx, act, req, args)
	if err != nil {
		return nil, err
	}
	changes, err := s.planChanges(act, req.Target, preview.Changes)
	if err != nil {
		return nil, err
	}
	if act.Source == PluginSource {
		for _, p := range preview.Preconditions {
			if err := validateRelativeSubject(p.Subject); err != nil {
				return nil, problem.FromPlugin("INVALID_SUBJECT", "The plugin returned an invalid precondition subject.", false, nil)
			}
			pluginPreconds = append(pluginPreconds, p)
		}
	} else {
		hostPreconds = append(hostPreconds, preview.Preconditions...)
	}
	pluginPreconds = dedupePreconditions(pluginPreconds)
	hostPreconds = dedupePreconditions(hostPreconds)

	now := s.clock.Now().UTC().Truncate(time.Millisecond)
	nodeID := req.Target.NodeID
	if nodeID == "" {
		nodeID = req.NodeID
	}
	plan := &Plan{
		ID:                  s.ids.New(ids.Plan),
		Action:              act.ID,
		Target:              req.Target,
		Args:                args,
		ArgsDigest:          digest,
		Plannable:           plannable,
		Changes:             changes,
		Violations:          preview.Violations,
		Warnings:            preview.Warnings,
		Preconditions:       hostPreconds,
		PluginPreconditions: pluginPreconds,
		EffectiveRisk:       effectiveRisk,
		RequiresApproval:    decision.NeedApproval,
		RequiresMFA:         act.Effect == EffectDestructive,
		Executable:          len(preview.Violations) == 0,
		Owner:               req.Actor,
		Meta:                act,
		RequestID:           req.RequestID,
		TraceID:             req.TraceID,
		CreatedAt:           now,
		ExpiresAt:           expiresAt(now, s.cfg.PlanTTL),
	}
	err = s.db.Update(ctx, func(tx *storage.Tx) error {
		tx.SetOrigin(s.origin(req.Actor, "", req.TraceID, nodeID))
		rev, err := tx.Changed(ctx, storage.Change{Subject: planSubject(plan.ID), Kind: storage.Created})
		if err != nil {
			return err
		}
		plan.Revision = storage.Revision(rev)
		return insertPlanRow(ctx, tx, plan)
	})
	if err != nil {
		return nil, problem.From(err)
	}
	retained = true
	return plan, nil
}

// planPreconditions turns the caller's expected_revision into a host-side or a
// plugin-side precondition.
func (s *Service) planPreconditions(act Action, req PlanRequest) (host, plugin []Precondition, err error) {
	if req.ExpectedRevision == "" {
		return nil, nil, nil
	}
	if req.Target.Subject == "" {
		return nil, nil, problem.Validation(violation("/target/subject", "REQUIRED",
			"expected_revision needs a target subject."))
	}
	if act.Source == HostSource {
		return []Precondition{{Subject: req.Target.Subject, Revision: req.ExpectedRevision}}, nil, nil
	}
	rel, ok := pluginRelativeSubjectFor(act, req.Target, req.Target.Subject)
	if !ok {
		return nil, nil, problem.Validation(violation("/target/subject", "INVALID_SUBJECT",
			"The subject is not one of the plugin instance's resources."))
	}
	return nil, []Precondition{{Subject: rel, Revision: req.ExpectedRevision}}, nil
}

// preview asks the host planner or the plugin for a structured preview. A
// non-plannable action still gets a plan with no changes (OpenAPI createPlan).
func (s *Service) preview(ctx context.Context, act Action, req PlanRequest, args []byte) (Preview, bool, error) {
	hostReq := HostRequest{
		Actor: req.Actor, TraceID: req.TraceID, RequestID: req.RequestID, Action: act,
		Target: req.Target, Args: args, ExpectedRevision: req.ExpectedRevision,
	}
	if act.Source == HostSource {
		registered, ok := s.hostAction(act.ID)
		if !ok || registered.planner == nil {
			return Preview{}, false, nil
		}
		var preview Preview
		err := s.db.View(ctx, func(tx *sql.Tx) error {
			var perr error
			preview, perr = registered.planner(ctx, tx, hostReq)
			return perr
		})
		if err != nil {
			return Preview{}, false, problem.From(err)
		}
		return preview, true, nil
	}
	if !act.Plannable {
		return Preview{}, false, nil
	}
	if s.dispatcher == nil {
		return Preview{}, false, problem.New(problem.Unavailable, "No plugin dispatcher is configured.")
	}
	preview, err := s.dispatcher.Plan(ctx, PluginPlanRequest{
		Actor: req.Actor, TraceID: req.TraceID, RequestID: req.RequestID, Locale: req.Locale,
		NodeID: req.Target.NodeID, PluginID: act.PluginID, InstanceID: req.Target.InstanceID,
		Placement: act.Placement, Operation: act.Operation, APIVersion: act.APIVersion, Payload: args,
	})
	if err != nil {
		return Preview{}, false, problem.From(err)
	}
	return preview, true, nil
}

// planChanges validates plugin-reported changes and turns their relative
// subjects into full ones (ADR-0007 #2). Host changes keep their subject.
func (s *Service) planChanges(act Action, target Target, changes []PlannedChange) ([]PlannedChange, error) {
	out := make([]PlannedChange, 0, len(changes))
	for _, c := range changes {
		// 公共序列化可关闭畸形输出，规划入口仍须拒绝非法插件预览。
		if (len(c.Before) > 0 && !json.Valid(c.Before)) || (len(c.After) > 0 && !json.Valid(c.After)) {
			return nil, problem.FromPlugin("INVALID_CHANGE", "The action reported invalid JSON in its change preview.", false, nil)
		}
		c.Source = string(act.Source)
		if act.Source == PluginSource {
			full, err := prefixPluginSubject(act.Placement, target.NodeID, act.PluginID, target.InstanceID, c.Subject)
			if err != nil {
				return nil, problem.FromPlugin("INVALID_SUBJECT",
					"The plugin reported an invalid change subject.", false, nil)
			}
			c.Subject = full
			c.PluginID = act.PluginID
		} else if c.Subject != "" {
			if err := validateFullSubject(c.Subject); err != nil {
				return nil, problem.Wrap(err)
			}
		}
		switch c.Kind {
		case "create", "update", "delete":
		default:
			return nil, problem.FromPlugin("INVALID_CHANGE", "The plugin reported an unknown change kind.", false, nil)
		}
		out = append(out, c)
	}
	return out, nil
}

// dedupePreconditions removes duplicates, keeping the first occurrence.
func dedupePreconditions(in []Precondition) []Precondition {
	if len(in) < 2 {
		return in
	}
	seen := make(map[Precondition]bool, len(in))
	out := in[:0]
	for _, p := range in {
		if seen[p] {
			continue
		}
		seen[p] = true
		out = append(out, p)
	}
	return out
}

// GetPlan returns a plan to the principal that created it (OpenAPI getPlan).
func (s *Service) GetPlan(ctx context.Context, a actor.Actor, id string) (*Plan, error) {
	plan, err := loadPlan(ctx, s.db.Reader(), id)
	if err != nil {
		return nil, err
	}
	if !samePrincipal(a, plan.Owner) && a.Kind != actor.System {
		return nil, notFound("plan")
	}
	return plan, nil
}

// ExecutePlan creates the operation a plan previewed. A plan executes at most
// once; an expired plan, blocking violations and stale preconditions fail
// before anything runs (ADR-0004 D7).
func (s *Service) ExecutePlan(ctx context.Context, req ExecutePlanRequest) (*Response, error) {
	if req.Actor.ID == "" || req.Actor.Valid() != nil {
		return nil, problem.New(problem.Unauthenticated, "The request has no valid actor.")
	}
	if req.Idempotency.Key == "" {
		return nil, missingIdempotencyKey()
	}
	if req.NodeID == "" {
		req.NodeID = s.nodeID
	}
	claim, replay, err := s.claimIdempotency(ctx, req.Actor, req.Idempotency, fingerprintOf("execute_plan", req.PlanID))
	if err != nil {
		return nil, err
	}
	if replay != nil {
		s.hydrateReplay(ctx, replay)
		return replay, nil
	}
	resp, execErr := s.executePlan(ctx, req, claim)
	s.finishIdempotency(ctx, claim, resp, execErr, req.RequestID, req.Idempotency.Route)
	return resp, execErr
}

func (s *Service) executePlan(ctx context.Context, req ExecutePlanRequest, claim *idemClaim) (*Response, error) {
	plan, err := loadPlan(ctx, s.db.Reader(), req.PlanID)
	if err != nil {
		return nil, err
	}
	if !samePrincipal(req.Actor, plan.Owner) && req.Actor.Kind != actor.System {
		return nil, notFound("plan")
	}
	if plan.OperationID != "" {
		return nil, &problem.Error{
			Code:        problem.StateConflict,
			Detail:      "The plan was already executed.",
			OperationID: plan.OperationID,
		}
	}
	if !plan.ExpiresAt.After(s.clock.Now().UTC()) {
		return nil, problem.New(problem.PlanExpired, "The plan expired; create a new one.")
	}
	if len(plan.Violations) > 0 {
		return nil, problem.Validation(plan.Violations...)
	}
	act := plan.Meta
	if act.ID == "" {
		act.ID = plan.Action
	}
	act = act.normalized(s.defaultTimeout(act.Mode))
	if err := act.validate(); err != nil {
		return nil, problem.Wrap(err)
	}
	if err := s.authorize(ctx, req.Actor, act, plan.Target); err != nil {
		return nil, err
	}
	limits, err := s.limits(ctx, req.Actor, act, plan.Target)
	if err != nil {
		return nil, err
	}
	if limits.MaxRisk != "" && riskRank(plan.EffectiveRisk) > riskRank(limits.MaxRisk) {
		return nil, riskCapError(plan.EffectiveRisk)
	}
	decision := act.DecideApproval(req.Actor, plan.EffectiveRisk, limits)
	if decision.Denied {
		return nil, permissionModeDenied(act, limits.Mode())
	}
	needApproval := plan.RequiresApproval || decision.NeedApproval
	if needApproval && limits.OnApprovalRequired == ApprovalFail {
		return nil, &problem.Error{
			Code:          problem.ApprovalRequired,
			Detail:        "This plan needs a human approval and the caller's policy does not queue them.",
			EffectiveRisk: plan.EffectiveRisk,
		}
	}
	w := &writeRequest{
		req: RunRequest{
			Actor: req.Actor, TraceID: req.TraceID, RequestID: req.RequestID, NodeID: req.NodeID,
			Locale: req.Locale, Action: plan.Action, Target: plan.Target, Args: plan.Args,
			ExpectedRevision: hostExpectedRevision(plan), Idempotency: req.Idempotency,
		},
		act: act, args: plan.Args, digest: plan.ArgsDigest, effectiveRisk: plan.EffectiveRisk,
		needApproval: needApproval, mode: limits.Mode(), plan: plan, claim: claim,
	}
	return s.runWrite(ctx, w)
}

// hostExpectedRevision returns the plan's precondition on its own subject, so a
// host handler still sees expected_revision. Plugin-side preconditions travel in
// the operation itself.
func hostExpectedRevision(plan *Plan) string {
	if plan.Meta.Source != HostSource || plan.Target.Subject == "" {
		return ""
	}
	for _, p := range plan.Preconditions {
		if p.Subject == plan.Target.Subject {
			return p.Revision
		}
	}
	return ""
}
