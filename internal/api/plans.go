// SPDX-License-Identifier: AGPL-3.0-only

package api

import (
	"encoding/json"
	"net/http"

	"github.com/qwq-panel/qwq/internal/operations"
	"github.com/qwq-panel/qwq/internal/platform/problem"
)

// planRequest is the PlanRequest schema: the action, its arguments and the
// optional concurrency guard.
type planRequest struct {
	Action           string          `json:"action"`
	Args             json.RawMessage `json:"args"`
	Target           *targetInput    `json:"target,omitempty"`
	ExpectedRevision string          `json:"expected_revision,omitempty"`
}

// targetInput is the TargetInput schema.
type targetInput struct {
	NodeID     string `json:"node_id,omitempty"`
	PluginID   string `json:"plugin_id,omitempty"`
	InstanceID string `json:"instance_id,omitempty"`
	Subject    string `json:"subject,omitempty"`
}

// createPlan previews an action without side effects. The plan is bound to the
// caller and later executed with executePlan.
func (a *api) createPlan(w http.ResponseWriter, r *http.Request) {
	act, err := a.caller(r)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	var req planRequest
	if err := a.decodeJSON(r, &req); err != nil {
		a.fail(w, r, err)
		return
	}
	if err := requireFields(map[string]string{"/action": req.Action}); err != nil {
		a.fail(w, r, err)
		return
	}
	if !isJSONObject(req.Args) {
		a.fail(w, r, problem.Validation(problem.Violation{
			Pointer: "/args", Code: "REQUIRED", Message: "args must be a JSON object.",
		}))
		return
	}
	target := operations.Target{}
	if req.Target != nil {
		target = operations.Target{
			NodeID:     req.Target.NodeID,
			PluginID:   req.Target.PluginID,
			InstanceID: req.Target.InstanceID,
			Subject:    req.Target.Subject,
		}
	}
	plan, err := a.d.Ops.CreatePlan(r.Context(), operations.PlanRequest{
		Actor:            act,
		TraceID:          traceID(r),
		RequestID:        requestID(r),
		NodeID:           a.d.NodeID,
		Action:           req.Action,
		Args:             req.Args,
		Target:           target,
		ExpectedRevision: req.ExpectedRevision,
	})
	if err != nil {
		a.fail(w, r, err)
		return
	}
	w.Header().Set("Location", "/api/v1/plans/"+plan.ID)
	a.writeResource(w, r, http.StatusCreated, newPlanDTO(plan), nil)
}

// getPlan returns a plan to the principal that created it.
func (a *api) getPlan(w http.ResponseWriter, r *http.Request) {
	act, err := a.caller(r)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	if err := a.authorize(r.Context(), act, "host.plans:read", ""); err != nil {
		a.fail(w, r, err)
		return
	}
	plan, err := a.d.Ops.GetPlan(r.Context(), act, r.PathValue("plan_id"))
	if err != nil {
		a.fail(w, r, err)
		return
	}
	fields, err := a.fields(r)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	a.writeResource(w, r, http.StatusOK, newPlanDTO(plan), fields)
}

// executePlan creates the operation a plan previewed. A plan executes at most
// once; the operation manager owns the expiry and precondition checks.
func (a *api) executePlan(w http.ResponseWriter, r *http.Request) {
	act, err := a.caller(r)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	idem, err := a.idempotency(r, r.PathValue("plan_id"))
	if err != nil {
		a.fail(w, r, err)
		return
	}
	resp, err := a.d.Ops.ExecutePlan(r.Context(), operations.ExecutePlanRequest{
		Actor:       act,
		PlanID:      r.PathValue("plan_id"),
		NodeID:      a.d.NodeID,
		TraceID:     traceID(r),
		RequestID:   requestID(r),
		Idempotency: idem,
	})
	if err != nil {
		a.fail(w, r, err)
		return
	}
	a.writeOperationResponse(w, resp)
}
