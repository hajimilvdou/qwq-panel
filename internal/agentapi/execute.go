// SPDX-License-Identifier: AGPL-3.0-only

package agentapi

import (
	"encoding/json"
	"net/http"

	"github.com/qwq-panel/qwq/internal/operations"
)

// executeRequest is the ExecuteRequest schema. The document deliberately uses a
// plain object instead of oneOf (function-calling APIs need a flat schema), so
// the host enforces "plan_id, or action + args" itself.
type executeRequest struct {
	PlanID           string          `json:"plan_id,omitempty"`
	Action           string          `json:"action,omitempty"`
	Args             json.RawMessage `json:"args,omitempty"`
	Target           *targetInput    `json:"target,omitempty"`
	ExpectedRevision string          `json:"expected_revision,omitempty"`
}

// check enforces the exactly-one-form rule and validates each form.
func (req *executeRequest) check() error {
	byPlan, byAction := req.PlanID != "", req.Action != ""
	switch {
	case byPlan && byAction:
		return invalid("/plan_id", "CONFLICT", "Give either plan_id or action, not both.")
	case !byPlan && !byAction:
		return requiredField("/plan_id", "Give plan_id, or action with args.")
	}
	if byPlan {
		if err := checkResourceID("/plan_id", req.PlanID); err != nil {
			return err
		}
		if req.Args != nil || req.Target != nil || req.ExpectedRevision != "" {
			return invalid("/plan_id", "CONFLICT",
				"plan_id already carries the arguments, target and revision recorded by plan.")
		}
		return nil
	}
	if err := checkActionID("/action", req.Action); err != nil {
		return err
	}
	if err := checkArgs("/args", req.Args); err != nil {
		return err
	}
	if req.Target != nil {
		if err := req.Target.check("/target"); err != nil {
			return err
		}
	}
	if req.ExpectedRevision != "" {
		if req.Target == nil || req.Target.Subject == "" {
			return requiredField("/target/subject", "expected_revision needs a target subject.")
		}
		if err := checkRevisionField("/expected_revision", req.ExpectedRevision); err != nil {
			return err
		}
	}
	return nil
}

// execute implements POST /api/v1/agent/execute: it creates the operation a
// plan previewed, or one described by action + args, and answers 200 with an
// OperationOutcome whatever the operation's state is. Policy decides what
// happens next (read runs directly, low runs and notifies, medium and high stop
// at AWAITING_APPROVAL), and the caller follows up with wait.
func (h *handlers) execute(w http.ResponseWriter, r *http.Request) {
	c, err := h.begin(r)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	var req executeRequest
	if err := h.decode(r, &req); err != nil {
		h.fail(w, r, err)
		return
	}
	if err := req.check(); err != nil {
		h.fail(w, r, err)
		return
	}
	key, err := h.toolKey(r, "execute")
	if err != nil {
		h.fail(w, r, err)
		return
	}
	idem := operations.Idempotency{Key: key, Method: http.MethodPost, Route: "/api/v1/agent/execute"}

	var resp *operations.Response
	if req.PlanID != "" {
		resp, err = h.ops.ExecutePlan(r.Context(), operations.ExecutePlanRequest{
			Actor:       c.actor,
			PlanID:      req.PlanID,
			NodeID:      h.nodeID,
			TraceID:     c.traceID,
			RequestID:   c.request,
			Idempotency: idem,
		})
	} else {
		resp, err = h.ops.Run(r.Context(), operations.RunRequest{
			Actor:            c.actor,
			TraceID:          c.traceID,
			RequestID:        c.request,
			NodeID:           h.nodeID,
			Action:           req.Action,
			Target:           req.Target.toTarget(),
			Args:             req.Args,
			ExpectedRevision: req.ExpectedRevision,
			Idempotency:      idem,
		})
	}
	if err != nil {
		h.fail(w, r, err)
		return
	}
	out, err := outcomeOf(resp)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	body, err := outcomeBody(out)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	h.write(w, r, body)
}
