// SPDX-License-Identifier: AGPL-3.0-only

package agentapi

import (
	"encoding/json"
	"net/http"

	"github.com/qwq-panel/qwq/internal/operations"
)

// targetInput is the TargetInput schema: where an action runs.
type targetInput struct {
	NodeID     string `json:"node_id,omitempty"`
	PluginID   string `json:"plugin_id,omitempty"`
	InstanceID string `json:"instance_id,omitempty"`
	Subject    string `json:"subject,omitempty"`
}

// check validates the members against their schemas. The action-specific rules
// (which members the placement needs) belong to internal/operations, which
// owns the catalog metadata.
func (t *targetInput) check(pointer string) error {
	if t.NodeID != "" {
		if err := checkNodeID(pointer+"/node_id", t.NodeID); err != nil {
			return err
		}
	}
	if t.PluginID != "" {
		if err := checkPluginID(pointer+"/plugin_id", t.PluginID); err != nil {
			return err
		}
	}
	if t.InstanceID != "" {
		if err := checkInstanceID(pointer+"/instance_id", t.InstanceID); err != nil {
			return err
		}
	}
	if t.Subject != "" {
		if err := checkSubjectAt(pointer+"/subject", t.Subject); err != nil {
			return err
		}
	}
	return nil
}

// toTarget converts the request member to the operations type.
func (t *targetInput) toTarget() operations.Target {
	if t == nil {
		return operations.Target{}
	}
	return operations.Target{
		NodeID:     t.NodeID,
		PluginID:   t.PluginID,
		InstanceID: t.InstanceID,
		Subject:    t.Subject,
	}
}

// planRequest is the PlanRequest schema.
type planRequest struct {
	Action           string          `json:"action"`
	Args             json.RawMessage `json:"args"`
	Target           *targetInput    `json:"target,omitempty"`
	ExpectedRevision string          `json:"expected_revision,omitempty"`
}

// check validates the request against the schema.
func (req *planRequest) check() error {
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

// plan implements POST /api/v1/agent/plan: the same preview as
// POST /api/v1/plans, with 200 for tool callers. Nothing is created except the
// short-lived plan record.
func (h *handlers) plan(w http.ResponseWriter, r *http.Request) {
	c, err := h.begin(r)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	var req planRequest
	if err := h.decode(r, &req); err != nil {
		h.fail(w, r, err)
		return
	}
	if err := req.check(); err != nil {
		h.fail(w, r, err)
		return
	}
	preview, err := h.ops.CreatePlan(r.Context(), operations.PlanRequest{
		Actor:            c.actor,
		TraceID:          c.traceID,
		RequestID:        c.request,
		NodeID:           h.nodeID,
		Action:           req.Action,
		Args:             req.Args,
		Target:           req.Target.toTarget(),
		ExpectedRevision: req.ExpectedRevision,
	})
	if err != nil {
		h.fail(w, r, err)
		return
	}
	body, err := planBody(preview)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	h.write(w, r, body)
}

// checkArgs validates an `args` member: present and a JSON object.
func checkArgs(pointer string, args json.RawMessage) error {
	if args == nil {
		return requiredField(pointer, "Arguments are required; pass {} for an action without arguments.")
	}
	var object map[string]any
	if err := json.Unmarshal(args, &object); err != nil || object == nil {
		return wrongFormat(pointer, "Arguments must be a JSON object.")
	}
	return nil
}
