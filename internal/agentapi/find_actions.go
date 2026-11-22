// SPDX-License-Identifier: AGPL-3.0-only

package agentapi

import (
	"net/http"

	"github.com/qwq-panel/qwq/internal/catalog"
)

// findActionsRequest is the FindActionsRequest schema.
type findActionsRequest struct {
	Query string            `json:"query"`
	Scope *findActionsScope `json:"scope,omitempty"`
	Limit int               `json:"limit,omitempty"`
}

// findActionsScope is FindActionsRequest.scope.
type findActionsScope struct {
	PluginID string `json:"plugin_id,omitempty"`
	NodeID   string `json:"node_id,omitempty"`
	Effect   string `json:"effect,omitempty"`
}

// findActionsResponse is the FindActionsResponse schema. catalog.Brief already
// carries the ActionSummary members (id, summary, effect, risk).
type findActionsResponse struct {
	Actions   []catalog.Brief `json:"actions"`
	Truncated bool            `json:"truncated"`
}

// check validates the request against the schema.
func (req *findActionsRequest) check() error {
	switch n := len([]rune(req.Query)); {
	case n == 0:
		return requiredField("/query", "A search query is required.")
	case n > 200:
		return wrongFormat("/query", "The query is longer than 200 characters.")
	}
	if req.Scope != nil {
		if req.Scope.PluginID != "" {
			if err := checkPluginID("/scope/plugin_id", req.Scope.PluginID); err != nil {
				return err
			}
		}
		if req.Scope.NodeID != "" {
			if err := checkNodeID("/scope/node_id", req.Scope.NodeID); err != nil {
				return err
			}
		}
		switch req.Scope.Effect {
		case "", "read", "write", "destructive":
		default:
			return wrongFormat("/scope/effect", "The effect must be read, write or destructive.")
		}
	}
	if req.Limit != 0 && (req.Limit < 1 || req.Limit > FindActionsMaxLimit) {
		return outOfRange("/limit", "The limit must be between 1 and 20.")
	}
	return nil
}

// findActions implements POST /api/v1/agent/find_actions: a local keyword
// search over the action catalog, filtered by the delegation's effective
// permission, with only id, summary, effect and risk per entry.
func (h *handlers) findActions(w http.ResponseWriter, r *http.Request) {
	c, err := h.begin(r)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	var req findActionsRequest
	if err := h.decode(r, &req); err != nil {
		h.fail(w, r, err)
		return
	}
	if err := req.check(); err != nil {
		h.fail(w, r, err)
		return
	}

	scope := catalog.Scope{}
	nodeID := ""
	if req.Scope != nil {
		scope.PluginID, scope.Effect = req.Scope.PluginID, req.Scope.Effect
		nodeID = req.Scope.NodeID
	}
	limit := req.Limit
	if limit == 0 {
		limit = FindActionsDefaultLimit
	}

	var (
		briefs    []catalog.Brief
		truncated bool
	)
	// This host manages one node (P1 is standalone). Asking for another node
	// cannot be answered truthfully by this catalog, so the result is empty
	// rather than a list of actions that execute would reject.
	if nodeID == "" || nodeID == h.nodeID {
		allow := func(e *catalog.Entry) bool {
			return c.view.allowsAction(e, h.actionNode(e))
		}
		briefs, truncated = h.catalog.Find(req.Query, scope, limit, allow)
	}
	if briefs == nil {
		briefs = []catalog.Brief{}
	}
	h.write(w, r, findActionsResponse{Actions: briefs, Truncated: truncated})
}

// actionNode is the node an action runs on: this host for a host action and a
// controller-placed plugin action, the managed node for a node-placed one.
func (h *handlers) actionNode(e *catalog.Entry) string {
	if e.Source == catalog.Plugin && e.Placement == "node" {
		return h.nodeID
	}
	return ""
}
