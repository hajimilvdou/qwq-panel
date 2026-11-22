// SPDX-License-Identifier: AGPL-3.0-only

package agentapi

import (
	"encoding/json"
	"net/http"

	"github.com/qwq-panel/qwq/internal/catalog"
	"github.com/qwq-panel/qwq/internal/platform/problem"
)

// maxDocsRunes is the maxLength of ActionDescription.docs.
const maxDocsRunes = 16384

// describeActionRequest is the DescribeActionRequest schema.
type describeActionRequest struct {
	ID                  string `json:"id"`
	IncludeDocs         bool   `json:"include_docs,omitempty"`
	IncludeResultSchema bool   `json:"include_result_schema,omitempty"`
}

// actionMeta is the ActionMeta schema: the catalog metadata of an action, with
// Risk as the effective risk and DeclaredRisk as what the author declared.
type actionMeta struct {
	ID           string `json:"id"`
	Summary      string `json:"summary"`
	Effect       string `json:"effect"`
	Risk         string `json:"risk"`
	DeclaredRisk string `json:"declared_risk"`
	Mode         string `json:"mode"`
	Idempotent   bool   `json:"idempotent"`
	Plannable    bool   `json:"plannable"`
	Undo         string `json:"undo,omitempty"`
	UIRoute      string `json:"ui_route,omitempty"`
	Permission   string `json:"permission,omitempty"`
	TimeoutMS    int    `json:"timeout_ms,omitempty"`
	Source       string `json:"source"`
	PluginID     string `json:"plugin_id,omitempty"`
	Placement    string `json:"placement,omitempty"`
	// Reachability: the action can cut the administrator off (ADR-0016).
	Reachability bool `json:"reachability,omitempty"`
}

// actionTarget says which Target members plan and execute need.
type actionTarget struct {
	NodeID     bool `json:"node_id"`
	PluginID   bool `json:"plugin_id"`
	InstanceID bool `json:"instance_id"`
	Subject    bool `json:"subject"`
}

// actionDescription is the ActionDescription schema.
type actionDescription struct {
	Action        actionMeta      `json:"action"`
	Target        actionTarget    `json:"target"`
	ArgsSchema    json.RawMessage `json:"args_schema"`
	ResultSchema  json.RawMessage `json:"result_schema,omitempty"`
	Docs          string          `json:"docs,omitempty"`
	DocsTruncated bool            `json:"docs_truncated,omitempty"`
}

// check validates the request against the schema.
func (req *describeActionRequest) check() error {
	return checkActionID("/id", req.ID)
}

// describeAction implements POST /api/v1/agent/describe_action. Looking at an
// action outside the delegation's effective permission answers 404, exactly
// like an unknown ID, so the catalog is not an existence oracle.
func (h *handlers) describeAction(w http.ResponseWriter, r *http.Request) {
	c, err := h.begin(r)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	var req describeActionRequest
	if err := h.decode(r, &req); err != nil {
		h.fail(w, r, err)
		return
	}
	if err := req.check(); err != nil {
		h.fail(w, r, err)
		return
	}

	entry, ok := h.catalog.Get(req.ID)
	if !ok || !c.view.allowsAction(entry, h.actionNode(entry)) {
		h.fail(w, r, problem.New(problem.NotFound, "No such action."))
		return
	}
	desc := actionDescription{
		Action:     metaOf(entry),
		Target:     targetOf(entry),
		ArgsSchema: schemaOf(entry.ArgsSchema),
	}
	if req.IncludeResultSchema {
		desc.ResultSchema = schemaOf(entry.ResultSchema)
	}
	if req.IncludeDocs {
		desc.Docs, desc.DocsTruncated = h.loadDocs(r, entry)
	}
	h.write(w, r, desc)
}

// loadDocs returns the bundled documentation of a plugin action, cut to the
// schema limit. A loader failure is logged and treated as "no docs": the tool
// still answers, because documentation is optional data.
func (h *handlers) loadDocs(r *http.Request, entry *catalog.Entry) (string, bool) {
	if h.docs == nil || entry.Docs == "" {
		return "", false
	}
	raw, err := h.docs(r.Context(), entry)
	if err != nil {
		h.log.WarnContext(r.Context(), "agent tool: load plugin docs",
			"action", entry.ID, "plugin_id", entry.PluginID, "error", err)
		return "", false
	}
	text := string(raw)
	clipped, truncated := clipRunes(text, maxDocsRunes)
	return clipped, truncated
}

// metaOf converts a catalog entry to the ActionMeta schema.
func metaOf(e *catalog.Entry) actionMeta {
	return actionMeta{
		ID:           e.ID,
		Summary:      e.Summary,
		Effect:       e.Effect,
		Risk:         e.Risk,
		DeclaredRisk: e.DeclaredRisk,
		Mode:         e.Mode,
		Idempotent:   e.Idempotent,
		Plannable:    e.Plannable,
		Undo:         e.Undo,
		UIRoute:      e.UIRoute,
		Permission:   e.Permission,
		TimeoutMS:    e.TimeoutMS,
		Source:       string(e.Source),
		PluginID:     e.PluginID,
		Placement:    e.Placement,
		Reachability: e.Reachability,
	}
}

// targetOf derives the required Target members from the placement. Host
// actions take an optional subject and nothing else; a node-placed plugin
// action needs the node and the instance; a controller-placed one needs only
// the plugin.
func targetOf(e *catalog.Entry) actionTarget {
	if e.Source != catalog.Plugin {
		return actionTarget{}
	}
	if e.Placement == "node" {
		return actionTarget{NodeID: true, PluginID: true, InstanceID: true}
	}
	return actionTarget{PluginID: true}
}

// schemaOf returns the schema, or an empty object schema when the action has
// none, so `args_schema` is always a JSON object.
func schemaOf(raw json.RawMessage) json.RawMessage {
	if len(raw) == 0 {
		return json.RawMessage(`{"type":"object"}`)
	}
	return raw
}
