// SPDX-License-Identifier: AGPL-3.0-only

package api

import (
	"encoding/json"
	"net/http"
	"regexp"
	"strconv"

	"github.com/qwq-panel/qwq/internal/authz"
	"github.com/qwq-panel/qwq/internal/catalog"
	"github.com/qwq-panel/qwq/internal/platform/problem"
)

// The action catalog for people (GAPS gap 5). AI operators keep their own
// /api/v1/agent/find_actions, which answers for a delegation; these two routes
// answer for the signed-in person, so the gateway admits a browser session only
// and the filter is the person's role. Routes marked x-qwq-action-exempt never
// enter the catalog, so secret-carrying actions cannot appear here.

// Paging limits of GET /actions (GAPS gap 5), not the collection list limits:
// a search page is short because a person reads it.
const (
	actionsDefaultLimit = 20
	actionsMaxLimit     = 50
	actionsMaxQuery     = 200
)

var (
	actionIDPattern = regexp.MustCompile(`^(host\.[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+|[a-z][a-z0-9]*([.-][a-z0-9]+)*/[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)*)$`)
	pluginIDPattern = regexp.MustCompile(`^[a-z][a-z0-9]*([.-][a-z0-9]+)*$`)
)

// actionList is the ActionList schema.
type actionList struct {
	Items     []pluginActionDTO `json:"items"`
	Truncated bool              `json:"truncated"`
}

// actionDetail is the ActionDetail schema: the catalog metadata plus the
// argument schema, which a list leaves out to stay small.
type actionDetail struct {
	pluginActionDTO
	RequestSchema json.RawMessage `json:"request_schema"`
}

// actionsQuery is the parsed query of GET /actions.
type actionsQuery struct {
	query    string
	pluginID string
	effect   string
	limit    int
}

// parseActionsQuery validates the search parameters. Violations point at the
// query parameter that failed.
func parseActionsQuery(r *http.Request) (actionsQuery, error) {
	q := r.URL.Query()
	out := actionsQuery{limit: actionsDefaultLimit}
	out.query = q.Get("q")
	if n := len([]rune(out.query)); n > actionsMaxQuery {
		return out, queryViolation("/q", "INVALID", "The query is longer than 200 characters.")
	}
	out.pluginID = q.Get("plugin_id")
	if out.pluginID != "" && (len(out.pluginID) > 128 || !pluginIDPattern.MatchString(out.pluginID)) {
		return out, queryViolation("/plugin_id", "INVALID", "A plugin ID is lower-case letters, digits, '.' and '-'.")
	}
	out.effect = q.Get("effect")
	switch out.effect {
	case "", "read", "write", "destructive":
	default:
		return out, queryViolation("/effect", "INVALID", "The effect must be read, write or destructive.")
	}
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > actionsMaxLimit {
			return out, queryViolation("/limit", "OUT_OF_RANGE", "The limit must be an integer between 1 and 50.")
		}
		out.limit = n
	}
	return out, nil
}

func queryViolation(pointer, code, message string) error {
	return problem.Validation(problem.Violation{In: "query", Pointer: pointer, Code: code, Message: message})
}

// actionRole is the role the catalog is filtered by. A disabled account has no
// role, so it sees nothing.
func (a *api) actionRole(r *http.Request) (authz.Role, error) {
	act, err := a.caller(r)
	if err != nil {
		return "", err
	}
	role, disabled, err := a.d.Identity.PrincipalRole(r.Context(), act.ID)
	if err != nil {
		return "", problem.From(err)
	}
	if disabled {
		return "", problem.New(problem.PermissionDenied, "The account is disabled.")
	}
	return authz.Role(role), nil
}

// actionAllow is the RBAC filter of the catalog: an action the person's role
// does not grant is not offered, and its detail answers 404 like an unknown ID.
func actionAllow(role authz.Role) catalog.Allow {
	return func(e *catalog.Entry) bool {
		perm, err := authz.ParsePermission(e.Permission)
		if err != nil {
			return false
		}
		return authz.RoleAllows(role, perm)
	}
}

// listActions implements GET /api/v1/actions: the catalog search a person uses
// to find what they may run. Execution stays on the existing routes.
func (a *api) listActions(w http.ResponseWriter, r *http.Request) {
	role, err := a.actionRole(r)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	q, err := parseActionsQuery(r)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	entries, truncated := a.d.Catalog.Search(q.query, catalog.Scope{PluginID: q.pluginID, Effect: q.effect},
		q.limit, actionAllow(role))
	items := make([]pluginActionDTO, 0, len(entries))
	for _, e := range entries {
		items = append(items, newPluginActionDTO(e))
	}
	a.writeResource(w, r, http.StatusOK, actionList{Items: items, Truncated: truncated}, nil)
}

// getAction implements GET /api/v1/actions/{action_id}. The ID carries a '/',
// so clients percent-encode it; ServeMux unescapes one segment at a time.
func (a *api) getAction(w http.ResponseWriter, r *http.Request) {
	role, err := a.actionRole(r)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	id := r.PathValue("action_id")
	if len(id) > 200 || !actionIDPattern.MatchString(id) {
		a.fail(w, r, problem.Validation(problem.Violation{
			Pointer: "/action_id", Code: "INVALID",
			Message: "An action ID is a host.<resource>.<verb> ID or <plugin_id>/<operation>.",
		}))
		return
	}
	e, ok := a.d.Catalog.Get(id)
	if !ok || !actionAllow(role)(e) {
		a.fail(w, r, problem.New(problem.NotFound, "No such action."))
		return
	}
	schema := e.ArgsSchema
	if len(schema) == 0 {
		schema = json.RawMessage(`{"type":"object"}`)
	}
	a.writeResource(w, r, http.StatusOK, actionDetail{pluginActionDTO: newPluginActionDTO(e), RequestSchema: schema}, nil)
}
