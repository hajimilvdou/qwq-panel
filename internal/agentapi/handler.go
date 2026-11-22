// SPDX-License-Identifier: AGPL-3.0-only

package agentapi

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"regexp"
	"unicode/utf8"

	"github.com/qwq-panel/qwq/internal/actor"
	"github.com/qwq-panel/qwq/internal/authz"
	"github.com/qwq-panel/qwq/internal/catalog"
	"github.com/qwq-panel/qwq/internal/gateway"
	"github.com/qwq-panel/qwq/internal/identity"
	"github.com/qwq-panel/qwq/internal/operations"
	"github.com/qwq-panel/qwq/internal/platform/clock"
	"github.com/qwq-panel/qwq/internal/platform/ids"
	"github.com/qwq-panel/qwq/internal/platform/problem"
	"github.com/qwq-panel/qwq/internal/storage"
)

// Patterns of the public schemas this package decodes. They are the patterns of
// api/public/v1/openapi.yaml; anything else is VALIDATION_FAILED before a
// service is called, so a malformed request never reaches SQL.
var (
	actionIDRe   = regexp.MustCompile(`^(host\.[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+|[a-z][a-z0-9]*([.-][a-z0-9]+)*/[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)*)$`)
	resourceIDRe = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)
	nodeIDRe     = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?$`)
	pluginIDRe   = regexp.MustCompile(`^[a-z][a-z0-9]*([.-][a-z0-9]+)*$`)
	instanceIDRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9_-]*[a-z0-9])?$`)
	subjectRe    = regexp.MustCompile(`^[a-z][a-z0-9_-]*(/[A-Za-z0-9._~:@-]+)*$`)
	revisionRe   = regexp.MustCompile(`^[A-Za-z0-9._~-]+$`)
	pointerRe    = regexp.MustCompile(`^(/([^/~]|~[01])*)*$`)
)

// handlers carries the dependencies of the seven tools.
type handlers struct {
	gw       *gateway.Gateway
	db       *storage.DB
	clock    clock.Clock
	ids      *ids.Generator
	log      *slog.Logger
	identity *identity.Service
	authz    *authz.Authorizer
	ops      *operations.Service
	catalog  *catalog.Catalog
	nodeID   string
	docs     DocsLoader
	waits    *waitLimiter
}

func newHandlers(g *gateway.Gateway, d Deps) *handlers {
	return &handlers{
		gw:       g,
		db:       d.DB,
		clock:    d.Clock,
		ids:      d.IDs,
		log:      d.Logger,
		identity: d.Identity,
		authz:    d.Authz,
		ops:      d.Ops,
		catalog:  d.Catalog,
		nodeID:   d.NodeID,
		docs:     d.Docs,
		waits:    newWaitLimiter(ConcurrentWaitsPerDelegation),
	}
}

// call is the authenticated context of one tool request.
type call struct {
	actor   actor.Actor
	view    *delegationView
	traceID string
	request string
}

// begin resolves the principal, requires a delegation and loads its effective
// permission. Every tool calls it first, so a suspended or expired delegation
// is denied by all seven tools even if a route were wired with another access
// policy by mistake.
func (h *handlers) begin(r *http.Request) (*call, error) {
	p, ok := gateway.PrincipalFrom(r.Context())
	if !ok {
		return nil, problem.New(problem.Unauthenticated, "The request has no credentials.")
	}
	if p.Scheme != gateway.SchemeDelegation || p.Actor.Kind != actor.AIAgent {
		return nil, problem.New(problem.PermissionDenied,
			"This route accepts a delegation bearer token only.")
	}
	view, err := h.delegationView(r.Context(), p.Actor)
	if err != nil {
		return nil, err
	}
	return &call{
		actor:   p.Actor,
		view:    view,
		traceID: gateway.TraceID(r.Context()),
		request: gateway.RequestID(r.Context()),
	}, nil
}

// decode reads the request body through the gateway decoder: bounded size,
// bounded nesting, unknown members and type mismatches reported as
// VALIDATION_FAILED with JSON Pointers.
func (h *handlers) decode(r *http.Request, dst any) error {
	return h.gw.DecodeJSON(r, dst)
}

// write sends a 200 JSON response.
func (h *handlers) write(w http.ResponseWriter, r *http.Request, v any) {
	if err := gateway.WriteJSON(w, http.StatusOK, v); err != nil {
		h.log.WarnContext(r.Context(), "agent tool: write response", "error", err)
	}
}

// fail renders err as RFC 9457 Problem Details. The cause of an INTERNAL error
// is logged with the request ID and never sent to the client.
func (h *handlers) fail(w http.ResponseWriter, r *http.Request, err error) {
	p := problem.Write(w, err, gateway.RequestID(r.Context()), r.URL.Path)
	switch {
	case p.Status >= http.StatusInternalServerError:
		h.log.ErrorContext(r.Context(), "agent tool failed",
			slog.String("code", string(p.Code)), slog.Int("status", p.Status), slog.Any("error", err))
	case h.log.Enabled(r.Context(), slog.LevelDebug):
		h.log.DebugContext(r.Context(), "agent tool rejected",
			slog.String("code", string(p.Code)), slog.String("path", r.URL.Path))
	}
}

// ---- field violations -----------------------------------------------------

// invalid builds VALIDATION_FAILED with one body violation.
func invalid(pointer, code, message string) error {
	return problem.Validation(problem.Violation{Pointer: pointer, Code: code, Message: message})
}

// requiredField is the violation of a missing required member.
func requiredField(pointer, message string) error { return invalid(pointer, "REQUIRED", message) }

// outOfRange is the violation of a number outside its schema bounds.
func outOfRange(pointer, message string) error { return invalid(pointer, "OUT_OF_RANGE", message) }

// wrongFormat is the violation of a string that does not match its pattern.
func wrongFormat(pointer, message string) error { return invalid(pointer, "INVALID", message) }

// ---- schema checks --------------------------------------------------------

// checkActionID validates an ActionId.
func checkActionID(pointer, id string) error {
	if id == "" {
		return requiredField(pointer, "An action identifier is required.")
	}
	if len(id) > 200 || !actionIDRe.MatchString(id) {
		return wrongFormat(pointer, "An action ID is a host.<resource>.<verb> ID or <plugin_id>/<operation>.")
	}
	return nil
}

// checkResourceID validates a ResourceId.
func checkResourceID(pointer, id string) error {
	if id == "" {
		return requiredField(pointer, "An identifier is required.")
	}
	if len(id) > 64 || !resourceIDRe.MatchString(id) {
		return wrongFormat(pointer, "An identifier is 1 to 64 characters of A-Z, a-z, 0-9, '_' and '-'.")
	}
	return nil
}

// checkNodeID validates a NodeId.
func checkNodeID(pointer, id string) error {
	if len(id) > 64 || !nodeIDRe.MatchString(id) {
		return wrongFormat(pointer, "A node ID is 1 to 64 lower-case letters, digits and '-'.")
	}
	return nil
}

// checkPluginID validates a PluginId.
func checkPluginID(pointer, id string) error {
	if len(id) > 128 || !pluginIDRe.MatchString(id) {
		return wrongFormat(pointer, "A plugin ID starts with a lower-case letter and contains lower-case letters, digits, '.' and '-'.")
	}
	return nil
}

// checkInstanceID validates an InstanceId.
func checkInstanceID(pointer, id string) error {
	if len(id) > 64 || !instanceIDRe.MatchString(id) {
		return wrongFormat(pointer, "An instance ID is 1 to 64 lower-case letters, digits, '_' and '-'.")
	}
	return nil
}

// checkSubject validates a Subject and returns its head (the resource kind) and
// the rest (the identifier, empty for a collection).
func checkSubject(subject string) (head, id string, err error) {
	if err := checkSubjectAt("/subject", subject); err != nil {
		return "", "", err
	}
	for i := 0; i < len(subject); i++ {
		if subject[i] == '/' {
			return subject[:i], subject[i+1:], nil
		}
	}
	return subject, "", nil
}

// checkSubjectAt validates a Subject member at pointer.
func checkSubjectAt(pointer, subject string) error {
	if subject == "" {
		return requiredField(pointer, "A subject is required.")
	}
	if len(subject) > 512 || !subjectRe.MatchString(subject) {
		return wrongFormat(pointer, "A subject is a resource name such as users/<id> or operations/newest.")
	}
	return nil
}

// checkRevisionField validates a Revision member.
func checkRevisionField(pointer, rev string) error {
	if len(rev) > 64 || !revisionRe.MatchString(rev) {
		return wrongFormat(pointer, "A revision is 1 to 64 characters of A-Z, a-z, 0-9, '.', '_', '~' and '-'.")
	}
	return nil
}

// clipRunes cuts s to at most max code points on a rune boundary.
func clipRunes(s string, max int) (string, bool) {
	if utf8.RuneCountInString(s) <= max {
		return s, false
	}
	n := 0
	for i := range s {
		if n == max {
			return s[:i], true
		}
		n++
	}
	return s, false
}

// jsonObject decodes a JSON value into a generic object, so responses can be
// adjusted to the public schema (for example replacing a nil array with []).
func jsonObject(v any) (map[string]any, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("agentapi: marshal: %w", err)
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("agentapi: unmarshal: %w", err)
	}
	if out == nil {
		out = map[string]any{}
	}
	return out, nil
}

// ensureArray replaces a null member with an empty array, so a response always
// satisfies `type: array` in the OpenAPI document.
func ensureArray(obj map[string]any, key string) {
	if v, ok := obj[key]; !ok || v == nil {
		obj[key] = []any{}
	}
}
