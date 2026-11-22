// SPDX-License-Identifier: AGPL-3.0-only

package gateway

import (
	"fmt"
	"net/http"
	"sort"
	"strings"

	"github.com/qwq-panel/qwq/internal/platform/problem"
)

// Access is the credential policy of a route: the OpenAPI `security` list of
// the operation, reduced to what the gateway can enforce.
type Access int

const (
	// AccessDenied is the zero value: no credential is accepted and the route
	// is unreachable. It fails closed, so a route registered without an
	// explicit policy cannot be opened by accident.
	AccessDenied Access = iota
	// AccessPublic accepts unauthenticated requests (`security: []`), e.g.
	// /healthz, /readyz and the setup status.
	AccessPublic
	// AccessSession accepts only a browser session (approvals, delegation
	// management, session endpoints).
	AccessSession
	// AccessSessionOrService accepts a browser session or a service-account
	// bearer token (the regular REST routes).
	AccessSessionOrService
	// AccessDelegation accepts only a delegation bearer token
	// (/api/v1/agent/*).
	AccessDelegation
)

func (a Access) allows(s Scheme) bool {
	switch a {
	case AccessPublic:
		return true
	case AccessSession:
		return s == SchemeSession
	case AccessSessionOrService:
		return s == SchemeSession || s == SchemeService
	case AccessDelegation:
		return s == SchemeDelegation
	}
	return false
}

// BodyMode declares what a route expects in the request body.
type BodyMode int

const (
	// BodyNone: no JSON body is expected (GET, DELETE with query parameters).
	BodyNone BodyMode = iota
	// BodyJSON: an application/json body up to max_body_bytes.
	BodyJSON
	// BodyPluginJSON: an application/json body up to max_plugin_body_bytes
	// (routes that carry plugin payloads).
	BodyPluginJSON
	// BodyPackage: a multipart/form-data body up to max_package_bytes. It is
	// the only mode that accepts a binary upload; the handler streams the
	// `package` part to a private staging file and never trusts its filename.
	BodyPackage
)

// Route is one public API operation: one OpenAPI path and method.
type Route struct {
	Method  string
	Pattern string
	Handler http.Handler
	// Access is the credential policy. The zero value denies every request.
	Access Access
	// Body selects the body limit and the Content-Type check.
	Body BodyMode
	// RequireIdempotency enforces an Idempotency-Key header before the handler.
	RequireIdempotency bool
	// NoRateLimit exempts probes from the limiter.
	NoRateLimit bool
}

// RouteInfo describes a registered route (used by the OpenAPI contract test and
// by `qwq doctor`).
type RouteInfo struct {
	Method  string
	Pattern string
	Access  Access
}

type route struct {
	method             string
	pattern            string
	access             Access
	body               BodyMode
	requireIdempotency bool
	noRateLimit        bool
	maxBody            int64
	handler            http.Handler
}

// bodyLimitName is the x-qwq-limits key reported in PAYLOAD_TOO_LARGE.
func (r *route) bodyLimitName() string {
	switch r.body {
	case BodyPluginJSON:
		return "max_plugin_body_bytes"
	case BodyPackage:
		return "max_package_bytes"
	}
	return "max_body_bytes"
}

// Handle registers one route. Call it before the gateway starts serving.
//
// The per-route middleware is composed here, in the fixed order of the package
// documentation; no caller can reorder it.
func (g *Gateway) Handle(rt Route) error {
	method := strings.ToUpper(strings.TrimSpace(rt.Method))
	if !validMethod(method) {
		return fmt.Errorf("gateway: route %q: unsupported method %q", rt.Pattern, rt.Method)
	}
	if err := validPattern(rt.Pattern); err != nil {
		return fmt.Errorf("gateway: route %s %s: %w", method, rt.Pattern, err)
	}
	if rt.Handler == nil {
		return fmt.Errorf("gateway: route %s %s: no handler", method, rt.Pattern)
	}
	if rt.Body != BodyNone && !mutating(method) {
		return fmt.Errorf("gateway: route %s %s: a body is only allowed on unsafe methods", method, rt.Pattern)
	}

	maxBody := g.limits.MaxBodyBytes
	switch rt.Body {
	case BodyPluginJSON:
		maxBody = g.limits.MaxPluginBodyBytes
	case BodyPackage:
		maxBody = g.limits.MaxPackageBytes
	}
	r := &route{
		method:             method,
		pattern:            rt.Pattern,
		access:             rt.Access,
		body:               rt.Body,
		requireIdempotency: rt.RequireIdempotency,
		noRateLimit:        rt.NoRateLimit,
		maxBody:            maxBody,
	}

	// Wrapped from the inside out: a request passes these from bottom to top.
	h := rt.Handler
	h = g.requireIdempotency(r, h)
	h = g.rateLimit(r, h)
	h = g.credentialPolicy(r, h)
	h = g.csrf(r, h)
	h = g.authenticate(r, h)
	h = g.preAuthLimit(r, h)
	h = g.contentType(r, h)
	h = g.bodyLimit(r, h)
	r.handler = h

	g.mu.Lock()
	defer g.mu.Unlock()
	methods := g.routes[rt.Pattern]
	if methods == nil {
		methods = make(map[string]*route)
		g.routes[rt.Pattern] = methods
	}
	if _, dup := methods[method]; dup {
		return fmt.Errorf("gateway: duplicate route %s %s", method, rt.Pattern)
	}
	methods[method] = r
	g.methods[rt.Pattern] = append(g.methods[rt.Pattern], method)
	sort.Strings(g.methods[rt.Pattern])
	// Register one method-independent pattern on ServeMux and dispatch methods
	// inside the gateway. That preserves 405+Allow and avoids ServeMux conflicts
	// between literal sub-paths (e.g. /service-accounts/renewal-bootstrap) and
	// sibling wildcards (e.g. /service-accounts/{service_id}).
	if len(methods) == 1 {
		g.mux.Handle(rt.Pattern, http.HandlerFunc(g.dispatchPattern(rt.Pattern)))
	}
	return nil
}

func (g *Gateway) dispatchPattern(pattern string) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		g.mu.Lock()
		methods := g.routes[pattern]
		rt := methods[r.Method]
		if rt == nil && r.Method == http.MethodHead {
			rt = methods[http.MethodGet]
		}
		var allowed []string
		if rt == nil {
			allowed = append([]string(nil), g.methods[pattern]...)
		}
		g.mu.Unlock()
		if rt != nil {
			rt.handler.ServeHTTP(w, r)
			return
		}
		w.Header().Set("Allow", strings.Join(allowed, ", "))
		g.writeProblem(w, r, problem.New(problem.MethodNotAllowed,
			"The method %s is not allowed for this path.", r.Method))
	}
}

// Routes returns the registered routes, sorted, for the contract test.
func (g *Gateway) Routes() []RouteInfo {
	g.mu.Lock()
	defer g.mu.Unlock()
	out := make([]RouteInfo, 0, len(g.routes))
	for pattern, methods := range g.routes {
		for method, rt := range methods {
			out = append(out, RouteInfo{Method: method, Pattern: pattern, Access: rt.access})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Pattern != out[j].Pattern {
			return out[i].Pattern < out[j].Pattern
		}
		return out[i].Method < out[j].Method
	})
	return out
}

func validMethod(m string) bool {
	switch m {
	case http.MethodGet, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete,
		http.MethodHead, http.MethodOptions:
		return true
	}
	return false
}

// validPattern checks the subset of ServeMux patterns the public API uses:
// literal segments and single-segment `{name}` wildcards, no subtrees.
func validPattern(p string) error {
	if p == "" || !strings.HasPrefix(p, "/") {
		return fmt.Errorf("pattern must start with /")
	}
	if p == "/" || strings.HasSuffix(p, "/") {
		return fmt.Errorf("subtree patterns are not used by the public API")
	}
	if strings.ContainsAny(p, " \t\r\n") {
		return fmt.Errorf("pattern contains whitespace")
	}
	if strings.Contains(p, "*") || strings.Contains(p, "{$}") {
		return fmt.Errorf("pattern uses an unsupported wildcard")
	}
	seen := make(map[string]bool)
	for _, seg := range strings.Split(p[1:], "/") {
		if seg == "" || seg == "." || seg == ".." {
			return fmt.Errorf("pattern has an empty or relative segment")
		}
		if !strings.HasPrefix(seg, "{") {
			continue
		}
		if !strings.HasSuffix(seg, "}") || len(seg) < 3 {
			return fmt.Errorf("pattern has a malformed wildcard %q", seg)
		}
		name := seg[1 : len(seg)-1]
		for i := 0; i < len(name); i++ {
			c := name[i]
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_') {
				return fmt.Errorf("pattern has an invalid wildcard name %q", name)
			}
		}
		if seen[name] {
			return fmt.Errorf("pattern reuses the wildcard name %q", name)
		}
		seen[name] = true
	}
	return nil
}
