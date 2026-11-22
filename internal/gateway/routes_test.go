// SPDX-License-Identifier: AGPL-3.0-only

package gateway_test

import (
	"net/http"
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/qwq-panel/qwq/internal/gateway"
	"github.com/qwq-panel/qwq/internal/platform/problem"
)

func TestUnknownPathIsProblemNotFound(t *testing.T) {
	g := testGateway(t)
	resp := do(t, g, newRequest(http.MethodGet, "/api/v1/nope", ""))
	if resp.code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", resp.code)
	}
	p := resp.problem(t)
	if p.Code != problem.NotFound {
		t.Fatalf("code = %q", p.Code)
	}
	if p.RequestID == "" {
		t.Fatal("problem has no request_id")
	}
	// A path with a trailing slash or a double slash is not redirected.
	for _, path := range []string{"/api/v1/things/", "/api/v1//things", "/api/v1/./things"} {
		if resp := do(t, g, newRequest(http.MethodGet, path, "")); resp.code != http.StatusNotFound {
			t.Errorf("%s status = %d, want 404", path, resp.code)
		}
	}
}

func TestMethodNotAllowedCarriesAllow(t *testing.T) {
	g := testGateway(t,
		gateway.Route{Method: http.MethodGet, Pattern: "/api/v1/things", Access: gateway.AccessPublic, Handler: http.HandlerFunc(okHandler)},
		gateway.Route{Method: http.MethodPost, Pattern: "/api/v1/things", Access: gateway.AccessPublic, Body: gateway.BodyJSON, Handler: http.HandlerFunc(okHandler)},
	)
	resp := do(t, g, newRequest(http.MethodDelete, "/api/v1/things", ""))
	if resp.code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", resp.code)
	}
	if got := resp.header.Get("Allow"); got != "GET, POST" {
		t.Fatalf("Allow = %q, want %q", got, "GET, POST")
	}
	if p := resp.problem(t); p.Code != problem.MethodNotAllowed {
		t.Fatalf("code = %q", p.Code)
	}

	// ServeMux answers HEAD from a GET pattern (the body is dropped by the
	// server), which is standard HTTP even though the document lists only GET.
	resp = do(t, g, newRequest(http.MethodHead, "/api/v1/things", ""))
	if resp.code != http.StatusOK {
		t.Fatalf("HEAD status = %d, want 200 from the GET route", resp.code)
	}
}

func TestHandleValidation(t *testing.T) {
	g := testGateway(t)
	ok := http.HandlerFunc(okHandler)
	bad := []gateway.Route{
		{Method: "TRACE", Pattern: "/api/v1/x", Handler: ok},
		{Method: http.MethodGet, Pattern: "api/v1/x", Handler: ok},
		{Method: http.MethodGet, Pattern: "/api/v1/", Handler: ok},
		{Method: http.MethodGet, Pattern: "/api/v1/{id", Handler: ok},
		{Method: http.MethodGet, Pattern: "/api/v1/{a}/{a}", Handler: ok},
		{Method: http.MethodGet, Pattern: "/api/v1/x", Handler: nil},
		{Method: http.MethodGet, Pattern: "/api/v1/body", Body: gateway.BodyJSON, Handler: ok},
	}
	for i, rt := range bad {
		if err := g.Handle(rt); err == nil {
			t.Errorf("route %d (%s %s) was accepted", i, rt.Method, rt.Pattern)
		}
	}
	if err := g.Handle(gateway.Route{Method: http.MethodGet, Pattern: "/api/v1/{thing_id}/sub", Handler: ok, Access: gateway.AccessPublic}); err != nil {
		t.Fatalf("wildcard route rejected: %v", err)
	}
	if err := g.Handle(gateway.Route{Method: http.MethodGet, Pattern: "/api/v1/{thing_id}/sub", Handler: ok}); err == nil {
		t.Fatal("duplicate route was accepted")
	}
}

func TestRoutesAreListedSorted(t *testing.T) {
	g := testGateway(t, gateway.Route{
		Method: http.MethodPost, Pattern: "/api/v1/things", Access: gateway.AccessPublic,
		Body: gateway.BodyJSON, Handler: http.HandlerFunc(okHandler),
	})
	routes := g.Routes()
	if len(routes) < 4 {
		t.Fatalf("routes = %v", routes)
	}
	if !sort.SliceIsSorted(routes, func(i, j int) bool {
		if routes[i].Pattern != routes[j].Pattern {
			return routes[i].Pattern < routes[j].Pattern
		}
		return routes[i].Method < routes[j].Method
	}) {
		t.Fatalf("routes are not sorted: %v", routes)
	}
	found := false
	for _, rt := range routes {
		if rt.Method == http.MethodPost && rt.Pattern == "/api/v1/things" && rt.Access == gateway.AccessPublic {
			found = true
		}
	}
	if !found {
		t.Fatalf("registered route missing from %v", routes)
	}
}

// TestOpenAPIRouteContract is the route contract test of ADR-0006 D2: every
// route the gateway registers must exist in the public document, otherwise a
// client generated from the document would not know it. Operations the document
// declares but this package does not implement yet are printed, not failed, so
// the list shrinks as the domain handlers land.
func TestOpenAPIRouteContract(t *testing.T) {
	spec := loadOpenAPIRoutes(t, "../../api/public/v1/openapi.yaml")
	g := testGateway(t)

	registered := make(map[string]bool)
	for _, rt := range g.Routes() {
		registered[rt.Method+" "+rt.Pattern] = true
	}
	var unexpected []string
	for key := range registered {
		if !spec[key] {
			unexpected = append(unexpected, key)
		}
	}
	sort.Strings(unexpected)
	if len(unexpected) > 0 {
		t.Fatalf("routes registered by the gateway but missing from openapi.yaml:\n%s", strings.Join(unexpected, "\n"))
	}

	for _, required := range []string{"GET /healthz", "GET /readyz", "GET /api/v1/events"} {
		if !registered[required] {
			t.Errorf("required route %s is not registered", required)
		}
	}

	var missing []string
	for key := range spec {
		if !registered[key] {
			missing = append(missing, key)
		}
	}
	sort.Strings(missing)
	t.Logf("%d of %d OpenAPI operations are not implemented by this package yet (pending integration):\n%s",
		len(missing), len(spec), strings.Join(missing, "\n"))
}

// loadOpenAPIRoutes reads the paths section of the document with the standard
// library: the document is line-oriented enough that a full YAML dependency
// would not buy anything here.
func loadOpenAPIRoutes(t *testing.T, path string) map[string]bool {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	methods := map[string]bool{
		"get": true, "post": true, "put": true, "patch": true,
		"delete": true, "head": true, "options": true, "trace": true,
	}
	routes := make(map[string]bool)
	inPaths := false
	current := ""
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimRight(line, " \t\r")
		if line == "paths:" {
			inPaths = true
			continue
		}
		if !inPaths {
			continue
		}
		if line != "" && line[0] != ' ' {
			break // the next top-level key ends the section
		}
		if strings.HasPrefix(line, "  /") && strings.HasSuffix(line, ":") && !strings.HasPrefix(line, "   ") {
			current = strings.TrimSuffix(strings.TrimSpace(line), ":")
			continue
		}
		if current == "" || !strings.HasPrefix(line, "    ") || !strings.HasSuffix(line, ":") {
			continue
		}
		name := strings.TrimSpace(strings.TrimSuffix(line, ":"))
		if !methods[name] {
			continue
		}
		routes[strings.ToUpper(name)+" "+current] = true
	}
	if len(routes) < 10 {
		t.Fatalf("parsed only %d operations from %s", len(routes), path)
	}
	return routes
}
