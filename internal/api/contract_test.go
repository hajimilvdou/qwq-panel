// SPDX-License-Identifier: AGPL-3.0-only

package api_test

import (
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/qwq-panel/qwq/internal/api"
	"github.com/qwq-panel/qwq/internal/gateway"
)

// TestRegisterRequiresServices checks that a mis-wired host fails at startup
// instead of serving routes that would panic on the first request.
func TestRegisterRequiresServices(t *testing.T) {
	if err := api.Register(nil, api.Deps{}); err == nil {
		t.Fatal("Register accepted a nil gateway")
	}
	g, err := gateway.New(gateway.Config{PublicOrigins: []string{testOrigin}})
	if err != nil {
		t.Fatalf("gateway.New: %v", err)
	}
	defer g.Close()
	if err := api.Register(g, api.Deps{}); err == nil {
		t.Fatal("Register accepted empty deps")
	}
}

// TestOpenAPIRouteContract is the route contract test of ADR-0006 D2: every route
// the host registers exists in the public document, and every operation of the
// document except the agent tools and the three gateway routes is implemented
// here. The gateway's own contract test only knows its three routes, so this is
// where the resource routes are held to the document.
func TestOpenAPIRouteContract(t *testing.T) {
	e := newEnv(t)
	spec := loadOpenAPIRoutes(t, "../../api/public/v1/openapi.yaml")
	registered := make(map[string]bool)
	var unexpected []string
	for _, rt := range e.c.Gateway().Routes() {
		key := rt.Method + " " + rt.Pattern
		registered[key] = true
		if !spec[key] {
			unexpected = append(unexpected, key)
		}
		if strings.HasPrefix(rt.Pattern, "/api/v1/agent/") {
			t.Errorf("agent route %s is registered by internal/api", key)
		}
	}
	sort.Strings(unexpected)
	if len(unexpected) > 0 {
		t.Fatalf("routes registered but missing from openapi.yaml:\n%s", strings.Join(unexpected, "\n"))
	}

	gatewayOwned := map[string]bool{
		"GET /healthz":       true,
		"GET /readyz":        true,
		"GET /api/v1/events": true,
	}
	var missing []string
	for key := range spec {
		if gatewayOwned[key] || strings.Contains(key, "/api/v1/agent/") {
			continue
		}
		if !registered[key] {
			missing = append(missing, key)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Fatalf("OpenAPI operations without a handler:\n%s", strings.Join(missing, "\n"))
	}
	if got, want := len(registered), len(spec)-7; got != want {
		t.Fatalf("registered %d routes, want %d (%d operations minus the 7 agent tools)", got, want, len(spec))
	}
}

// loadOpenAPIRoutes reads the paths section of the document with the standard
// library: the document is line-oriented enough that a YAML dependency would not
// buy anything here.
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
