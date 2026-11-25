// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/qwq-panel/qwq/internal/agent"
	"github.com/qwq-panel/qwq/internal/controller"
	"github.com/qwq-panel/qwq/internal/platform/clock"
	"github.com/qwq-panel/qwq/internal/platform/config"
	"github.com/qwq-panel/qwq/internal/pluginhost/supervisor"
)

func TestServeMissingConfig(t *testing.T) {
	var out, errb bytes.Buffer
	code := run([]string{"serve-controller", "--config", filepath.Join(t.TempDir(), "missing.json")}, &out, &errb)
	if code != 2 {
		t.Fatalf("exit = %d, want 2 (stderr %q)", code, errb.String())
	}
	if !strings.Contains(errb.String(), "serve-controller:") {
		t.Fatalf("stderr = %q", errb.String())
	}
}

// TestRegisterPublicRoutes mounts the public API, the agent tools and the
// agent-session API on a real gateway and checks the resulting route table:
// the gateway's own routes, the public/agent-session routes and the 7 agent
// tools, all distinct.
func TestRegisterPublicRoutes(t *testing.T) {
	opts := controller.Options{Config: testConfig(t)}
	c, err := controller.New(t.Context(), opts)
	if err != nil {
		t.Fatalf("controller.New: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })

	logger := slog.New(slog.DiscardHandler)
	count, err := registerPublicRoutes(c, nil, nil, logger)
	if err != nil {
		t.Fatalf("registerPublicRoutes: %v", err)
	}
	if count != 132 {
		t.Fatalf("route count = %d, want 132", count)
	}
	routes := c.Gateway().Routes()
	if len(routes) != count {
		t.Fatalf("Routes() = %d entries, register reported %d", len(routes), count)
	}

	seen := make(map[string]bool, len(routes))
	for _, route := range routes {
		key := route.Method + " " + route.Pattern
		if seen[key] {
			t.Fatalf("duplicate route %s", key)
		}
		seen[key] = true
	}

	required := []string{
		"GET /healthz",
		"GET /readyz",
		"GET /api/v1/events",
		"POST /api/v1/setup",
		"GET /api/v1/users",
		"POST /api/v1/delegations",
		"POST /api/v1/service-accounts/renewal-bootstrap",
		"GET /api/v1/plugins",
		"GET /api/v1/plugin-catalog",
		"POST /api/v1/plugin-packages",
		"POST /api/v1/plugins/{plugin_id}/update",
		"POST /api/v1/plugins/{plugin_id}/rollback",
		"GET /api/v1/plugins/{plugin_id}/config",
		"PUT /api/v1/plugins/{plugin_id}/config",
		"POST /api/v1/plugins/{plugin_id}/operations/{operation}",
		"POST /api/v1/nodes/{node_id}/plugins/{plugin_id}/instances/{instance_id}/operations/{operation}",
		"POST /api/v1/plans",
		"POST /api/v1/approvals/{approval_id}/decision",
		"GET /api/v1/actions",
		"GET /api/v1/actions/{action_id}",
		"GET /api/v1/audit",
		"GET /api/v1/system",
		"GET /api/v1/system/access",
		"PUT /api/v1/system/access",
		"GET /api/v1/plugins/{plugin_id}/logs",
		"POST /api/v1/plugins/{plugin_id}/restart",
		"POST /api/v1/plugins/{plugin_id}/enable",
		"POST /api/v1/plugins/{plugin_id}/disable",
		"POST /api/v1/agent/find_actions",
		"POST /api/v1/agent/describe_action",
		"POST /api/v1/agent/read",
		"POST /api/v1/agent/plan",
		"POST /api/v1/agent/execute",
		"POST /api/v1/agent/wait",
		"POST /api/v1/agent/cancel",
		"GET /api/v1/agent-sessions/{session_id}/export",
		"GET /api/v1/agent-exchange/entries",
		"POST /api/v1/agent-exchange/mkdir",
		"POST /api/v1/agent-exchange/upload",
		"GET /api/v1/agent-exchange/download",
		"GET /api/v1/agent-exchange/preview",
		"PUT /api/v1/agent-exchange/file",
		"POST /api/v1/agent-exchange/rename",
		"DELETE /api/v1/agent-exchange/entry",
	}
	for _, key := range required {
		if !seen[key] {
			t.Fatalf("route %s is missing", key)
		}
	}

	var agentRoutes int
	for key := range seen {
		if strings.Contains(key, "/api/v1/agent/") {
			agentRoutes++
		}
	}
	if agentRoutes != 7 {
		t.Fatalf("agent routes = %d, want 7", agentRoutes)
	}
}

// TestRegisterPublicRoutesWiresAgentSessions checks that mounting the API also
// builds the production agent session backend (runner + approval bridge) and
// installs it on the controller, so the API never falls back to its runner-less
// default service.
func TestRegisterPublicRoutesWiresAgentSessions(t *testing.T) {
	c, err := controller.New(t.Context(), controller.Options{Config: testConfig(t)})
	if err != nil {
		t.Fatalf("controller.New: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	if c.AgentSessions() != nil {
		t.Fatal("controller built agent sessions before the API was mounted")
	}

	if _, err := registerPublicRoutes(c, nil, nil, slog.New(slog.DiscardHandler)); err != nil {
		t.Fatalf("registerPublicRoutes: %v", err)
	}
	first := c.AgentSessions()
	if first == nil {
		t.Fatal("registerPublicRoutes did not build the agent session backend")
	}
	second, err := c.NewAgentSessions(context.Background())
	if err != nil {
		t.Fatalf("NewAgentSessions: %v", err)
	}
	if second != first {
		t.Fatal("NewAgentSessions built a second service")
	}
	if err := c.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if c.AgentSessions() != nil {
		t.Fatal("Close kept the agent session backend")
	}
}

// TestServeAgentFlags checks the argument handling of serve-agent without
// touching systemd: a missing configuration and a relative directory are usage
// errors, and no unit is started on the way out.
func TestServeAgentFlags(t *testing.T) {
	var out, errb bytes.Buffer
	code := run([]string{"serve-agent", "--config", filepath.Join(t.TempDir(), "missing.json")}, &out, &errb)
	if code != 2 {
		t.Fatalf("serve-agent(missing config) exit = %d, want 2 (stderr %q)", code, errb.String())
	}
	if !strings.Contains(errb.String(), "serve-agent:") {
		t.Fatalf("stderr = %q", errb.String())
	}

	path := filepath.Join(t.TempDir(), "qwq.json")
	if err := os.WriteFile(path, []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	errb.Reset()
	code = run([]string{"serve-agent", "--config", path, "--run-dir", "relative/run"}, &out, &errb)
	if code != 2 || !strings.Contains(errb.String(), "run-dir") {
		t.Fatalf("serve-agent(relative run dir) exit = %d, stderr = %q", code, errb.String())
	}
	out.Reset()
	errb.Reset()
	code = run([]string{"serve-agent", "--config", path, "--plugins-dir", "relative/plugins"}, &out, &errb)
	if code != 2 || !strings.Contains(errb.String(), "plugins-dir") {
		t.Fatalf("serve-agent(relative plugins dir) exit = %d, stderr = %q", code, errb.String())
	}

	// serve-controller rejects a relative plugin directory as a usage error
	// before it opens anything.
	out.Reset()
	errb.Reset()
	code = run([]string{"serve-controller", "--config", path, "--plugins-dir", "relative/plugins"}, &out, &errb)
	if code != 2 || !strings.Contains(errb.String(), "plugins-dir") {
		t.Fatalf("serve-controller(relative plugins dir) exit = %d, stderr = %q", code, errb.String())
	}
}

// TestNewPluginRuntimeDisableRules checks the two conditions that keep the
// plugin runtime out of the process: a non-standalone role and a missing plugin
// directory. Neither case fails startup.
func TestNewPluginRuntimeDisableRules(t *testing.T) {
	logger := slog.New(slog.DiscardHandler)
	cfg := config.Default()

	rt, _, err := newPluginRuntime(cfg, filepath.Join(t.TempDir(), "missing"), logger)
	if err != nil || rt != nil {
		t.Fatalf("newPluginRuntime(missing dir) = %v, %v; want nil, nil", rt, err)
	}

	notStandalone := cfg
	notStandalone.Role = config.RoleController
	existing := t.TempDir()
	rt, _, err = newPluginRuntime(notStandalone, existing, logger)
	if err != nil || rt != nil {
		t.Fatalf("newPluginRuntime(role controller) = %v, %v; want nil, nil", rt, err)
	}

	rt, _, err = newPluginRuntime(cfg, existing, logger)
	if err != nil {
		t.Fatalf("newPluginRuntime(standalone) = %v", err)
	}
	if rt == nil {
		t.Fatal("newPluginRuntime returned nil for a standalone host with a plugin dir")
	}
	rt.Stop()
}

// fakeUnitManager is a supervisor.UnitManager that never starts a unit, so the
// agent wiring can be exercised without systemd.
type fakeUnitManager struct{}

func (fakeUnitManager) Start(context.Context, string) error { return nil }

func (fakeUnitManager) Stop(context.Context, string) error { return nil }

func (fakeUnitManager) Kill(context.Context, string) error { return nil }

func (fakeUnitManager) Show(context.Context, string) (supervisor.UnitState, error) {
	return supervisor.UnitState{MainPID: 4242, ActiveState: "active", SubState: "running"}, nil
}

// TestNewAgentRuntime builds the same graph serve-agent uses, with a fake unit
// manager: the supervisor and the host factory must be wired and the runtime
// must start without touching systemd.
func TestNewAgentRuntime(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Default()
	cfg.DataDir = filepath.Join(dir, "data")
	cfg.RunDir = filepath.Join(dir, "run")
	plugins := filepath.Join(dir, "plugins")
	if err := os.MkdirAll(plugins, 0o755); err != nil {
		t.Fatal(err)
	}
	logger := slog.New(slog.DiscardHandler)

	rt, err := newAgentRuntime(cfg, plugins, fakeUnitManager{}, logger)
	if err != nil {
		t.Fatalf("newAgentRuntime: %v", err)
	}
	t.Cleanup(rt.Stop)
	if rt.Supervisor() == nil {
		t.Fatal("agent runtime has no supervisor")
	}
	if err := rt.Start(context.Background(), controller.HostDeps{Clock: clock.System{}, Logger: logger, NodeID: "local"}); err != nil {
		t.Fatalf("Start: %v", err)
	}
	a, err := agent.New(agent.Options{
		Config:      cfg,
		Logger:      logger,
		Supervisor:  rt.Supervisor(),
		HostFactory: rt.HostServer,
	})
	if err != nil {
		t.Fatalf("agent.New: %v", err)
	}
	if a.HostServer() == nil {
		t.Fatal("agent has no host server")
	}
	host, err := rt.HostServer("alpha")
	if err != nil || host == nil {
		t.Fatalf("HostServer = %v, %v", host, err)
	}
}

// testConfig returns a bootstrap configuration whose directories live in a
// temporary directory.
func testConfig(t *testing.T) config.Config {
	t.Helper()
	dir := t.TempDir()
	cfg := config.Default()
	cfg.DataDir = filepath.Join(dir, "data")
	cfg.RunDir = filepath.Join(dir, "run")
	return cfg
}
