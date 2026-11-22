// SPDX-License-Identifier: AGPL-3.0-only

package api_test

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/qwq-panel/qwq/internal/api"
	"github.com/qwq-panel/qwq/sdk/manifest"
)

// metadataManifestJSON is a schema 1.3 manifest carrying every optional member
// the plugin DTO exposes (GAPS gap 3). meta.apply may use a lockout capability,
// so the catalog is expected to force reachability on it.
const metadataManifestJSON = `{
  "schema_version": "1.3",
  "id": "com.example.meta",
  "version": "1.2.3",
  "name": "元数据示例",
  "summary": "检查插件 DTO 的元数据",
  "description": "说明文本，供应用详情页展示。",
  "license": "MIT",
  "homepage": "https://example.com/meta",
  "icon": "assets/icon.svg",
  "publisher": {"id": "acme", "key_id": "ed25519:4f1c2b7d9a2e6c014f1c2b7d9a2e6c014f1c2b7d9a2e6c014f1c2b7d9a2e6c01"},
  "abi": {"major": 1, "minimum_minor": 0},
  "engine_constraint": ">=0.1.0 <1.0.0",
  "target": "linux/amd64",
  "entrypoint": "bin/plugin",
  "files": {
    "bin/plugin": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
    "schemas/config.schema.json": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
    "schemas/meta.request.json": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
    "schemas/meta.response.json": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
    "attestations/sbom.spdx.json": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
    "assets/icon.svg": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
    "ui/index.html": "sha256:0000000000000000000000000000000000000000000000000000000000000000"
  },
  "provenance": {"sbom": "attestations/sbom.spdx.json"},
  "placement": "node",
  "lifecycle": {"startup": "eager", "background": false, "update_strategy": "restart"},
  "operations": [
    {
      "name": "meta.run", "api_version": "v1", "permission": "com.example.meta:read",
      "mode": "invoke", "effect": "read", "risk": "low", "idempotent": true, "timeout_ms": 5000,
      "summary": "读取元数据",
      "request_schema": "schemas/meta.request.json", "response_schema": "schemas/meta.response.json"
    },
    {
      "name": "meta.apply", "api_version": "v1", "permission": "com.example.meta:write",
      "mode": "invoke", "effect": "write", "risk": "medium", "idempotent": false, "timeout_ms": 5000,
      "summary": "应用设置",
      "capabilities": [{"name": "system.firewall.manage", "scope": "nftables"}],
      "request_schema": "schemas/meta.request.json", "response_schema": "schemas/meta.response.json"
    }
  ],
  "capabilities": [
    {"name": "system.firewall.manage", "scope": "nftables", "reason": "调整防火墙"},
    {"name": "state.kv.write", "scope": "self", "reason": "保存状态"}
  ],
  "dependencies": [{"kind": "plugin", "id": "security.scan", "constraint": "^0.4.0", "required": false}],
  "state": {"schema_version": "1", "minimum_rollback_version": "1.0.0", "backup_paths": []},
  "config": {"schema": "schemas/config.schema.json", "hot_apply": false},
  "resources": {"memory_max_mb": 64, "cpu_quota_percent": 25, "pids_max": 32, "fds_max": 128, "disk_max_mb": 64},
  "ui": {
    "entry": "ui/index.html",
    "sandbox": true,
    "connect_sources": ["https://api.example.com"],
    "routes": [{"path": "/plugins/com.example.meta", "title": "元数据", "nav": true, "permission": "com.example.meta:read"}],
    "widgets": [{"id": "status", "title": "状态", "kind": "stat", "operation": "meta.run", "refresh_seconds": 5, "size": "s", "icon": "shield", "color": "green"}]
  }
}`

// metadataPluginManager seeds the fake manager with the api.Plugin an adapter
// would build from the manifest above.
func metadataPluginManager(t *testing.T) *fakePluginManager {
	t.Helper()
	created := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	mgr := newFakePluginManager()
	p := api.Plugin{
		PluginID: "com.example.meta", Name: "元数据示例", Summary: "检查插件 DTO 的元数据",
		Publisher: "acme", Placement: "node", ActiveVersion: "1.2.3",
		ActiveStatus: "ACTIVE", InstallStatus: "INSTALLED", ConfigRevision: 1,
		CreatedAt: created, Revision: 42,
		Versions: []api.PluginVersion{
			{PluginID: "com.example.meta", Version: "1.2.3", Status: "ACTIVE", InstallStatus: "INSTALLED", Active: true, Revision: 42},
		},
		Description: "说明文本，供应用详情页展示。",
		Icon:        "assets/icon.svg",
		Homepage:    "https://example.com/meta",
		License:     "MIT",
		HasConfig:   true,
		Capabilities: []api.PluginCapability{
			{Name: "system.firewall.manage", Scope: "nftables", Reason: "调整防火墙", Sensitive: true},
			{Name: "state.kv.write", Scope: "self", Reason: "保存状态"},
		},
		Dependencies: []string{"security.scan"},
		Resources: &api.PluginResources{
			MemoryMaxMB: 64, CPUQuotaPercent: 25, PIDsMax: 32, FDsMax: 128, DiskMaxMB: 64,
		},
		UI: &api.PluginUI{
			Entry: "ui/index.html",
			Routes: []api.PluginRoute{
				{Path: "/plugins/com.example.meta", Title: "元数据", Nav: true, Permission: "com.example.meta:read"},
			},
			Widgets: []api.PluginWidget{
				{ID: "status", Title: "状态", Kind: "stat", Operation: "meta.run", RefreshSeconds: 5, Size: "s", Icon: "shield", Color: "green"},
			},
			ConnectSources: []string{"https://api.example.com"},
		},
		Runtime: &api.PluginRuntime{State: "running", Since: created},
	}
	mgr.plugins = []api.Plugin{p}
	mgr.byID[p.PluginID] = p
	return mgr
}

// TestPluginMetadataMembers: GET /plugins and /plugins/{id} expose the manifest
// metadata, the catalog operations (with the reachability clamp applied) and
// the in-memory runtime state (GAPS gap 3; ADR-0016).
func TestPluginMetadataMembers(t *testing.T) {
	m, err := manifest.Parse([]byte(metadataManifestJSON))
	if err != nil {
		t.Fatalf("fixture manifest: %v", err)
	}
	mgr := metadataPluginManager(t)
	e := newPluginTestEnv(t, mgr)
	if err := e.c.Catalog().SetPlugin(m, func(string) ([]byte, error) {
		return []byte(`{"type":"object"}`), nil
	}); err != nil {
		t.Fatalf("SetPlugin: %v", err)
	}
	a := e.setupAdmin(adminUser)

	got := e.do(a.sign(http.MethodGet, "/api/v1/plugins/com.example.meta", "")).expect(t, http.StatusOK).decodeMap(t)
	if mustString(t, got, "description") != "说明文本，供应用详情页展示。" ||
		mustString(t, got, "icon_url") != "/plugin-ui/com.example.meta/1.2.3/assets/icon.svg" ||
		mustString(t, got, "homepage") != "https://example.com/meta" ||
		mustString(t, got, "license") != "MIT" {
		t.Fatalf("manifest metadata = %s %s %s %s", got["description"], got["icon_url"], got["homepage"], got["license"])
	}
	if got["has_config"] != true {
		t.Fatalf("has_config = %v", got["has_config"])
	}
	if _, ok := got["builtin"]; ok {
		t.Fatalf("builtin present for a third-party plugin: %v", got["builtin"])
	}

	caps, _ := got["capabilities"].([]any)
	if len(caps) != 2 {
		t.Fatalf("capabilities = %v", got["capabilities"])
	}
	first := caps[0].(map[string]any)
	if first["name"] != "system.firewall.manage" || first["scope"] != "nftables" ||
		first["reason"] != "调整防火墙" || first["sensitive"] != true {
		t.Fatalf("capability = %v", first)
	}
	if second := caps[1].(map[string]any); second["sensitive"] != false {
		t.Fatalf("state.kv.write sensitive = %v", second["sensitive"])
	}

	res, _ := got["resources"].(map[string]any)
	if res == nil || res["memory_max_mb"] != float64(64) || res["disk_max_mb"] != float64(64) {
		t.Fatalf("resources = %v", got["resources"])
	}
	deps, _ := got["dependencies"].([]any)
	if len(deps) != 1 || deps[0] != "security.scan" {
		t.Fatalf("dependencies = %v", got["dependencies"])
	}

	ui, _ := got["ui"].(map[string]any)
	if ui == nil || ui["entry_url"] != "/plugin-ui/com.example.meta/1.2.3/ui/index.html" {
		t.Fatalf("ui = %v", got["ui"])
	}
	routes, _ := ui["routes"].([]any)
	if len(routes) != 1 {
		t.Fatalf("ui.routes = %v", ui["routes"])
	}
	route := routes[0].(map[string]any)
	if route["path"] != "/plugins/com.example.meta" || route["nav"] != true || route["permission"] != "com.example.meta:read" {
		t.Fatalf("route = %v", route)
	}
	widgets, _ := ui["widgets"].([]any)
	if len(widgets) != 1 {
		t.Fatalf("ui.widgets = %v", ui["widgets"])
	}
	widget := widgets[0].(map[string]any)
	if widget["id"] != "status" || widget["kind"] != "stat" || widget["operation"] != "meta.run" ||
		widget["refresh_seconds"] != float64(5) || widget["size"] != "s" || widget["icon"] != "shield" || widget["color"] != "green" {
		t.Fatalf("widget = %v", widget)
	}
	sources, _ := ui["connect_sources"].([]any)
	if len(sources) != 1 || sources[0] != "https://api.example.com" {
		t.Fatalf("connect_sources = %v", ui["connect_sources"])
	}

	ops, _ := got["operations"].([]any)
	if len(ops) != 2 {
		t.Fatalf("operations = %v", got["operations"])
	}
	apply := ops[0].(map[string]any)
	// meta.apply declares no approval: the derived confirm is stricter than the
	// ai_confirm floor of a reachability action, so it is kept.
	if apply["id"] != "com.example.meta/meta.apply" || apply["declared_risk"] != "medium" ||
		apply["risk"] != "high" || apply["approval"] != "confirm" || apply["reachability"] != true {
		t.Fatalf("meta.apply = %v", apply)
	}
	run := ops[1].(map[string]any)
	if run["id"] != "com.example.meta/meta.run" || run["reachability"] != nil {
		t.Fatalf("meta.run = %v", run)
	}

	runtime, _ := got["runtime"].(map[string]any)
	if runtime == nil || runtime["state"] != "running" {
		t.Fatalf("runtime = %v", got["runtime"])
	}

	// The list carries the same members.
	page := e.do(a.sign(http.MethodGet, "/api/v1/plugins", "")).expect(t, http.StatusOK)
	var list struct {
		Items []map[string]any `json:"items"`
	}
	page.decode(t, &list)
	if len(list.Items) != 1 || list.Items[0]["description"] != "说明文本，供应用详情页展示。" {
		t.Fatalf("list item = %v", list.Items)
	}
	if rt, _ := list.Items[0]["runtime"].(map[string]any); rt == nil || rt["state"] != "running" {
		t.Fatalf("list runtime = %v", list.Items[0]["runtime"])
	}
}

// TestPluginConfigSchemaRoute: GET /plugins/{id}/config-schema returns the
// schema itself, untrusted, and maps a missing plugin to NOT_FOUND.
func TestPluginConfigSchemaRoute(t *testing.T) {
	mgr := metadataPluginManager(t)
	mgr.schemas["com.example.meta"] = json.RawMessage(`{"type":"object","properties":{"interval":{"type":"integer","minimum":2}}}`)
	mgr.missing["ghost"] = true
	e := newPluginTestEnv(t, mgr)
	a := e.setupAdmin(adminUser)

	var schema map[string]any
	e.do(a.sign(http.MethodGet, "/api/v1/plugins/com.example.meta/config-schema", "")).expect(t, http.StatusOK).decode(t, &schema)
	if schema["type"] != "object" {
		t.Fatalf("schema = %v", schema)
	}
	props, _ := schema["properties"].(map[string]any)
	if _, ok := props["interval"]; !ok {
		t.Fatalf("schema properties = %v", schema["properties"])
	}

	e.do(a.sign(http.MethodGet, "/api/v1/plugins/ghost/config-schema", "")).expect(t, http.StatusNotFound)
}
