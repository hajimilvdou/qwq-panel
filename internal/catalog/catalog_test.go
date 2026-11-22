// SPDX-License-Identifier: AGPL-3.0-only

package catalog

import (
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/qwq-panel/qwq/sdk/manifest"
)

// floor mirrors the ADR-0004 D6 table closely enough for tests.
func floor(declared, effect string, caps []Capability) string {
	rank := map[string]int{"low": 1, "medium": 2, "high": 3}
	r := rank[declared]
	if effect == "destructive" {
		r = 3
	}
	for _, c := range caps {
		switch {
		case strings.HasPrefix(c.Name, "system."):
			r = max(r, 3)
		case strings.HasPrefix(c.Name, "state."):
			r = max(r, 1)
		}
	}
	return []string{"", "low", "medium", "high"}[r]
}

// forced mirrors operations.ForcedReachability closely enough for tests: a
// non-read operation that may use the host firewall is reachability-changing.
func forced(effect string, caps []Capability) bool {
	if effect == "read" {
		return false
	}
	for _, c := range caps {
		if strings.HasPrefix(c.Name, "system.firewall") {
			return true
		}
	}
	return false
}

func newCatalog(t *testing.T) *Catalog {
	t.Helper()
	c, err := New(floor, forced)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func examplePlugin(t *testing.T) *manifest.Manifest {
	t.Helper()
	raw, err := os.ReadFile("../../api/manifest/v1/examples/security.scan.manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	m, err := manifest.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func schemaLoader(path string) ([]byte, error) {
	return []byte(`{"type":"object","properties":{"note":{"type":"string"}}}`), nil
}

func TestHostActionsGenerated(t *testing.T) {
	c := newCatalog(t)
	e, ok := c.Get("host.users.create")
	if !ok || e.Source != Host || e.Method != "POST" || e.Path != "/api/v1/users" || e.Permission == "" {
		t.Fatalf("%+v", e)
	}
	var args map[string]any
	if err := json.Unmarshal(e.ArgsSchema, &args); err != nil {
		t.Fatal(err)
	}
	props := args["properties"].(map[string]any)
	if _, ok := props["username"]; !ok || args["additionalProperties"] != false {
		t.Fatalf("args schema %v", args)
	}
	if strings.Contains(string(e.ArgsSchema), "x-qwq") {
		t.Fatal("vendor extensions leaked into args schema")
	}
	d, _ := c.Get("host.users.delete")
	var dargs map[string]any
	json.Unmarshal(d.ArgsSchema, &dargs)
	if _, ok := dargs["properties"].(map[string]any)["expected_revision"]; !ok {
		t.Fatalf("delete lacks expected_revision: %s", d.ArgsSchema)
	}
	if d.Risk != "high" {
		t.Fatalf("destructive risk %s", d.Risk)
	}
}

func TestPluginEntriesAndRisk(t *testing.T) {
	c := newCatalog(t)
	m := examplePlugin(t)
	if err := c.SetPlugin(m, schemaLoader); err != nil {
		t.Fatal(err)
	}
	scan, ok := c.Get("security.scan/scan.run")
	if !ok || scan.Source != Plugin || scan.PluginID != "security.scan" || scan.Placement != "node" {
		t.Fatalf("%+v", scan)
	}
	// scan.run declares system.config.read: floor raises low to high.
	if scan.DeclaredRisk != "low" || scan.Risk != "high" {
		t.Fatalf("scan.run risk %s/%s", scan.DeclaredRisk, scan.Risk)
	}
	// baseline.enable only uses state.kv.write: declared medium stays medium.
	if b, _ := c.Get("security.scan/baseline.enable"); b.Risk != "medium" || b.Undo != "security.scan/baseline.disable" {
		t.Fatalf("baseline.enable %+v", b)
	}
	// ADR-0010: the declared level and card texts land in the entry, and an
	// operation without a declaration gets the effect-derived default.
	if scan.Approval != "auto" {
		t.Fatalf("scan.run approval = %q, want the derived auto", scan.Approval)
	}
	enable, _ := c.Get("security.scan/baseline.enable")
	if enable.Approval != "ai_confirm" || enable.ApprovalSummary != "开启定期安全巡检" ||
		!strings.Contains(enable.ApprovalDescription, "作用") || !strings.Contains(enable.ApprovalDescription, "\n") {
		t.Fatalf("baseline.enable approval = %q %q %q", enable.Approval, enable.ApprovalSummary, enable.ApprovalDescription)
	}
	if disable, _ := c.Get("security.scan/baseline.disable"); disable.Approval != "confirm" {
		t.Fatalf("baseline.disable approval = %q, want the derived confirm", disable.Approval)
	}
	// Host actions carry no plugin approval metadata.
	if host, _ := c.Get("host.users.update"); host.Approval != "" || host.ApprovalSummary != "" {
		t.Fatalf("host action approval = %q %q", host.Approval, host.ApprovalSummary)
	}
	c.RemovePlugin("security.scan")
	if _, ok := c.Get("security.scan/scan.run"); ok {
		t.Fatal("entry survived RemovePlugin")
	}
}

func TestSetPluginFailureKeepsOldEntries(t *testing.T) {
	c := newCatalog(t)
	m := examplePlugin(t)
	if err := c.SetPlugin(m, schemaLoader); err != nil {
		t.Fatal(err)
	}
	bad := func(string) ([]byte, error) { return nil, errors.New("missing") }
	if err := c.SetPlugin(m, bad); err == nil {
		t.Fatal("bad loader accepted")
	}
	if _, ok := c.Get("security.scan/scan.run"); !ok {
		t.Fatal("old entries lost")
	}
	huge := func(string) ([]byte, error) { return []byte(`"` + strings.Repeat("x", maxSchema) + `"`), nil }
	if err := c.SetPlugin(m, huge); err == nil {
		t.Fatal("oversized schema accepted")
	}
}

func TestFind(t *testing.T) {
	c := newCatalog(t)
	if err := c.SetPlugin(examplePlugin(t), schemaLoader); err != nil {
		t.Fatal(err)
	}
	ids := func(bs []Brief) []string {
		var out []string
		for _, b := range bs {
			out = append(out, b.ID)
		}
		return out
	}
	cases := []struct {
		query, want string
	}{
		{"create user", "host.users.create"},
		{"创建用户", "host.users.create"},
		{"删除用户", "host.users.delete"},
		{"开启巡检", "security.scan/baseline.enable"},
		{"开启安全基线", "security.scan/baseline.enable"},
		{"host.users.update", "host.users.update"},
		{"uninst", "host.plugins.uninstall"},
	}
	for _, tc := range cases {
		got, _ := c.Find(tc.query, Scope{}, 3, nil)
		if len(got) == 0 || got[0].ID != tc.want {
			t.Errorf("Find(%q) = %v, want %s first", tc.query, ids(got), tc.want)
		}
	}
	if got, _ := c.Find("zzzz", Scope{}, 8, nil); len(got) != 0 {
		t.Errorf("nonsense query matched %v", ids(got))
	}
	// Scope and permission filtering.
	got, _ := c.Find("用户 插件 巡检", Scope{PluginID: "security.scan"}, 20, nil)
	for _, b := range got {
		if !strings.HasPrefix(b.ID, "security.scan/") {
			t.Errorf("scope leaked %s", b.ID)
		}
	}
	deny := func(e *Entry) bool { return e.Source == Host }
	got, _ = c.Find("开启巡检", Scope{}, 8, deny)
	for _, b := range got {
		if strings.HasPrefix(b.ID, "security.scan/") {
			t.Errorf("denied action offered: %s", b.ID)
		}
	}
	// Limit and truncation; briefs carry only the four fields.
	all, truncated := c.Find("user plugin scan", Scope{}, 1, nil)
	if len(all) != 1 || !truncated {
		t.Errorf("limit: %v %v", ids(all), truncated)
	}
	b, _ := json.Marshal(all[0])
	var m map[string]any
	json.Unmarshal(b, &m)
	if len(m) != 4 {
		t.Errorf("brief has %d fields: %s", len(m), b)
	}
}

func TestTokens(t *testing.T) {
	got := strings.Join(tokens("开启 SSH 防火墙, Port-22"), "|")
	if got != "开启|ssh|防火|火墙|port|22" {
		t.Fatalf("tokens = %s", got)
	}
	if got := cleanText("a\u202eb\x00c", 120); got != "abc" {
		t.Fatalf("cleanText = %q", got)
	}
}

// TestSetPluginReachabilityClamp: at load the catalog applies the reachability
// floor of ADR-0016. A declared flag is clamped even when the manifest bypassed
// Parse, and a non-read operation that may use a lockout capability is forced
// to reachability without any declaration.
func TestSetPluginReachabilityClamp(t *testing.T) {
	yes := true
	m := &manifest.Manifest{
		SchemaVersion: "1.3", ID: "acme.app", Placement: "node",
		Capabilities: []manifest.Capability{
			{Name: "system.firewall.manage", Scope: "nftables", Reason: "调整防火墙"},
			{Name: "state.kv.write", Scope: "self", Reason: "保存状态"},
		},
		Operations: []manifest.Operation{
			{Name: "fw.open", Effect: "write", Risk: "medium", Mode: "invoke", Approval: "auto",
				Permission: "acme.app:write", Summary: "放行端口", Reachability: &yes,
				RequestSchema: "schemas/x.json", ResponseSchema: "schemas/x.json"},
			{Name: "fw.close", Effect: "write", Risk: "high", Mode: "invoke", Approval: "confirm",
				Permission: "acme.app:write", Summary: "封禁端口", Reachability: &yes,
				RequestSchema: "schemas/x.json", ResponseSchema: "schemas/x.json"},
			{Name: "route.set", Effect: "write", Risk: "medium", Mode: "invoke",
				Permission: "acme.app:write", Summary: "改路由",
				Capabilities:  []manifest.CapabilityRef{{Name: "system.firewall.manage", Scope: "nftables"}},
				RequestSchema: "schemas/x.json", ResponseSchema: "schemas/x.json"},
			{Name: "note.set", Effect: "write", Risk: "medium", Mode: "invoke",
				Permission: "acme.app:write", Summary: "记一笔",
				Capabilities:  []manifest.CapabilityRef{{Name: "state.kv.write", Scope: "self"}},
				RequestSchema: "schemas/x.json", ResponseSchema: "schemas/x.json"},
		},
	}
	c := newCatalog(t)
	if err := c.SetPlugin(m, schemaLoader); err != nil {
		t.Fatal(err)
	}
	open, ok := c.Get("acme.app/fw.open")
	if !ok || !open.Reachability || open.Risk != "high" || open.Approval != "ai_confirm" || open.DeclaredRisk != "medium" {
		t.Fatalf("fw.open = %+v", open)
	}
	close, _ := c.Get("acme.app/fw.close")
	if close.Risk != "high" || close.Approval != "confirm" {
		t.Fatalf("fw.close = %+v", close)
	}
	route, _ := c.Get("acme.app/route.set")
	// The forced flag raises the risk; the approval derived from a write
	// (confirm) is already stricter than the ai_confirm floor.
	if !route.Reachability || route.Risk != "high" || route.Approval != "confirm" {
		t.Fatalf("forced route.set = %+v", route)
	}
	note, _ := c.Get("acme.app/note.set")
	if note.Reachability || note.Risk != "medium" || note.Approval != "confirm" {
		t.Fatalf("note.set = %+v", note)
	}
}
