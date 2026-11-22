// SPDX-License-Identifier: AGPL-3.0-only

package authz

import (
	"testing"

	"github.com/qwq-panel/qwq/internal/platform/problem"
)

func TestParsePermission(t *testing.T) {
	valid := []string{"host.users:create", "host.plugins:install", "com.example.monitor:read", "host.nodes:list"}
	for _, s := range valid {
		p, err := ParsePermission(s)
		if err != nil {
			t.Fatalf("ParsePermission(%q): %v", s, err)
		}
		if string(p) != s || p.Resource()+":"+p.Action() != s {
			t.Fatalf("%q split into %q:%q", s, p.Resource(), p.Action())
		}
	}
	invalid := []string{"", "hostusers", "host.users:", "Host.Users:create", "host.users:Create", ":read", "host users:read"}
	for _, s := range invalid {
		if _, err := ParsePermission(s); !problem.HasCode(err, problem.ValidationFailed) {
			t.Errorf("ParsePermission(%q) = %v, want VALIDATION_FAILED", s, err)
		}
	}
}

func TestPatternMatches(t *testing.T) {
	cases := []struct {
		pattern string
		perm    string
		want    bool
	}{
		{"*", "host.users:create", true},
		{"*", "com.example.monitor:read", true},
		{"host.users:*", "host.users:create", true},
		{"host.users:*", "host.users:read", true},
		{"host.users:read", "host.users:create", false},
		{"host.users:create", "host.users:create", true},
		{"host.*:create", "host.users:create", false}, // whole-segment wildcard only
		{"host.users:read", "host.plugins:read", false},
		{"com.example.monitor:read", "com.example.monitor:write", false},
	}
	for _, c := range cases {
		if got := Pattern(c.pattern).Matches(Permission(c.perm)); got != c.want {
			t.Errorf("Pattern(%q).Matches(%q) = %v, want %v", c.pattern, c.perm, got, c.want)
		}
	}
}

func TestRoleGrants(t *testing.T) {
	cases := []struct {
		role string
		perm string
		want bool
	}{
		{"admin", "host.users:create", true},
		{"admin", "host.approvals:approve", true},
		{"operator", "host.plugins:install", true},
		{"operator", "host.nodes:read", true},
		{"operator", "host.users:read", false},
		{"operator", "host.delegations:create", true},
		{"operator", "host.service_accounts:revoke", false},
		{"viewer", "host.nodes:read", true},
		{"viewer", "host.users:list", false},
		{"viewer", "host.users:create", false},
		{"viewer", "host.plugins:install", false},
		{"root", "host.nodes:read", false}, // unknown role fails closed
		// Everyone manages their own account; the handler targets the caller.
		{"admin", "host.account:update", true},
		{"operator", "host.account:update", true},
		{"viewer", "host.account:update", true},
		{"root", "host.account:update", false},
		// Providers are administrator-only to manage; everyone may list.
		{"admin", "host.ai_providers:create", true},
		{"operator", "host.ai_providers:create", false},
		{"operator", "host.ai_providers:update", false},
		{"operator", "host.ai_providers:delete", false},
		{"operator", "host.ai_providers:read", true},
		{"viewer", "host.ai_providers:create", false},
		{"viewer", "host.ai_providers:read", true},
	}
	for _, c := range cases {
		if got := RoleAllows(Role(c.role), Permission(c.perm)); got != c.want {
			t.Errorf("RoleAllows(%q, %q) = %v, want %v", c.role, c.perm, got, c.want)
		}
	}
	if !UnknownRole("root") || UnknownRole("admin") {
		t.Fatal("UnknownRole is wrong")
	}
	if _, err := ParseRole("root"); !problem.HasCode(err, problem.ValidationFailed) {
		t.Fatalf("ParseRole(root) = %v", err)
	}
}

func TestPolicyValidationAndDefaults(t *testing.T) {
	p := Policy{}
	n := p.Normalized()
	if n.AutoApproveMaxRisk != "low" || n.OnApprovalRequired != "queue" || n.RequestsPerMinute != 60 {
		t.Fatalf("defaults = %+v", n)
	}
	if err := n.Validate(); err != nil {
		t.Fatalf("default policy invalid: %v", err)
	}
	bad := []Policy{
		{Actions: []string{"UPPER/case"}},
		{Actions: []string{""}},
		{NodeIDs: []string{"Local Node"}},
		{AutoApproveMaxRisk: "high"},
		{OnApprovalRequired: "reject"},
		{RequestsPerMinute: 601},
	}
	for _, p := range bad {
		if err := p.Validate(); !problem.HasCode(err, problem.ValidationFailed) {
			t.Errorf("Validate(%+v) = %v, want VALIDATION_FAILED", p, err)
		}
	}
}

func TestPolicyAllowsAction(t *testing.T) {
	all := Policy{}
	if !all.AllowsAction("host.users.create") || !all.AllowsAction("com.example.monitor/scan.run") {
		t.Fatal("empty action list should allow everything")
	}
	p := Policy{Actions: []string{"com.example.monitor/*", "host.nodes.read"}}
	cases := []struct {
		action string
		want   bool
	}{
		{"com.example.monitor/scan.run", true},
		{"com.example.monitor/apply", true},
		{"com.example.other/scan.run", false},
		{"host.nodes.read", true},
		{"host.nodes.write", false},
		{"host.nodes", false}, // wrong segment count
	}
	for _, c := range cases {
		if got := p.AllowsAction(c.action); got != c.want {
			t.Errorf("AllowsAction(%q) = %v, want %v", c.action, got, c.want)
		}
	}
}

func TestPolicyCovers(t *testing.T) {
	base := Policy{
		Actions:            []string{"com.example.monitor/*"},
		NodeIDs:            []string{"local"},
		AutoApproveMaxRisk: "low",
		OnApprovalRequired: "fail",
		RequestsPerMinute:  60,
	}
	narrower := Policy{
		Actions:            []string{"com.example.monitor/*"},
		NodeIDs:            []string{"local"},
		AutoApproveMaxRisk: "none",
		OnApprovalRequired: "fail",
		RequestsPerMinute:  30,
	}
	if err := base.Covers(narrower); err != nil {
		t.Fatalf("narrower policy rejected: %v", err)
	}
	if err := base.Covers(base); err != nil {
		t.Fatalf("same policy rejected: %v", err)
	}
	wider := []Policy{
		{Actions: []string{"host.users.create"}},
		{NodeIDs: []string{"other"}},
		{AutoApproveMaxRisk: "low", OnApprovalRequired: "queue", RequestsPerMinute: 120},
		{OnApprovalRequired: "queue", RequestsPerMinute: 60},
	}
	for _, w := range wider {
		if err := base.Covers(w); !problem.HasCode(err, problem.ValidationFailed) {
			t.Errorf("Covers(%+v) = %v, want VALIDATION_FAILED", w, err)
		}
	}
	// An unrestricted base policy covers any restriction.
	if err := (Policy{}).Covers(narrower); err != nil {
		t.Fatalf("unrestricted policy rejected a restriction: %v", err)
	}
}
