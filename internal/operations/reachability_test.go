// SPDX-License-Identifier: AGPL-3.0-only

package operations

import "testing"

// TestReachabilityClampsRiskAndApproval covers the host-side floor of a
// reachability action (ADR-0016): the effective risk is at least high and the
// governing approval level at least ai_confirm, whatever the declaration says.
// A stricter declaration is kept; nothing raises confirm to ai_confirm.
func TestReachabilityClampsRiskAndApproval(t *testing.T) {
	cases := []struct {
		name     string
		action   Action
		wantRisk string
		wantAppr string
	}{
		{
			// A medium risk is raised; the derived write approval confirm is
			// stricter than ai_confirm and stays.
			"a declared medium risk is raised",
			Action{Source: PluginSource, Effect: EffectWrite, Risk: RiskMedium, Reachability: true},
			RiskHigh, ApprovalConfirm,
		},
		{
			"an auto approval is raised",
			Action{Source: PluginSource, Effect: EffectWrite, Risk: RiskHigh, Reachability: true, Approval: ApprovalAuto},
			RiskHigh, ApprovalAIConfirm,
		},
		{
			"ai_confirm is kept",
			Action{Source: PluginSource, Effect: EffectWrite, Risk: RiskHigh, Reachability: true, Approval: ApprovalAIConfirm},
			RiskHigh, ApprovalAIConfirm,
		},
		{
			"confirm is kept",
			Action{Source: PluginSource, Effect: EffectWrite, Risk: RiskHigh, Reachability: true, Approval: ApprovalConfirm},
			RiskHigh, ApprovalConfirm,
		},
		{
			"without the flag nothing changes",
			Action{Source: PluginSource, Effect: EffectWrite, Risk: RiskMedium, Approval: ApprovalAuto},
			RiskMedium, ApprovalAuto,
		},
	}
	for _, c := range cases {
		if got := c.action.EffectiveRisk(); got != c.wantRisk {
			t.Errorf("%s: EffectiveRisk = %q, want %q", c.name, got, c.wantRisk)
		}
		if got := c.action.ApprovalLevel(); got != c.wantAppr {
			t.Errorf("%s: ApprovalLevel = %q, want %q", c.name, got, c.wantAppr)
		}
	}
}

// TestForcedReachability: a non-read operation that may use a lockout
// capability is reachability-changing even when the manifest did not declare it
// (ADR-0016, GAPS gap 5).
func TestForcedReachability(t *testing.T) {
	cases := []struct {
		name   string
		effect string
		caps   []Capability
		want   bool
	}{
		{"firewall capability forces a write", EffectWrite, []Capability{{Name: "system.firewall.manage", Scope: "nftables"}}, true},
		{"ssh capability forces a write", EffectWrite, []Capability{{Name: "system.sshd.configure", Scope: "drop-in"}}, true},
		{"panel listening forces a write", EffectWrite, []Capability{{Name: "system.panel.listen", Scope: "8443"}}, true},
		{"tls capability forces a write", EffectWrite, []Capability{{Name: "system.tls.certificate", Scope: "panel"}}, true},
		{"network capability forces a write", EffectWrite, []Capability{{Name: "system.network.config", Scope: "eth0"}}, true},
		{"the exact family name matches", EffectWrite, []Capability{{Name: "system.firewall", Scope: "nftables"}}, true},
		{"a read never forces", EffectRead, []Capability{{Name: "system.firewall.manage", Scope: "nftables"}}, false},
		{"unrelated capabilities do not force", EffectWrite, []Capability{{Name: "state.kv.write", Scope: "self"}}, false},
		{"proxy data plane does not force reachability", EffectWrite, []Capability{{Name: "network.proxy", Scope: "direct"}}, false},
		{"a lookalike prefix does not match", EffectWrite, []Capability{{Name: "system.firewallx", Scope: "x"}}, false},
		{"no capabilities at all", EffectWrite, nil, false},
	}
	for _, c := range cases {
		if got := ForcedReachability(c.effect, c.caps); got != c.want {
			t.Errorf("%s: ForcedReachability = %v, want %v", c.name, got, c.want)
		}
	}
}

// TestCapabilitySensitive: the install wizard gives a capability its own
// consent line when it pins the risk floor at high (ARCH §10.3 高敏).
func TestCapabilitySensitive(t *testing.T) {
	cases := map[string]bool{
		"secret.reveal":            true,
		"secret.reveal.dns_token":  true,
		"system.firewall.manage":   true,
		"system.sshd.configure":    true,
		"network.egress":           true,
		"network.egress.s3":        true,
		"network.proxy":            true,
		"network.proxy.direct":     true,
		"network.proxyx":           false,
		"state.kv.write":           false,
		"state.kv.read":            false,
		"metrics.read":             false,
		"metrics.read.host":        false,
		"events.publish":           false,
		"events.publish.alert":     false,
		"systemlookalike.do":       false,
		"public.route":             false,
		"public.route.status_page": false,
	}
	for name, want := range cases {
		if got := CapabilitySensitive(name); got != want {
			t.Errorf("CapabilitySensitive(%q) = %v, want %v", name, got, want)
		}
	}
}

// TestP6ForcedReachability 覆盖账户/封禁真实管理通道风险及点分段边界。
func TestP6ForcedReachability(t *testing.T) {
	for _, name := range []string{"system.account", "system.account.keys", "system.account.password", "system.ban", "system.ban.manage"} {
		for _, effect := range []string{EffectWrite, EffectDestructive} {
			if !ForcedReachability(effect, []Capability{{Name: name, Scope: "all"}}) {
				t.Errorf("管理能力未触发可达性兜底：%s", name)
			}
		}
		if ForcedReachability(EffectRead, []Capability{{Name: name, Scope: "all"}}) {
			t.Errorf("读操作被错误强制：%s", name)
		}
	}
	for _, name := range []string{"system.accounting", "system.banana", "metrics.read", "network.proxy"} {
		if ForcedReachability(EffectWrite, []Capability{{Name: name, Scope: "self"}}) {
			t.Errorf("近似前缀/无关能力被误匹配：%s", name)
		}
	}
}
