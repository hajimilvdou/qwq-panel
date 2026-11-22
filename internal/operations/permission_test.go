// SPDX-License-Identifier: AGPL-3.0-only

package operations

import "testing"

// TestFullModeKeepsHostHighRiskApproval: full only relaxes plugin actions. A
// host action whose effective risk is high still asks a person, so a host
// action that slips into an AI tool list never runs unreviewed (ADR-0010 §3).
func TestFullModeKeepsHostHighRiskApproval(t *testing.T) {
	full := Limits{PermissionMode: PermissionFull}
	host := func(risk string) Action {
		return Action{ID: "host.example.update", Source: HostSource, Effect: EffectWrite, Risk: risk}
	}
	cases := []struct {
		name string
		act  Action
		need bool
	}{
		{"host high", host(RiskHigh), true},
		{"host medium", host(RiskMedium), false},
		{"host low", host(RiskLow), false},
		{"plugin high", pluginAction(ApprovalAuto, RiskHigh, EffectWrite), false},
	}
	for _, tc := range cases {
		for _, who := range []string{"human", "ai"} {
			a := humanActor()
			if who == "ai" {
				a = aiActor()
			}
			got := tc.act.DecideApproval(a, tc.act.EffectiveRisk(), full)
			if got.Denied || got.NeedApproval != tc.need {
				t.Errorf("%s/%s: %+v, want need=%v", tc.name, who, got, tc.need)
			}
			if tc.need && got.Reason != reasonHighRisk {
				t.Errorf("%s/%s: reason %q, want %q", tc.name, who, got.Reason, reasonHighRisk)
			}
		}
	}
}
