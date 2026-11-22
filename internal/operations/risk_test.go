// SPDX-License-Identifier: AGPL-3.0-only

package operations

import (
	"errors"
	"strings"
	"testing"

	"github.com/qwq-panel/qwq/internal/platform/problem"
)

func TestRiskFloor(t *testing.T) {
	cases := []struct {
		name     string
		declared string
		effect   string
		caps     []Capability
		want     string
	}{
		{"declared only", RiskLow, EffectWrite, nil, RiskLow},
		{"declared high stays high", RiskHigh, EffectWrite, nil, RiskHigh},
		{"destructive is high", RiskLow, EffectDestructive, nil, RiskHigh},
		{"system capability is high", RiskLow, EffectWrite, []Capability{{Name: "system.firewall"}}, RiskHigh},
		{"secret reveal is high", RiskLow, EffectWrite, []Capability{{Name: "secret.reveal"}}, RiskHigh},
		{"secret reveal scoped is high", RiskLow, EffectWrite, []Capability{{Name: "secret.reveal", Scope: "env/*"}}, RiskHigh},
		{"network egress is high", RiskLow, EffectWrite, []Capability{{Name: "network.egress"}}, RiskHigh},
		{"network proxy is high", RiskLow, EffectWrite, []Capability{{Name: "network.proxy", Scope: "direct"}}, RiskHigh},
		{"network proxy lookalike is medium", RiskLow, EffectWrite, []Capability{{Name: "network.proxyx", Scope: "direct"}}, RiskMedium},
		{"state is low", RiskMedium, EffectWrite, []Capability{{Name: "state.kv.read"}}, RiskMedium},
		{"events is low", RiskLow, EffectWrite, []Capability{{Name: "events.publish"}}, RiskLow},
		{"metrics read is low", RiskLow, EffectRead, []Capability{{Name: "metrics.read"}}, RiskLow},
		{"unknown capability is medium", RiskLow, EffectWrite, []Capability{{Name: "vendor.custom"}}, RiskMedium},
		{"highest of many wins", RiskLow, EffectWrite, []Capability{
			{Name: "state.kv.read"}, {Name: "vendor.custom"}, {Name: "system.service"},
		}, RiskHigh},
		{"unknown declared risk is medium", "", EffectWrite, nil, RiskMedium},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := RiskFloor(tc.declared, tc.effect, tc.caps); got != tc.want {
				t.Fatalf("RiskFloor(%q, %q, %v) = %q, want %q", tc.declared, tc.effect, tc.caps, got, tc.want)
			}
		})
	}
	// A destructive effect cannot be lowered by capabilities either.
	if got := RiskFloor(RiskHigh, EffectDestructive, []Capability{{Name: "state.kv.read"}}); got != RiskHigh {
		t.Fatalf("destructive with low capability = %q", got)
	}
}

func TestLimitsNeedsApproval(t *testing.T) {
	def := Limits{AutoApproveMaxRisk: RiskLow, OnApprovalRequired: ApprovalQueue}
	if def.NeedsApproval(EffectRead, RiskHigh) {
		t.Fatal("read actions never need approval")
	}
	if def.NeedsApproval(EffectWrite, RiskLow) {
		t.Fatal("low risk runs by default")
	}
	if !def.NeedsApproval(EffectWrite, RiskMedium) {
		t.Fatal("medium risk needs approval by default")
	}
	if !def.NeedsApproval(EffectWrite, RiskHigh) {
		t.Fatal("high risk needs approval by default")
	}
	// The zero value means the default policy, not "approve everything".
	zero := Limits{}
	if zero.NeedsApproval(EffectWrite, RiskLow) {
		t.Fatal("zero Limits must default to auto-approving low risk")
	}
	none := Limits{AutoApproveMaxRisk: AutoApproveNone}
	if !none.NeedsApproval(EffectWrite, RiskLow) {
		t.Fatal("none auto-approves nothing")
	}
}

func TestAllowedTransitions(t *testing.T) {
	serial := []Status{Pending, AwaitingApproval, Approved, Running, Succeeded}
	for i := 0; i+1 < len(serial); i++ {
		if !allowedTransition(serial[i], serial[i+1]) {
			t.Fatalf("%s -> %s must be allowed", serial[i], serial[i+1])
		}
	}
	allowed := [][2]Status{
		{Pending, Canceled}, {Pending, Failed}, {Pending, Running},
		{AwaitingApproval, Rejected}, {AwaitingApproval, Expired}, {AwaitingApproval, Canceled},
		{Approved, Canceled}, {Approved, Failed},
		{Running, Failed}, {Running, Canceled},
	}
	for _, p := range allowed {
		if !allowedTransition(p[0], p[1]) {
			t.Fatalf("%s -> %s must be allowed", p[0], p[1])
		}
	}
	denied := [][2]Status{
		{Succeeded, Running}, {Failed, Succeeded}, {Canceled, Running}, {Rejected, Approved},
		{Expired, AwaitingApproval}, {Running, Pending}, {Running, AwaitingApproval},
		{AwaitingApproval, Running}, {Approved, AwaitingApproval},
	}
	for _, p := range denied {
		if allowedTransition(p[0], p[1]) {
			t.Fatalf("%s -> %s must be rejected", p[0], p[1])
		}
	}
}

func TestStateConflictError(t *testing.T) {
	err := stateConflict(&Operation{ID: "op_x"}, AwaitingApproval, Running)
	if !problem.HasCode(err, problem.StateConflict) {
		t.Fatalf("got %v, want STATE_CONFLICT", err)
	}
	var pe *problem.Error
	if !errors.As(err, &pe) || pe.OperationID != "op_x" {
		t.Fatalf("state conflict must carry the operation id: %v", err)
	}
}

func TestPrefixPluginSubject(t *testing.T) {
	got, err := prefixPluginSubject(PlacementNode, "local", pluginID, "default", "alerts/cpu")
	if err != nil {
		t.Fatal(err)
	}
	want := "nodes/local/plugins/com.example.demo/instances/default/resources/alerts/cpu"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
	got, err = prefixPluginSubject(PlacementController, "", pluginID, "", "baseline")
	if err != nil {
		t.Fatal(err)
	}
	if want := "plugins/com.example.demo/resources/baseline"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
	for _, bad := range []string{"", "/leading", "trailing/", "a//b", "a/../b", "a/./b", "has space", strings.Repeat("a", 129)} {
		if _, err := prefixPluginSubject(PlacementNode, "local", pluginID, "default", bad); err == nil {
			t.Fatalf("relative subject %q was accepted", bad)
		}
	}
	if _, err := prefixPluginSubject(PlacementNode, "local", pluginID, "default", strings.Repeat("a/", 300)+"b"); err == nil {
		t.Fatal("overlong subject was accepted")
	}
	if _, err := prefixPluginSubject("sideways", "local", pluginID, "default", "a"); err == nil {
		t.Fatal("unknown placement was accepted")
	}
}

func TestValidateFullSubject(t *testing.T) {
	ok := []string{
		"users/usr_1", "operations/op_01", "nodes/local/plugins/com.example.demo/instances/default/resources/x",
		"plugins/com.example.demo/resources/a", "approvals/apv_1", "users",
	}
	for _, s := range ok {
		if err := validateFullSubject(s); err != nil {
			t.Fatalf("%q rejected: %v", s, err)
		}
	}
	bad := []string{"", "Users/x", "users//x", "users/x/", "/users/x", "users/../x", "users/has space",
		strings.Repeat("a", 600)}
	for _, s := range bad {
		if err := validateFullSubject(s); err == nil {
			t.Fatalf("%q accepted", s)
		}
	}
}

func TestCanonicalJSON(t *testing.T) {
	a, err := canonicalJSON([]byte(`{"b": 1, "a": {"d": 2, "c": [3, 1]}}`))
	if err != nil {
		t.Fatal(err)
	}
	b, err := canonicalJSON([]byte(`{"a":{"c":[3,1],"d":2},"b":1}`))
	if err != nil {
		t.Fatal(err)
	}
	if string(a) != string(b) {
		t.Fatalf("canonical forms differ:\n%s\n%s", a, b)
	}
	if want := `{"a":{"c":[3,1],"d":2},"b":1}`; string(a) != want {
		t.Fatalf("got %s, want %s", a, want)
	}
	if digestOf(a) != digestOf(b) {
		t.Fatal("digests of equal documents differ")
	}
	c, err := canonicalJSON([]byte(`{"b":2,"a":{"d":2,"c":[3,1]}}`))
	if err != nil {
		t.Fatal(err)
	}
	if digestOf(a) == digestOf(c) {
		t.Fatal("different documents share a digest")
	}
	if _, err := canonicalJSON([]byte(`{"a":1}{"b":2}`)); err == nil {
		t.Fatal("trailing data accepted")
	}
	if _, err := canonicalObject([]byte(`[1,2]`)); err == nil {
		t.Fatal("array accepted as arguments")
	}
	empty, err := canonicalObject(nil)
	if err != nil || string(empty) != "{}" {
		t.Fatalf("empty arguments: %s, %v", empty, err)
	}
}
