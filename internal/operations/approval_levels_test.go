// SPDX-License-Identifier: AGPL-3.0-only

package operations

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/qwq-panel/qwq/internal/actor"
	"github.com/qwq-panel/qwq/internal/platform/problem"
)

// pluginAction returns an action copy with the given approval metadata, so a
// test can exercise a level without growing the shared fixture.
func pluginAction(level, risk, effect string) Action {
	return Action{
		ID: "com.example.demo/scan.run", Source: PluginSource, Effect: effect, Risk: risk,
		Mode: ModeInvoke, Idempotent: true, Permission: pluginID + ":scan", PluginID: pluginID,
		Placement: PlacementNode, Operation: "scan.run", APIVersion: "1", TimeoutMS: 5000,
		Approval: level,
	}
}

// TestDecideApprovalMatrix is the two-dimensional policy of ADR-0010 §2 and
// §2.1: permission mode x approval level x actor kind, inside the host hard
// rules that neither dimension may relax.
func TestDecideApprovalMatrix(t *testing.T) {
	who := map[string]actor.Actor{"human": humanActor(), "ai": aiActor(), "service": serviceActor()}
	limits := func(mode PermissionMode) Limits { return Limits{PermissionMode: mode} }
	cases := []struct {
		name   string
		act    Action
		who    actor.Actor
		lim    Limits
		denied bool
		need   bool
	}{
		// safe is the default and asks for everything except auto/low.
		{"safe confirm human", pluginAction(ApprovalConfirm, RiskLow, EffectWrite), who["human"], limits(""), false, true},
		{"safe confirm ai", pluginAction(ApprovalConfirm, RiskLow, EffectWrite), who["ai"], limits(PermissionSafe), false, true},
		{"safe confirm service", pluginAction(ApprovalConfirm, RiskLow, EffectWrite), who["service"], limits(PermissionSafe), false, true},
		{"safe auto human", pluginAction(ApprovalAuto, RiskLow, EffectWrite), who["human"], limits(PermissionSafe), false, false},
		{"safe auto ai", pluginAction(ApprovalAuto, RiskLow, EffectWrite), who["ai"], limits(PermissionSafe), false, false},
		{"safe auto medium", pluginAction(ApprovalAuto, RiskMedium, EffectWrite), who["human"], limits(PermissionSafe), false, true},
		{"safe auto high", pluginAction(ApprovalAuto, RiskHigh, EffectWrite), who["human"], limits(PermissionSafe), false, true},
		{"safe ai_confirm ai", pluginAction(ApprovalAIConfirm, RiskLow, EffectWrite), who["ai"], limits(PermissionSafe), false, true},
		{"safe ai_confirm human", pluginAction(ApprovalAIConfirm, RiskLow, EffectWrite), who["human"], limits(PermissionSafe), false, false},
		{"safe ai_confirm service", pluginAction(ApprovalAIConfirm, RiskLow, EffectWrite), who["service"], limits(PermissionSafe), false, false},
		{"safe ai_confirm human medium", pluginAction(ApprovalAIConfirm, RiskMedium, EffectWrite), who["human"], limits(PermissionSafe), false, true},
		// The declaration is empty: a plugin operation derives confirm from its
		// effect, a host action keeps the pre-ADR-0010 rule.
		{"derived plugin write", pluginAction("", RiskLow, EffectWrite), who["human"], limits(PermissionSafe), false, true},
		{"derived plugin read", pluginAction("", RiskLow, EffectRead), who["human"], limits(PermissionSafe), false, false},
		{"host write low", Action{ID: "host.users.update", Source: HostSource, Effect: EffectWrite, Risk: RiskLow}, who["human"], limits(PermissionSafe), false, false},
		{"host write medium", Action{ID: "host.users.update", Source: HostSource, Effect: EffectWrite, Risk: RiskMedium}, who["human"], limits(PermissionSafe), false, true},
		// Destructive asks in every mode, and auto cannot lower it.
		{"safe destructive", pluginAction(ApprovalAuto, RiskHigh, EffectDestructive), who["human"], limits(PermissionSafe), false, true},
		{"full destructive auto", pluginAction(ApprovalAuto, RiskHigh, EffectDestructive), who["ai"], limits(PermissionFull), false, true},
		{"full destructive confirm", pluginAction(ApprovalConfirm, RiskHigh, EffectDestructive), who["human"], limits(PermissionFull), false, true},
		// full skips the plugin levels and the high-risk rule.
		{"full confirm", pluginAction(ApprovalConfirm, RiskLow, EffectWrite), who["human"], limits(PermissionFull), false, false},
		{"full confirm ai", pluginAction(ApprovalConfirm, RiskLow, EffectWrite), who["ai"], limits(PermissionFull), false, false},
		{"full ai_confirm ai", pluginAction(ApprovalAIConfirm, RiskLow, EffectWrite), who["ai"], limits(PermissionFull), false, false},
		{"full auto high", pluginAction(ApprovalAuto, RiskHigh, EffectWrite), who["human"], limits(PermissionFull), false, false},
		// read_only refuses writes outright, including destructive ones.
		{"read_only write", pluginAction(ApprovalAuto, RiskLow, EffectWrite), who["human"], limits(PermissionReadOnly), true, false},
		{"read_only ai confirm", pluginAction(ApprovalConfirm, RiskLow, EffectWrite), who["ai"], limits(PermissionReadOnly), true, false},
		{"read_only destructive", pluginAction(ApprovalAuto, RiskHigh, EffectDestructive), who["human"], limits(PermissionReadOnly), true, false},
		{"read_only read", pluginAction(ApprovalAuto, RiskLow, EffectRead), who["human"], limits(PermissionReadOnly), false, false},
		// custom is level-based until per-item overrides exist.
		{"custom confirm", pluginAction(ApprovalConfirm, RiskLow, EffectWrite), who["human"], limits(PermissionCustom), false, true},
		{"custom ai_confirm ai", pluginAction(ApprovalAIConfirm, RiskLow, EffectWrite), who["ai"], limits(PermissionCustom), false, true},
		{"custom auto", pluginAction(ApprovalAuto, RiskLow, EffectWrite), who["human"], limits(PermissionCustom), false, false},
		// A policy that auto-approves nothing still wins inside safe; full is
		// the caller's explicit choice and overrides it.
		{"policy none safe auto", pluginAction(ApprovalAuto, RiskLow, EffectWrite), who["human"],
			Limits{AutoApproveMaxRisk: AutoApproveNone}, false, true},
		{"policy none full auto", pluginAction(ApprovalAuto, RiskLow, EffectWrite), who["human"],
			Limits{AutoApproveMaxRisk: AutoApproveNone, PermissionMode: PermissionFull}, false, false},
		{"policy high lets medium run", pluginAction(ApprovalAuto, RiskMedium, EffectWrite), who["human"],
			Limits{AutoApproveMaxRisk: RiskHigh}, false, false},
		// Unknown data cannot widen anything.
		{"unknown mode is safe", pluginAction(ApprovalConfirm, RiskLow, EffectWrite), who["human"], Limits{PermissionMode: "yolo"}, false, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.act.DecideApproval(tc.who, tc.act.EffectiveRisk(), tc.lim)
			if got.Denied != tc.denied || got.NeedApproval != tc.need {
				t.Fatalf("DecideApproval = %+v (reason %s), want denied=%v need=%v",
					got, got.Reason, tc.denied, tc.need)
			}
			if (got.Denied || got.NeedApproval) && got.Reason == "" {
				t.Fatal("a positive decision must carry a reason")
			}
		})
	}
}

// TestPermissionModeNormalized: an empty, invalid or missing mode is safe, and
// the four documented modes round-trip.
func TestPermissionModeNormalized(t *testing.T) {
	if got := (Limits{}).Mode(); got != PermissionSafe {
		t.Fatalf("default mode = %q", got)
	}
	if got := (Limits{PermissionMode: "yolo"}).Mode(); got != PermissionSafe {
		t.Fatalf("unknown mode = %q, want safe", got)
	}
	for _, m := range []PermissionMode{PermissionReadOnly, PermissionSafe, PermissionFull, PermissionCustom} {
		if !m.Valid() || (Limits{PermissionMode: m}).Mode() != m {
			t.Fatalf("%q does not round-trip", m)
		}
	}
	if !PermissionMode("").Valid() {
		t.Fatal("the empty mode must be valid (it means the default)")
	}
}

// TestApprovalLevelsEndToEnd walks confirm and ai_confirm for a human, a
// delegation and a service account through the real write path: confirm always
// queues an approval, ai_confirm queues one for the delegation only.
func TestApprovalLevelsEndToEnd(t *testing.T) {
	actors := []struct {
		name string
		who  actor.Actor
	}{
		{"human", humanActor()},
		{"ai", aiActor()},
		{"service", serviceActor()},
	}
	for _, level := range []string{ApprovalConfirm, ApprovalAIConfirm} {
		for _, a := range actors {
			t.Run(level+"/"+a.name, func(t *testing.T) {
				e := newTestEnv(t)
				e.setAction(actionPlugin, func(act *Action) {
					act.Approval = level
					act.ApprovalSummary = "立即执行一次巡检"
					act.ApprovalDescription = "只读取配置，不修改任何内容。"
				})
				resp, err := e.run(a.who, actionPlugin, nodeTarget(), map[string]any{})
				if err != nil {
					t.Fatalf("run: %v", err)
				}
				wantApproval := level == ApprovalConfirm || a.name == "ai"
				if wantApproval {
					if resp.Status != 202 || resp.Operation.Status != AwaitingApproval || resp.Operation.ApprovalID == "" {
						t.Fatalf("response = %d %s approval %q", resp.Status, resp.Operation.Status, resp.Operation.ApprovalID)
					}
					// The plugin's own text is on the card, marked as its text.
					facts := e.approval(resp.Operation.ApprovalID).Facts
					if facts.ApprovalSummary != "立即执行一次巡检" || facts.ApprovalDescription == "" {
						t.Fatalf("card text = %q / %q", facts.ApprovalSummary, facts.ApprovalDescription)
					}
					if facts.Action.Approval != level {
						t.Fatalf("action approval = %q, want %q", facts.Action.Approval, level)
					}
					// A human decides; the mode and level never let an AI approve.
					if _, err := e.decide(a.who, resp.Operation.ApprovalID, DecisionApprove); a.name != "human" {
						if !problem.HasCode(err, problem.PermissionDenied) {
							t.Fatalf("%s decision = %v, want PERMISSION_DENIED", a.name, err)
						}
					} else if err != nil {
						t.Fatalf("human decision: %v", err)
					}
					return
				}
				if resp.Status != 200 || resp.Operation.Status != Succeeded {
					t.Fatalf("response = %d %s, want a synchronous success", resp.Status, resp.Operation.Status)
				}
				if e.dispatcher.invokeCount() == 0 {
					t.Fatal("the operation did not run")
				}
			})
		}
	}
}

// TestPermissionModeFullSkipsPluginApprovals: full drops confirm, ai_confirm
// and the high-risk rule for every actor, but never a destructive operation.
func TestPermissionModeFullSkipsPluginApprovals(t *testing.T) {
	e := newTestEnv(t)
	e.setAction(actionPlugin, func(act *Action) {
		act.Approval = ApprovalConfirm
		act.Risk = RiskHigh
		act.ApprovalSummary = "完整巡检"
	})
	e.policy.set(humanActor(), Limits{PermissionMode: PermissionFull})
	e.policy.set(aiActor(), Limits{PermissionMode: PermissionFull})
	e.policy.set(serviceActor(), Limits{PermissionMode: PermissionFull})
	for _, who := range []actor.Actor{humanActor(), aiActor(), serviceActor()} {
		resp, err := e.run(who, actionPlugin, nodeTarget(), map[string]any{})
		if err != nil {
			t.Fatalf("%s: %v", who.Kind, err)
		}
		if resp.Status != 200 || resp.Operation.Status != Succeeded || resp.Operation.ApprovalID != "" {
			t.Fatalf("%s: %d %s approval %q", who.Kind, resp.Status, resp.Operation.Status, resp.Operation.ApprovalID)
		}
	}
	// Destructive is the hard rule full keeps.
	resp, err := e.run(humanActor(), actionDestroy, Target{Subject: resourceSubject}, map[string]any{"value": "gone"})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Operation.Status != AwaitingApproval {
		t.Fatalf("destructive in full mode = %s, want AWAITING_APPROVAL", resp.Operation.Status)
	}
	approval := e.approval(resp.Operation.ApprovalID)
	if !approval.RequiresMFA {
		t.Fatal("a destructive approval still demands the second factor in full mode")
	}
	if approval.Facts.PermissionMode != PermissionFull {
		t.Fatalf("permission mode on the card = %q", approval.Facts.PermissionMode)
	}
	if _, err := e.decide(humanMFA(), approval.ID, DecisionApprove); err != nil {
		t.Fatalf("approve: %v", err)
	}
}

// TestPermissionModeReadOnlyDeniesWrites: nothing is queued and no operation
// exists after a refused write; reads and plans still work.
func TestPermissionModeReadOnlyDeniesWrites(t *testing.T) {
	e := newTestEnv(t)
	e.policy.set(humanActor(), Limits{PermissionMode: PermissionReadOnly})
	_, err := e.run(humanActor(), actionPlugin, nodeTarget(), map[string]any{})
	if !problem.HasCode(err, problem.PermissionDenied) {
		t.Fatalf("read_only write = %v, want PERMISSION_DENIED", err)
	}
	if n := e.countOperations(); n != 0 {
		t.Fatalf("a refused write created %d operations", n)
	}
	page, err := e.svc.ListApprovals(e.ctx, humanActor(), ApprovalFilter{})
	if err != nil || len(page.Items) != 0 {
		t.Fatalf("approvals = %+v, %v", page, err)
	}
	// A plan is a side-effect free preview: allowed. Executing it is not.
	plan, err := e.svc.CreatePlan(e.ctx, PlanRequest{
		Actor: humanActor(), Action: actionPlugin, Target: nodeTarget(),
		Args: mustJSON(t, map[string]any{}),
	})
	if err != nil {
		t.Fatalf("create plan: %v", err)
	}
	if plan.RequiresApproval {
		t.Fatal("read_only does not queue approvals")
	}
	_, err = e.svc.ExecutePlan(e.ctx, ExecutePlanRequest{
		Actor: humanActor(), PlanID: plan.ID,
		Idempotency: Idempotency{Key: e.newKey(), Route: "/api/v1/plans/" + plan.ID + "/execute"},
	})
	if !problem.HasCode(err, problem.PermissionDenied) {
		t.Fatalf("read_only execute plan = %v, want PERMISSION_DENIED", err)
	}
	// A read action is the point of the mode and still runs.
	if _, err := e.run(humanActor(), actionRead, nodeTarget(), map[string]any{}); err != nil {
		t.Fatalf("read in read_only mode: %v", err)
	}
}

// TestApprovalCardCarriesPluginTextAndMode checks the card fields of ADR-0010
// §4 on the create, list, get and decision responses, and that a host action
// carries none of the plugin text.
func TestApprovalCardCarriesPluginTextAndMode(t *testing.T) {
	e := newTestEnv(t)
	description := "写入巡检计划并立即生效。\n- 作用：按计划检查 SSH 与端口\n- 是否可撤销：可以"
	e.setAction(actionPlugin, func(act *Action) {
		act.Approval = ApprovalConfirm
		act.ApprovalSummary = "开启定期安全巡检"
		act.ApprovalDescription = description
	})
	e.policy.set(humanActor(), Limits{PermissionMode: PermissionCustom})
	resp, err := e.run(humanActor(), actionPlugin, nodeTarget(), map[string]any{})
	if err != nil {
		t.Fatal(err)
	}
	facts := e.approval(resp.Operation.ApprovalID).Facts
	if facts.ApprovalSummary != "开启定期安全巡检" || facts.ApprovalDescription != description {
		t.Fatalf("card text = %q / %q", facts.ApprovalSummary, facts.ApprovalDescription)
	}
	if facts.PermissionMode != PermissionCustom {
		t.Fatalf("permission_mode = %q", facts.PermissionMode)
	}
	if facts.Action.Approval != ApprovalConfirm || facts.Action.ApprovalSummary != "开启定期安全巡检" ||
		facts.Action.ApprovalDescription != description {
		t.Fatalf("action meta approval = %+v", facts.Action)
	}
	// get and list carry the same facts.
	got, err := e.svc.GetApproval(e.ctx, humanActor(), resp.Operation.ApprovalID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Facts.ApprovalSummary != "开启定期安全巡检" || got.Facts.PermissionMode != PermissionCustom {
		t.Fatalf("get approval facts = %+v", got.Facts)
	}
	page, err := e.svc.ListApprovals(e.ctx, humanActor(), ApprovalFilter{})
	if err != nil || len(page.Items) != 1 {
		t.Fatalf("list approvals = %+v, %v", page, err)
	}
	if page.Items[0].Facts.ApprovalSummary != "开启定期安全巡检" {
		t.Fatalf("listed approval = %+v", page.Items[0].Facts)
	}
	// The decision response carries them too, and the wire names are the
	// documented ones.
	decided, err := e.decide(humanActor(), resp.Operation.ApprovalID, DecisionApprove)
	if err != nil {
		t.Fatalf("decide: %v", err)
	}
	if decided.Approval == nil || decided.Approval.Facts.ApprovalSummary != "开启定期安全巡检" {
		t.Fatalf("decided approval = %+v", decided.Approval)
	}
	raw, err := json.Marshal(decided.Approval.Facts)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{`"approval_summary"`, `"approval_description"`, `"permission_mode"`, `"approval":"confirm"`} {
		if !strings.Contains(string(raw), key) {
			t.Errorf("facts JSON lacks %s: %s", key, raw)
		}
	}
	// A host action has no plugin text on its card.
	hostResp, err := e.run(humanActor(), actionHigh, Target{Subject: resourceSubject}, map[string]any{"value": "x"})
	if err != nil {
		t.Fatal(err)
	}
	hostFacts := e.approval(hostResp.Operation.ApprovalID).Facts
	if hostFacts.ApprovalSummary != "" || hostFacts.ApprovalDescription != "" || hostFacts.Action.Approval != "" {
		t.Fatalf("host card text = %+v", hostFacts)
	}
}

// TestApprovalLevelDoesNotChangeApprovers: whichever level queued the approval,
// only a human browser session may decide it (ADR-0010 §5, ADR-0004 acceptance 3).
func TestApprovalLevelDoesNotChangeApprovers(t *testing.T) {
	e := newTestEnv(t)
	e.setAction(actionPlugin, func(act *Action) { act.Approval = ApprovalConfirm })
	approvalID := func(who actor.Actor) string {
		resp, err := e.run(who, actionPlugin, nodeTarget(), map[string]any{})
		if err != nil {
			t.Fatal(err)
		}
		if resp.Operation.ApprovalID == "" {
			t.Fatalf("%s: no approval was queued", who.Kind)
		}
		return resp.Operation.ApprovalID
	}
	id := approvalID(humanActor())
	for _, who := range []actor.Actor{aiActor(), serviceActor()} {
		if _, err := e.decide(who, id, DecisionApprove); !problem.HasCode(err, problem.PermissionDenied) {
			t.Fatalf("%s approval = %v, want PERMISSION_DENIED", who.Kind, err)
		}
	}
	if current := e.approval(id); current.Status != ApprovalPending {
		t.Fatalf("approval = %s after refused decisions", current.Status)
	}
	if _, err := e.decide(humanActor(), id, DecisionApprove); err != nil {
		t.Fatalf("human decision: %v", err)
	}
}

// TestInvalidApprovalLevelIsRejected: a catalog Action with an unknown level is
// a metadata bug, not a quieter operation.
func TestInvalidApprovalLevelIsRejected(t *testing.T) {
	e := newTestEnv(t)
	e.setAction(actionPlugin, func(act *Action) { act.Approval = "always" })
	if _, err := e.run(humanActor(), actionPlugin, nodeTarget(), map[string]any{}); err == nil {
		t.Fatal("an unknown approval level was accepted")
	}
}
