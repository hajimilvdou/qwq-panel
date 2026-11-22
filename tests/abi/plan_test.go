// SPDX-License-Identifier: AGPL-3.0-only

package abi_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	"google.golang.org/grpc/codes"

	pb "github.com/qwq-panel/qwq/sdk/gen/qwq/platform/v1"
)

// Scenario three: an AI agent enables the security baseline (ADR-0004 D6–D8):
// plan -> AWAITING_APPROVAL -> human approval -> execute(plan_id) -> SUCCEEDED.

// opManager is the slice of the gateway that binds a plan to its execution (ADR-0004 D7).
type opManager struct {
	h     *fakeHost
	inst  *hostInstance
	plans map[string]*plan
}

type plan struct {
	id       string
	op       *hostOp // the operation that plan_id will execute; it already has the payload and actor
	hash     [32]byte
	preconds []*pb.Precondition
	changes  []*pb.PlannedChange
	risk     pb.RiskLevel
	approver *pb.Actor
}

func newOpManager(h *fakeHost, inst *hostInstance) *opManager {
	return &opManager{h: h, inst: inst, plans: map[string]*plan{}}
}

// Plan creates the operation (PENDING), dispatches PlanOperation for it, stores the plan and applies
// the default policy: effective risk medium or high -> AWAITING_APPROVAL.
func (m *opManager) Plan(t *testing.T, actor *pb.Actor, opName string, payload []byte) (*plan, error) {
	t.Helper()
	desc := findOp(m.inst.plugin.desc, opName)
	if desc == nil || !desc.GetPlannable() {
		return nil, fmt.Errorf("%s is not plannable", opName)
	}
	op := m.h.newOp(opSpec{target: m.inst, op: opName, actor: actor, payload: payload})
	m.h.mu.Lock()
	op.dispatched, op.planning = true, true
	m.h.mu.Unlock()
	resp, err := m.inst.plugin.client.PlanOperation(testCtx(t), &pb.PlanOperationRequest{
		Context: m.h.requestContext(op), Operation: opName, ApiVersion: desc.GetApiVersion(), PayloadJson: payload})
	m.h.mu.Lock()
	op.dispatched, op.planning = false, false
	m.h.mu.Unlock()
	switch {
	case err != nil:
		m.h.finish(op, pb.OperationState_OPERATION_STATE_FAILED, nil, errorFromStatus(err))
		return nil, err
	case resp.GetError() != nil:
		m.h.finish(op, pb.OperationState_OPERATION_STATE_FAILED, nil, resp.GetError())
		return nil, fmt.Errorf("plan failed: %s", resp.GetError().GetCode())
	}
	for _, s := range append(subjectsOf(resp.GetChanges()), subjectsOfPre(resp.GetPreconditions())...) {
		if err := validRelativeSubject(s); err != nil {
			m.h.finish(op, pb.OperationState_OPERATION_STATE_FAILED, nil, &pb.ErrorDetail{Code: "PROTOCOL_ERROR", Message: err.Error()})
			return nil, err
		}
	}
	p := &plan{id: m.h.nextID("plan"), op: op, hash: sha256.Sum256(payload), preconds: resp.GetPreconditions(),
		changes: resp.GetChanges(), risk: op.risk}
	m.plans[p.id] = p
	if p.risk >= pb.RiskLevel_RISK_LEVEL_MEDIUM {
		m.h.setState(op, pb.OperationState_OPERATION_STATE_AWAITING_APPROVAL)
	}
	return p, nil
}

func subjectsOf(cs []*pb.PlannedChange) (out []string) {
	for _, c := range cs {
		out = append(out, c.GetSubject())
	}
	return out
}

func subjectsOfPre(ps []*pb.Precondition) (out []string) {
	for _, p := range ps {
		out = append(out, p.GetSubject())
	}
	return out
}

var errNotApprover = errors.New("only a human session can approve")

// Approve accepts only a human session; a delegation token (AI agent or service) never approves,
// even on behalf of the right user (ADR-0004 D6).
func (m *opManager) Approve(planID string, approver *pb.Actor) error {
	p := m.plans[planID]
	if p == nil {
		return fmt.Errorf("unknown plan %s", planID)
	}
	if approver.GetKind() != pb.ActorKind_ACTOR_KIND_HUMAN {
		return errNotApprover
	}
	m.h.mu.Lock()
	defer m.h.mu.Unlock()
	if p.op.state != pb.OperationState_OPERATION_STATE_AWAITING_APPROVAL {
		return fmt.Errorf("plan %s is %v", planID, p.op.state)
	}
	p.approver = approver
	m.h.setStateLocked(p.op, pb.OperationState_OPERATION_STATE_APPROVED)
	return nil
}

// Execute runs exactly what was planned: the stored payload, the plan's preconditions, attempt 1.
func (m *opManager) Execute(planID string) (*hostOp, error) {
	p := m.plans[planID]
	if p == nil {
		return nil, fmt.Errorf("unknown plan %s", planID)
	}
	m.h.mu.Lock()
	st := p.op.state
	m.h.mu.Unlock()
	ready := st == pb.OperationState_OPERATION_STATE_APPROVED ||
		(st == pb.OperationState_OPERATION_STATE_PENDING && p.risk < pb.RiskLevel_RISK_LEVEL_MEDIUM)
	if !ready {
		return nil, fmt.Errorf("plan %s is %v", planID, st)
	}
	if sha256.Sum256(p.op.payload) != p.hash {
		return nil, errors.New("payload differs from the plan")
	}
	p.op.preconds = p.preconds // set before the operation is dispatched, never changed afterwards
	m.h.runJob(p.op)
	return p.op, nil
}

// run is plan -> approve (by approver) -> execute -> await.
func (m *opManager) run(t *testing.T, actor, approver *pb.Actor, payload []byte) (*plan, opView) {
	t.Helper()
	p, err := m.Plan(t, actor, "baseline.enable", payload)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Approve(p.id, approver); err != nil {
		t.Fatal(err)
	}
	op, err := m.Execute(p.id)
	if err != nil {
		t.Fatal(err)
	}
	return p, m.h.await(t, op)
}

func newSecurityEnv(t *testing.T) (*fakeHost, *securityScan, *hostInstance, *opManager) {
	t.Helper()
	h := newFakeHost(t)
	p := &securityScan{basePlugin: newBasePlugin(securityScanDescriptor())}
	inst := h.start(t, h.mustLoad(t, "local", p), "default", nil)
	return h, p, inst, newOpManager(h, inst)
}

var aiAgent = &pb.Actor{Kind: pb.ActorKind_ACTOR_KIND_AI_AGENT, Id: "agent-1", OnBehalfOf: "user-1"}

func TestPlanApproveExecute(t *testing.T) {
	h, _, inst, m := newSecurityEnv(t)
	payload := []byte(`{"interval_hours":24}`)

	p, err := m.Plan(t, aiAgent, "baseline.enable", payload)
	if err != nil {
		t.Fatal(err)
	}
	if v := h.view(p.op); v.State != pb.OperationState_OPERATION_STATE_AWAITING_APPROVAL || p.risk != pb.RiskLevel_RISK_LEVEL_MEDIUM {
		t.Fatalf("after plan: %v, risk %v", v.State, p.risk)
	}
	c := p.changes
	if len(c) != 1 || c[0].GetKind() != pb.PlannedChange_KIND_CREATE || c[0].GetSubject() != "baseline" ||
		c[0].GetBeforeJson() != nil || !c[0].GetReversible() || c[0].GetDescription() == "" {
		t.Fatalf("planned changes = %v", c)
	}
	if len(p.preconds) != 1 || p.preconds[0].GetSubject() != "baseline" || p.preconds[0].GetRevision() != "" {
		t.Fatalf("preconditions = %v", p.preconds)
	}
	if _, found := h.kvGet(inst, "baseline"); found {
		t.Fatal("PlanOperation wrote state")
	}

	// The same AI cannot approve, even on behalf of the right user.
	if err := m.Approve(p.id, aiAgent); !errors.Is(err, errNotApprover) {
		t.Fatalf("AI approval: %v", err)
	}
	if _, err := m.Execute(p.id); err == nil {
		t.Fatal("executed without approval")
	}
	if err := m.Approve(p.id, human("user-1")); err != nil {
		t.Fatal(err)
	}
	op, err := m.Execute(p.id)
	if err != nil {
		t.Fatal(err)
	}
	v := h.await(t, op)
	want := []pb.OperationState{pb.OperationState_OPERATION_STATE_PENDING, pb.OperationState_OPERATION_STATE_AWAITING_APPROVAL,
		pb.OperationState_OPERATION_STATE_APPROVED, pb.OperationState_OPERATION_STATE_RUNNING, pb.OperationState_OPERATION_STATE_SUCCEEDED}
	if fmt.Sprint(v.History) != fmt.Sprint(want) {
		t.Fatalf("history = %v %v", v.History, v.Err)
	}
	wantSteps(t, v.Progress, "ssh", "ports", "weak_password")
	if len(v.Progress) != 4 || !v.Progress[3].GetCompleted() {
		t.Fatalf("progress = %v", v.Progress)
	}
	for i := 1; i < len(v.Progress); i++ {
		if v.Progress[i].GetPercent() <= v.Progress[i-1].GetPercent() {
			t.Fatalf("percent not increasing: %v", v.Progress)
		}
	}

	// What was confirmed is what was executed.
	stored, _ := h.kvGet(inst, "baseline")
	if !bytes.Equal(stored.value, c[0].GetAfterJson()) {
		t.Fatalf("stored %s, planned %s", stored.value, c[0].GetAfterJson())
	}

	ev := h.eventsOf(op.id)
	if len(ev) != 3 {
		t.Fatalf("%d resource.changed events", len(ev))
	}
	for i, e := range ev {
		var payload resourceChanged
		if err := json.Unmarshal(e.GetPayloadJson(), &payload); err != nil {
			t.Fatal(err)
		}
		if e.GetType() != "resource.changed" || e.GetSubject() != "nodes/local/plugins/security.scan/instances/default/resources/baseline" ||
			e.GetActor().GetKind() != pb.ActorKind_ACTOR_KIND_AI_AGENT || e.GetActor().GetOnBehalfOf() != "user-1" ||
			e.GetOperationId() != op.id || payload.Revision != v.Progress[i].GetChanges()[0].GetRevision() ||
			len(payload.ChangedPointers) == 0 {
			t.Fatalf("event %d = %v %s", i, e, e.GetPayloadJson())
		}
	}
	var last resourceChanged
	_ = json.Unmarshal(ev[2].GetPayloadJson(), &last)
	if last.Revision != stored.revision {
		t.Fatalf("last event revision %s, KV revision %s", last.Revision, stored.revision)
	}
	wantNoViolations(t, h)
}

func TestPlanPreconditionFailed(t *testing.T) {
	for _, c := range []struct {
		name      string
		seedFirst bool // the baseline exists before the AI plans (UPDATE + expected_revision)
	}{{"created after the plan", false}, {"updated after the plan", true}} {
		t.Run(c.name, func(t *testing.T) {
			h, _, inst, m := newSecurityEnv(t)
			if c.seedFirst {
				m.run(t, human("user-1"), human("user-1"), []byte(`{"interval_hours":48}`))
			}
			p, err := m.Plan(t, aiAgent, "baseline.enable", []byte(`{"interval_hours":24}`))
			if err != nil {
				t.Fatal(err)
			}
			// A human changes the baseline between the AI's plan and its execution.
			if _, hv := m.run(t, human("user-1"), human("user-1"), []byte(`{"interval_hours":12}`)); hv.State != pb.OperationState_OPERATION_STATE_SUCCEEDED {
				t.Fatalf("human edit = %v %v", hv.State, hv.Err)
			}
			humanWrite, _ := h.kvGet(inst, "baseline")

			if err := m.Approve(p.id, human("user-1")); err != nil {
				t.Fatal(err)
			}
			op, err := m.Execute(p.id)
			if err != nil {
				t.Fatal(err)
			}
			v := h.await(t, op)
			if v.State != pb.OperationState_OPERATION_STATE_FAILED || v.Err.GetCode() != "PRECONDITION_FAILED" {
				t.Fatalf("AI execution = %v %v", v.State, v.Err)
			}
			if len(v.Progress) != 1 || len(h.eventsOf(op.id)) != 0 {
				t.Fatalf("failed execution reported progress %v", v.Progress)
			}
			if got, _ := h.kvGet(inst, "baseline"); got.revision != humanWrite.revision || !bytes.Equal(got.value, humanWrite.value) {
				t.Fatalf("KV = %s@%s, want the human's %s@%s", got.value, got.revision, humanWrite.value, humanWrite.revision)
			}
		})
	}
}

// Effective risk = max(declared, capability floor), over the operation's capabilities, or over every
// plugin capability when the operation declares none (ADR-0004 D6, ADR-0007 #4).
func TestPlanEffectiveRisk(t *testing.T) {
	d := securityScanDescriptor()
	destructive := &pb.OperationDescriptor{Name: "reports.purge", Effect: pb.OperationEffect_OPERATION_EFFECT_DESTRUCTIVE,
		Risk: pb.RiskLevel_RISK_LEVEL_LOW, Capabilities: []*pb.Capability{capability("state.kv.write", "self")}}
	for _, c := range []struct {
		op   *pb.OperationDescriptor
		want pb.RiskLevel
	}{
		// declared medium, floor of state.kv.write is low
		{findOp(d, "baseline.enable"), pb.RiskLevel_RISK_LEVEL_MEDIUM},
		// declares no capabilities, so the floor is taken over the plugin's, which include
		// system.config.read (floor high)
		{findOp(d, "report.summary"), pb.RiskLevel_RISK_LEVEL_HIGH},
		// effect=read, risk=low, but it declares system.config.read itself
		{findOp(d, "scan.run"), pb.RiskLevel_RISK_LEVEL_HIGH},
		{destructive, pb.RiskLevel_RISK_LEVEL_HIGH},
	} {
		if got := effectiveRisk(d, c.op); got != c.want {
			t.Errorf("%s: effective risk %v, want %v", c.op.GetName(), got, c.want)
		}
	}
	// The plan carries the effective risk, not the declared one.
	_, _, _, m := newSecurityEnv(t)
	p, err := m.Plan(t, aiAgent, "baseline.enable", []byte(`{"interval_hours":24}`))
	if err != nil || p.risk != pb.RiskLevel_RISK_LEVEL_MEDIUM {
		t.Fatalf("plan risk = %v, %v", p.GetRisk(), err)
	}
}

func (p *plan) GetRisk() pb.RiskLevel {
	if p == nil {
		return pb.RiskLevel_RISK_LEVEL_UNSPECIFIED
	}
	return p.risk
}

// The host can refuse writes made during PlanOperation only when they carry the operation_id. The
// same write without operation_id is checked against the plugin-level grant and succeeds, so
// "plans are side-effect free" is not enforceable with the current ABI (see report).
func TestPlanSideEffectsWithoutOperationID(t *testing.T) {
	h, p, inst, m := newSecurityEnv(t)
	probe := make(chan [2]codes.Code, 1)
	p.mu.Lock()
	p.planProbe = probe
	p.mu.Unlock()
	if _, err := m.Plan(t, aiAgent, "baseline.enable", []byte(`{"interval_hours":24}`)); err != nil {
		t.Fatal(err)
	}
	got := recv(t, probe, "plan-time writes")
	if got[0] != codes.PermissionDenied || got[1] != codes.OK {
		t.Fatalf("plan-time PutState with/without operation_id = %v, want PermissionDenied/OK", got)
	}
	if _, found := h.kvGet(inst, "probe"); !found {
		t.Fatal("expected the write without operation_id to land")
	}
}
