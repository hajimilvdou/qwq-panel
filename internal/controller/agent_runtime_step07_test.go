// SPDX-License-Identifier: AGPL-3.0-only

package controller

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/qwq-panel/qwq/internal/actor"
	"github.com/qwq-panel/qwq/internal/agentsession"
	"github.com/qwq-panel/qwq/internal/identity"
	"github.com/qwq-panel/qwq/internal/netfacts"
	"github.com/qwq-panel/qwq/internal/operations"
	"github.com/qwq-panel/qwq/internal/platform/problem"
)

func TestAgentToolCatalogOffersBuiltinHostReadTools(t *testing.T) {
	e := newAgentEnv(t)
	tools := AgentToolCatalog{
		Catalog:    e.c.Catalog(),
		HostAction: e.c.Operations().HasHostAction,
	}.Actions(e.t.Context())
	byAction := map[string]agentsession.ToolSpec{}
	for _, spec := range tools {
		byAction[spec.Action] = spec
	}
	for _, want := range BuiltinHostReadTools() {
		spec, ok := byAction[want.Action]
		if !ok {
			t.Fatalf("missing builtin host read tool %q", want.Action)
		}
		if spec.Effect != operations.EffectRead || spec.Risk != operations.RiskLow {
			t.Fatalf("tool %q = %+v, want read/low", want.Action, spec)
		}
	}
}

func TestAgentRunnerHostReadToolsRBACAndExecution(t *testing.T) {
	e := newAgentEnv(t)
	e.runner.Controller = e.c
	e.runner.Authz = e.c.Authorizer()
	e.runner.NetFacts = func() (netfacts.HostNetworkFacts, error) {
		return netfacts.HostNetworkFacts{
			HasDefaultRouteV4: true,
			Addresses:         []netfacts.AddressFact{{Address: "203.0.113.10", Family: "ipv4", Scope: "public"}},
		}, nil
	}

	// Admin in read_only mode can invoke all 6 host read tools directly.
	for i, spec := range BuiltinHostReadTools() {
		res := e.run(e.call(e.admin.ID, operations.PermissionReadOnly, spec.Action, `{}`, 500+i))
		if res.Status != agentsession.ToolSucceeded {
			t.Fatalf("admin read_only %s failed: %+v", spec.Action, res)
		}
		if len(res.Result) == 0 || !json.Valid(res.Result) {
			t.Fatalf("admin %s returned invalid JSON: %q", spec.Action, res.Result)
		}
		if spec.Action == "host.system.info" {
			var doc map[string]any
			_ = json.Unmarshal(res.Result, &doc)
			if doc["listen"] == nil || doc["data_dir"] == nil {
				t.Fatalf("admin host.system.info should include listen and data_dir: %+v", doc)
			}
		}
	}

	// Viewer gets host.system.info without admin-only listen/data_dir fields.
	vRes := e.run(e.call(e.viewer.ID, operations.PermissionReadOnly, "host.system.info", `{}`, 599))
	if vRes.Status != agentsession.ToolSucceeded {
		t.Fatalf("viewer host.system.info failed: %+v", vRes)
	}
	var vDoc map[string]any
	_ = json.Unmarshal(vRes.Result, &vDoc)
	if _, hasListen := vDoc["listen"]; hasListen {
		t.Fatalf("viewer host.system.info leaked listen address: %+v", vDoc)
	}
	if _, hasDataDir := vDoc["data_dir"]; hasDataDir {
		t.Fatalf("viewer host.system.info leaked data_dir: %+v", vDoc)
	}
}

func TestAgentApprovalsMintExternalApprovalEndToEnd(t *testing.T) {
	e := newAgentEnv(t)
	operator := e.createUser("agent-op", identity.RoleOperator)
	e.bridge.OwnerLookup = func(_ context.Context, sessionID string) (actor.Actor, bool) {
		if sessionID == "sess_ext_admin" {
			return actor.Actor{Kind: actor.Human, ID: e.admin.ID}, true
		}
		return actor.Actor{}, false
	}

	aprID, opID, err := e.bridge.MintApproval(e.t.Context(), "sess_ext_admin", agentsession.ExternalApprovalRequest{
		CallID:  "call_ext_1",
		Kind:    agentsession.ApprovalKindShell,
		Action:  "codex.exec_command",
		Summary: "Codex 请求执行命令: systemctl reload nginx",
		Risk:    "high",
		Args:    json.RawMessage(`{"command":"systemctl reload nginx"}`),
	})
	if err != nil {
		t.Fatalf("MintApproval failed: %v", err)
	}
	if aprID == "" || opID == "" {
		t.Fatalf("expected non-empty approval/op IDs: apr=%q op=%q", aprID, opID)
	}

	// Operator MUST NOT be allowed to approve external CLI shell actions.
	_, err = e.c.Operations().Decide(e.t.Context(), operations.DecisionRequest{
		Actor:      humanActor(operator),
		ApprovalID: aprID,
		Decision:   operations.DecisionApprove,
		Idempotency: operations.Idempotency{
			Key: "op_try_" + aprID, Method: "POST", Route: "/api/v1/approvals/" + aprID + "/decision",
		},
	})
	if err == nil || !problem.HasCode(err, problem.PermissionDenied) {
		t.Fatalf("operator decide external approval = %v, want PERMISSION_DENIED", err)
	}

	// Admin human session approves it; Wait unblocks with DecisionApprove + ToolSucceeded.
	ctx, cancel := context.WithTimeout(e.t.Context(), 5*time.Second)
	defer cancel()
	w := e.waitBridge(ctx, aprID)
	e.decide(aprID, operations.DecisionApprove)
	dec := w.result(t, 3*time.Second)
	if dec.Decision != agentsession.DecisionApprove || dec.Status != agentsession.ToolSucceeded {
		t.Fatalf("unexpected external approval decision: %+v", dec)
	}
}
