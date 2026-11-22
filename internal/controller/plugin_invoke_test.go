// SPDX-License-Identifier: AGPL-3.0-only

package controller

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/qwq-panel/qwq/internal/identity"
	"github.com/qwq-panel/qwq/internal/operations"
	"github.com/qwq-panel/qwq/internal/pluginhost/hostsvc"
	"github.com/qwq-panel/qwq/internal/storage"
	platformv1 "github.com/qwq-panel/qwq/sdk/gen/qwq/platform/v1"
	"github.com/qwq-panel/qwq/sdk/manifest"
)

// ---------------------------------------------------------------------------
// ADR-0011 真实链路：真实的 operations.Service、目录、数据库与宿主 Invoker，
// 只有插件进程是假的。覆盖 §后果 列出的全部场景。
// ---------------------------------------------------------------------------

const (
	invokeCaller = "com.example.caller"
	invokeTarget = "com.example.target"
)

type invokeEnv struct {
	t       *testing.T
	c       *Controller
	clients *fakeClients
	client  *fakePluginClient
	admin   identity.User
	invoker *hostInvoker
	keySeq  int
}

func newInvokeEnv(t *testing.T) *invokeEnv {
	t.Helper()
	opts := testOptions(t)
	client := &fakePluginClient{invokeResp: &platformv1.InvokeResponse{PayloadJson: []byte(`{"applied":true}`)}}
	clients := &fakeClients{client: client}
	opts.PluginRuntime = &PluginRuntime{dispatcher: &pluginDispatcher{clients: clients}}
	c, err := New(t.Context(), opts)
	if err != nil {
		t.Fatalf("controller.New: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	ae := &agentEnv{t: t, c: c}
	e := &invokeEnv{t: t, c: c, clients: clients, client: client, admin: ae.createUser("invoke-admin", identity.RoleAdmin)}

	schema := func(string) ([]byte, error) { return []byte(`{"type":"object"}`), nil }
	write := func(name, risk string) manifest.Operation {
		return manifest.Operation{
			Name: name, APIVersion: "1", Permission: invokeTarget + ":" + strings.ReplaceAll(name, ".", "_"), Mode: "invoke",
			Effect: "write", Risk: risk, Idempotent: true, Approval: "auto", Summary: name,
			RequestSchema: "request.json", ResponseSchema: "response.json",
		}
	}
	grant := func(op string) manifest.Capability {
		return manifest.Capability{Name: capPluginInvoke, Scope: invokeTarget + "/" + op, Reason: "test"}
	}
	caller := &manifest.Manifest{
		ID: invokeCaller, Placement: "node",
		Capabilities: []manifest.Capability{grant("rule.apply"), grant("rule.tweak"), grant("rule.read")},
		Operations:   []manifest.Operation{write("scan.run", "low")},
	}
	caller.Operations[0].Permission = invokeCaller + ":scan"
	read := write("rule.read", "low")
	read.Effect = "read"
	target := &manifest.Manifest{
		ID: invokeTarget, Placement: "node",
		Operations: []manifest.Operation{
			write("rule.apply", "high"), write("rule.tweak", "low"), read, write("rule.secret", "low"),
		},
	}
	for _, m := range []*manifest.Manifest{caller, target} {
		if err := c.Catalog().SetPlugin(m, schema); err != nil {
			t.Fatalf("install %s: %v", m.ID, err)
		}
	}
	e.invoker = newTestRuntime(t).newHostInvoker(c.HostDeps(), invokeCaller)
	return e
}

// runningParent creates an operation of the caller plugin and marks it RUNNING,
// i.e. dispatched to the caller right now.
func (e *invokeEnv) runningParent() *operations.Operation {
	e.t.Helper()
	e.keySeq++
	resp, err := e.c.Operations().Run(e.t.Context(), operations.RunRequest{
		Actor: humanActor(e.admin), Action: invokeCaller + "/scan.run",
		Target: operations.Target{NodeID: "local", PluginID: invokeCaller, InstanceID: DefaultInstanceID},
		Args:   json.RawMessage(`{}`),
		Idempotency: operations.Idempotency{Key: "invoke-parent-key-" + strings.Repeat("0", e.keySeq),
			Method: "POST", Route: "/test/parent"},
	})
	if err != nil {
		e.t.Fatalf("create parent: %v", err)
	}
	e.exec(`UPDATE operations SET status = 'RUNNING' WHERE operation_id = ?`, resp.OperationID)
	return e.get(resp.OperationID)
}

func (e *invokeEnv) exec(query string, args ...any) {
	e.t.Helper()
	if err := e.c.DB().Update(e.t.Context(), func(tx *storage.Tx) error {
		_, err := tx.ExecContext(e.t.Context(), query, args...)
		return err
	}); err != nil {
		e.t.Fatalf("exec %q: %v", query, err)
	}
}

func (e *invokeEnv) get(id string) *operations.Operation {
	e.t.Helper()
	op, err := e.c.Operations().Get(e.t.Context(), humanActor(e.admin), id)
	if err != nil {
		e.t.Fatalf("get %s: %v", id, err)
	}
	return op
}

func (e *invokeEnv) invoke(parentID, operation string) hostsvc.InvokeResult {
	e.t.Helper()
	result, err := e.invoker.InvokePlugin(e.t.Context(), hostsvc.InvokeCall{
		CallerPluginID: invokeCaller, CallerInstanceID: DefaultInstanceID, ParentOperationID: parentID,
		TargetPluginID: invokeTarget, Operation: operation, APIVersion: "1",
		PayloadJSON: []byte(`{"port":8080}`),
	})
	if err != nil {
		e.t.Fatalf("InvokePlugin(%s): %v, want a domain result", operation, err)
	}
	return result
}

// auditDetails returns the details of the audit rows with the given action and outcome.
func (e *invokeEnv) auditDetails(action, outcome string) []string {
	e.t.Helper()
	rows, err := e.c.DB().Reader().QueryContext(e.t.Context(),
		`SELECT details FROM audit_log WHERE action = ? AND outcome = ? ORDER BY occurred_at`, action, outcome)
	if err != nil {
		e.t.Fatal(err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var d string
		if err := rows.Scan(&d); err != nil {
			e.t.Fatal(err)
		}
		out = append(out, d)
	}
	return out
}

func wantDenied(t *testing.T, result hostsvc.InvokeResult) {
	t.Helper()
	if result.Error == nil || result.Error.Code != "PERMISSION_DENIED" || result.PayloadJSON != nil || result.OperationID != "" {
		t.Fatalf("result = %+v, want a bare PERMISSION_DENIED", result)
	}
}

// TestPluginInvokeRiskierChildWaitsForApproval is the ADR's failure scenario:
// a riskier target becomes its own AWAITING_APPROVAL child with the full chain
// on record, and the target plugin is not called.
func TestPluginInvokeRiskierChildWaitsForApproval(t *testing.T) {
	e := newInvokeEnv(t)
	parent := e.runningParent()
	_, before, _ := e.client.snapshot()
	result := e.invoke(parent.ID, "rule.apply")
	if result.Error != nil || result.OperationID == "" || result.State != hostsvc.OperationAwaiting {
		t.Fatalf("result = %+v (%+v), want an operation awaiting approval", result, result.Error)
	}
	child := e.get(result.OperationID)
	if child.ParentOperationID != parent.ID || child.Actor.ID != parent.Actor.ID || child.Actor.Kind != parent.Actor.Kind ||
		child.EffectiveRisk != operations.RiskHigh || child.ApprovalID == "" {
		t.Fatalf("child = %+v", child)
	}
	if _, invoked, _ := e.client.snapshot(); invoked != before {
		t.Fatalf("the target ran before the approval: %+v", invoked)
	}
	created := e.auditDetails(invokeTarget+"/rule.apply", operations.AuditSuccess)
	if len(created) == 0 || !strings.Contains(created[0], `"invoked_by":{"plugin_id":"`+invokeCaller+`"`) ||
		!strings.Contains(created[0], `"parent_operation_id":"`+parent.ID+`"`) {
		t.Fatalf("creation audit = %v, want invoked_by and the parent link", created)
	}

	// The caller created it, so it may wait on it; the parent was only
	// dispatched to it, so it may not (ADR-0011 §6).
	if _, err := e.invoker.WaitOperation(t.Context(), hostsvc.WaitCall{OperationID: child.ID}); err != nil {
		t.Fatalf("WaitOperation(own child): %v", err)
	}
	_, err := e.invoker.WaitOperation(t.Context(), hostsvc.WaitCall{OperationID: parent.ID})
	wantNotOwned(t, err)
	_, err = e.invoker.CancelOperation(t.Context(), hostsvc.CancelCall{OperationID: parent.ID})
	wantNotOwned(t, err)
	if status.Code(err) != codes.NotFound || e.get(parent.ID).CancelRequested {
		t.Fatalf("the parent was touched: %v", err)
	}
}

// TestPluginInvokeRunsOnRunningTarget: an allowed, not riskier call runs at
// once, only on a target that already runs.
func TestPluginInvokeRunsOnRunningTarget(t *testing.T) {
	e := newInvokeEnv(t)
	parent := e.runningParent()
	result := e.invoke(parent.ID, "rule.tweak")
	if result.Error != nil || string(result.PayloadJSON) != `{"applied":true}` {
		t.Fatalf("result = %+v (%+v)", result, result.Error)
	}
	if !slices.Contains(e.clients.liveCalls, invokeTarget) || slices.Contains(e.clients.attached, invokeTarget) {
		t.Fatalf("live %v attach %v: a child must not start its target", e.clients.liveCalls, e.clients.attached)
	}
	if _, invoked, _ := e.client.snapshot(); invoked.GetContext().GetActor().GetId() != e.admin.ID {
		t.Fatalf("the target saw actor %+v, want the parent's", invoked.GetContext().GetActor())
	}

	// A read creates no operation; it is audited by the invoker.
	result = e.invoke(parent.ID, "rule.read")
	if result.Error != nil || result.OperationID != "" {
		t.Fatalf("read result = %+v", result)
	}
	if n := len(e.auditDetails("plugin.invoke", operations.AuditSuccess)); n != 1 {
		t.Fatalf("plugin.invoke success audits = %d, want 1", n)
	}

	// A stopped target is unavailable, never started.
	e.clients.liveErr = context.Canceled
	result = e.invoke(parent.ID, "rule.tweak")
	if result.Error == nil || result.Error.Code != "PLUGIN_UNAVAILABLE" {
		t.Fatalf("stopped target = %+v, want PLUGIN_UNAVAILABLE", result)
	}
	if slices.Contains(e.clients.attached, invokeTarget) {
		t.Fatal("a child started its target")
	}
}

// TestPluginInvokeRefusals: forged or missing parents, missing capabilities,
// another node and a too deep chain are refused, and every refusal is audited.
func TestPluginInvokeRefusals(t *testing.T) {
	e := newInvokeEnv(t)
	parent := e.runningParent()
	other := e.invoke(parent.ID, "rule.apply") // an operation of the target, not dispatched to the caller
	finished := e.runningParent()
	e.exec(`UPDATE operations SET status = 'SUCCEEDED' WHERE operation_id = ?`, finished.ID)
	_, before, _ := e.client.snapshot()

	refusals := 0
	for name, parentID := range map[string]string{
		"no parent": "", "unknown parent": "op_forged", "foreign parent": other.OperationID,
		"finished parent": finished.ID,
	} {
		t.Run(name, func(t *testing.T) {
			wantDenied(t, e.invoke(parentID, "rule.tweak"))
		})
		refusals++
	}
	t.Run("missing capability", func(t *testing.T) {
		wantDenied(t, e.invoke(parent.ID, "rule.secret"))
	})
	refusals++
	t.Run("another node", func(t *testing.T) {
		result, err := e.invoker.InvokePlugin(t.Context(), hostsvc.InvokeCall{
			ParentOperationID: parent.ID, TargetPluginID: invokeTarget, TargetNodeID: "node-2",
			Operation: "rule.tweak",
		})
		if err != nil {
			t.Fatal(err)
		}
		wantDenied(t, result)
	})
	refusals++
	t.Run("too deep", func(t *testing.T) {
		deep := e.runningParent()
		mid := e.runningParent()
		root := e.runningParent()
		e.exec(`UPDATE operations SET parent_operation_id = ? WHERE operation_id = ?`, mid.ID, deep.ID)
		e.exec(`UPDATE operations SET parent_operation_id = ? WHERE operation_id = ?`, root.ID, mid.ID)
		wantDenied(t, e.invoke(deep.ID, "rule.tweak"))
	})
	refusals++

	denied := e.auditDetails("plugin.invoke", operations.AuditDenied)
	if len(denied) != refusals {
		t.Fatalf("denied audits = %d, want %d: %v", len(denied), refusals, denied)
	}
	for _, d := range denied {
		if !strings.Contains(d, `"reason":`) || !strings.Contains(d, `"caller":{"instance_id":"default","plugin_id":"`+invokeCaller+`"}`) {
			t.Fatalf("denied audit without caller or reason: %s", d)
		}
	}
	if _, invoked, _ := e.client.snapshot(); invoked != before {
		t.Fatalf("a refused call reached the target: %+v", invoked)
	}
}

func TestInvokePluginBackgroundRead(t *testing.T) {
	e := newInvokeEnv(t)
	schema := func(string) ([]byte, error) { return []byte(`{"type":"object"}`), nil }

	// Grant both plugin.invoke and plugin.invoke.background for rule.read AND rule.tweak:
	// rule.read (effect=read) must succeed without a parent when live, while rule.tweak (effect=write) must still be refused!
	caller := &manifest.Manifest{
		ID: invokeCaller, Placement: "node",
		Capabilities: []manifest.Capability{
			{Name: capPluginInvoke, Scope: invokeTarget + "/rule.read", Reason: "bg read"},
			{Name: capPluginInvokeBackground, Scope: invokeTarget + "/rule.read", Reason: "bg read"},
			{Name: capPluginInvoke, Scope: invokeTarget + "/rule.tweak", Reason: "bg write attempt"},
			{Name: capPluginInvokeBackground, Scope: invokeTarget + "/rule.tweak", Reason: "bg write attempt"},
		},
		Operations: []manifest.Operation{{
			Name: "scan.run", APIVersion: "1", Permission: invokeCaller + ":scan", Mode: "invoke",
			Effect: "write", Risk: "low", Idempotent: true, Approval: "auto", Summary: "scan",
			RequestSchema: "request.json", ResponseSchema: "response.json",
		}},
	}
	if err := e.c.Catalog().SetPlugin(caller, schema); err != nil {
		t.Fatal(err)
	}

	// 0. Non-live target returns PLUGIN_UNAVAILABLE without cold-starting (e.invoker uses newTestRuntime with no live units)
	coldRes := e.invoke("", "rule.read")
	if coldRes.Error == nil || coldRes.Error.Code != "PLUGIN_UNAVAILABLE" {
		t.Fatalf("expected PLUGIN_UNAVAILABLE when target is not live, got %+v", coldRes)
	}

	// Switch to the controller's own PluginRuntime where invokeTarget is live
	e.invoker = e.c.PluginRuntime().newHostInvoker(e.c.HostDeps(), invokeCaller)

	// 1. Background read succeeds when target is live
	res := e.invoke("", "rule.read")
	if res.Error != nil || string(res.PayloadJSON) != `{"applied":true}` {
		t.Fatalf("background read failed: payload=%s err=%+v", string(res.PayloadJSON), res.Error)
	}

	// 2. Background write is strictly refused even if manifest claims plugin.invoke.background
	wantDenied(t, e.invoke("", "rule.tweak"))

	// 3. Background read is rate-limited after burst (burst=4; 1 consumed above, 3 more allowed, 5th rejected)
	for i := range 3 {
		if r := e.invoke("", "rule.read"); r.Error != nil {
			t.Fatalf("burst call %d failed: %+v", i, r.Error)
		}
	}
	rateRes := e.invoke("", "rule.read")
	if rateRes.Error == nil || rateRes.Error.Code != "RATE_LIMITED" {
		t.Fatalf("expected RATE_LIMITED on 5th burst background call, got %+v", rateRes.Error)
	}
}
