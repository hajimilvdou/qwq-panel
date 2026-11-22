// SPDX-License-Identifier: AGPL-3.0-only

package abi_test

import (
	"encoding/json"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"

	pb "github.com/qwq-panel/qwq/sdk/gen/qwq/platform/v1"
)

// Scenario two: the subscription plugin (placement=controller) calls core.apply of the Core Driver
// core.xray (placement=node, mode=job) through HostInvokeService.

type invokeEnv struct {
	h        *fakeHost
	sub      *subscriptionPlugin
	subInst  *hostInstance
	core     map[string]*coreXray     // node -> plugin
	coreInst map[string]*hostInstance // node -> instance "default"
}

// newInvokeEnv runs core.xray on nodes "local" and "n2" and the subscription plugin on "local"
// (for placement=controller that is the Controller host's Agent, ADR-0002).
func newInvokeEnv(t *testing.T, sub *pb.PluginDescriptor, holdAfter int) *invokeEnv {
	t.Helper()
	e := &invokeEnv{h: newFakeHost(t), core: map[string]*coreXray{}, coreInst: map[string]*hostInstance{}}
	for _, node := range []string{"local", "n2"} {
		e.core[node] = newCoreXray(holdAfter)
		e.coreInst[node] = e.h.start(t, e.h.mustLoad(t, node, e.core[node]), "default", nil)
	}
	e.sub = newSubscriptionPlugin(sub)
	e.subInst = e.h.start(t, e.h.mustLoad(t, "local", e.sub), "default", nil)
	return e
}

func (e *invokeEnv) sync(t *testing.T, inst *hostInstance, node string) *hostOp {
	t.Helper()
	return e.h.dispatchInvoke(t, inst, "subscription.sync", human("admin"),
		mustJSON(map[string]any{"node_id": node, "users": []string{"alice", "bob"}}))
}

func (e *invokeEnv) invokeClient(p *basePlugin) pb.HostInvokeServiceClient {
	return pb.NewHostInvokeServiceClient(p.hostConn())
}

func (h *fakeHost) opByID(id string) *hostOp {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.ops[id]
}

func wantSteps(t *testing.T, ps []*pb.JobProgress, steps ...string) {
	t.Helper()
	if len(ps) < len(steps) {
		t.Fatalf("got %d progress messages, want at least %d", len(ps), len(steps))
	}
	for i, s := range steps {
		p := ps[i]
		if p.GetStep() != s || p.GetStepIndex() != uint32(i+1) || p.GetStepCount() != uint32(len(steps)) || p.GetCompleted() {
			t.Fatalf("progress %d = %v, want step %s %d/%d", i, p, s, i+1, len(steps))
		}
	}
}

func wantNoViolations(t *testing.T, h *fakeHost) {
	t.Helper()
	if v := h.violationsSnapshot(); len(v) != 0 {
		t.Fatalf("protocol violations: %v", v)
	}
}

func TestInvokeApplySucceeds(t *testing.T) {
	for _, target := range []string{"", "n2"} {
		node := target
		if node == "" {
			node = "local"
		}
		t.Run("node "+node, func(t *testing.T) {
			e := newInvokeEnv(t, subscriptionDescriptor(pb.Placement_PLACEMENT_CONTROLLER, invokeCoreApply()), 0)
			parent := e.sync(t, e.subInst, target)
			pv := e.h.await(t, parent)
			if pv.State != pb.OperationState_OPERATION_STATE_SUCCEEDED {
				t.Fatalf("parent = %v %v", pv.State, pv.Err)
			}

			// One child operation on the target node, with parent_operation_id and the parent's actor.
			kids := e.h.childrenOf(parent)
			if len(kids) != 1 || kids[0].target != e.coreInst[node] || kids[0].creator != e.subInst {
				t.Fatalf("children = %v", kids)
			}
			child := kids[0]
			cv := e.h.view(child)
			if cv.ParentID != parent.id || cv.Actor.GetKind() != pb.ActorKind_ACTOR_KIND_HUMAN || cv.Actor.GetId() != "admin" ||
				cv.State != pb.OperationState_OPERATION_STATE_SUCCEEDED || child.trace != parent.trace {
				t.Fatalf("child = %+v", cv)
			}
			wantSteps(t, cv.Progress, "render", "validate", "reload")
			if last := cv.Progress[len(cv.Progress)-1]; !last.GetCompleted() || len(cv.Progress) != 4 {
				t.Fatalf("terminal message = %v (of %d)", last, len(cv.Progress))
			}
			runs := e.core[node].runsSnapshot()
			if len(runs) != 1 || runs[0].opID != child.id || runs[0].attempt != 1 || runs[0].actor.GetId() != "admin" || runs[0].node != node {
				t.Fatalf("core runs = %+v", runs)
			}
			if other := map[string]string{"local": "n2", "n2": "local"}[node]; len(e.core[other].runsSnapshot()) != 0 {
				t.Fatalf("core on %s ran too", other)
			}

			var out struct {
				CoreOp  string `json:"core_operation_id"`
				Attempt uint32 `json:"core_attempt"`
			}
			if err := json.Unmarshal(pv.Result, &out); err != nil || out.CoreOp != child.id || out.Attempt != 1 {
				t.Fatalf("result = %s", pv.Result)
			}

			// Events: the core's changes under the core instance namespace, the subscription's own
			// change under plugins/subscription/resources/; all with the human actor and their operation_id.
			prefix := "nodes/" + node + "/plugins/core.xray/instances/default/resources/"
			ce := e.h.eventsOf(child.id)
			if len(ce) != 2 || ce[0].GetSubject() != prefix+"config" || ce[1].GetSubject() != prefix+"runtime" {
				t.Fatalf("core events = %v", ce)
			}
			pe := e.h.eventsOf(parent.id)
			if len(pe) != 1 || pe[0].GetSubject() != "plugins/subscription/resources/sync-state" || pe[0].GetActor().GetId() != "admin" {
				t.Fatalf("subscription events = %v", pe)
			}
			var rcPayload resourceChanged
			if err := json.Unmarshal(pe[0].GetPayloadJson(), &rcPayload); err != nil || rcPayload.Revision != "1" ||
				len(rcPayload.ChangedPointers) != 1 || rcPayload.ChangedPointers[0] != "/users" {
				t.Fatalf("resource.changed payload = %s", pe[0].GetPayloadJson())
			}
			wantNoViolations(t, e.h)
		})
	}
}

func TestInvokeMissingCapability(t *testing.T) {
	narrowed := subscriptionDescriptor(pb.Placement_PLACEMENT_CONTROLLER, invokeCoreApply(), capability("state.kv.read", "self"))
	narrowed.Operations[0].Capabilities = []*pb.Capability{capability("state.kv.read", "self")}
	cases := []struct {
		name     string
		desc     *pb.PluginDescriptor
		code     string     // ErrorDetail.code of the failed parent
		direct   codes.Code // InvokePlugin without operation_id, made by the test as the plugin
		bypassed bool
	}{
		{"other operation granted", subscriptionDescriptor(pb.Placement_PLACEMENT_CONTROLLER,
			capability("plugin.invoke", "core.xray/core.status")), "PERMISSION_DENIED", codes.PermissionDenied, false},
		// Operation-level capabilities narrow calls that carry operation_id (ADR-0007 #4) ...
		{"operation does not declare it", narrowed, "PERMISSION_DENIED", codes.OK, true},
		// ... and a plugin without any plugin.invoke grant has no HostInvokeService at all.
		{"no plugin.invoke at all", subscriptionDescriptor(pb.Placement_PLACEMENT_CONTROLLER), "UNIMPLEMENTED", codes.Unimplemented, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := newInvokeEnv(t, c.desc, 0)
			pv := e.h.await(t, e.sync(t, e.subInst, ""))
			if pv.State != pb.OperationState_OPERATION_STATE_FAILED || pv.Err.GetCode() != c.code {
				t.Fatalf("parent = %v %v, want FAILED %s", pv.State, pv.Err, c.code)
			}
			resp, err := e.invokeClient(e.sub.basePlugin).InvokePlugin(testCtx(t), &pb.InvokePluginRequest{
				Context: &pb.HostCallContext{InstanceHandle: e.subInst.handle}, TargetPluginId: "core.xray",
				TargetInstanceId: "default", Operation: "core.apply", ApiVersion: "v1", PayloadJson: []byte(`{}`)})
			wantCode(t, err, c.direct)
			if c.bypassed {
				// Leaving out operation_id falls back to the plugin-level grant (see report). The
				// child has no parent, so it runs as the plugin and needs approval.
				v := e.h.view(e.h.opByID(resp.GetOperationId()))
				if v.State != pb.OperationState_OPERATION_STATE_AWAITING_APPROVAL || v.Actor.GetKind() != pb.ActorKind_ACTOR_KIND_SERVICE {
					t.Fatalf("parentless child = %+v", v)
				}
			}
			if n := len(e.core["local"].runsSnapshot()); n != 0 {
				t.Fatalf("core ran %d times", n)
			}
		})
	}
}

func TestInvokeCancel(t *testing.T) {
	t.Run("caller cancels the child", func(t *testing.T) {
		e := newInvokeEnv(t, subscriptionDescriptor(pb.Placement_PLACEMENT_CONTROLLER, invokeCoreApply()), 1)
		parent := e.sync(t, e.subInst, "")
		childID := recv(t, e.core["local"].holding, "core job at step 1")
		// Send returning in the plugin does not mean the host has read the message: canceling now
		// could lose step 1 and its changes (see report). Wait until the host has recorded it.
		e.h.waitFor(t, e.h.opByID(childID), "step 1", func(op *hostOp) bool { return len(op.progress) == 1 })
		resp, err := e.invokeClient(e.sub.basePlugin).CancelOperation(testCtx(t), &pb.CancelOperationRequest{
			Context: &pb.HostCallContext{InstanceHandle: e.subInst.handle}, OperationId: childID})
		if err != nil || resp.GetState() != pb.OperationState_OPERATION_STATE_CANCELED {
			t.Fatalf("CancelOperation = %v, %v", resp, err)
		}
		if got := recv(t, e.core["local"].exited, "RunJob to return"); got != childID {
			t.Fatalf("exited %s", got)
		}
		cv := e.h.view(e.h.opByID(childID))
		if cv.State != pb.OperationState_OPERATION_STATE_CANCELED || cv.Err.GetCode() != "CANCELED" || len(cv.Progress) != 1 {
			t.Fatalf("child = %+v", cv)
		}
		// Changes reported before the cancel stay published; nothing after step 1.
		if ev := e.h.eventsOf(childID); len(ev) != 1 || !strings.HasSuffix(ev[0].GetSubject(), "/config") {
			t.Fatalf("child events = %v", ev)
		}
		pv := e.h.await(t, parent)
		if pv.State != pb.OperationState_OPERATION_STATE_FAILED || pv.Err.GetCode() != "CANCELED" {
			t.Fatalf("parent = %v %v", pv.State, pv.Err)
		}
		w, err := e.invokeClient(e.sub.basePlugin).WaitOperation(testCtx(t), &pb.WaitOperationRequest{
			Context: &pb.HostCallContext{InstanceHandle: e.subInst.handle}, OperationId: childID})
		if err != nil || w.GetState() != pb.OperationState_OPERATION_STATE_CANCELED || w.GetError().GetCode() != "CANCELED" {
			t.Fatalf("WaitOperation after cancel = %v, %v", w, err)
		}
	})

	t.Run("canceling the parent", func(t *testing.T) {
		e := newInvokeEnv(t, subscriptionDescriptor(pb.Placement_PLACEMENT_CONTROLLER, invokeCoreApply()), 1)
		parent := e.sync(t, e.subInst, "")
		childID := recv(t, e.core["local"].holding, "core job at step 1")
		e.h.cancelOp(parent)
		if pv := e.h.await(t, parent); pv.State != pb.OperationState_OPERATION_STATE_CANCELED {
			t.Fatalf("parent = %v", pv.State)
		}
		// The child stops only because the subscription plugin cancels it itself.
		if cv := e.h.await(t, e.h.opByID(childID)); cv.State != pb.OperationState_OPERATION_STATE_CANCELED {
			t.Fatalf("child = %v", cv.State)
		}
		recv(t, e.core["local"].exited, "RunJob to return")
	})
}

func TestInvokeTargetNodeRule(t *testing.T) {
	e := newInvokeEnv(t, subscriptionDescriptor(pb.Placement_PLACEMENT_NODE, invokeCoreApply()), 0)
	for _, own := range []string{"", "local"} {
		if pv := e.h.await(t, e.sync(t, e.subInst, own)); pv.State != pb.OperationState_OPERATION_STATE_SUCCEEDED {
			t.Fatalf("node plugin targeting its own node %q: %v %v", own, pv.State, pv.Err)
		}
	}
	parent := e.sync(t, e.subInst, "n2")
	if pv := e.h.await(t, parent); pv.State != pb.OperationState_OPERATION_STATE_FAILED || pv.Err.GetCode() != "PERMISSION_DENIED" {
		t.Fatalf("node plugin targeting n2: %v %v", pv.State, pv.Err)
	}
	if len(e.h.childrenOf(parent)) != 0 || len(e.core["n2"].runsSnapshot()) != 0 {
		t.Fatal("a child operation was started on n2")
	}
	// Direct call, same result: the rule is checked by the host, not by the plugin.
	_, err := e.invokeClient(e.sub.basePlugin).InvokePlugin(testCtx(t), &pb.InvokePluginRequest{
		Context: &pb.HostCallContext{InstanceHandle: e.subInst.handle}, TargetPluginId: "core.xray",
		Operation: "core.apply", TargetNodeId: "n2", PayloadJson: []byte(`{}`)})
	wantCode(t, err, codes.PermissionDenied)
}

// Wait and Cancel work only on operations the calling instance created; handles work only on the
// socket of their own plugin; operation_id must be one dispatched to the caller.
func TestInvokeForeignOperation(t *testing.T) {
	e := newInvokeEnv(t, subscriptionDescriptor(pb.Placement_PLACEMENT_NODE, invokeCoreApply()), 1)
	other := e.h.start(t, e.subInst.plugin, "other", nil)
	parent := e.sync(t, e.subInst, "")
	childID := recv(t, e.core["local"].holding, "core job at step 1")
	child := e.h.opByID(childID)
	e.h.waitFor(t, child, "first progress", func(op *hostOp) bool { return len(op.progress) > 0 })
	ctx := testCtx(t)
	c := e.invokeClient(e.sub.basePlugin)
	mine := &pb.HostCallContext{InstanceHandle: e.subInst.handle}
	theirs := &pb.HostCallContext{InstanceHandle: other.handle}

	w, err := c.WaitOperation(ctx, &pb.WaitOperationRequest{Context: mine, OperationId: childID})
	if err != nil || w.GetState() != pb.OperationState_OPERATION_STATE_RUNNING || w.GetProgress().GetStep() != "render" {
		t.Fatalf("creator WaitOperation(0) = %v, %v", w, err)
	}
	w, err = c.WaitOperation(ctx, &pb.WaitOperationRequest{Context: mine, OperationId: childID, TimeoutMs: 20})
	if err != nil || w.GetState() != pb.OperationState_OPERATION_STATE_RUNNING {
		t.Fatalf("creator WaitOperation(20ms) = %v, %v", w, err)
	}
	_, err = c.WaitOperation(ctx, &pb.WaitOperationRequest{Context: mine, OperationId: "op-unknown"})
	wantCode(t, err, codes.NotFound)
	_, err = c.WaitOperation(ctx, &pb.WaitOperationRequest{Context: theirs, OperationId: childID})
	wantCode(t, err, codes.NotFound)
	_, err = c.CancelOperation(ctx, &pb.CancelOperationRequest{Context: theirs, OperationId: childID})
	wantCode(t, err, codes.NotFound)

	// Another instance cannot act for an operation that is not dispatched to it (forged parent,
	// which would inherit the human actor).
	_, err = c.InvokePlugin(ctx, &pb.InvokePluginRequest{Context: &pb.HostCallContext{InstanceHandle: other.handle,
		OperationId: parent.id}, TargetPluginId: "core.xray", Operation: "core.apply", PayloadJson: []byte(`{}`)})
	wantCode(t, err, codes.PermissionDenied)
	// A handle is only valid on its own plugin's socket.
	_, err = pb.NewHostEventsServiceClient(e.core["local"].hostConn()).ReportChanges(ctx, &pb.ReportChangesRequest{
		Context: mine, Changes: []*pb.ResourceChange{{Subject: "config"}}})
	wantCode(t, err, codes.Unauthenticated)

	// A retry with the same idempotency_key finds the running child instead of starting another.
	again, err := c.InvokePlugin(ctx, &pb.InvokePluginRequest{Context: &pb.HostCallContext{InstanceHandle: e.subInst.handle,
		OperationId: parent.id}, TargetPluginId: "core.xray", TargetInstanceId: "default", Operation: "core.apply",
		PayloadJson: []byte(`{}`), IdempotencyKey: parent.id})
	if err != nil || again.GetOperationId() != childID || again.GetState() != pb.OperationState_OPERATION_STATE_RUNNING {
		t.Fatalf("retry = %v, %v", again, err)
	}
	if n := len(e.h.childrenOf(parent)); n != 1 {
		t.Fatalf("%d children", n)
	}

	e.h.cancelOp(parent)
	e.h.await(t, parent)
	e.h.await(t, child)
}

// ADR-0007 #5: a child whose effective risk exceeds its parent's waits for its own approval. An
// invoke-mode parent has no way to wait for a human, so it can only fail (see report).
func TestInvokeChildNeedsApproval(t *testing.T) {
	d := subscriptionDescriptor(pb.Placement_PLACEMENT_CONTROLLER, invokeCoreApply())
	d.Operations[0].Risk = pb.RiskLevel_RISK_LEVEL_LOW
	e := newInvokeEnv(t, d, 0)
	parent := e.sync(t, e.subInst, "")
	pv := e.h.await(t, parent)
	if pv.State != pb.OperationState_OPERATION_STATE_FAILED || pv.Err.GetCode() != "APPROVAL_REQUIRED" {
		t.Fatalf("parent = %v %v", pv.State, pv.Err)
	}
	kids := e.h.childrenOf(parent)
	if len(kids) != 1 {
		t.Fatalf("%d children", len(kids))
	}
	if cv := e.h.view(kids[0]); cv.State != pb.OperationState_OPERATION_STATE_AWAITING_APPROVAL {
		t.Fatalf("child = %v", cv.State)
	}
	if len(e.core["local"].runsSnapshot()) != 0 {
		t.Fatal("core ran without approval")
	}
}

func TestResourceChangeSubjects(t *testing.T) {
	e := newInvokeEnv(t, subscriptionDescriptor(pb.Placement_PLACEMENT_CONTROLLER, invokeCoreApply()), 0)
	report := func(p *basePlugin, inst *hostInstance, subject string) error {
		_, err := pb.NewHostEventsServiceClient(p.hostConn()).ReportChanges(testCtx(t), &pb.ReportChangesRequest{
			Context: &pb.HostCallContext{InstanceHandle: inst.handle},
			Changes: []*pb.ResourceChange{{Subject: subject, Revision: "9"}}})
		return err
	}

	t.Run("prefixed by the host", func(t *testing.T) {
		if err := report(e.sub.basePlugin, e.subInst, "subscriptions/sub-1"); err != nil {
			t.Fatal(err)
		}
		if err := report(e.core["n2"].basePlugin, e.coreInst["n2"], "inbounds/vless-in~1"); err != nil {
			t.Fatal(err)
		}
		ev := e.h.eventsOf("")
		if len(ev) != 2 || ev[0].GetSubject() != "plugins/subscription/resources/subscriptions/sub-1" ||
			ev[1].GetSubject() != "nodes/n2/plugins/core.xray/instances/default/resources/inbounds/vless-in~1" ||
			ev[1].GetNodeId() != "n2" || ev[0].GetActor().GetKind() != pb.ActorKind_ACTOR_KIND_SERVICE {
			t.Fatalf("events = %v", ev)
		}
	})

	t.Run("rejected", func(t *testing.T) {
		before := len(e.h.eventsOf(""))
		for _, s := range []string{"/etc/passwd", "..", "a/../b", "./a", "a//b", "a/", "", "a b", "订阅",
			"../../core.xray/instances/default/config", strings.Repeat("x", 129)} {
			err := report(e.sub.basePlugin, e.subInst, s)
			wantCode(t, err, codes.InvalidArgument)
		}
		if after := len(e.h.eventsOf("")); after != before {
			t.Fatalf("%d events emitted for invalid subjects", after-before)
		}
	})

	t.Run("dropped from an operation result", func(t *testing.T) {
		e.sub.setChangeSubject("../core.xray/instances/default/config")
		parent := e.sync(t, e.subInst, "")
		if pv := e.h.await(t, parent); pv.State != pb.OperationState_OPERATION_STATE_SUCCEEDED {
			t.Fatalf("parent = %v %v", pv.State, pv.Err)
		}
		if ev := e.h.eventsOf(parent.id); len(ev) != 0 {
			t.Fatalf("events = %v", ev)
		}
		if v := e.h.violationsSnapshot(); len(v) != 1 || !strings.Contains(v[0], parent.id) {
			t.Fatalf("violations = %v", v)
		}
	})
}
