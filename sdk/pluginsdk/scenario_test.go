// SPDX-License-Identifier: Apache-2.0

package pluginsdk

import (
	"context"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	platformv1 "github.com/qwq-panel/qwq/sdk/gen/qwq/platform/v1"
)

// TestScenarioTwoControllerInvokesCore is the plugin side of tests/abi
// scenario two: a controller plugin calls core.apply through HostInvokeService,
// long-polls WaitOperation and reports its own change.
func TestScenarioTwoControllerInvokesCore(t *testing.T) {
	env := newTestEnv(t, newTestPlugin())
	env.active("default", nil)

	var got *platformv1.InvokePluginRequest
	env.host.setInvokePlugin(func(req *platformv1.InvokePluginRequest) (*platformv1.InvokePluginResponse, error) {
		got = req
		return &platformv1.InvokePluginResponse{
			OperationId: "core-op-1", State: platformv1.OperationState_OPERATION_STATE_RUNNING,
		}, nil
	})
	waits := 0
	env.host.setWaitOperation(func(_ context.Context, req *platformv1.WaitOperationRequest) (*platformv1.WaitOperationResponse, error) {
		if req.GetOperationId() != "core-op-1" {
			return nil, status.Errorf(codes.NotFound, "operation %q", req.GetOperationId())
		}
		waits++
		if waits == 1 {
			return &platformv1.WaitOperationResponse{
				State:    platformv1.OperationState_OPERATION_STATE_RUNNING,
				Progress: &platformv1.JobProgress{Step: "render", StepIndex: 1, StepCount: 2},
			}, nil
		}
		return &platformv1.WaitOperationResponse{
			State:      platformv1.OperationState_OPERATION_STATE_SUCCEEDED,
			ResultJson: []byte(`{"applied_revision":"3"}`),
		}, nil
	})

	resp := invokeOp(t, env, "default", "op-parent", "en", "test.sync",
		mustJSON(syncRequest{Users: []string{"alice", "bob"}}))
	if resp.GetError() != nil {
		t.Fatalf("sync = %v", resp.GetError())
	}
	var out syncResponse
	if err := unmarshalJSON(resp.GetPayloadJson(), &out); err != nil || out.CoreOperationID != "core-op-1" || out.Users != 2 {
		t.Fatalf("payload = %s, %v", resp.GetPayloadJson(), err)
	}
	changes := resp.GetChanges()
	if len(changes) != 1 || changes[0].GetSubject() != "sync-state" || changes[0].GetRevision() != "1" ||
		len(changes[0].GetChangedPointers()) != 1 || changes[0].GetChangedPointers()[0] != "/users" {
		t.Fatalf("changes = %v", changes)
	}

	if got == nil {
		t.Fatal("the host did not receive InvokePlugin")
	}
	if got.GetTargetPluginId() != "core.xray" || got.GetTargetInstanceId() != "default" ||
		got.GetOperation() != "core.apply" || got.GetApiVersion() != "v1" ||
		got.GetIdempotencyKey() != "op-parent" || got.GetTargetNodeId() != "" {
		t.Fatalf("InvokePlugin = %v", got)
	}
	var child struct {
		Inbounds []struct {
			Tag   string   `json:"tag"`
			Users []string `json:"users"`
		} `json:"inbounds"`
	}
	if err := unmarshalJSON(got.GetPayloadJson(), &child); err != nil || len(child.Inbounds) != 1 ||
		child.Inbounds[0].Tag != "vless-in" || len(child.Inbounds[0].Users) != 2 {
		t.Fatalf("child payload = %s, %v", got.GetPayloadJson(), err)
	}

	calls := env.host.callsOf("WaitOperation")
	if len(calls) != 2 {
		t.Fatalf("%d WaitOperation calls", len(calls))
	}
	if calls[0].OperationID != "op-parent" || calls[0].TraceID != "trace-op-parent" || calls[0].Handle != handleFor("default") {
		t.Fatalf("WaitOperation HostCallContext = %+v", calls[0])
	}
	if n := len(env.host.callsOf("InvokePlugin")); n != 1 {
		t.Fatalf("%d InvokePlugin calls", n)
	}
}

// TestScenarioTwoCancelPropagatesToChild cancels the parent operation and
// checks that the plugin cancels the child with a detached context, because the
// ABI does not cancel children automatically (ADR-0007 review #5).
func TestScenarioTwoCancelPropagatesToChild(t *testing.T) {
	env := newTestEnv(t, newTestPlugin())
	env.active("default", nil)

	waitStarted := make(chan struct{}, 1)
	env.host.setInvokePlugin(func(*platformv1.InvokePluginRequest) (*platformv1.InvokePluginResponse, error) {
		return &platformv1.InvokePluginResponse{
			OperationId: "core-op-1", State: platformv1.OperationState_OPERATION_STATE_RUNNING,
		}, nil
	})
	env.host.setWaitOperation(func(ctx context.Context, _ *platformv1.WaitOperationRequest) (*platformv1.WaitOperationResponse, error) {
		select {
		case waitStarted <- struct{}{}:
		default:
		}
		<-ctx.Done()
		return nil, status.FromContextError(ctx.Err()).Err()
	})

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	result := make(chan error, 1)
	go func() {
		_, err := env.client.Invoke(ctx, &platformv1.InvokeRequest{
			Context: operationContext("default", "op-parent", "en"), Operation: "test.sync", ApiVersion: "v1",
			PayloadJson: mustJSON(syncRequest{Users: []string{"alice"}}), Attempt: 1,
		})
		result <- err
	}()
	recv(t, waitStarted, "the child wait to start")
	cancel()
	if err := recv(t, result, "Invoke to return"); status.Code(err) != codes.Canceled {
		t.Fatalf("Invoke after cancel = %v", err)
	}
	recv(t, env.plugin.exited, "the sync handler to return")

	cancels := env.host.callsOf("CancelOperation")
	if len(cancels) != 1 || cancels[0].Key != "core-op-1" || cancels[0].Handle != handleFor("default") {
		t.Fatalf("CancelOperation calls = %+v", cancels)
	}
}

// TestScenarioTwoChildApprovalFails mirrors the ABI's statement that an
// invoke-mode parent cannot wait for a human approval.
func TestScenarioTwoChildApproval(t *testing.T) {
	env := newTestEnv(t, newTestPlugin())
	env.active("default", nil)
	env.host.setInvokePlugin(func(*platformv1.InvokePluginRequest) (*platformv1.InvokePluginResponse, error) {
		return &platformv1.InvokePluginResponse{
			OperationId: "core-op-1", State: platformv1.OperationState_OPERATION_STATE_RUNNING,
		}, nil
	})
	env.host.setWaitOperation(func(context.Context, *platformv1.WaitOperationRequest) (*platformv1.WaitOperationResponse, error) {
		return &platformv1.WaitOperationResponse{State: platformv1.OperationState_OPERATION_STATE_AWAITING_APPROVAL}, nil
	})
	resp := invokeOp(t, env, "default", "op-parent", "en", "test.sync",
		mustJSON(syncRequest{Users: []string{"alice"}}))
	if resp.GetError().GetCode() != "APPROVAL_REQUIRED" {
		t.Fatalf("response = %v", resp)
	}
	if n := len(env.host.callsOf("CancelOperation")); n != 0 {
		t.Fatalf("a waiting-for-approval child was canceled %d times", n)
	}
}

// TestScenarioThreePlannableJob is the plugin side of tests/abi scenario three:
// a plannable job checks the plan's precondition atomically, reports its change
// in a progress message and then returns the terminal result. A stale plan
// fails before any progress message, as in the ABI scenario test.
func TestScenarioThreePlannableJob(t *testing.T) {
	env := newTestEnv(t, newTestPlugin())
	env.active("default", nil)
	ctx := testContext(t)

	plan, err := env.client.PlanOperation(ctx, &platformv1.PlanOperationRequest{
		Context: operationContext("default", "op-plan", "en"), Operation: "test.setjob", ApiVersion: "v1",
		PayloadJson: []byte(`{"value":"hello"}`),
	})
	if err != nil || plan.GetError() != nil {
		t.Fatalf("PlanOperation: %v %v", err, plan.GetError())
	}
	if puts := env.host.count("PutState"); puts != 0 {
		t.Fatalf("PlanOperation wrote %d times", puts)
	}
	pre := plan.GetPreconditions()
	if len(pre) != 1 || pre[0].GetSubject() != "value" || pre[0].GetRevision() != "" {
		t.Fatalf("preconditions = %v", pre)
	}

	messages := runJob(t, env, "default", "op-exec", "test.setjob", []byte(`{"value":"hello"}`), pre...)
	if len(messages) != 3 {
		t.Fatalf("%d messages, want 2 progress + 1 terminal", len(messages))
	}
	if p := messages[0]; p.GetStep() != "write" || p.GetStepIndex() != 1 || p.GetStepCount() != 2 ||
		len(p.GetChanges()) != 1 || p.GetChanges()[0].GetSubject() != "value" {
		t.Fatalf("first progress = %v", p)
	}
	last := messages[2]
	if !last.GetCompleted() || last.GetError() != nil {
		t.Fatalf("terminal = %v", last)
	}
	var out struct {
		Revision string `json:"revision"`
	}
	if err := unmarshalJSON(last.GetResultJson(), &out); err != nil || out.Revision == "" {
		t.Fatalf("result = %s", last.GetResultJson())
	}
	written, ok := env.host.stateOf(handleFor("default"), "value")
	if !ok || string(written.value) != `"hello"` || written.revision != out.Revision {
		t.Fatalf("stored = %q @%s", written.value, written.revision)
	}

	stale := runJob(t, env, "default", "op-stale", "test.setjob", []byte(`{"value":"other"}`), pre...)
	if len(stale) != 1 || stale[0].GetError().GetCode() != "PRECONDITION_FAILED" || stale[0].GetCompleted() {
		t.Fatalf("stale execution = %v", stale)
	}
	if again, _ := env.host.stateOf(handleFor("default"), "value"); string(again.value) != `"hello"` {
		t.Fatalf("stale execution changed the value to %s", again.value)
	}
}
