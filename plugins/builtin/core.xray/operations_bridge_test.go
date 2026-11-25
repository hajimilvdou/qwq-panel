// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/qwq-panel/qwq/internal/xraycore/state"
	"github.com/qwq-panel/qwq/plugins/builtin/core.xray/internal/apply"
	pb "github.com/qwq-panel/qwq/sdk/gen/qwq/platform/v1"
	"github.com/qwq-panel/qwq/sdk/pluginsdk"
)

// fakeApplyConnection 让实际 SDK Host 的绑定上下文与 RPC 代码进入测试。
type fakeApplyConnection struct{ host *fakeApplyHost }

func (c *fakeApplyConnection) Invoke(ctx context.Context, method string, input, output any, _ ...grpc.CallOption) error {
	switch method {
	case pb.HostConfigService_GetConfig_FullMethodName:
		request := input.(*pb.GetConfigRequest)
		if request.GetContext().GetInstanceHandle() == "" {
			return status.Error(codes.PermissionDenied, "fake missing handle")
		}
		data, revision, err := c.host.GetConfig(ctx, request.GetRevision())
		response := output.(*pb.GetConfigResponse)
		response.ConfigJson, response.Revision = data, revision
		return err
	case pb.HostSecretsService_RevealSecret_FullMethodName:
		request := input.(*pb.RevealSecretRequest)
		if request.GetContext().GetOperationId() == "" {
			return status.Error(codes.PermissionDenied, "fake missing operation")
		}
		value, err := c.host.RevealSecret(ctx, request.GetSecretRef(), request.GetPurpose())
		output.(*pb.RevealSecretResponse).Value = value
		return err
	case pb.HostStateService_GetState_FullMethodName:
		request := input.(*pb.GetStateRequest)
		data, revision, found, err := c.host.GetState(ctx, request.GetKey())
		response := output.(*pb.GetStateResponse)
		response.ValueJson, response.Revision, response.Found = data, revision, found
		return err
	case pb.HostStateService_PutState_FullMethodName:
		request := input.(*pb.PutStateRequest)
		revision, err := c.host.PutState(ctx, request.GetKey(), request.GetValueJson(), pluginsdk.PutOption{MustNotExist: request.GetMustNotExist(), ExpectedRevision: request.GetExpectedRevision()})
		output.(*pb.PutStateResponse).Revision = revision
		return err
	case pb.HostStateService_DeleteState_FullMethodName:
		request := input.(*pb.DeleteStateRequest)
		return c.host.DeleteState(ctx, request.GetKey(), request.GetExpectedRevision())
	case pb.HostEventsService_ReportChanges_FullMethodName:
		return c.host.ReportChanges(ctx)
	}
	return status.Error(codes.Unimplemented, "fake unsupported RPC")
}

func (*fakeApplyConnection) NewStream(context.Context, *grpc.StreamDesc, string, ...grpc.CallOption) (grpc.ClientStream, error) {
	return nil, errors.New("fake apply connection has no stream")
}

func sdkApplyFixture(t *testing.T) (*applyFixture, *pluginsdk.Server) {
	t.Helper()
	return sdkApplyFixtureWithHost(t, nil)
}

// sdkApplyFixtureWithHost 复用真实 SDK，只装饰宿主连接边界。
func sdkApplyFixtureWithHost(t *testing.T, decorate func(*fakeApplyConnection) grpc.ClientConnInterface) (*applyFixture, *pluginsdk.Server) {
	t.Helper()
	f := newApplyFixture(t)
	plugin := &Plugin{driverFactory: func(*instance) (*driverRuntime, error) {
		f.driver = &driverRuntime{store: f.store, process: f.process, controller: f.engine, coreVersion: state.CoreVersion, trusted: true}
		return f.driver, nil
	}}
	base := &fakeApplyConnection{host: f.host}
	connection := grpc.ClientConnInterface(base)
	if decorate != nil {
		connection = decorate(base)
	}
	server, _ := newPluginServer(t, plugin, f.host.config, connection, f.directory)
	return f, server
}

func runSDKApply(t *testing.T, server *pluginsdk.Server, revision string) *pb.JobProgress {
	t.Helper()
	stream := &testJobStream{ctx: t.Context()}
	if err := server.RunJob(&pb.RunJobRequest{Context: testContext(), Operation: "core.apply", ApiVersion: "v2", PayloadJson: []byte(`{"config_revision":"` + revision + `"}`), Attempt: 1}, stream); err != nil {
		t.Fatal(err)
	}
	if len(stream.messages) == 0 {
		t.Fatal("job produced no terminal result")
	}
	terminal := stream.messages[len(stream.messages)-1].GetProgress()
	if !terminal.GetCompleted() && terminal.GetError() == nil {
		t.Fatal("job produced neither completion nor terminal error")
	}
	if terminal.GetCompleted() && terminal.GetError() == nil {
		assertResponseSchema(t, "core.apply", terminal.GetResultJson())
	}
	return terminal
}

func TestFakeSDKApplyPlanLifecycleAndPendingState(t *testing.T) {
	f, server := sdkApplyFixture(t)
	plan, err := server.PlanOperation(t.Context(), &pb.PlanOperationRequest{Context: testContext(), Operation: "core.apply", ApiVersion: "v2", PayloadJson: []byte(`{"config_revision":"1"}`)})
	if err != nil || plan.GetError() != nil || len(plan.GetChanges()) == 0 || len(f.host.revealed) != 0 {
		t.Fatal("SDK Plan failed or revealed material")
	}
	terminal := runSDKApply(t, server, "1")
	if terminal.GetError() != nil {
		t.Fatalf("SDK apply failed: %s", terminal.GetError().GetCode())
	}
	var result apply.Result
	if json.Unmarshal(terminal.GetResultJson(), &result) != nil || result.RunningRevision != "1" || result.APIState != "READY" {
		t.Fatal("SDK terminal result was not a real engine result")
	}
	f.changeDesired()
	if _, err := server.ApplyConfig(t.Context(), &pb.ApplyConfigRequest{Context: testContext(), ConfigJson: f.host.config, ProposedRevision: "2"}); err != nil {
		t.Fatal(err)
	}
	f.host.putLost = true
	failed := runSDKApply(t, server, "2")
	if failed.GetError().GetCode() != "STATE_COMMIT_FAILED" || !strings.Contains(string(failed.GetError().GetDetailsJson()), `"rollback_performed":true`) {
		t.Fatal("SDK lost the compensated error details")
	}
	state := decodeReadResult[statusResult](t, readInvoke(t, server, "core.status", `{}`))
	if state.State != "PENDING_APPLY" || state.RunningRevision != "1" || state.DesiredRevision != "2" || !state.ProxyAvailable || state.LastError != "STATE_COMMIT_FAILED" {
		t.Fatal("historical failure hid the pending healthy old configuration")
	}
	if _, err := server.Deactivate(t.Context(), &pb.DeactivateRequest{Context: testContext()}); err != nil {
		t.Fatal(err)
	}
	stopped := decodeReadResult[statusResult](t, readInvoke(t, server, "core.status", `{}`))
	if stopped.ProcessState != "STOPPED" || stopped.ProxyAvailable || stopped.State == "FAILED" {
		t.Fatal("deactivation was reported as an unplanned core failure")
	}
}

func TestSupervisedDriverFailureKeepsRPCAlive(t *testing.T) {
	err := superviseDriver(t.Context(), func(ctx context.Context, plugin *Plugin) error {
		plugin.onFailure(errors.New("unsafe native diagnostic"))
		if ctx.Err() != nil {
			t.Fatal("driver failure unexpectedly cancelled RPC server context")
		}
		return nil
	})
	if err != nil {
		t.Fatalf("superviseDriver should stay alive after core degradation, got: %v", err)
	}
}
