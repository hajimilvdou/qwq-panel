// SPDX-License-Identifier: AGPL-3.0-only

package abi_test

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"google.golang.org/grpc"

	"github.com/qwq-panel/qwq/sdk/abi"
	pb "github.com/qwq-panel/qwq/sdk/gen/qwq/platform/v1"
)

func invokeCoreApply() *pb.Capability { return capability("plugin.invoke", "core.xray/core.apply") }

func subscriptionDescriptor(placement pb.Placement, caps ...*pb.Capability) *pb.PluginDescriptor {
	return &pb.PluginDescriptor{
		PluginId: "subscription", PluginVersion: "0.1.0", AbiMajor: abi.Major, Placement: placement,
		Capabilities: caps, StateSchemaVersion: "1",
		Operations: []*pb.OperationDescriptor{{
			Name: "subscription.sync", ApiVersion: "v1", Permission: "subscription:sync",
			Mode: pb.OperationMode_OPERATION_MODE_INVOKE, Effect: pb.OperationEffect_OPERATION_EFFECT_WRITE,
			Risk: pb.RiskLevel_RISK_LEVEL_MEDIUM, Idempotent: true, TimeoutMs: 30000,
			Summary: "push the users of a node to its core",
		}},
	}
}

func coreXrayDescriptor() *pb.PluginDescriptor {
	return &pb.PluginDescriptor{
		PluginId: "core.xray", PluginVersion: "0.1.0", AbiMajor: abi.Major, Placement: pb.Placement_PLACEMENT_NODE,
		Capabilities: []*pb.Capability{capability("state.kv.write", "self")}, StateSchemaVersion: "1",
		Operations: []*pb.OperationDescriptor{{
			Name: "core.apply", ApiVersion: "v1", Permission: "core:apply",
			Mode: pb.OperationMode_OPERATION_MODE_JOB, Effect: pb.OperationEffect_OPERATION_EFFECT_WRITE,
			Risk: pb.RiskLevel_RISK_LEVEL_MEDIUM, Idempotent: true, TimeoutMs: 60000,
			Summary: "apply a core intent revision",
		}},
	}
}

// coreXray is the Core Driver of scenario two (ARCH §9): core.apply renders, validates and reloads
// the core config as a job.
type coreXray struct {
	*basePlugin
	holdAfter int         // test hook: after sending step holdAfter, wait until canceled
	holding   chan string // receives the operation_id when the job waits
	exited    chan string // receives the operation_id when a RunJob handler returns
	runs      []runRecord // guarded by mu
}

type runRecord struct {
	opID    string
	attempt uint32
	actor   *pb.Actor
	node    string
}

func newCoreXray(holdAfter int) *coreXray {
	return &coreXray{basePlugin: newBasePlugin(coreXrayDescriptor()), holdAfter: holdAfter,
		holding: make(chan string, 64), exited: make(chan string, 64)}
}

func (p *coreXray) runsSnapshot() []runRecord {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]runRecord(nil), p.runs...)
}

func (p *coreXray) RunJob(req *pb.RunJobRequest, stream grpc.ServerStreamingServer[pb.RunJobResponse]) error {
	ctx, rc := stream.Context(), req.GetContext()
	inst, err := p.enter(rc)
	if err != nil {
		return err
	}
	defer p.leave(inst)
	defer notify(p.exited, rc.GetOperationId())
	p.mu.Lock()
	p.runs = append(p.runs, runRecord{rc.GetOperationId(), req.GetAttempt(), rc.GetActor(), rc.GetNodeId()})
	p.mu.Unlock()
	send := func(jp *pb.JobProgress) error { return stream.Send(&pb.RunJobResponse{Progress: jp}) }

	if req.GetOperation() != "core.apply" {
		return send(&pb.JobProgress{Error: unknownOp(rc, req.GetOperation())})
	}
	var in struct {
		Inbounds []struct {
			Tag   string   `json:"tag"`
			Users []string `json:"users"`
		} `json:"inbounds"`
	}
	if json.Unmarshal(req.GetPayloadJson(), &in) != nil || len(in.Inbounds) == 0 {
		return send(&pb.JobProgress{Error: validationFailed(rc, &pb.FieldViolation{Pointer: "/inbounds", Code: "REQUIRED",
			Message: localize(rc, "至少需要一个入站", "at least one inbound is required")})})
	}
	// (operation_id, attempt) identifies this execution: the staged file is per attempt, so a retry
	// never picks up a half-written file of an earlier attempt.
	staged := fmt.Sprintf("staged/%s.%d.json", rc.GetOperationId(), req.GetAttempt())
	steps := []struct{ id, zh, en, subject, pointer string }{
		{"render", "生成配置", "render config", "config", "/inbounds"},
		{"validate", "校验配置", "validate config", "", ""},
		{"reload", "重载核心", "reload core", "runtime", "/status"},
	}
	var applied string
	for i, s := range steps {
		if err := ctx.Err(); err != nil {
			return err
		}
		jp := &pb.JobProgress{Percent: uint32(100 * i / len(steps)), Step: s.id, StepIndex: uint32(i + 1),
			StepCount: uint32(len(steps)), Message: localize(rc, s.zh, s.en)}
		if s.subject != "" {
			c := p.bump(inst, s.subject, "applied", s.pointer)
			jp.Changes = []*pb.ResourceChange{c}
			if s.subject == "config" {
				applied = c.GetRevision()
			}
		}
		if err := send(jp); err != nil {
			return err
		}
		if i+1 == p.holdAfter {
			notify(p.holding, rc.GetOperationId())
			<-ctx.Done()
			// Rollback to the last good config would happen here. The stream is already canceled:
			// no terminal message can be sent and changes made now cannot be reported in it.
			return ctx.Err()
		}
	}
	return send(&pb.JobProgress{Percent: 100, Completed: true, ResultJson: mustJSON(map[string]any{
		"applied_revision": applied, "attempt": req.GetAttempt(), "staged": staged, "inbounds": len(in.Inbounds),
	})})
}

// subscriptionPlugin is the controller plugin of scenario two: subscription.sync pushes the users
// of a node to that node's Core Driver with InvokePlugin and waits for the job.
type subscriptionPlugin struct {
	*basePlugin
	changeSubject string // relative subject of its own state; guarded by mu; tests make it misbehave
}

func newSubscriptionPlugin(d *pb.PluginDescriptor) *subscriptionPlugin {
	return &subscriptionPlugin{basePlugin: newBasePlugin(d), changeSubject: "sync-state"}
}

func (p *subscriptionPlugin) setChangeSubject(s string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.changeSubject = s
}

// notify sends a test-hook value without ever blocking a handler.
func notify(ch chan string, v string) {
	select {
	case ch <- v:
	default:
	}
}

// bump records a change of a plugin-owned resource and returns it as a ResourceChange.
func (b *basePlugin) bump(inst *pluginInstance, subject, value string, pointers ...string) *pb.ResourceChange {
	b.mu.Lock()
	defer b.mu.Unlock()
	n := 0
	_, _ = fmt.Sscan(inst.res[subject].revision, &n)
	rev := fmt.Sprint(n + 1)
	inst.res[subject] = resource{value: value, revision: rev}
	return &pb.ResourceChange{Subject: subject, Revision: rev, ChangedPointers: pointers}
}

func (p *subscriptionPlugin) Invoke(ctx context.Context, req *pb.InvokeRequest) (*pb.InvokeResponse, error) {
	rc := req.GetContext()
	inst, err := p.enter(rc)
	if err != nil {
		return nil, err
	}
	defer p.leave(inst)
	if req.GetOperation() != "subscription.sync" {
		return &pb.InvokeResponse{Error: unknownOp(rc, req.GetOperation())}, nil
	}
	var in struct {
		NodeID string   `json:"node_id"`
		Users  []string `json:"users"`
	}
	if json.Unmarshal(req.GetPayloadJson(), &in) != nil || len(in.Users) == 0 {
		return &pb.InvokeResponse{Error: validationFailed(rc, &pb.FieldViolation{Pointer: "/users", Code: "REQUIRED",
			Message: localize(rc, "至少需要一个用户", "at least one user is required")})}, nil
	}
	invoke := pb.NewHostInvokeServiceClient(p.hostConn())
	hc := hostCtx(inst, rc, rc.GetOperationId())
	started, err := invoke.InvokePlugin(ctx, &pb.InvokePluginRequest{
		Context: hc, TargetPluginId: "core.xray", TargetInstanceId: "default", Operation: "core.apply", ApiVersion: "v1",
		PayloadJson: mustJSON(map[string]any{"inbounds": []map[string]any{{"tag": "vless-in", "users": in.Users}}}),
		// The parent operation_id: a retry of this operation finds the child it already started.
		IdempotencyKey: rc.GetOperationId(),
		TargetNodeId:   in.NodeID,
	})
	if err != nil {
		return &pb.InvokeResponse{Error: errorFromStatus(err)}, nil
	}
	final, err := waitDone(ctx, invoke, hc, started.GetOperationId())
	if ctx.Err() != nil {
		// Our own operation was canceled. Nothing in the ABI cancels the child for us (see report).
		cctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
		defer cancel()
		_, _ = invoke.CancelOperation(cctx, &pb.CancelOperationRequest{Context: hc, OperationId: started.GetOperationId()})
		return nil, ctx.Err()
	}
	if err != nil {
		return &pb.InvokeResponse{Error: errorFromStatus(err)}, nil
	}
	switch final.GetState() {
	case pb.OperationState_OPERATION_STATE_SUCCEEDED:
	case pb.OperationState_OPERATION_STATE_AWAITING_APPROVAL:
		// An invoke-mode parent cannot wait for a human (see report).
		return &pb.InvokeResponse{Error: &pb.ErrorDetail{Code: "APPROVAL_REQUIRED",
			Message:     localize(rc, "核心变更需要单独批准", "the core change needs its own approval"),
			DetailsJson: mustJSON(map[string]string{"operation_id": started.GetOperationId()})}}, nil
	default:
		return &pb.InvokeResponse{Error: final.GetError()}, nil
	}
	var core struct {
		AppliedRevision string `json:"applied_revision"`
		Attempt         uint32 `json:"attempt"`
	}
	_ = json.Unmarshal(final.GetResultJson(), &core)
	p.mu.Lock()
	subject := p.changeSubject
	p.mu.Unlock()
	change := p.bump(inst, subject, fmt.Sprint(len(in.Users)), "/users")
	return &pb.InvokeResponse{
		PayloadJson: mustJSON(map[string]any{"core_operation_id": started.GetOperationId(),
			"core_revision": core.AppliedRevision, "core_attempt": core.Attempt, "users": len(in.Users)}),
		Changes: []*pb.ResourceChange{change},
	}, nil
}

// waitDone long-polls WaitOperation while the operation is still on its way.
func waitDone(ctx context.Context, c pb.HostInvokeServiceClient, hc *pb.HostCallContext, id string) (*pb.WaitOperationResponse, error) {
	for {
		resp, err := c.WaitOperation(ctx, &pb.WaitOperationRequest{Context: hc, OperationId: id, TimeoutMs: 30000})
		if err != nil {
			return nil, err
		}
		switch resp.GetState() {
		case pb.OperationState_OPERATION_STATE_PENDING, pb.OperationState_OPERATION_STATE_APPROVED,
			pb.OperationState_OPERATION_STATE_RUNNING:
			continue
		}
		// Terminal, AWAITING_APPROVAL, or a state added by a later minor: this code cannot tell
		// whether an unknown state is final (see report).
		return resp, nil
	}
}
