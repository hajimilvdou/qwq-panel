// SPDX-License-Identifier: AGPL-3.0-only

package abi_test

import (
	"context"
	"encoding/json"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/qwq-panel/qwq/sdk/abi"
	pb "github.com/qwq-panel/qwq/sdk/gen/qwq/platform/v1"
)

// securityScanDescriptor mirrors the parts of api/manifest/v1/examples/security.scan.manifest.json
// used here, plus report.summary: an operation that declares no capabilities, for the risk
// comparison of ADR-0007 #4.
func securityScanDescriptor() *pb.PluginDescriptor {
	return &pb.PluginDescriptor{
		PluginId: "security.scan", PluginVersion: "0.4.1", AbiMajor: abi.Major, AbiMinor: 0,
		Placement: pb.Placement_PLACEMENT_NODE, StateSchemaVersion: "2", MinimumRollbackVersion: "0.3.0",
		ConfigSchemaRef: "schemas/config.schema.json", ConfigHotApply: true,
		Capabilities: []*pb.Capability{
			capability("system.config.read", "sshd"), capability("metrics.read", "host:ports"),
			capability("events.publish", "security.alert"), capability("state.kv.write", "self"),
		},
		Operations: []*pb.OperationDescriptor{
			{Name: "scan.run", ApiVersion: "v1", Permission: "security.scan:run",
				Mode: pb.OperationMode_OPERATION_MODE_JOB, Effect: pb.OperationEffect_OPERATION_EFFECT_READ,
				Risk: pb.RiskLevel_RISK_LEVEL_LOW, Idempotent: true, TimeoutMs: 120000,
				RequestSchemaRef: "schemas/scan.run.request.json", ResponseSchemaRef: "schemas/scan.run.response.json",
				Summary: "立即执行一次巡检并返回发现的问题", UiRoute: "/plugins/security.scan/report",
				Capabilities: []*pb.Capability{capability("system.config.read", "sshd"),
					capability("metrics.read", "host:ports"), capability("state.kv.write", "self")}},
			{Name: "report.summary", ApiVersion: "v1", Permission: "security.scan:read",
				Mode: pb.OperationMode_OPERATION_MODE_INVOKE, Effect: pb.OperationEffect_OPERATION_EFFECT_READ,
				Risk: pb.RiskLevel_RISK_LEVEL_LOW, Idempotent: true, TimeoutMs: 5000, Summary: "最近一次巡检的摘要"},
			{Name: "baseline.enable", ApiVersion: "v1", Permission: "security.scan:configure",
				Mode: pb.OperationMode_OPERATION_MODE_JOB, Effect: pb.OperationEffect_OPERATION_EFFECT_WRITE,
				Risk: pb.RiskLevel_RISK_LEVEL_MEDIUM, Idempotent: true, Plannable: true, TimeoutMs: 60000,
				RequestSchemaRef: "schemas/baseline.enable.request.json", ResponseSchemaRef: "schemas/baseline.enable.response.json",
				Summary: "开启 SSH、端口与弱口令的定期巡检", UndoOperation: "baseline.disable", UiRoute: "/plugins/security.scan/settings",
				Capabilities: []*pb.Capability{capability("state.kv.write", "self")}},
		},
	}
}

// securityScan implements baseline.enable: an intent-level job (ADR-0004 D8) that enables three
// checks, one step each, on the KV key "baseline".
type securityScan struct {
	*basePlugin
	planProbe chan [2]codes.Code // test hook, guarded by mu: PlanOperation tries two KV writes
}

type baseline struct {
	Enabled       bool     `json:"enabled"`
	IntervalHours int      `json:"interval_hours"`
	Checks        []string `json:"checks"`
}

var baselineSteps = []struct{ check, zh, en string }{
	{"ssh", "开启 SSH 配置检查", "enable the SSH config check"},
	{"ports", "开启开放端口检查", "enable the open port check"},
	{"weak_password", "开启弱口令策略检查", "enable the weak password check"},
}

func baselineRequest(rc *pb.RequestContext, payload []byte) (baseline, *pb.ErrorDetail) {
	var in struct {
		IntervalHours int `json:"interval_hours"`
	}
	if json.Unmarshal(payload, &in) != nil || in.IntervalHours < 1 || in.IntervalHours > 168 {
		return baseline{}, validationFailed(rc, &pb.FieldViolation{Pointer: "/interval_hours", Code: "RANGE",
			Message: localize(rc, "必须在 1 到 168 之间", "must be between 1 and 168")})
	}
	b := baseline{Enabled: true, IntervalHours: in.IntervalHours}
	for _, s := range baselineSteps {
		b.Checks = append(b.Checks, s.check)
	}
	return b, nil
}

func (p *securityScan) kv() pb.HostStateServiceClient {
	return pb.NewHostStateServiceClient(p.hostConn())
}

// PlanOperation reads the current baseline and returns the change and the precondition that pins
// it. It writes nothing.
func (p *securityScan) PlanOperation(ctx context.Context, req *pb.PlanOperationRequest) (*pb.PlanOperationResponse, error) {
	rc := req.GetContext()
	inst, err := p.enter(rc)
	if err != nil {
		return nil, err
	}
	defer p.leave(inst)
	if req.GetOperation() != "baseline.enable" {
		return &pb.PlanOperationResponse{Error: unknownOp(rc, req.GetOperation())}, nil
	}
	after, verr := baselineRequest(rc, req.GetPayloadJson())
	if verr != nil {
		return &pb.PlanOperationResponse{Error: verr}, nil
	}
	p.mu.Lock()
	probe := p.planProbe
	p.mu.Unlock()
	if probe != nil {
		put := func(opID string) codes.Code {
			_, err := p.kv().PutState(ctx, &pb.PutStateRequest{Context: hostCtx(inst, rc, opID), Key: "probe", ValueJson: []byte(`1`)})
			return status.Code(err)
		}
		probe <- [2]codes.Code{put(rc.GetOperationId()), put("")}
	}
	cur, err := p.kv().GetState(ctx, &pb.GetStateRequest{Context: hostCtx(inst, rc, rc.GetOperationId()), Key: "baseline"})
	if err != nil {
		return &pb.PlanOperationResponse{Error: errorFromStatus(err)}, nil
	}
	change := &pb.PlannedChange{Kind: pb.PlannedChange_KIND_CREATE, Subject: "baseline", AfterJson: mustJSON(after),
		Reversible: true, Description: localize(rc, "开启 SSH、端口与弱口令巡检", "enable SSH, port and weak password checks")}
	if cur.GetFound() {
		change.Kind, change.BeforeJson = pb.PlannedChange_KIND_UPDATE, cur.GetValueJson()
	}
	return &pb.PlanOperationResponse{
		Changes:       []*pb.PlannedChange{change},
		Preconditions: []*pb.Precondition{{Subject: "baseline", Revision: cur.GetRevision()}}, // "" = must not exist
	}, nil
}

// RunJob executes baseline.enable in three steps. Each write is guarded by PutState: the first one
// by the plan's precondition, the next ones by the revision the job itself wrote, so the check and
// the write are atomic on the host's KV (ADR-0004 D7).
func (p *securityScan) RunJob(req *pb.RunJobRequest, stream grpc.ServerStreamingServer[pb.RunJobResponse]) error {
	ctx, rc := stream.Context(), req.GetContext()
	inst, err := p.enter(rc)
	if err != nil {
		return err
	}
	defer p.leave(inst)
	send := func(jp *pb.JobProgress) error { return stream.Send(&pb.RunJobResponse{Progress: jp}) }
	if req.GetOperation() != "baseline.enable" {
		return send(&pb.JobProgress{Error: unknownOp(rc, req.GetOperation())})
	}
	want, verr := baselineRequest(rc, req.GetPayloadJson())
	if verr != nil {
		return send(&pb.JobProgress{Error: verr})
	}
	put := &pb.PutStateRequest{Context: hostCtx(inst, rc, rc.GetOperationId()), Key: "baseline"}
	for _, pc := range req.GetPreconditions() {
		if pc.GetSubject() != "baseline" {
			return send(&pb.JobProgress{Error: &pb.ErrorDetail{Code: "PRECONDITION_FAILED",
				Message: localize(rc, "未知的前置条件 "+pc.GetSubject(), "unknown precondition "+pc.GetSubject())}})
		}
		// Precondition.revision "" means "must not exist"; PutState spells that must_not_exist.
		if pc.GetRevision() == "" {
			put.Precondition = &pb.PutStateRequest_MustNotExist{MustNotExist: true}
		} else {
			put.Precondition = &pb.PutStateRequest_ExpectedRevision{ExpectedRevision: pc.GetRevision()}
		}
	}
	cur := baseline{Enabled: true, IntervalHours: want.IntervalHours}
	for i, s := range baselineSteps {
		cur.Checks = append(cur.Checks, s.check)
		put.ValueJson = mustJSON(cur)
		resp, err := p.kv().PutState(ctx, put)
		switch {
		case ctx.Err() != nil:
			return ctx.Err()
		case status.Code(err) == codes.Aborted:
			return send(&pb.JobProgress{Error: &pb.ErrorDetail{Code: "PRECONDITION_FAILED",
				Message:     localize(rc, "计划之后基线已被修改，请重新预览", "the baseline changed after the plan; plan again"),
				DetailsJson: mustJSON(map[string]string{"subject": "baseline", "step": s.check})}})
		case err != nil:
			return send(&pb.JobProgress{Error: errorFromStatus(err)})
		}
		put.Precondition = &pb.PutStateRequest_ExpectedRevision{ExpectedRevision: resp.GetRevision()}
		pointers := []string{"/checks"}
		if i == 0 {
			pointers = []string{"/enabled", "/interval_hours", "/checks"}
		}
		if err := send(&pb.JobProgress{Percent: uint32(100 * (i + 1) / (len(baselineSteps) + 1)), Step: s.check,
			StepIndex: uint32(i + 1), StepCount: uint32(len(baselineSteps)), Message: localize(rc, s.zh, s.en),
			Changes: []*pb.ResourceChange{{Subject: "baseline", Revision: resp.GetRevision(), ChangedPointers: pointers}},
		}); err != nil {
			return err
		}
	}
	return send(&pb.JobProgress{Percent: 100, Completed: true, ResultJson: mustJSON(map[string]any{
		"enabled": true, "checks": cur.Checks, "revision": put.GetExpectedRevision(),
	})})
}
