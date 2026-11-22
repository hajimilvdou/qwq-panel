// SPDX-License-Identifier: AGPL-3.0-only

package abi_test

import (
	"context"
	"encoding/json"
	"strconv"
	"unicode/utf8"

	"github.com/qwq-panel/qwq/sdk/abi"
	pb "github.com/qwq-panel/qwq/sdk/gen/qwq/platform/v1"
)

// noopPlugin is the empty plugin of scenario one. noop.echo is read-only; noop.rename changes the
// in-memory "greeting" resource of an instance and is plannable.
type noopPlugin struct {
	*basePlugin
	held    chan string   // test hook: echo of "hold" reports its instance here, then waits
	release chan struct{} // closed by the test to let held echoes return
}

func newNoopPlugin() *noopPlugin {
	return &noopPlugin{basePlugin: newBasePlugin(noopDescriptor()), held: make(chan string, 1), release: make(chan struct{})}
}

func noopDescriptor() *pb.PluginDescriptor {
	return &pb.PluginDescriptor{
		PluginId: "noop", PluginVersion: "0.1.0", AbiMajor: abi.Major, AbiMinor: 0,
		Placement: pb.Placement_PLACEMENT_NODE, StateSchemaVersion: "1",
		Operations: []*pb.OperationDescriptor{
			{Name: "noop.echo", ApiVersion: "v1", Permission: "noop:read", Mode: pb.OperationMode_OPERATION_MODE_INVOKE,
				Effect: pb.OperationEffect_OPERATION_EFFECT_READ, Risk: pb.RiskLevel_RISK_LEVEL_LOW, Idempotent: true,
				TimeoutMs: 5000, Summary: "echo a message"},
			{Name: "noop.rename", ApiVersion: "v1", Permission: "noop:write", Mode: pb.OperationMode_OPERATION_MODE_INVOKE,
				Effect: pb.OperationEffect_OPERATION_EFFECT_WRITE, Risk: pb.RiskLevel_RISK_LEVEL_LOW, Plannable: true,
				TimeoutMs: 5000, Summary: "change the greeting"},
		},
	}
}

// Initialize also loads the instance's greeting from its config.
func (p *noopPlugin) Initialize(ctx context.Context, req *pb.InitializeRequest) (*pb.InitializeResponse, error) {
	resp, err := p.basePlugin.Initialize(ctx, req)
	if err != nil {
		return nil, err
	}
	var cfg struct {
		Greeting string `json:"greeting"`
	}
	_ = json.Unmarshal(req.GetConfigJson(), &cfg)
	if cfg.Greeting != "" {
		p.mu.Lock()
		p.insts[req.GetContext().GetInstanceId()].res["greeting"] = resource{value: cfg.Greeting, revision: "1"}
		p.mu.Unlock()
	}
	return resp, nil
}

func (p *noopPlugin) Invoke(ctx context.Context, req *pb.InvokeRequest) (*pb.InvokeResponse, error) {
	rc := req.GetContext()
	inst, err := p.enter(rc)
	if err != nil {
		return nil, err
	}
	defer p.leave(inst)
	switch req.GetOperation() {
	case "noop.echo":
		return p.echo(ctx, inst, req)
	case "noop.rename":
		return p.rename(inst, req)
	}
	return &pb.InvokeResponse{Error: unknownOp(rc, req.GetOperation())}, nil
}

func validationFailed(rc *pb.RequestContext, vs ...*pb.FieldViolation) *pb.ErrorDetail {
	return &pb.ErrorDetail{Code: "VALIDATION_FAILED", Message: localize(rc, "请求参数不合法", "invalid request"), Violations: vs}
}

func (p *noopPlugin) echo(ctx context.Context, inst *pluginInstance, req *pb.InvokeRequest) (*pb.InvokeResponse, error) {
	rc := req.GetContext()
	var in map[string]json.RawMessage
	if err := json.Unmarshal(req.GetPayloadJson(), &in); err != nil {
		return &pb.InvokeResponse{Error: validationFailed(rc, &pb.FieldViolation{Pointer: "", Code: "INVALID_JSON",
			Message: localize(rc, "请求不是 JSON 对象", "request is not a JSON object")})}, nil
	}
	var msg string
	raw, ok := in["message"]
	switch {
	case !ok:
		return &pb.InvokeResponse{Error: validationFailed(rc, &pb.FieldViolation{Pointer: "/message", Code: "REQUIRED",
			Message: localize(rc, "必须填写", "is required")})}, nil
	case json.Unmarshal(raw, &msg) != nil:
		return &pb.InvokeResponse{Error: validationFailed(rc, &pb.FieldViolation{Pointer: "/message", Code: "TYPE",
			Message: localize(rc, "必须是字符串", "must be a string")})}, nil
	case msg == "" || utf8.RuneCountInString(msg) > 64:
		return &pb.InvokeResponse{Error: validationFailed(rc, &pb.FieldViolation{Pointer: "/message", Code: "LENGTH",
			Message: localize(rc, "长度必须为 1 到 64 个字符", "must be 1 to 64 characters")})}, nil
	}
	if msg == "hold" {
		select {
		case p.held <- inst.id:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		select {
		case <-p.release:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	unknown := len(req.ProtoReflect().GetUnknown()) + len(rc.ProtoReflect().GetUnknown())
	return &pb.InvokeResponse{PayloadJson: mustJSON(map[string]any{
		"message": msg, "instance_id": inst.id, "attempt": req.GetAttempt(), "unknown_bytes": unknown,
	})}, nil
}

// greetingRequest is the payload of noop.rename.
func greetingRequest(rc *pb.RequestContext, payload []byte) (string, *pb.ErrorDetail) {
	var in struct {
		Greeting string `json:"greeting"`
	}
	if json.Unmarshal(payload, &in) != nil || in.Greeting == "" {
		return "", validationFailed(rc, &pb.FieldViolation{Pointer: "/greeting", Code: "REQUIRED",
			Message: localize(rc, "必须填写", "is required")})
	}
	return in.Greeting, nil
}

// rename checks the plugin-owned preconditions and writes under one lock, i.e. atomically
// (ADR-0004 D7), and reports the change with a relative subject.
func (p *noopPlugin) rename(inst *pluginInstance, req *pb.InvokeRequest) (*pb.InvokeResponse, error) {
	rc := req.GetContext()
	greeting, verr := greetingRequest(rc, req.GetPayloadJson())
	if verr != nil {
		return &pb.InvokeResponse{Error: verr}, nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, pc := range req.GetPreconditions() {
		cur := inst.res[pc.GetSubject()]
		if pc.GetSubject() != "greeting" || cur.revision != pc.GetRevision() {
			return &pb.InvokeResponse{Error: &pb.ErrorDetail{Code: "PRECONDITION_FAILED",
				Message:     localize(rc, "资源已被修改", "the resource has changed"),
				DetailsJson: mustJSON(map[string]string{"subject": pc.GetSubject(), "revision": cur.revision})}}, nil
		}
	}
	n, _ := strconv.Atoi(inst.res["greeting"].revision)
	rev := strconv.Itoa(n + 1)
	inst.res["greeting"] = resource{value: greeting, revision: rev}
	return &pb.InvokeResponse{
		PayloadJson: mustJSON(map[string]string{"greeting": greeting, "revision": rev}),
		Changes:     []*pb.ResourceChange{{Subject: "greeting", Revision: rev, ChangedPointers: []string{"/greeting"}}},
	}, nil
}

// PlanOperation previews noop.rename without side effects. Validation failures are reported as
// ErrorDetail{VALIDATION_FAILED} like Invoke; PlanOperationResponse.violations is left unused
// (see report).
func (p *noopPlugin) PlanOperation(_ context.Context, req *pb.PlanOperationRequest) (*pb.PlanOperationResponse, error) {
	rc := req.GetContext()
	inst, err := p.enter(rc)
	if err != nil {
		return nil, err
	}
	defer p.leave(inst)
	if req.GetOperation() != "noop.rename" {
		return &pb.PlanOperationResponse{Error: unknownOp(rc, req.GetOperation())}, nil
	}
	greeting, verr := greetingRequest(rc, req.GetPayloadJson())
	if verr != nil {
		return &pb.PlanOperationResponse{Error: verr}, nil
	}
	p.mu.Lock()
	cur, exists := inst.res["greeting"]
	p.mu.Unlock()
	change := &pb.PlannedChange{Kind: pb.PlannedChange_KIND_CREATE, Subject: "greeting", Pointer: "/greeting",
		AfterJson: mustJSON(greeting), Reversible: true,
		Description: localize(rc, "问候语设为 "+greeting, "set the greeting to "+greeting)}
	if exists {
		change.Kind = pb.PlannedChange_KIND_UPDATE
		change.BeforeJson = mustJSON(cur.value)
	}
	return &pb.PlanOperationResponse{
		Changes: []*pb.PlannedChange{change},
		// Revision "" means "must not exist" (Precondition comment).
		Preconditions: []*pb.Precondition{{Subject: "greeting", Revision: cur.revision}},
	}, nil
}
