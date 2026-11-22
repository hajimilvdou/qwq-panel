// SPDX-License-Identifier: AGPL-3.0-only

package abi_test

import (
	"context"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/qwq-panel/qwq/sdk/gen/qwq/platform/v1"
)

// invokeService is HostInvokeService on one plugin's socket (ADR-0007 #5, #6).
type invokeService struct {
	pb.UnimplementedHostInvokeServiceServer
	h *fakeHost
	p *hostPlugin
}

func (s *invokeService) InvokePlugin(_ context.Context, req *pb.InvokePluginRequest) (*pb.InvokePluginResponse, error) {
	h, hc := s.h, req.GetContext()
	inst, err := h.caller(s.p, hc)
	if err != nil {
		return nil, err
	}
	need := req.GetTargetPluginId() + "/" + req.GetOperation()
	// Starting a child operation is a side effect, so it counts as a write while planning.
	if err := h.authorize(inst, hc, true, capMatch("plugin.invoke", need), "plugin.invoke:"+need); err != nil {
		return nil, err
	}
	node := req.GetTargetNodeId()
	if node == "" {
		node = s.p.node
	}
	if node != s.p.node && s.p.desc.GetPlacement() != pb.Placement_PLACEMENT_CONTROLLER {
		return nil, status.Error(codes.PermissionDenied, "only placement=controller plugins may target another node")
	}
	targetID := req.GetTargetInstanceId()
	if targetID == "" {
		targetID = "default" // the proto does not say what an empty target_instance_id means (see report)
	}
	target := h.activeInstance(node, req.GetTargetPluginId(), targetID)
	if target == nil {
		return nil, status.Errorf(codes.Unavailable, "no ACTIVE instance %s/%s on node %s", req.GetTargetPluginId(), targetID, node)
	}
	desc := findOp(target.plugin.desc, req.GetOperation())
	if desc == nil {
		return nil, status.Errorf(codes.NotFound, "operation %s", need)
	}
	if desc.GetMode() != pb.OperationMode_OPERATION_MODE_JOB {
		return nil, status.Error(codes.Unimplemented, "the trial host only routes mode=job targets")
	}

	h.mu.Lock()
	parent := h.ops[hc.GetOperationId()] // authorize checked it is dispatched to inst
	idem := ""
	if k := req.GetIdempotencyKey(); k != "" {
		idem = inst.key() + "\x00" + k
		if prev := h.ops[h.idem[idem]]; prev != nil {
			defer h.mu.Unlock()
			return &pb.InvokePluginResponse{OperationId: prev.id, State: prev.state}, nil
		}
	}
	// Without a parent operation the caller acts as itself; the ABI leaves this open (see report).
	actor := &pb.Actor{Kind: pb.ActorKind_ACTOR_KIND_SERVICE, Id: "plugin:" + s.p.desc.GetPluginId()}
	op := h.newOpLocked(opSpec{target: target, op: req.GetOperation(), actor: actor,
		payload: req.GetPayloadJson(), parent: parent, creator: inst})
	if idem != "" {
		h.idem[idem] = op.id
	}
	// A child whose effective risk exceeds its parent's waits for its own approval (ADR-0007 #5).
	needsApproval := op.risk >= pb.RiskLevel_RISK_LEVEL_MEDIUM
	if parent != nil {
		needsApproval = op.risk > parent.risk
	}
	if needsApproval {
		h.setStateLocked(op, pb.OperationState_OPERATION_STATE_AWAITING_APPROVAL)
	}
	h.mu.Unlock()

	if needsApproval {
		return &pb.InvokePluginResponse{OperationId: op.id, State: pb.OperationState_OPERATION_STATE_AWAITING_APPROVAL}, nil
	}
	h.runJob(op)
	return &pb.InvokePluginResponse{OperationId: op.id, State: pb.OperationState_OPERATION_STATE_RUNNING}, nil
}

// ownedOp returns an operation the calling instance created with InvokePlugin. Anything else is
// NOT_FOUND, so a plugin cannot even learn that another instance's operation exists.
func (h *fakeHost) ownedOp(inst *hostInstance, id string) (*hostOp, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if op := h.ops[id]; op != nil && op.creator == inst {
		return op, nil
	}
	return nil, status.Errorf(codes.NotFound, "operation %s", id)
}

const maxWait = 60 * time.Second

func (s *invokeService) WaitOperation(ctx context.Context, req *pb.WaitOperationRequest) (*pb.WaitOperationResponse, error) {
	inst, err := s.h.caller(s.p, req.GetContext())
	if err != nil {
		return nil, err
	}
	op, err := s.h.ownedOp(inst, req.GetOperationId())
	if err != nil {
		return nil, err
	}
	wait := min(time.Duration(req.GetTimeoutMs())*time.Millisecond, maxWait)
	if dl, ok := ctx.Deadline(); ok {
		wait = min(wait, time.Until(dl)*9/10) // answer before the caller's deadline
	}
	timer := time.NewTimer(wait)
	defer timer.Stop()
	for {
		s.h.mu.Lock()
		st, changed := op.state, op.changed
		s.h.mu.Unlock()
		if terminal(st) || st == pb.OperationState_OPERATION_STATE_AWAITING_APPROVAL || wait <= 0 {
			return s.h.waitResponse(op), nil
		}
		select {
		case <-changed:
		case <-timer.C:
			return s.h.waitResponse(op), nil
		case <-ctx.Done():
			return nil, status.FromContextError(ctx.Err()).Err()
		}
	}
}

func (h *fakeHost) waitResponse(op *hostOp) *pb.WaitOperationResponse {
	h.mu.Lock()
	defer h.mu.Unlock()
	r := &pb.WaitOperationResponse{State: op.state}
	switch {
	case op.state == pb.OperationState_OPERATION_STATE_SUCCEEDED:
		r.ResultJson = op.result
	case terminal(op.state):
		r.Error = op.err
	case len(op.progress) > 0:
		r.Progress = op.progress[len(op.progress)-1]
	}
	return r
}

// CancelOperation returns once the plugin's call has ended, so the state it reports is final.
func (s *invokeService) CancelOperation(ctx context.Context, req *pb.CancelOperationRequest) (*pb.CancelOperationResponse, error) {
	inst, err := s.h.caller(s.p, req.GetContext())
	if err != nil {
		return nil, err
	}
	op, err := s.h.ownedOp(inst, req.GetOperationId())
	if err != nil {
		return nil, err
	}
	s.h.cancelOp(op)
	select {
	case <-op.done:
	case <-ctx.Done():
		return nil, status.FromContextError(ctx.Err()).Err()
	}
	return &pb.CancelOperationResponse{State: s.h.view(op).State}, nil
}
