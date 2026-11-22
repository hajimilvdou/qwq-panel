// SPDX-License-Identifier: AGPL-3.0-only

package abi_test

import (
	"context"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	pb "github.com/qwq-panel/qwq/sdk/gen/qwq/platform/v1"
)

// basePlugin is the instance table shared by the trial plugins: one process, many instances, each
// call addressed by RequestContext.instance_id (ADR-0002). It embeds the generated Unimplemented
// server, so every plugin built on it answers UNIMPLEMENTED for RPCs it does not override.
//
// Addressing errors are gRPC statuses, not ErrorDetail (see report): an unknown or released
// instance is NOT_FOUND, an instance that is not accepting requests is FAILED_PRECONDITION. Most
// lifecycle responses have no ErrorDetail field, and these are host routing faults rather than
// domain outcomes, so one rule covers every instance-level RPC.
type basePlugin struct {
	pb.UnimplementedPluginServiceServer
	desc *pb.PluginDescriptor

	mu       sync.Mutex
	host     grpc.ClientConnInterface
	insts    map[string]*pluginInstance
	draining chan string // test hook: receives the instance id when Stop starts draining
}

type pluginInstance struct {
	id        string
	handle    string // instance_handle for HostCallContext
	configRev string
	state     pb.LifecycleState
	inflight  int
	idle      chan struct{} // closed when inflight drops to 0 while draining
	res       map[string]resource
}

// resource is plugin-owned state kept in memory, with a revision per subject.
type resource struct {
	value    string
	revision string
}

func newBasePlugin(desc *pb.PluginDescriptor) *basePlugin {
	return &basePlugin{desc: desc, insts: map[string]*pluginInstance{}}
}

func (b *basePlugin) connectHost(cc grpc.ClientConnInterface) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.host = cc
}

func (b *basePlugin) hostConn() grpc.ClientConnInterface {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.host
}

func (b *basePlugin) GetDescriptor(context.Context, *pb.GetDescriptorRequest) (*pb.GetDescriptorResponse, error) {
	return &pb.GetDescriptorResponse{Descriptor_: proto.Clone(b.desc).(*pb.PluginDescriptor)}, nil
}

func (b *basePlugin) Initialize(_ context.Context, req *pb.InitializeRequest) (*pb.InitializeResponse, error) {
	id := req.GetContext().GetInstanceId()
	if id == "" || req.GetInstanceHandle() == "" {
		return nil, status.Error(codes.InvalidArgument, "instance_id and instance_handle are required")
	}
	if req.GetHostAbiMinor() < b.desc.GetAbiMinor() {
		return nil, status.Errorf(codes.FailedPrecondition, "host ABI minor %d < required %d", req.GetHostAbiMinor(), b.desc.GetAbiMinor())
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if _, ok := b.insts[id]; ok {
		return nil, status.Errorf(codes.FailedPrecondition, "instance %s already initialized", id)
	}
	b.insts[id] = &pluginInstance{id: id, handle: req.GetInstanceHandle(), configRev: req.GetConfigRevision(),
		state: pb.LifecycleState_LIFECYCLE_STATE_INITIALIZED, res: map[string]resource{}}
	return &pb.InitializeResponse{StateSchemaVersion: b.desc.GetStateSchemaVersion()}, nil
}

// transition moves an instance from one of the states in from to to.
func (b *basePlugin) transition(rc *pb.RequestContext, to pb.LifecycleState, from ...pb.LifecycleState) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	inst := b.insts[rc.GetInstanceId()]
	if inst == nil {
		return status.Errorf(codes.NotFound, "instance %q", rc.GetInstanceId())
	}
	for _, f := range from {
		if inst.state == f {
			inst.state = to
			return nil
		}
	}
	return status.Errorf(codes.FailedPrecondition, "instance %s is %v", inst.id, inst.state)
}

func (b *basePlugin) Start(_ context.Context, req *pb.StartRequest) (*pb.StartResponse, error) {
	if err := b.transition(req.GetContext(), pb.LifecycleState_LIFECYCLE_STATE_READY, pb.LifecycleState_LIFECYCLE_STATE_INITIALIZED); err != nil {
		return nil, err
	}
	return &pb.StartResponse{}, nil
}

func (b *basePlugin) Activate(_ context.Context, req *pb.ActivateRequest) (*pb.ActivateResponse, error) {
	if err := b.transition(req.GetContext(), pb.LifecycleState_LIFECYCLE_STATE_ACTIVE, pb.LifecycleState_LIFECYCLE_STATE_READY); err != nil {
		return nil, err
	}
	return &pb.ActivateResponse{}, nil
}

// Deactivate stops background work only; the instance keeps serving requests (READY).
func (b *basePlugin) Deactivate(_ context.Context, req *pb.DeactivateRequest) (*pb.DeactivateResponse, error) {
	if err := b.transition(req.GetContext(), pb.LifecycleState_LIFECYCLE_STATE_READY, pb.LifecycleState_LIFECYCLE_STATE_ACTIVE); err != nil {
		return nil, err
	}
	return &pb.DeactivateResponse{}, nil
}

// Stop moves the instance to DRAINING, which refuses new requests; with drain it waits for
// in-flight requests up to grace_period_ms (or the gRPC deadline), then reports STOPPED.
func (b *basePlugin) Stop(ctx context.Context, req *pb.StopRequest) (*pb.StopResponse, error) {
	b.mu.Lock()
	inst := b.insts[req.GetContext().GetInstanceId()]
	if inst == nil {
		b.mu.Unlock()
		return nil, status.Errorf(codes.NotFound, "instance %q", req.GetContext().GetInstanceId())
	}
	if inst.state != pb.LifecycleState_LIFECYCLE_STATE_READY && inst.state != pb.LifecycleState_LIFECYCLE_STATE_ACTIVE {
		b.mu.Unlock()
		return nil, status.Errorf(codes.FailedPrecondition, "instance %s is %v", inst.id, inst.state)
	}
	inst.state = pb.LifecycleState_LIFECYCLE_STATE_DRAINING
	var idle chan struct{}
	if req.GetDrain() && inst.inflight > 0 {
		idle = make(chan struct{})
		inst.idle = idle
	}
	hook := b.draining
	b.mu.Unlock()
	if hook != nil {
		hook <- inst.id
	}
	if idle != nil {
		var grace <-chan time.Time
		if ms := req.GetGracePeriodMs(); ms > 0 {
			timer := time.NewTimer(time.Duration(ms) * time.Millisecond)
			defer timer.Stop()
			grace = timer.C
		}
		select {
		case <-idle:
		case <-grace:
		case <-ctx.Done():
		}
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	inst.state = pb.LifecycleState_LIFECYCLE_STATE_STOPPED
	return &pb.StopResponse{Drained: inst.inflight == 0}, nil
}

// ReleaseInstance forgets the instance; the process keeps serving the others. It is idempotent
// because host-side cleanup never depends on it (ARCH §5.7).
func (b *basePlugin) ReleaseInstance(_ context.Context, req *pb.ReleaseInstanceRequest) (*pb.ReleaseInstanceResponse, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.insts, req.GetContext().GetInstanceId())
	return &pb.ReleaseInstanceResponse{}, nil
}

func (b *basePlugin) CheckHealth(_ context.Context, req *pb.CheckHealthRequest) (*pb.CheckHealthResponse, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	inst := b.insts[req.GetContext().GetInstanceId()]
	if inst == nil {
		return nil, status.Errorf(codes.NotFound, "instance %q", req.GetContext().GetInstanceId())
	}
	st := pb.CheckHealthResponse_STATUS_NOT_SERVING
	if inst.state == pb.LifecycleState_LIFECYCLE_STATE_READY || inst.state == pb.LifecycleState_LIFECYCLE_STATE_ACTIVE {
		st = pb.CheckHealthResponse_STATUS_SERVING
	}
	return &pb.CheckHealthResponse{Status: st, LifecycleState: inst.state, AppliedConfigRevision: inst.configRev}, nil
}

// enter admits a request to its instance; callers defer leave.
func (b *basePlugin) enter(rc *pb.RequestContext) (*pluginInstance, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	inst := b.insts[rc.GetInstanceId()]
	if inst == nil {
		return nil, status.Errorf(codes.NotFound, "instance %q", rc.GetInstanceId())
	}
	if inst.state != pb.LifecycleState_LIFECYCLE_STATE_READY && inst.state != pb.LifecycleState_LIFECYCLE_STATE_ACTIVE {
		return nil, status.Errorf(codes.FailedPrecondition, "instance %s is %v", inst.id, inst.state)
	}
	inst.inflight++
	return inst, nil
}

func (b *basePlugin) leave(inst *pluginInstance) {
	b.mu.Lock()
	defer b.mu.Unlock()
	inst.inflight--
	if inst.inflight == 0 && inst.idle != nil {
		close(inst.idle)
		inst.idle = nil
	}
}

// hostCtx is the HostCallContext for calls made while serving operation opID ("" outside one).
func hostCtx(inst *pluginInstance, rc *pb.RequestContext, opID string) *pb.HostCallContext {
	return &pb.HostCallContext{InstanceHandle: inst.handle, OperationId: opID, TraceId: rc.GetTraceId()}
}

// localize picks user-facing text by RequestContext.locale.
func localize(rc *pb.RequestContext, zh, en string) string {
	if strings.HasPrefix(rc.GetLocale(), "zh") {
		return zh
	}
	return en
}

func unknownOp(rc *pb.RequestContext, op string) *pb.ErrorDetail {
	return &pb.ErrorDetail{Code: "UNKNOWN_OPERATION", Message: localize(rc, "未知操作 "+op, "unknown operation "+op)}
}
