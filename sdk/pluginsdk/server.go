// SPDX-License-Identifier: Apache-2.0

package pluginsdk

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	platformv1 "github.com/qwq-panel/qwq/sdk/gen/qwq/platform/v1"
	"github.com/qwq-panel/qwq/sdk/manifest"
)

// Server implements platformv1.PluginServiceServer for one plugin process.
// It is created by [Serve]; plugins never construct it directly.
type Server struct {
	platformv1.UnimplementedPluginServiceServer

	plugin     Plugin
	manifest   *manifest.Manifest
	descriptor *platformv1.PluginDescriptor
	hostConn   grpc.ClientConnInterface
	hostSocket string
	log        *slog.Logger
	baseCtx    context.Context
	grace      time.Duration
	relGrace   time.Duration
	memory     MemoryLimit
	drainer    *IdleDrainer

	// crashOnPanic mirrors Options.CrashOnPanic.
	crashOnPanic bool

	mu        sync.Mutex
	instances map[string]*instance
	closed    bool
}

// GetDescriptor returns the descriptor derived from the embedded manifest.
// It is available before any instance exists.
func (s *Server) GetDescriptor(context.Context, *platformv1.GetDescriptorRequest) (*platformv1.GetDescriptorResponse, error) {
	return &platformv1.GetDescriptorResponse{
		Descriptor_: proto.Clone(s.descriptor).(*platformv1.PluginDescriptor),
	}, nil
}

// Initialize creates one instance. The instance accepts nothing until Start.
func (s *Server) Initialize(ctx context.Context, req *platformv1.InitializeRequest) (*platformv1.InitializeResponse, error) {
	rc := req.GetContext()
	id := rc.GetInstanceId()
	if id == "" {
		return nil, status.Error(codes.InvalidArgument, "context.instance_id is required")
	}
	if req.GetInstanceHandle() == "" {
		return nil, status.Error(codes.InvalidArgument, "instance_handle is required")
	}
	if req.GetHostAbiMinor() < uint32(s.manifest.ABI.MinimumMinor) {
		return nil, status.Errorf(codes.FailedPrecondition, "host ABI minor %d is below the manifest minimum %d",
			req.GetHostAbiMinor(), s.manifest.ABI.MinimumMinor)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, status.Error(codes.Unavailable, "the plugin is shutting down")
	}
	if s.instances[id] != nil {
		return nil, status.Errorf(codes.FailedPrecondition, "instance %q is already initialized", id)
	}

	log := s.log.With(slog.String("instance", id))
	host := &Host{conn: s.hostConn, handle: req.GetInstanceHandle()}
	in := newInstance(id, req.GetInstanceHandle(), host, log)
	in.crashOnPanic = s.crashOnPanic
	in.setConfig(req.GetConfigJson(), req.GetConfigRevision())
	info := InstanceInfo{
		ID:                 id,
		DataDir:            req.GetDataDir(),
		Config:             append([]byte(nil), req.GetConfigJson()...),
		ConfigRevision:     req.GetConfigRevision(),
		StateSchemaVersion: req.GetStateSchemaVersion(),
		HostABIMinor:       req.GetHostAbiMinor(),
		core:               in,
	}

	ictx := in.callContext(ctx, rc, 0, false)
	// Registration misuse (a nil handler, a duplicate) panics by design; here it
	// becomes a refused Initialize instead of a dead process.
	author, err := safely(in, "new_instance", func() (Instance, error) {
		return s.plugin.NewInstance(ictx, info)
	})
	if err != nil {
		log.Error("new instance failed", slog.String("error", err.Error()))
		var pe *panicError
		if errors.As(err, &pe) {
			return nil, status.Errorf(codes.FailedPrecondition, "plugin panicked creating instance %q: %v", id, pe.value)
		}
		return nil, status.Errorf(codes.FailedPrecondition, "plugin rejected instance %q", id)
	}
	if err := safelyRun(in, "bind", func() error { return in.bind(author) }); err != nil {
		log.Error("invalid instance", slog.String("error", err.Error()))
		return nil, status.Errorf(codes.FailedPrecondition, "invalid instance %q", id)
	}
	in.author = author
	if _, ok := author.(ConfigApplier); ok && !s.manifest.Config.HotApply {
		log.Warn("the instance implements ConfigApplier but the manifest sets config.hot_apply=false; the hook is only called if the host applies config live")
	}
	ops := in.operations()
	if err := validateHandlers(s.manifest, ops); err != nil {
		log.Error("operation registry does not match the manifest", slog.String("error", err.Error()))
		return nil, status.Errorf(codes.FailedPrecondition, "operation registry does not match the manifest: %v", err)
	}
	in.ops = ops

	s.instances[id] = in
	log.Info("instance initialized", slog.String("config_revision", req.GetConfigRevision()))
	return &platformv1.InitializeResponse{StateSchemaVersion: s.manifest.State.SchemaVersion}, nil
}

// Start moves INITIALIZED to READY. Requests are served only after it returns.
func (s *Server) Start(ctx context.Context, req *platformv1.StartRequest) (*platformv1.StartResponse, error) {
	in, err := s.instance(req.GetContext())
	if err != nil {
		return nil, err
	}
	unlock, err := in.lockLife(ctx)
	if err != nil {
		return nil, err
	}
	defer unlock()
	if state := in.stateNow(); state != StateInitialized {
		return nil, status.Errorf(codes.FailedPrecondition, "instance %q is %s, cannot move to READY", in.id, state)
	}
	if st, ok := in.author.(Starter); ok {
		ictx := in.callContext(ctx, req.GetContext(), 0, false)
		if err := safelyRun(in, "start", func() error { return st.Start(ictx) }); err != nil {
			in.fail()
			in.log.Error("start failed", slog.String("error", err.Error()))
			return nil, status.Error(codes.Internal, "the plugin failed to start the instance")
		}
	}
	// The hook ran while the instance was still INITIALIZED, so nothing could be
	// served before the plugin was ready.
	if err := in.transition(StateReady, StateInitialized); err != nil {
		return nil, err
	}
	if streamer, ok := in.author.(PublicHTTPStreamer); ok {
		hostSock := s.hostSocket
		if hostSock == "" {
			hostSock = os.Getenv(EnvHostSocket)
		}
		if hostSock != "" {
			bridge, bErr := StartPublicStreamBridge(hostSock, streamer, nil)
			if bErr != nil {
				in.log.Warn("failed to start public stream bridge; falling back to buffered ABI", slog.String("error", bErr.Error()))
			} else if bridge != nil {
				in.setStreamBridge(bridge)
				in.log.Info("public stream bridge listening", slog.String("socket", bridge.SocketPath()))
			}
		}
	}
	in.log.Info("instance ready")
	return &platformv1.StartResponse{}, nil
}

// Activate 将 READY 转为 ACTIVE；恢复时重复激活不重建后台代次。
func (s *Server) Activate(ctx context.Context, req *platformv1.ActivateRequest) (*platformv1.ActivateResponse, error) {
	in, err := s.instance(req.GetContext())
	if err != nil {
		return nil, err
	}
	unlock, err := in.lockLife(ctx)
	if err != nil {
		return nil, err
	}
	defer unlock()
	// -----------------------------------------------------------------------
	// 宿主的恢复步骤允许重复投递；生命周期锁保证首个 hook 已结束后才判定
	// ACTIVE。直接返回保留当前后台上下文，避免重复启动任务或重置内存历史。
	// -----------------------------------------------------------------------
	if in.stateNow() == StateActive {
		return &platformv1.ActivateResponse{}, nil
	}
	// Work of the previous generation that outlived its grace period must end
	// first: two generations never run background work at the same time.
	if err := in.awaitPreviousBackground(ctx); err != nil {
		return nil, err
	}
	bg, err := in.startBackground(s.baseCtx, req.GetContext().GetTraceId())
	if err != nil {
		return nil, err
	}
	if ac, ok := in.author.(Activator); ok {
		if err := safelyRun(in, "activate", func() error { return ac.Activate(bg) }); err != nil {
			in.stopBackground(ctx, s.grace)
			in.fail()
			in.log.Error("activate failed", slog.String("error", err.Error()))
			return nil, status.Error(codes.Internal, "the plugin failed to activate the instance")
		}
	}
	in.log.Info("instance active")
	return &platformv1.ActivateResponse{}, nil
}

// Deactivate stops background work and returns the instance to READY.
func (s *Server) Deactivate(ctx context.Context, req *platformv1.DeactivateRequest) (*platformv1.DeactivateResponse, error) {
	in, err := s.instance(req.GetContext())
	if err != nil {
		return nil, err
	}
	grace := s.graceOf(req.GetGracePeriodMs())
	dctx, cancel := context.WithTimeout(ctx, grace)
	defer cancel()
	unlock, err := in.lockLife(dctx)
	if err != nil {
		return nil, err
	}
	defer unlock()
	if err := in.transition(StateReady, StateActive); err != nil {
		return nil, err
	}
	if !in.stopBackground(dctx, grace) {
		in.log.Warn("tracked background work did not stop within the grace period")
	}
	if de, ok := in.author.(Deactivator); ok {
		hctx := in.callContext(dctx, req.GetContext(), 0, false)
		if err := safelyRun(in, "deactivate", func() error { return de.Deactivate(hctx) }); err != nil {
			// The background context is canceled and the instance is READY; report
			// the hook failure but do not leave it ACTIVE.
			in.log.Error("deactivate hook failed", slog.String("error", err.Error()))
			return nil, status.Error(codes.Internal, "the plugin failed to deactivate the instance")
		}
	}
	in.log.Info("instance deactivated")
	return &platformv1.DeactivateResponse{}, nil
}

// Stop drains the instance, stops background work and moves it to STOPPED.
func (s *Server) Stop(ctx context.Context, req *platformv1.StopRequest) (*platformv1.StopResponse, error) {
	in, err := s.instance(req.GetContext())
	if err != nil {
		return nil, err
	}
	grace := s.graceOf(req.GetGracePeriodMs())
	dctx, cancel := context.WithTimeout(ctx, grace)
	defer cancel()
	unlock, err := in.lockLife(dctx)
	if err != nil {
		return nil, err
	}
	defer unlock()
	// A direct Stop from ACTIVE must also run the Deactivate hook, otherwise
	// untracked background work (a timer the plugin stops itself) would leak.
	wasActive := in.stateNow() == StateActive
	if err := in.transition(StateDraining, StateInitialized, StateReady, StateActive, StateFailed); err != nil {
		return nil, err
	}
	if !in.stopBackground(dctx, grace) {
		in.log.Warn("tracked background work did not stop within the grace period")
	}
	// Drain in-flight requests before final teardown, so a Stopper/Deactivate
	// hook cannot free state that a running request still uses. drain=false is
	// the host's explicit "do not wait" and keeps the current behaviour.
	var drained bool
	if req.GetDrain() {
		drained = in.waitIdle(dctx, grace)
	} else {
		drained = in.isIdle()
	}
	if wasActive {
		if de, ok := in.author.(Deactivator); ok {
			hctx := in.callContext(dctx, req.GetContext(), 0, false)
			if err := safelyRun(in, "deactivate", func() error { return de.Deactivate(hctx) }); err != nil {
				in.log.Error("deactivate hook failed during stop", slog.String("error", err.Error()))
			}
		}
	}
	in.closeStreamBridge(dctx)
	if st, ok := in.author.(Stopper); ok {
		hctx := in.callContext(dctx, req.GetContext(), 0, false)
		if err := safelyRun(in, "stop", func() error { return st.Stop(hctx) }); err != nil {
			// Teardown continues; the drained flag still tells the host whether
			// in-flight calls finished.
			in.log.Error("stop hook failed", slog.String("error", err.Error()))
		}
	}
	in.setState(StateStopped)
	if !drained {
		in.log.Warn("in-flight requests did not drain within the grace period")
	}
	in.log.Info("instance stopped", slog.Bool("drained", drained))
	return &platformv1.StopResponse{Drained: drained}, nil
}

// ReleaseInstance frees one instance's goroutines and state. The process keeps
// serving the other instances, and the call is idempotent (ARCH §5.7).
func (s *Server) ReleaseInstance(ctx context.Context, req *platformv1.ReleaseInstanceRequest) (*platformv1.ReleaseInstanceResponse, error) {
	id := req.GetContext().GetInstanceId()
	if id == "" {
		return nil, status.Error(codes.InvalidArgument, "context.instance_id is required")
	}
	s.mu.Lock()
	in := s.instances[id]
	if in != nil {
		delete(s.instances, id)
	}
	s.mu.Unlock()
	if in == nil || !in.markReleased() {
		return &platformv1.ReleaseInstanceResponse{}, nil
	}

	dctx, cancel := context.WithTimeout(ctx, s.relGrace)
	defer cancel()
	s.releaseInstance(in.callContext(dctx, req.GetContext(), 0, false), in)
	return &platformv1.ReleaseInstanceResponse{}, nil
}

// CheckHealth reports domain readiness of one instance.
func (s *Server) CheckHealth(ctx context.Context, req *platformv1.CheckHealthRequest) (*platformv1.CheckHealthResponse, error) {
	in, err := s.instance(req.GetContext())
	if err != nil {
		return nil, err
	}
	state := in.stateNow()
	resp := &platformv1.CheckHealthResponse{
		Status:         platformv1.CheckHealthResponse_STATUS_NOT_SERVING,
		LifecycleState: state.proto(),
		DetailsJson:    s.healthDetails(),
	}
	if state == StateReady || state == StateActive {
		resp.Status = platformv1.CheckHealthResponse_STATUS_SERVING
	}
	if hr, ok := in.author.(HealthReporter); ok && state != StateStopped && state != StateFailed {
		hctx := in.callContext(ctx, req.GetContext(), 0, false)
		h, err := safely(in, "health", func() (Health, error) { return hr.Health(hctx), nil })
		if err != nil {
			resp.Status = platformv1.CheckHealthResponse_STATUS_NOT_SERVING
			resp.Message = "the health check failed unexpectedly"
		} else {
			resp.Message = h.Message
			resp.DetailsJson = s.healthDetails(h.Details)
		}
	}
	_, resp.AppliedConfigRevision = in.configSnapshot()
	return resp, nil
}

// ValidateConfig validates a candidate config revision without applying it.
func (s *Server) ValidateConfig(ctx context.Context, req *platformv1.ValidateConfigRequest) (*platformv1.ValidateConfigResponse, error) {
	in, err := s.instance(req.GetContext())
	if err != nil {
		return nil, err
	}
	if err := in.servingConfig(); err != nil {
		return nil, err
	}
	_, current := in.configSnapshot()
	cfg := Config{JSON: req.GetConfigJson(), Revision: req.GetProposedRevision(), CurrentRevision: current}
	resp := &platformv1.ValidateConfigResponse{}
	cv, ok := in.author.(ConfigValidator)
	if !ok {
		return resp, nil
	}
	hctx := in.callContext(ctx, req.GetContext(), 0, false)
	res, err := safely(in, "validate_config", func() (ConfigValidation, error) { return cv.ValidateConfig(hctx, cfg) })
	if err != nil {
		in.log.Error("validate config failed", slog.String("error", err.Error()))
		resp.Error = errorDetail(err, req.GetContext().GetLocale())
		resp.Violations = resp.Error.GetViolations()
		return resp, nil
	}
	resp.Violations = violationsToProto(res.Violations)
	resp.Warnings = violationsToProto(res.Warnings)
	return resp, nil
}

// ApplyConfig applies a config revision. The applied revision is recorded only
// after the plugin accepted it.
func (s *Server) ApplyConfig(ctx context.Context, req *platformv1.ApplyConfigRequest) (*platformv1.ApplyConfigResponse, error) {
	in, err := s.instance(req.GetContext())
	if err != nil {
		return nil, err
	}
	unlock, err := in.lockLife(ctx)
	if err != nil {
		return nil, err
	}
	defer unlock()
	if err := in.servingConfig(); err != nil {
		return nil, err
	}
	_, current := in.configSnapshot()
	applied := req.GetProposedRevision()
	if applied == "" {
		applied = current
	}
	ap, ok := in.author.(ConfigApplier)
	if !ok {
		if !s.manifest.Config.HotApply {
			return nil, status.Error(codes.Unimplemented, "this plugin does not support hot config apply; restart it instead")
		}
		// hot_apply=true without a hook: accept it, handlers read the latest
		// snapshot through InstanceBase.Config.
		in.setConfig(req.GetConfigJson(), applied)
		in.log.Info("config applied", slog.String("config_revision", applied))
		return &platformv1.ApplyConfigResponse{AppliedRevision: applied}, nil
	}
	cfg := Config{JSON: req.GetConfigJson(), Revision: req.GetProposedRevision(), CurrentRevision: current}
	hctx := in.callContext(ctx, req.GetContext(), 0, false)
	if err := safelyRun(in, "apply_config", func() error { return ap.ApplyConfig(hctx, cfg) }); err != nil {
		in.log.Error("apply config failed", slog.String("error", err.Error()))
		return &platformv1.ApplyConfigResponse{Error: errorDetail(err, req.GetContext().GetLocale())}, nil
	}
	in.setConfig(req.GetConfigJson(), applied)
	in.log.Info("config applied", slog.String("config_revision", applied))
	return &platformv1.ApplyConfigResponse{AppliedRevision: applied}, nil
}

// instance resolves RequestContext.instance_id. An unknown or released instance
// is NOT_FOUND; that is a host routing fault, not a domain outcome.
func (s *Server) instance(rc *platformv1.RequestContext) (*instance, error) {
	id := rc.GetInstanceId()
	if id == "" {
		return nil, status.Error(codes.InvalidArgument, "context.instance_id is required")
	}
	s.mu.Lock()
	in := s.instances[id]
	s.mu.Unlock()
	if in == nil {
		return nil, status.Errorf(codes.NotFound, "instance %q", id)
	}
	return in, nil
}

// servingConfig reports whether the instance accepts config changes.
func (in *instance) servingConfig() error {
	switch in.stateNow() {
	case StateInitialized, StateReady, StateActive:
		return nil
	}
	return status.Errorf(codes.FailedPrecondition, "instance %q is %s", in.id, in.stateNow())
}

// setState stores st without a transition check.
func (in *instance) setState(st LifecycleState) {
	in.mu.Lock()
	in.state = st
	in.mu.Unlock()
}

// callContext adds the call metadata for this RPC.
func (in *instance) callContext(ctx context.Context, rc *platformv1.RequestContext, attempt uint32, planning bool) context.Context {
	return withCallInfo(ctx, callInfo{planning: planning, call: Call{
		RequestID:   rc.GetRequestId(),
		OperationID: rc.GetOperationId(),
		TraceID:     rc.GetTraceId(),
		InstanceID:  in.id,
		NodeID:      rc.GetNodeId(),
		Locale:      rc.GetLocale(),
		Actor:       rc.GetActor(),
		Attempt:     attempt,
	}})
}

// graceOf applies the default grace period when the request did not set one.
func (s *Server) graceOf(ms int32) time.Duration {
	if ms > 0 {
		return time.Duration(ms) * time.Millisecond
	}
	return s.grace
}

// healthDetails builds CheckHealthResponse.details_json. The SDK always
// reports GOMEMLIMIT because the runtime cannot (ARCH §6.3); plugin details are
// kept under "plugin".
func (s *Server) healthDetails(plugin ...json.RawMessage) []byte {
	out := map[string]json.RawMessage{}
	mem := map[string]any{
		"gomemlimit_bytes": s.memory.Bytes,
		"gomemlimit_set":   s.memory.Set,
		"memory_max_mb":    s.manifest.Resources.MemoryMaxMB,
	}
	if b, err := json.Marshal(mem); err == nil {
		out["memory"] = b
	}
	if len(plugin) > 0 && len(plugin[0]) > 0 && json.Valid(plugin[0]) {
		out["plugin"] = plugin[0]
	}
	b, err := json.Marshal(out)
	if err != nil {
		return nil
	}
	return b
}

// validateHandlers checks that the registered operations are exactly the
// manifest's operations with the declared modes and plannability. A mismatch
// would make the descriptor promise behaviour the plugin does not have, so it
// fails Initialize.
func validateHandlers(m *manifest.Manifest, ops operations) error {
	declared := make(map[string]manifest.Operation, len(m.Operations))
	for _, op := range m.Operations {
		declared[op.Name] = op
	}
	for name := range ops.invokes {
		op, ok := declared[name]
		if !ok {
			return errorf("invoke handler %q has no manifest operation", name)
		}
		if op.Mode != "invoke" {
			return errorf("operation %q is declared mode %q but an invoke handler is registered", name, op.Mode)
		}
	}
	for name := range ops.jobs {
		op, ok := declared[name]
		if !ok {
			return errorf("job handler %q has no manifest operation", name)
		}
		if op.Mode != "job" {
			return errorf("operation %q is declared mode %q but a job handler is registered", name, op.Mode)
		}
	}
	for name := range ops.plans {
		op, ok := declared[name]
		if !ok {
			return errorf("plan handler %q has no manifest operation", name)
		}
		if !op.EffectivePlannable() {
			return errorf("operation %q has a plan handler but plannable is false", name)
		}
	}
	for _, op := range m.Operations {
		switch op.Mode {
		case "invoke":
			if ops.invokes[op.Name] == nil {
				return errorf("operation %q has no invoke handler", op.Name)
			}
		case "job":
			if ops.jobs[op.Name] == nil {
				return errorf("operation %q has no job handler", op.Name)
			}
		}
		if op.EffectivePlannable() && ops.plans[op.Name] == nil {
			return errorf("plannable operation %q has no plan handler", op.Name)
		}
	}
	return nil
}

// errorf builds a registry-validation error.
func errorf(format string, args ...any) error {
	return fmt.Errorf(format, args...)
}
