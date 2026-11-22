// SPDX-License-Identifier: AGPL-3.0-only

package supervisor

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/qwq-panel/qwq/internal/platform/problem"
	platformv1 "github.com/qwq-panel/qwq/sdk/gen/qwq/platform/v1"
)

// Client is a thin wrapper around platformv1.PluginServiceClient for one plugin
// instance. The host adapts it to operations.Dispatcher; the wrapper owns the
// stream bookkeeping that the ABI requires (ADR-0007 #15):
//
//   - RunJob forwards zero or more progress messages and at most one terminal
//     message (completed = true or error set) to the callback, and returns only
//     after it delivered the outcome or has an error to report.
//   - A stream that ends, breaks or is cancelled without a terminal message is
//     reported as an error, never as success.
//   - Cancel cancels the stream context of the named operation; ABI v1 has no
//     cancellation RPC.
//
// Every call checks that the instance is still the current generation, so a
// client kept across an out-of-band restart fails with PLUGIN_UNAVAILABLE
// instead of talking to a stale process.
type Client struct {
	sup  *Supervisor
	inst *Instance

	mu   sync.Mutex
	jobs map[string]context.CancelFunc
}

func newClient(sup *Supervisor, inst *Instance) *Client {
	return &Client{sup: sup, inst: inst, jobs: make(map[string]context.CancelFunc)}
}

// PluginID returns the plugin id of the instance.
func (c *Client) PluginID() string { return c.inst.PluginID() }

// Generation returns the generation the client is bound to.
func (c *Client) Generation() string { return c.inst.Generation() }

// Owner returns the host-side owner string of the instance.
func (c *Client) Owner() string { return c.inst.Owner() }

// Plan previews an operation without side effects. It rejects requests the
// plugin marks as failed, so the caller never renders a failed plan as valid.
func (c *Client) Plan(ctx context.Context, req *platformv1.PlanOperationRequest) (*platformv1.PlanOperationResponse, error) {
	if req == nil {
		return nil, problem.New(problem.ValidationFailed, "PlanOperation needs a request")
	}
	svc, err := c.service()
	if err != nil {
		return nil, err
	}
	resp, err := svc.PlanOperation(ctx, req)
	if err != nil {
		return nil, c.rpcError("PlanOperation", err)
	}
	if e := resp.GetError(); e != nil {
		return nil, fromErrorDetail(e)
	}
	return resp, nil
}

// Invoke runs a synchronous operation and returns its result and the
// plugin-owned resources it changed. A plugin-reported failure becomes a
// *problem.Error carrying the plugin code, retryability and violations.
func (c *Client) Invoke(ctx context.Context, req *platformv1.InvokeRequest) (*platformv1.InvokeResponse, error) {
	if req == nil {
		return nil, problem.New(problem.ValidationFailed, "Invoke needs a request")
	}
	svc, err := c.service()
	if err != nil {
		return nil, err
	}
	resp, err := svc.Invoke(ctx, req)
	if err != nil {
		return nil, c.rpcError("Invoke", err)
	}
	if e := resp.GetError(); e != nil {
		return nil, fromErrorDetail(e)
	}
	return resp, nil
}

// ServePublicRoute 分发一次经宿主边界过滤后的公开 HTTP 路由请求（ADR-0024）。
func (c *Client) ServePublicRoute(ctx context.Context, req *platformv1.ServePublicRouteRequest) (*platformv1.ServePublicRouteResponse, error) {
	if req == nil {
		return nil, problem.New(problem.ValidationFailed, "ServePublicRoute needs a request")
	}
	svc, err := c.service()
	if err != nil {
		return nil, err
	}
	resp, err := svc.ServePublicRoute(ctx, req)
	if err != nil {
		return nil, c.rpcError("ServePublicRoute", err)
	}
	return resp, nil
}

// RunJob runs a long-running operation and streams its progress to progress.
// progress is called sequentially from one goroutine and sees at most one
// terminal message; a non-nil return aborts the job and is returned unchanged,
// after the plugin stream was cancelled.
//
// A plugin-reported terminal failure is returned as *problem.Error. A stream
// that closes (io.EOF), breaks or is cancelled before a terminal message is an
// error too: the host never treats an interrupted attempt as success.
func (c *Client) RunJob(ctx context.Context, req *platformv1.RunJobRequest, progress func(*platformv1.JobProgress) error) error {
	if req == nil {
		return problem.New(problem.ValidationFailed, "RunJob needs a request")
	}
	if progress == nil {
		return problem.New(problem.ValidationFailed, "RunJob needs a progress callback")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	svc, err := c.service()
	if err != nil {
		return err
	}

	jobCtx, cancel := context.WithCancel(ctx)
	operationID := req.GetContext().GetOperationId()
	if operationID != "" {
		if !c.trackJob(operationID, cancel) {
			cancel()
			return problem.New(problem.ValidationFailed,
				"a job stream for operation %q is already running on plugin %q", operationID, c.PluginID())
		}
		defer c.untrackJob(operationID)
	}
	defer cancel()

	stream, err := svc.RunJob(jobCtx, req)
	if err != nil {
		return c.rpcError("RunJob", err)
	}

	for {
		resp, rerr := stream.Recv()
		if rerr != nil {
			return c.streamEndError(jobCtx, rerr)
		}
		p := resp.GetProgress()
		if p == nil {
			cancel()
			return problem.New(problem.PluginError, "the plugin sent an empty RunJob message")
		}
		if perr := progress(p); perr != nil {
			// Abort the stream so the plugin stops as soon as possible.
			cancel()
			return perr
		}
		if !p.GetCompleted() && p.GetError() == nil {
			continue
		}
		// ABI v1: exactly one terminal message, then the stream ends. Return here
		// instead of waiting for a plugin that forgets to close it, so the caller
		// sees exactly one terminal message.
		if e := p.GetError(); e != nil {
			return fromErrorDetail(e)
		}
		return nil
	}
}

// Cancel cancels the local stream of operationID. Cancellation is asynchronous
// and best effort (ADR-0007 #15: the host cancels the stream context); a job
// that is not streaming here is not an error.
func (c *Client) Cancel(ctx context.Context, operationID string) error {
	if operationID == "" {
		return problem.New(problem.ValidationFailed, "Cancel needs an operation id")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return contextError(err, "cancelling the job")
	}
	c.mu.Lock()
	cancel := c.jobs[operationID]
	c.mu.Unlock()
	if cancel == nil {
		c.sup.logger.Debug("cancel requested for a job that is not streaming",
			"plugin_id", c.PluginID(), "generation", c.Generation(), "operation_id", operationID)
		return nil
	}
	cancel()
	return nil
}

// Lifecycle calls.
//
// The ten RPCs below are the instance lifecycle of ABI v1 (ARCH §6.1). They are
// thin forwarding methods on purpose: the supervisor's Client owns the
// generation check and the error mapping, while the update saga
// (internal/pluginhost/updater) owns the order and the meaning of each step.
// None of them starts, stops or signals the process; systemd and the saga do.

// GetDescriptor returns the plugin descriptor the process advertises.
func (c *Client) GetDescriptor(ctx context.Context, req *platformv1.GetDescriptorRequest) (*platformv1.GetDescriptorResponse, error) {
	if req == nil {
		return nil, problem.New(problem.ValidationFailed, "GetDescriptor needs a request")
	}
	svc, err := c.service()
	if err != nil {
		return nil, err
	}
	resp, err := svc.GetDescriptor(ctx, req)
	if err != nil {
		return nil, c.rpcError("GetDescriptor", err)
	}
	return resp, nil
}

// Initialize creates the host-side instance of the plugin.
func (c *Client) Initialize(ctx context.Context, req *platformv1.InitializeRequest) (*platformv1.InitializeResponse, error) {
	if req == nil {
		return nil, problem.New(problem.ValidationFailed, "Initialize needs a request")
	}
	svc, err := c.service()
	if err != nil {
		return nil, err
	}
	resp, err := svc.Initialize(ctx, req)
	if err != nil {
		return nil, c.rpcError("Initialize", err)
	}
	return resp, nil
}

// Start makes the plugin ready to serve requests without running background
// work; background work only starts with Activate.
func (c *Client) Start(ctx context.Context, req *platformv1.StartRequest) (*platformv1.StartResponse, error) {
	if req == nil {
		return nil, problem.New(problem.ValidationFailed, "Start needs a request")
	}
	svc, err := c.service()
	if err != nil {
		return nil, err
	}
	resp, err := svc.Start(ctx, req)
	if err != nil {
		return nil, c.rpcError("Start", err)
	}
	return resp, nil
}

// Activate starts the plugin's background work. Activate is idempotent per the
// ABI, so recovery may repeat it.
func (c *Client) Activate(ctx context.Context, req *platformv1.ActivateRequest) (*platformv1.ActivateResponse, error) {
	if req == nil {
		return nil, problem.New(problem.ValidationFailed, "Activate needs a request")
	}
	svc, err := c.service()
	if err != nil {
		return nil, err
	}
	resp, err := svc.Activate(ctx, req)
	if err != nil {
		return nil, c.rpcError("Activate", err)
	}
	return resp, nil
}

// Deactivate stops the plugin's background work. It is safe on an instance
// that never activated.
func (c *Client) Deactivate(ctx context.Context, req *platformv1.DeactivateRequest) (*platformv1.DeactivateResponse, error) {
	if req == nil {
		return nil, problem.New(problem.ValidationFailed, "Deactivate needs a request")
	}
	svc, err := c.service()
	if err != nil {
		return nil, err
	}
	resp, err := svc.Deactivate(ctx, req)
	if err != nil {
		return nil, c.rpcError("Deactivate", err)
	}
	return resp, nil
}

// Stop asks the plugin to drain and stop. It does not signal the process:
// systemd owns the cgroup (Stop's caller drives it through UnitManager).
func (c *Client) Stop(ctx context.Context, req *platformv1.StopRequest) (*platformv1.StopResponse, error) {
	if req == nil {
		return nil, problem.New(problem.ValidationFailed, "Stop needs a request")
	}
	svc, err := c.service()
	if err != nil {
		return nil, err
	}
	resp, err := svc.Stop(ctx, req)
	if err != nil {
		return nil, c.rpcError("Stop", err)
	}
	return resp, nil
}

// ReleaseInstance frees the plugin-side instance identity of a stopped
// instance. It never stops the process.
func (c *Client) ReleaseInstance(ctx context.Context, req *platformv1.ReleaseInstanceRequest) (*platformv1.ReleaseInstanceResponse, error) {
	if req == nil {
		return nil, problem.New(problem.ValidationFailed, "ReleaseInstance needs a request")
	}
	svc, err := c.service()
	if err != nil {
		return nil, err
	}
	resp, err := svc.ReleaseInstance(ctx, req)
	if err != nil {
		return nil, c.rpcError("ReleaseInstance", err)
	}
	return resp, nil
}

// CheckHealth performs the plugin's self-check. The caller decides how to treat
// a NOT_SERVING status; a transport failure is PLUGIN_UNAVAILABLE.
func (c *Client) CheckHealth(ctx context.Context, req *platformv1.CheckHealthRequest) (*platformv1.CheckHealthResponse, error) {
	if req == nil {
		return nil, problem.New(problem.ValidationFailed, "CheckHealth needs a request")
	}
	svc, err := c.service()
	if err != nil {
		return nil, err
	}
	resp, err := svc.CheckHealth(ctx, req)
	if err != nil {
		return nil, c.rpcError("CheckHealth", err)
	}
	return resp, nil
}

// ValidateConfig asks the plugin to validate a configuration snapshot without
// applying it. A plugin-reported ErrorDetail keeps the plugin code, violations
// and retryability.
func (c *Client) ValidateConfig(ctx context.Context, req *platformv1.ValidateConfigRequest) (*platformv1.ValidateConfigResponse, error) {
	if req == nil {
		return nil, problem.New(problem.ValidationFailed, "ValidateConfig needs a request")
	}
	svc, err := c.service()
	if err != nil {
		return nil, err
	}
	resp, err := svc.ValidateConfig(ctx, req)
	if err != nil {
		return nil, c.rpcError("ValidateConfig", err)
	}
	if e := resp.GetError(); e != nil {
		return nil, fromErrorDetail(e)
	}
	return resp, nil
}

// ApplyConfig applies a configuration snapshot. The caller checks
// AppliedRevision against the revision it requested; this method only reports
// what the plugin answered.
func (c *Client) ApplyConfig(ctx context.Context, req *platformv1.ApplyConfigRequest) (*platformv1.ApplyConfigResponse, error) {
	if req == nil {
		return nil, problem.New(problem.ValidationFailed, "ApplyConfig needs a request")
	}
	svc, err := c.service()
	if err != nil {
		return nil, err
	}
	resp, err := svc.ApplyConfig(ctx, req)
	if err != nil {
		return nil, c.rpcError("ApplyConfig", err)
	}
	if e := resp.GetError(); e != nil {
		return nil, fromErrorDetail(e)
	}
	return resp, nil
}

// service returns the generated client after checking that the instance is still
// the current generation.
func (c *Client) service() (platformv1.PluginServiceClient, error) {
	if !c.inst.usable() {
		return nil, c.staleError()
	}
	if current := c.sup.current(c.inst.PluginID()); current != c.inst {
		return nil, c.staleError()
	}
	if c.inst.brokenConnection() {
		return nil, problem.New(problem.PluginUnavailable,
			"the connection to plugin %q is broken; call Ensure to attach again", c.PluginID())
	}
	svc := c.inst.pluginService()
	if svc == nil {
		return nil, c.staleError()
	}
	return svc, nil
}

func (c *Client) staleError() *problem.Error {
	return problem.New(problem.PluginUnavailable,
		"plugin %q generation %s is no longer current; call Ensure", c.PluginID(), c.Generation())
}

func (c *Client) trackJob(operationID string, cancel context.CancelFunc) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.jobs[operationID]; ok {
		return false
	}
	if c.jobs == nil {
		c.jobs = make(map[string]context.CancelFunc)
	}
	c.jobs[operationID] = cancel
	return true
}

func (c *Client) untrackJob(operationID string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.jobs, operationID)
}

// streamEndError maps the end of a RunJob stream without a terminal message. A
// cancelled or expired context wins over the transport error, because both the
// ABI and the operations layer classify that case as cancellation/timeout
// (ADR-0007 #15).
func (c *Client) streamEndError(ctx context.Context, err error) error {
	if cerr := ctx.Err(); cerr != nil {
		if errors.Is(cerr, context.DeadlineExceeded) {
			return &problem.Error{Code: problem.Timeout, Detail: "The job did not finish before its deadline.", Cause: cerr}
		}
		return &problem.Error{Code: problem.Unavailable, Detail: "The job was cancelled before the plugin finished.", Cause: cerr}
	}
	if errors.Is(err, io.EOF) {
		return problem.New(problem.PluginUnavailable,
			"plugin %q ended the job stream without a terminal message", c.PluginID())
	}
	return c.rpcError("RunJob", err)
}

// rpcError maps a gRPC error to a host error and records transport failures so
// the next Ensure reattaches instead of reusing a dead connection.
func (c *Client) rpcError(op string, err error) *problem.Error {
	if status.Code(err) == codes.Unavailable {
		c.inst.markTransportFailure(err)
	}
	return rpcStatusError(op, err)
}

// rpcStatusError maps transport and host-side failures to host codes (ADR-0007 #13).
func rpcStatusError(op string, err error) *problem.Error {
	if errors.Is(err, context.DeadlineExceeded) {
		return &problem.Error{Code: problem.Timeout, Detail: "The plugin did not answer " + op + " before its deadline.", Cause: err}
	}
	code := status.Code(err)
	detail := "The plugin failed " + op + "."
	switch code {
	case codes.Unavailable:
		return &problem.Error{Code: problem.PluginUnavailable, Detail: "The plugin did not answer " + op + ".", Cause: err}
	case codes.DeadlineExceeded:
		return &problem.Error{Code: problem.Timeout, Detail: "The plugin did not answer " + op + " before its deadline.", Cause: err}
	case codes.Canceled:
		return &problem.Error{Code: problem.Unavailable, Detail: op + " was cancelled.", Cause: err}
	case codes.Unimplemented:
		return &problem.Error{Code: problem.PluginError, Detail: "The plugin does not implement " + op + ".", Cause: err}
	case codes.PermissionDenied:
		return &problem.Error{Code: problem.PermissionDenied, Detail: "The plugin denied " + op + ".", Cause: err}
	case codes.InvalidArgument, codes.FailedPrecondition:
		return &problem.Error{Code: problem.ValidationFailed, Detail: "The plugin rejected the request of " + op + ".", Cause: err}
	case codes.NotFound:
		return &problem.Error{Code: problem.NotFound, Detail: "The plugin does not know the target of " + op + ".", Cause: err}
	}
	return &problem.Error{Code: problem.PluginError, Detail: detail, Cause: fmt.Errorf("%s: %w", status.Code(err), err)}
}

// fromErrorDetail maps a plugin-reported ErrorDetail (ADR-0007) to a host error,
// keeping the plugin's code, violations and retryability.
func fromErrorDetail(d *platformv1.ErrorDetail) *problem.Error {
	if d == nil {
		return nil
	}
	violations := make([]problem.Violation, 0, len(d.GetViolations()))
	for _, v := range d.GetViolations() {
		violations = append(violations, problem.Violation{
			Pointer: v.GetPointer(),
			Code:    v.GetCode(),
			Message: v.GetMessage(),
		})
	}
	return problem.FromPlugin(d.GetCode(), d.GetMessage(), d.GetRetryable(), violations)
}
