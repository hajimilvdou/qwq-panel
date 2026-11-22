// SPDX-License-Identifier: AGPL-3.0-only

package supervisor

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/qwq-panel/qwq/internal/platform/clock"
	"github.com/qwq-panel/qwq/internal/platform/problem"
	platformv1 "github.com/qwq-panel/qwq/sdk/gen/qwq/platform/v1"
)

func jobRequest(operationID string) *platformv1.RunJobRequest {
	return &platformv1.RunJobRequest{
		Context:   &platformv1.RequestContext{OperationId: operationID, TraceId: "trace"},
		Operation: "apply",
	}
}

func TestPlanAndInvoke(t *testing.T) {
	env := newEnv(t)
	inst := env.ensure(t, "alpha")
	client := inst.Client()
	ctx := context.Background()

	if _, err := client.Plan(ctx, nil); !problem.HasCode(err, problem.ValidationFailed) {
		t.Fatalf("Plan(nil) error = %v, want VALIDATION_FAILED", err)
	}

	env.pluginFor(t, "alpha").setPlan(func(context.Context, *platformv1.PlanOperationRequest) (*platformv1.PlanOperationResponse, error) {
		return &platformv1.PlanOperationResponse{
			Changes:    []*platformv1.PlannedChange{{Subject: "inbounds/0", Description: "add"}},
			Violations: []*platformv1.FieldViolation{{Pointer: "/port", Code: "PORT_IN_USE", Message: "busy"}},
		}, nil
	})
	resp, err := client.Plan(ctx, &platformv1.PlanOperationRequest{Operation: "apply"})
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	if len(resp.GetChanges()) != 1 || len(resp.GetViolations()) != 1 {
		t.Fatalf("plan response = %+v", resp)
	}

	env.pluginFor(t, "alpha").setPlan(func(context.Context, *platformv1.PlanOperationRequest) (*platformv1.PlanOperationResponse, error) {
		return &platformv1.PlanOperationResponse{Error: &platformv1.ErrorDetail{
			Code:       "VALIDATION_FAILED",
			Message:    "invalid payload",
			Violations: []*platformv1.FieldViolation{{Pointer: "/inbounds/0/port", Code: "OUT_OF_RANGE", Message: "bad"}},
		}}, nil
	})
	_, err = client.Plan(ctx, &platformv1.PlanOperationRequest{})
	if !problem.HasCode(err, problem.ValidationFailed) {
		t.Fatalf("plugin error = %v, want VALIDATION_FAILED", err)
	}
	var pe *problem.Error
	if !errors.As(err, &pe) || len(pe.Violations) != 1 || pe.Violations[0].Pointer != "/inbounds/0/port" {
		t.Fatalf("plugin error violations = %+v", pe)
	}

	env.pluginFor(t, "alpha").setPlan(func(context.Context, *platformv1.PlanOperationRequest) (*platformv1.PlanOperationResponse, error) {
		return nil, status.Error(codes.Unimplemented, "no plan")
	})
	if _, err := client.Plan(ctx, &platformv1.PlanOperationRequest{}); !problem.HasCode(err, problem.PluginError) {
		t.Fatalf("unimplemented plan error = %v, want PLUGIN_ERROR", err)
	}

	if _, err := client.Invoke(ctx, nil); !problem.HasCode(err, problem.ValidationFailed) {
		t.Fatalf("Invoke(nil) error = %v, want VALIDATION_FAILED", err)
	}
	env.pluginFor(t, "alpha").setInvoke(func(context.Context, *platformv1.InvokeRequest) (*platformv1.InvokeResponse, error) {
		return &platformv1.InvokeResponse{
			PayloadJson: []byte(`{"ok":true}`),
			Changes:     []*platformv1.ResourceChange{{Subject: "inbounds/0", Revision: "7"}},
		}, nil
	})
	invokeResp, err := client.Invoke(ctx, &platformv1.InvokeRequest{Operation: "apply"})
	if err != nil {
		t.Fatalf("Invoke: %v", err)
	}
	if string(invokeResp.GetPayloadJson()) != `{"ok":true}` || len(invokeResp.GetChanges()) != 1 {
		t.Fatalf("invoke response = %+v", invokeResp)
	}

	env.pluginFor(t, "alpha").setInvoke(func(context.Context, *platformv1.InvokeRequest) (*platformv1.InvokeResponse, error) {
		return &platformv1.InvokeResponse{Error: &platformv1.ErrorDetail{
			Code: "BUSY", Message: "try later", Retryable: true,
		}}, nil
	})
	_, err = client.Invoke(ctx, &platformv1.InvokeRequest{})
	if !problem.HasCode(err, problem.PluginError) {
		t.Fatalf("plugin error = %v, want PLUGIN_ERROR", err)
	}
	var busy *problem.Error
	if !errors.As(err, &busy) || busy.PluginCode != "BUSY" || busy.Retryable == nil || !*busy.Retryable {
		t.Fatalf("plugin error = %+v, want plugin code BUSY and retryable", busy)
	}

	// Codes the host also uses keep their host meaning (ADR-0007).
	env.pluginFor(t, "alpha").setInvoke(func(context.Context, *platformv1.InvokeRequest) (*platformv1.InvokeResponse, error) {
		return &platformv1.InvokeResponse{Error: &platformv1.ErrorDetail{
			Code: "PRECONDITION_FAILED", Message: "revision moved",
		}}, nil
	})
	if _, err := client.Invoke(ctx, &platformv1.InvokeRequest{}); !problem.HasCode(err, problem.PreconditionFailed) {
		t.Fatalf("precondition error = %v, want PRECONDITION_FAILED", err)
	}

	// A transport failure is reported as PLUGIN_UNAVAILABLE and marks the instance
	// broken so the next Ensure reattaches.
	env.pluginFor(t, "alpha").setInvoke(func(context.Context, *platformv1.InvokeRequest) (*platformv1.InvokeResponse, error) {
		return nil, status.Error(codes.Unavailable, "connection lost")
	})
	if _, err := client.Invoke(ctx, &platformv1.InvokeRequest{}); !problem.HasCode(err, problem.PluginUnavailable) {
		t.Fatalf("transport error = %v, want PLUGIN_UNAVAILABLE", err)
	}
	if !inst.brokenConnection() {
		t.Fatal("a transport failure did not mark the instance broken")
	}
}

// TestClientRejectsOversizedPluginResponse pins the receive limit of the
// connection Ensure opens: go-plugin would let a plugin make the host buffer a
// response of up to 2 GiB. A 4 MiB payload, the ABI's largest, still fits
// together with its framing.
func TestClientRejectsOversizedPluginResponse(t *testing.T) {
	env := newEnv(t)
	client := env.ensure(t, "alpha").Client()

	cases := []struct {
		name string
		size int
		want codes.Code
	}{
		{"4 MiB payload", 4 << 20, codes.OK},
		{"5 MiB payload", 5 << 20, codes.ResourceExhausted},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			payload := []byte(`"` + strings.Repeat("a", tc.size-2) + `"`)
			env.pluginFor(t, "alpha").setInvoke(func(context.Context, *platformv1.InvokeRequest) (*platformv1.InvokeResponse, error) {
				return &platformv1.InvokeResponse{PayloadJson: payload}, nil
			})
			resp, err := client.Invoke(context.Background(), &platformv1.InvokeRequest{Operation: "apply"})
			if got := status.Code(err); got != tc.want {
				t.Fatalf("Invoke: host received %d payload bytes, err = %v; want %v",
					len(resp.GetPayloadJson()), err, tc.want)
			}
			if tc.want == codes.OK && len(resp.GetPayloadJson()) != tc.size {
				t.Fatalf("payload = %d bytes, want %d", len(resp.GetPayloadJson()), tc.size)
			}
		})
	}
}

func TestRunJobTerminalSuccess(t *testing.T) {
	env := newEnv(t)
	inst := env.ensure(t, "alpha")
	client := inst.Client()

	env.pluginFor(t, "alpha").setRunJob(func(_ *platformv1.RunJobRequest, stream grpc.ServerStreamingServer[platformv1.RunJobResponse]) error {
		messages := []*platformv1.JobProgress{
			{Percent: 10, Step: "prepare"},
			{Percent: 50, Step: "apply"},
			{Completed: true, Percent: 100, ResultJson: []byte(`{"ok":true}`)},
		}
		for _, m := range messages {
			if err := stream.Send(&platformv1.RunJobResponse{Progress: m}); err != nil {
				return err
			}
		}
		return nil
	})

	var got []*platformv1.JobProgress
	err := client.RunJob(context.Background(), jobRequest("op-ok"), func(p *platformv1.JobProgress) error {
		got = append(got, p)
		return nil
	})
	if err != nil {
		t.Fatalf("RunJob: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("progress messages = %d, want 3", len(got))
	}
	terminals := 0
	for _, p := range got {
		if p.GetCompleted() || p.GetError() != nil {
			terminals++
		}
	}
	if terminals != 1 {
		t.Fatalf("terminal messages = %d, want exactly 1", terminals)
	}
	if !got[2].GetCompleted() || string(got[2].GetResultJson()) != `{"ok":true}` {
		t.Fatalf("terminal message = %+v", got[2])
	}
}

func TestRunJobTerminalError(t *testing.T) {
	env := newEnv(t)
	client := env.ensure(t, "alpha").Client()

	env.pluginFor(t, "alpha").setRunJob(func(_ *platformv1.RunJobRequest, stream grpc.ServerStreamingServer[platformv1.RunJobResponse]) error {
		if err := stream.Send(&platformv1.RunJobResponse{Progress: &platformv1.JobProgress{Percent: 20}}); err != nil {
			return err
		}
		return stream.Send(&platformv1.RunJobResponse{Progress: &platformv1.JobProgress{
			Completed: true,
			Error: &platformv1.ErrorDetail{
				Code:       "VALIDATION_FAILED",
				Message:    "bad step",
				Violations: []*platformv1.FieldViolation{{Pointer: "/steps/1", Code: "BAD", Message: "bad"}},
			},
		}})
	})

	var got []*platformv1.JobProgress
	err := client.RunJob(context.Background(), jobRequest("op-fail"), func(p *platformv1.JobProgress) error {
		got = append(got, p)
		return nil
	})
	if !problem.HasCode(err, problem.ValidationFailed) {
		t.Fatalf("RunJob error = %v, want VALIDATION_FAILED", err)
	}
	if len(got) != 2 || got[1].GetError() == nil {
		t.Fatalf("terminal message was not delivered: %d messages", len(got))
	}
	var pe *problem.Error
	if !errors.As(err, &pe) || len(pe.Violations) != 1 {
		t.Fatalf("plugin error = %+v", pe)
	}
}

func TestRunJobStreamEndsWithoutTerminal(t *testing.T) {
	env := newEnv(t)
	client := env.ensure(t, "alpha").Client()

	env.pluginFor(t, "alpha").setRunJob(func(_ *platformv1.RunJobRequest, stream grpc.ServerStreamingServer[platformv1.RunJobResponse]) error {
		return stream.Send(&platformv1.RunJobResponse{Progress: &platformv1.JobProgress{Percent: 10}})
	})

	var got []*platformv1.JobProgress
	err := client.RunJob(context.Background(), jobRequest("op-eof"), func(p *platformv1.JobProgress) error {
		got = append(got, p)
		return nil
	})
	if !problem.HasCode(err, problem.PluginUnavailable) {
		t.Fatalf("RunJob error = %v, want PLUGIN_UNAVAILABLE", err)
	}
	if len(got) != 1 {
		t.Fatalf("progress messages = %d, want 1 (no terminal message)", len(got))
	}
}

func TestRunJobCancellationMapsToError(t *testing.T) {
	env := newEnv(t)
	client := env.ensure(t, "alpha").Client()

	env.pluginFor(t, "alpha").setRunJob(func(_ *platformv1.RunJobRequest, stream grpc.ServerStreamingServer[platformv1.RunJobResponse]) error {
		if err := stream.Send(&platformv1.RunJobResponse{Progress: &platformv1.JobProgress{Percent: 5}}); err != nil {
			return err
		}
		<-stream.Context().Done()
		return stream.Context().Err()
	})

	ctx, cancel := context.WithCancel(context.Background())
	var got []*platformv1.JobProgress
	err := client.RunJob(ctx, jobRequest("op-cancel-ctx"), func(p *platformv1.JobProgress) error {
		got = append(got, p)
		cancel() // the caller cancels after the first progress report
		return nil
	})
	if err == nil {
		t.Fatal("RunJob returned success for a cancelled stream")
	}
	if !problem.HasCode(err, problem.Unavailable) && !problem.HasCode(err, problem.Timeout) {
		t.Fatalf("cancellation error = %v, want UNAVAILABLE or TIMEOUT", err)
	}
	if len(got) != 1 {
		t.Fatalf("progress messages = %d, want 1", len(got))
	}
}

func TestRunJobCancelStopsTheStream(t *testing.T) {
	env := newEnv(t)
	client := env.ensure(t, "alpha").Client()

	started := make(chan struct{})
	env.pluginFor(t, "alpha").setRunJob(func(_ *platformv1.RunJobRequest, stream grpc.ServerStreamingServer[platformv1.RunJobResponse]) error {
		if err := stream.Send(&platformv1.RunJobResponse{Progress: &platformv1.JobProgress{Percent: 5}}); err != nil {
			return err
		}
		close(started)
		<-stream.Context().Done()
		return stream.Context().Err()
	})

	cancelErr := make(chan error, 1)
	go func() {
		<-started
		cancelErr <- client.Cancel(context.Background(), "op-cancel-rpc")
	}()
	err := client.RunJob(context.Background(), jobRequest("op-cancel-rpc"), func(*platformv1.JobProgress) error { return nil })
	if err == nil {
		t.Fatal("RunJob returned success after Cancel")
	}
	if cerr := <-cancelErr; cerr != nil {
		t.Fatalf("Cancel: %v", cerr)
	}
	if err := client.Cancel(context.Background(), ""); !problem.HasCode(err, problem.ValidationFailed) {
		t.Fatalf("Cancel(empty) error = %v, want VALIDATION_FAILED", err)
	}
	if err := client.Cancel(context.Background(), "op-not-running"); err != nil {
		t.Fatalf("Cancel of an idle operation = %v, want nil", err)
	}
}

func TestRunJobProgressErrorAbortsTheJob(t *testing.T) {
	env := newEnv(t)
	client := env.ensure(t, "alpha").Client()

	sentinel := errors.New("host aborted the job")
	sawCancel := make(chan struct{})
	env.pluginFor(t, "alpha").setRunJob(func(_ *platformv1.RunJobRequest, stream grpc.ServerStreamingServer[platformv1.RunJobResponse]) error {
		if err := stream.Send(&platformv1.RunJobResponse{Progress: &platformv1.JobProgress{Percent: 5}}); err != nil {
			return err
		}
		<-stream.Context().Done()
		close(sawCancel)
		return stream.Context().Err()
	})

	err := client.RunJob(context.Background(), jobRequest("op-abort"), func(*platformv1.JobProgress) error {
		return sentinel
	})
	if !errors.Is(err, sentinel) {
		t.Fatalf("RunJob error = %v, want the callback error", err)
	}
	select {
	case <-sawCancel:
	case <-time.After(10 * time.Second):
		t.Fatal("the plugin stream was not cancelled after the callback failed")
	}
}

func TestRunJobRejectsDuplicateOperation(t *testing.T) {
	env := newEnv(t)
	client := env.ensure(t, "alpha").Client()

	started := make(chan struct{})
	env.pluginFor(t, "alpha").setRunJob(func(_ *platformv1.RunJobRequest, stream grpc.ServerStreamingServer[platformv1.RunJobResponse]) error {
		if err := stream.Send(&platformv1.RunJobResponse{Progress: &platformv1.JobProgress{Percent: 5}}); err != nil {
			return err
		}
		close(started)
		<-stream.Context().Done()
		return stream.Context().Err()
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	firstDone := make(chan error, 1)
	go func() {
		firstDone <- client.RunJob(ctx, jobRequest("op-dup"), func(*platformv1.JobProgress) error { return nil })
	}()
	<-started

	if err := client.RunJob(context.Background(), jobRequest("op-dup"), func(*platformv1.JobProgress) error { return nil }); !problem.HasCode(err, problem.ValidationFailed) {
		t.Fatalf("second RunJob error = %v, want VALIDATION_FAILED", err)
	}
	if err := client.Cancel(context.Background(), "op-dup"); err != nil {
		t.Fatalf("Cancel: %v", err)
	}
	select {
	case <-firstDone:
	case <-time.After(10 * time.Second):
		t.Fatal("the first RunJob did not return after Cancel")
	}
}

func TestRunJobStaleClient(t *testing.T) {
	env := newEnv(t)
	first := env.ensure(t, "alpha")
	client := first.Client()

	env.restartOutOfBand("alpha", 4242, time.Unix(1700000300, 0).UTC())
	env.ensure(t, "alpha")

	called := false
	err := client.RunJob(context.Background(), jobRequest("op-stale"), func(*platformv1.JobProgress) error {
		called = true
		return nil
	})
	if !problem.HasCode(err, problem.PluginUnavailable) {
		t.Fatalf("stale RunJob error = %v, want PLUGIN_UNAVAILABLE", err)
	}
	if called {
		t.Fatal("the callback of a stale client was called")
	}
}

// --- lifecycle RPCs ---------------------------------------------------------

// lifecyclePlugin is an in-process PluginService whose ten lifecycle RPCs are
// scripted per test. It is separate from testPlugin so this file owns the
// lifecycle fixtures without changing the shared helpers.
type lifecyclePlugin struct {
	platformv1.UnimplementedPluginServiceServer

	mu         sync.Mutex
	calls      []string
	requests   map[string]any
	err        error
	descriptor *platformv1.PluginDescriptor
	health     *platformv1.CheckHealthResponse
	validate   *platformv1.ValidateConfigResponse
	apply      *platformv1.ApplyConfigResponse
}

// record stores one call and returns the error the test armed.
func (p *lifecyclePlugin) record(name string, req any) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.calls = append(p.calls, name)
	if p.requests == nil {
		p.requests = make(map[string]any)
	}
	p.requests[name] = req
	return p.err
}

func (p *lifecyclePlugin) setErr(err error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.err = err
}

func (p *lifecyclePlugin) setHealth(h *platformv1.CheckHealthResponse) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.health = h
}

func (p *lifecyclePlugin) setValidate(v *platformv1.ValidateConfigResponse) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.validate = v
}

func (p *lifecyclePlugin) setApply(a *platformv1.ApplyConfigResponse) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.apply = a
}

func (p *lifecyclePlugin) callNames() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.calls...)
}

func (p *lifecyclePlugin) request(name string) any {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.requests[name]
}

func (p *lifecyclePlugin) GetDescriptor(ctx context.Context, req *platformv1.GetDescriptorRequest) (*platformv1.GetDescriptorResponse, error) {
	if err := p.record("GetDescriptor", req); err != nil {
		return nil, err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return &platformv1.GetDescriptorResponse{Descriptor_: p.descriptor}, nil
}

func (p *lifecyclePlugin) Initialize(ctx context.Context, req *platformv1.InitializeRequest) (*platformv1.InitializeResponse, error) {
	if err := p.record("Initialize", req); err != nil {
		return nil, err
	}
	return &platformv1.InitializeResponse{StateSchemaVersion: "2"}, nil
}

func (p *lifecyclePlugin) Start(ctx context.Context, req *platformv1.StartRequest) (*platformv1.StartResponse, error) {
	if err := p.record("Start", req); err != nil {
		return nil, err
	}
	return &platformv1.StartResponse{}, nil
}

func (p *lifecyclePlugin) Activate(ctx context.Context, req *platformv1.ActivateRequest) (*platformv1.ActivateResponse, error) {
	if err := p.record("Activate", req); err != nil {
		return nil, err
	}
	return &platformv1.ActivateResponse{}, nil
}

func (p *lifecyclePlugin) Deactivate(ctx context.Context, req *platformv1.DeactivateRequest) (*platformv1.DeactivateResponse, error) {
	if err := p.record("Deactivate", req); err != nil {
		return nil, err
	}
	return &platformv1.DeactivateResponse{}, nil
}

func (p *lifecyclePlugin) Stop(ctx context.Context, req *platformv1.StopRequest) (*platformv1.StopResponse, error) {
	if err := p.record("Stop", req); err != nil {
		return nil, err
	}
	return &platformv1.StopResponse{Drained: true}, nil
}

func (p *lifecyclePlugin) ReleaseInstance(ctx context.Context, req *platformv1.ReleaseInstanceRequest) (*platformv1.ReleaseInstanceResponse, error) {
	if err := p.record("ReleaseInstance", req); err != nil {
		return nil, err
	}
	return &platformv1.ReleaseInstanceResponse{}, nil
}

func (p *lifecyclePlugin) CheckHealth(ctx context.Context, req *platformv1.CheckHealthRequest) (*platformv1.CheckHealthResponse, error) {
	if err := p.record("CheckHealth", req); err != nil {
		return nil, err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.health == nil {
		return &platformv1.CheckHealthResponse{}, nil
	}
	return p.health, nil
}

func (p *lifecyclePlugin) ValidateConfig(ctx context.Context, req *platformv1.ValidateConfigRequest) (*platformv1.ValidateConfigResponse, error) {
	if err := p.record("ValidateConfig", req); err != nil {
		return nil, err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.validate == nil {
		return &platformv1.ValidateConfigResponse{}, nil
	}
	return p.validate, nil
}

func (p *lifecyclePlugin) ApplyConfig(ctx context.Context, req *platformv1.ApplyConfigRequest) (*platformv1.ApplyConfigResponse, error) {
	if err := p.record("ApplyConfig", req); err != nil {
		return nil, err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.apply == nil {
		return &platformv1.ApplyConfigResponse{}, nil
	}
	return p.apply, nil
}

// lifecycleEnv is a supervisor Client bound to an in-process lifecycle server.
// The supervisor is not started and Ensure is never called: the instance is
// registered directly, which is what Ensure would do after a successful attach.
type lifecycleEnv struct {
	client *Client
	plugin *lifecyclePlugin
	sup    *Supervisor
	inst   *Instance
	server *grpc.Server
}

func newLifecycleEnv(t *testing.T) *lifecycleEnv {
	t.Helper()
	base := shortTempDir(t)
	runDir := filepath.Join(base, "run")
	socket := SocketPath(runDir, "beta")
	if err := os.MkdirAll(filepath.Dir(socket), 0o700); err != nil {
		t.Fatalf("mkdir socket dir: %v", err)
	}
	ln, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatalf("listen %s: %v", socket, err)
	}
	fake := &lifecyclePlugin{}
	srv := grpc.NewServer()
	platformv1.RegisterPluginServiceServer(srv, fake)
	go func() { _ = srv.Serve(ln) }()

	sup, err := New(Options{
		Units: &fakeUnits{},
		Host:  &fakeHost{},
		PluginDir: func(pluginID string) (string, error) {
			return filepath.Join(base, "plugins", pluginID), nil
		},
		Clock:          clock.NewFake(time.Unix(1700000000, 0).UTC()),
		Logger:         slog.New(slog.DiscardHandler),
		RunDir:         runDir,
		ConnectTimeout: 5 * time.Second,
	})
	if err != nil {
		srv.Stop()
		t.Fatalf("New: %v", err)
	}

	connection, err := OpenPluginConnection(t.Context(), socket, 5*time.Second)
	if err != nil {
		srv.Stop()
		sup.Close()
		t.Fatalf("reattach: %v", err)
	}
	state := UnitState{
		MainPID:      os.Getpid(),
		ActiveState:  "active",
		SubState:     "running",
		ControlGroup: "/system.slice/qwq-plugin@beta.service",
		StartTime:    time.Unix(1700000000, 0).UTC(),
	}
	inst := newInstance(sup, "beta", generation(UnitName("beta"), state.MainPID, state.StartTime),
		state, filepath.Join(base, "plugins", "beta"), Limits{})
	inst.attach(connection, func() {}, nil)
	sup.mu.Lock()
	sup.instances["beta"] = inst
	sup.mu.Unlock()

	t.Cleanup(func() {
		srv.Stop()
		sup.Close()
	})
	return &lifecycleEnv{client: inst.Client(), plugin: fake, sup: sup, inst: inst, server: srv}
}

func TestClientLifecycleForwarding(t *testing.T) {
	env := newLifecycleEnv(t)
	client := env.client
	ctx := context.Background()
	reqCtx := &platformv1.RequestContext{OperationId: "op-1", TraceId: "trace-1"}

	for name, call := range map[string]func(context.Context) error{
		"GetDescriptor": func(ctx context.Context) error {
			_, err := client.GetDescriptor(ctx, nil)
			return err
		},
		"Initialize": func(ctx context.Context) error {
			_, err := client.Initialize(ctx, nil)
			return err
		},
		"Start": func(ctx context.Context) error {
			_, err := client.Start(ctx, nil)
			return err
		},
		"Activate": func(ctx context.Context) error {
			_, err := client.Activate(ctx, nil)
			return err
		},
		"Deactivate": func(ctx context.Context) error {
			_, err := client.Deactivate(ctx, nil)
			return err
		},
		"Stop": func(ctx context.Context) error {
			_, err := client.Stop(ctx, nil)
			return err
		},
		"ReleaseInstance": func(ctx context.Context) error {
			_, err := client.ReleaseInstance(ctx, nil)
			return err
		},
		"CheckHealth": func(ctx context.Context) error {
			_, err := client.CheckHealth(ctx, nil)
			return err
		},
		"ValidateConfig": func(ctx context.Context) error {
			_, err := client.ValidateConfig(ctx, nil)
			return err
		},
		"ApplyConfig": func(ctx context.Context) error {
			_, err := client.ApplyConfig(ctx, nil)
			return err
		},
	} {
		if err := call(ctx); !problem.HasCode(err, problem.ValidationFailed) {
			t.Errorf("%s(nil) error = %v, want VALIDATION_FAILED", name, err)
		}
	}

	descriptor := &platformv1.PluginDescriptor{PluginId: "beta", PluginVersion: "1.2.3"}
	env.plugin.mu.Lock()
	env.plugin.descriptor = descriptor
	env.plugin.mu.Unlock()
	resp, err := client.GetDescriptor(ctx, &platformv1.GetDescriptorRequest{})
	if err != nil {
		t.Fatalf("GetDescriptor: %v", err)
	}
	if resp.GetDescriptor_().GetPluginVersion() != "1.2.3" {
		t.Fatalf("descriptor = %+v", resp.GetDescriptor_())
	}

	if _, err := client.Initialize(ctx, &platformv1.InitializeRequest{
		Context:            reqCtx,
		InstanceHandle:     "handle-1",
		DataDir:            "/var/lib/qwq/plugin-data/beta",
		ConfigJson:         []byte(`{"port":8080}`),
		ConfigRevision:     "3",
		HostAbiMinor:       7,
		StateSchemaVersion: "2",
	}); err != nil {
		t.Fatalf("Initialize: %v", err)
	}
	initReq := env.plugin.request("Initialize").(*platformv1.InitializeRequest)
	if initReq.GetInstanceHandle() != "handle-1" || initReq.GetHostAbiMinor() != 7 ||
		initReq.GetConfigRevision() != "3" || string(initReq.GetConfigJson()) != `{"port":8080}` {
		t.Fatalf("Initialize request was not forwarded: %+v", initReq)
	}

	if _, err := client.Start(ctx, &platformv1.StartRequest{Context: reqCtx}); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if _, err := client.Activate(ctx, &platformv1.ActivateRequest{Context: reqCtx}); err != nil {
		t.Fatalf("Activate: %v", err)
	}
	if _, err := client.Deactivate(ctx, &platformv1.DeactivateRequest{Context: reqCtx, GracePeriodMs: 250}); err != nil {
		t.Fatalf("Deactivate: %v", err)
	}
	deactivateReq := env.plugin.request("Deactivate").(*platformv1.DeactivateRequest)
	if deactivateReq.GetGracePeriodMs() != 250 {
		t.Fatalf("Deactivate grace = %d, want 250", deactivateReq.GetGracePeriodMs())
	}
	stopResp, err := client.Stop(ctx, &platformv1.StopRequest{Context: reqCtx, Drain: true, GracePeriodMs: 5000})
	if err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if !stopResp.GetDrained() {
		t.Fatalf("Stop response = %+v, want drained", stopResp)
	}
	stopReq := env.plugin.request("Stop").(*platformv1.StopRequest)
	if !stopReq.GetDrain() || stopReq.GetGracePeriodMs() != 5000 {
		t.Fatalf("Stop request was not forwarded: %+v", stopReq)
	}
	if _, err := client.ReleaseInstance(ctx, &platformv1.ReleaseInstanceRequest{Context: reqCtx}); err != nil {
		t.Fatalf("ReleaseInstance: %v", err)
	}

	env.plugin.setHealth(&platformv1.CheckHealthResponse{
		Status:         platformv1.CheckHealthResponse_STATUS_SERVING,
		LifecycleState: platformv1.LifecycleState_LIFECYCLE_STATE_ACTIVE,
		Message:        "ok",
	})
	health, err := client.CheckHealth(ctx, &platformv1.CheckHealthRequest{Context: reqCtx})
	if err != nil {
		t.Fatalf("CheckHealth: %v", err)
	}
	if health.GetStatus() != platformv1.CheckHealthResponse_STATUS_SERVING || health.GetMessage() != "ok" {
		t.Fatalf("health = %+v", health)
	}

	env.plugin.setValidate(&platformv1.ValidateConfigResponse{
		Violations: []*platformv1.FieldViolation{{Pointer: "/port", Code: "OUT_OF_RANGE", Message: "bad"}},
	})
	validate, err := client.ValidateConfig(ctx, &platformv1.ValidateConfigRequest{
		Context: reqCtx, ConfigJson: []byte(`{"port":1}`),
		ProposedRevision: "4", CurrentRevision: "3",
	})
	if err != nil {
		t.Fatalf("ValidateConfig: %v", err)
	}
	if len(validate.GetViolations()) != 1 {
		t.Fatalf("validate = %+v", validate)
	}
	validateReq := env.plugin.request("ValidateConfig").(*platformv1.ValidateConfigRequest)
	if validateReq.GetProposedRevision() != "4" || validateReq.GetCurrentRevision() != "3" {
		t.Fatalf("ValidateConfig request was not forwarded: %+v", validateReq)
	}

	env.plugin.setApply(&platformv1.ApplyConfigResponse{AppliedRevision: "4"})
	apply, err := client.ApplyConfig(ctx, &platformv1.ApplyConfigRequest{
		Context: reqCtx, ConfigJson: []byte(`{"port":1}`),
		ProposedRevision: "4", CurrentRevision: "3",
	})
	if err != nil {
		t.Fatalf("ApplyConfig: %v", err)
	}
	if apply.GetAppliedRevision() != "4" {
		t.Fatalf("apply = %+v", apply)
	}

	if got := len(env.plugin.callNames()); got != 10 {
		t.Fatalf("lifecycle calls = %d, want 10: %v", got, env.plugin.callNames())
	}
}

func TestClientLifecyclePluginErrors(t *testing.T) {
	env := newLifecycleEnv(t)
	ctx := context.Background()

	env.plugin.setValidate(&platformv1.ValidateConfigResponse{Error: &platformv1.ErrorDetail{
		Code:       "VALIDATION_FAILED",
		Message:    "invalid port",
		Violations: []*platformv1.FieldViolation{{Pointer: "/port", Code: "BAD", Message: "bad"}},
	}})
	_, err := env.client.ValidateConfig(ctx, &platformv1.ValidateConfigRequest{})
	if !problem.HasCode(err, problem.ValidationFailed) {
		t.Fatalf("ValidateConfig error = %v, want VALIDATION_FAILED", err)
	}
	var pe *problem.Error
	if !errors.As(err, &pe) || len(pe.Violations) != 1 {
		t.Fatalf("ValidateConfig plugin error = %+v", pe)
	}

	env.plugin.setApply(&platformv1.ApplyConfigResponse{Error: &platformv1.ErrorDetail{
		Code: "BUSY", Message: "try later", Retryable: true,
	}})
	_, err = env.client.ApplyConfig(ctx, &platformv1.ApplyConfigRequest{})
	if !problem.HasCode(err, problem.PluginError) {
		t.Fatalf("ApplyConfig error = %v, want PLUGIN_ERROR", err)
	}

	env.plugin.setErr(status.Error(codes.Unimplemented, "not implemented"))
	if _, err := env.client.Activate(ctx, &platformv1.ActivateRequest{}); !problem.HasCode(err, problem.PluginError) {
		t.Fatalf("unimplemented Activate error = %v, want PLUGIN_ERROR", err)
	}
}

func TestClientLifecycleStaleGeneration(t *testing.T) {
	env := newLifecycleEnv(t)
	env.sup.mu.Lock()
	delete(env.sup.instances, "beta")
	env.sup.mu.Unlock()

	_, err := env.client.CheckHealth(context.Background(), &platformv1.CheckHealthRequest{})
	if !problem.HasCode(err, problem.PluginUnavailable) {
		t.Fatalf("stale CheckHealth error = %v, want PLUGIN_UNAVAILABLE", err)
	}
	if got := len(env.plugin.callNames()); got != 0 {
		t.Fatalf("a stale client reached the plugin: %v", env.plugin.callNames())
	}
}

func TestClientLifecycleDisconnect(t *testing.T) {
	env := newLifecycleEnv(t)
	env.server.Stop()

	_, err := env.client.Start(context.Background(), &platformv1.StartRequest{})
	if !problem.HasCode(err, problem.PluginUnavailable) {
		t.Fatalf("Start after disconnect = %v, want PLUGIN_UNAVAILABLE", err)
	}
	if !env.inst.brokenConnection() {
		t.Fatal("a transport failure did not mark the instance broken")
	}
}
