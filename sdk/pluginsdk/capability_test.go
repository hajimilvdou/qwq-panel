// SPDX-License-Identifier: Apache-2.0

package pluginsdk

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	metricsv1 "github.com/qwq-panel/qwq/sdk/gen/qwq/capability/metrics/v1"
	platformv1 "github.com/qwq-panel/qwq/sdk/gen/qwq/platform/v1"
)

// fakeMetrics is a MetricsService served on the fake host channel; it records
// the HostCallContext of every call (ADR-0019 decision 1, ADR-0020).
type fakeMetrics struct {
	metricsv1.UnimplementedMetricsServiceServer
	mu       sync.Mutex
	calls    []*platformv1.HostCallContext
	snapshot *metricsv1.MetricsSnapshot
}

func (f *fakeMetrics) ReadMetrics(_ context.Context, req *metricsv1.ReadMetricsRequest) (*metricsv1.ReadMetricsResponse, error) {
	f.mu.Lock()
	f.calls = append(f.calls, req.GetContext())
	f.mu.Unlock()
	if req.GetContext().GetInstanceHandle() == "" {
		return nil, status.Error(codes.Unauthenticated, "missing instance_handle")
	}
	return &metricsv1.ReadMetricsResponse{Snapshot: f.snapshot}, nil
}

func (f *fakeMetrics) callsSnapshot() []*platformv1.HostCallContext {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]*platformv1.HostCallContext(nil), f.calls...)
}

// capPlugin exercises Host.Conn and Host.CapabilityContext through a generated
// capability client, the way a real plugin does (ADR-0019 decision 1).
type capPlugin struct {
	mu      sync.Mutex
	inst    *capInstance
	planErr error
}

func (p *capPlugin) NewInstance(_ context.Context, info InstanceInfo) (Instance, error) {
	inst := &capInstance{InstanceBase: NewInstanceBase(info), p: p}
	HandleInvoke(inst, "test.cap.read", inst.read)
	HandleInvoke(inst, "test.cap.plan", inst.echoPlan)
	HandlePlan(inst, "test.cap.plan", inst.plan)
	p.mu.Lock()
	p.inst = inst
	p.mu.Unlock()
	return inst, nil
}

func (p *capPlugin) setPlanErr(err error) {
	p.mu.Lock()
	p.planErr = err
	p.mu.Unlock()
}

func (p *capPlugin) planErrNow() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.planErr
}

type capInstance struct {
	*InstanceBase
	p *capPlugin
}

// read calls ReadMetrics on the host conn with a CapabilityContext.
func (i *capInstance) read(ctx context.Context, _ struct{}) (map[string]any, error) {
	hc, err := i.Host().CapabilityContext(ctx)
	if err != nil {
		return nil, err
	}
	resp, err := metricsv1.NewMetricsServiceClient(i.Host().Conn()).ReadMetrics(ctx,
		&metricsv1.ReadMetricsRequest{Context: hc})
	if err != nil {
		return nil, err
	}
	return map[string]any{"uptime": resp.GetSnapshot().GetUptimeSeconds()}, nil
}

func (i *capInstance) echoPlan(context.Context, struct{}) (struct{}, error) {
	return struct{}{}, nil
}

// plan probes CapabilityContext while planning; it must be refused.
func (i *capInstance) plan(ctx context.Context, _ struct{}) (Plan, error) {
	_, err := i.Host().CapabilityContext(ctx)
	i.p.setPlanErr(err)
	return Plan{}, nil
}

var capOps = []opSpec{
	{Name: "test.cap.read", Mode: "invoke", Effect: "read"},
	{Name: "test.cap.plan", Mode: "invoke", Effect: "write", Plannable: true},
}

var capCaps = append(append([]capSpec(nil), defaultCaps...), capSpec{"metrics.read", "self"})

// newCapEnv serves the fake host channel with both the Host services and the
// fake MetricsService, then serves capPlugin against it.
func newCapEnv(t *testing.T, p *capPlugin, fm *fakeMetrics) *testEnv {
	t.Helper()
	host := newFakeHost()
	hostConn := serveGRPC(t, func(s *grpc.Server) {
		(&hostServices{h: host}).register(s)
		metricsv1.RegisterMetricsServiceServer(s, fm)
	})
	logs := &bytes.Buffer{}
	logger := slog.New(slog.NewJSONHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	env := &testEnv{t: t, host: host, logs: logs}
	env.client = platformv1.NewPluginServiceClient(serveGRPC(t, func(s *grpc.Server) {
		var err error
		env.server, err = Serve(t.Context(), Options{
			Plugin: p, Manifest: fixtureManifest(0, capOps, capCaps), Registrar: s, Host: hostConn, Logger: logger,
			DefaultGracePeriod: time.Second, ReleaseGracePeriod: time.Second,
		})
		if err != nil {
			t.Fatalf("Serve: %v", err)
		}
	}))
	t.Cleanup(func() { env.server.Close() })
	return env
}

func TestCapabilityCallOverConn(t *testing.T) {
	fm := &fakeMetrics{snapshot: &metricsv1.MetricsSnapshot{UptimeSeconds: 4242}}
	p := &capPlugin{}
	env := newCapEnv(t, p, fm)
	env.active("a", nil)

	resp := invokeOp(t, env, "a", "op-cap", "en", "test.cap.read", []byte(`{}`))
	if resp.GetError() != nil {
		t.Fatalf("response = %v", resp.GetError())
	}
	var out struct {
		Uptime uint64 `json:"uptime"`
	}
	if err := unmarshalJSON(resp.GetPayloadJson(), &out); err != nil {
		t.Fatal(err)
	}
	if out.Uptime != 4242 {
		t.Fatalf("uptime = %d, want 4242", out.Uptime)
	}
	calls := fm.callsSnapshot()
	if len(calls) != 1 {
		t.Fatalf("%d ReadMetrics calls", len(calls))
	}
	c := calls[0]
	if c.GetInstanceHandle() != handleFor("a") || c.GetOperationId() != "op-cap" || c.GetTraceId() != "trace-op-cap" {
		t.Fatalf("HostCallContext = %+v", c)
	}
}

func TestCapabilityContextRefusedWhilePlanning(t *testing.T) {
	fm := &fakeMetrics{snapshot: &metricsv1.MetricsSnapshot{}}
	p := &capPlugin{}
	env := newCapEnv(t, p, fm)
	env.active("a", nil)

	resp, err := env.client.PlanOperation(testContext(t), &platformv1.PlanOperationRequest{
		Context: operationContext("a", "op-cap-plan", "en"), Operation: "test.cap.plan", ApiVersion: "v1",
		PayloadJson: []byte(`{}`),
	})
	if err != nil || resp.GetError() != nil {
		t.Fatalf("PlanOperation: %v %v", err, resp.GetError())
	}
	if planErr := p.planErrNow(); CodeOf(planErr) != "PLAN_SIDE_EFFECT" {
		t.Fatalf("plan-time CapabilityContext error = %v", planErr)
	}
	if n := len(fm.callsSnapshot()); n != 0 {
		t.Fatalf("the host saw %d ReadMetrics calls during planning", n)
	}
}

func TestCapabilityContextOutsideOperation(t *testing.T) {
	fm := &fakeMetrics{snapshot: &metricsv1.MetricsSnapshot{}}
	p := &capPlugin{}
	env := newCapEnv(t, p, fm)
	env.active("a", nil)

	p.mu.Lock()
	inst := p.inst
	p.mu.Unlock()
	host := inst.Host()
	if host.Conn() == nil || host.Conn() != host.Conn() {
		t.Fatalf("Conn = %v", host.Conn())
	}
	hc, err := host.CapabilityContext(t.Context())
	if err != nil {
		t.Fatalf("CapabilityContext: %v", err)
	}
	if hc.GetInstanceHandle() != handleFor("a") || hc.GetOperationId() != "" || hc.GetTraceId() != "" {
		t.Fatalf("HostCallContext = %+v", hc)
	}
}

func TestCapabilityNoHost(t *testing.T) {
	var noHost Host
	if noHost.Conn() != nil {
		t.Fatalf("Conn without a host = %v", noHost.Conn())
	}
	_, err := noHost.CapabilityContext(t.Context())
	if !errors.Is(err, ErrNoHost) {
		t.Fatalf("no-host error = %v", err)
	}
}

func TestCapabilityContextReadOnlyWhilePlanning(t *testing.T) {
	fm := &fakeMetrics{snapshot: &metricsv1.MetricsSnapshot{}}
	p := &capPlugin{}
	env := newCapEnv(t, p, fm)
	env.active("a", nil)
	p.mu.Lock()
	inst := p.inst
	p.mu.Unlock()
	ctx := inst.core.callContext(t.Context(), operationContext("a", "op-plan", "zh-CN"), 1, true)
	read, err := inst.Host().CapabilityContextReadOnly(ctx)
	if err != nil || read.GetOperationId() != "op-plan" || read.GetInstanceHandle() != handleFor("a") {
		t.Fatalf("规划阶段不能构造只读能力上下文：%v", err)
	}
	if _, err := inst.Host().CapabilityContext(ctx); CodeOf(err) != "PLAN_SIDE_EFFECT" {
		t.Fatal("只读入口放宽了原写入口")
	}
	var noHost Host
	if _, err := noHost.CapabilityContextReadOnly(t.Context()); !errors.Is(err, ErrNoHost) {
		t.Fatal("缺少宿主连接时未拒绝")
	}
}
