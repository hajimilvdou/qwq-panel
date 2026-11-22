// SPDX-License-Identifier: AGPL-3.0-only

package supervisor

import (
	"context"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc"

	"github.com/qwq-panel/qwq/internal/platform/clock"
	platformv1 "github.com/qwq-panel/qwq/sdk/gen/qwq/platform/v1"
)

// shortTempDir returns a short temporary directory. Unix socket paths are limited
// to 108 bytes on Linux and t.TempDir embeds the test name, which would make the
// socket path too long for the longer test names.
func shortTempDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "qwqsup-")
	if err != nil {
		t.Fatalf("temp dir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

// fakeUnits is a UnitManager that keeps one unit state in memory. Start installs
// a live-looking main process (the test process itself); connection tests keep
// it alive so process exit cannot hide a leaked observer.
type fakeUnits struct {
	mu         sync.Mutex
	state      UnitState
	startState UnitState
	starts     int
	stops      int
	kills      int
	showErr    error
	startErr   error
	stopErr    error
	killErr    error
}

func (f *fakeUnits) Start(context.Context, string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.startErr != nil {
		return f.startErr
	}
	f.starts++
	if f.state.MainPID == 0 {
		if f.startState.MainPID != 0 {
			f.state = f.startState
		} else {
			f.state = UnitState{
				MainPID:      os.Getpid(),
				ActiveState:  "active",
				SubState:     "running",
				ControlGroup: "/system.slice/qwq-plugin@test.service",
				StartTime:    time.Unix(1700000000, 0).UTC(),
			}
		}
	}
	return nil
}

func (f *fakeUnits) Stop(context.Context, string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.stopErr != nil {
		return f.stopErr
	}
	f.stops++
	f.state = UnitState{}
	return nil
}

func (f *fakeUnits) Kill(context.Context, string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.killErr != nil {
		return f.killErr
	}
	f.kills++
	f.state = UnitState{}
	return nil
}

func (f *fakeUnits) Show(context.Context, string) (UnitState, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.showErr != nil {
		return UnitState{}, f.showErr
	}
	return f.state, nil
}

func (f *fakeUnits) setState(state UnitState) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.state = state
}

func (f *fakeUnits) setErrors(show, start, stop, kill error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.showErr, f.startErr, f.stopErr, f.killErr = show, start, stop, kill
}

func (f *fakeUnits) counts() (starts, stops, kills int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.starts, f.stops, f.kills
}

// fakeHost counts Serve and stop calls and can fail Serve on demand.
type fakeHost struct {
	mu       sync.Mutex
	tries    int
	serves   int
	stops    int
	serveErr error
	stopFn   func()
	served   []string
}

func (h *fakeHost) Serve(_ context.Context, pluginID string) (func(), error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.tries++
	if h.serveErr != nil {
		return nil, h.serveErr
	}
	h.serves++
	h.served = append(h.served, pluginID)
	return func() {
		h.mu.Lock()
		h.stops++
		fn := h.stopFn
		h.mu.Unlock()
		if fn != nil {
			fn()
		}
	}, nil
}

func (h *fakeHost) setServeErr(err error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.serveErr = err
}

func (h *fakeHost) counts() (serves, stops int) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.serves, h.stops
}

// attempts returns how often Serve was called, successful or not.
func (h *fakeHost) attempts() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.tries
}

// testPlugin is an in-process PluginService on a real unix socket. Every RPC can
// be scripted per test; the default is the generated Unimplemented behaviour.
type testPlugin struct {
	platformv1.UnimplementedPluginServiceServer

	mu     sync.Mutex
	plan   func(context.Context, *platformv1.PlanOperationRequest) (*platformv1.PlanOperationResponse, error)
	invoke func(context.Context, *platformv1.InvokeRequest) (*platformv1.InvokeResponse, error)
	runJob func(*platformv1.RunJobRequest, grpc.ServerStreamingServer[platformv1.RunJobResponse]) error
}

func (p *testPlugin) setPlan(fn func(context.Context, *platformv1.PlanOperationRequest) (*platformv1.PlanOperationResponse, error)) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.plan = fn
}

func (p *testPlugin) setInvoke(fn func(context.Context, *platformv1.InvokeRequest) (*platformv1.InvokeResponse, error)) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.invoke = fn
}

func (p *testPlugin) setRunJob(fn func(*platformv1.RunJobRequest, grpc.ServerStreamingServer[platformv1.RunJobResponse]) error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.runJob = fn
}

func (p *testPlugin) PlanOperation(ctx context.Context, req *platformv1.PlanOperationRequest) (*platformv1.PlanOperationResponse, error) {
	p.mu.Lock()
	fn := p.plan
	p.mu.Unlock()
	if fn != nil {
		return fn(ctx, req)
	}
	return p.UnimplementedPluginServiceServer.PlanOperation(ctx, req)
}

func (p *testPlugin) Invoke(ctx context.Context, req *platformv1.InvokeRequest) (*platformv1.InvokeResponse, error) {
	p.mu.Lock()
	fn := p.invoke
	p.mu.Unlock()
	if fn != nil {
		return fn(ctx, req)
	}
	return p.UnimplementedPluginServiceServer.Invoke(ctx, req)
}

func (p *testPlugin) RunJob(req *platformv1.RunJobRequest, stream grpc.ServerStreamingServer[platformv1.RunJobResponse]) error {
	p.mu.Lock()
	fn := p.runJob
	p.mu.Unlock()
	if fn != nil {
		return fn(req, stream)
	}
	return p.UnimplementedPluginServiceServer.RunJob(req, stream)
}

// logCapture is a slog.Handler that keeps records for assertions.
type logCapture struct {
	mu      sync.Mutex
	records []slog.Record
}

func (c *logCapture) Enabled(context.Context, slog.Level) bool { return true }

func (c *logCapture) Handle(_ context.Context, r slog.Record) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.records = append(c.records, r.Clone())
	return nil
}

func (c *logCapture) WithAttrs([]slog.Attr) slog.Handler { return c }
func (c *logCapture) WithGroup(string) slog.Handler      { return c }

func (c *logCapture) snapshot() []slog.Record {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]slog.Record, len(c.records))
	copy(out, c.records)
	return out
}

func (c *logCapture) recordsWithMessage(msg string) []slog.Record {
	var out []slog.Record
	for _, r := range c.snapshot() {
		if r.Message == msg {
			out = append(out, r)
		}
	}
	return out
}

// recordAttr returns the attribute value of key in r.
func recordAttr(t *testing.T, r slog.Record, key string) slog.Value {
	t.Helper()
	var found slog.Value
	ok := false
	r.Attrs(func(a slog.Attr) bool {
		if a.Key == key {
			found = a.Value
			ok = true
			return false
		}
		return true
	})
	if !ok {
		t.Fatalf("log record %q has no attribute %q", r.Message, key)
	}
	return found
}

// testEnv wires a supervisor to fake unit and host services and to a real
// in-process plugin server per plugin id.
type testEnv struct {
	sup    *Supervisor
	units  *fakeUnits
	host   *fakeHost
	clock  *clock.Fake
	runDir string
	logs   *logCapture

	mu      sync.Mutex
	servers map[string]*grpc.Server
	plugins map[string]*testPlugin
}

func newEnv(t *testing.T, mutators ...func(*Options)) *testEnv {
	t.Helper()
	base := shortTempDir(t)
	runDir := filepath.Join(base, "run")
	units := &fakeUnits{}
	host := &fakeHost{}
	clk := clock.NewFake(time.Unix(1700000000, 0).UTC())
	logs := &logCapture{}
	opts := Options{
		Units: units,
		Host:  host,
		PluginDir: func(pluginID string) (string, error) {
			return filepath.Join(base, "plugins", pluginID, "1.0.0"), nil
		},
		Clock:             clk,
		Logger:            slog.New(logs),
		NodeID:            "test-node",
		MaxRestarts:       2,
		BackoffMin:        10 * time.Millisecond,
		BackoffMax:        80 * time.Millisecond,
		LogLinesPerSecond: 1000,
		LogBytesPerSecond: 1 << 20,
		RunDir:            runDir,
		ConnectTimeout:    5 * time.Second,
	}
	for _, mutate := range mutators {
		mutate(&opts)
	}
	sup, err := New(opts)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	sup.jitter = func() float64 { return 0.5 }
	t.Cleanup(sup.Close)
	env := &testEnv{
		sup:     sup,
		units:   units,
		host:    host,
		clock:   clk,
		runDir:  runDir,
		logs:    logs,
		servers: make(map[string]*grpc.Server),
		plugins: make(map[string]*testPlugin),
	}
	env.addPlugin(t, "alpha")
	return env
}

// addPlugin starts an in-process PluginService on the plugin socket of pluginID.
func (e *testEnv) addPlugin(t *testing.T, pluginID string) *testPlugin {
	t.Helper()
	plugin := &testPlugin{}
	socket := SocketPath(e.runDir, pluginID)
	if err := os.MkdirAll(filepath.Dir(socket), 0o700); err != nil {
		t.Fatalf("mkdir socket dir: %v", err)
	}
	ln, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatalf("listen %s: %v", socket, err)
	}
	srv := grpc.NewServer()
	platformv1.RegisterPluginServiceServer(srv, plugin)
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(srv.Stop)
	e.mu.Lock()
	e.servers[pluginID] = srv
	e.plugins[pluginID] = plugin
	e.mu.Unlock()
	return plugin
}

func (e *testEnv) pluginFor(t *testing.T, pluginID string) *testPlugin {
	t.Helper()
	e.mu.Lock()
	defer e.mu.Unlock()
	plugin := e.plugins[pluginID]
	if plugin == nil {
		t.Fatalf("no test plugin for %q", pluginID)
	}
	return plugin
}

// ensure runs Ensure while driving the fake clock: the supervisor waits on
// clock.After between attempts, so the test advances time whenever a waiter
// appears instead of sleeping.
func (e *testEnv) ensure(t *testing.T, pluginID string) *Instance {
	t.Helper()
	inst, err := ensureWithClock(t, e.sup, e.clock, pluginID)
	if err != nil {
		t.Fatalf("Ensure(%q): %v", pluginID, err)
	}
	return inst
}

// restartOutOfBand changes the unit state as an operator's systemctl restart
// would: a new main process and a new start timestamp, same unit.
func (e *testEnv) restartOutOfBand(pluginID string, mainPID int, start time.Time) {
	e.units.setState(UnitState{
		MainPID:      mainPID,
		ActiveState:  "active",
		SubState:     "running",
		ControlGroup: "/system.slice/qwq-plugin@" + pluginID + ".service",
		StartTime:    start,
	})
}

func ensureWithClock(t *testing.T, s *Supervisor, clk *clock.Fake, pluginID string) (*Instance, error) {
	t.Helper()
	type result struct {
		inst *Instance
		err  error
	}
	done := make(chan result, 1)
	go func() {
		inst, err := s.Ensure(context.Background(), pluginID)
		done <- result{inst: inst, err: err}
	}()
	timeout := time.After(15 * time.Second)
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case r := <-done:
			return r.inst, r.err
		case <-timeout:
			t.Fatal("Ensure did not finish")
			return nil, nil
		case <-ticker.C:
		}
		if clk.Waiters() > 0 {
			clk.Advance(time.Minute)
		}
	}
}

// countingCleanup returns a cleanup callback and the counter it increments.
func countingCleanup() (func(), *atomic.Int32) {
	var n atomic.Int32
	return func() { n.Add(1) }, &n
}
