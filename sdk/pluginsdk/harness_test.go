// SPDX-License-Identifier: Apache-2.0

package pluginsdk

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	platformv1 "github.com/qwq-panel/qwq/sdk/gen/qwq/platform/v1"
	"github.com/qwq-panel/qwq/sdk/manifest"
)

// testTimeout bounds every wait in these tests.
const testTimeout = 5 * time.Second

// errTest is the sentinel returned by plugin hooks the tests make fail.
var errTest = errors.New("test failure")

func unmarshalJSON(data []byte, v any) error { return json.Unmarshal(data, v) }

// ---------------- gRPC harness ----------------

// serveGRPC starts an in-memory gRPC server and returns a client connection.
func serveGRPC(t *testing.T, register func(*grpc.Server)) *grpc.ClientConn {
	t.Helper()
	lis := bufconn.Listen(1 << 20)
	srv := grpc.NewServer(grpc.WaitForHandlers(true))
	register(srv)
	go func() { _ = srv.Serve(lis) }()
	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return lis.DialContext(ctx) }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("dial bufconn: %v", err)
	}
	t.Cleanup(func() {
		_ = conn.Close()
		srv.Stop()
	})
	return conn
}

func testContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), testTimeout)
	t.Cleanup(cancel)
	return ctx
}

func recv[T any](t *testing.T, ch <-chan T, what string) T {
	t.Helper()
	select {
	case v := <-ch:
		return v
	case <-time.After(testTimeout):
		t.Fatalf("timed out waiting for %s", what)
		panic("unreachable")
	}
}

func mustJSON(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}

// ---------------- fixture manifest ----------------

type capSpec struct{ Name, Scope string }

type opSpec struct {
	Name      string
	Mode      string // invoke | job
	Effect    string // read | write
	Plannable bool
	Caps      []capSpec
}

var defaultCaps = []capSpec{
	{"state.kv.read", "self"},
	{"state.kv.write", "self"},
	{"plugin.invoke", "core.xray/core.apply"},
}

var defaultOps = []opSpec{
	{Name: "test.echo", Mode: "invoke", Effect: "read"},
	{Name: "test.raw", Mode: "invoke", Effect: "write"},
	{Name: "test.fail", Mode: "invoke", Effect: "read"},
	{Name: "test.wait", Mode: "job", Effect: "read"},
	{Name: "test.apply", Mode: "job", Effect: "write"},
	{Name: "test.set", Mode: "invoke", Effect: "write", Plannable: true,
		Caps: []capSpec{{"state.kv.read", "self"}, {"state.kv.write", "self"}}},
	{Name: "test.setjob", Mode: "job", Effect: "write", Plannable: true,
		Caps: []capSpec{{"state.kv.read", "self"}, {"state.kv.write", "self"}}},
	{Name: "test.sync", Mode: "invoke", Effect: "write",
		Caps: []capSpec{{"plugin.invoke", "core.xray/core.apply"}}},
	{Name: "test.list", Mode: "invoke", Effect: "read"},
	{Name: "test.subscribe", Mode: "invoke", Effect: "read"},
	{Name: "test.secret", Mode: "invoke", Effect: "read"},
}

func digest() string { return "sha256:" + strings.Repeat("0", 64) }

// fixtureManifest builds a manifest that passes sdk/manifest.Parse for the
// given operations.
func fixtureManifest(minor int, ops []opSpec, caps []capSpec) []byte {
	files := map[string]string{
		"bin/plugin":                  digest(),
		"schemas/config.schema.json":  digest(),
		"attestations/sbom.spdx.json": digest(),
	}
	var jsonOps = []any{}
	for _, op := range ops {
		name := op.Name
		req := "schemas/" + name + ".request.json"
		resp := "schemas/" + name + ".response.json"
		files[req], files[resp] = digest(), digest()
		effect := op.Effect
		idempotent := effect == "read"
		m := map[string]any{
			"name": name, "api_version": "v1", "permission": "test:" + strings.ReplaceAll(name, ".", "_"),
			"mode": op.Mode, "effect": effect, "risk": "low", "idempotent": idempotent,
			"timeout_ms": 5000, "summary": "operation " + name,
			"request_schema": req, "response_schema": resp,
		}
		if op.Plannable {
			m["plannable"] = true
		}
		if len(op.Caps) > 0 {
			var cs []any
			for _, c := range op.Caps {
				cs = append(cs, map[string]any{"name": c.Name, "scope": c.Scope})
			}
			m["capabilities"] = cs
		}
		jsonOps = append(jsonOps, m)
	}
	var jsonCaps = []any{}
	for _, c := range caps {
		jsonCaps = append(jsonCaps, map[string]any{"name": c.Name, "scope": c.Scope, "reason": "test"})
	}
	root := map[string]any{
		"schema_version":    "1.0",
		"id":                "test.plugin",
		"version":           "0.1.0",
		"name":              "Test Plugin",
		"summary":           "fixture manifest for SDK tests",
		"publisher":         map[string]any{"id": "qwq-builtin", "key_id": "ed25519:" + strings.Repeat("0", 64)},
		"abi":               map[string]any{"major": 1, "minimum_minor": minor},
		"engine_constraint": ">=0.1.0 <1.0.0",
		"target":            "linux/amd64",
		"entrypoint":        "bin/plugin",
		"files":             files,
		"provenance":        map[string]any{"sbom": "attestations/sbom.spdx.json"},
		"placement":         "node",
		"lifecycle":         map[string]any{"startup": "eager", "background": false, "update_strategy": "auto"},
		"operations":        jsonOps,
		"capabilities":      jsonCaps,
		"dependencies":      []any{},
		"state":             map[string]any{"schema_version": "1", "minimum_rollback_version": "0.1.0", "backup_paths": []any{}},
		"config":            map[string]any{"schema": "schemas/config.schema.json", "hot_apply": true},
		"resources":         map[string]any{"memory_max_mb": 64, "cpu_quota_percent": 5, "pids_max": 16, "fds_max": 64, "disk_max_mb": 16},
	}
	return mustJSON(root)
}

// ---------------- fake Host Service ----------------

type kvEntry struct {
	value    []byte
	revision string
}

// hostCall is one recorded Host Service call.
type hostCall struct {
	Method      string
	Handle      string
	OperationID string
	TraceID     string
	Key         string
	Subject     string
}

type fakeHost struct {
	mu      sync.Mutex
	kv      map[string]kvEntry
	seq     uint64
	calls   []hostCall
	config  []byte
	rev     string
	audits  []*platformv1.AuditRecord
	publish []*platformv1.EventDraft
	acks    []uint64
	subs    []string

	invokePlugin    func(*platformv1.InvokePluginRequest) (*platformv1.InvokePluginResponse, error)
	waitOperation   func(context.Context, *platformv1.WaitOperationRequest) (*platformv1.WaitOperationResponse, error)
	cancelOperation func(*platformv1.CancelOperationRequest) (*platformv1.CancelOperationResponse, error)
	subscribeEvents func(*platformv1.SubscribeEventsRequest, grpc.ServerStreamingServer[platformv1.SubscribeEventsResponse]) error
}

func newFakeHost() *fakeHost {
	return &fakeHost{kv: map[string]kvEntry{}, config: []byte(`{"greeting":"hello"}`), rev: "1"}
}

func (h *fakeHost) record(c hostCall) {
	h.mu.Lock()
	h.calls = append(h.calls, c)
	h.mu.Unlock()
}

func (h *fakeHost) callsOf(method string) []hostCall {
	h.mu.Lock()
	defer h.mu.Unlock()
	var out []hostCall
	for _, c := range h.calls {
		if c.Method == method {
			out = append(out, c)
		}
	}
	return out
}

func (h *fakeHost) count(method string) int { return len(h.callsOf(method)) }

func (h *fakeHost) seedKV(handle, key, value string) string {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.seq++
	rev := strconv.FormatUint(h.seq, 10)
	h.kv[handle+"\x00"+key] = kvEntry{value: []byte(value), revision: rev}
	return rev
}

func (h *fakeHost) stateOf(handle, key string) (kvEntry, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	e, ok := h.kv[handle+"\x00"+key]
	return e, ok
}

func (h *fakeHost) setInvokePlugin(fn func(*platformv1.InvokePluginRequest) (*platformv1.InvokePluginResponse, error)) {
	h.mu.Lock()
	h.invokePlugin = fn
	h.mu.Unlock()
}

func (h *fakeHost) setWaitOperation(fn func(context.Context, *platformv1.WaitOperationRequest) (*platformv1.WaitOperationResponse, error)) {
	h.mu.Lock()
	h.waitOperation = fn
	h.mu.Unlock()
}

func (h *fakeHost) setSubscribeEvents(fn func(*platformv1.SubscribeEventsRequest, grpc.ServerStreamingServer[platformv1.SubscribeEventsResponse]) error) {
	h.mu.Lock()
	h.subscribeEvents = fn
	h.mu.Unlock()
}

// hostServices implements every Host Service on one plugin's socket.
type hostServices struct {
	platformv1.UnimplementedHostStateServiceServer
	platformv1.UnimplementedHostEventsServiceServer
	platformv1.UnimplementedHostConfigServiceServer
	platformv1.UnimplementedHostSecretsServiceServer
	platformv1.UnimplementedHostAuditServiceServer
	platformv1.UnimplementedHostInvokeServiceServer

	h *fakeHost
}

func (s *hostServices) register(srv *grpc.Server) {
	platformv1.RegisterHostStateServiceServer(srv, s)
	platformv1.RegisterHostEventsServiceServer(srv, s)
	platformv1.RegisterHostConfigServiceServer(srv, s)
	platformv1.RegisterHostSecretsServiceServer(srv, s)
	platformv1.RegisterHostAuditServiceServer(srv, s)
	platformv1.RegisterHostInvokeServiceServer(srv, s)
}

func (s *hostServices) check(hc *platformv1.HostCallContext, method, key, subject string) error {
	if hc.GetInstanceHandle() == "" {
		return status.Error(codes.Unauthenticated, "missing instance_handle")
	}
	s.h.record(hostCall{Method: method, Handle: hc.GetInstanceHandle(), OperationID: hc.GetOperationId(),
		TraceID: hc.GetTraceId(), Key: key, Subject: subject})
	return nil
}

func (s *hostServices) GetState(_ context.Context, req *platformv1.GetStateRequest) (*platformv1.GetStateResponse, error) {
	if err := s.check(req.GetContext(), "GetState", req.GetKey(), ""); err != nil {
		return nil, err
	}
	e, ok := s.h.stateOf(req.GetContext().GetInstanceHandle(), req.GetKey())
	if !ok {
		return &platformv1.GetStateResponse{Found: false}, nil
	}
	return &platformv1.GetStateResponse{ValueJson: append([]byte(nil), e.value...), Found: true, Revision: e.revision}, nil
}

func (s *hostServices) PutState(_ context.Context, req *platformv1.PutStateRequest) (*platformv1.PutStateResponse, error) {
	if err := s.check(req.GetContext(), "PutState", req.GetKey(), ""); err != nil {
		return nil, err
	}
	handle := req.GetContext().GetInstanceHandle()
	s.h.mu.Lock()
	defer s.h.mu.Unlock()
	cur, exists := s.h.kv[handle+"\x00"+req.GetKey()]
	switch pre := req.GetPrecondition().(type) {
	case *platformv1.PutStateRequest_MustNotExist:
		if pre.MustNotExist && exists {
			return nil, status.Errorf(codes.Aborted, "key exists at revision %s", cur.revision)
		}
	case *platformv1.PutStateRequest_ExpectedRevision:
		if !exists || cur.revision != pre.ExpectedRevision {
			return nil, status.Errorf(codes.Aborted, "key is at revision %q, not %q", cur.revision, pre.ExpectedRevision)
		}
	}
	s.h.seq++
	rev := strconv.FormatUint(s.h.seq, 10)
	s.h.kv[handle+"\x00"+req.GetKey()] = kvEntry{value: append([]byte(nil), req.GetValueJson()...), revision: rev}
	return &platformv1.PutStateResponse{Revision: rev}, nil
}

func (s *hostServices) DeleteState(_ context.Context, req *platformv1.DeleteStateRequest) (*platformv1.DeleteStateResponse, error) {
	if err := s.check(req.GetContext(), "DeleteState", req.GetKey(), ""); err != nil {
		return nil, err
	}
	handle := req.GetContext().GetInstanceHandle()
	s.h.mu.Lock()
	defer s.h.mu.Unlock()
	cur, exists := s.h.kv[handle+"\x00"+req.GetKey()]
	if req.GetExpectedRevision() != "" && (!exists || cur.revision != req.GetExpectedRevision()) {
		return nil, status.Error(codes.Aborted, "revision mismatch")
	}
	delete(s.h.kv, handle+"\x00"+req.GetKey())
	return &platformv1.DeleteStateResponse{}, nil
}

func (s *hostServices) ListState(_ context.Context, req *platformv1.ListStateRequest) (*platformv1.ListStateResponse, error) {
	if err := s.check(req.GetContext(), "ListState", req.GetPrefix(), ""); err != nil {
		return nil, err
	}
	handle := req.GetContext().GetInstanceHandle()
	offset := 0
	if req.GetPageToken() != "" {
		n, err := strconv.Atoi(req.GetPageToken())
		if err != nil || n < 0 {
			return nil, status.Error(codes.InvalidArgument, "invalid page token")
		}
		offset = n
	}
	size := int(req.GetPageSize())
	if size <= 0 {
		size = 100
	}
	s.h.mu.Lock()
	defer s.h.mu.Unlock()
	prefix := handle + "\x00" + req.GetPrefix()
	var keys []string
	for k := range s.h.kv {
		if strings.HasPrefix(k, prefix) {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	resp := &platformv1.ListStateResponse{}
	if offset > len(keys) {
		return resp, nil
	}
	end := min(offset+size, len(keys))
	for _, k := range keys[offset:end] {
		e := s.h.kv[k]
		entry := &platformv1.StateEntry{Key: strings.TrimPrefix(k, handle+"\x00"), Revision: e.revision}
		if req.GetIncludeValues() {
			entry.ValueJson = append([]byte(nil), e.value...)
		}
		resp.Entries = append(resp.Entries, entry)
	}
	if end < len(keys) {
		resp.NextPageToken = strconv.Itoa(end)
	}
	return resp, nil
}

func (s *hostServices) PublishEvent(_ context.Context, req *platformv1.PublishEventRequest) (*platformv1.PublishEventResponse, error) {
	if err := s.check(req.GetContext(), "PublishEvent", "", req.GetEvent().GetSubject()); err != nil {
		return nil, err
	}
	s.h.mu.Lock()
	defer s.h.mu.Unlock()
	s.h.seq++
	s.h.publish = append(s.h.publish, req.GetEvent())
	return &platformv1.PublishEventResponse{EventId: strconv.FormatUint(s.h.seq, 10), Sequence: s.h.seq}, nil
}

func (s *hostServices) SubscribeEvents(req *platformv1.SubscribeEventsRequest, stream grpc.ServerStreamingServer[platformv1.SubscribeEventsResponse]) error {
	if err := s.check(req.GetContext(), "SubscribeEvents", "", strings.Join(req.GetTopics(), ",")); err != nil {
		return err
	}
	s.h.mu.Lock()
	s.h.subs = append(s.h.subs, req.GetSubscription())
	subscribe := s.h.subscribeEvents
	s.h.mu.Unlock()
	if subscribe != nil {
		return subscribe(req, stream)
	}
	return nil
}

func (s *hostServices) AckEvents(_ context.Context, req *platformv1.AckEventsRequest) (*platformv1.AckEventsResponse, error) {
	if err := s.check(req.GetContext(), "AckEvents", "", req.GetSubscription()); err != nil {
		return nil, err
	}
	s.h.mu.Lock()
	s.h.acks = append(s.h.acks, req.GetSequence())
	s.h.mu.Unlock()
	return &platformv1.AckEventsResponse{}, nil
}

func (s *hostServices) ReportChanges(_ context.Context, req *platformv1.ReportChangesRequest) (*platformv1.ReportChangesResponse, error) {
	var subjects []string
	for _, c := range req.GetChanges() {
		subjects = append(subjects, c.GetSubject())
	}
	if err := s.check(req.GetContext(), "ReportChanges", "", strings.Join(subjects, ",")); err != nil {
		return nil, err
	}
	return &platformv1.ReportChangesResponse{}, nil
}

func (s *hostServices) GetConfig(_ context.Context, req *platformv1.GetConfigRequest) (*platformv1.GetConfigResponse, error) {
	if err := s.check(req.GetContext(), "GetConfig", req.GetRevision(), ""); err != nil {
		return nil, err
	}
	s.h.mu.Lock()
	defer s.h.mu.Unlock()
	return &platformv1.GetConfigResponse{ConfigJson: append([]byte(nil), s.h.config...), Revision: s.h.rev}, nil
}

func (s *hostServices) RevealSecret(_ context.Context, req *platformv1.RevealSecretRequest) (*platformv1.RevealSecretResponse, error) {
	if err := s.check(req.GetContext(), "RevealSecret", req.GetSecretRef(), ""); err != nil {
		return nil, err
	}
	if req.GetContext().GetOperationId() == "" {
		return nil, status.Error(codes.PermissionDenied, "operation_id required")
	}
	return &platformv1.RevealSecretResponse{Value: []byte("s3cr3t")}, nil
}

func (s *hostServices) WriteAudit(_ context.Context, req *platformv1.WriteAuditRequest) (*platformv1.WriteAuditResponse, error) {
	if err := s.check(req.GetContext(), "WriteAudit", req.GetRecord().GetAction(), req.GetRecord().GetSubject()); err != nil {
		return nil, err
	}
	s.h.mu.Lock()
	s.h.audits = append(s.h.audits, req.GetRecord())
	s.h.mu.Unlock()
	return &platformv1.WriteAuditResponse{}, nil
}

func (s *hostServices) InvokePlugin(_ context.Context, req *platformv1.InvokePluginRequest) (*platformv1.InvokePluginResponse, error) {
	if err := s.check(req.GetContext(), "InvokePlugin", req.GetOperation(), req.GetTargetPluginId()); err != nil {
		return nil, err
	}
	s.h.mu.Lock()
	fn := s.h.invokePlugin
	s.h.mu.Unlock()
	if fn == nil {
		return nil, status.Error(codes.Unimplemented, "no InvokePlugin script")
	}
	return fn(req)
}

func (s *hostServices) WaitOperation(ctx context.Context, req *platformv1.WaitOperationRequest) (*platformv1.WaitOperationResponse, error) {
	if err := s.check(req.GetContext(), "WaitOperation", req.GetOperationId(), ""); err != nil {
		return nil, err
	}
	s.h.mu.Lock()
	fn := s.h.waitOperation
	s.h.mu.Unlock()
	if fn == nil {
		return nil, status.Error(codes.NotFound, "no WaitOperation script")
	}
	return fn(ctx, req)
}

func (s *hostServices) CancelOperation(_ context.Context, req *platformv1.CancelOperationRequest) (*platformv1.CancelOperationResponse, error) {
	if err := s.check(req.GetContext(), "CancelOperation", req.GetOperationId(), ""); err != nil {
		return nil, err
	}
	s.h.mu.Lock()
	fn := s.h.cancelOperation
	s.h.mu.Unlock()
	if fn == nil {
		return &platformv1.CancelOperationResponse{State: platformv1.OperationState_OPERATION_STATE_CANCELED}, nil
	}
	return fn(req)
}

// ---------------- test environment ----------------

type testEnv struct {
	t      *testing.T
	client platformv1.PluginServiceClient
	host   *fakeHost
	server *Server
	plugin *testPlugin
	logs   *bytes.Buffer
}

func newTestEnv(t *testing.T, p *testPlugin) *testEnv {
	return newTestEnvWithManifest(t, p, fixtureManifest(0, defaultOps, defaultCaps))
}

func newTestEnvWithManifest(t *testing.T, p *testPlugin, rawManifest []byte) *testEnv {
	t.Helper()
	return newEnv(t, p, rawManifest)
}

func newEnv(t *testing.T, plugin Plugin, rawManifest []byte) *testEnv {
	t.Helper()
	host := newFakeHost()
	hostConn := serveGRPC(t, func(s *grpc.Server) { (&hostServices{h: host}).register(s) })
	logs := &bytes.Buffer{}
	logger := slog.New(slog.NewJSONHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	env := &testEnv{t: t, host: host, logs: logs}
	if p, ok := plugin.(*testPlugin); ok {
		env.plugin = p
	}
	env.client = platformv1.NewPluginServiceClient(serveGRPC(t, func(s *grpc.Server) {
		var err error
		env.server, err = Serve(t.Context(), Options{
			Plugin: plugin, Manifest: rawManifest, Registrar: s, Host: hostConn, Logger: logger,
			DefaultGracePeriod: time.Second, ReleaseGracePeriod: time.Second,
		})
		if err != nil {
			t.Fatalf("Serve: %v", err)
		}
	}))
	t.Cleanup(func() { env.server.Close() })
	return env
}

func handleFor(id string) string { return "handle-" + id }

func lifecycleContext(id string) *platformv1.RequestContext {
	return &platformv1.RequestContext{
		RequestId: "req-" + id, TraceId: "trace-" + id, InstanceId: id, NodeId: "local", Locale: "en",
		Actor: &platformv1.Actor{Kind: platformv1.ActorKind_ACTOR_KIND_SYSTEM, Id: "agent"},
	}
}

func operationContext(id, operationID, locale string) *platformv1.RequestContext {
	return &platformv1.RequestContext{
		RequestId: "req-" + operationID, TraceId: "trace-" + operationID, InstanceId: id, NodeId: "local",
		OperationId: operationID, Locale: locale,
		Actor: &platformv1.Actor{Kind: platformv1.ActorKind_ACTOR_KIND_HUMAN, Id: "admin"},
	}
}

func (e *testEnv) initialize(id string, config []byte) *platformv1.InitializeResponse {
	e.t.Helper()
	resp, err := e.initializeWith(id, config, 0)
	if err != nil {
		e.t.Fatalf("Initialize %s: %v", id, err)
	}
	return resp
}

func (e *testEnv) initializeWith(id string, config []byte, hostMinor uint32) (*platformv1.InitializeResponse, error) {
	e.t.Helper()
	return e.client.Initialize(testContext(e.t), &platformv1.InitializeRequest{
		Context: lifecycleContext(id), InstanceHandle: handleFor(id), DataDir: "/tmp/" + id,
		ConfigJson: config, ConfigRevision: "1", HostAbiMinor: hostMinor,
	})
}

func (e *testEnv) start(id string) {
	e.t.Helper()
	if _, err := e.client.Start(testContext(e.t), &platformv1.StartRequest{Context: lifecycleContext(id)}); err != nil {
		e.t.Fatalf("Start %s: %v", id, err)
	}
}

func (e *testEnv) activate(id string) {
	e.t.Helper()
	if _, err := e.client.Activate(testContext(e.t), &platformv1.ActivateRequest{Context: lifecycleContext(id)}); err != nil {
		e.t.Fatalf("Activate %s: %v", id, err)
	}
}

// ready runs Initialize and Start.
func (e *testEnv) ready(id string, config []byte) *platformv1.InitializeResponse {
	e.t.Helper()
	resp := e.initialize(id, config)
	e.start(id)
	return resp
}

// active runs Initialize, Start and Activate.
func (e *testEnv) active(id string, config []byte) *platformv1.InitializeResponse {
	e.t.Helper()
	resp := e.ready(id, config)
	e.activate(id)
	return resp
}

func (e *testEnv) instance(id string) *testInstance {
	e.t.Helper()
	for _, inst := range e.plugin.instancesSnapshot() {
		if inst.ID() == id {
			return inst
		}
	}
	e.t.Fatalf("no test instance %s", id)
	return nil
}

// parseFixture parses the default fixture manifest for descriptor comparisons.
func parseFixture(t *testing.T, raw []byte) *manifest.Manifest {
	t.Helper()
	m, err := manifest.Parse(raw)
	if err != nil {
		t.Fatalf("fixture manifest does not parse: %v", err)
	}
	return m
}

// wantCode asserts a gRPC status code.
func wantCode(t *testing.T, err error, want codes.Code) {
	t.Helper()
	if got := status.Code(err); got != want {
		t.Fatalf("gRPC status = %v (%v), want %v", got, err, want)
	}
}

func (e *testEnv) logContains(s string) bool {
	return strings.Contains(e.logs.String(), s)
}

func (e *testEnv) lastLog() string {
	return e.logs.String()
}
