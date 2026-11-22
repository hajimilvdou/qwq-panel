// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
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

	pb "github.com/qwq-panel/qwq/sdk/gen/qwq/platform/v1"
	"github.com/qwq-panel/qwq/sdk/manifest"
	"github.com/qwq-panel/qwq/sdk/pluginsdk"
)

const testTimeout = 5 * time.Second

func TestManifestParses(t *testing.T) {
	m, err := manifest.Parse(Manifest())
	if err != nil {
		t.Fatalf("manifest.Parse: %v", err)
	}
	if m.ID != "noop" || m.Version != "0.1.0" || m.Placement != "node" ||
		m.ABI.Major != 1 || m.ABI.MinimumMinor != 0 || m.Config.Schema != "schemas/config.schema.json" {
		t.Fatalf("manifest = %+v", m)
	}
	ops := map[string]manifest.Operation{}
	for _, op := range m.Operations {
		ops[op.Name] = op
	}
	if len(ops) != 3 {
		t.Fatalf("%d operations", len(ops))
	}
	if op := ops["noop.echo"]; op.Mode != "invoke" || op.Effect != "read" || op.EffectivePlannable() {
		t.Fatalf("noop.echo = %+v", op)
	}
	if op := ops["noop.wait"]; op.Mode != "job" || op.Effect != "read" {
		t.Fatalf("noop.wait = %+v", op)
	}
	if op := ops["noop.set"]; op.Mode != "invoke" || op.Effect != "write" || !op.EffectivePlannable() {
		t.Fatalf("noop.set = %+v", op)
	}
	// Every referenced package file is listed with a digest.
	for _, path := range []string{m.Entrypoint, m.Config.Schema, m.Provenance.SBOM,
		ops["noop.echo"].RequestSchema, ops["noop.echo"].ResponseSchema,
		ops["noop.wait"].RequestSchema, ops["noop.wait"].ResponseSchema,
		ops["noop.set"].RequestSchema, ops["noop.set"].ResponseSchema} {
		if _, ok := m.Files[path]; !ok {
			t.Errorf("%s is not listed in files", path)
		}
	}
}

// TestManifestFilesExist keeps the package coherent: every non-build file
// listed in the manifest exists in the source tree. The digests are placeholders
// until P2-T3 packs the plugin.
func TestManifestFilesExist(t *testing.T) {
	m, err := manifest.Parse(Manifest())
	if err != nil {
		t.Fatal(err)
	}
	for path := range m.Files {
		if path == m.Entrypoint {
			continue // built by P2-T3, not present in the source tree
		}
		if _, err := os.Stat(filepath.FromSlash(path)); err != nil {
			t.Errorf("%s: %v", path, err)
		}
	}
}

func TestDescriptorMatchesManifest(t *testing.T) {
	srv, err := pluginsdk.Serve(context.Background(), pluginsdk.Options{
		Plugin: New(), Manifest: Manifest(), Registrar: stubRegistrar{}, Logger: discardLogger(t),
	})
	if err != nil {
		t.Fatalf("Serve: %v", err)
	}
	defer srv.Close()
	resp, err := srv.GetDescriptor(context.Background(), &pb.GetDescriptorRequest{})
	if err != nil {
		t.Fatalf("GetDescriptor: %v", err)
	}
	d := resp.GetDescriptor_()
	m, err := manifest.Parse(Manifest())
	if err != nil {
		t.Fatal(err)
	}
	if d.GetPluginId() != m.ID || d.GetPluginVersion() != m.Version ||
		d.GetAbiMajor() != uint32(m.ABI.Major) || d.GetAbiMinor() != uint32(m.ABI.MinimumMinor) ||
		d.GetPlacement() != pb.Placement_PLACEMENT_NODE || d.GetConfigSchemaRef() != m.Config.Schema ||
		d.GetStateSchemaVersion() != m.State.SchemaVersion {
		t.Fatalf("descriptor = %v", d)
	}
	if len(d.GetOperations()) != len(m.Operations) || len(d.GetCapabilities()) != len(m.Capabilities) {
		t.Fatalf("descriptor = %v", d)
	}
	for idx, op := range m.Operations {
		got := d.GetOperations()[idx]
		if got.GetName() != op.Name || got.GetApiVersion() != op.APIVersion ||
			got.GetPlannable() != op.EffectivePlannable() || got.GetTimeoutMs() != int32(op.TimeoutMS) ||
			got.GetRequestSchemaRef() != op.RequestSchema || got.GetResponseSchemaRef() != op.ResponseSchema {
			t.Fatalf("operation %d = %v, want %s", idx, got, op.Name)
		}
	}
}

// ---------------- end-to-end harness ----------------

type kvEntry struct {
	value    []byte
	revision string
}

type kvHost struct {
	pb.UnimplementedHostStateServiceServer
	mu    sync.Mutex
	kv    map[string]kvEntry
	seq   uint64
	puts  int
	reads int
}

func newKVHost() *kvHost { return &kvHost{kv: map[string]kvEntry{}} }

func (h *kvHost) GetState(_ context.Context, req *pb.GetStateRequest) (*pb.GetStateResponse, error) {
	if req.GetContext().GetInstanceHandle() == "" {
		return nil, status.Error(codes.Unauthenticated, "missing instance_handle")
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.reads++
	e, ok := h.kv[req.GetContext().GetInstanceHandle()+"\x00"+req.GetKey()]
	if !ok {
		return &pb.GetStateResponse{Found: false}, nil
	}
	return &pb.GetStateResponse{ValueJson: append([]byte(nil), e.value...), Found: true, Revision: e.revision}, nil
}

func (h *kvHost) PutState(_ context.Context, req *pb.PutStateRequest) (*pb.PutStateResponse, error) {
	if req.GetContext().GetInstanceHandle() == "" {
		return nil, status.Error(codes.Unauthenticated, "missing instance_handle")
	}
	handle := req.GetContext().GetInstanceHandle()
	h.mu.Lock()
	defer h.mu.Unlock()
	cur, exists := h.kv[handle+"\x00"+req.GetKey()]
	switch pre := req.GetPrecondition().(type) {
	case *pb.PutStateRequest_MustNotExist:
		if pre.MustNotExist && exists {
			return nil, status.Error(codes.Aborted, "already exists")
		}
	case *pb.PutStateRequest_ExpectedRevision:
		if !exists || cur.revision != pre.ExpectedRevision {
			return nil, status.Error(codes.Aborted, "revision mismatch")
		}
	}
	h.seq++
	rev := strconv.FormatUint(h.seq, 10)
	h.kv[handle+"\x00"+req.GetKey()] = kvEntry{value: append([]byte(nil), req.GetValueJson()...), revision: rev}
	h.puts++
	return &pb.PutStateResponse{Revision: rev}, nil
}

func (h *kvHost) counts() (puts, reads int) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.puts, h.reads
}

type stubRegistrar struct{}

func (stubRegistrar) RegisterService(*grpc.ServiceDesc, any) {}

func discardLogger(t *testing.T) *slog.Logger {
	t.Helper()
	return slog.New(slog.NewJSONHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
}

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

type env struct {
	t      *testing.T
	client pb.PluginServiceClient
	host   *kvHost
	server *pluginsdk.Server
}

func newEnv(t *testing.T) *env {
	t.Helper()
	host := newKVHost()
	hostConn := serveGRPC(t, func(s *grpc.Server) { pb.RegisterHostStateServiceServer(s, host) })
	e := &env{t: t, host: host}
	e.client = pb.NewPluginServiceClient(serveGRPC(t, func(s *grpc.Server) {
		var err error
		e.server, err = pluginsdk.Serve(t.Context(), pluginsdk.Options{
			Plugin: New(), Manifest: Manifest(), Registrar: s, Host: hostConn, Logger: discardLogger(t),
			DefaultGracePeriod: time.Second, ReleaseGracePeriod: time.Second,
		})
		if err != nil {
			t.Fatalf("Serve: %v", err)
		}
	}))
	t.Cleanup(func() { e.server.Close() })
	return e
}

func (e *env) ctx() context.Context {
	e.t.Helper()
	ctx, cancel := context.WithTimeout(e.t.Context(), testTimeout)
	e.t.Cleanup(cancel)
	return ctx
}

func requestContext(id, operationID, locale string) *pb.RequestContext {
	return &pb.RequestContext{
		RequestId: "req-" + id, TraceId: "trace-" + id, InstanceId: id, OperationId: operationID,
		NodeId: "local", Locale: locale,
		Actor: &pb.Actor{Kind: pb.ActorKind_ACTOR_KIND_HUMAN, Id: "admin"},
	}
}

func (e *env) startInstance(id string) {
	e.t.Helper()
	ctx := e.ctx()
	handle := "handle-" + id
	if _, err := e.client.Initialize(ctx, &pb.InitializeRequest{
		Context: requestContext(id, "", "en"), InstanceHandle: handle, DataDir: "/tmp/" + id,
		ConfigJson: []byte(`{}`), ConfigRevision: "1", HostAbiMinor: 0,
	}); err != nil {
		e.t.Fatalf("Initialize: %v", err)
	}
	if _, err := e.client.Start(ctx, &pb.StartRequest{Context: requestContext(id, "", "en")}); err != nil {
		e.t.Fatalf("Start: %v", err)
	}
	if _, err := e.client.Activate(ctx, &pb.ActivateRequest{Context: requestContext(id, "", "en")}); err != nil {
		e.t.Fatalf("Activate: %v", err)
	}
}

func (e *env) invoke(id, operation string, payload any, pre ...*pb.Precondition) *pb.InvokeResponse {
	e.t.Helper()
	body, err := json.Marshal(payload)
	if err != nil {
		e.t.Fatal(err)
	}
	resp, err := e.client.Invoke(e.ctx(), &pb.InvokeRequest{
		Context: requestContext(id, "op-"+operation, "en"), Operation: operation, ApiVersion: "v1",
		PayloadJson: body, Preconditions: pre, Attempt: 1,
	})
	if err != nil {
		e.t.Fatalf("Invoke %s: %v", operation, err)
	}
	return resp
}

func TestLifecycleAndOperations(t *testing.T) {
	e := newEnv(t)
	ctx := e.ctx()

	// Before Initialize, the instance is unknown.
	_, err := e.client.CheckHealth(ctx, &pb.CheckHealthRequest{Context: requestContext("default", "", "en")})
	if status.Code(err) != codes.NotFound {
		t.Fatalf("CheckHealth before Initialize = %v", err)
	}

	e.startInstance("default")
	health, err := e.client.CheckHealth(ctx, &pb.CheckHealthRequest{Context: requestContext("default", "", "en")})
	if err != nil {
		t.Fatal(err)
	}
	if health.GetStatus() != pb.CheckHealthResponse_STATUS_SERVING ||
		health.GetLifecycleState() != pb.LifecycleState_LIFECYCLE_STATE_ACTIVE ||
		health.GetMessage() != "noop is empty" || health.GetAppliedConfigRevision() != "1" {
		t.Fatalf("health = %v", health)
	}

	t.Run("echo", func(t *testing.T) {
		resp := e.invoke("default", "noop.echo", map[string]string{"message": "hi"})
		if resp.GetError() != nil {
			t.Fatalf("echo = %v", resp.GetError())
		}
		var out struct {
			Message    string `json:"message"`
			InstanceID string `json:"instance_id"`
			Attempt    uint32 `json:"attempt"`
		}
		if err := json.Unmarshal(resp.GetPayloadJson(), &out); err != nil || out.Message != "hi" ||
			out.InstanceID != "default" || out.Attempt != 1 {
			t.Fatalf("echo payload = %s", resp.GetPayloadJson())
		}
		bad := e.invoke("default", "noop.echo", map[string]string{"message": strings.Repeat("x", 65)})
		if bad.GetError().GetCode() != "VALIDATION_FAILED" || len(bad.GetError().GetViolations()) != 1 ||
			bad.GetError().GetViolations()[0].GetPointer() != "/message" {
			t.Fatalf("echo validation = %v", bad)
		}
	})

	t.Run("wait reports three steps and one terminal", func(t *testing.T) {
		stream, err := e.client.RunJob(ctx, &pb.RunJobRequest{
			Context: requestContext("default", "op-wait", "en"), Operation: "noop.wait", ApiVersion: "v1",
			PayloadJson: []byte(`{"step_delay_ms":1}`), Attempt: 1,
		})
		if err != nil {
			t.Fatal(err)
		}
		var messages []*pb.JobProgress
		for {
			resp, err := stream.Recv()
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil {
				t.Fatalf("Recv: %v", err)
			}
			messages = append(messages, resp.GetProgress())
		}
		if len(messages) != 4 {
			t.Fatalf("%d messages", len(messages))
		}
		for idx, step := range waitSteps {
			p := messages[idx]
			if p.GetStep() != step.id || p.GetStepIndex() != uint32(idx+1) || p.GetStepCount() != 3 ||
				p.GetCompleted() || p.GetMessage() == "" {
				t.Fatalf("progress %d = %v", idx, p)
			}
		}
		if last := messages[3]; !last.GetCompleted() || string(last.GetResultJson()) != `{"steps":3}` {
			t.Fatalf("terminal = %v", last)
		}
	})

	t.Run("plan then set", func(t *testing.T) {
		plan, err := e.client.PlanOperation(ctx, &pb.PlanOperationRequest{
			Context: requestContext("default", "op-plan", "en"), Operation: "noop.set", ApiVersion: "v1",
			PayloadJson: []byte(`{"value":"hello"}`),
		})
		if err != nil || plan.GetError() != nil {
			t.Fatalf("PlanOperation = %v, %v", plan, err)
		}
		if puts, _ := e.host.counts(); puts != 0 {
			t.Fatalf("PlanOperation wrote %d keys", puts)
		}
		change := plan.GetChanges()[0]
		if change.GetKind() != pb.PlannedChange_KIND_CREATE || change.GetSubject() != "value" ||
			string(change.GetAfterJson()) != `"hello"` || change.GetDescription() == "" {
			t.Fatalf("planned change = %v", change)
		}
		pre := plan.GetPreconditions()
		if len(pre) != 1 || pre[0].GetSubject() != "value" || pre[0].GetRevision() != "" {
			t.Fatalf("preconditions = %v", pre)
		}

		resp := e.invoke("default", "noop.set", map[string]string{"value": "hello"}, pre...)
		if resp.GetError() != nil || len(resp.GetChanges()) != 1 ||
			resp.GetChanges()[0].GetSubject() != "value" || resp.GetChanges()[0].GetRevision() == "" {
			t.Fatalf("set = %v", resp)
		}
		var out struct {
			Value    string `json:"value"`
			Revision string `json:"revision"`
		}
		if err := json.Unmarshal(resp.GetPayloadJson(), &out); err != nil || out.Value != "hello" {
			t.Fatalf("set payload = %s", resp.GetPayloadJson())
		}

		stale := e.invoke("default", "noop.set", map[string]string{"value": "again"}, pre...)
		if stale.GetError().GetCode() != "PRECONDITION_FAILED" {
			t.Fatalf("stale set = %v", stale)
		}

		update, err := e.client.PlanOperation(ctx, &pb.PlanOperationRequest{
			Context: requestContext("default", "op-plan-2", "en"), Operation: "noop.set", ApiVersion: "v1",
			PayloadJson: []byte(`{"value":"again"}`),
		})
		if err != nil || update.GetError() != nil {
			t.Fatalf("second plan = %v, %v", update, err)
		}
		if c := update.GetChanges()[0]; c.GetKind() != pb.PlannedChange_KIND_UPDATE ||
			string(c.GetBeforeJson()) != `"hello"` {
			t.Fatalf("update change = %v", c)
		}
		if got := update.GetPreconditions()[0].GetRevision(); got != out.Revision {
			t.Fatalf("precondition revision = %q, want %q", got, out.Revision)
		}
	})

	if _, err := e.client.Deactivate(ctx, &pb.DeactivateRequest{Context: requestContext("default", "", "en"), GracePeriodMs: 1000}); err != nil {
		t.Fatal(err)
	}
	stop, err := e.client.Stop(ctx, &pb.StopRequest{Context: requestContext("default", "", "en"), Drain: true, GracePeriodMs: 1000})
	if err != nil || !stop.GetDrained() {
		t.Fatalf("Stop = %v, %v", stop, err)
	}
	if _, err := e.client.ReleaseInstance(ctx, &pb.ReleaseInstanceRequest{Context: requestContext("default", "", "en")}); err != nil {
		t.Fatal(err)
	}
}

func TestNoopApplyConfig(t *testing.T) {
	e := newEnv(t)
	e.startInstance("a")
	resp, err := e.client.ApplyConfig(e.ctx(), &pb.ApplyConfigRequest{
		Context: requestContext("a", "", "en"), ConfigJson: []byte(`{}`), ProposedRevision: "2"})
	if err != nil || resp.GetError() != nil || resp.GetAppliedRevision() != "2" {
		t.Fatalf("ApplyConfig: %v %v", err, resp)
	}
	bad, err := e.client.ApplyConfig(e.ctx(), &pb.ApplyConfigRequest{
		Context: requestContext("a", "", "en"), ConfigJson: []byte(`{"x":1}`), ProposedRevision: "3"})
	if err != nil {
		t.Fatal(err)
	}
	if bad.GetError().GetCode() != "VALIDATION_FAILED" {
		t.Fatalf("bad config = %v", bad)
	}
}
