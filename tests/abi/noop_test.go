// SPDX-License-Identifier: AGPL-3.0-only

package abi_test

import (
	"crypto/rand"
	"encoding/json"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"

	"github.com/qwq-panel/qwq/sdk/abi"
	pb "github.com/qwq-panel/qwq/sdk/gen/qwq/platform/v1"
)

// Scenario one: an empty plugin, one process serving two instances (ADR-0002).

func reqCtx(inst *hostInstance, locale string) *pb.RequestContext {
	return &pb.RequestContext{RequestId: rand.Text(), TraceId: rand.Text(), Actor: human("admin"),
		NodeId: inst.plugin.node, InstanceId: inst.id, Locale: locale}
}

func echo(t *testing.T, inst *hostInstance, msg string) (*pb.InvokeResponse, error) {
	t.Helper()
	return inst.plugin.client.Invoke(testCtx(t), &pb.InvokeRequest{Context: reqCtx(inst, "zh-CN"),
		Operation: "noop.echo", ApiVersion: "v1", PayloadJson: mustJSON(map[string]string{"message": msg}), Attempt: 1})
}

func wantEcho(t *testing.T, inst *hostInstance, msg string) {
	t.Helper()
	resp, err := echo(t, inst, msg)
	if err != nil || resp.GetError() != nil {
		t.Fatalf("echo on %s: %v %v", inst.id, err, resp.GetError())
	}
	var out struct {
		Message    string `json:"message"`
		InstanceID string `json:"instance_id"`
	}
	if err := json.Unmarshal(resp.GetPayloadJson(), &out); err != nil || out.Message != msg || out.InstanceID != inst.id {
		t.Fatalf("echo on %s returned %s", inst.id, resp.GetPayloadJson())
	}
}

func wantHealth(t *testing.T, inst *hostInstance, st pb.CheckHealthResponse_Status, ls pb.LifecycleState) {
	t.Helper()
	resp, err := inst.plugin.client.CheckHealth(testCtx(t), &pb.CheckHealthRequest{Context: lifecycleContext(inst)})
	if err != nil {
		t.Fatalf("CheckHealth %s: %v", inst.id, err)
	}
	if resp.GetStatus() != st || resp.GetLifecycleState() != ls || resp.GetAppliedConfigRevision() != inst.configRev {
		t.Fatalf("CheckHealth %s = %v/%v/rev %q, want %v/%v/rev %q", inst.id, resp.GetStatus(), resp.GetLifecycleState(),
			resp.GetAppliedConfigRevision(), st, ls, inst.configRev)
	}
}

func planRename(t *testing.T, inst *hostInstance, greeting string) *pb.PlanOperationResponse {
	t.Helper()
	resp, err := inst.plugin.client.PlanOperation(testCtx(t), &pb.PlanOperationRequest{Context: reqCtx(inst, "en"),
		Operation: "noop.rename", ApiVersion: "v1", PayloadJson: mustJSON(map[string]string{"greeting": greeting})})
	if err != nil || resp.GetError() != nil {
		t.Fatalf("PlanOperation on %s: %v %v", inst.id, err, resp.GetError())
	}
	return resp
}

func rename(t *testing.T, inst *hostInstance, greeting string, pre []*pb.Precondition) *pb.InvokeResponse {
	t.Helper()
	resp, err := inst.plugin.client.Invoke(testCtx(t), &pb.InvokeRequest{Context: reqCtx(inst, "en"),
		Operation: "noop.rename", ApiVersion: "v1", PayloadJson: mustJSON(map[string]string{"greeting": greeting}),
		Preconditions: pre, Attempt: 1})
	if err != nil {
		t.Fatalf("rename on %s: %v", inst.id, err)
	}
	return resp
}

func TestNoopDescriptorAndABI(t *testing.T) {
	h := newFakeHost(t)
	hp := h.mustLoad(t, "local", newNoopPlugin())
	if d := hp.desc; d.GetAbiMajor() != abi.Major || d.GetPluginId() != "noop" || len(d.GetOperations()) != 2 {
		t.Fatalf("descriptor = %v", d)
	}
	for _, bad := range []func(*pb.PluginDescriptor){
		func(d *pb.PluginDescriptor) { d.AbiMajor = abi.Major + 1 },
		func(d *pb.PluginDescriptor) { d.AbiMinor = hostMinor + 1 },
	} {
		p := newNoopPlugin()
		bad(p.desc)
		if _, err := h.load(t, "local", p); err == nil {
			t.Fatalf("host loaded an incompatible plugin: ABI %d.%d", p.desc.GetAbiMajor(), p.desc.GetAbiMinor())
		}
	}
}

func TestNoopLifecycleTwoInstances(t *testing.T) {
	h := newFakeHost(t)
	p := newNoopPlugin()
	hp := h.mustLoad(t, "local", p)
	ctx := testCtx(t)

	a, ra := h.initialize(t, hp, "a", "3", mustJSON(map[string]string{"greeting": "hello"}))
	b, _ := h.initialize(t, hp, "b", "7", nil)
	if ra.GetStateSchemaVersion() != "1" {
		t.Fatalf("state_schema_version = %q", ra.GetStateSchemaVersion())
	}
	p.mu.Lock()
	if p.insts["a"].handle != a.handle || p.insts["b"].handle != b.handle || a.handle == b.handle {
		t.Fatal("instances did not keep their own instance_handle")
	}
	p.mu.Unlock()
	for _, inst := range []*hostInstance{a, b} {
		wantHealth(t, inst, pb.CheckHealthResponse_STATUS_NOT_SERVING, pb.LifecycleState_LIFECYCLE_STATE_INITIALIZED)
		if _, err := hp.client.Start(ctx, &pb.StartRequest{Context: lifecycleContext(inst)}); err != nil {
			t.Fatal(err)
		}
		wantHealth(t, inst, pb.CheckHealthResponse_STATUS_SERVING, pb.LifecycleState_LIFECYCLE_STATE_READY)
		if _, err := hp.client.Activate(ctx, &pb.ActivateRequest{Context: lifecycleContext(inst)}); err != nil {
			t.Fatal(err)
		}
		h.setActive(inst, true)
		wantHealth(t, inst, pb.CheckHealthResponse_STATUS_SERVING, pb.LifecycleState_LIFECYCLE_STATE_ACTIVE)
		wantEcho(t, inst, "hi from "+inst.id)
	}
	// The handle maps a host call to the right instance of the shared process.
	cfg := pb.NewHostConfigServiceClient(p.hostConn())
	for _, inst := range []*hostInstance{a, b} {
		got, err := cfg.GetConfig(ctx, &pb.GetConfigRequest{Context: &pb.HostCallContext{InstanceHandle: inst.handle}})
		if err != nil || got.GetRevision() != inst.configRev {
			t.Fatalf("GetConfig for %s = %v, %v", inst.id, got, err)
		}
	}

	t.Run("plan has no side effects and binds preconditions", func(t *testing.T) {
		first, second := planRename(t, a, "hi"), planRename(t, a, "hi")
		c := first.GetChanges()
		if len(c) != 1 || c[0].GetKind() != pb.PlannedChange_KIND_UPDATE || c[0].GetSubject() != "greeting" ||
			string(c[0].GetBeforeJson()) != `"hello"` || string(c[0].GetAfterJson()) != `"hi"` || c[0].GetDescription() == "" {
			t.Fatalf("planned changes = %v", c)
		}
		pre := first.GetPreconditions()
		if len(pre) != 1 || pre[0].GetSubject() != "greeting" || pre[0].GetRevision() != "1" {
			t.Fatalf("preconditions = %v", pre)
		}
		if !proto.Equal(first, second) {
			t.Fatal("planning twice gave different preconditions")
		}
		ok := rename(t, a, "hi", pre)
		if ok.GetError() != nil || len(ok.GetChanges()) != 1 || ok.GetChanges()[0].GetRevision() != "2" {
			t.Fatalf("rename with fresh preconditions = %v", ok)
		}
		if stale := rename(t, a, "hey", pre); stale.GetError().GetCode() != "PRECONDITION_FAILED" {
			t.Fatalf("rename with stale preconditions = %v", stale)
		}
		nb := planRename(t, b, "hi")
		if nb.GetChanges()[0].GetKind() != pb.PlannedChange_KIND_CREATE || nb.GetPreconditions()[0].GetRevision() != "" {
			t.Fatalf("plan on an instance without a greeting = %v", nb)
		}
	})

	// Deactivate stops background work only.
	if _, err := hp.client.Deactivate(ctx, &pb.DeactivateRequest{Context: lifecycleContext(a), GracePeriodMs: 1000}); err != nil {
		t.Fatal(err)
	}
	h.setActive(a, false)
	wantHealth(t, a, pb.CheckHealthResponse_STATUS_SERVING, pb.LifecycleState_LIFECYCLE_STATE_READY)
	wantEcho(t, a, "still serving")

	// Stop(drain) waits for the in-flight call and refuses new ones meanwhile.
	draining := make(chan string, 1)
	p.mu.Lock()
	p.draining = draining
	p.mu.Unlock()
	held := make(chan error, 1)
	go func() { _, err := echo(t, a, "hold"); held <- err }()
	recv(t, p.held, "held echo")
	stopped := make(chan *pb.StopResponse, 1)
	go func() {
		resp, _ := hp.client.Stop(ctx, &pb.StopRequest{Context: lifecycleContext(a), Drain: true, GracePeriodMs: 3000})
		stopped <- resp
	}()
	recv(t, draining, "drain start")
	_, err := echo(t, a, "too late")
	wantCode(t, err, codes.FailedPrecondition)
	wantHealth(t, a, pb.CheckHealthResponse_STATUS_NOT_SERVING, pb.LifecycleState_LIFECYCLE_STATE_DRAINING)
	wantEcho(t, b, "b is not affected")
	close(p.release)
	if err := recv(t, held, "held echo result"); err != nil {
		t.Fatalf("in-flight call during drain: %v", err)
	}
	if resp := recv(t, stopped, "Stop"); !resp.GetDrained() {
		t.Fatalf("Stop = %v, want drained", resp)
	}
	wantHealth(t, a, pb.CheckHealthResponse_STATUS_NOT_SERVING, pb.LifecycleState_LIFECYCLE_STATE_STOPPED)
	_, err = echo(t, a, "stopped")
	wantCode(t, err, codes.FailedPrecondition)

	// ReleaseInstance frees a; host-side cleanup invalidates its handle.
	if _, err := hp.client.ReleaseInstance(ctx, &pb.ReleaseInstanceRequest{Context: lifecycleContext(a)}); err != nil {
		t.Fatal(err)
	}
	h.cleanupOwner(a)
	_, err = echo(t, a, "released")
	wantCode(t, err, codes.NotFound)
	_, err = hp.client.CheckHealth(ctx, &pb.CheckHealthRequest{Context: lifecycleContext(a)})
	wantCode(t, err, codes.NotFound)
	_, err = cfg.GetConfig(ctx, &pb.GetConfigRequest{Context: &pb.HostCallContext{InstanceHandle: a.handle}})
	wantCode(t, err, codes.Unauthenticated)

	wantHealth(t, b, pb.CheckHealthResponse_STATUS_SERVING, pb.LifecycleState_LIFECYCLE_STATE_ACTIVE)
	wantEcho(t, b, "b still works")
}

func TestNoopUnimplementedRPCs(t *testing.T) {
	h := newFakeHost(t)
	p := newNoopPlugin()
	hp := h.mustLoad(t, "local", p)
	inst := h.start(t, hp, "default", nil)
	ctx := testCtx(t)

	_, err := hp.client.ServePublicRoute(ctx, &pb.ServePublicRouteRequest{Context: reqCtx(inst, "en"), Route: "sub", Method: "GET", Path: "/"})
	wantCode(t, err, codes.Unimplemented)
	_, err = hp.client.ValidateConfig(ctx, &pb.ValidateConfigRequest{Context: reqCtx(inst, "en"), ConfigJson: []byte(`{}`)})
	wantCode(t, err, codes.Unimplemented)
	stream, err := hp.client.RunJob(ctx, &pb.RunJobRequest{Context: reqCtx(inst, "en"), Operation: "noop.echo", Attempt: 1})
	if err == nil {
		_, err = stream.Recv()
	}
	wantCode(t, err, codes.Unimplemented)

	// Host side: services that need a capability the plugin lacks are not registered.
	hc := &pb.HostCallContext{InstanceHandle: inst.handle}
	_, err = pb.NewHostSecretsServiceClient(p.hostConn()).RevealSecret(ctx, &pb.RevealSecretRequest{Context: hc, SecretRef: "x"})
	wantCode(t, err, codes.Unimplemented)
	_, err = pb.NewHostInvokeServiceClient(p.hostConn()).InvokePlugin(ctx, &pb.InvokePluginRequest{Context: hc})
	wantCode(t, err, codes.Unimplemented)
}

// A host on a newer minor sends fields this SDK does not know: decoding keeps them as unknown
// fields, known fields are unchanged and re-encoding preserves them (a relay does not drop them).
func TestNoopForwardCompatibility(t *testing.T) {
	orig := &pb.InvokeRequest{
		Context:   &pb.RequestContext{RequestId: "r1", OperationId: "op-1", Actor: human("u1"), InstanceId: "a", Locale: "en"},
		Operation: "noop.echo", ApiVersion: "v1", PayloadJson: []byte(`{"message":"x"}`), Attempt: 1,
	}
	wire, err := proto.Marshal(orig)
	if err != nil {
		t.Fatal(err)
	}
	topUnknown := protowire.AppendVarint(protowire.AppendTag(nil, 99, protowire.VarintType), 7)
	ctxUnknown := protowire.AppendString(protowire.AppendTag(nil, 50, protowire.BytesType), "tenant-1")
	// A second occurrence of field 1 (context) is merged into the first by the decoder.
	wire = append(wire, topUnknown...)
	wire = protowire.AppendBytes(protowire.AppendTag(wire, 1, protowire.BytesType), ctxUnknown)

	got := &pb.InvokeRequest{}
	if err := proto.Unmarshal(wire, got); err != nil {
		t.Fatalf("old code rejected a newer message: %v", err)
	}
	if string(got.ProtoReflect().GetUnknown()) != string(topUnknown) ||
		string(got.GetContext().ProtoReflect().GetUnknown()) != string(ctxUnknown) {
		t.Fatal("unknown fields were not kept")
	}
	again, err := proto.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	reparsed := &pb.InvokeRequest{}
	if err := proto.Unmarshal(again, reparsed); err != nil {
		t.Fatal(err)
	}
	if string(reparsed.ProtoReflect().GetUnknown()) != string(topUnknown) ||
		string(reparsed.GetContext().ProtoReflect().GetUnknown()) != string(ctxUnknown) {
		t.Fatal("re-encoding dropped unknown fields")
	}
	got.ProtoReflect().SetUnknown(nil)
	got.GetContext().ProtoReflect().SetUnknown(nil)
	if !proto.Equal(got, orig) {
		t.Fatalf("known fields changed: %v", got)
	}

	t.Run("unknown enum value", func(t *testing.T) {
		// OperationState 10 does not exist in v1.0; proto3 enums are open, so it decodes as 10.
		w := protowire.AppendVarint(protowire.AppendTag(nil, 1, protowire.VarintType), 10)
		resp := &pb.WaitOperationResponse{}
		if err := proto.Unmarshal(w, resp); err != nil || resp.GetState() != 10 {
			t.Fatalf("decode unknown enum: %v %v", resp.GetState(), err)
		}
		// An old SDK cannot tell whether the new state is terminal (see report).
		if terminal(resp.GetState()) {
			t.Fatal("unknown state classified as terminal")
		}
	})

	t.Run("over gRPC", func(t *testing.T) {
		h := newFakeHost(t)
		hp := h.mustLoad(t, "local", newNoopPlugin())
		inst := h.start(t, hp, "a", nil)
		req := proto.Clone(orig).(*pb.InvokeRequest)
		req.Context = reqCtx(inst, "en")
		req.ProtoReflect().SetUnknown(topUnknown)
		req.GetContext().ProtoReflect().SetUnknown(ctxUnknown)
		resp, err := hp.client.Invoke(testCtx(t), req)
		if err != nil || resp.GetError() != nil {
			t.Fatalf("Invoke with unknown fields: %v %v", err, resp.GetError())
		}
		var out struct {
			Unknown int `json:"unknown_bytes"`
		}
		if err := json.Unmarshal(resp.GetPayloadJson(), &out); err != nil || out.Unknown != len(topUnknown)+len(ctxUnknown) {
			t.Fatalf("plugin saw %d unknown bytes, want %d", out.Unknown, len(topUnknown)+len(ctxUnknown))
		}
	})
}

// A call that reached the handler and failed on the payload is gRPC OK with
// ErrorDetail{VALIDATION_FAILED, violations}; the messages follow RequestContext.locale.
func TestNoopValidationError(t *testing.T) {
	h := newFakeHost(t)
	hp := h.mustLoad(t, "local", newNoopPlugin())
	inst := h.start(t, hp, "default", nil)
	cases := []struct {
		name, payload, pointer, code string
	}{
		{"missing", `{}`, "/message", "REQUIRED"},
		{"wrong type", `{"message":42}`, "/message", "TYPE"},
		{"too long", string(mustJSON(map[string]string{"message": strings.Repeat("x", 65)})), "/message", "LENGTH"},
		{"not an object", `[1]`, "", "INVALID_JSON"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			msgs := map[string]string{}
			for _, locale := range []string{"zh-CN", "en"} {
				resp, err := hp.client.Invoke(testCtx(t), &pb.InvokeRequest{Context: reqCtx(inst, locale),
					Operation: "noop.echo", ApiVersion: "v1", PayloadJson: []byte(c.payload), Attempt: 1})
				if err != nil {
					t.Fatalf("gRPC error %v, want OK with ErrorDetail", err)
				}
				e := resp.GetError()
				if e.GetCode() != "VALIDATION_FAILED" || len(e.GetViolations()) != 1 || resp.GetPayloadJson() != nil {
					t.Fatalf("response = %v", resp)
				}
				v := e.GetViolations()[0]
				if v.GetPointer() != c.pointer || v.GetCode() != c.code || v.GetMessage() == "" {
					t.Fatalf("violation = %v, want %s %s", v, c.pointer, c.code)
				}
				msgs[locale] = v.GetMessage()
			}
			if msgs["zh-CN"] == msgs["en"] {
				t.Fatalf("message not localized: %q", msgs["en"])
			}
		})
	}
}
