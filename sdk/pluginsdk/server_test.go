// SPDX-License-Identifier: Apache-2.0

package pluginsdk

import (
	"strings"
	"testing"

	"google.golang.org/grpc/codes"

	platformv1 "github.com/qwq-panel/qwq/sdk/gen/qwq/platform/v1"
)

func TestDescriptorMatchesManifest(t *testing.T) {
	env := newTestEnv(t, newTestPlugin())
	resp, err := env.client.GetDescriptor(testContext(t), &platformv1.GetDescriptorRequest{})
	if err != nil {
		t.Fatal(err)
	}
	d := resp.GetDescriptor_()
	m := parseFixture(t, fixtureManifest(0, defaultOps, defaultCaps))

	if d.GetPluginId() != m.ID || d.GetPluginVersion() != m.Version ||
		d.GetAbiMajor() != uint32(m.ABI.Major) || d.GetAbiMinor() != uint32(m.ABI.MinimumMinor) ||
		d.GetPlacement() != platformv1.Placement_PLACEMENT_NODE ||
		d.GetStateSchemaVersion() != m.State.SchemaVersion ||
		d.GetMinimumRollbackVersion() != m.State.MinimumRollbackVersion ||
		d.GetConfigSchemaRef() != m.Config.Schema ||
		d.GetConfigHotApply() != m.Config.HotApply {
		t.Fatalf("descriptor does not match the manifest: %v", d)
	}
	if len(d.GetCapabilities()) != len(m.Capabilities) {
		t.Fatalf("%d capabilities, want %d", len(d.GetCapabilities()), len(m.Capabilities))
	}
	if len(d.GetOperations()) != len(m.Operations) {
		t.Fatalf("%d operations, want %d", len(d.GetOperations()), len(m.Operations))
	}
	for idx, op := range m.Operations {
		got := d.GetOperations()[idx]
		if got.GetName() != op.Name || got.GetApiVersion() != op.APIVersion ||
			got.GetPermission() != op.Permission || got.GetMode().String() != "OPERATION_MODE_"+
			strings.ToUpper(op.Mode) || got.GetTimeoutMs() != int32(op.TimeoutMS) ||
			got.GetSummary() != op.Summary || got.GetRequestSchemaRef() != op.RequestSchema ||
			got.GetResponseSchemaRef() != op.ResponseSchema || got.GetPlannable() != op.EffectivePlannable() ||
			got.GetIdempotent() != op.Idempotent {
			t.Fatalf("operation %d = %v, want %s", idx, got, op.Name)
		}
		if len(got.GetCapabilities()) != len(op.Capabilities) {
			t.Fatalf("operation %s has %d capabilities, want %d", op.Name, len(got.GetCapabilities()), len(op.Capabilities))
		}
	}
}

func TestLifecycleOrder(t *testing.T) {
	env := newTestEnv(t, newTestPlugin())
	ctx := testContext(t)

	_, err := env.client.CheckHealth(ctx, &platformv1.CheckHealthRequest{Context: lifecycleContext("missing")})
	wantCode(t, err, codes.NotFound)
	_, err = env.client.Invoke(ctx, &platformv1.InvokeRequest{Context: lifecycleContext("missing"), Operation: "test.echo"})
	wantCode(t, err, codes.NotFound)

	env.initialize("a", nil)
	health, err := env.client.CheckHealth(ctx, &platformv1.CheckHealthRequest{Context: lifecycleContext("a")})
	if err != nil {
		t.Fatal(err)
	}
	if health.GetStatus() != platformv1.CheckHealthResponse_STATUS_NOT_SERVING ||
		health.GetLifecycleState() != platformv1.LifecycleState_LIFECYCLE_STATE_INITIALIZED {
		t.Fatalf("health after Initialize = %v", health)
	}
	_, err = env.client.Invoke(ctx, &platformv1.InvokeRequest{Context: operationContext("a", "op-early", "en"), Operation: "test.echo",
		PayloadJson: mustJSON(map[string]string{"message": "x"}), Attempt: 1})
	wantCode(t, err, codes.FailedPrecondition)
	_, err = env.client.Activate(ctx, &platformv1.ActivateRequest{Context: lifecycleContext("a")})
	wantCode(t, err, codes.FailedPrecondition)

	env.start("a")
	health, _ = env.client.CheckHealth(ctx, &platformv1.CheckHealthRequest{Context: lifecycleContext("a")})
	if health.GetStatus() != platformv1.CheckHealthResponse_STATUS_SERVING ||
		health.GetLifecycleState() != platformv1.LifecycleState_LIFECYCLE_STATE_READY ||
		health.GetMessage() != "test healthy" || health.GetAppliedConfigRevision() != "1" {
		t.Fatalf("health after Start = %v", health)
	}
	if _, err := env.client.Invoke(ctx, &platformv1.InvokeRequest{Context: operationContext("a", "op-1", "en"), Operation: "test.echo",
		PayloadJson: mustJSON(map[string]string{"message": "ready"}), Attempt: 1}); err != nil {
		t.Fatalf("Invoke in READY: %v", err)
	}

	env.activate("a")
	health, _ = env.client.CheckHealth(ctx, &platformv1.CheckHealthRequest{Context: lifecycleContext("a")})
	if health.GetLifecycleState() != platformv1.LifecycleState_LIFECYCLE_STATE_ACTIVE {
		t.Fatalf("health after Activate = %v", health)
	}
	if _, err := env.client.Deactivate(ctx, &platformv1.DeactivateRequest{Context: lifecycleContext("a"), GracePeriodMs: 1000}); err != nil {
		t.Fatal(err)
	}
	health, _ = env.client.CheckHealth(ctx, &platformv1.CheckHealthRequest{Context: lifecycleContext("a")})
	if health.GetLifecycleState() != platformv1.LifecycleState_LIFECYCLE_STATE_READY {
		t.Fatalf("health after Deactivate = %v", health)
	}
	if _, err := env.client.Deactivate(ctx, &platformv1.DeactivateRequest{Context: lifecycleContext("a")}); err == nil {
		t.Fatal("Deactivate in READY succeeded")
	}

	stop, err := env.client.Stop(ctx, &platformv1.StopRequest{Context: lifecycleContext("a"), Drain: true, GracePeriodMs: 1000})
	if err != nil || !stop.GetDrained() {
		t.Fatalf("Stop = %v, %v", stop, err)
	}
	health, _ = env.client.CheckHealth(ctx, &platformv1.CheckHealthRequest{Context: lifecycleContext("a")})
	if health.GetStatus() != platformv1.CheckHealthResponse_STATUS_NOT_SERVING ||
		health.GetLifecycleState() != platformv1.LifecycleState_LIFECYCLE_STATE_STOPPED {
		t.Fatalf("health after Stop = %v", health)
	}
	_, err = env.client.Invoke(ctx, &platformv1.InvokeRequest{Context: operationContext("a", "op-2", "en"), Operation: "test.echo"})
	wantCode(t, err, codes.FailedPrecondition)
	_, err = env.client.Stop(ctx, &platformv1.StopRequest{Context: lifecycleContext("a")})
	wantCode(t, err, codes.FailedPrecondition)

	if _, err := env.client.ReleaseInstance(ctx, &platformv1.ReleaseInstanceRequest{Context: lifecycleContext("a")}); err != nil {
		t.Fatal(err)
	}
	if _, err := env.client.ReleaseInstance(ctx, &platformv1.ReleaseInstanceRequest{Context: lifecycleContext("a")}); err != nil {
		t.Fatalf("second ReleaseInstance: %v", err)
	}
	_, err = env.client.CheckHealth(ctx, &platformv1.CheckHealthRequest{Context: lifecycleContext("a")})
	wantCode(t, err, codes.NotFound)

	want := []string{"a:start", "a:activate", "a:deactivate", "a:stop", "a:release"}
	if got := env.plugin.lifecycleSnapshot(); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("lifecycle = %v, want %v", got, want)
	}
}

func TestTwoInstancesAreIsolated(t *testing.T) {
	env := newTestEnv(t, newTestPlugin())
	env.active("a", nil)
	env.active("b", nil)
	ctx := testContext(t)

	echo := func(id, msg string) echoResponse {
		t.Helper()
		resp, err := env.client.Invoke(ctx, &platformv1.InvokeRequest{
			Context: operationContext(id, "op-"+id, "en"), Operation: "test.echo",
			PayloadJson: mustJSON(map[string]string{"message": msg}), Attempt: 1,
		})
		if err != nil || resp.GetError() != nil {
			t.Fatalf("echo %s: %v %v", id, err, resp.GetError())
		}
		var out echoResponse
		if err := unmarshalJSON(resp.GetPayloadJson(), &out); err != nil {
			t.Fatal(err)
		}
		return out
	}
	if got := echo("a", "hi"); got.InstanceID != "a" {
		t.Fatalf("echo a = %+v", got)
	}
	if got := echo("b", "hi"); got.InstanceID != "b" {
		t.Fatalf("echo b = %+v", got)
	}

	// Host calls carry the instance's own handle.
	for _, id := range []string{"a", "b"} {
		resp, err := env.client.Invoke(ctx, &platformv1.InvokeRequest{
			Context: operationContext(id, "op-secret-"+id, "en"), Operation: "test.secret", Attempt: 1,
		})
		if err != nil || resp.GetError() != nil {
			t.Fatalf("secret %s: %v %v", id, err, resp.GetError())
		}
	}
	seen := map[string]bool{}
	for _, c := range env.host.callsOf("RevealSecret") {
		seen[c.Handle] = true
	}
	if !seen[handleFor("a")] || !seen[handleFor("b")] {
		t.Fatalf("host saw handles %v", seen)
	}

	// KV is namespaced by instance.
	set := func(id, value string) {
		t.Helper()
		resp, err := env.client.Invoke(ctx, &platformv1.InvokeRequest{
			Context: operationContext(id, "op-set-"+id, "en"), Operation: "test.set",
			PayloadJson: mustJSON(map[string]string{"value": value}), Attempt: 1,
		})
		if err != nil || resp.GetError() != nil {
			t.Fatalf("set %s: %v %v", id, err, resp.GetError())
		}
		if len(resp.GetChanges()) != 1 {
			t.Fatalf("set %s changes = %v", id, resp.GetChanges())
		}
	}
	set("a", "alpha")
	set("b", "beta")
	if e, ok := env.host.stateOf(handleFor("a"), "value"); !ok || string(e.value) != `"alpha"` {
		t.Fatalf("a value = %q, %v", e.value, ok)
	}
	if e, ok := env.host.stateOf(handleFor("b"), "value"); !ok || string(e.value) != `"beta"` {
		t.Fatalf("b value = %q, %v", e.value, ok)
	}

	if _, err := env.client.ReleaseInstance(ctx, &platformv1.ReleaseInstanceRequest{Context: lifecycleContext("a")}); err != nil {
		t.Fatal(err)
	}
	if got := echo("b", "still here"); got.InstanceID != "b" {
		t.Fatalf("echo b after release of a = %+v", got)
	}
	_, err := env.client.Invoke(ctx, &platformv1.InvokeRequest{
		Context: operationContext("a", "op-gone", "en"), Operation: "test.echo", PayloadJson: mustJSON(map[string]string{"message": "x"})})
	wantCode(t, err, codes.NotFound)
}

func TestInitializeValidation(t *testing.T) {
	env := newTestEnv(t, newTestPlugin())
	ctx := testContext(t)

	_, err := env.client.Initialize(ctx, &platformv1.InitializeRequest{
		Context: &platformv1.RequestContext{InstanceId: ""}, InstanceHandle: "h"})
	wantCode(t, err, codes.InvalidArgument)
	_, err = env.client.Initialize(ctx, &platformv1.InitializeRequest{Context: &platformv1.RequestContext{InstanceId: "a"}})
	wantCode(t, err, codes.InvalidArgument)

	// The SDK implements ABI 1.0, so a manifest requiring 1.1 is rejected at
	// Serve (future SDK minors exercise the host_minor check in Initialize).
	_, err = Serve(ctx, Options{Plugin: newTestPlugin(), Manifest: fixtureManifest(1, defaultOps, defaultCaps),
		Registrar: stubRegistrar{}})
	if err == nil || !strings.Contains(err.Error(), "ABI") {
		t.Fatalf("Serve with a newer required ABI = %v", err)
	}

	env.initialize("a", nil)
	_, err = env.initializeWith("a", nil, 0)
	wantCode(t, err, codes.FailedPrecondition)
}

func TestNewInstanceFailure(t *testing.T) {
	p := newTestPlugin()
	p.newErr = errTest
	env := newTestEnv(t, p)
	_, err := env.initializeWith("a", nil, 0)
	wantCode(t, err, codes.FailedPrecondition)
	if _, err := env.client.GetDescriptor(testContext(t), &platformv1.GetDescriptorRequest{}); err != nil {
		t.Fatalf("descriptor after failed Initialize: %v", err)
	}
}

func TestHandlerRegistryMustMatchManifest(t *testing.T) {
	t.Run("manifest operation without handler", func(t *testing.T) {
		p := newTestPlugin()
		p.skip["test.echo"] = true
		env := newTestEnv(t, p)
		_, err := env.initializeWith("a", nil, 0)
		wantCode(t, err, codes.FailedPrecondition)
		if !strings.Contains(err.Error(), "no invoke handler") {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("handler without manifest operation", func(t *testing.T) {
		p := newTestPlugin()
		p.extra = []string{"test.extra"}
		env := newTestEnv(t, p)
		_, err := env.initializeWith("a", nil, 0)
		wantCode(t, err, codes.FailedPrecondition)
		if !strings.Contains(err.Error(), "no manifest operation") {
			t.Fatalf("error = %v", err)
		}
	})
}

func TestMinimalPlugin(t *testing.T) {
	m := fixtureManifest(0, nil, nil)
	env := newEnv(t, minimalPlugin{}, m)
	env.active("default", nil)
	ctx := testContext(t)

	_, err := env.client.ServePublicRoute(ctx, &platformv1.ServePublicRouteRequest{
		Context: operationContext("default", "op-r", "en"), Route: "r", Method: "GET", Path: "/"})
	wantCode(t, err, codes.Unimplemented)
	if _, err := env.client.ValidateConfig(ctx, &platformv1.ValidateConfigRequest{
		Context: operationContext("default", "op-c", "en"), ConfigJson: []byte(`{}`)}); err != nil {
		t.Fatalf("ValidateConfig without a validator: %v", err)
	}
	_, err = env.client.ApplyConfig(ctx, &platformv1.ApplyConfigRequest{
		Context: operationContext("default", "op-c", "en"), ConfigJson: []byte(`{}`), ProposedRevision: "2"})
	if err != nil {
		t.Fatalf("ApplyConfig with hot_apply and no hook: %v", err)
	}

	health, err := env.client.CheckHealth(ctx, &platformv1.CheckHealthRequest{Context: lifecycleContext("default")})
	if err != nil {
		t.Fatal(err)
	}
	if health.GetMessage() != "" || !strings.Contains(string(health.GetDetailsJson()), "gomemlimit_bytes") {
		t.Fatalf("health details = %s", health.GetDetailsJson())
	}
}
