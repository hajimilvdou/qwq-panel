// SPDX-License-Identifier: Apache-2.0

package pluginsdk

import (
	"strings"
	"testing"

	"google.golang.org/grpc/codes"

	platformv1 "github.com/qwq-panel/qwq/sdk/gen/qwq/platform/v1"
)

func invokeOp(t *testing.T, env *testEnv, id, opID, locale, op string, payload []byte, pre ...*platformv1.Precondition) *platformv1.InvokeResponse {
	t.Helper()
	resp, err := env.client.Invoke(testContext(t), &platformv1.InvokeRequest{
		Context: operationContext(id, opID, locale), Operation: op, ApiVersion: "v1",
		PayloadJson: payload, Preconditions: pre, Attempt: 1,
	})
	if err != nil {
		t.Fatalf("Invoke %s: %v", op, err)
	}
	return resp
}

func TestInvokeValidationIsLocalized(t *testing.T) {
	env := newTestEnv(t, newTestPlugin())
	env.active("a", nil)

	messages := map[string]string{}
	for _, locale := range []string{"zh-CN", "en"} {
		resp := invokeOp(t, env, "a", "op-validation", locale, "test.echo", mustJSON(map[string]string{"message": ""}))
		e := resp.GetError()
		if e.GetCode() != "VALIDATION_FAILED" || len(e.GetViolations()) != 1 || resp.GetPayloadJson() != nil {
			t.Fatalf("response = %v", resp)
		}
		v := e.GetViolations()[0]
		if v.GetPointer() != "/message" || v.GetCode() != "REQUIRED" || v.GetMessage() == "" {
			t.Fatalf("violation = %v", v)
		}
		messages[locale] = v.GetMessage()
	}
	if messages["zh-CN"] == messages["en"] {
		t.Fatalf("validation message is not localized: %q", messages["en"])
	}
}

func TestInvokeUnknownOperationAndAPIVersion(t *testing.T) {
	env := newTestEnv(t, newTestPlugin())
	env.active("a", nil)

	resp := invokeOp(t, env, "a", "op-unknown", "en", "test.nope", []byte(`{}`))
	if resp.GetError().GetCode() != "UNKNOWN_OPERATION" || resp.GetPayloadJson() != nil {
		t.Fatalf("unknown operation response = %v", resp)
	}

	bad, err := env.client.Invoke(testContext(t), &platformv1.InvokeRequest{
		Context: operationContext("a", "op-version", "en"), Operation: "test.echo", ApiVersion: "v2",
		PayloadJson: mustJSON(map[string]string{"message": "x"}), Attempt: 1,
	})
	if err != nil {
		t.Fatalf("api version mismatch must stay a domain error: %v", err)
	}
	if bad.GetError().GetCode() != "UNSUPPORTED_API_VERSION" {
		t.Fatalf("response = %v", bad)
	}

	// An empty api_version is accepted for forward compatibility.
	ok := invokeOp(t, env, "a", "op-empty-version", "en", "test.echo", mustJSON(map[string]string{"message": "x"}))
	if ok.GetError() != nil {
		t.Fatalf("empty api_version: %v", ok.GetError())
	}
}

func TestInvokeInternalHidesPluginError(t *testing.T) {
	env := newTestEnv(t, newTestPlugin())
	env.active("a", nil)

	resp := invokeOp(t, env, "a", "op-internal", "en", "test.fail", []byte(`{}`))
	e := resp.GetError()
	if e.GetCode() != "INTERNAL" || strings.Contains(e.GetMessage(), "hunter2") {
		t.Fatalf("response = %v", resp)
	}
	if !env.logContains("hunter2") {
		t.Fatalf("the plugin error was not logged: %s", env.lastLog())
	}
}

func TestInvokeChangesAreValidated(t *testing.T) {
	env := newTestEnv(t, newTestPlugin())
	env.active("a", nil)

	ok := invokeOp(t, env, "a", "op-change", "en", "test.raw", mustJSON(map[string]string{"subject": "greeting"}))
	if ok.GetError() != nil || len(ok.GetChanges()) != 1 || ok.GetChanges()[0].GetSubject() != "greeting" ||
		ok.GetChanges()[0].GetRevision() != "1" {
		t.Fatalf("response = %v", ok)
	}

	bad := invokeOp(t, env, "a", "op-bad-change", "en", "test.raw", mustJSON(map[string]string{"subject": "../escape"}))
	if bad.GetError().GetCode() != "PROTOCOL_ERROR" || bad.GetPayloadJson() != nil {
		t.Fatalf("invalid change response = %v", bad)
	}
}

func TestPlanIsSideEffectFreeAndBindsPreconditions(t *testing.T) {
	env := newTestEnv(t, newTestPlugin())
	env.active("a", nil)
	ctx := testContext(t)

	plan, err := env.client.PlanOperation(ctx, &platformv1.PlanOperationRequest{
		Context: operationContext("a", "op-plan", "en"), Operation: "test.set", ApiVersion: "v1",
		PayloadJson: mustJSON(map[string]string{"value": "hi"}),
	})
	if err != nil || plan.GetError() != nil {
		t.Fatalf("PlanOperation: %v %v", err, plan.GetError())
	}
	changes := plan.GetChanges()
	if len(changes) != 1 || changes[0].GetKind() != platformv1.PlannedChange_KIND_CREATE ||
		changes[0].GetSubject() != "value" || changes[0].GetPointer() != "/value" ||
		string(changes[0].GetAfterJson()) != `"hi"` || changes[0].GetBeforeJson() != nil ||
		changes[0].GetDescription() == "" || !changes[0].GetReversible() {
		t.Fatalf("planned changes = %v", changes)
	}
	pre := plan.GetPreconditions()
	if len(pre) != 1 || pre[0].GetSubject() != "value" || pre[0].GetRevision() != "" {
		t.Fatalf("preconditions = %v", pre)
	}
	if n := env.host.count("PutState"); n != 0 {
		t.Fatalf("PlanOperation wrote state %d times", n)
	}

	executed := invokeOp(t, env, "a", "op-exec", "en", "test.set", mustJSON(map[string]string{"value": "hi"}), pre...)
	if executed.GetError() != nil || len(executed.GetChanges()) != 1 {
		t.Fatalf("execute = %v", executed)
	}
	var out setResponse
	if err := unmarshalJSON(executed.GetPayloadJson(), &out); err != nil || out.Value != "hi" || out.Revision == "" {
		t.Fatalf("payload = %s, %v", executed.GetPayloadJson(), err)
	}
	if e, ok := env.host.stateOf(handleFor("a"), "value"); !ok || string(e.value) != `"hi"` || e.revision != out.Revision {
		t.Fatalf("stored = %q @%s", e.value, e.revision)
	}

	// The same preconditions are stale now.
	stale := invokeOp(t, env, "a", "op-stale", "en", "test.set", mustJSON(map[string]string{"value": "hey"}), pre...)
	if stale.GetError().GetCode() != "PRECONDITION_FAILED" {
		t.Fatalf("stale execute = %v", stale)
	}
	if e, _ := env.host.stateOf(handleFor("a"), "value"); string(e.value) != `"hi"` {
		t.Fatalf("stale execute changed the value to %s", e.value)
	}

	update, err := env.client.PlanOperation(ctx, &platformv1.PlanOperationRequest{
		Context: operationContext("a", "op-plan-2", "en"), Operation: "test.set", ApiVersion: "v1",
		PayloadJson: mustJSON(map[string]string{"value": "hey"}),
	})
	if err != nil || update.GetError() != nil {
		t.Fatalf("second plan: %v %v", err, update.GetError())
	}
	c := update.GetChanges()[0]
	if c.GetKind() != platformv1.PlannedChange_KIND_UPDATE || string(c.GetBeforeJson()) != `"hi"` {
		t.Fatalf("update change = %v", c)
	}
	if got := update.GetPreconditions()[0].GetRevision(); got != out.Revision {
		t.Fatalf("precondition revision = %q, want %q", got, out.Revision)
	}
}

func TestPlanNonPlannableOperation(t *testing.T) {
	env := newTestEnv(t, newTestPlugin())
	env.active("a", nil)
	resp, err := env.client.PlanOperation(testContext(t), &platformv1.PlanOperationRequest{
		Context: operationContext("a", "op-plan", "zh-CN"), Operation: "test.echo", ApiVersion: "v1",
		PayloadJson: mustJSON(map[string]string{"message": "x"}),
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.GetError().GetCode() != "NOT_PLANNABLE" || !strings.Contains(resp.GetError().GetMessage(), "test.echo") {
		t.Fatalf("response = %v", resp)
	}
}

func TestConfigValidateAndApply(t *testing.T) {
	env := newTestEnv(t, newTestPlugin())
	env.active("a", nil)
	ctx := testContext(t)

	invalid, err := env.client.ValidateConfig(ctx, &platformv1.ValidateConfigRequest{
		Context: operationContext("a", "op-config", "en"), ConfigJson: []byte(`{"bad":true}`), ProposedRevision: "2"})
	if err != nil || invalid.GetError() != nil {
		t.Fatalf("ValidateConfig: %v %v", err, invalid.GetError())
	}
	if len(invalid.GetViolations()) != 1 || invalid.GetViolations()[0].GetPointer() != "/bad" ||
		len(invalid.GetWarnings()) != 1 {
		t.Fatalf("validation = %v", invalid)
	}

	apply, err := env.client.ApplyConfig(ctx, &platformv1.ApplyConfigRequest{
		Context: operationContext("a", "op-config", "en"), ConfigJson: []byte(`{"greeting":"x"}`), ProposedRevision: "2"})
	if err != nil || apply.GetError() != nil || apply.GetAppliedRevision() != "2" {
		t.Fatalf("ApplyConfig: %v %v %v", apply, err, apply.GetError())
	}
	health, _ := env.client.CheckHealth(ctx, &platformv1.CheckHealthRequest{Context: lifecycleContext("a")})
	if health.GetAppliedConfigRevision() != "2" {
		t.Fatalf("applied revision = %q", health.GetAppliedConfigRevision())
	}
	inst := env.instance("a")
	if string(inst.Config()) != `{"greeting":"x"}` || inst.ConfigRevision() != "2" {
		t.Fatalf("instance config = %s @%s", inst.Config(), inst.ConfigRevision())
	}

	failed, err := env.client.ApplyConfig(ctx, &platformv1.ApplyConfigRequest{
		Context: operationContext("a", "op-config", "en"), ConfigJson: []byte(`{"fail":true}`), ProposedRevision: "3"})
	if err != nil {
		t.Fatalf("a domain failure must keep the gRPC status OK: %v", err)
	}
	if failed.GetError().GetCode() != "VALIDATION_FAILED" || failed.GetAppliedRevision() != "" {
		t.Fatalf("failed apply = %v", failed)
	}
	if got := inst.ConfigRevision(); got != "2" {
		t.Fatalf("revision after failed apply = %q", got)
	}
}

func TestPublicRoute(t *testing.T) {
	env := newTestEnv(t, newTestPlugin())
	env.active("a", nil)
	ctx := testContext(t)

	resp, err := env.client.ServePublicRoute(ctx, &platformv1.ServePublicRouteRequest{
		Context: operationContext("a", "op-public", "en"), Route: "status", Method: "GET", Path: "/hello",
		RawQuery: "x=1", Headers: []*platformv1.HttpHeader{{Name: "accept", Value: "text/plain"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.GetStatus() != 201 || string(resp.GetBody()) != "route:/hello" ||
		len(resp.GetHeaders()) != 1 || resp.GetHeaders()[0].GetName() != "x-test" {
		t.Fatalf("route response = %v", resp)
	}

	_, err = env.client.ServePublicRoute(ctx, &platformv1.ServePublicRouteRequest{
		Context: operationContext("a", "op-public", "en"), Route: "status", Method: "GET", Path: "/error"})
	wantCode(t, err, codes.InvalidArgument)
}
