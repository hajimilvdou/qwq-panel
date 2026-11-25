// SPDX-License-Identifier: AGPL-3.0-only

package api_test

import (
	"context"
	"net/http"
	"testing"

	"github.com/qwq-panel/qwq/internal/api"
	"github.com/qwq-panel/qwq/internal/operations"
	"github.com/qwq-panel/qwq/internal/platform/problem"
	"github.com/qwq-panel/qwq/sdk/manifest"
)

type humanInvokeCatalog struct{ base readHTTPJobCatalog }

func (c humanInvokeCatalog) Action(id string) (operations.Action, bool) {
	entry, found := c.base.catalog.Get(id)
	if !found {
		return operations.Action{}, false
	}
	caps := make([]operations.Capability, 0, len(entry.Capabilities))
	for _, cp := range entry.Capabilities {
		caps = append(caps, operations.Capability{Name: cp.Name, Scope: cp.Scope})
	}
	return operations.Action{
		ID: entry.ID, Summary: entry.Summary, Effect: entry.Effect, Risk: entry.DeclaredRisk,
		Mode: entry.Mode, Idempotent: entry.Idempotent, Permission: entry.Permission,
		Source: operations.PluginSource, PluginID: entry.PluginID, Placement: entry.Placement,
		Operation: entry.Operation, APIVersion: entry.APIVersion, TimeoutMS: 60000,
		Approval: entry.Approval, Reachability: entry.Reachability, Capabilities: caps,
		ArgsSchema: entry.ArgsSchema,
	}, true
}

type callbackDispatcher struct {
	readHTTPJobDispatcher
	onInvoke func(ctx context.Context, req operations.PluginInvokeRequest) error
}

func (d *callbackDispatcher) Invoke(ctx context.Context, req operations.PluginInvokeRequest) (operations.PluginInvokeResponse, error) {
	if d.onInvoke != nil {
		if err := d.onInvoke(ctx, req); err != nil {
			return operations.PluginInvokeResponse{}, err
		}
	}
	return d.readHTTPJobDispatcher.Invoke(ctx, req)
}

func TestHumanPluginDirectInvokeRespectsApprovalLevels(t *testing.T) {
	var service *operations.Service
	dispatch := &callbackDispatcher{readHTTPJobDispatcher: readHTTPJobDispatcher{started: make(chan operations.PluginRunJobRequest, 4)}}
	dispatch.onInvoke = func(ctx context.Context, req operations.PluginInvokeRequest) error {
		if req.Operation == "warp.register" {
			// Simulate plugin invoking host secret.reveal on a fresh gRPC context
			// (no PermissionMode on ctx) while the operation is actively running.
			accepted, err := service.ResolveDispatchedInstance(context.Background(), req.PluginID, operations.ControllerDispatchInstance, "local", req.OperationID)
			if err != nil {
				return err
			}
			accepted.Clear()
		}
		return nil
	}

	e := newEnvWith(t, func(deps *api.Deps) {
		deps.Ops.Stop()
		authorization := readHTTPJobAuthorization{deps.Authz}
		var err error
		service, err = operations.New(operations.Options{
			DB: deps.DB, Clock: deps.Clock, IDs: deps.IDs, NodeID: "local",
			Catalog: humanInvokeCatalog{readHTTPJobCatalog{deps.Catalog}}, Dispatcher: dispatch,
			Authorizer: authorization, Policy: authorization,
			Config: operations.Config{JobWorkers: 1, JobQueue: 4, MaxAttempts: 1},
		})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(service.Stop)
		if err := service.Start(t.Context()); err != nil {
			t.Fatal(err)
		}
		deps.Ops = service
	})

	reachTrue := true
	m := &manifest.Manifest{
		ID: "acme.proxy", Placement: "controller",
		Capabilities: []manifest.Capability{
			{Name: "network.proxy", Scope: "direct"},
			{Name: "network.egress", Scope: "chain"},
			{Name: "secret.reveal", Scope: "operation"},
		},
		Operations: []manifest.Operation{
			{
				Name: "warp.register", Summary: "Register WARP", Effect: "write", Risk: "low",
				Mode: "invoke", Approval: "ai_confirm", Permission: "acme.proxy:manage", APIVersion: "v1",
				Capabilities: []manifest.CapabilityRef{
					{Name: "network.proxy", Scope: "direct"},
					{Name: "secret.reveal", Scope: "operation"},
				},
			},
			{
				Name: "channel.test", Summary: "Test egress", Effect: "write", Risk: "low",
				Mode: "invoke", Approval: "auto", Permission: "acme.proxy:manage", APIVersion: "v1",
				Capabilities: []manifest.CapabilityRef{{Name: "network.egress", Scope: "chain"}},
			},
			{
				Name: "warp.delete", Summary: "Delete WARP", Effect: "destructive", Risk: "high",
				Mode: "invoke", Approval: "confirm", Permission: "acme.proxy:manage", APIVersion: "v1",
				Capabilities: []manifest.CapabilityRef{{Name: "network.proxy", Scope: "direct"}},
			},
			{
				Name: "fw.apply", Summary: "Apply firewall", Effect: "write", Risk: "high",
				Mode: "invoke", Approval: "ai_confirm", Reachability: &reachTrue, Permission: "acme.proxy:manage", APIVersion: "v1",
			},
			{
				Name: "strict.write", Summary: "Strict confirm", Effect: "write", Risk: "low",
				Mode: "invoke", Approval: "confirm", Permission: "acme.proxy:manage", APIVersion: "v1",
			},
		},
	}
	if err := e.c.Catalog().SetPlugin(m, func(string) ([]byte, error) { return []byte(`{"type":"object"}`), nil }); err != nil {
		t.Fatal(err)
	}

	admin := e.setupAdmin(adminUser)

	// 1. Direct human browser click on ai_confirm (with network.proxy + secret.reveal)
	//    executes immediately AND ResolveDispatchedInstance succeeds inside the handler.
	req := withIdempotency(admin.sign(http.MethodPost, "/api/v1/plugins/acme.proxy/operations/warp.register", `{"payload":{}}`), idempotencyKey(10))
	res := e.do(req).expect(t, http.StatusOK).decodeMap(t)
	if res["status"] != "SUCCEEDED" {
		t.Fatalf("human warp.register status = %v, want SUCCEEDED", res["status"])
	}

	// 2. Direct human browser click on auto (with network.egress) executes immediately.
	reqAuto := withIdempotency(admin.sign(http.MethodPost, "/api/v1/plugins/acme.proxy/operations/channel.test", `{"payload":{}}`), idempotencyKey(11))
	resAuto := e.do(reqAuto).expect(t, http.StatusOK).decodeMap(t)
	if resAuto["status"] != "SUCCEEDED" {
		t.Fatalf("human channel.test status = %v, want SUCCEEDED", resAuto["status"])
	}

	// 3. Destructive, reachability, and explicit confirm operations still queue AWAITING_APPROVAL.
	for i, op := range []string{"warp.delete", "fw.apply", "strict.write"} {
		r := withIdempotency(admin.sign(http.MethodPost, "/api/v1/plugins/acme.proxy/operations/"+op, `{"payload":{}}`), idempotencyKey(50+i))
		out := e.do(r).expect(t, http.StatusAccepted).decodeMap(t)
		if out["status"] != "AWAITING_APPROVAL" {
			t.Fatalf("human %s status = %v, want AWAITING_APPROVAL", op, out["status"])
		}
	}

	// 4. Explicit PermissionReadOnly on context is never widened.
	roReq := withIdempotency(admin.sign(http.MethodPost, "/api/v1/plugins/acme.proxy/operations/warp.register", `{"payload":{}}`), idempotencyKey(12))
	roReq = roReq.WithContext(operations.WithPermissionMode(roReq.Context(), operations.PermissionReadOnly))
	e.do(roReq).expectProblem(t, http.StatusForbidden, problem.PermissionDenied)

	// 5. Service account (non-human session) invoking the same ai_confirm op still awaits approval.
	svcReq := newRequest(http.MethodPost, "/api/v1/plugins/acme.proxy/operations/warp.register", `{"payload":{}}`)
	svcReq.Header.Set("Authorization", "Bearer "+e.serviceToken(admin))
	svcReq.Header.Set("Idempotency-Key", idempotencyKey(13))
	svcOut := e.do(svcReq).expect(t, http.StatusAccepted).decodeMap(t)
	if svcOut["status"] != "AWAITING_APPROVAL" {
		t.Fatalf("service account warp.register status = %v, want AWAITING_APPROVAL", svcOut["status"])
	}
}
