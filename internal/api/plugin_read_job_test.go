// SPDX-License-Identifier: AGPL-3.0-only

package api_test

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/qwq-panel/qwq/internal/actor"
	"github.com/qwq-panel/qwq/internal/api"
	"github.com/qwq-panel/qwq/internal/authz"
	"github.com/qwq-panel/qwq/internal/catalog"
	"github.com/qwq-panel/qwq/internal/identity"
	"github.com/qwq-panel/qwq/internal/operations"
	"github.com/qwq-panel/qwq/internal/platform/problem"
	"github.com/qwq-panel/qwq/sdk/manifest"
)

// ======================== 真实 API/身份/权限/operation，明确插件执行 fixture ========================

type readHTTPJobCatalog struct{ catalog *catalog.Catalog }

func (c readHTTPJobCatalog) Action(id string) (operations.Action, bool) {
	entry, found := c.catalog.Get(id)
	if !found {
		return operations.Action{}, false
	}
	return operations.Action{ID: entry.ID, Summary: entry.Summary, Effect: entry.Effect, Risk: entry.Risk, Mode: entry.Mode,
		Idempotent: entry.Idempotent, Permission: entry.Permission, Source: operations.PluginSource, PluginID: entry.PluginID,
		Placement: entry.Placement, Operation: entry.Operation, APIVersion: entry.APIVersion, TimeoutMS: 60000, Approval: entry.Approval}, true
}

type readHTTPJobAuthorization struct{ backend *authz.Authorizer }

func (a readHTTPJobAuthorization) Authorize(ctx context.Context, who actor.Actor, action operations.Action, _ operations.Target) error {
	permission, err := authz.ParsePermission(action.Permission)
	if err != nil {
		return err
	}
	return a.backend.Authorize(ctx, who, action.Permission, authz.Resource{Name: permission.Resource(), NodeID: "local", Action: action.ID})
}

func (a readHTTPJobAuthorization) Limits(ctx context.Context, who actor.Actor, _ operations.Action, _ operations.Target) (operations.Limits, error) {
	limits := operations.Limits{AutoApproveMaxRisk: operations.RiskLow, OnApprovalRequired: operations.ApprovalQueue}
	if who.Kind == actor.AIAgent {
		delegation, err := a.backend.Delegation(ctx, who.ID)
		if err != nil {
			return operations.Limits{}, err
		}
		policy := delegation.Policy.Normalized()
		limits.AutoApproveMaxRisk, limits.OnApprovalRequired = policy.AutoApproveMaxRisk, policy.OnApprovalRequired
	}
	if mode, ok := operations.PermissionModeFromContext(ctx); ok {
		limits.PermissionMode = mode
	}
	return limits, nil
}

type readHTTPJobDispatcher struct {
	started chan operations.PluginRunJobRequest
	jobs    atomic.Int32
	invokes atomic.Int32
}

func (*readHTTPJobDispatcher) Plan(context.Context, operations.PluginPlanRequest) (operations.Preview, error) {
	return operations.Preview{}, nil
}
func (d *readHTTPJobDispatcher) Invoke(context.Context, operations.PluginInvokeRequest) (operations.PluginInvokeResponse, error) {
	d.invokes.Add(1)
	return operations.PluginInvokeResponse{Result: json.RawMessage(`{"ready":true}`)}, nil
}
func (*readHTTPJobDispatcher) Cancel(context.Context, operations.PluginCancelRequest) error {
	return nil
}
func (d *readHTTPJobDispatcher) RunJob(ctx context.Context, request operations.PluginRunJobRequest, _ func(operations.JobProgress) error) error {
	d.jobs.Add(1)
	select {
	case d.started <- request:
	case <-ctx.Done():
		return ctx.Err()
	}
	<-ctx.Done()
	return ctx.Err()
}

func newPluginReadJobEnv(t *testing.T) (*env, *readHTTPJobDispatcher, *operations.Service) {
	t.Helper()
	dispatch := &readHTTPJobDispatcher{started: make(chan operations.PluginRunJobRequest, 8)}
	var service *operations.Service
	e := newEnvWith(t, func(deps *api.Deps) {
		// 同一真实 DB/身份/权限只有这个 fixture executor 接受新任务。
		// 控制面原 service 仍由原 c.Close 收尾；Stop 本身幂等。
		deps.Ops.Stop()
		authorization := readHTTPJobAuthorization{deps.Authz}
		var err error
		service, err = operations.New(operations.Options{DB: deps.DB, Clock: deps.Clock, IDs: deps.IDs, NodeID: "local",
			Catalog: readHTTPJobCatalog{deps.Catalog}, Dispatcher: dispatch, Authorizer: authorization, Policy: authorization,
			Config: operations.Config{JobWorkers: 1, JobQueue: 4, MaxAttempts: 1}})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(service.Stop)
		if err := service.Start(t.Context()); err != nil {
			t.Fatal(err)
		}
		deps.Ops = service
	})
	m := &manifest.Manifest{ID: "acme.demo", Placement: "controller", Operations: []manifest.Operation{
		{Name: "scan", Summary: "受控只读任务", Effect: "read", Risk: "low", Mode: "job", Idempotent: true, Permission: "plugin.acme.demo:read", APIVersion: "1"},
		{Name: "status", Summary: "同步状态", Effect: "read", Risk: "low", Mode: "invoke", Permission: "plugin.acme.demo:read", APIVersion: "1"},
		{Name: "restricted", Summary: "受权限限制的读取", Effect: "read", Risk: "low", Mode: "job", Permission: "plugin.acme.demo:manage", APIVersion: "1"},
	}, UI: &manifest.UI{Widgets: []manifest.UIWidget{{ID: "invalid-job-widget", Title: "异常登记防守", Kind: "stat", Operation: "scan", RefreshSeconds: 60, Size: "s"}}}}
	// 有意在 catalog fixture 放入异常 job widget：HTTP 防守仍只能对 read+invoke 限频。
	if err := e.c.Catalog().SetPlugin(m, func(string) ([]byte, error) { return []byte(`{"type":"object"}`), nil }); err != nil {
		t.Fatal(err)
	}
	return e, dispatch, service
}

func TestPluginReadJobNeedsKeyAndPersistsExactDispatch(t *testing.T) {
	e, dispatcher, service := newPluginReadJobEnv(t)
	admin := e.setupAdmin(adminUser)
	path := "/api/v1/plugins/acme.demo/operations/scan"
	body := `{"payload":{},"subject":"plugins/acme.demo/resources/read"}`
	e.do(admin.sign(http.MethodPost, path, body)).expectProblem(t, http.StatusBadRequest, problem.ValidationFailed)
	request := withIdempotency(admin.sign(http.MethodPost, path, body), "read-job-request-one")
	request = request.WithContext(operations.WithPermissionMode(request.Context(), operations.PermissionReadOnly))
	first := e.do(request).expect(t, http.StatusAccepted)
	result := first.decodeMap(t)
	id, _ := result["operation_id"].(string)
	if id == "" || first.header.Get("Location") != "/api/v1/operations/"+id {
		t.Fatal("只读持久任务缺少真实 operation 与 Location")
	}
	select {
	case started := <-dispatcher.started:
		if started.OperationID != id {
			t.Fatal("API 派发了其他 operation")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("只读持久任务未进入 executor")
	}
	snapshot, err := service.ResolveDispatched(t.Context(), operations.DispatchTarget{ActionID: "acme.demo/scan", NodeID: "local",
		PluginID: "acme.demo", InstanceID: "default", Subject: "plugins/acme.demo/resources/read"}, id)
	defer snapshot.Clear()
	if err != nil || snapshot.Action.Effect != operations.EffectRead || snapshot.Action.Mode != operations.ModeJob || snapshot.Actor.SessionID != "" {
		t.Fatalf("API 的真实只读派发事实无效：%v", err)
	}
	replay := e.do(withIdempotency(admin.sign(http.MethodPost, path, body), "read-job-request-one")).expect(t, http.StatusAccepted)
	if replay.header.Get("Idempotency-Replayed") != "true" || dispatcher.jobs.Load() != 1 {
		t.Fatal("幂等重放触发了第二次派发")
	}
	// 新 key 也只入有界队列，不应被异常 widget 登记变成轮询 429。
	e.do(withIdempotency(admin.sign(http.MethodPost, path, body), "read-job-request-two")).expect(t, http.StatusAccepted)
}

func TestPluginReadJobPreservesSynchronousReadAndCurrentPermission(t *testing.T) {
	e, dispatcher, _ := newPluginReadJobEnv(t)
	admin := e.setupAdmin(adminUser)
	path := "/api/v1/plugins/acme.demo/operations/status"
	for range 2 {
		response := e.do(withIdempotency(admin.sign(http.MethodPost, path, `{"payload":{}}`), "ignored-sync-read-key")).expect(t, http.StatusOK)
		result := response.decodeMap(t)
		if id, _ := result["operation_id"].(string); id != "" {
			t.Fatal("同步只读轮询产生了 operation")
		}
	}
	var operationsCount, idempotencyCount int
	if err := e.c.DB().Reader().QueryRowContext(t.Context(), "SELECT COUNT(*) FROM operations").Scan(&operationsCount); err != nil {
		t.Fatal(err)
	}
	if err := e.c.DB().Reader().QueryRowContext(t.Context(), "SELECT COUNT(*) FROM idempotency_keys").Scan(&idempotencyCount); err != nil {
		t.Fatal(err)
	}
	if operationsCount != 0 || idempotencyCount != 0 || dispatcher.invokes.Load() != 2 {
		t.Fatal("原同步读被改为持久任务")
	}
	viewer := e.signIn("job-viewer", identity.RoleViewer)
	denied := e.do(withIdempotency(viewer.sign(http.MethodPost, "/api/v1/plugins/acme.demo/operations/restricted", `{"payload":{}}`), "denied-read-job-key"))
	problemDoc := denied.expectProblem(t, http.StatusForbidden, problem.PermissionDenied)
	if strings.Contains(problemDoc.Detail, "secret") || dispatcher.jobs.Load() != 0 {
		t.Fatal("无当前权限的读任务触发了执行")
	}
}
