// SPDX-License-Identifier: AGPL-3.0-only

package hostauth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/qwq-panel/qwq/internal/actor"
	"github.com/qwq-panel/qwq/internal/authz"
	"github.com/qwq-panel/qwq/internal/identity"
	"github.com/qwq-panel/qwq/internal/operations"
	"github.com/qwq-panel/qwq/internal/platform/clock"
	"github.com/qwq-panel/qwq/internal/platform/ids"
	"github.com/qwq-panel/qwq/internal/platform/problem"
	"github.com/qwq-panel/qwq/internal/prerequisites/dns"
	"github.com/qwq-panel/qwq/internal/prerequisites/fault"
	"github.com/qwq-panel/qwq/internal/prerequisites/provider"
	"github.com/qwq-panel/qwq/internal/prerequisites/testsupport"
	"github.com/qwq-panel/qwq/internal/secrets"
	"github.com/qwq-panel/qwq/internal/storage"
)

// ======================== 真实身份、权限、SQLite 与 operation 执行 ========================

type fixtureCatalog struct {
	mu      sync.Mutex
	actions map[string]operations.Action
}

func (c *fixtureCatalog) Action(id string) (operations.Action, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	value, found := c.actions[id]
	return value, found
}

type fixtureDispatch struct {
	started          chan *fixtureJob
	holdCancellation bool
}
type fixtureJob struct {
	ctx     context.Context
	request operations.PluginRunJobRequest
	done    chan struct{}
	once    sync.Once
}

func (d fixtureDispatch) Plan(context.Context, operations.PluginPlanRequest) (operations.Preview, error) {
	return operations.Preview{}, errors.New("fixture 不使用替代预演")
}
func (d fixtureDispatch) Invoke(context.Context, operations.PluginInvokeRequest) (operations.PluginInvokeResponse, error) {
	return operations.PluginInvokeResponse{}, errors.New("fixture 只接真实 job 派发")
}
func (d fixtureDispatch) Cancel(context.Context, operations.PluginCancelRequest) error { return nil }
func (d fixtureDispatch) RunJob(ctx context.Context, request operations.PluginRunJobRequest, progress func(operations.JobProgress) error) error {
	job := &fixtureJob{ctx: ctx, request: request, done: make(chan struct{})}
	select {
	case d.started <- job:
	case <-ctx.Done():
		return ctx.Err()
	}
	select {
	case <-job.done:
		return progress(operations.JobProgress{Completed: true, Result: json.RawMessage(`{"complete":true}`)})
	case <-ctx.Done():
		if d.holdCancellation {
			// executor 在物理退出前进行补偿；fixture cleanup 始终关闭 done。
			<-job.done
		}
		return ctx.Err()
	}
}

type fixtureCall struct {
	ctx        context.Context
	invocation Invocation
	job        *fixtureJob
	release    func()
}

func (c *fixtureCall) finish() {
	c.release()
	c.job.once.Do(func() { close(c.job.done) })
}

type authorityFixture struct {
	base       *testsupport.HostFixture
	ctx        context.Context
	db         *storage.DB
	secrets    *secrets.Store
	clock      *clock.Fake
	ids        *ids.Generator
	principals *identity.Service
	authz      *authz.Authorizer
	ops        *operations.Service
	authority  *Authority
	catalog    *fixtureCatalog
	dispatch   fixtureDispatch
	api        *fixtureAPI
	human      actor.Actor
}

func newAuthorityFixture(t *testing.T, configure ...func(*fixtureDispatch)) *authorityFixture {
	t.Helper()
	f := &authorityFixture{ctx: context.Background(), clock: clock.NewFake(time.Date(2026, 11, 16, 10, 0, 0, 0, time.UTC))}
	f.catalog = &fixtureCatalog{actions: make(map[string]operations.Action)}
	f.dispatch = fixtureDispatch{started: make(chan *fixtureJob, 8)}
	for _, change := range configure {
		change(&f.dispatch)
	}
	f.base = testsupport.NewHost(t, f.clock, f.catalog, f.dispatch)
	f.db, f.secrets, f.ids = f.base.DB, f.base.Secrets, f.base.IDs
	f.principals, f.authz, f.ops = f.base.Identity, f.base.Authorizer, f.base.Operations
	f.human = f.base.User(t, "scope-admin", authz.RoleAdmin)
	f.api = newFixtureAPI(t)
	var err error
	f.authority, err = New(f.options("installation", "local"))
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *authorityFixture) options(ownerID, nodeID string) Options {
	return Options{DB: f.db, Secrets: f.secrets, Operations: f.ops, Authorizer: f.authz,
		NodeID: nodeID, OwnerID: ownerID, HTTPClient: &http.Client{Transport: f.api}, Clock: f.clock}
}

func (f *authorityFixture) user(t *testing.T, name string, role authz.Role) actor.Actor {
	return f.base.User(t, name, role)
}

func (f *authorityFixture) dispatchCall(t *testing.T, who actor.Actor, plugin, operation, subject, expected string, args any, configure ...func(*operations.Action)) (*fixtureJob, Invocation) {
	t.Helper()
	write := operation != "records.list" && operation != "records.reconcile" && operation != "dns.check" && operation != "certificates.get"
	resource := "system.dns"
	if plugin == "tls.certificates" {
		resource = "system.certificates"
	}
	effect, risk, permission, capability := operations.EffectRead, operations.RiskLow, resource+":read", resource+".read"
	if write {
		effect, risk, permission, capability = operations.EffectWrite, operations.RiskHigh, resource+":manage", resource+".manage"
	}
	meta := operations.Action{ID: plugin + "/" + operation, Summary: "DNC 宿主授权回归", Effect: effect, Risk: risk,
		Mode: operations.ModeJob, Idempotent: true, Source: operations.PluginSource, PluginID: plugin,
		Placement: operations.PlacementController, Operation: operation, APIVersion: "1", Permission: permission,
		TimeoutMS: 60000, Capabilities: []operations.Capability{{Name: capability, Scope: "self"}}}
	if write {
		meta.Approval = operations.ApprovalConfirm
	}
	if operation == "providers.register" {
		meta.ArgsSchema = json.RawMessage(`{"type":"object","properties":{"provider_id":{"type":"string"},"kind":{"type":"string"},"name":{"type":"string"},"credential":{"type":"object","x-secret":true,"additionalProperties":true}},"required":["provider_id","kind","name","credential"],"additionalProperties":false}`)
	}
	if plugin == "tls.certificates" && operation == "certificates.import" {
		meta.ArgsSchema = json.RawMessage(`{"type":"object","properties":{"certificate_id":{"type":"string"},"attempt_id":{"type":"string"},"spec":{"type":"object"},"chain_pem":{"type":"string"},"private_key":{"type":"string","writeOnly":true,"x-secret":true},"trust":{"type":"string"}},"required":["certificate_id","attempt_id","spec","chain_pem","private_key","trust"],"additionalProperties":false}`)
	}
	for _, change := range configure {
		change(&meta)
	}
	f.catalog.mu.Lock()
	f.catalog.actions[meta.ID] = meta
	f.catalog.mu.Unlock()
	raw, err := json.Marshal(args)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(raw)
	response, err := f.ops.Run(f.ctx, operations.RunRequest{Actor: who, Action: meta.ID,
		Target: operations.Target{PluginID: plugin, Subject: subject}, Args: raw, ExpectedRevision: expected,
		Idempotency: operations.Idempotency{Key: f.ids.New(ids.Operation), Method: "POST", Route: "/fixture/run"}})
	if err != nil || response == nil || response.Operation == nil {
		t.Fatalf("真实 operation 创建失败：%v", err)
	}
	if response.Operation.Status == operations.AwaitingApproval {
		approver := f.human
		if who.IsHumanSession() {
			approver = who
		}
		approval, err := f.ops.GetApproval(f.ctx, approver, response.Operation.ApprovalID)
		if err != nil {
			t.Fatal(err)
		}
		_, err = f.ops.Decide(f.ctx, operations.DecisionRequest{Actor: approver, ApprovalID: approval.ID,
			Decision: operations.DecisionApprove, ExpectedRevision: approval.Revision,
			Idempotency: operations.Idempotency{Key: f.ids.New(ids.Operation), Method: "POST", Route: "/fixture/approval"}})
		if err != nil {
			t.Fatal(err)
		}
	}
	select {
	case job := <-f.dispatch.started:
		if job.request.OperationID != response.Operation.ID {
			t.Fatal("收到其他 operation 的执行上下文")
		}
		invocation := Invocation{PluginID: plugin, InstanceID: "default", OperationID: job.request.OperationID, Operation: operation, Subject: subject}
		t.Cleanup(func() { job.once.Do(func() { close(job.done) }) })
		return job, invocation
	case <-time.After(5 * time.Second):
		t.Fatal("真实 operation worker 未派发")
	}
	return nil, Invocation{}
}

func (f *authorityFixture) start(t *testing.T, who actor.Actor, plugin, operation, subject, expected string, args any) *fixtureCall {
	t.Helper()
	job, invocation := f.dispatchCall(t, who, plugin, operation, subject, expected, args)
	ctx, release, err := f.authority.Begin(job.ctx, invocation)
	if err != nil {
		t.Fatal(err)
	}
	call := &fixtureCall{ctx: ctx, invocation: invocation, job: job, release: release}
	t.Cleanup(call.finish)
	return call
}

const fixtureProvider = "provider-one"
const fixtureZone = "11111111111111111111111111111111"

func providerSubject(id string) string { return "plugins/domain.dns/resources/providers/" + id }
func zoneSubject(providerID, zoneID string) string {
	return "plugins/domain.dns/resources/zones/" + providerID + "/" + zoneID
}

func (f *authorityFixture) register(t *testing.T) (*fixtureCall, providerRegistration, string) {
	t.Helper()
	call := f.start(t, f.human, "domain.dns", "providers.register", providerSubject(fixtureProvider), "absent",
		map[string]any{"provider_id": fixtureProvider, "kind": dns.Cloudflare, "name": "受控提供商", "credential": map[string]string{"token": f.api.token}})
	if _, _, err := f.authority.RegisterProvider(call.ctx, fixtureProvider, "absent"); err != nil {
		t.Fatal(err)
	}
	registration, revision, found, err := f.authority.loadProvider(f.ctx, fixtureProvider)
	if err != nil || !found {
		t.Fatalf("宿主私有登记缺失：%v", err)
	}
	return call, registration, revision
}

func (f *authorityFixture) zone(t *testing.T, who actor.Actor, expected string) (*fixtureCall, dns.Scope, string) {
	t.Helper()
	call := f.start(t, who, "domain.dns", "zones.authorize", zoneSubject(fixtureProvider, fixtureZone), expected,
		ZoneArgs{ProviderID: fixtureProvider, ZoneID: fixtureZone})
	scope, revision, err := f.authority.AuthorizeZone(call.ctx, fixtureProvider, fixtureZone, expected)
	if err != nil {
		t.Fatal(err)
	}
	return call, scope, revision
}

func requireCode(t *testing.T, err error, code string) {
	t.Helper()
	if err == nil || (!problem.HasCode(err, problem.Code(code)) && fault.Code(err) != code) {
		t.Fatalf("预期固定错误 %s，实际：%v", code, err)
	}
}

// ======================== 明确网络 fixture：没有真实 DNS/CA 请求 ========================

type fixtureAPI struct {
	mu         sync.Mutex
	token      string
	requests   int
	pages      int
	afterFirst func(*http.Request) error
}

func newFixtureAPI(t *testing.T) *fixtureAPI {
	t.Helper()
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		t.Fatal(err)
	}
	defer clear(raw[:])
	return &fixtureAPI{token: base64.RawURLEncoding.EncodeToString(raw[:]), pages: 1}
}

func (a *fixtureAPI) count() int { a.mu.Lock(); defer a.mu.Unlock(); return a.requests }
func (a *fixtureAPI) RoundTrip(request *http.Request) (*http.Response, error) {
	if request.URL.Scheme != "https" || request.URL.Host != "api.cloudflare.com" || request.Method != http.MethodGet || request.URL.Path != "/client/v4/zones" || request.Header.Get("Authorization") != "Bearer "+a.token {
		return nil, errors.New("fixture 收到非固定提供商发现请求")
	}
	page, err := strconv.Atoi(request.URL.Query().Get("page"))
	if err != nil {
		return nil, err
	}
	a.mu.Lock()
	a.requests++
	pages, after := a.pages, a.afterFirst
	a.mu.Unlock()
	if page == 1 && after != nil {
		if err := after(request); err != nil {
			return nil, err
		}
	}
	id, name := fixtureZone, "example.test"
	if page > 1 {
		id, name = "22222222222222222222222222222222", "other.test"
	}
	body, err := json.Marshal(map[string]any{"success": true, "result": []provider.Zone{{ID: id, Name: name}},
		"result_info": map[string]int{"page": page, "count": 1, "total_pages": pages, "total_count": pages}})
	if err != nil {
		return nil, err
	}
	return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(string(body))), Request: request}, nil
}
