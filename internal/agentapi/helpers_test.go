// SPDX-License-Identifier: AGPL-3.0-only

package agentapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/qwq-panel/qwq/internal/actor"
	"github.com/qwq-panel/qwq/internal/authz"
	"github.com/qwq-panel/qwq/internal/catalog"
	"github.com/qwq-panel/qwq/internal/gateway"
	"github.com/qwq-panel/qwq/internal/identity"
	"github.com/qwq-panel/qwq/internal/operations"
	"github.com/qwq-panel/qwq/internal/platform/clock"
	"github.com/qwq-panel/qwq/internal/platform/ids"
	"github.com/qwq-panel/qwq/internal/platform/problem"
	"github.com/qwq-panel/qwq/internal/storage"
	"github.com/qwq-panel/qwq/sdk/manifest"
)

// Fixture identifiers. The plugin is installed into a real catalog.Catalog, so
// find_actions and describe_action see the same entries the host would.
const (
	fixturePlugin  = "com.example.demo"
	actionScan     = fixturePlugin + "/scan.run"
	actionBaseline = fixturePlugin + "/baseline.enable"
	actionReport   = fixturePlugin + "/report.read"
	testNode       = "local"
	testInstance   = "default"
)

// testEnv is one fully assembled host: database, identity, authz, catalog,
// operations, gateway and the agent routes.
type testEnv struct {
	t      *testing.T
	ctx    context.Context
	clock  *clock.Fake
	ids    *ids.Generator
	db     *storage.DB
	ident  *identity.Service
	authz  *authz.Authorizer
	cat    *catalog.Catalog
	ops    *operations.Service
	gw     *gateway.Gateway
	server *httptest.Server
	h      *handlers
	client *http.Client

	dispatcher *fakeDispatcher

	adminUser  identity.User
	viewerUser identity.User

	adminDelegation    string
	adminToken         string
	viewerDelegation   string
	viewerToken        string
	adminDelegationTwo string
	adminTokenTwo      string
}

func newTestEnv(t *testing.T) *testEnv {
	t.Helper()
	ctx := context.Background()
	clk := clock.NewFake(time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC))
	gen := ids.New(clk.Now)
	db, err := storage.Open(ctx, storage.Options{
		Path:  filepath.Join(t.TempDir(), "qwq.db"),
		Clock: clk,
		IDs:   gen,
	})
	if err != nil {
		t.Fatalf("open database: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	ident, err := identity.New(identity.Options{DB: db, Clock: clk, IDs: gen})
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	authzSvc, err := authz.New(authz.Options{DB: db, Clock: clk, Principals: ident})
	if err != nil {
		t.Fatalf("authz: %v", err)
	}

	e := &testEnv{
		t: t, ctx: ctx, clock: clk, ids: gen, db: db, ident: ident, authz: authzSvc,
		dispatcher: &fakeDispatcher{},
	}
	e.adminUser = e.createUser("alice", identity.RoleAdmin)
	e.viewerUser = e.createUser("vera", identity.RoleViewer)

	// The catalog merges the generated host actions with the fixture plugin.
	e.cat = newCatalog(t)
	e.ops = newOperations(t, e)
	e.adminDelegation, e.adminToken = e.createDelegation(e.adminUser.ID, authz.DefaultPolicy())
	e.adminDelegationTwo, e.adminTokenTwo = e.createDelegation(e.adminUser.ID, authz.DefaultPolicy())
	e.viewerDelegation, e.viewerToken = e.createDelegation(e.viewerUser.ID, authz.DefaultPolicy())

	gw, err := gateway.New(gateway.Config{
		Clock:  clk,
		IDs:    gen,
		Logger: slog.New(slog.DiscardHandler),
		Auth:   testAuthenticator{authz: authzSvc},
	})
	if err != nil {
		t.Fatalf("gateway: %v", err)
	}
	e.gw = gw
	// Register is the public entry point; the split keeps the handlers (and
	// their wait limiter) reachable for white-box assertions.
	e.h = newHandlers(gw, Deps{
		DB: db, Clock: clk, IDs: gen, Logger: slog.New(slog.DiscardHandler),
		Identity: ident, Authz: authzSvc, Ops: e.ops, Catalog: e.cat,
		NodeID: testNode,
		Docs: func(_ context.Context, entry *catalog.Entry) ([]byte, error) {
			return []byte("# " + entry.ID + "\nBundled documentation.\n"), nil
		},
	})
	if err := e.h.register(gw); err != nil {
		t.Fatalf("register: %v", err)
	}
	e.server = httptest.NewServer(gw)
	t.Cleanup(e.server.Close)
	// A long-poll handler that is still waiting on a fake-clock timer would
	// block Server.Close forever. Jumping the clock far past every deadline
	// makes such a handler observe the timeout and return; cleanups run last
	// registered first, so this happens before Close.
	t.Cleanup(func() { e.clock.Advance(24 * time.Hour) })
	e.client = e.server.Client()
	return e
}

// newCatalog builds the catalog with the fixture plugin's three actions.
func newCatalog(t *testing.T) *catalog.Catalog {
	t.Helper()
	toOps := func(caps []catalog.Capability) []operations.Capability {
		oc := make([]operations.Capability, 0, len(caps))
		for _, c := range caps {
			oc = append(oc, operations.Capability{Name: c.Name, Scope: c.Scope})
		}
		return oc
	}
	cat, err := catalog.New(
		func(declared, effect string, caps []catalog.Capability) string {
			return operations.RiskFloor(declared, effect, toOps(caps))
		},
		func(effect string, caps []catalog.Capability) bool {
			return operations.ForcedReachability(effect, toOps(caps))
		},
	)
	if err != nil {
		t.Fatalf("catalog: %v", err)
	}
	plannable := true
	m := &manifest.Manifest{
		ID:        fixturePlugin,
		Placement: "node",
		Operations: []manifest.Operation{
			{
				Name: "scan.run", APIVersion: "1", Permission: fixturePlugin + ":scan",
				Mode: "invoke", Effect: "write", Risk: "low", Idempotent: true,
				Approval:  "auto",
				Plannable: &plannable, Summary: "Scan the host for alerts",
				Docs:          "docs/scan.md",
				RequestSchema: "request.json", ResponseSchema: "response.json",
			},
			{
				Name: "baseline.enable", APIVersion: "1", Permission: fixturePlugin + ":baseline",
				Mode: "invoke", Effect: "write", Risk: "high", Idempotent: true,
				Approval:  "auto",
				Plannable: &plannable, Summary: "Enable the security baseline",
				RequestSchema: "request.json", ResponseSchema: "response.json",
			},
			{
				// A read-class permission ("read", "list", "get", ...) is what a
				// viewer's role grants (internal/authz roles.go).
				Name: "report.read", APIVersion: "1", Permission: fixturePlugin + ":read",
				Mode: "invoke", Effect: "read", Risk: "low", Idempotent: true,
				Summary:       "Report host findings",
				RequestSchema: "request.json", ResponseSchema: "response.json",
			},
		},
	}
	if err := cat.SetPlugin(m, func(string) ([]byte, error) {
		return []byte(`{"type":"object","additionalProperties":true}`), nil
	}); err != nil {
		t.Fatalf("install fixture plugin: %v", err)
	}
	return cat
}

// newOperations assembles the operations service with the same adapters the
// controller uses (kept here so this package does not import internal/controller
// and create an import cycle with the host wiring).
func newOperations(t *testing.T, e *testEnv) *operations.Service {
	t.Helper()
	svc, err := operations.New(operations.Options{
		DB:         e.db,
		Clock:      e.clock,
		IDs:        e.ids,
		Catalog:    catalogAdapter{cat: e.cat},
		Dispatcher: e.dispatcher,
		Authorizer: authorizerAdapter{authz: e.authz},
		Policy:     policyAdapter{authz: e.authz},
		NodeID:     testNode,
	})
	if err != nil {
		t.Fatalf("operations: %v", err)
	}
	t.Cleanup(svc.Stop)
	return svc
}

// createUser inserts a user directly, without a password (no argon2 cost).
func (e *testEnv) createUser(name string, role identity.Role) identity.User {
	e.t.Helper()
	var out identity.User
	err := e.db.Update(e.ctx, func(tx *storage.Tx) error {
		res, err := e.ident.CreateUser(e.ctx, tx, identity.CreateUserInput{
			Username: name, DisplayName: name, Role: role,
			Actor: actor.SystemActor("test"),
		})
		out = res.User
		return err
	})
	if err != nil {
		e.t.Fatalf("create user %s: %v", name, err)
	}
	return out
}

// createDelegation issues a token for a human owner and returns it.
func (e *testEnv) createDelegation(ownerID string, policy authz.Policy) (id, token string) {
	e.t.Helper()
	var created authz.Created
	err := e.db.Update(e.ctx, func(tx *storage.Tx) error {
		var err error
		created, err = e.authz.CreateDelegation(e.ctx, tx, authz.CreateDelegationInput{
			Actor:  actor.Actor{Kind: actor.Human, ID: ownerID, SessionID: "ses_test"},
			Label:  "test ai",
			Policy: policy,
			TTL:    24 * time.Hour,
		})
		return err
	})
	if err != nil {
		e.t.Fatalf("create delegation: %v", err)
	}
	return created.ID, created.Token
}

// serviceToken issues a service-account token: it authenticates, but the agent
// routes must reject it.
func (e *testEnv) serviceToken() string {
	e.t.Helper()
	var created authz.CreatedServiceAccount
	err := e.db.Update(e.ctx, func(tx *storage.Tx) error {
		var err error
		created, err = e.authz.CreateServiceAccount(e.ctx, tx, authz.CreateServiceAccountInput{
			Actor: actor.Actor{Kind: actor.Human, ID: e.adminUser.ID, SessionID: "ses_test"},
			Name:  "ci",
			Role:  authz.RoleAdmin,
		})
		return err
	})
	if err != nil {
		e.t.Fatalf("create service account: %v", err)
	}
	return created.Token
}

// aiActor is the actor of one delegation.
func aiActor(id, ownerID string) actor.Actor {
	return actor.Actor{Kind: actor.AIAgent, ID: id, OnBehalfOf: ownerID}
}

// ---- adapters (the controller wires the same ones) ------------------------

type catalogAdapter struct{ cat *catalog.Catalog }

func (a catalogAdapter) Action(id string) (operations.Action, bool) {
	entry, ok := a.cat.Get(id)
	if !ok {
		return operations.Action{}, false
	}
	caps := make([]operations.Capability, 0, len(entry.Capabilities))
	for _, c := range entry.Capabilities {
		caps = append(caps, operations.Capability{Name: c.Name, Scope: c.Scope})
	}
	source := operations.HostSource
	if entry.Source == catalog.Plugin {
		source = operations.PluginSource
	}
	return operations.Action{
		ID: entry.ID, Summary: entry.Summary, Effect: entry.Effect, Risk: entry.DeclaredRisk,
		Mode: entry.Mode, Idempotent: entry.Idempotent, Plannable: entry.Plannable,
		Capabilities: caps, Undo: entry.Undo, UIRoute: entry.UIRoute, Permission: entry.Permission,
		TimeoutMS: entry.TimeoutMS, Source: source, PluginID: entry.PluginID,
		Placement: entry.Placement, Operation: entry.Operation, APIVersion: entry.APIVersion,
		Approval: entry.Approval, ApprovalSummary: entry.ApprovalSummary,
		ApprovalDescription: entry.ApprovalDescription,
	}, true
}

type authorizerAdapter struct{ authz *authz.Authorizer }

func (a authorizerAdapter) Authorize(ctx context.Context, act actor.Actor,
	action operations.Action, target operations.Target) error {
	if action.Permission == "" {
		return problem.New(problem.PermissionDenied, "The action has no permission mapping.")
	}
	perm, err := authz.ParsePermission(action.Permission)
	if err != nil {
		return err
	}
	return a.authz.Authorize(ctx, act, string(perm), authz.Resource{
		Name: string(perm.Resource()), NodeID: target.NodeID, Action: action.ID,
	})
}

type policyAdapter struct{ authz *authz.Authorizer }

func (p policyAdapter) Limits(ctx context.Context, act actor.Actor,
	_ operations.Action, _ operations.Target) (operations.Limits, error) {
	limits := operations.Limits{
		MaxRisk: operations.RiskHigh, AutoApproveMaxRisk: operations.RiskLow,
		OnApprovalRequired: operations.ApprovalQueue,
	}
	if act.Kind != actor.AIAgent {
		return limits, nil
	}
	d, err := p.authz.Delegation(ctx, act.ID)
	if err != nil {
		return operations.Limits{}, problem.New(problem.PermissionDenied, "The delegation is not active.")
	}
	if d.Policy.AutoApproveMaxRisk != "" {
		limits.AutoApproveMaxRisk = d.Policy.AutoApproveMaxRisk
	}
	if d.Policy.OnApprovalRequired != "" {
		limits.OnApprovalRequired = d.Policy.OnApprovalRequired
	}
	return limits, nil
}

// testAuthenticator accepts delegation and service-account bearer tokens; the
// gateway's credential policy decides which route may use which.
type testAuthenticator struct{ authz *authz.Authorizer }

func (a testAuthenticator) Authenticate(ctx context.Context, c gateway.Credentials) (gateway.Principal, error) {
	if c.Bearer == "" {
		return gateway.Principal{}, gateway.ErrNoCredentials
	}
	act, err := a.authz.AuthenticateBearer(ctx, c.Bearer)
	if err != nil {
		return gateway.Principal{}, err
	}
	scheme := gateway.SchemeDelegation
	if act.Kind == actor.Service {
		scheme = gateway.SchemeService
	}
	return gateway.Principal{Actor: act, Scheme: scheme}, nil
}

// ---- fake dispatcher ------------------------------------------------------

type fakeDispatcher struct {
	mu        sync.Mutex
	result    json.RawMessage
	planFn    func(context.Context, operations.PluginPlanRequest) (operations.Preview, error)
	invokeFn  func(context.Context, operations.PluginInvokeRequest) (operations.PluginInvokeResponse, error)
	jobFn     func(context.Context, operations.PluginRunJobRequest, func(operations.JobProgress) error) error
	cancelFn  func(context.Context, operations.PluginCancelRequest) error
	invokes   int
	planCalls int
}

func (d *fakeDispatcher) Plan(ctx context.Context, req operations.PluginPlanRequest) (operations.Preview, error) {
	d.mu.Lock()
	fn := d.planFn
	d.planCalls++
	d.mu.Unlock()
	if fn != nil {
		return fn(ctx, req)
	}
	return operations.Preview{
		Changes: []operations.PlannedChange{{
			Kind: "update", Subject: "alerts/cpu", Reversible: true,
		}},
	}, nil
}

func (d *fakeDispatcher) Invoke(ctx context.Context, req operations.PluginInvokeRequest) (operations.PluginInvokeResponse, error) {
	d.mu.Lock()
	fn := d.invokeFn
	d.invokes++
	result := d.result
	d.mu.Unlock()
	if fn != nil {
		return fn(ctx, req)
	}
	if len(result) == 0 {
		result = json.RawMessage(`{"ok":true}`)
	}
	return operations.PluginInvokeResponse{Result: result}, nil
}

func (d *fakeDispatcher) RunJob(ctx context.Context, req operations.PluginRunJobRequest,
	progress func(operations.JobProgress) error) error {
	d.mu.Lock()
	fn := d.jobFn
	d.mu.Unlock()
	if fn != nil {
		return fn(ctx, req, progress)
	}
	return progress(operations.JobProgress{Completed: true})
}

func (d *fakeDispatcher) Cancel(ctx context.Context, req operations.PluginCancelRequest) error {
	d.mu.Lock()
	fn := d.cancelFn
	d.mu.Unlock()
	if fn != nil {
		return fn(ctx, req)
	}
	return nil
}

func (d *fakeDispatcher) invokeCount() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.invokes
}

// ---- HTTP helpers ---------------------------------------------------------

// do posts one tool request. token "" means no Authorization header.
func (e *testEnv) do(t *testing.T, token, path string, body any, headers map[string]string) (int, []byte) {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	return e.doRaw(t, token, path, raw, headers)
}

func (e *testEnv) doRaw(t *testing.T, token, path string, raw []byte, headers map[string]string) (int, []byte) {
	t.Helper()
	status, data, err := e.send(token, path, raw, headers)
	if err != nil {
		t.Fatalf("post %s: %v", path, err)
	}
	return status, data
}

// send is the goroutine-safe form of doRaw: it never calls testing.T, so it can
// be used from the concurrent wait tests.
func (e *testEnv) send(token, path string, raw []byte, headers map[string]string) (int, []byte, error) {
	req, err := http.NewRequestWithContext(e.ctx, http.MethodPost, e.server.URL+path, bytes.NewReader(raw))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := e.client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, nil, err
	}
	return resp.StatusCode, data, nil
}

// sendJSON marshals body and posts it, for use in goroutines.
func (e *testEnv) sendJSON(token, path string, body any, headers map[string]string) (int, []byte, error) {
	raw, err := json.Marshal(body)
	if err != nil {
		return 0, nil, err
	}
	return e.send(token, path, raw, headers)
}

// post posts as the admin delegation and decodes a JSON object.
func (e *testEnv) post(t *testing.T, path string, body any) (int, map[string]any) {
	t.Helper()
	return e.postAs(t, e.adminToken, path, body, nil)
}

func (e *testEnv) postAs(t *testing.T, token, path string, body any, headers map[string]string) (int, map[string]any) {
	t.Helper()
	status, data := e.do(t, token, path, body, headers)
	var obj map[string]any
	if len(data) > 0 {
		if err := json.Unmarshal(data, &obj); err != nil {
			t.Fatalf("decode %s response %q: %v", path, data, err)
		}
	}
	return status, obj
}

// problemOf decodes a problem document and returns its code and violations.
func problemOf(t *testing.T, data []byte) (code string, status int, violations []any) {
	t.Helper()
	var p struct {
		Code       string `json:"code"`
		Status     int    `json:"status"`
		Violations []any  `json:"violations"`
	}
	if err := json.Unmarshal(data, &p); err != nil {
		t.Fatalf("decode problem %q: %v", data, err)
	}
	return p.Code, p.Status, p.Violations
}

// detailOf returns the human-readable detail of a problem document, so two
// answers can be compared without their per-request IDs.
func detailOf(t *testing.T, data []byte) string {
	t.Helper()
	var p struct {
		Detail string `json:"detail"`
	}
	if err := json.Unmarshal(data, &p); err != nil {
		t.Fatalf("decode problem %q: %v", data, err)
	}
	return p.Detail
}

// expectProblem asserts the status and code of a failed request.
func (e *testEnv) expectProblem(t *testing.T, token, path string, body any, wantStatus int, wantCode string) []byte {
	t.Helper()
	status, data := e.do(t, token, path, body, nil)
	if status != wantStatus {
		t.Fatalf("%s: status %d, want %d (body %s)", path, status, wantStatus, data)
	}
	code, gotStatus, _ := problemOf(t, data)
	if code != wantCode || gotStatus != wantStatus {
		t.Fatalf("%s: problem %s/%d, want %s/%d (body %s)", path, code, gotStatus, wantCode, wantStatus, data)
	}
	return data
}

// ---- assertions -----------------------------------------------------------

func str(t *testing.T, v any) string {
	t.Helper()
	s, ok := v.(string)
	if !ok {
		t.Fatalf("%v is not a string", v)
	}
	return s
}

func obj(t *testing.T, v any) map[string]any {
	t.Helper()
	m, ok := v.(map[string]any)
	if !ok {
		t.Fatalf("%v is not an object", v)
	}
	return m
}

func list(t *testing.T, v any) []any {
	t.Helper()
	a, ok := v.([]any)
	if !ok {
		t.Fatalf("%v is not an array", v)
	}
	return a
}

func mustContain(t *testing.T, got, want string) {
	t.Helper()
	if !bytes.Contains([]byte(got), []byte(want)) {
		t.Fatalf("%q does not contain %q", got, want)
	}
}

// advance moves the fake clock forward in one step. It is for tests that have
// no handler waiting on a timer; a long poll re-arms its timer after every
// wake-up, so those tests advance in a loop and yield in between instead.
func (e *testEnv) advance(d time.Duration) {
	e.clock.Advance(d)
}

// waitFor polls a condition in real time; it never advances the fake clock.
func (e *testEnv) waitFor(what string, cond func() bool) {
	e.t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	e.t.Fatalf("timed out waiting for %s", what)
}

// lastOperation returns the most recent operation of the admin delegation via
// the service (the read tool is exercised separately).
func (e *testEnv) operation(id string) *operations.Operation {
	e.t.Helper()
	op, err := e.ops.Get(e.ctx, aiActor(e.adminDelegation, e.adminUser.ID), id)
	if err != nil {
		e.t.Fatalf("load operation %s: %v", id, err)
	}
	return op
}

// execute runs an action as the admin delegation and returns the outcome.
func (e *testEnv) execute(t *testing.T, body map[string]any) map[string]any {
	t.Helper()
	status, out := e.post(t, "/api/v1/agent/execute", body)
	if status != http.StatusOK {
		t.Fatalf("execute: status %d, body %v", status, out)
	}
	return out
}

// executedOperation runs the low-risk fixture action and returns its ID.
func (e *testEnv) executedOperation(t *testing.T) string {
	t.Helper()
	out := e.execute(t, map[string]any{
		"action": actionScan, "args": map[string]any{"scope": "cpu"}, "target": nodeTarget(),
	})
	if out["status"] != "SUCCEEDED" {
		t.Fatalf("execute status = %v (%v)", out["status"], out)
	}
	id := str(t, out["operation_id"])
	if id == "" {
		t.Fatal("operation_id is empty")
	}
	return id
}

// pendingApproval runs the high-risk fixture action; it stops at
// AWAITING_APPROVAL and returns both identifiers.
func (e *testEnv) pendingApproval(t *testing.T) (operationID, approvalID string) {
	t.Helper()
	out := e.execute(t, map[string]any{
		"action": actionBaseline, "args": map[string]any{"enable": true}, "target": nodeTarget(),
	})
	if out["status"] != "AWAITING_APPROVAL" {
		t.Fatalf("execute status = %v (%v)", out["status"], out)
	}
	operationID, _ = out["operation_id"].(string)
	approvalID, _ = out["approval_id"].(string)
	if operationID == "" || approvalID == "" {
		t.Fatalf("operation_id = %q, approval_id = %q", operationID, approvalID)
	}
	return operationID, approvalID
}

// nodeTarget is the target of a node-placed fixture action.
func nodeTarget() map[string]any {
	return map[string]any{
		"node_id": testNode, "plugin_id": fixturePlugin, "instance_id": testInstance,
	}
}

// asProblem extracts a *problem.Error (tests of service-level helpers).
func asProblem(err error) (*problem.Error, bool) {
	var p *problem.Error
	if errors.As(err, &p) {
		return p, true
	}
	return nil, false
}

// errString formats an error for a failure message without leaking it.
func errString(err error) string {
	if err == nil {
		return "<nil>"
	}
	if p, ok := asProblem(err); ok {
		return fmt.Sprintf("%s: %s", p.Code, p.Detail)
	}
	return err.Error()
}
