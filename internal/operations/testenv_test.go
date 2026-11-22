// SPDX-License-Identifier: AGPL-3.0-only

package operations

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/qwq-panel/qwq/internal/actor"
	"github.com/qwq-panel/qwq/internal/platform/clock"
	"github.com/qwq-panel/qwq/internal/platform/ids"
	"github.com/qwq-panel/qwq/internal/platform/problem"
	"github.com/qwq-panel/qwq/internal/storage"
)

// Test actions. The catalog is a fake; the host handler writes a small
// test_resources table so preconditions and revisions are real database rows.
const (
	actionWrite   = "test.write"
	actionHigh    = "test.high"
	actionDestroy = "test.destroy"
	actionPlugin  = "com.example.demo/scan.run"
	actionPluginH = "com.example.demo/baseline.enable"
	actionJob     = "com.example.demo/cleanup"
	actionJobOnce = "com.example.demo/cleanup.once"
	actionRead    = "com.example.demo/report"
	pluginID      = "com.example.demo"
)

const resourceSubject = "test_resources/demo"

type testEnv struct {
	t     *testing.T
	ctx   context.Context
	db    *storage.DB
	clock *clock.Fake
	ids   *ids.Generator
	svc   *Service

	catalog    *fakeCatalog
	dispatcher *fakeDispatcher
	authorizer *fakeAuthorizer
	policy     *fakePolicy
	notifier   *recordingNotifier

	keySeq atomic.Uint64
}

func newTestEnv(t *testing.T) *testEnv {
	t.Helper()
	ctx := context.Background()
	fake := clock.NewFake(time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC))
	gen := ids.New(fake.Now)
	db, err := storage.Open(ctx, storage.Options{
		Path:   filepath.Join(t.TempDir(), "qwq.db"),
		Clock:  fake,
		IDs:    gen,
		Logger: nil,
	})
	if err != nil {
		t.Fatalf("open database: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	e := &testEnv{
		t: t, ctx: ctx, db: db, clock: fake, ids: gen,
		catalog:    newFakeCatalog(),
		dispatcher: &fakeDispatcher{},
		authorizer: &fakeAuthorizer{deny: map[string]string{}},
		policy:     &fakePolicy{byPrincipal: map[string]Limits{}},
		notifier:   &recordingNotifier{},
	}
	if err := db.Update(ctx, func(tx *storage.Tx) error {
		_, err := tx.ExecContext(ctx, `CREATE TABLE test_resources (
			subject  TEXT PRIMARY KEY,
			revision INTEGER NOT NULL,
			value    TEXT NOT NULL
		) STRICT`)
		return err
	}); err != nil {
		t.Fatalf("create test table: %v", err)
	}
	svc, err := New(Options{
		DB: db, Clock: fake, IDs: gen,
		Catalog: e.catalog, Dispatcher: e.dispatcher, Authorizer: e.authorizer,
		Policy: e.policy, Revisions: testRevisions{}, Notifier: e.notifier,
	})
	if err != nil {
		t.Fatalf("new service: %v", err)
	}
	t.Cleanup(svc.Stop)
	e.svc = svc
	svc.RegisterHostAction(actionWrite, e.writeResource, nil)
	svc.RegisterHostAction(actionHigh, e.writeResource, nil)
	svc.RegisterHostAction(actionDestroy, e.writeResource, nil)
	return e
}

// testRevisions resolves the revision of a test_resources row inside the
// transaction that is about to modify it.
type testRevisions struct{}

func (testRevisions) CurrentRevision(ctx context.Context, tx *storage.Tx, subject string) (string, error) {
	var rev int64
	err := tx.QueryRowContext(ctx, `SELECT revision FROM test_resources WHERE subject = ?`, subject).Scan(&rev)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return strconv.FormatInt(rev, 10), nil
}

// writeResource is the host action used by most tests: it updates one row and
// records the resource.changed event whose sequence becomes its revision.
func (e *testEnv) writeResource(ctx context.Context, tx *storage.Tx, req HostRequest) (json.RawMessage, error) {
	var args struct {
		Value string `json:"value"`
	}
	if len(req.Args) > 0 {
		if err := json.Unmarshal(req.Args, &args); err != nil {
			return nil, problem.Validation(problem.Violation{Pointer: "/value", Code: "INVALID", Message: "bad value"})
		}
	}
	var current int64
	err := tx.QueryRowContext(ctx, `SELECT revision FROM test_resources WHERE subject = ?`, req.Target.Subject).Scan(&current)
	exists := err == nil
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	kind := storage.Updated
	if !exists {
		kind = storage.Created
	}
	rev, err := tx.Changed(ctx, storage.Change{Subject: req.Target.Subject, Kind: kind})
	if err != nil {
		return nil, err
	}
	if exists {
		_, err = tx.ExecContext(ctx, `UPDATE test_resources SET revision = ?, value = ? WHERE subject = ?`,
			rev, args.Value, req.Target.Subject)
	} else {
		_, err = tx.ExecContext(ctx, `INSERT INTO test_resources (subject, revision, value) VALUES (?, ?, ?)`,
			req.Target.Subject, rev, args.Value)
	}
	if err != nil {
		return nil, err
	}
	return json.RawMessage(fmt.Sprintf(`{"revision":%d}`, rev)), nil
}

// ---- actors ----

func humanActor() actor.Actor {
	return actor.Actor{Kind: actor.Human, ID: "usr_human", SessionID: "ses_human", MFA: false}
}

func humanMFA() actor.Actor {
	a := humanActor()
	a.MFA = true
	return a
}

func aiActor() actor.Actor {
	return actor.Actor{Kind: actor.AIAgent, ID: "dlg_ai", OnBehalfOf: "usr_human"}
}

func serviceActor() actor.Actor {
	return actor.Actor{Kind: actor.Service, ID: "svc_1", OnBehalfOf: "usr_human"}
}

// ---- requests ----

// newKey returns a fresh idempotency key.
func (e *testEnv) newKey() string {
	return fmt.Sprintf("test-key-%016d", e.keySeq.Add(1))
}

// run executes an action as the given actor.
func (e *testEnv) run(a actor.Actor, action string, target Target, args map[string]any) (*Response, error) {
	return e.runReq(a, RunRequest{
		Actor: a, Action: action, Target: target, Args: mustJSON(e.t, args),
		Idempotency: Idempotency{Key: e.newKey(), Method: "POST", Route: "/api/v1/test/" + action},
	})
}

func (e *testEnv) runReq(a actor.Actor, req RunRequest) (*Response, error) {
	if req.Actor.Kind == "" {
		req.Actor = a
	}
	req.TraceID = "trace-0123456789abcdef0123456789abcdef"
	req.RequestID = "req_test"
	return e.svc.Run(e.ctx, req)
}

// runWithRevision executes a host write with an expected_revision.
func (e *testEnv) runWithRevision(a actor.Actor, action, subject, revision, value string) (*Response, error) {
	return e.runReq(a, RunRequest{
		Actor: a, Action: action, Target: Target{Subject: subject},
		Args:             mustJSON(e.t, map[string]any{"value": value}),
		ExpectedRevision: revision,
		Idempotency: Idempotency{Key: e.newKey(), Method: "POST",
			Route: "/api/v1/test/" + action + "/" + subject},
	})
}

func mustJSON(t *testing.T, v any) json.RawMessage {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}

// ---- database helpers ----

func (e *testEnv) resourceRevision(subject string) string {
	e.t.Helper()
	var rev int64
	if err := e.db.Reader().QueryRowContext(e.ctx,
		`SELECT revision FROM test_resources WHERE subject = ?`, subject).Scan(&rev); err != nil {
		e.t.Fatalf("read resource revision: %v", err)
	}
	return strconv.FormatInt(rev, 10)
}

func (e *testEnv) countOperations() int {
	e.t.Helper()
	var n int
	if err := e.db.Reader().QueryRowContext(e.ctx, `SELECT COUNT(*) FROM operations`).Scan(&n); err != nil {
		e.t.Fatalf("count operations: %v", err)
	}
	return n
}

func (e *testEnv) countAudit(action string) int {
	e.t.Helper()
	var n int
	if err := e.db.Reader().QueryRowContext(e.ctx,
		`SELECT COUNT(*) FROM audit_log WHERE action = ?`, action).Scan(&n); err != nil {
		e.t.Fatalf("count audit: %v", err)
	}
	return n
}

// events returns the journal entries of one type for a subject.
func (e *testEnv) events(eventType, subject string) []storage.Event {
	e.t.Helper()
	var out []storage.Event
	err := e.db.View(e.ctx, func(tx *sql.Tx) error {
		query := `SELECT seq, event_id, type, schema_version, subject, occurred_at, actor_kind, actor_id,
			on_behalf_of, node_id, trace_id, operation_id, payload FROM event_journal WHERE type = ?`
		args := []any{eventType}
		if subject != "" {
			query += ` AND subject = ?`
			args = append(args, subject)
		}
		query += ` ORDER BY seq`
		rows, err := tx.QueryContext(e.ctx, query, args...)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var ev storage.Event
			var at, payload string
			if err := rows.Scan(&ev.Seq, &ev.EventID, &ev.Type, &ev.SchemaVersion, &ev.Subject, &at,
				&ev.ActorKind, &ev.ActorID, &ev.OnBehalfOf, &ev.NodeID, &ev.TraceID, &ev.OperationID,
				&payload); err != nil {
				return err
			}
			ev.Payload = json.RawMessage(payload)
			out = append(out, ev)
		}
		return rows.Err()
	})
	if err != nil {
		e.t.Fatalf("read journal: %v", err)
	}
	return out
}

// waitFor polls until cond holds or the deadline passes. It advances nothing;
// the poll interval is real time so tests never hang on a fake clock.
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

func (e *testEnv) operation(id string) *Operation {
	e.t.Helper()
	op, err := loadOperation(e.ctx, e.db.Reader(), id)
	if err != nil {
		e.t.Fatalf("load operation: %v", err)
	}
	return op
}

func (e *testEnv) approval(id string) *Approval {
	e.t.Helper()
	approval, err := loadApproval(e.ctx, e.db.Reader(), id)
	if err != nil {
		e.t.Fatalf("load approval: %v", err)
	}
	return approval
}

// ---- fakes ----

type fakeCatalog struct {
	mu      sync.Mutex
	actions map[string]Action
}

func newFakeCatalog() *fakeCatalog {
	c := &fakeCatalog{actions: map[string]Action{}}
	c.actions[actionWrite] = Action{
		ID: actionWrite, Summary: "Write a test resource", Effect: EffectWrite, Risk: RiskLow,
		Mode: ModeInvoke, Idempotent: true, Permission: "test:write", Source: HostSource, TimeoutMS: 5000,
	}
	c.actions[actionHigh] = Action{
		ID: actionHigh, Summary: "Write a high risk test resource", Effect: EffectWrite, Risk: RiskHigh,
		Mode: ModeInvoke, Permission: "test:high", Source: HostSource, TimeoutMS: 5000,
	}
	c.actions[actionDestroy] = Action{
		ID: actionDestroy, Summary: "Destroy a test resource", Effect: EffectDestructive, Risk: RiskLow,
		Mode: ModeInvoke, Permission: "test:destroy", Source: HostSource, TimeoutMS: 5000,
	}
	c.actions[actionPlugin] = Action{
		ID: actionPlugin, Summary: "Scan", Effect: EffectWrite, Risk: RiskLow, Mode: ModeInvoke,
		Idempotent: true, Plannable: true, Permission: pluginID + ":scan", Source: PluginSource,
		PluginID: pluginID, Placement: PlacementNode, Operation: "scan.run", APIVersion: "1",
		Capabilities: []Capability{{Name: "state.kv.read", Scope: "*"}},
		TimeoutMS:    5000,
		// ADR-0010: a plugin write without a declaration derives confirm, so the
		// auto path this fixture exercises needs the explicit level.
		Approval: ApprovalAuto,
	}
	c.actions[actionPluginH] = Action{
		ID: actionPluginH, Summary: "Enable the baseline", Effect: EffectWrite, Risk: RiskMedium,
		Mode: ModeInvoke, Permission: pluginID + ":baseline", Source: PluginSource, PluginID: pluginID,
		Placement: PlacementNode, Operation: "baseline.enable", APIVersion: "1",
		Capabilities: []Capability{{Name: "system.firewall", Scope: "*"}},
		TimeoutMS:    5000,
	}
	c.actions[actionJob] = Action{
		ID: actionJob, Summary: "Clean up", Effect: EffectWrite, Risk: RiskLow, Mode: ModeJob,
		Idempotent: true, Permission: pluginID + ":cleanup", Source: PluginSource, PluginID: pluginID,
		Placement: PlacementNode, Operation: "cleanup", APIVersion: "1", TimeoutMS: 5000,
		Approval: ApprovalAuto,
	}
	c.actions[actionJobOnce] = Action{
		ID: actionJobOnce, Summary: "One-shot cleanup", Effect: EffectWrite, Risk: RiskLow, Mode: ModeJob,
		Idempotent: false, Permission: pluginID + ":cleanup", Source: PluginSource, PluginID: pluginID,
		Placement: PlacementNode, Operation: "cleanup.once", APIVersion: "1", TimeoutMS: 5000,
		Approval: ApprovalAuto,
	}
	c.actions[actionRead] = Action{
		ID: actionRead, Summary: "Report", Effect: EffectRead, Risk: RiskLow, Mode: ModeInvoke,
		Permission: pluginID + ":report", Source: PluginSource, PluginID: pluginID,
		Placement: PlacementNode, Operation: "report", APIVersion: "1", TimeoutMS: 5000,
	}
	return c
}

func (c *fakeCatalog) Action(id string) (Action, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	a, ok := c.actions[id]
	return a, ok
}

// setAction mutates one catalog action for a test (ADR-0010 levels, card text).
func (e *testEnv) setAction(id string, mutate func(*Action)) {
	e.catalog.mu.Lock()
	defer e.catalog.mu.Unlock()
	a := e.catalog.actions[id]
	mutate(&a)
	e.catalog.actions[id] = a
}

type fakeAuthorizer struct {
	mu   sync.Mutex
	deny map[string]string // principal + "|" + action -> detail
}

func (a *fakeAuthorizer) Authorize(_ context.Context, who actor.Actor, act Action, _ Target) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if detail, ok := a.deny[principalKey(who)+"|"+act.ID]; ok {
		return problem.New(problem.PermissionDenied, "%s", detail)
	}
	return nil
}

func (a *fakeAuthorizer) denyFor(who actor.Actor, action, detail string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.deny[principalKey(who)+"|"+action] = detail
}

func (a *fakeAuthorizer) allow(who actor.Actor, action string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.deny, principalKey(who)+"|"+action)
}

type fakePolicy struct {
	mu          sync.Mutex
	limits      Limits
	byPrincipal map[string]Limits
}

func (p *fakePolicy) Limits(_ context.Context, who actor.Actor, _ Action, _ Target) (Limits, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if l, ok := p.byPrincipal[principalKey(who)]; ok {
		return l, nil
	}
	return p.limits, nil
}

func (p *fakePolicy) set(who actor.Actor, limits Limits) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.byPrincipal[principalKey(who)] = limits
}

type recordingNotifier struct {
	mu  sync.Mutex
	ops []string
}

func (n *recordingNotifier) Notify(_ context.Context, op *Operation) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.ops = append(n.ops, op.ID)
}

func (n *recordingNotifier) count() int {
	n.mu.Lock()
	defer n.mu.Unlock()
	return len(n.ops)
}

type fakeDispatcher struct {
	mu        sync.Mutex
	planFn    func(context.Context, PluginPlanRequest) (Preview, error)
	invokeFn  func(context.Context, PluginInvokeRequest) (PluginInvokeResponse, error)
	jobFn     func(context.Context, PluginRunJobRequest, func(JobProgress) error) error
	cancelFn  func(context.Context, PluginCancelRequest) error
	cancels   []string
	invokes   int
	planCalls int
}

func (d *fakeDispatcher) Plan(ctx context.Context, req PluginPlanRequest) (Preview, error) {
	d.mu.Lock()
	fn := d.planFn
	d.planCalls++
	d.mu.Unlock()
	if fn != nil {
		return fn(ctx, req)
	}
	return Preview{}, nil
}

func (d *fakeDispatcher) Invoke(ctx context.Context, req PluginInvokeRequest) (PluginInvokeResponse, error) {
	d.mu.Lock()
	fn := d.invokeFn
	d.invokes++
	d.mu.Unlock()
	if fn != nil {
		return fn(ctx, req)
	}
	return PluginInvokeResponse{Result: json.RawMessage(`{"ok":true}`)}, nil
}

func (d *fakeDispatcher) RunJob(ctx context.Context, req PluginRunJobRequest, progress func(JobProgress) error) error {
	d.mu.Lock()
	fn := d.jobFn
	d.mu.Unlock()
	if fn != nil {
		return fn(ctx, req, progress)
	}
	return progress(JobProgress{Completed: true, Percent: intPtr(100), Result: json.RawMessage(`{"ok":true}`)})
}

func (d *fakeDispatcher) Cancel(ctx context.Context, req PluginCancelRequest) error {
	d.mu.Lock()
	d.cancels = append(d.cancels, req.OperationID)
	fn := d.cancelFn
	d.mu.Unlock()
	if fn != nil {
		return fn(ctx, req)
	}
	return nil
}

func (d *fakeDispatcher) cancelCount() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.cancels)
}

func (d *fakeDispatcher) invokeCount() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.invokes
}

func intPtr(v int) *int { return &v }

// asProblemError is errors.As for *problem.Error.
func asProblemError(err error, out **problem.Error) bool { return errors.As(err, out) }
