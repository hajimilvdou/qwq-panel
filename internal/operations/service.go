// SPDX-License-Identifier: AGPL-3.0-only

package operations

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/qwq-panel/qwq/internal/actor"
	"github.com/qwq-panel/qwq/internal/platform/clock"
	"github.com/qwq-panel/qwq/internal/platform/ids"
	"github.com/qwq-panel/qwq/internal/platform/problem"
	"github.com/qwq-panel/qwq/internal/secrets"
	"github.com/qwq-panel/qwq/internal/storage"
)

// Config tunes the manager. The zero value is valid and small-host friendly:
// one job worker, one notification at a time, 15 minute plans and approvals.
type Config struct {
	// PlanTTL is how long a plan stays executable (OpenAPI plan_ttl_seconds).
	PlanTTL time.Duration
	// ApprovalTTL is how long an approval waits for a human (ADR-0004 D6).
	ApprovalTTL time.Duration
	// IdempotencyTTL is the lifetime of an idempotency key from first use.
	IdempotencyTTL time.Duration
	// IdempotencyInProgressTTL is when an unfinished key is considered stale
	// after a crash and may be reclaimed by a retry.
	IdempotencyInProgressTTL time.Duration
	// IdempotencyKeysPerPrincipal bounds live keys per principal
	// (OpenAPI idempotency_keys_per_principal).
	IdempotencyKeysPerPrincipal int
	// JobWorkers is the number of job goroutines (1 suits a 1C1G host).
	JobWorkers int
	// JobQueue bounds the number of accepted but not started jobs.
	JobQueue int
	// MaxAttempts bounds automatic retries of idempotent jobs.
	MaxAttempts int
	// ProgressInterval throttles progress writes (the final one is always
	// written). ADR-0008 §3: progress is a short transaction, not a stream of
	// them.
	ProgressInterval time.Duration
	// JobCancelGrace is how long a canceled job gets before its context is
	// canceled.
	JobCancelGrace time.Duration
	// DefaultInvokeTimeout applies to mode=invoke actions without timeout_ms.
	DefaultInvokeTimeout time.Duration
	// DefaultJobTimeout applies to mode=job actions without timeout_ms.
	DefaultJobTimeout time.Duration
	// SweepInterval is how often expired approvals, plans and keys are pruned.
	SweepInterval time.Duration
	// RetentionOperations is how long a finished operation is kept with its
	// attempts and approvals (OPS-05). An unfinished operation is never pruned.
	RetentionOperations time.Duration
	// RetentionAudit is how long an audit row is kept (OPS-05).
	RetentionAudit time.Duration
}

func (c Config) withDefaults() Config {
	set := func(d *time.Duration, v time.Duration) {
		if *d <= 0 {
			*d = v
		}
	}
	set(&c.PlanTTL, 15*time.Minute)
	set(&c.ApprovalTTL, 15*time.Minute)
	set(&c.IdempotencyTTL, 24*time.Hour)
	set(&c.IdempotencyInProgressTTL, 10*time.Minute)
	set(&c.ProgressInterval, 500*time.Millisecond)
	set(&c.JobCancelGrace, 2*time.Second)
	set(&c.DefaultInvokeTimeout, 30*time.Second)
	set(&c.DefaultJobTimeout, 5*time.Minute)
	set(&c.SweepInterval, 30*time.Second)
	set(&c.RetentionOperations, DefaultRetentionOperations)
	set(&c.RetentionAudit, DefaultRetentionAudit)
	if c.IdempotencyKeysPerPrincipal <= 0 {
		c.IdempotencyKeysPerPrincipal = 10000
	}
	if c.JobWorkers <= 0 {
		c.JobWorkers = 1
	}
	if c.JobQueue <= 0 {
		c.JobQueue = 128
	}
	if c.MaxAttempts <= 0 {
		c.MaxAttempts = 3
	}
	return c
}

// Options configure New. DB and Catalog are required; the remaining interfaces
// are optional and wired by internal/controller.
type Options struct {
	DB *storage.DB
	// Clock and IDs default to the real clock and a generator on it.
	Clock  clock.Clock
	IDs    *ids.Generator
	Logger *slog.Logger
	// Catalog resolves action metadata; without it no action can run.
	Catalog Catalog
	// Dispatcher reaches plugin instances. P1 passes a fake (ADR-0008 §8).
	Dispatcher Dispatcher
	// Authorizer checks RBAC and delegation permissions.
	Authorizer Authorizer
	// Policy supplies the approval limits of an actor.
	Policy Policy
	// Revisions resolves host resource revisions for preconditions.
	Revisions Revisions
	// Notifier is called after low-risk operations that needed no approval.
	Notifier Notifier
	// Pruner removes another domain's expired rows on the Sweep tick (OPS-05):
	// the host passes identity, so sessions and tokens share this timer instead
	// of starting a second one. Optional.
	Pruner Pruner
	// ArgumentProtector 保护插件 operation/plan 的 x-secret 与 writeOnly 参数。
	// 未配置时敏感参数拒绝执行，普通参数保持既有路径。
	ArgumentProtector ArgumentProtector
	// NodeID is the node the host manages; standalone uses "local".
	NodeID string
	Config Config
	// DeferDispatch makes Start only repair state and run the sweeper: the job
	// workers and the resumption of recovered operations wait for StartDispatch,
	// which the host calls once plugin runtimes and host action handlers are
	// ready. False keeps the single-call behaviour of Start.
	DeferDispatch bool
}

// Service is the operation manager. It is safe for concurrent use.
type Service struct {
	db      *storage.DB
	clock   clock.Clock
	ids     *ids.Generator
	log     *slog.Logger
	cfg     Config
	nodeID  string
	catalog Catalog

	dispatcher        Dispatcher
	authorizer        Authorizer
	policy            Policy
	revisions         Revisions
	notifier          Notifier
	pruner            Pruner
	argumentProtector ArgumentProtector

	hostMu   sync.RWMutex
	host     map[string]hostAction
	hostJobs map[string]HostJobHandler

	runMu   sync.Mutex
	running map[string]*runningJob

	jobs *jobQueue

	startMu sync.Mutex
	started bool
	cancel  context.CancelFunc
	wg      sync.WaitGroup

	// base is the worker context created by Start; recovered holds the IDs
	// Recover returned until StartDispatch resumes them. All guarded by startMu.
	base          context.Context
	recovered     []string
	deferDispatch bool
	dispatched    bool
}

// hostAction is a registered host action.
type hostAction struct {
	handler HostHandler
	planner HostPlanner
}

// runningJob lets Cancel reach a running job.
type runningJob struct {
	context       context.Context
	release       context.CancelFunc
	cancel        context.CancelFunc
	done          chan struct{}
	cleanupWindow *runtimeCleanupWindow // 原 runMu 保护；同 executor 只允许一个硬清理窗口。
}

// New returns a manager. Start must be called to run jobs and expire approvals.
func New(opts Options) (*Service, error) {
	switch {
	case opts.DB == nil:
		return nil, errors.New("operations: nil database")
	case opts.Catalog == nil:
		return nil, errors.New("operations: nil catalog")
	}
	if opts.Clock == nil {
		opts.Clock = clock.System{}
	}
	if opts.IDs == nil {
		opts.IDs = ids.New(opts.Clock.Now)
	}
	if opts.Logger == nil {
		opts.Logger = slog.New(slog.DiscardHandler)
	}
	if opts.NodeID == "" {
		opts.NodeID = "local"
	}
	s := &Service{
		db:                opts.DB,
		clock:             opts.Clock,
		ids:               opts.IDs,
		log:               opts.Logger,
		cfg:               opts.Config.withDefaults(),
		nodeID:            opts.NodeID,
		catalog:           opts.Catalog,
		dispatcher:        opts.Dispatcher,
		authorizer:        opts.Authorizer,
		policy:            opts.Policy,
		revisions:         opts.Revisions,
		notifier:          opts.Notifier,
		pruner:            opts.Pruner,
		argumentProtector: opts.ArgumentProtector,
		host:              map[string]hostAction{},
		hostJobs:          map[string]HostJobHandler{},
		running:           map[string]*runningJob{},
	}
	s.jobs = newJobQueue(s.cfg.JobQueue)
	s.deferDispatch = opts.DeferDispatch
	return s, nil
}

// Config returns the effective configuration.
func (s *Service) Config() Config { return s.cfg }

// NodeID returns the node this host manages.
func (s *Service) NodeID() string { return s.nodeID }

// DB returns the underlying storage, for callers that need a read snapshot of
// their own resource in the same unit of work.
func (s *Service) DB() *storage.DB { return s.db }

// RegisterHostAction registers the executor and, optionally, the preview of a
// host action. Registration replaces a previous entry.
func (s *Service) RegisterHostAction(id string, h HostHandler, p HostPlanner) {
	s.hostMu.Lock()
	defer s.hostMu.Unlock()
	s.host[id] = hostAction{handler: h, planner: p}
}

// RegisterHostJob registers the executor of a mode=job host action. It runs on
// a job worker outside any transaction (see HostJobHandler). Registration
// replaces a previous entry.
func (s *Service) RegisterHostJob(id string, h HostJobHandler) {
	s.hostMu.Lock()
	defer s.hostMu.Unlock()
	s.hostJobs[id] = h
}

// hostJob returns the executor of a mode=job host action.
func (s *Service) hostJob(id string) (HostJobHandler, bool) {
	s.hostMu.RLock()
	defer s.hostMu.RUnlock()
	h, ok := s.hostJobs[id]
	return h, ok
}

// RegisterHostPlanner registers only the preview of a host action.
func (s *Service) RegisterHostPlanner(id string, p HostPlanner) {
	s.hostMu.Lock()
	defer s.hostMu.Unlock()
	a := s.host[id]
	a.planner = p
	s.host[id] = a
}

func (s *Service) hostAction(id string) (hostAction, bool) {
	s.hostMu.RLock()
	defer s.hostMu.RUnlock()
	h, ok := s.host[id]
	return h, ok
}

// HasHostAction reports whether a host action has an executor registered. It is
// introspection for callers that must not offer an action they cannot run: the
// native agent session builds its tool list from the catalog, which also holds
// host actions served outside the operation surface (for example the plugin
// install routes). It never exposes the handler.
func (s *Service) HasHostAction(id string) bool {
	if _, ok := s.hostAction(id); ok {
		return true
	}
	_, ok := s.hostJob(id)
	return ok
}

// Start recovers interrupted work, starts the job workers and the expiry
// scanner. It runs once per service: Stop is final, because the in-memory job
// queue cannot be reopened without losing the recovery guarantee.
func (s *Service) Start(ctx context.Context) error {
	s.startMu.Lock()
	if s.started {
		s.startMu.Unlock()
		return nil
	}
	if s.jobs.isClosed() {
		s.startMu.Unlock()
		return errors.New("operations: the service was stopped and cannot be started again")
	}
	s.started = true
	base, cancel := context.WithCancel(ctx)
	s.cancel = cancel
	s.base = base
	s.startMu.Unlock()

	requeued, err := s.Recover(ctx)
	if err != nil {
		s.Stop()
		return err
	}
	s.startMu.Lock()
	s.recovered = requeued
	s.startMu.Unlock()
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.sweepLoop(base)
	}()
	if !s.deferDispatch {
		// Single-call mode resumes synchronously, as callers of Start expect.
		for _, id := range s.beginDispatch() {
			s.resume(ctx, id)
		}
	}
	return nil
}

// StartDispatch 启动 job worker，并在后台异步 resume Recover 记录下来的待恢复列表。
// 必须在插件运行时、updater 恢复与全部宿主动作 handler 就绪之后调用。
// It is a no-op before Start, after Stop, or when dispatch already started.
func (s *Service) StartDispatch(ctx context.Context) {
	requeued := s.beginDispatch()
	if requeued == nil {
		return
	}
	s.startMu.Lock()
	base := s.base
	s.startMu.Unlock()
	// The resumption is bounded by both the caller and the service lifetime.
	rctx, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(base, cancel)
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		defer stop()
		defer cancel()
		for _, id := range requeued {
			if rctx.Err() != nil {
				return // the next start recovers what is left
			}
			s.resume(rctx, id)
		}
	}()
}

// beginDispatch starts the job workers once and hands out the recovered IDs.
// It returns nil when dispatch must not (or already did) start; an empty,
// non-nil slice means workers started with nothing to resume.
func (s *Service) beginDispatch() []string {
	s.startMu.Lock()
	defer s.startMu.Unlock()
	if !s.started || s.dispatched {
		return nil
	}
	s.dispatched = true
	base := s.base
	for i := 0; i < s.cfg.JobWorkers; i++ {
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.runWorker(base)
		}()
	}
	requeued := s.recovered
	s.recovered = nil
	if requeued == nil {
		requeued = []string{}
	}
	return requeued
}

func (s *Service) Stop() {
	s.startMu.Lock()
	if !s.started {
		s.startMu.Unlock()
		return
	}
	s.started = false
	cancel := s.cancel
	s.startMu.Unlock()
	s.jobs.close()
	if cancel != nil {
		cancel()
	}
	// 进行中的 invoke 不挂在 worker ctx 上（已与请求解耦），关停时逐个打断。
	s.runMu.Lock()
	for _, job := range s.running {
		job.cancel()
	}
	s.runMu.Unlock()
	s.wg.Wait()
}

// WaitJobs blocks until no job is queued or running, for tests and shutdown.
func (s *Service) WaitJobs(ctx context.Context) error { return s.jobs.wait(ctx) }

// defaultTimeout is the fallback deadline of an action of the given mode.
func (s *Service) defaultTimeout(mode string) time.Duration {
	if mode == ModeJob {
		return s.cfg.DefaultJobTimeout
	}
	return s.cfg.DefaultInvokeTimeout
}

// action resolves and normalises catalog metadata.
func (s *Service) action(id string) (Action, error) {
	if id == "" {
		return Action{}, problem.Validation(problem.Violation{
			Pointer: "/action", Code: "REQUIRED", Message: "An action is required.",
		})
	}
	a, ok := s.catalog.Action(id)
	if !ok {
		return Action{}, problem.New(problem.NotFound, "Unknown action %q.", id)
	}
	if a.ID == "" {
		a.ID = id
	}
	a = a.normalized(s.defaultTimeout(a.Mode))
	if err := a.validate(); err != nil {
		return Action{}, problem.Wrap(err)
	}
	return a, nil
}

// limits returns the execution limits of the actor, with the ADR-0004 D6
// defaults filled in.
func (s *Service) limits(ctx context.Context, a actor.Actor, act Action, target Target) (Limits, error) {
	var l Limits
	if s.policy != nil {
		got, err := s.policy.Limits(ctx, a, act, target)
		if err != nil {
			return Limits{}, problem.From(err)
		}
		l = got
	}
	if l.AutoApproveMaxRisk == "" {
		l.AutoApproveMaxRisk = RiskLow
	}
	if l.OnApprovalRequired == "" {
		l.OnApprovalRequired = ApprovalQueue
	}
	return l, nil
}

// authorize applies RBAC and the delegation policy. A permission error from the
// authorizer may carry more context; it is passed through as is.
func (s *Service) authorize(ctx context.Context, a actor.Actor, act Action, target Target) error {
	if s.authorizer == nil {
		return nil
	}
	if err := s.authorizer.Authorize(ctx, a, act, target); err != nil {
		return problem.From(err)
	}
	return nil
}

// currentRevision asks the resource owner for the revision of a host subject.
func (s *Service) currentRevision(ctx context.Context, tx *storage.Tx, subject string) (string, error) {
	if s.revisions == nil {
		return "", nil
	}
	rev, err := s.revisions.CurrentRevision(ctx, tx, subject)
	if err != nil {
		return "", problem.Wrap(err)
	}
	return rev, nil
}

// origin is the transaction origin of an operation.
func (s *Service) origin(a actor.Actor, operationID, traceID, nodeID string) storage.Origin {
	if nodeID == "" {
		nodeID = s.nodeID
	}
	return storage.Origin{Actor: a, OperationID: operationID, TraceID: traceID, NodeID: nodeID}
}

// principalKey is the idempotency scope of an actor (ARCH §4.1: user + route).
func principalKey(a actor.Actor) string {
	switch a.Kind {
	case actor.Human:
		return "human:" + a.ID
	case actor.AIAgent:
		return "ai_agent:" + a.ID + ":" + a.OnBehalfOf
	case actor.Service:
		return "service:" + a.ID
	case actor.System:
		return "system:" + a.ID
	default:
		return string(a.Kind) + ":" + a.ID
	}
}

// samePrincipal reports whether two actors are the same principal. Sessions and
// factors are deliberately ignored: they identify a request, not a person.
func samePrincipal(a, b actor.Actor) bool {
	return a.Kind == b.Kind && a.ID == b.ID && a.OnBehalfOf == b.OnBehalfOf
}

// digestOf returns the SHA-256 of a canonical JSON document.
func digestOf(canonical []byte) string {
	sum := sha256.Sum256(canonical)
	return canonicalJSONPrefix + hex.EncodeToString(sum[:])
}

// fingerprintOf combines the parts of a request that identify it for
// idempotency: the action, its canonical arguments, the target and the
// concurrency guard.
func fingerprintOf(parts ...any) string {
	raw, err := json.Marshal(parts)
	if err != nil {
		// The parts are plain structs, JSON and strings; this cannot fail.
		return digestOf([]byte("[]"))
	}
	canon, err := canonicalJSON(raw)
	if err != nil {
		return digestOf([]byte("[]"))
	}
	return digestOf(canon)
}

// responseJSON marshals a response body, replacing a nil body with null.
func responseJSON(v any) json.RawMessage {
	if v == nil {
		return json.RawMessage("null")
	}
	b, err := json.Marshal(v)
	if err != nil {
		return json.RawMessage("null")
	}
	return secrets.RedactRefs(b)
}

// newResponse builds the 202-style response for an operation.
func newResponse(op *Operation) *Response {
	return &Response{Status: 202, Body: responseJSON(op), OperationID: op.ID, Operation: op}
}

// finishedResponse builds either the 200 operation outcome or the 202
// operation, following the OpenAPI rule that a mutating call answers 200 only
// when it finished synchronously.
func finishedResponse(op *Operation) *Response {
	if op.Status == Succeeded {
		out := op.Outcome()
		return &Response{Status: 200, Body: responseJSON(out), OperationID: op.ID, Operation: op, Outcome: out}
	}
	return newResponse(op)
}
