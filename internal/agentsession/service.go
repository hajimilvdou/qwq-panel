// SPDX-License-Identifier: AGPL-3.0-only

package agentsession

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/qwq-panel/qwq/internal/actor"
	"github.com/qwq-panel/qwq/internal/authz"
	"github.com/qwq-panel/qwq/internal/operations"
	"github.com/qwq-panel/qwq/internal/platform/clock"
	"github.com/qwq-panel/qwq/internal/platform/ids"
	"github.com/qwq-panel/qwq/internal/platform/problem"
	"github.com/qwq-panel/qwq/internal/secrets"
	"github.com/qwq-panel/qwq/internal/storage"
)

// ToolCatalog supplies the actions a session may offer to its core. The host
// adapts internal/catalog to it; this package only defines the contract so the
// native core and its tests do not depend on the catalog.
type ToolCatalog interface {
	// Actions returns every action that could be offered, without permission
	// filtering: the session hides non-read actions in read_only mode.
	Actions(ctx context.Context) []ToolSpec
}

// Config tunes the service. The zero value is small-host friendly: 200
// messages retained, 40 messages of history, a 256-event ring, a 15 s SSE
// heartbeat, a 2 minute turn deadline, and per owner 50 sessions, 3 running
// turns and 30 turns a minute.
type Config struct {
	// RetainMessages is the number of messages kept per session.
	RetainMessages int
	// MaxHistory is the number of messages handed to a core as context.
	MaxHistory int
	// RingSize bounds the in-memory event ring used by SSE replay.
	RingSize int
	// SubscriberBuffer bounds one SSE subscriber's queue.
	SubscriberBuffer int
	// Heartbeat is the SSE heartbeat interval.
	Heartbeat time.Duration
	// TurnTimeout bounds one core run.
	TurnTimeout time.Duration
	// ListLimit is the default page size of the session list.
	ListLimit int
	// MaxSessionsPerOwner bounds the sessions one owner may keep.
	MaxSessionsPerOwner int
	// MaxRunningPerOwner bounds the turns one owner may run at the same time.
	MaxRunningPerOwner int
	// TurnsPerMinute is the per-owner turn rate (ADR-0004 D10).
	TurnsPerMinute int
}

func (c Config) withDefaults() Config {
	if c.RetainMessages <= 0 {
		c.RetainMessages = 200
	}
	if c.MaxHistory <= 0 {
		c.MaxHistory = 40
	}
	if c.RingSize <= 0 || c.RingSize > maxEventRing {
		c.RingSize = maxEventRing
	}
	if c.SubscriberBuffer <= 0 {
		c.SubscriberBuffer = 1024
	}
	if c.Heartbeat <= 0 {
		c.Heartbeat = 15 * time.Second
	}
	if c.TurnTimeout <= 0 {
		c.TurnTimeout = 5 * time.Minute
	}
	if c.ListLimit <= 0 {
		c.ListLimit = 50
	}
	if c.MaxSessionsPerOwner <= 0 {
		c.MaxSessionsPerOwner = 50
	}
	if c.MaxRunningPerOwner <= 0 {
		c.MaxRunningPerOwner = 3
	}
	if c.TurnsPerMinute <= 0 {
		c.TurnsPerMinute = 30
	}
	return c
}

// Options configure New. DB is required; Secrets stores the sessions' API keys
// (without it SetAPIKey answers UNAVAILABLE and the native core sends no key),
// and Catalog/Runner/Approvals are wired by the host.
type Options struct {
	DB      *storage.DB
	Clock   clock.Clock
	IDs     *ids.Generator
	Logger  *slog.Logger
	Secrets *secrets.Store

	// Catalog resolves the actions offered to a core. Nil means the core gets
	// no tools.
	Catalog ToolCatalog
	// Runner executes tool calls through the host operation path. Nil makes
	// every tool call answer UNAVAILABLE.
	Runner Runner
	// Approvals lets a paused session learn the human decision. Nil leaves the
	// session waiting_approval until the user cancels.
	Approvals ApprovalBridge
	// ApprovalMinter mints real host approvals for external CLI permission prompts.
	// When nil and Approvals implements HostApprovalMinter, Approvals is used.
	ApprovalMinter HostApprovalMinter
	// RoleResolver optionally resolves the current RBAC role ("admin", "operator",
	// "viewer") of a session owner to enforce security boundaries on turns and
	// slash commands (e.g. /mode full).
	RoleResolver func(ctx context.Context, owner actor.Actor) (string, error)
	// Cores replaces or adds cores; the native core is always registered.
	Cores []Core
	// HTTPClient is used by the native core (tests inject one).
	HTTPClient *http.Client
	// Native tunes the built-in core.
	Native NativeOptions
	// DataDir is the host's persistent data directory (e.g. /var/lib/qwq) where
	// isolated per-core CLI official login credentials are stored under
	// <DataDir>/agent-homes/<core>.
	DataDir string
	Config  Config
}

// Service is the agent session backend. It is safe for concurrent use.
type Service struct {
	db           *storage.DB
	clock        clock.Clock
	ids          *ids.Generator
	log          *slog.Logger
	cfg          Config
	catalog      ToolCatalog
	runner       Runner
	bridge       ApprovalBridge
	roleResolver func(ctx context.Context, owner actor.Actor) (string, error)
	secrets      *secrets.Store
	cliAuth      *CLIAuthManager
	workspace    *WorkspaceManager
	exchange     *ExchangeManager
	registry     *RegistryManager

	cores map[string]Core

	// turnRate limits the turns of one owner.
	turnRate *authz.RateLimiter
	// admitMu makes "count the owner's running turns, then start one" atomic.
	// It is only ever taken under rt.mu.
	admitMu sync.Mutex
	// streams 是该服务全部会话的活跃订阅数，由订阅的一次关闭统一释放。
	streams atomic.Int64

	base   context.Context
	cancel context.CancelFunc
	// sweeper tracks the idle-runtime sweep goroutine.
	sweeper sync.WaitGroup

	// closed refuses new turns from the moment Close starts. It is atomic
	// because Send reads it under rt.mu, where s.mu must not be taken.
	closed atomic.Bool

	mu       sync.Mutex
	sessions map[string]*sessionRuntime
}

// sessionPrefix is the TypeID prefix of a session.
const sessionPrefix = "sess"

// errUserCancel is the cause a cancelled turn carries, so the turn loop can
// tell a user cancel from a deadline.
var errUserCancel = errors.New("agentsession: cancelled by the user")

// New returns the service. The native core is registered by default; call
// Close to stop the background turns.
func New(opts Options) (*Service, error) {
	if opts.DB == nil {
		return nil, errors.New("agentsession: nil database")
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
	cfg := opts.Config.withDefaults()
	base, cancel := context.WithCancel(context.Background())
	cliAuth := NewCLIAuthManager(opts.DataDir)
	ws := NewWorkspaceManager(opts.DataDir, cliAuth)
	ex := NewExchangeManager(opts.DataDir)
	reg := NewRegistryManager(ws, opts.HTTPClient)
	s := &Service{
		db:           opts.DB,
		clock:        opts.Clock,
		ids:          opts.IDs,
		log:          opts.Logger,
		cfg:          cfg,
		catalog:      opts.Catalog,
		runner:       opts.Runner,
		bridge:       opts.Approvals,
		roleResolver: opts.RoleResolver,
		secrets:      opts.Secrets,
		cliAuth:      cliAuth,
		workspace:    ws,
		exchange:     ex,
		registry:     reg,
		cores:        map[string]Core{},
		turnRate:     authz.NewRateLimiter(0, opts.Clock.Now),
		base:         base,
		cancel:       cancel,
		sessions:     map[string]*sessionRuntime{},
	}
	// The service itself resolves the global AI providers of the native and
	// external adapter cores (GAP-2): it owns the rows and the secret store.
	s.registerDefaultAdapterCores(opts)
	for _, c := range opts.Cores {
		if c != nil && c.Name() != "" {
			s.cores[c.Name()] = c
		}
	}
	s.sweeper.Add(1)
	go s.sweepLoop()
	return s, nil
}

// Runtime eviction: a runtime is only a cache of the session row plus the
// replay ring, so one nobody uses is released and rebuilt on demand.
const (
	runtimeIdleTTL    = 10 * time.Minute
	runtimeSweepEvery = time.Minute
)

// sweepLoop periodically releases idle runtimes until the service closes.
func (s *Service) sweepLoop() {
	defer s.sweeper.Done()
	for {
		select {
		case <-s.base.Done():
			return
		case <-s.clock.After(runtimeSweepEvery):
			s.sweepRuntimes(s.clock.Now())
		}
	}
}

// sweepRuntimes drops the runtimes with no turn, approval or subscriber that
// runtimeFor has not handed out for runtimeIdleTTL. A runtime that is locked is
// in use, so it is skipped rather than waited for under s.mu.
func (s *Service) sweepRuntimes(now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, rt := range s.sessions {
		if now.UnixNano()-rt.lastUsed.Load() < int64(runtimeIdleTTL) || !rt.mu.TryLock() {
			continue
		}
		idle := !rt.running && rt.pending == nil && len(rt.subs) == 0
		rt.mu.Unlock()
		if idle {
			delete(s.sessions, id)
		}
	}
}

// Heartbeat is the SSE heartbeat interval the API uses.
func (s *Service) Heartbeat() time.Duration { return s.cfg.Heartbeat }

// CLIAuth returns the persistent external CLI login manager.
func (s *Service) CLIAuth() *CLIAuthManager { return s.cliAuth }

// Workspace returns the separated MCP/Skills/Prompts workspace manager.
func (s *Service) Workspace() *WorkspaceManager { return s.workspace }

// Exchange returns the interactive file exchange folder manager.
func (s *Service) Exchange() *ExchangeManager { return s.exchange }

// Registry returns the official Skills & MCP registry manager.
func (s *Service) Registry() *RegistryManager { return s.registry }

// Close stops every running turn, waits until the turns wrote their final
// status, and only then closes the SSE subscribers. A paused approval stays
// waiting_approval in the database, for Recover to pick up. It is safe to call
// more than once.
func (s *Service) Close() {
	if !s.closed.CompareAndSwap(false, true) {
		return
	}
	if s.cliAuth != nil {
		s.cliAuth.Close()
	}
	s.mu.Lock()
	runtimes := make([]*sessionRuntime, 0, len(s.sessions))
	for _, rt := range s.sessions {
		runtimes = append(runtimes, rt)
	}
	s.sessions = map[string]*sessionRuntime{}
	s.mu.Unlock()

	for _, rt := range runtimes {
		rt.mu.Lock()
		if rt.cancel != nil {
			rt.cancel(errUserCancel)
		}
		if rt.pending != nil && rt.pending.cancel != nil {
			rt.pending.cancel()
		}
		rt.mu.Unlock()
	}
	s.cancel()
	s.sweeper.Wait()
	for _, rt := range runtimes {
		rt.wg.Wait()
	}
	for _, rt := range runtimes {
		rt.mu.Lock()
		rt.closed = true
		rt.closeSubscribersLocked()
		rt.mu.Unlock()
	}
}

// interruptedDetail is what the model and the user read about a call that was
// open when the process stopped.
const interruptedDetail = "turn interrupted by restart; the operation may have run: check operation_id"

// Recover repairs the sessions a previous process left busy: a running turn
// cannot continue, so it ends as failed, and a paused approval gets its waiter
// back. It runs once, before requests are served. A session that cannot be
// repaired is logged and left for the owner to cancel; only a failure to list
// the sessions is returned.
func (s *Service) Recover(ctx context.Context) error {
	recs, err := s.busySessions(ctx)
	if err != nil {
		return err
	}
	for i := range recs {
		rec := &recs[i]
		if err := s.recoverSession(ctx, rec); err != nil {
			s.log.WarnContext(ctx, "agent session: recover", "session_id", rec.ID, "error", err)
		}
	}
	return nil
}

// recoverSession repairs one busy session.
func (s *Service) recoverSession(ctx context.Context, rec *Session) error {
	rt := s.runtimeFor(rec)
	var waiting []ToolRecord
	if rec.Status == StatusWaitingApproval {
		var err error
		if waiting, err = s.toolCallsWithStatus(ctx, rec.ID, ToolAwaitingApproval); err != nil {
			return err
		}
	}
	if len(waiting) == 0 {
		rt.mu.Lock()
		defer rt.mu.Unlock()
		if err := s.closeOpenCallsLocked(ctx, rt, ToolFailed, interruptedDetail); err != nil {
			return err
		}
		return s.publishLocked(ctx, rt, Event{Type: EventTurnCompleted, Status: string(StatusFailed)})
	}
	call := waiting[len(waiting)-1]
	messageID, err := s.assistantMessageOf(ctx, rec.ID, call.CallID)
	if err != nil {
		return err
	}
	p := &pendingApproval{
		callID: call.CallID, approvalID: call.ApprovalID, operationID: call.OperationID,
		action: call.Action, args: call.Args, messageID: messageID,
	}
	rt.mu.Lock()
	rt.pending = p
	rt.mu.Unlock()
	s.startWaiter(rt, p)
	return nil
}

// closeOpenCallsLocked gives every call without a result one, so the transcript
// stays paired. A call that already reported a running job has its result and
// is left alone. The caller holds rt.mu.
func (s *Service) closeOpenCallsLocked(ctx context.Context, rt *sessionRuntime, status ToolStatus, detail string) error {
	calls, err := s.toolCallsWithStatus(ctx, rt.session.ID, ToolProposed, ToolRunning, ToolAwaitingApproval)
	if err != nil {
		return err
	}
	have, err := s.toolMessageCallIDs(ctx, rt.session.ID)
	if err != nil {
		return err
	}
	last := ""
	for _, call := range calls {
		if have[call.CallID] {
			continue
		}
		if err := s.publishLocked(ctx, rt, Event{
			Type: EventToolResult, CallID: call.CallID, Action: call.Action, Status: string(status),
			Error:       ErrorOf(problem.New(problem.Unavailable, "%s", detail)),
			OperationID: call.OperationID, ApprovalID: call.ApprovalID,
		}); err != nil {
			return err
		}
		last = call.CallID
	}
	if last == "" {
		return nil
	}
	messageID, err := s.assistantMessageOf(ctx, rt.session.ID, last)
	if err != nil {
		return err
	}
	return s.fillMissingToolResultsLocked(ctx, rt, messageID, detail)
}

// runtimeFor returns the runtime of a session, creating it on first use and
// refreshing the fields another request may have changed.
func (s *Service) runtimeFor(rec *Session) *sessionRuntime {
	s.mu.Lock()
	rt := s.sessions[rec.ID]
	if rt == nil {
		rt = &sessionRuntime{
			session: *rec,
			seq:     rec.LastSeq,
			subs:    map[*subscriber]struct{}{},
			delta:   map[string]*strings.Builder{},
		}
		rt.lastUsed.Store(s.clock.Now().UnixNano())
		s.sessions[rec.ID] = rt
		s.mu.Unlock()
		return rt
	}
	rt.lastUsed.Store(s.clock.Now().UnixNano())
	s.mu.Unlock()

	rt.mu.Lock()
	rt.session.Title = rec.Title
	rt.session.Core = rec.Core
	rt.session.PermissionMode = rec.PermissionMode
	rt.session.Config = rec.Config
	rt.session.APIKeyRef = rec.APIKeyRef
	rt.session.Revision = rec.Revision
	rt.session.Pending = rec.Pending
	rt.session.LastMessageAt = rec.LastMessageAt
	if rec.LastSeq > rt.seq {
		rt.seq = rec.LastSeq
	}
	if !rt.running {
		rt.session.Status = rec.Status
	}
	rt.mu.Unlock()
	return rt
}

// loadFor loads a session the owner may see; another principal's session is
// NOT_FOUND.
func (s *Service) loadFor(ctx context.Context, owner actor.Actor, id string) (*Session, error) {
	if err := checkOwner(owner); err != nil {
		return nil, err
	}
	return loadSessionFor(ctx, s.db.Reader(), owner, id)
}

// checkOwner rejects actors that cannot own a session (an anonymous system
// principal, or a server-to-server delegation token).
func checkOwner(a actor.Actor) error {
	switch a.Kind {
	case actor.Human, actor.Service:
		if a.ID == "" {
			return problem.New(problem.Unauthenticated, "The request has no credentials.")
		}
		return nil
	}
	return problem.New(problem.PermissionDenied, "Agent sessions belong to a person or a service account.")
}

// enforceSecurityBoundary validates the session owner's current role and actor
// kind against the session core and permission mode whenever RoleResolver is
// wired.
func (s *Service) enforceSecurityBoundary(ctx context.Context, owner actor.Actor, core CoreName, mode operations.PermissionMode) error {
	if s.roleResolver == nil {
		return nil
	}
	role, err := s.roleResolver(ctx, owner)
	if err != nil {
		return problem.From(err)
	}
	return ValidateAgentSessionActorBoundary(owner, role, string(core), string(mode))
}

// Create creates a session owned by owner.
func (s *Service) Create(ctx context.Context, owner actor.Actor, req CreateRequest) (*Session, error) {
	if err := checkOwner(owner); err != nil {
		return nil, err
	}
	title, err := validateTitle(req.Title)
	if err != nil {
		return nil, err
	}
	core := req.Core
	if core == "" {
		core = CoreNative
	}
	if !core.Valid() {
		return nil, problem.Validation(problem.Violation{
			Pointer: "/core", Code: "INVALID",
			Message: "core must be native, claude-code, codex or opencode.",
		})
	}
	mode := req.PermissionMode
	if mode == "" {
		mode = operations.DefaultPermissionMode
	}
	if !mode.Valid() {
		return nil, problem.Validation(problem.Violation{
			Pointer: "/permission_mode", Code: "INVALID",
			Message: "permission_mode must be read_only, safe, full or custom.",
		})
	}
	if err := s.enforceSecurityBoundary(ctx, owner, core, mode); err != nil {
		return nil, err
	}
	cfg, err := normalizeConfig(core, req.Config)
	if err != nil {
		return nil, err
	}
	now := s.clock.Now().UTC().Truncate(time.Millisecond)
	rec := &Session{
		ID: s.ids.New(sessionPrefix), PluginID: PluginID, Title: title, Core: core,
		PermissionMode: mode, Status: StatusIdle, Config: cfg,
		CreatedAt: now, UpdatedAt: now, OwnerKind: owner.Kind, OwnerID: owner.ID,
	}
	if err := s.insertSession(ctx, owner, rec); err != nil {
		return nil, err
	}
	s.runtimeFor(rec)
	return rec, nil
}

// Get returns one session of the owner.
func (s *Service) Get(ctx context.Context, owner actor.Actor, sessionID string) (*Session, error) {
	rec, err := s.loadFor(ctx, owner, sessionID)
	if err != nil {
		return nil, err
	}
	s.runtimeFor(rec)
	return rec, nil
}

// OwnerOf resolves the owner actor of a session by its identifier, without the
// caller predicate of the read paths: the event dispatcher needs the raw owner
// to decide stream visibility (gap 6), and a missing row reports ok=false.
// The public API never calls it.
func (s *Service) OwnerOf(ctx context.Context, sessionID string) (actor.Actor, bool) {
	var kind, id string
	err := s.db.Reader().QueryRowContext(ctx,
		`SELECT owner_kind, owner_id FROM agent_sessions WHERE session_id = ?`, sessionID).Scan(&kind, &id)
	if err != nil {
		return actor.Actor{}, false
	}
	return actor.Actor{Kind: actor.Kind(kind), ID: id}, true
}

// List returns one page of the owner's sessions. status may be a Status,
// StatusAttention, or empty.
func (s *Service) List(ctx context.Context, owner actor.Actor, f ListFilter) (*SessionPage, error) {
	if err := checkOwner(owner); err != nil {
		return nil, err
	}
	return s.listSessions(ctx, owner, f)
}

// Messages returns the newest limit messages of a session in chronological
// order (0 means the configured history size).
func (s *Service) Messages(ctx context.Context, owner actor.Actor, sessionID string, limit int) ([]Message, error) {
	return s.MessagesBefore(ctx, owner, sessionID, 0, limit)
}

// MessagesBefore returns the newest limit messages with seq < before (before
// <= 0 means the newest page), in chronological order, for the owner of the
// session only (gap 6: transcript pagination).
func (s *Service) MessagesBefore(ctx context.Context, owner actor.Actor, sessionID string, before int64, limit int) ([]Message, error) {
	if _, err := s.loadFor(ctx, owner, sessionID); err != nil {
		return nil, err
	}
	msgs, err := s.messages(ctx, sessionID, before, limit)
	if err != nil {
		return nil, err
	}
	if msgs == nil {
		msgs = []Message{}
	}
	return msgs, nil
}

// PendingApprovals returns the calls of a session that wait for a human
// decision, enriched with the catalog's confirmation-card text.
func (s *Service) PendingApprovals(ctx context.Context, owner actor.Actor, sessionID string) ([]PendingApproval, error) {
	if _, err := s.loadFor(ctx, owner, sessionID); err != nil {
		return nil, err
	}
	recs, err := s.toolCallsWithStatus(ctx, sessionID, ToolAwaitingApproval)
	if err != nil {
		return nil, err
	}
	out := make([]PendingApproval, 0, len(recs))
	for _, rec := range recs {
		pa := PendingApproval{
			CallID: rec.CallID, ApprovalID: rec.ApprovalID, OperationID: rec.OperationID,
			Action: rec.Action, Args: rec.Args, Status: rec.Status, CreatedAt: rec.CreatedAt,
		}
		if tool, ok := s.toolFor(ctx, rec.Action); ok {
			pa.Summary, pa.Description = tool.Summary, tool.Description
			pa.Risk, pa.Approval = tool.Risk, tool.Approval
		}
		out = append(out, pa)
	}
	return out, nil
}

// Update changes the title and/or the permission mode. The mode is read from
// the session row only: a core cannot change it, and the API route accepts a
// browser session or a service account, never a delegation.
func (s *Service) Update(ctx context.Context, owner actor.Actor, sessionID string, req UpdateRequest) (*Session, error) {
	rec, err := s.loadFor(ctx, owner, sessionID)
	if err != nil {
		return nil, err
	}
	if req.Title == nil && req.PermissionMode == "" && len(req.Config) == 0 {
		return nil, problem.Validation(problem.Violation{
			Pointer: "/title", Code: "REQUIRED", Message: "Provide title, permission_mode, and/or config.",
		})
	}
	if req.ExpectedRevision != "" && req.ExpectedRevision != rec.Revision {
		return nil, problem.Conflict(rec.Revision)
	}
	var title *string
	if req.Title != nil {
		v, err := validateTitle(*req.Title)
		if err != nil {
			return nil, err
		}
		title = &v
	}
	if req.PermissionMode != "" && !req.PermissionMode.Valid() {
		return nil, problem.Validation(problem.Violation{
			Pointer: "/permission_mode", Code: "INVALID",
			Message: "permission_mode must be read_only, safe, full or custom.",
		})
	}
	nextMode := rec.PermissionMode
	if req.PermissionMode != "" {
		nextMode = req.PermissionMode
	}
	if err := s.enforceSecurityBoundary(ctx, owner, rec.Core, nextMode); err != nil {
		return nil, err
	}
	var mergedCfg json.RawMessage
	if len(req.Config) > 0 {
		var err error
		mergedCfg, err = mergeSessionConfig(rec.Core, rec.Config, req.Config)
		if err != nil {
			return nil, err
		}
	}
	var pointers []string
	if title != nil {
		pointers = append(pointers, "/title")
	}
	if req.PermissionMode != "" {
		pointers = append(pointers, "/permission_mode")
	}
	if len(mergedCfg) > 0 {
		pointers = append(pointers, "/config")
	}
	updated, err := s.updateSession(ctx, owner, sessionID, 0, pointers, func(cur *Session) error {
		if req.ExpectedRevision != "" && req.ExpectedRevision != cur.Revision {
			return problem.Conflict(cur.Revision)
		}
		effMode := cur.PermissionMode
		if req.PermissionMode != "" {
			effMode = req.PermissionMode
		}
		if err := s.enforceSecurityBoundary(ctx, owner, cur.Core, effMode); err != nil {
			return err
		}
		if title != nil {
			cur.Title = *title
		}
		if req.PermissionMode != "" {
			cur.PermissionMode = req.PermissionMode
		}
		if len(mergedCfg) > 0 {
			m, err := mergeSessionConfig(cur.Core, cur.Config, req.Config)
			if err != nil {
				return err
			}
			cur.Config = m
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	s.auditUpdate(ctx, owner, updated, pointers)
	rt := s.runtimeFor(updated)
	if len(mergedCfg) > 0 {
		rt.mu.Lock()
		rt.session.Config = updated.Config
		rt.mu.Unlock()
	}
	if req.PermissionMode != "" {
		s.applyMode(ctx, rt, req.PermissionMode)
	}
	return updated, nil
}

// mergeSessionConfig merges a partial JSON object patch onto an existing session
// config, refusing plaintext secrets and validating the resulting config.
func mergeSessionConfig(core CoreName, existing, patch json.RawMessage) (json.RawMessage, error) {
	if err := refusePlaintextSecrets(patch); err != nil {
		return nil, err
	}
	base := map[string]any{}
	if len(existing) > 0 {
		_ = json.Unmarshal(existing, &base)
	}
	var delta map[string]any
	if err := json.Unmarshal(patch, &delta); err != nil || delta == nil {
		return nil, problem.Validation(problem.Violation{
			Pointer: "/config", Code: "INVALID", Message: "config must be a JSON object.",
		})
	}
	for k, v := range delta {
		if v == nil {
			delete(base, k)
		} else {
			base[k] = v
		}
	}
	raw, err := json.Marshal(base)
	if err != nil {
		return nil, problem.Wrap(err)
	}
	if len(raw) > maxConfigBytes {
		return nil, problem.Validation(problem.Violation{
			Pointer: "/config", Code: "too_large", Message: "config exceeds 32 KiB.",
		})
	}
	normalized, err := normalizeConfig(core, raw)
	if err != nil {
		return nil, err
	}
	if core == CoreNative {
		if _, err := decodeEnhancedNativeConfig(normalized); err != nil {
			return nil, err
		}
	}
	return normalized, nil
}

// auditUpdate records a metadata or permission-mode change. It runs in its own
// transaction after the update committed, so a failing audit can never undo the
// user's decision; the error is only logged.
func (s *Service) auditUpdate(ctx context.Context, owner actor.Actor, rec *Session, pointers []string) {
	err := s.db.Update(ctx, func(tx *storage.Tx) error {
		tx.SetOrigin(storage.Origin{Actor: owner})
		return operations.Audit(ctx, tx, operations.AuditRecord{
			Actor: owner, Action: "agent.session.update", Subject: sessionSubject(rec.ID),
			Outcome: operations.AuditSuccess,
			Details: auditDetails(map[string]any{
				"permission_mode": rec.PermissionMode, "changed": pointers,
			}),
		})
	})
	if err != nil {
		s.log.WarnContext(ctx, "agent session: audit update", "session_id", rec.ID, "error", err)
	}
}

// applyMode reacts to a permission-mode change: switching to read_only withdraws
// a pending write tool call (ADR-0010 §2.1, design §6). When an external CLI
// turn is still actively running inline while waiting on an approval, it cancels
// the running turn so ApprovalRouter aborts and cancels the minted operation.
func (s *Service) applyMode(ctx context.Context, rt *sessionRuntime, mode operations.PermissionMode) {
	if mode != operations.PermissionReadOnly {
		return
	}
	rt.mu.Lock()
	if rt.pending == nil {
		rt.mu.Unlock()
		return
	}
	if rt.running {
		if rt.cancel != nil {
			rt.cancel(errUserCancel)
		}
		rt.mu.Unlock()
		return
	}
	if tool, ok := s.toolFor(ctx, rt.pending.action); ok && tool.Effect == operations.EffectRead {
		rt.mu.Unlock()
		return
	}
	p := claimPendingLocked(rt)
	rt.mu.Unlock()
	s.withdrawPending(ctx, rt, p, "the session switched to read_only before the approval was decided")
}

// SetAPIKey stores the native core's API key of a session, replacing the
// previous one (AGT-02). The key becomes a secret owned by the session itself,
// so the core can only ever reveal the key of the session it runs for, and the
// key goes with the session when it is deleted. It is write-only: the answer,
// the events and the audit row only say that a key is set. Like the permission
// mode, only the owner can change it; an AI actor is refused by checkOwner.
func (s *Service) SetAPIKey(ctx context.Context, owner actor.Actor, sessionID, key string) (*Session, error) {
	if err := checkOwner(owner); err != nil {
		return nil, err
	}
	plaintext, err := validateAPIKey(key)
	if err != nil {
		return nil, err
	}
	defer clear(plaintext)
	return s.writeAPIKey(ctx, owner, sessionID, plaintext)
}

// ClearAPIKey removes the API key of a session; the native core then sends no
// Authorization header. Clearing a session without a key changes nothing.
func (s *Service) ClearAPIKey(ctx context.Context, owner actor.Actor, sessionID string) (*Session, error) {
	if err := checkOwner(owner); err != nil {
		return nil, err
	}
	return s.writeAPIKey(ctx, owner, sessionID, nil)
}

// writeAPIKey runs the API-key write and refreshes the runtime, so the next
// turn (also one resumed after an approval) uses the new key.
func (s *Service) writeAPIKey(ctx context.Context, owner actor.Actor, sessionID string, key []byte) (*Session, error) {
	if s.secrets == nil {
		return nil, problem.New(problem.Unavailable, "API keys cannot be stored: this host has no secret store.")
	}
	rec, err := s.storeAPIKey(ctx, owner, sessionID, key)
	if err != nil {
		return nil, err
	}
	s.runtimeFor(rec)
	return rec, nil
}

// Delete closes a session and removes its transcript. An audit row keeps the
// fact that it existed.
func (s *Service) Delete(ctx context.Context, owner actor.Actor, sessionID string) error {
	rec, err := s.loadFor(ctx, owner, sessionID)
	if err != nil {
		return err
	}
	rt := s.runtimeFor(rec)
	if err := s.stopRuntime(ctx, rt); err != nil {
		return err
	}
	rt.mu.Lock()
	if rt.closed || rt.running || rt.pending != nil {
		rt.mu.Unlock()
		return problem.New(problem.StateConflict, "The agent session changed while it was being stopped.")
	}
	// 原会话锁保护提交到 closed 的边界；事务失败不能丢失入口或关闭已有订阅。
	if err := s.deleteSession(ctx, owner, sessionID); err != nil {
		rt.mu.Unlock()
		return err
	}
	rt.closed = true
	rt.closeSubscribersLocked()
	rt.mu.Unlock()
	s.mu.Lock()
	if s.sessions[sessionID] == rt {
		delete(s.sessions, sessionID)
	}
	s.mu.Unlock()
	if s.cliAuth != nil {
		s.cliAuth.RemoveSessionState(sessionID)
	}
	return nil
}

// stopRuntime cancels a running turn or a pending approval and waits until the
// affected goroutines released the runtime.
func (s *Service) stopRuntime(ctx context.Context, rt *sessionRuntime) error {
	rt.mu.Lock()
	var waiting []chan struct{}
	if rt.turnDone != nil {
		waiting = append(waiting, rt.turnDone)
	}
	if rt.pending != nil && rt.pending.done != nil {
		waiting = append(waiting, rt.pending.done)
	}
	p := claimPendingLocked(rt)
	if rt.cancel != nil {
		rt.cancel(errUserCancel)
	}
	rt.mu.Unlock()
	s.withdrawPending(ctx, rt, p, "The session was deleted.")
	if len(waiting) == 0 {
		return nil
	}
	timeout := time.After(5 * time.Second)
	for _, ch := range waiting {
		select {
		case <-ch:
		case <-timeout:
			return problem.New(problem.StateConflict, "The session is still busy; cancel the turn and retry.")
		}
	}
	return nil
}

// Send appends a user message and starts the turn that answers it. The turn
// runs in the background; its events go to the session SSE.
func (s *Service) Send(ctx context.Context, owner actor.Actor, sessionID string, req SendRequest) (*SendResult, error) {
	content, err := validateContent(req.Content)
	if err != nil {
		return nil, err
	}
	clientID, err := validateClientMessageID(req.ClientMessageID)
	if err != nil {
		return nil, err
	}
	rec, err := s.loadFor(ctx, owner, sessionID)
	if err != nil {
		return nil, err
	}
	if err := s.enforceSecurityBoundary(ctx, owner, rec.Core, rec.PermissionMode); err != nil {
		return nil, err
	}
	if !isDirectSlashCommand(content) {
		if err := s.preflight(ctx, rec); err != nil {
			return nil, err
		}
	}
	rt := s.runtimeFor(rec)
	rt.mu.Lock()
	if s.closed.Load() {
		rt.mu.Unlock()
		return nil, problem.New(problem.Unavailable, "The host is shutting down.")
	}
	// --- 锁内重查当前归属和原消息：重试先回放，不重复占用回合额度 -----------------
	if rt.closed {
		rt.mu.Unlock()
		return nil, notFound()
	}
	if _, err := s.loadFor(ctx, owner, sessionID); err != nil {
		rt.mu.Unlock()
		return nil, err
	}
	if existing, err := s.messageByClientID(ctx, rec.ID, clientID); err != nil {
		rt.mu.Unlock()
		return nil, err
	} else if existing != nil {
		out := &SendResult{Session: rt.session, Message: *existing}
		rt.mu.Unlock()
		return out, nil
	}
	if rt.session.Status.Busy() {
		st := rt.session.Status
		rt.mu.Unlock()
		return nil, &problem.Error{
			Code:   problem.StateConflict,
			Detail: fmt.Sprintf("The session is %s; wait for the turn to finish or cancel it.", st),
		}
	}
	s.admitMu.Lock()
	defer s.admitMu.Unlock()
	if err := s.admitTurn(ctx, rt.owner()); err != nil {
		rt.mu.Unlock()
		return nil, err
	}
	seq := rt.nextSeqLocked()
	now := s.clock.Now().UTC().Truncate(time.Millisecond)
	msg := &Message{SessionID: rec.ID, Seq: seq, MessageID: s.ids.New(messagePrefix), Role: RoleUser, Content: content, CreatedAt: now}
	rev, err := s.insertMessageWithClientID(ctx, rt.owner(), msg, clientID, StatusRunning, s.cfg.RetainMessages)
	if err != nil {
		rt.mu.Unlock()
		return nil, err
	}
	rt.session.Status = StatusRunning
	rt.session.LastSeq = seq
	rt.session.Revision = rev
	turnCtx := s.beginTurnLocked(rt)
	out := &SendResult{Session: rt.session, Message: *msg}
	rt.mu.Unlock()
	go s.runTurn(turnCtx, rt)
	return out, nil
}

// admitTurn applies the owner's concurrency limit and turn rate. A resumed
// approval is not a new turn and does not come through here.
func (s *Service) admitTurn(ctx context.Context, owner actor.Actor) error {
	running, err := s.runningTurns(ctx, owner)
	if err != nil {
		return err
	}
	if running >= s.cfg.MaxRunningPerOwner {
		return problem.New(problem.StateConflict, "You already have %d agent turns running; wait for one to finish.", running)
	}
	if ok, wait := s.turnRate.Allow(string(owner.Kind)+":"+owner.ID, s.cfg.TurnsPerMinute); !ok {
		return &problem.Error{
			Code: problem.RateLimited, Detail: "Too many agent turns; try again shortly.",
			RetryAfterSec: int(wait/time.Second) + 1,
		}
	}
	return nil
}

// Cancel cancels the running turn, or closes a paused approval turn. Cancelling
// an idle session is a no-op.
func (s *Service) Cancel(ctx context.Context, owner actor.Actor, sessionID, reason string) (*Session, error) {
	rec, err := s.loadFor(ctx, owner, sessionID)
	if err != nil {
		return nil, err
	}
	rt := s.runtimeFor(rec)
	rt.mu.Lock()
	if !rt.running && rt.pending != nil {
		p := claimPendingLocked(rt)
		rt.mu.Unlock()
		text := "The user cancelled the session."
		if reason != "" {
			text = "The user cancelled the session: " + clipText(reason, 200)
		}
		s.withdrawPending(ctx, rt, p, text)
		out := rt.snapshot()
		return &out, nil
	}
	defer rt.mu.Unlock()
	switch {
	case rt.running:
		if rt.cancel != nil {
			rt.cancel(errUserCancel)
		}
	case rt.session.Status.Busy():
		// No turn and no waiter owns this status: recovery could not repair the
		// session, so cancelling is what releases it.
		if err := s.closeOpenCallsLocked(ctx, rt, ToolCancelled, "The user cancelled an interrupted turn."); err != nil {
			s.log.WarnContext(ctx, "agent session: close open calls", "session_id", sessionID, "error", err)
		}
		if err := s.publishLocked(ctx, rt, Event{Type: EventTurnCompleted, Status: string(StatusCancelled)}); err != nil {
			return nil, err
		}
	}
	out := rt.session
	return &out, nil
}

// WaitTurn blocks until the current turn (or the paused approval turn) ends. It
// is for tests and shutdown; it performs no authorization.
func (s *Service) WaitTurn(ctx context.Context, sessionID string) error {
	s.mu.Lock()
	rt := s.sessions[sessionID]
	s.mu.Unlock()
	if rt == nil {
		return nil
	}
	rt.mu.Lock()
	done := rt.turnDone
	rt.mu.Unlock()
	if done == nil {
		return nil
	}
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// beginTurnLocked marks the runtime running and returns the turn context.
func (s *Service) beginTurnLocked(rt *sessionRuntime) context.Context {
	ctx, cancel := context.WithCancelCause(s.base)
	rt.running = true
	rt.cancel = cancel
	rt.turnDone = make(chan struct{})
	rt.delta = map[string]*strings.Builder{}
	rt.reasoning.Reset()
	rt.currentMessage = ""
	rt.lastAssistant = ""
	rt.wg.Add(1)
	return ctx
}

// endTurn marks the turn as finished and wakes WaitTurn.
func endTurn(rt *sessionRuntime) {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	rt.running = false
	rt.cancel = nil
	if rt.session.Status != StatusWaitingApproval {
		rt.pending = nil
	}
	if rt.turnDone != nil {
		close(rt.turnDone)
		rt.turnDone = nil
	}
	rt.delta = nil
	rt.reasoning.Reset()
	rt.currentMessage = ""
}

// runTurn runs one core against the persisted history and maps its outcome to
// the session status.
func (s *Service) runTurn(turnCtx context.Context, rt *sessionRuntime) {
	defer rt.wg.Done()
	defer endTurn(rt)

	sess := rt.snapshot()
	if err := s.enforceSecurityBoundary(turnCtx, rt.owner(), sess.Core, sess.PermissionMode); err != nil {
		p := problem.From(err)
		s.emit(context.WithoutCancel(turnCtx), rt, Event{Type: EventError, Code: string(p.Code), Detail: p.Detail})
		s.emit(context.WithoutCancel(turnCtx), rt, Event{Type: EventTurnCompleted, Status: string(StatusFailed)})
		return
	}
	core, ok := s.cores[string(sess.Core)]
	if !ok {
		s.emit(turnCtx, rt, Event{Type: EventError, Code: string(problem.Unavailable),
			Detail: fmt.Sprintf("The %q core is not available.", sess.Core)})
		s.emit(turnCtx, rt, Event{Type: EventTurnCompleted, Status: string(StatusFailed)})
		return
	}
	hist, err := s.messages(context.WithoutCancel(turnCtx), sess.ID, 0, s.cfg.MaxHistory)
	if err != nil {
		s.emit(turnCtx, rt, Event{Type: EventError, Code: string(problem.Internal),
			Detail: "The session history could not be read."})
		s.emit(turnCtx, rt, Event{Type: EventTurnCompleted, Status: string(StatusFailed)})
		return
	}
	ctx, cancel := context.WithTimeout(operations.WithPermissionMode(turnCtx, sess.PermissionMode), s.cfg.TurnTimeout)
	defer cancel()
	tools := s.toolsFor(ctx, sess)
	if s.tryHandleSlashCommand(ctx, rt, sess, hist, tools) {
		s.emit(context.WithoutCancel(turnCtx), rt, Event{Type: EventTurnCompleted, Status: string(StatusIdle)})
		return
	}
	turn := Turn{
		SessionID:      sess.ID,
		Owner:          rt.owner(),
		PermissionMode: sess.PermissionMode,
		Messages:       hist,
		Tools:          tools,
		Config:         sess.Config,
		APIKeyRef:      sess.APIKeyRef,
		Runner:         s.runnerFor(rt),
		NextCallID:     func() string { return s.ids.New(callPrefix) },
		PersistExternalID: func(pctx context.Context, key, externalID string) error {
			return s.persistExternalResumeID(pctx, rt, key, externalID)
		},
	}
	err = core.Run(ctx, turn, func(e Event) error { return s.emit(ctx, rt, e) })

	// The final events are written even when the user just cancelled the turn:
	// the request context is done by then, but the transcript and the status
	// must still record the outcome.
	finishCtx := context.WithoutCancel(turnCtx)
	waiting := errors.Is(err, ErrWaitingApproval)
	if !waiting {
		s.flushPendingAssistant(finishCtx, rt)
	}
	switch {
	case waiting:
		// A withdrawal that won the race has already closed the turn.
		if rt.snapshot().Status.Busy() {
			s.emit(finishCtx, rt, Event{Type: EventTurnCompleted, Status: string(StatusWaitingApproval)})
		}
		if p := rt.pendingSnapshot(); p != nil {
			s.startWaiter(rt, p)
		}
	case errors.Is(context.Cause(ctx), errUserCancel):
		s.emit(finishCtx, rt, Event{Type: EventTurnCompleted, Status: string(StatusCancelled)})
	case err != nil:
		p := problem.From(err)
		if errors.Is(err, context.DeadlineExceeded) {
			p = problem.New(problem.Timeout, "The agent turn did not finish before its deadline.")
		}
		s.emit(finishCtx, rt, Event{Type: EventError, Code: string(p.Code), Detail: p.Detail})
		s.emit(finishCtx, rt, Event{Type: EventTurnCompleted, Status: string(StatusFailed)})
	default:
		s.emit(finishCtx, rt, Event{Type: EventTurnCompleted, Status: string(StatusIdle)})
	}
}

// runnerFor returns the runner handed to a core. It reads the session's current
// permission mode for every call, so a mode change applies to the calls that
// follow it even while a turn is running, and it always puts the mode on the
// context for operations.WithPermissionMode.
func (s *Service) runnerFor(rt *sessionRuntime) Runner {
	return RunnerFunc(func(ctx context.Context, call ToolCall) (ToolResult, error) {
		owner := rt.owner()
		mode := rt.snapshot().PermissionMode
		call.Actor = owner
		call.PermissionMode = mode
		ctx = operations.WithPermissionMode(ctx, mode)
		if s.runner == nil {
			return ToolResult{
				Status: ToolFailed,
				Error:  problem.New(problem.Unavailable, "No tool runner is configured on this host."),
			}, nil
		}
		return s.runner.RunTool(ctx, call)
	})
}

// toolsFor returns the catalog filtered by the permission mode: a read_only
// session only ever sees read actions (ADR-0010 §2.1).
func (s *Service) toolsFor(ctx context.Context, sess Session) []ToolSpec {
	if s.catalog == nil {
		return nil
	}
	all := s.catalog.Actions(ctx)
	if sess.PermissionMode != operations.PermissionReadOnly {
		return all
	}
	out := make([]ToolSpec, 0, len(all))
	for _, t := range all {
		if t.Effect == operations.EffectRead {
			out = append(out, t)
		}
	}
	return out
}

// toolFor resolves one action from the catalog.
func (s *Service) toolFor(ctx context.Context, actionID string) (ToolSpec, bool) {
	if s.catalog == nil {
		return ToolSpec{}, false
	}
	for _, t := range s.catalog.Actions(ctx) {
		if t.Action == actionID {
			return t, true
		}
	}
	return ToolSpec{}, false
}

// preflight reports a core that cannot run before a message is stored: a
// missing core, an unconfigured native core and a session whose provider is
// gone are UNAVAILABLE (design §4).
func (s *Service) preflight(ctx context.Context, rec *Session) error {
	core, ok := s.cores[string(rec.Core)]
	if !ok {
		return problem.New(problem.Unavailable,
			"The %q core is not available on this host yet; use the native core.", rec.Core)
	}
	_, isClassicNative := core.(*NativeCore)
	_, isEnhancedNative := core.(*EnhancedNativeCore)
	if isClassicNative || isEnhancedNative {
		cfg, err := decodeNativeConfig(rec.Config)
		if err != nil {
			return err
		}
		if cfg.BaseURL == "" {
			// The endpoint comes from a global AI provider (GAP-2); resolve it
			// now, so a missing provider is answered before the message is
			// stored instead of failing the turn.
			_, found, err := s.providerRecord(ctx, cfg.ProviderID)
			if err != nil {
				return problem.From(err)
			}
			if !found {
				if cfg.ProviderID != "" {
					return problem.New(problem.Unavailable,
						"The AI provider config.provider_id names no longer exists; pick another one or ask an administrator.")
				}
				return problem.New(problem.Unavailable,
					"The native core is not configured: set config.base_url and config.model on the session, "+
						"or configure a default AI provider.")
			}
			return nil
		}
		if err := cfg.configured(); err != nil {
			return err
		}
		return nil
	}
	if pf, ok := core.(PreflightableCore); ok {
		return pf.Preflight(ctx, rec.Config)
	}
	return nil
}

// startWaiter watches the approval a paused turn is waiting for.
func (s *Service) startWaiter(rt *sessionRuntime, p *pendingApproval) {
	if s.bridge == nil {
		return
	}
	ctx, cancel := context.WithCancel(s.base)
	rt.mu.Lock()
	if rt.pending != p || rt.closed || p.withdrawing {
		rt.mu.Unlock()
		cancel()
		return
	}
	p.cancel = cancel
	p.done = make(chan struct{})
	rt.wg.Add(1)
	rt.mu.Unlock()
	go func() {
		defer rt.wg.Done()
		defer close(p.done)
		dec, err := s.bridge.Wait(ctx, p.approvalID)
		s.finishApproval(rt, p, dec, err)
	}()
}

// finishApproval applies the human decision: approve stores the outcome and
// resumes the core, reject closes the turn.
func (s *Service) finishApproval(rt *sessionRuntime, p *pendingApproval, dec ApprovalDecision, waitErr error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	rt.mu.Lock()
	if rt.pending != p || rt.closed || p.withdrawing {
		rt.mu.Unlock()
		return
	}
	if waitErr != nil {
		if errors.Is(waitErr, context.Canceled) {
			// Cancel or Delete owns the state change.
			rt.mu.Unlock()
			return
		}
		rt.pending = nil
		rt.mu.Unlock()
		s.emit(ctx, rt, Event{Type: EventError, Code: string(problem.Internal),
			Detail: "The approval could not be resolved."})
		s.emit(ctx, rt, Event{Type: EventTurnCompleted, Status: string(StatusFailed)})
		return
	}
	decision := dec.Decision
	if decision != DecisionApprove && decision != DecisionReject {
		decision = DecisionReject
	}
	status := dec.Status
	if !status.Valid() {
		if decision == DecisionApprove {
			status = ToolSucceeded
		} else {
			status = ToolRejected
		}
	}
	s.publishLocked(ctx, rt, Event{
		Type: EventApprovalDecided, ApprovalID: p.approvalID, Decision: decision, Comment: dec.Comment,
	})
	s.publishLocked(ctx, rt, Event{
		Type: EventToolResult, CallID: p.callID, Action: p.action, Status: string(status),
		Result: dec.Result, Error: ErrorOf(dec.Error), OperationID: p.operationID, ApprovalID: p.approvalID,
	})
	rt.pending = nil
	if err := s.fillMissingToolResultsLocked(ctx, rt, p.messageID, skippedCallDetail); err != nil {
		s.log.WarnContext(ctx, "agent session: fill tool results", "error", err)
	}
	if decision != DecisionApprove {
		s.publishLocked(ctx, rt, Event{Type: EventTurnCompleted, Status: string(StatusIdle)})
		rt.mu.Unlock()
		return
	}
	if err := s.enforceSecurityBoundary(ctx, rt.owner(), rt.session.Core, rt.session.PermissionMode); err != nil {
		p := problem.From(err)
		s.publishLocked(ctx, rt, Event{Type: EventError, Code: string(p.Code), Detail: p.Detail})
		s.publishLocked(ctx, rt, Event{Type: EventTurnCompleted, Status: string(StatusFailed)})
		rt.mu.Unlock()
		return
	}
	if err := s.setRuntimeStatusLocked(ctx, rt, StatusRunning, 0); err != nil {
		rt.mu.Unlock()
		s.emit(ctx, rt, Event{Type: EventTurnCompleted, Status: string(StatusFailed)})
		return
	}
	turnCtx := s.beginTurnLocked(rt)
	rt.mu.Unlock()
	go s.runTurn(turnCtx, rt)
}

// withdrawTimeout bounds taking back one host operation.
const withdrawTimeout = 30 * time.Second

// claimPendingLocked stops the waiter and reserves the pause for one
// withdrawPending call; nil means there is nothing to claim. The caller holds
// rt.mu.
func claimPendingLocked(rt *sessionRuntime) *pendingApproval {
	p := rt.pending
	if p == nil || p.withdrawing {
		return nil
	}
	p.withdrawing = true
	if p.cancel != nil {
		p.cancel()
	}
	return p
}

// withdrawPending withdraws the host operation of a claimed pause, records the
// outcome and ends the turn. A nil p is a no-op. rt.mu must not be held: the
// host call can take seconds, and it needs its own deadline because the
// request that asked for it may already be gone.
func (s *Service) withdrawPending(ctx context.Context, rt *sessionRuntime, p *pendingApproval, reason string) {
	if p == nil {
		return
	}
	ctx = context.WithoutCancel(ctx)
	hostCtx, cancel := context.WithTimeout(ctx, withdrawTimeout)
	defer cancel()
	result := Event{
		Type: EventToolResult, CallID: p.callID, Action: p.action, Status: string(ToolCancelled),
		Error:       ErrorOf(problem.New(problem.StateConflict, "%s", reason)),
		OperationID: p.operationID, ApprovalID: p.approvalID,
	}
	s.withdrawHostOperation(hostCtx, rt, p, reason, &result)

	rt.mu.Lock()
	defer rt.mu.Unlock()
	if rt.pending != p || rt.closed {
		return
	}
	rt.pending = nil
	s.publishLocked(ctx, rt, result)
	if err := s.fillMissingToolResultsLocked(ctx, rt, p.messageID, skippedCallDetail); err != nil {
		s.log.WarnContext(ctx, "agent session: fill tool results", "error", err)
	}
	s.publishLocked(ctx, rt, Event{Type: EventTurnCompleted, Status: string(StatusCancelled)})
}

// withdrawHostOperation cancels the operation behind p and corrects result when
// that was too late: an operation that already ended is reported as it ended.
func (s *Service) withdrawHostOperation(ctx context.Context, rt *sessionRuntime, p *pendingApproval, reason string, result *Event) {
	canceller, ok := s.bridge.(ApprovalCanceller)
	if !ok || p.operationID == "" {
		return
	}
	err := canceller.CancelApproval(ctx, rt.owner(), rt.session.ID, p.operationID, reason)
	switch {
	case err == nil:
	case problem.HasCode(err, problem.StateConflict):
		dec, waitErr := s.bridge.Wait(ctx, p.approvalID)
		if waitErr != nil {
			s.log.WarnContext(ctx, "agent session: read the final approval outcome", "error", waitErr)
			return
		}
		if dec.Status.Valid() {
			result.Status = string(dec.Status)
		}
		result.Result, result.Error = dec.Result, ErrorOf(dec.Error)
	default:
		s.log.WarnContext(ctx, "agent session: withdraw the host operation", "operation_id", p.operationID, "error", err)
		result.Error = ErrorOf(problem.New(problem.StateConflict,
			"%s The host operation could not be withdrawn; check the approval list.", reason))
	}
}

// skippedCallDetail explains a call that a paused step never reached.
const skippedCallDetail = "The call was not executed because another call in the same step needed a decision."

// fillMissingToolResultsLocked appends the tool messages of an assistant step
// that were never produced (the turn paused or was cancelled before reaching
// them), so the next model request has a valid tool-call pairing.
func (s *Service) fillMissingToolResultsLocked(ctx context.Context, rt *sessionRuntime, messageID, detail string) error {
	if messageID == "" {
		return nil
	}
	msg, err := s.messageByID(ctx, messageID)
	if err != nil {
		return nil // the message was pruned or does not exist (yet)
	}
	if len(msg.ContentJSON) == 0 {
		return nil
	}
	var ac assistantContent
	if err := json.Unmarshal(msg.ContentJSON, &ac); err != nil || len(ac.ToolCalls) == 0 {
		return nil
	}
	have, err := s.toolMessageCallIDs(ctx, rt.session.ID)
	if err != nil {
		return err
	}
	now := s.clock.Now().UTC().Truncate(time.Millisecond)
	for _, tc := range ac.ToolCalls {
		if have[tc.CallID] {
			continue
		}
		p := problem.New(problem.StateConflict, "%s", detail)
		raw, err := json.Marshal(toolContent{
			CallID: tc.CallID, Action: tc.Action, Status: string(ToolCancelled), Error: ErrorOf(p),
		})
		if err != nil {
			return err
		}
		seq := rt.nextSeqLocked()
		out := &Message{
			SessionID: rt.session.ID, Seq: seq, MessageID: s.ids.New(messagePrefix), Role: RoleTool,
			Content: p.Detail, ContentJSON: raw, CreatedAt: now,
		}
		if _, err := s.insertMessage(ctx, rt.owner(), out, rt.session.Status, s.cfg.RetainMessages); err != nil {
			return err
		}
		rt.session.LastSeq = seq
		have[tc.CallID] = true
	}
	return nil
}

// emit is the Emit implementation handed to a core.
func (s *Service) emit(ctx context.Context, rt *sessionRuntime, e Event) error {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	return s.publishLocked(ctx, rt, e)
}

// flushPendingAssistant persists any streamed assistant deltas that were not
// yet closed by EventMessageCompleted (for instance on user cancel, mid-stream
// error, or a core that only emitted deltas), so partial output survives reload.
func (s *Service) flushPendingAssistant(ctx context.Context, rt *sessionRuntime) {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	if rt.closed || rt.currentMessage == "" {
		return
	}
	b := rt.delta[rt.currentMessage]
	if b == nil || b.Len() == 0 {
		rt.currentMessage = ""
		return
	}
	_ = s.publishLocked(ctx, rt, Event{
		Type:      EventMessageCompleted,
		MessageID: rt.currentMessage,
	})
}

// pendingSnapshot returns the pending approval, if any.
func (rt *sessionRuntime) pendingSnapshot() *pendingApproval {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	return rt.pending
}

// validateTitle normalizes a session title.
func validateTitle(raw string) (string, error) {
	title := strings.TrimSpace(raw)
	if title == "" {
		return "New session", nil
	}
	if utf8.RuneCountInString(title) > 120 {
		return "", problem.Validation(problem.Violation{
			Pointer: "/title", Code: "INVALID", Message: "title is at most 120 characters.",
		})
	}
	for _, r := range title {
		if unicode.IsControl(r) && r != '\t' {
			return "", problem.Validation(problem.Violation{
				Pointer: "/title", Code: "INVALID", Message: "title contains control characters.",
			})
		}
	}
	return title, nil
}

// validateContent normalizes a user message.
func validateContent(raw string) (string, error) {
	content := strings.TrimSpace(raw)
	if content == "" {
		return "", problem.Validation(problem.Violation{
			Pointer: "/content", Code: "REQUIRED", Message: "content is required.",
		})
	}
	if len(content) > maxUserBytes {
		return "", problem.Validation(problem.Violation{
			Pointer: "/content", Code: "INVALID", Message: "content is at most 32768 bytes.",
		})
	}
	return content, nil
}

// maxUserBytes bounds one user message.
const maxUserBytes = 32 << 10

// validateClientMessageID validates the optional idempotency key of a send.
func validateClientMessageID(raw string) (string, error) {
	if raw == "" {
		return "", nil
	}
	if len(raw) > 128 {
		return "", problem.Validation(problem.Violation{
			Pointer: "/client_message_id", Code: "INVALID", Message: "client_message_id is at most 128 characters.",
		})
	}
	for i := 0; i < len(raw); i++ {
		c := raw[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' ||
			c == '_' || c == '.' || c == ':' || c == '-') {
			return "", problem.Validation(problem.Violation{
				Pointer: "/client_message_id", Code: "INVALID",
				Message: "client_message_id contains characters that are not allowed.",
			})
		}
	}
	return raw, nil
}

// normalizeConfig validates the session config and fills the default.
func normalizeConfig(core CoreName, raw json.RawMessage) (json.RawMessage, error) {
	if len(raw) == 0 {
		return json.RawMessage("{}"), nil
	}
	if len(raw) > maxConfigBytes {
		return nil, problem.Validation(problem.Violation{
			Pointer: "/config", Code: "INVALID", Message: "config is at most 32768 bytes.",
		})
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil || obj == nil {
		return nil, problem.Validation(problem.Violation{
			Pointer: "/config", Code: "INVALID", Message: "config must be a JSON object.",
		})
	}
	// A config carries no credential, neither a plaintext value nor a secret
	// reference: a reference would let the session name any secret of the host
	// (AGT-02). The native core's key is stored with SetAPIKey.
	for _, key := range []string{"api_key", "apiKey", "api_key_secret", "token", "password", "secret"} {
		if _, ok := obj[key]; ok {
			return nil, problem.Validation(problem.Violation{
				Pointer: "/config/" + key, Code: "INVALID",
				Message: "A session config cannot carry a secret or a secret reference; " +
					"set the API key with PUT /api/v1/agent-sessions/{session_id}/api-key.",
			})
		}
	}
	if core == CoreNative {
		if _, err := decodeNativeConfig(raw); err != nil {
			return nil, err
		}
	} else {
		if _, err := ValidateExternalSessionConfig(raw); err != nil {
			return nil, err
		}
	}
	return raw, nil
}

// maxConfigBytes bounds a session config.
const maxConfigBytes = 32 << 10

// maxAPIKeyBytes bounds a stored API key. Provider keys are a few hundred
// bytes; the bound leaves room for long JWT-style tokens.
const maxAPIKeyBytes = 4096

// validateAPIKey normalizes an API key and returns it as bytes the caller
// wipes. Surrounding whitespace of a paste is dropped; the rest must be visible
// ASCII because the key becomes an HTTP header value, where a space, a control
// character or a line break would break the header or inject another one. A
// violation never echoes the value.
func validateAPIKey(raw string) ([]byte, error) {
	key := strings.TrimSpace(raw)
	if key == "" {
		return nil, problem.Validation(problem.Violation{
			Pointer: "/api_key", Code: "REQUIRED", Message: "api_key is required.",
		})
	}
	if len(key) > maxAPIKeyBytes {
		return nil, problem.Validation(problem.Violation{
			Pointer: "/api_key", Code: "INVALID", Message: "api_key is at most 4096 bytes.",
		})
	}
	for i := 0; i < len(key); i++ {
		if c := key[i]; c < 0x21 || c > 0x7e {
			return nil, problem.Validation(problem.Violation{
				Pointer: "/api_key", Code: "INVALID", Message: "api_key may only contain visible ASCII characters.",
			})
		}
	}
	return []byte(key), nil
}
