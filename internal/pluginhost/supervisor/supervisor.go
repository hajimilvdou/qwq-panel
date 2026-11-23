// SPDX-License-Identifier: AGPL-3.0-only

package supervisor

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"

	"github.com/qwq-panel/qwq/internal/platform/clock"
	"github.com/qwq-panel/qwq/internal/platform/problem"
)

const (
	// DefaultRunDir is the runtime root (ADR-0003 section 5): the plugin socket
	// lives at <run_dir>/plugin/<id>/plugin.sock and the host channel at
	// <run_dir>/host/<id>/host.sock.
	DefaultRunDir = "/run/qwq"

	// UnitTemplate is the systemd template unit of a plugin (ADR-0003 section 1).
	UnitTemplate = "qwq-plugin@%s.service"

	// DefaultMaxRestarts bounds the attach attempts of one Ensure call,
	// including the first one. Failures are separated by the backoff below.
	DefaultMaxRestarts = 3

	// DefaultBackoffMin and DefaultBackoffMax bound reconnect backoff
	// (ARCH 6.4: 1s, 2s, 4s, ... up to 5min).
	DefaultBackoffMin = time.Second
	DefaultBackoffMax = 5 * time.Minute

	// DefaultConnectTimeout bounds one attach attempt. P2-T1 measured 17-164 ms
	// for socket activation plus Reattach, so 10s is a generous cap.
	DefaultConnectTimeout = 10 * time.Second

	// MaxPluginMessageBytes caps one gRPC message the host sends to or receives
	// from a plugin; hostsvc bounds the calls in the other direction. The ABI
	// limits a payload to 4 MiB (platform.proto), and the extra 256 KiB is room
	// for the rest of a message that carries a full payload. The plugin side
	// (SDK-08, in sdk/, which cannot import this module) must use the same value.
	MaxPluginMessageBytes = 4<<20 + 256<<10

	// DefaultLogLinesPerSecond and DefaultLogBytesPerSecond are the per-plugin
	// log budget: plugin output is untrusted and must not flood the journal.
	DefaultLogLinesPerSecond = 200
	DefaultLogBytesPerSecond = 64 << 10

	// maxPluginIDLen mirrors the plugin_id schema in sdk/manifest.
	maxPluginIDLen = 128
)

// UnitState is the systemd view of one plugin unit, as reported by the unit
// manager. It is the identity input of the supervisor: MainPID and StartTime
// must come from systemd every time, never from a cache.
type UnitState struct {
	// MainPID is the unit's main process, 0 when the unit is not running.
	MainPID int
	// ControlGroup is the unit's cgroup, e.g.
	// /system.slice/system-qwq\x2dplugin.slice/qwq-plugin@alpha.service.
	ControlGroup string
	// ActiveState and SubState are systemd's state pair (active/running,
	// failed/failed, activating/start, ...).
	ActiveState string
	SubState    string
	// StartTime is the start timestamp of the unit's main process
	// (systemd's ExecMainStartTimestamp). Together with the unit name and
	// MainPID it identifies the process generation; an empty value is
	// tolerated but weakens PID-reuse detection.
	StartTime time.Time
}

// UnitManager starts, stops and inspects plugin units. internal/sandbox adapts
// systemd to it; the supervisor only ever passes plugin ids, never unit
// contents, and cannot be used to run arbitrary commands.
type UnitManager interface {
	// Start starts the plugin unit and returns after systemd accepted it. The
	// following Show must report the unit's MainPID.
	Start(ctx context.Context, pluginID string) error
	// Stop stops the plugin unit; systemd cleans the whole cgroup.
	Stop(ctx context.Context, pluginID string) error
	// Kill sends SIGKILL to the unit's main process (systemctl kill); the unit's
	// KillMode=control-group cleans the rest of the cgroup.
	Kill(ctx context.Context, pluginID string) error
	// Show reads the unit state from systemd. It must not cache: MainPID changes
	// whenever the unit restarts out of band.
	Show(ctx context.Context, pluginID string) (UnitState, error)
}

// HostServer serves the per-plugin host channel (ADR-0003 section 3): the plugin
// connects back to the host to report events, state and health. internal/hostsvc
// adapts it. Serve must return a stop function that tears down every host-side
// registration of that plugin instance and is safe to call once.
//
// The supervisor calls Serve after the plugin connection is ready and calls stop
// when the instance is stopped, killed, cleaned up or closed. ctx is canceled at
// the same time, so an implementation may use it instead of watching stop.
type HostServer interface {
	Serve(ctx context.Context, pluginID string) (stop func(), err error)
}

// Options configure New. Units, Host and PluginDir are required.
type Options struct {
	Units UnitManager
	Host  HostServer
	// PluginDir returns the installed version directory of a plugin. It is a
	// read-only lookup: the supervisor never writes below it. An error makes the
	// attach attempt fail without starting the unit.
	PluginDir func(pluginID string) (versionDir string, err error)
	// Clock defaults to clock.System. Tests pass clock.Fake to drive backoff.
	Clock clock.Clock
	// Logger defaults to slog.Default.
	Logger *slog.Logger
	// NodeID is logged with lifecycle records; "local" when empty.
	NodeID string
	// MaxRestarts is the attach attempt budget of one Ensure call (default 3).
	MaxRestarts int
	// BackoffMin and BackoffMax bound the exponential backoff between attempts
	// (defaults 1s and 5min).
	BackoffMin, BackoffMax time.Duration
	// LogLinesPerSecond is the per-plugin log line budget (default 200).
	LogLinesPerSecond int

	// Optional additions, documented in REPORT.md.
	//
	// LogBytesPerSecond is the per-plugin log byte budget (default 64 KiB/s).
	LogBytesPerSecond int
	// RunDir is the runtime root holding the plugin and host sockets (default
	// DefaultRunDir). The host should pass config.Config.RunDir.
	RunDir string
	// ConnectTimeout bounds one attach attempt, including the gRPC handshake
	// (default 10s).
	ConnectTimeout time.Duration
	// Limits, when set, supplies the resource expectations of a plugin
	// (ARCH 6.3, ADR-0003 section 7). The supervisor validates them and exposes
	// them in Status; internal/sandbox applies them as unit drop-ins.
	Limits func(pluginID string) (Limits, error)
	// OnNewGeneration, when set, runs before the supervisor attaches to a
	// process generation other than the one it last attached to (systemd
	// restarted a crashed plugin). The new process has no instance yet; the
	// host restores it here (Initialize/Start/Activate). An error fails the
	// attach attempt.
	OnNewGeneration func(ctx context.Context, pluginID string) error
}

// Supervisor manages plugin instances. It is safe for concurrent use; each
// plugin has its own mutex and no lock is held across a network call.
type Supervisor struct {
	opts   Options
	clock  clock.Clock
	logger *slog.Logger
	// jitter returns a value in [0,1); tests replace it for deterministic backoff.
	jitter func() float64

	mu        sync.Mutex
	closed    bool
	started   bool
	rootCtx   context.Context
	cancel    context.CancelFunc
	locks     map[string]*sync.Mutex
	instances map[string]*Instance
	degraded  map[string]*degradedState
	cleanups  map[string][]func()
	logs      []*logAttachment
	limiters  map[string]*logLimiter
	// lastGen is the generation of each plugin's last attached instance.
	lastGen map[string]string
}

// degradedState records a plugin whose last Ensure exhausted its attempts.
type degradedState struct {
	err      error
	attempts int
	since    time.Time
	retryAt  time.Time
}

// New validates opts and returns a supervisor. It does not start anything:
// Start only fixes the lifetime context, Ensure attaches plugins.
func New(opts Options) (*Supervisor, error) {
	if opts.Units == nil {
		return nil, problem.New(problem.ValidationFailed, "supervisor: a unit manager is required")
	}
	if opts.Host == nil {
		return nil, problem.New(problem.ValidationFailed, "supervisor: a host server is required")
	}
	if opts.PluginDir == nil {
		return nil, problem.New(problem.ValidationFailed, "supervisor: a plugin directory resolver is required")
	}
	opts.RunDir = filepath.Clean(opts.RunDir)
	if opts.RunDir == "." || opts.RunDir == "" {
		opts.RunDir = DefaultRunDir
	}
	if !filepath.IsAbs(opts.RunDir) || filepath.Dir(opts.RunDir) == opts.RunDir {
		return nil, problem.New(problem.ValidationFailed,
			"supervisor: run dir %q must be a clean absolute path other than /", opts.RunDir)
	}
	if opts.Clock == nil {
		opts.Clock = clock.System{}
	}
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	if opts.NodeID == "" {
		opts.NodeID = "local"
	}
	if opts.MaxRestarts <= 0 {
		opts.MaxRestarts = DefaultMaxRestarts
	}
	if opts.BackoffMin <= 0 {
		opts.BackoffMin = DefaultBackoffMin
	}
	if opts.BackoffMax <= 0 {
		opts.BackoffMax = DefaultBackoffMax
	}
	if opts.BackoffMax < opts.BackoffMin {
		opts.BackoffMax = opts.BackoffMin
	}
	if opts.ConnectTimeout <= 0 {
		opts.ConnectTimeout = DefaultConnectTimeout
	}
	if opts.LogLinesPerSecond <= 0 {
		opts.LogLinesPerSecond = DefaultLogLinesPerSecond
	}
	if opts.LogBytesPerSecond <= 0 {
		opts.LogBytesPerSecond = DefaultLogBytesPerSecond
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &Supervisor{
		opts:      opts,
		clock:     opts.Clock,
		logger:    opts.Logger,
		jitter:    rand.Float64,
		rootCtx:   ctx,
		cancel:    cancel,
		locks:     make(map[string]*sync.Mutex),
		instances: make(map[string]*Instance),
		degraded:  make(map[string]*degradedState),
		cleanups:  make(map[string][]func()),
		limiters:  make(map[string]*logLimiter),
		lastGen:   make(map[string]string),
	}, nil
}

// Start fixes the lifetime context of the supervisor. ctx should live as long as
// the process; cancelling it stops every host channel. Start is idempotent and
// optional: Ensure works on the background lifetime context when it is not
// called.
func (s *Supervisor) Start(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return problem.New(problem.Unavailable, "the plugin supervisor is closed")
	}
	if s.started {
		s.mu.Unlock()
		return nil
	}
	if len(s.instances) > 0 {
		// Ensure ran first; keep the lifetime context the instances were built on.
		s.started = true
		s.mu.Unlock()
		return nil
	}
	root, cancel := context.WithCancel(ctx)
	s.cancel()
	s.rootCtx, s.cancel = root, cancel
	s.started = true
	s.mu.Unlock()
	s.logger.InfoContext(ctx, "plugin supervisor started", "node_id", s.opts.NodeID, "run_dir", s.opts.RunDir)
	return nil
}

// Ensure returns a live instance for pluginID, starting the unit when it is not
// running and attaching to the plugin socket. Every call re-reads the unit
// state: a changed generation (out-of-band restart) invalidates the previous
// instance before the new one is attached.
//
// Failures are retried with exponential backoff and jitter up to MaxRestarts
// times. Exhausting the budget marks the plugin degraded and returns an error;
// a later Ensure before the cooldown reports the degraded state without
// touching the unit, so a crash loop cannot become a poll loop.
func (s *Supervisor) Ensure(ctx context.Context, pluginID string) (*Instance, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := validatePluginID(pluginID); err != nil {
		return nil, err
	}
	if err := s.open(); err != nil {
		return nil, err
	}

	lock := s.lockFor(pluginID)
	lock.Lock()
	defer lock.Unlock()

	if err := s.open(); err != nil {
		return nil, err
	}
	if inst := s.current(pluginID); inst != nil {
		state, err := s.opts.Units.Show(ctx, pluginID)
		if err != nil {
			return nil, unitError(pluginID, "shown", err)
		}
		if state.MainPID > 0 &&
			generation(s.unitName(pluginID), state.MainPID, state.StartTime) == inst.Generation() &&
			!inst.brokenConnection() {
			return inst, nil
		}
		reason := "the unit reported a new generation"
		if inst.brokenConnection() {
			reason = "the plugin connection broke"
		}
		s.drop(inst, reason)
	}
	if retryAt, lastErr := s.degradedAt(pluginID); !retryAt.IsZero() {
		if s.clock.Now().Before(retryAt) {
			s.logger.DebugContext(ctx, "plugin is degraded; skipping until its cooldown ends",
				"plugin_id", pluginID, "retry_at", retryAt)
			return nil, &problem.Error{
				Code:   problem.PluginUnavailable,
				Detail: fmt.Sprintf("plugin %q is degraded; retrying after %s", pluginID, retryAt.UTC().Format(time.RFC3339)),
				Cause:  lastErr,
			}
		}
		s.clearDegraded(pluginID)
	}

	var lastErr error
	for attempt := 1; attempt <= s.opts.MaxRestarts; attempt++ {
		inst, err := s.connect(ctx, pluginID)
		if err == nil {
			s.clearDegraded(pluginID)
			return inst, nil
		}
		lastErr = err
		if attempt == s.opts.MaxRestarts {
			break
		}
		delay := s.backoff(attempt)
		s.logger.WarnContext(ctx, "plugin attach failed; retrying",
			"plugin_id", pluginID, "attempt", attempt, "backoff", delay, "error", err)
		if werr := s.wait(ctx, delay); werr != nil {
			return nil, werr
		}
		if err := s.open(); err != nil {
			return nil, err
		}
	}
	retryAt := s.clock.Now().Add(s.opts.BackoffMax)
	s.markDegraded(pluginID, lastErr, s.opts.MaxRestarts, retryAt)
	s.logger.ErrorContext(ctx, "plugin is degraded",
		"plugin_id", pluginID, "attempts", s.opts.MaxRestarts, "retry_at", retryAt, "error", lastErr)
	if lastErr == nil {
		lastErr = problem.New(problem.PluginUnavailable, "plugin %q could not be attached", pluginID)
	}
	return nil, lastErr
}

// connect performs one attach attempt: resolve the package directory, make sure
// the unit runs, derive the generation, attach to the plugin socket and start the
// host channel. Any failure cleans up the partial connection.
func (s *Supervisor) connect(ctx context.Context, pluginID string) (*Instance, error) {
	versionDir, err := s.opts.PluginDir(pluginID)
	if err != nil {
		return nil, &problem.Error{
			Code:   problem.PluginUnavailable,
			Detail: fmt.Sprintf("the package directory of plugin %q is unavailable", pluginID),
			Cause:  err,
		}
	}
	if versionDir == "" {
		return nil, problem.New(problem.PluginUnavailable, "the package directory of plugin %q is unknown", pluginID)
	}

	// Validate the resource expectations before any side effect, so an invalid
	// manifest cannot start a unit.
	var limits Limits
	if s.opts.Limits != nil {
		limits, err = s.opts.Limits(pluginID)
		if err != nil {
			return nil, &problem.Error{
				Code:   problem.PluginUnavailable,
				Detail: fmt.Sprintf("the resource limits of plugin %q are unavailable", pluginID),
				Cause:  err,
			}
		}
		if err := limits.Validate(); err != nil {
			return nil, &problem.Error{
				Code:   problem.ValidationFailed,
				Detail: fmt.Sprintf("the resource limits of plugin %q are invalid", pluginID),
				Cause:  err,
			}
		}
	}

	state, err := s.opts.Units.Show(ctx, pluginID)
	if err != nil {
		return nil, unitError(pluginID, "shown", err)
	}
	started := false
	if state.MainPID == 0 {
		if err := s.opts.Units.Start(ctx, pluginID); err != nil {
			return nil, unitError(pluginID, "started", err)
		}
		started = true
		if state, err = s.opts.Units.Show(ctx, pluginID); err != nil {
			return nil, unitError(pluginID, "shown", err)
		}
	}
	if state.MainPID == 0 {
		return nil, problem.New(problem.PluginUnavailable, "the unit of plugin %q has no main process after start", pluginID)
	}

	gen := generation(s.unitName(pluginID), state.MainPID, state.StartTime)
	if err := s.restoreGeneration(ctx, pluginID, gen); err != nil {
		return nil, err
	}
	grpcClient, err := s.reattach(ctx, pluginID)
	if err != nil {
		return nil, err
	}

	inst := newInstance(s, pluginID, gen, state, versionDir, limits)
	hostCtx, hostCancel := context.WithCancel(s.lifetimeContext())
	stop, err := s.opts.Host.Serve(hostCtx, pluginID)
	if err != nil {
		hostCancel()
		closePluginClient(grpcClient)
		return nil, &problem.Error{
			Code:   problem.PluginUnavailable,
			Detail: fmt.Sprintf("the host channel of plugin %q could not be served", pluginID),
			Cause:  err,
		}
	}
	inst.attach(grpcClient, stop, hostCancel)

	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		inst.shutdown("the supervisor was closed while attaching")
		return nil, problem.New(problem.Unavailable, "the plugin supervisor is closed")
	}
	s.instances[pluginID] = inst
	s.lastGen[pluginID] = gen
	s.mu.Unlock()

	s.logger.InfoContext(ctx, "plugin attached",
		"plugin_id", pluginID, "unit", inst.Unit(), "main_pid", state.MainPID,
		"generation", gen, "owner", inst.Owner(), "version_dir", versionDir,
		"unit_started", started, "unit_state", state.ActiveState+"/"+state.SubState,
		"node_id", s.opts.NodeID)
	return inst, nil
}

// restoreGeneration runs OnNewGeneration when gen replaces the generation the
// supervisor last attached to. The first attach of a process lifetime is the
// caller's to restore (it knows whether the plugin should run at all).
func (s *Supervisor) restoreGeneration(ctx context.Context, pluginID, gen string) error {
	if s.opts.OnNewGeneration == nil {
		return nil
	}
	s.mu.Lock()
	prev := s.lastGen[pluginID]
	s.mu.Unlock()
	if prev == "" || prev == gen {
		return nil
	}
	if err := s.opts.OnNewGeneration(ctx, pluginID); err != nil {
		return &problem.Error{
			Code:   problem.PluginUnavailable,
			Detail: fmt.Sprintf("the new process of plugin %q could not be restored", pluginID),
			Cause:  err,
		}
	}
	return nil
}

// reattach 复用原生连接；当前 PID/代次已由上层从 systemd 重新核验。
func (s *Supervisor) reattach(ctx context.Context, pluginID string) (*grpc.ClientConn, error) {
	socket := SocketPath(s.opts.RunDir, pluginID)
	connection, err := OpenPluginConnection(ctx, socket, s.opts.ConnectTimeout)
	if err != nil {
		return nil, &problem.Error{
			Code:   problem.PluginUnavailable,
			Detail: fmt.Sprintf("cannot attach to the socket of plugin %q", pluginID),
			Cause:  err,
		}
	}
	return connection, nil
}

// Stop stops the plugin unit through the unit manager and tears the instance
// down. It does not signal the process itself; systemd owns the cgroup.
func (s *Supervisor) Stop(ctx context.Context, pluginID string) error {
	return s.lifecycle(ctx, pluginID, "stopped", func(ctx context.Context) error {
		return s.opts.Units.Stop(ctx, pluginID)
	})
}

// Kill force-kills the plugin unit through the unit manager (systemctl kill;
// KillMode=control-group cleans the cgroup).
func (s *Supervisor) Kill(ctx context.Context, pluginID string) error {
	return s.lifecycle(ctx, pluginID, "killed", func(ctx context.Context) error {
		return s.opts.Units.Kill(ctx, pluginID)
	})
}

// lifecycle performs a unit operation and drops the local instance whatever the
// unit manager reports: the process may still be gone even if the command
// failed, and keeping a dead instance would hide it.
func (s *Supervisor) lifecycle(ctx context.Context, pluginID, verb string, unitOp func(context.Context) error) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := validatePluginID(pluginID); err != nil {
		return err
	}
	if err := s.open(); err != nil {
		return err
	}
	lock := s.lockFor(pluginID)
	lock.Lock()
	defer lock.Unlock()

	inst := s.current(pluginID)
	uerr := unitOp(ctx)
	if uerr != nil {
		uerr = unitError(pluginID, verb, uerr)
	}
	if inst != nil {
		s.drop(inst, "the plugin was "+verb)
	}
	s.clearDegraded(pluginID)
	return uerr
}

// Cleanup tears down every host-side registration of owner. owner is either
// Owner(pluginID, generation) or a bare plugin id for the current instance. It
// is idempotent, does not stop the unit and is safe to call from any goroutine.
func (s *Supervisor) Cleanup(owner string) {
	pluginID, gen := splitOwner(owner)
	if pluginID == "" {
		return
	}
	lock := s.lockFor(pluginID)
	s.mu.Lock()
	inst := s.instances[pluginID]
	s.mu.Unlock()
	if inst != nil && (gen == "" || inst.Generation() == gen) {
		lock.Lock()
		if cur := s.current(pluginID); cur == inst {
			s.drop(inst, "the owner was cleaned up")
		}
		lock.Unlock()
	}
	s.runCleanups(owner)
}

// RegisterCleanup registers fn with owner; Cleanup runs it once. The host
// service may use it for registrations that outlive a single Serve call; a
// failing registration must never leak, so a closed supervisor runs fn at once.
func (s *Supervisor) RegisterCleanup(owner string, fn func()) {
	if fn == nil || owner == "" {
		return
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		fn()
		return
	}
	s.cleanups[owner] = append(s.cleanups[owner], fn)
	s.mu.Unlock()
}

// Instances returns a snapshot of the live and degraded instances, sorted by
// plugin id. The unit fields are the values observed at the last attach; query
// the unit manager for live systemd state.
func (s *Supervisor) Instances() []Status {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Status, 0, len(s.instances)+len(s.degraded))
	for _, inst := range s.instances {
		out = append(out, inst.status())
	}
	for id, d := range s.degraded {
		if _, ok := s.instances[id]; ok {
			continue
		}
		st := Status{
			PluginID: id,
			Unit:     UnitName(id),
			State:    StateDegraded,
			Attempts: d.attempts,
			Since:    d.since,
			RetryAt:  d.retryAt,
		}
		if d.err != nil {
			st.LastError = d.err.Error()
		}
		out = append(out, st)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].PluginID < out[j].PluginID })
	return out
}

// Client returns the RPC wrapper of the current instance. It fails with
// PLUGIN_UNAVAILABLE when the plugin was never attached or its instance is no
// longer current; call Ensure first.
func (s *Supervisor) Client(pluginID string) (*Client, error) {
	if err := validatePluginID(pluginID); err != nil {
		return nil, err
	}
	inst := s.current(pluginID)
	if inst == nil {
		return nil, problem.New(problem.PluginUnavailable, "plugin %q has no live instance; call Ensure first", pluginID)
	}
	client := inst.Client()
	if client == nil {
		return nil, problem.New(problem.PluginUnavailable, "plugin %q has no live instance; call Ensure first", pluginID)
	}
	return client, nil
}

// Close shuts down every client and host channel and cancels the lifetime
// context. It never kills a plugin process: systemd owns the units, and the next
// agent process reattaches.
func (s *Supervisor) Close() {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	instances := make([]*Instance, 0, len(s.instances))
	for _, inst := range s.instances {
		instances = append(instances, inst)
	}
	attachments := s.logs
	s.logs = nil
	leftovers := s.cleanups
	s.cleanups = nil
	// A closed supervisor reports no instances, degraded or not.
	s.degraded = make(map[string]*degradedState)
	cancel := s.cancel
	s.mu.Unlock()

	cancel()
	for _, a := range attachments {
		a.stopWithin(logStopTimeout)
	}
	for _, inst := range instances {
		lock := s.lockFor(inst.PluginID())
		lock.Lock()
		if cur := s.current(inst.PluginID()); cur == inst {
			s.drop(inst, "the supervisor was closed")
		}
		lock.Unlock()
	}
	for owner, fns := range leftovers {
		for _, fn := range fns {
			fn()
		}
		s.logger.Debug("ran leftover host registrations", "owner", owner, "count", len(fns))
	}
	s.logger.Info("plugin supervisor closed", "node_id", s.opts.NodeID)
}

// drop unregisters inst, shuts its connection and host channel down and runs the
// cleanup callbacks of its owner. Callers hold the plugin lock.
func (s *Supervisor) drop(inst *Instance, reason string) {
	if inst == nil {
		return
	}
	s.mu.Lock()
	if s.instances[inst.PluginID()] == inst {
		delete(s.instances, inst.PluginID())
	}
	s.mu.Unlock()
	inst.shutdown(reason)
	s.runCleanups(inst.Owner())
}

// runCleanups pops and runs the callbacks registered for owner.
func (s *Supervisor) runCleanups(owner string) {
	s.mu.Lock()
	fns := s.cleanups[owner]
	delete(s.cleanups, owner)
	s.mu.Unlock()
	for _, fn := range fns {
		fn()
	}
}

// backoff returns the delay before the next attempt: exponential from
// BackoffMin, capped at BackoffMax, with jitter in [d/2, d) so a fleet of
// plugins does not reconnect in lockstep. attempt is 1 for the first retry.
func (s *Supervisor) backoff(attempt int) time.Duration {
	d := s.opts.BackoffMin
	for i := 1; i < attempt; i++ {
		if d >= s.opts.BackoffMax/2 {
			d = s.opts.BackoffMax
			break
		}
		d *= 2
	}
	if d > s.opts.BackoffMax {
		d = s.opts.BackoffMax
	}
	if d <= 0 {
		return 0
	}
	half := d / 2
	return half + time.Duration(s.jitter()*float64(half))
}

// wait sleeps for d or until ctx ends, whichever is first.
func (s *Supervisor) wait(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return nil
	}
	select {
	case <-ctx.Done():
		return contextError(ctx.Err(), "waiting to retry")
	case <-s.clock.After(d):
		return nil
	}
}

func (s *Supervisor) open() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return problem.New(problem.Unavailable, "the plugin supervisor is closed")
	}
	return nil
}

func (s *Supervisor) current(pluginID string) *Instance {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.instances[pluginID]
}

func (s *Supervisor) lockFor(pluginID string) *sync.Mutex {
	s.mu.Lock()
	defer s.mu.Unlock()
	lock := s.locks[pluginID]
	if lock == nil {
		lock = &sync.Mutex{}
		s.locks[pluginID] = lock
	}
	return lock
}

func (s *Supervisor) degradedAt(pluginID string) (time.Time, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if d := s.degraded[pluginID]; d != nil {
		return d.retryAt, d.err
	}
	return time.Time{}, nil
}

func (s *Supervisor) markDegraded(pluginID string, err error, attempts int, retryAt time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	d := s.degraded[pluginID]
	if d == nil {
		d = &degradedState{since: s.clock.Now()}
		s.degraded[pluginID] = d
	}
	d.err, d.attempts, d.retryAt = err, attempts, retryAt
}

// ResetDegraded clears any residual degraded cooldown state for pluginID after
// an explicit restore has confirmed the unit is healthy again.
func (s *Supervisor) ResetDegraded(pluginID string) {
	s.clearDegraded(pluginID)
}

func (s *Supervisor) clearDegraded(pluginID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.degraded, pluginID)
}

// lifetimeContext returns the context host channels are derived from.
func (s *Supervisor) lifetimeContext() context.Context {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.rootCtx
}

func (s *Supervisor) unitName(pluginID string) string { return UnitName(pluginID) }

// UnitName returns the systemd unit of a plugin (ADR-0003 section 1).
func UnitName(pluginID string) string { return fmt.Sprintf(UnitTemplate, pluginID) }

// SocketPath returns the plugin socket of a plugin below runDir. systemd owns
// the listener (SocketUser=<agent>, SocketMode=0600); the agent only connects.
func SocketPath(runDir, pluginID string) string {
	return filepath.Join(runDir, "plugin", pluginID, "plugin.sock")
}

// HostSocketPath returns the host channel socket of a plugin below runDir. The
// agent listens there; the plugin only sees it through BindPaths
// (ADR-0003 section 3).
func HostSocketPath(runDir, pluginID string) string {
	return filepath.Join(runDir, "host", pluginID, "host.sock")
}

// Owner is the identity host-side registrations belong to (ARCH 5.7):
// plugin_instance_id + process_generation.
func Owner(pluginID, generation string) string {
	if generation == "" {
		return pluginID
	}
	return pluginID + "@" + generation
}

func splitOwner(owner string) (pluginID, generation string) {
	if i := strings.LastIndexByte(owner, '@'); i >= 0 {
		return owner[:i], owner[i+1:]
	}
	return owner, ""
}

var pluginIDPattern = regexp.MustCompile(`^[a-z][a-z0-9]*([.-][a-z0-9]+)*$`)

// validatePluginID enforces the manifest id grammar (sdk/manifest schema) before
// the id reaches a unit name, a socket path or a systemd command.
func validatePluginID(pluginID string) error {
	if len(pluginID) == 0 || len(pluginID) > maxPluginIDLen || !pluginIDPattern.MatchString(pluginID) {
		return problem.New(problem.ValidationFailed, "plugin id %q is not a valid plugin id", pluginID)
	}
	return nil
}

// unitError maps a unit manager failure to a host error. The cause is logged,
// never sent to clients.
func unitError(pluginID, verb string, err error) *problem.Error {
	return &problem.Error{
		Code:   problem.PluginUnavailable,
		Detail: fmt.Sprintf("the unit of plugin %q could not be %s", pluginID, verb),
		Cause:  err,
	}
}

// waitReady waits until the gRPC connection is ready, which proves that the
// plugin socket accepted a connection and completed the HTTP/2 handshake. It
// does not call a plugin RPC, so a partially implemented plugin still attaches.
func waitReady(ctx context.Context, conn *grpc.ClientConn, timeout time.Duration) error {
	if conn == nil {
		return errors.New("no gRPC connection")
	}
	wctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	conn.Connect()
	for {
		state := conn.GetState()
		switch state {
		case connectivity.Ready:
			return nil
		case connectivity.Shutdown:
			return errors.New("the plugin connection was shut down before it became ready")
		}
		if !conn.WaitForStateChange(wctx, state) {
			if err := wctx.Err(); err != nil {
				return fmt.Errorf("the plugin socket did not become ready: %w", err)
			}
			return errors.New("the plugin socket did not become ready")
		}
	}
}

// closePluginClient 只关闭本机连接；不得把清理转为进程 Kill。
func closePluginClient(client *grpc.ClientConn) {
	if client == nil {
		return
	}
	_ = client.Close()
}

// contextError maps a cancelled context to a host error.
func contextError(err error, doing string) *problem.Error {
	if errors.Is(err, context.DeadlineExceeded) {
		return &problem.Error{Code: problem.Timeout, Detail: "The host gave up " + doing + ".", Cause: err}
	}
	return &problem.Error{Code: problem.Unavailable, Detail: "The host stopped " + doing + ".", Cause: err}
}
