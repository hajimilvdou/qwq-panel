// SPDX-License-Identifier: Apache-2.0

package pluginsdk

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// InstanceBase is the per-instance state the SDK manages. Every plugin
// instance must embed a pointer to it:
//
//	type myInstance struct{ *pluginsdk.InstanceBase }
//
// It provides the operation registry, the current config snapshot, the Host
// client, the instance logger and the tracked background-goroutine helper.
type InstanceBase struct {
	info InstanceInfo
	core *instance
}

// NewInstanceBase wraps the InstanceInfo passed to [Plugin.NewInstance]. It
// panics when info was not supplied by the SDK, which means the plugin was not
// created through NewInstance.
func NewInstanceBase(info InstanceInfo) *InstanceBase {
	if info.core == nil {
		panic("pluginsdk: NewInstanceBase called with an InstanceInfo that did not come from NewInstance")
	}
	return &InstanceBase{info: info, core: info.core}
}

// base implements the sealed [Instance] interface.
func (b *InstanceBase) base() *InstanceBase { return b }

// ID returns RequestContext.instance_id of this instance.
func (b *InstanceBase) ID() string { return b.info.ID }

// DataDir returns the instance's private writable directory.
func (b *InstanceBase) DataDir() string { return b.info.DataDir }

// Info returns the Initialize snapshot. Config is the snapshot from
// Initialize; use [InstanceBase.Config] for the currently applied one.
func (b *InstanceBase) Info() InstanceInfo { return b.info }

// Config returns a copy of the currently applied config JSON.
func (b *InstanceBase) Config() []byte {
	cfg, _ := b.core.configSnapshot()
	return cfg
}

// ConfigRevision returns the revision of the currently applied config.
func (b *InstanceBase) ConfigRevision() string {
	_, rev := b.core.configSnapshot()
	return rev
}

// State returns the instance's current lifecycle state.
func (b *InstanceBase) State() LifecycleState { return b.core.stateNow() }

// Host returns the Host Service client for this instance. Host calls made
// without a call context (e.g. from a goroutine outside a handler) carry an
// empty operation_id.
func (b *InstanceBase) Host() *Host { return b.core.host }

// Logger returns the structured logger of this instance. It writes JSON to
// stderr with plugin and instance fields.
func (b *InstanceBase) Logger() *slog.Logger { return b.core.log }

// Go starts fn as tracked background work. It is the supported way to run
// long-lived work: the context passed to fn is canceled by Deactivate, Stop and
// ReleaseInstance, and those calls wait for fn to return.
//
// Go only works while the instance is ACTIVE: starting work from Initialize or
// Start returns an error, so two generations never run background work at the
// same time (ADR-0002).
//
// A panic in fn is recovered and marks the instance FAILED (see
// [Options.CrashOnPanic]). Goroutines the plugin starts itself with the go
// statement cannot be recovered by the SDK and take the whole process down.
func (b *InstanceBase) Go(fn func(ctx context.Context)) error {
	if fn == nil {
		return fmt.Errorf("pluginsdk: Go called with a nil function")
	}
	return b.core.startTracked(fn)
}

// HandleInvoke registers a raw invoke handler. Most plugins use the typed
// [HandleInvoke] helper. Registration is only allowed inside
// [Plugin.NewInstance]; any other call panics.
func (b *InstanceBase) HandleInvoke(name string, h InvokeHandler) {
	if h == nil {
		panic("pluginsdk: nil invoke handler for " + name)
	}
	b.core.registerInvoke(name, h)
}

// HandleJob registers a raw job handler.
func (b *InstanceBase) HandleJob(name string, h JobHandler) {
	if h == nil {
		panic("pluginsdk: nil job handler for " + name)
	}
	b.core.registerJob(name, h)
}

// HandlePlan registers a raw plan handler.
func (b *InstanceBase) HandlePlan(name string, h PlanHandler) {
	if h == nil {
		panic("pluginsdk: nil plan handler for " + name)
	}
	b.core.registerPlan(name, h)
}

// operations is a registry snapshot used by the server for manifest checks and
// dispatch.
type operations struct {
	invokes map[string]InvokeHandler
	jobs    map[string]JobHandler
	plans   map[string]PlanHandler
}

// instance is one initialized instance. Its mutex guards lifecycle, config and
// in-flight accounting; registration is protected by regMu so the hot path
// never contends with it.
type instance struct {
	id     string
	handle string
	host   *Host
	log    *slog.Logger
	author Instance

	// crashOnPanic disables panic recovery around plugin code (Options.CrashOnPanic).
	crashOnPanic bool

	regMu     sync.Mutex
	open      bool
	regInvoke map[string]InvokeHandler
	regJob    map[string]JobHandler
	regPlan   map[string]PlanHandler
	ops       operations

	// life serializes the lifecycle calls of this instance, hooks included; mu
	// below only guards fields. Requests never take it.
	life chan struct{}

	mu        sync.Mutex
	state     LifecycleState
	config    []byte
	configRev string
	inflight  int
	idle      chan struct{}
	released  bool

	bgCtx     context.Context
	bgCancel  context.CancelFunc
	bgAllowed bool
	bgWG      sync.WaitGroup
	// bgDone closes when the generation stopped last has fully returned.
	bgDone chan struct{}
}

func newInstance(id, handle string, host *Host, log *slog.Logger) *instance {
	return &instance{
		id:        id,
		handle:    handle,
		host:      host,
		log:       log,
		life:      make(chan struct{}, 1),
		state:     StateInitialized,
		open:      true,
		regInvoke: map[string]InvokeHandler{},
		regJob:    map[string]JobHandler{},
		regPlan:   map[string]PlanHandler{},
	}
}

// operations freezes the registry and returns a snapshot. It is called once,
// after NewInstance returned, so dispatch never takes regMu.
func (in *instance) operations() operations {
	in.regMu.Lock()
	defer in.regMu.Unlock()
	in.open = false
	return operations{invokes: in.regInvoke, jobs: in.regJob, plans: in.regPlan}
}

func (in *instance) registerInvoke(name string, h InvokeHandler) {
	in.regMu.Lock()
	defer in.regMu.Unlock()
	if !in.open {
		panic("pluginsdk: HandleInvoke(" + name + ") called outside NewInstance")
	}
	if _, dup := in.regInvoke[name]; dup {
		panic("pluginsdk: duplicate invoke handler for " + name)
	}
	in.regInvoke[name] = h
}

func (in *instance) registerJob(name string, h JobHandler) {
	in.regMu.Lock()
	defer in.regMu.Unlock()
	if !in.open {
		panic("pluginsdk: HandleJob(" + name + ") called outside NewInstance")
	}
	if _, dup := in.regJob[name]; dup {
		panic("pluginsdk: duplicate job handler for " + name)
	}
	in.regJob[name] = h
}

func (in *instance) registerPlan(name string, h PlanHandler) {
	in.regMu.Lock()
	defer in.regMu.Unlock()
	if !in.open {
		panic("pluginsdk: HandlePlan(" + name + ") called outside NewInstance")
	}
	if _, dup := in.regPlan[name]; dup {
		panic("pluginsdk: duplicate plan handler for " + name)
	}
	in.regPlan[name] = h
}

// bind hands the InstanceInfo to the author's NewInstance result. It is called
// after NewInstance returned and links the InstanceBase the author created with
// the core instance.
func (in *instance) bind(author Instance) error {
	b := author.base()
	if b == nil || b.core != in {
		return fmt.Errorf("pluginsdk: NewInstance returned an Instance that was not built from the InstanceInfo it received")
	}
	return nil
}

// acquireLife takes the lifecycle lock; the wait is bounded by ctx.
func (in *instance) acquireLife(ctx context.Context) (func(), error) {
	select {
	case in.life <- struct{}{}:
		return func() { <-in.life }, nil
	case <-ctx.Done():
		return nil, status.FromContextError(ctx.Err()).Err()
	}
}

// lockLife is acquireLife for calls that act on a live instance: a call that
// waited behind ReleaseInstance must not restart what the release just stopped.
func (in *instance) lockLife(ctx context.Context) (func(), error) {
	unlock, err := in.acquireLife(ctx)
	if err != nil {
		return nil, err
	}
	in.mu.Lock()
	released := in.released
	in.mu.Unlock()
	if released {
		unlock()
		return nil, status.Errorf(codes.NotFound, "instance %q was released", in.id)
	}
	return unlock, nil
}

// stateNow returns the current lifecycle state.
func (in *instance) stateNow() LifecycleState {
	in.mu.Lock()
	defer in.mu.Unlock()
	return in.state
}

// transition moves the instance to to when it currently is one of from.
func (in *instance) transition(to LifecycleState, from ...LifecycleState) error {
	in.mu.Lock()
	defer in.mu.Unlock()
	for _, f := range from {
		if in.state == f {
			in.state = to
			return nil
		}
	}
	return status.Errorf(codes.FailedPrecondition, "instance %q is %s, cannot move to %s", in.id, in.state, to)
}

// fail marks the instance FAILED after a lifecycle hook error.
func (in *instance) fail() {
	in.mu.Lock()
	in.state = StateFailed
	in.mu.Unlock()
}

// failBackground marks a serving instance FAILED after its tracked work
// panicked, so CheckHealth reports NOT_SERVING and the supervisor takes over. An
// instance already draining or stopped keeps its state.
func (in *instance) failBackground() {
	in.mu.Lock()
	defer in.mu.Unlock()
	if in.state == StateReady || in.state == StateActive {
		in.state = StateFailed
	}
}

// begin admits a request that runs plugin code. The caller must defer the
// returned release function. Only READY and ACTIVE instances serve requests.
func (in *instance) begin() (release func(), err error) {
	in.mu.Lock()
	defer in.mu.Unlock()
	if in.released {
		return nil, status.Errorf(codes.NotFound, "instance %q was released", in.id)
	}
	if in.state != StateReady && in.state != StateActive {
		return nil, status.Errorf(codes.FailedPrecondition, "instance %q is %s", in.id, in.state)
	}
	in.inflight++
	return in.leave, nil
}

// leave ends one admitted request.
func (in *instance) leave() {
	in.mu.Lock()
	defer in.mu.Unlock()
	if in.inflight > 0 {
		in.inflight--
	}
	if in.inflight == 0 && in.idle != nil {
		close(in.idle)
		in.idle = nil
	}
}

// isIdle reports whether no request is running.
func (in *instance) isIdle() bool {
	in.mu.Lock()
	defer in.mu.Unlock()
	return in.inflight == 0
}

// waitIdle waits up to grace for the in-flight requests to finish. It returns
// true when the instance is idle.
func (in *instance) waitIdle(ctx context.Context, grace time.Duration) bool {
	in.mu.Lock()
	if in.inflight == 0 {
		in.mu.Unlock()
		return true
	}
	// A concurrent waiter shares the channel; leave closes it exactly once.
	if in.idle == nil {
		in.idle = make(chan struct{})
	}
	idle := in.idle
	in.mu.Unlock()
	return waitFor(ctx, idle, grace)
}

// waitFor waits for ch, a timer or ctx cancellation.
func waitFor(ctx context.Context, ch <-chan struct{}, grace time.Duration) bool {
	timer := time.NewTimer(grace)
	defer timer.Stop()
	select {
	case <-ch:
		return true
	case <-timer.C:
		return false
	case <-ctx.Done():
		return false
	}
}

// awaitPreviousBackground waits for the generation stopped last. The caller
// holds the lifecycle lock.
func (in *instance) awaitPreviousBackground(ctx context.Context) error {
	in.mu.Lock()
	done := in.bgDone
	in.mu.Unlock()
	if done == nil {
		return nil
	}
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return status.FromContextError(ctx.Err()).Err()
	}
}

// startBackground moves READY to ACTIVE and, in the same critical section,
// creates the background context and enables tracked work. traceID is kept for
// host-call log correlation; the operation id stays empty because background
// work does not act for a dispatched operation.
func (in *instance) startBackground(parent context.Context, traceID string) (context.Context, error) {
	in.mu.Lock()
	defer in.mu.Unlock()
	if in.state != StateReady {
		return nil, status.Errorf(codes.FailedPrecondition, "instance %q is %s, cannot move to %s", in.id, in.state, StateActive)
	}
	if in.bgCancel != nil {
		in.bgCancel()
	}
	ctx, cancel := context.WithCancel(parent)
	ctx = withCallInfo(ctx, callInfo{call: Call{TraceID: traceID, InstanceID: in.id}})
	in.state = StateActive
	in.bgCtx, in.bgCancel, in.bgAllowed = ctx, cancel, true
	return ctx, nil
}

// startTracked runs fn as background work.
func (in *instance) startTracked(fn func(ctx context.Context)) error {
	in.mu.Lock()
	if !in.bgAllowed || in.bgCtx == nil {
		in.mu.Unlock()
		return fmt.Errorf("pluginsdk: background work may only start inside Activate")
	}
	ctx := in.bgCtx
	in.bgWG.Add(1)
	in.mu.Unlock()
	go func() {
		defer in.bgWG.Done()
		if err := safelyRun(in, "background", func() error { fn(ctx); return nil }); err != nil {
			in.failBackground()
		}
	}()
	return nil
}

// stopBackground disables tracked work, cancels the background context and
// waits for tracked goroutines up to grace. It returns true when they all
// returned.
func (in *instance) stopBackground(ctx context.Context, grace time.Duration) bool {
	in.mu.Lock()
	in.bgAllowed = false
	cancel := in.bgCancel
	in.bgCancel = nil
	in.bgCtx = nil
	done := make(chan struct{})
	in.bgDone = done
	in.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	go func() {
		in.bgWG.Wait()
		close(done)
	}()
	return waitFor(ctx, done, grace)
}

// configSnapshot returns a copy of the applied config and its revision.
func (in *instance) configSnapshot() ([]byte, string) {
	in.mu.Lock()
	defer in.mu.Unlock()
	return append([]byte(nil), in.config...), in.configRev
}

func (in *instance) setConfig(config []byte, revision string) {
	in.mu.Lock()
	in.config = append([]byte(nil), config...)
	in.configRev = revision
	in.mu.Unlock()
}

// markReleased reports whether this call released the instance. Only one
// caller wins; ReleaseInstance is idempotent.
func (in *instance) markReleased() bool {
	in.mu.Lock()
	defer in.mu.Unlock()
	if in.released {
		return false
	}
	in.released = true
	return true
}

// callInfo is stored in the contexts handed to plugin code so Host calls can
// fill HostCallContext and handlers can read the call metadata.
type callInfo struct {
	call Call
	// planning is set while PlanOperation runs; host writes are refused then.
	planning bool
}

type callInfoKey struct{}

func withCallInfo(ctx context.Context, ci callInfo) context.Context {
	return context.WithValue(ctx, callInfoKey{}, ci)
}

// withPreconditions stores the host-supplied optimistic guards in the call
// metadata so typed handlers can read them through [CallFromContext].
func withPreconditions(ctx context.Context, pre []Precondition) context.Context {
	ci, ok := callInfoOf(ctx)
	if !ok {
		return ctx
	}
	ci.call.Preconditions = pre
	return withCallInfo(ctx, ci)
}

func callInfoOf(ctx context.Context) (callInfo, bool) {
	ci, ok := ctx.Value(callInfoKey{}).(callInfo)
	return ci, ok
}

// CallFromContext returns the metadata of the call being served by ctx. It is
// false outside plugin code (e.g. in NewInstance) and for contexts the plugin
// created itself.
func CallFromContext(ctx context.Context) (Call, bool) {
	ci, ok := callInfoOf(ctx)
	return ci.call, ok
}
