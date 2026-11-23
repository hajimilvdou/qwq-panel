// SPDX-License-Identifier: AGPL-3.0-only

package events

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/qwq-panel/qwq/internal/actor"
	"github.com/qwq-panel/qwq/internal/platform/clock"
	"github.com/qwq-panel/qwq/internal/storage"
)

// Defaults of Config.
const (
	DefaultBuffer         = 256 // sse_buffer_events in x-qwq-limits
	DefaultBatch          = 256
	DefaultMaxSubscribers = 1024
	// MaxBuffer bounds a subscriber's explicit buffer request.
	MaxBuffer = 4096
)

// DefaultRetain keeps a week and at least 100k events; pruning removes only
// events outside both bounds (ADR-0008 §4).
var DefaultRetain = Retain{
	Keep:     100_000,
	MaxAge:   7 * 24 * time.Hour,
	Interval: 5 * time.Minute,
	Batch:    1000,
}

// Errors returned by the hub.
var (
	// ErrTooManySubscribers is returned when the configured subscription
	// limit is reached; the caller maps it to 503 UNAVAILABLE.
	ErrTooManySubscribers = errors.New("events: too many subscribers")
	// ErrClosed is returned after Close.
	ErrClosed = errors.New("events: hub closed")
)

// Journal is the part of storage.DB the hub reads. *storage.DB implements it,
// so the hub has no SQL of its own and tests can substitute a fake.
type Journal interface {
	EventsAfter(ctx context.Context, after int64, limit int) ([]storage.Event, error)
	OldestSeq(ctx context.Context) (int64, error)
	HeadSeq() int64
	WaitAfter(ctx context.Context, after int64) (int64, error)
	PruneEvents(ctx context.Context, keep int64, minAge time.Duration, batch int) (int64, error)
}

// Retain configures journal pruning. Retention is the union of both bounds:
// the newest Keep events and everything younger than MaxAge survive.
type Retain struct {
	Keep   int64
	MaxAge time.Duration
	// Interval between pruning passes; 0 disables pruning.
	Interval time.Duration
	// Batch bounds the rows deleted per pass.
	Batch int
}

// Config configures a Hub.
type Config struct {
	// Journal is the event journal; required.
	Journal Journal
	Clock   clock.Clock
	Logger  *slog.Logger
	// Buffer is the per-subscriber buffer (default DefaultBuffer).
	Buffer int
	// MaxSubscribers bounds concurrent subscriptions (default
	// DefaultMaxSubscribers).
	MaxSubscribers int
	// Batch is the journal read size (default DefaultBatch).
	Batch int
	// Retain configures pruning; the zero value disables it.
	Retain Retain
}

// Start describes where a subscription begins.
type Start struct {
	// Head is the journal head when the subscription was accepted. Events
	// delivered to the subscription are newer than the client's cursor and,
	// after Resync, newer than this value.
	Head int64
	// Resync is set when events between the client's cursor and Head are gone;
	// the caller must tell the client to reload its snapshots.
	Resync bool
	// Reason is the Resync reason (ReasonRetentionExceeded or
	// ReasonServerRestart).
	Reason string
}

// SubscribeOptions describe one subscription.
type SubscribeOptions struct {
	// Filter selects topics and subjects.
	Filter Filter
	// Visibility decides which events the actor may see; nil denies all.
	Visibility Visibility
	// Actor is the subscriber, for Visibility and logs.
	Actor actor.Actor
	// Since is the last event sequence the client already processed: events
	// after it are replayed from the journal. A negative value means "live
	// only" (no resume); 0 resumes from the oldest retained event.
	Since int64
	// Buffer overrides Config.Buffer for this subscription.
	Buffer int
}

// Subscription is a bounded stream of events.
type Subscription struct {
	hub    *Hub
	ch     chan Event
	vis    Visibility
	actor  actor.Actor
	filter Filter

	// Guarded by hub.mu.
	live       bool
	replayNext int64 // next sequence to replay; 0 = no replay pending
	replayTo   int64
	// resumeFrom is the highest sequence already covered for this subscriber:
	// the head at Subscribe time, raised by a replay. Live delivery starts
	// above it, so an event is never delivered twice because the tail loop was
	// behind when the subscriber arrived.
	resumeFrom int64
	closed     bool

	closeRequested atomic.Bool
	overflow       atomic.Bool
}

// Events is the delivery channel. The hub closes it when the subscription
// ends: because it was closed, the client was too slow (see Overflowed), or the
// hub stopped.
func (s *Subscription) Events() <-chan Event { return s.ch }

// Overflowed reports whether the subscription ended because its buffer was
// full. The caller must send a resync frame with reason buffer_overflow.
func (s *Subscription) Overflowed() bool { return s.overflow.Load() }

// Close unsubscribes. It is safe to call from any goroutine, more than once,
// and after the subscription has already ended.
func (s *Subscription) Close() {
	if s.closeRequested.CompareAndSwap(false, true) {
		s.hub.wake()
	}
}

func (s *Subscription) visible(e Event) bool {
	if s.vis == nil {
		return false
	}
	return s.vis(s.actor, e)
}

// Stats reports hub counters (ARCH §13: subscriptions, losses, resyncs).
type Stats struct {
	Subscribers    int
	MaxSubscribers int
	// Dropped counts events lost because a subscriber's buffer was full (each
	// such event also disconnects that subscriber with a resync).
	Dropped int64
	// Resyncs counts subscriptions that started with a resync.
	Resyncs int64
	// Replayed counts events replayed from the journal.
	Replayed int64
	// Pruned counts journal events deleted by retention.
	Pruned int64
	// Failed counts subscriptions ended by a journal read error.
	Failed int64
	// Delivered counts events handed to subscribers (replays included).
	Delivered int64
}

type counters struct {
	dropped, resyncs, replayed, pruned, failed, delivered atomic.Int64
}

// Hub tails the journal once and fans events out to its subscribers.
type Hub struct {
	cfg Config
	log *slog.Logger

	mu         sync.Mutex
	subs       map[*Subscription]struct{}
	cursor     int64 // highest sequence the tail loop has dispatched
	cancelWait context.CancelFunc
	cancelRun  context.CancelFunc
	started    bool
	stopped    bool
	lastPrune  time.Time

	done  chan struct{}
	stats counters
}

// New returns a hub. Run must be called for events to flow.
func New(cfg Config) (*Hub, error) {
	if cfg.Journal == nil {
		return nil, errors.New("events: Config.Journal is required")
	}
	if cfg.Clock == nil {
		cfg.Clock = clock.System{}
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.DiscardHandler)
	}
	if cfg.Buffer <= 0 {
		cfg.Buffer = DefaultBuffer
	}
	if cfg.Buffer > MaxBuffer {
		cfg.Buffer = MaxBuffer
	}
	if cfg.MaxSubscribers <= 0 {
		cfg.MaxSubscribers = DefaultMaxSubscribers
	}
	if cfg.Batch <= 0 {
		cfg.Batch = DefaultBatch
	}
	if cfg.Retain.Batch <= 0 {
		cfg.Retain.Batch = 1000
	}
	return &Hub{
		cfg:       cfg,
		log:       cfg.Logger.With("component", "events"),
		subs:      make(map[*Subscription]struct{}),
		lastPrune: cfg.Clock.Now(),
		done:      make(chan struct{}),
	}, nil
}

// Run tails the journal and the retention timer until ctx ends or Close is
// called. It is meant to be called once, from its own goroutine; it returns
// when every subscription has been closed.
func (h *Hub) Run(ctx context.Context) {
	h.mu.Lock()
	if h.started || h.stopped {
		h.mu.Unlock()
		return
	}
	runCtx, cancel := context.WithCancel(ctx)
	h.started = true
	h.cancelRun = cancel
	h.mu.Unlock()

	h.log.Debug("event hub started")

	pruneCtx, cancelPrune := context.WithCancel(runCtx)
	var wg sync.WaitGroup
	if h.cfg.Retain.Interval > 0 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			h.pruneLoop(pruneCtx)
		}()
	}

	h.tail(runCtx)
	cancelPrune()
	wg.Wait()

	h.mu.Lock()
	h.started = false
	h.cancelRun = nil
	h.mu.Unlock()
	h.closeAll()
	close(h.done)
	h.log.Debug("event hub stopped")
}

// Close stops the hub and closes every subscription. It waits for Run to
// return when it is running.
func (h *Hub) Close() {
	h.mu.Lock()
	if h.stopped {
		h.mu.Unlock()
		return
	}
	h.stopped = true
	started := h.started
	cancelRun, cancelWait := h.cancelRun, h.cancelWait
	h.mu.Unlock()

	if cancelRun != nil {
		cancelRun()
	}
	if cancelWait != nil {
		cancelWait()
	}
	if started {
		<-h.done
	}
	// Close before Run started (or after it returned) still has to end the
	// subscriptions; closeAll is idempotent.
	h.closeAll()
}

// Head returns the current journal head; heartbeat and resync frames carry it.
func (h *Hub) Head() int64 { return h.cfg.Journal.HeadSeq() }

// Stats returns the hub counters.
func (h *Hub) Stats() Stats {
	h.mu.Lock()
	n := len(h.subs)
	h.mu.Unlock()
	return Stats{
		Subscribers:    n,
		MaxSubscribers: h.cfg.MaxSubscribers,
		Dropped:        h.stats.dropped.Load(),
		Resyncs:        h.stats.resyncs.Load(),
		Replayed:       h.stats.replayed.Load(),
		Pruned:         h.stats.pruned.Load(),
		Failed:         h.stats.failed.Load(),
		Delivered:      h.stats.delivered.Load(),
	}
}

// Subscribe registers a subscriber. With Since >= 0 the events after that
// sequence are replayed from the journal (bounded by the subscriber buffer)
// before live delivery; when they are no longer retained, Start.Resync is set
// and delivery begins at the head.
func (h *Hub) Subscribe(ctx context.Context, opts SubscribeOptions) (*Subscription, Start, error) {
	if err := ctx.Err(); err != nil {
		return nil, Start{}, err
	}
	oldest, err := h.cfg.Journal.OldestSeq(ctx)
	if err != nil {
		return nil, Start{}, fmt.Errorf("events: read oldest sequence: %w", err)
	}

	buf := opts.Buffer
	if buf <= 0 {
		buf = h.cfg.Buffer
	}
	if buf > MaxBuffer {
		buf = MaxBuffer
	}

	head := h.cfg.Journal.HeadSeq()

	h.mu.Lock()
	if h.stopped {
		h.mu.Unlock()
		return nil, Start{}, ErrClosed
	}
	if len(h.subs) >= h.cfg.MaxSubscribers {
		h.mu.Unlock()
		return nil, Start{}, ErrTooManySubscribers
	}
	// A subscriber admitted now must replay up to everything the tail loop can
	// already dispatch, or the events in flight between the two reads would be
	// skipped.
	if h.cursor > head {
		head = h.cursor
	}
	s := &Subscription{
		hub:    h,
		ch:     make(chan Event, buf),
		vis:    opts.Visibility,
		actor:  opts.Actor,
		filter: opts.Filter,
	}
	start := Start{Head: head}
	s.resumeFrom = head
	switch {
	case opts.Since < 0:
		// No resume requested: live from the head.
		s.live = true
	case opts.Since > head:
		// The client is ahead of this journal (restored backup, or another
		// host answered earlier). Nothing can be replayed.
		start.Resync, start.Reason = true, ReasonServerRestart
		s.live = true
	case head == 0:
		// The journal is empty: nothing was ever lost.
		s.live = true
	case oldest == 0 || opts.Since+1 < oldest:
		start.Resync, start.Reason = true, ReasonRetentionExceeded
		s.live = true
	default:
		s.replayNext, s.replayTo = opts.Since+1, head
		if s.replayNext > s.replayTo {
			s.live, s.replayNext = true, 0
		}
	}
	h.subs[s] = struct{}{}
	if start.Resync {
		h.stats.resyncs.Add(1)
	}
	cancel := h.cancelWait
	h.mu.Unlock()

	// Wake the tail loop so a pending replay starts immediately.
	if cancel != nil {
		cancel()
	}
	return s, start, nil
}

// wake interrupts the tail loop's journal wait.
func (h *Hub) wake() {
	h.mu.Lock()
	cancel := h.cancelWait
	h.mu.Unlock()
	if cancel != nil {
		cancel()
	}
}

// tail is the hub's single journal reader.
func (h *Hub) tail(ctx context.Context) {
	for {
		if ctx.Err() != nil {
			return
		}
		h.sweep()
		h.replayPending(ctx)
		if ctx.Err() != nil {
			return
		}
		h.drain(ctx)
		if ctx.Err() != nil {
			return
		}
		if !h.wait(ctx) {
			return
		}
	}
}

// wait blocks until the journal head moves past the cursor or wake is called.
// Work that arrived before the wait (a pending replay, a closing subscriber) is
// detected under the same mutex Subscribe and Close use, so a wake-up can never
// be lost between the end of one iteration and the start of the next.
func (h *Hub) wait(ctx context.Context) bool {
	waitCtx, cancel := context.WithCancel(ctx)

	h.mu.Lock()
	h.cancelWait = cancel
	after := h.cursor
	work := h.hasWorkLocked()
	h.mu.Unlock()
	if work {
		cancel()
		return true
	}

	_, err := h.cfg.Journal.WaitAfter(waitCtx, after)

	h.mu.Lock()
	h.cancelWait = nil
	h.mu.Unlock()
	cancel()

	if ctx.Err() != nil {
		return false
	}
	if err != nil && !errors.Is(err, context.Canceled) {
		h.log.Warn("wait for event journal", "error", err)
		h.pause(ctx, 200*time.Millisecond)
	}
	return true
}

// hasWorkLocked reports whether the loop has something to do that does not
// depend on the journal head moving. h.mu must be held.
func (h *Hub) hasWorkLocked() bool {
	for s := range h.subs {
		if s.closed {
			continue
		}
		if s.closeRequested.Load() || s.replayNext > 0 {
			return true
		}
	}
	return false
}

// pause sleeps using the configured clock.
func (h *Hub) pause(ctx context.Context, d time.Duration) {
	select {
	case <-ctx.Done():
	case <-h.cfg.Clock.After(d):
	}
}

// sweep removes subscriptions whose Close was called.
func (h *Hub) sweep() {
	h.mu.Lock()
	for s := range h.subs {
		if s.closeRequested.Load() {
			h.removeLocked(s)
		}
	}
	h.mu.Unlock()
}

// drain reads new journal events and dispatches them.
func (h *Hub) drain(ctx context.Context) {
	for {
		h.mu.Lock()
		after := h.cursor
		n := len(h.subs)
		h.mu.Unlock()

		if n == 0 {
			// Head 读取期间可能有新订阅入场；同锁再次确认空场才允许跳过日志。
			head := h.cfg.Journal.HeadSeq()
			h.mu.Lock()
			if len(h.subs) == 0 {
				if head > h.cursor {
					h.cursor = head
				}
				h.mu.Unlock()
				return
			}
			after = h.cursor
			h.mu.Unlock()
		}

		batch, err := h.cfg.Journal.EventsAfter(ctx, after, h.cfg.Batch)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			h.log.Warn("read event journal", "error", err)
			h.pause(ctx, 200*time.Millisecond)
			return
		}
		for i := range batch {
			e := Convert(batch[i])
			h.setCursor(e.Seq)
			h.dispatch(e)
			if ctx.Err() != nil {
				return
			}
		}
		if len(batch) < h.cfg.Batch {
			return
		}
	}
}

func (h *Hub) setCursor(seq int64) {
	h.mu.Lock()
	if seq > h.cursor {
		h.cursor = seq
	}
	h.mu.Unlock()
}

// dispatch 由唯一 tail loop 按序投递。锁内只取订阅快照，动态权限查询放在锁外。
// 查询返回后再核订阅状态与水位，满缓冲仍按原规则断开。
func (h *Hub) dispatch(e Event) {
	h.mu.Lock()
	subs := make([]*Subscription, 0, len(h.subs))
	for s := range h.subs {
		if h.liveSubscriberLocked(s, e) {
			subs = append(subs, s)
		}
	}
	h.mu.Unlock()
	for _, s := range subs {
		h.mu.Lock()
		open := h.liveSubscriberLocked(s, e)
		h.mu.Unlock()
		if !open {
			continue
		}
		if !s.filter.Match(e) || !s.visible(e) {
			continue
		}
		h.mu.Lock()
		if h.liveSubscriberLocked(s, e) {
			h.deliverLocked(s, e)
		}
		h.mu.Unlock()
	}
}

// replayPending feeds journal events to subscriptions that resumed from an
// older sequence, capping each round at 1024 scanned rows so live drain is
// never starved by a catching-up subscriber.
func (h *Hub) replayPending(ctx context.Context) {
	const maxReplayRowsPerRound = 1024
	scanned := 0
	for scanned < maxReplayRowsPerRound {
		s, from, to, ok := h.replayState()
		if !ok {
			return
		}
		if ctx.Err() != nil {
			return
		}
		limit := min(h.cfg.Batch, maxReplayRowsPerRound-scanned)
		batch, err := h.cfg.Journal.EventsAfter(ctx, from-1, limit)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			h.log.Warn("replay event journal", "error", err)
			h.failReplay(s, err)
			continue
		}
		scanned += len(batch)
		if !h.applyReplay(s, from, to, batch) {
			h.failReplay(s, errors.New("events: journal no longer holds the replay range"))
			continue
		}
	}
}

func (h *Hub) replayState() (s *Subscription, from, to int64, ok bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for sub := range h.subs {
		if sub.closed || sub.closeRequested.Load() || sub.replayNext == 0 {
			continue
		}
		return sub, sub.replayNext, sub.replayTo, true
	}
	return nil, 0, 0, false
}

// applyReplay 逐事件查询动态权限，锁只覆盖投递与回放水位更新。
func (h *Hub) applyReplay(s *Subscription, from, to int64, batch []storage.Event) bool {
	advanced := false
	for i := range batch {
		e := Convert(batch[i])
		if e.Seq < from {
			continue
		}
		if e.Seq > to {
			break
		}
		h.mu.Lock()
		open := h.subscriptionOpenLocked(s)
		h.mu.Unlock()
		if !open {
			return true
		}
		allowed := s.filter.Match(e) && s.visible(e)
		h.mu.Lock()
		if !h.subscriptionOpenLocked(s) {
			h.mu.Unlock()
			return true
		}
		if allowed {
			if h.deliverLocked(s, e) {
				h.stats.replayed.Add(1)
			} else {
				h.mu.Unlock()
				return true
			}
		}
		s.replayNext = e.Seq + 1
		advanced = true
		h.mu.Unlock()
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if !h.subscriptionOpenLocked(s) {
		return true
	}
	if s.replayNext > s.replayTo {
		// The live loop may have moved past the replay target while this batch
		// was in flight; extend instead of skipping those events.
		if h.cursor > s.replayTo {
			s.replayTo, s.resumeFrom = h.cursor, h.cursor
		} else {
			s.replayNext, s.live, s.resumeFrom = 0, true, s.replayTo
		}
	}
	return advanced
}

// ======================== 同锁重核与有界投递，实时/回放复用 ========================

func (h *Hub) subscriptionOpenLocked(s *Subscription) bool {
	return !h.stopped && !s.closed && !s.closeRequested.Load()
}

func (h *Hub) liveSubscriberLocked(s *Subscription, e Event) bool {
	return h.subscriptionOpenLocked(s) && s.live && e.Seq > s.resumeFrom
}

// deliverLocked 的调用方必须持有 h.mu；检查与发送不能被关闭 channel 插入。
func (h *Hub) deliverLocked(s *Subscription, e Event) bool {
	if !h.subscriptionOpenLocked(s) {
		return false
	}
	select {
	case s.ch <- e:
		h.stats.delivered.Add(1)
		return true
	default:
		h.dropLocked(s)
		return false
	}
}

// failReplay disconnects a subscriber that cannot be brought up to date.
func (h *Hub) failReplay(s *Subscription, err error) {
	h.mu.Lock()
	if !s.closed {
		h.stats.failed.Add(1)
		h.removeLocked(s)
	}
	h.mu.Unlock()
	h.log.Warn("event replay failed", "error", err)
}

// dropLocked disconnects a subscriber whose buffer is full and counts the
// loss. h.mu must be held.
func (h *Hub) dropLocked(s *Subscription) {
	s.overflow.Store(true)
	h.stats.dropped.Add(1)
	h.log.Warn("event subscriber dropped",
		"reason", ReasonBufferOverflow,
		"actor_kind", s.actor.Kind, "actor_id", s.actor.ID, "buffer", cap(s.ch))
	h.removeLocked(s)
}

// removeLocked closes the subscription and forgets it. h.mu must be held.
func (h *Hub) removeLocked(s *Subscription) {
	if s.closed {
		return
	}
	s.closed = true
	delete(h.subs, s)
	close(s.ch)
}

func (h *Hub) closeAll() {
	h.mu.Lock()
	for s := range h.subs {
		h.removeLocked(s)
	}
	h.mu.Unlock()
}

// pruneLoop deletes journal events outside the retention window. It is driven
// by the configured clock so retention is testable without sleeping.
func (h *Hub) pruneLoop(ctx context.Context) {
	for {
		r := h.cfg.Retain
		if r.Interval <= 0 {
			return
		}
		h.mu.Lock()
		wait := r.Interval - h.cfg.Clock.Now().Sub(h.lastPrune)
		h.mu.Unlock()
		if wait < 0 {
			wait = 0
		}
		select {
		case <-ctx.Done():
			return
		case <-h.cfg.Clock.After(wait):
			h.prune(ctx)
		}
	}
}

// prune deletes events outside the retention window, but never events a
// replaying subscriber still needs.
func (h *Hub) prune(ctx context.Context) {
	r := h.cfg.Retain
	if r.Interval <= 0 {
		return
	}
	keep := r.Keep

	h.mu.Lock()
	h.lastPrune = h.cfg.Clock.Now()
	head := h.cfg.Journal.HeadSeq()
	for s := range h.subs {
		if s.replayNext > 0 {
			if need := head - s.replayNext + 1; need > keep {
				keep = need
			}
		}
	}
	h.mu.Unlock()

	n, err := h.cfg.Journal.PruneEvents(ctx, keep, r.MaxAge, r.Batch)
	if err != nil {
		if ctx.Err() == nil {
			h.log.Warn("prune event journal", "error", err)
		}
		return
	}
	if n > 0 {
		h.stats.pruned.Add(n)
		h.log.Debug("pruned event journal", "deleted", n, "keep", keep, "max_age", r.MaxAge.String())
	}
}
