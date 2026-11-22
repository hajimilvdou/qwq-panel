// SPDX-License-Identifier: AGPL-3.0-only

package events_test

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/qwq-panel/qwq/internal/actor"
	"github.com/qwq-panel/qwq/internal/events"
	"github.com/qwq-panel/qwq/internal/platform/clock"
	"github.com/qwq-panel/qwq/internal/storage"
)

// fakeJournal is an in-memory stand-in for storage.DB with the same visibility
// rule: an event is readable once it is appended, and WaitAfter blocks until
// the head passes the caller's cursor.
type fakeJournal struct {
	mu     sync.Mutex
	events []storage.Event
	head   int64
	ch     chan struct{}

	reads    int
	waits    int
	prunes   int
	keep     int64
	maxAge   time.Duration
	gate     <-chan struct{} // when set, EventsAfter waits for it to close
	headHook func()
	clock    clock.Clock
	prunedN  int64
}

func newFakeJournal(clk clock.Clock) *fakeJournal {
	if clk == nil {
		clk = clock.System{}
	}
	return &fakeJournal{ch: make(chan struct{}), clock: clk}
}

func (j *fakeJournal) append(e storage.Event) int64 {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.head++
	e.Seq = j.head
	if e.EventID == "" {
		e.EventID = fmt.Sprintf("evt_%026d", j.head)
	}
	if e.OccurredAt.IsZero() {
		e.OccurredAt = j.clock.Now()
	}
	if e.Type == "" {
		e.Type = "resource.changed"
	}
	if e.SchemaVersion == "" {
		e.SchemaVersion = "1"
	}
	if e.Subject == "" {
		e.Subject = "users/usr_1"
	}
	if e.Payload == nil {
		e.Payload = []byte(`{}`)
	}
	j.events = append(j.events, e)
	close(j.ch)
	j.ch = make(chan struct{})
	return e.Seq
}

func (j *fakeJournal) EventsAfter(ctx context.Context, after int64, limit int) ([]storage.Event, error) {
	j.mu.Lock()
	gate := j.gate
	j.mu.Unlock()
	if gate != nil {
		select {
		case <-gate:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	j.reads++
	out := make([]storage.Event, 0, limit)
	for _, e := range j.events {
		if e.Seq > after {
			out = append(out, e)
			if len(out) == limit {
				break
			}
		}
	}
	return out, nil
}

func (j *fakeJournal) OldestSeq(context.Context) (int64, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if len(j.events) == 0 {
		return 0, nil
	}
	return j.events[0].Seq, nil
}

func (j *fakeJournal) HeadSeq() int64 {
	j.mu.Lock()
	hook := j.headHook
	j.headHook = nil
	j.mu.Unlock()
	if hook != nil {
		hook()
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.head
}

// ======================== 只拦下一次 HeadSeq，其他订阅仍可读取当前水位 ========================

func (j *fakeJournal) onNextHead(fn func()) {
	j.mu.Lock()
	j.headHook = fn
	j.mu.Unlock()
}

func (j *fakeJournal) WaitAfter(ctx context.Context, after int64) (int64, error) {
	for {
		j.mu.Lock()
		head, ch := j.head, j.ch
		j.waits++
		j.mu.Unlock()
		if head > after {
			return head, nil
		}
		select {
		case <-ch:
		case <-ctx.Done():
			return head, ctx.Err()
		}
	}
}

func (j *fakeJournal) PruneEvents(_ context.Context, keep int64, minAge time.Duration, _ int) (int64, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.prunes++
	j.keep = keep
	j.maxAge = minAge
	var kept []storage.Event
	n := int64(0)
	cutoff := j.clock.Now().Add(-minAge)
	for i, e := range j.events {
		old := int64(len(j.events)-i) > keep && e.OccurredAt.Before(cutoff)
		if old {
			n++
			continue
		}
		kept = append(kept, e)
	}
	j.events = kept
	j.prunedN += n
	return n, nil
}

func (j *fakeJournal) stats() (reads, waits, prunes int, keep int64, maxAge time.Duration) {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.reads, j.waits, j.prunes, j.keep, j.maxAge
}

// pruneState returns how often PruneEvents ran and with which bounds.
func (j *fakeJournal) pruneState() (calls int, keep int64, maxAge time.Duration) {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.prunes, j.keep, j.maxAge
}

// dropBefore simulates retention: it removes every event with seq <= n.
func (j *fakeJournal) dropBefore(n int64) {
	j.mu.Lock()
	defer j.mu.Unlock()
	var kept []storage.Event
	for _, e := range j.events {
		if e.Seq > n {
			kept = append(kept, e)
		}
	}
	j.events = kept
}

func (j *fakeJournal) holdReads(gate <-chan struct{}) {
	j.mu.Lock()
	j.gate = gate
	j.mu.Unlock()
}

var testActor = actor.Actor{Kind: actor.Human, ID: "usr_test"}

func newHub(t *testing.T, j *fakeJournal, cfg events.Config) *events.Hub {
	t.Helper()
	cfg.Journal = j
	if cfg.Clock == nil {
		cfg.Clock = clock.System{}
	}
	h, err := events.New(cfg)
	if err != nil {
		t.Fatalf("events.New: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	done := make(chan struct{})
	go func() {
		defer close(done)
		h.Run(ctx)
	}()
	t.Cleanup(func() {
		h.Close()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("hub.Run did not return")
		}
	})
	return h
}

func subscribe(t *testing.T, h *events.Hub, opts events.SubscribeOptions) (*events.Subscription, events.Start) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	sub, start, err := h.Subscribe(ctx, opts)
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	return sub, start
}

func recv(t *testing.T, sub *events.Subscription) events.Event {
	t.Helper()
	select {
	case e, ok := <-sub.Events():
		if !ok {
			t.Fatal("subscription closed while waiting for an event")
		}
		return e
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for an event")
		return events.Event{}
	}
}

func expectNoEvent(t *testing.T, sub *events.Subscription, d time.Duration) {
	t.Helper()
	select {
	case e, ok := <-sub.Events():
		if ok {
			t.Fatalf("unexpected event %d %s", e.Seq, e.Type)
		}
	case <-time.After(d):
	}
}

func expectClosed(t *testing.T, sub *events.Subscription) {
	t.Helper()
	deadline := time.After(3 * time.Second)
	for {
		select {
		case _, ok := <-sub.Events():
			if !ok {
				return
			}
		case <-deadline:
			t.Fatal("subscription was not closed")
		}
	}
}

// ======================== 日志观察器只看通知，不能反向取得 Hub 的锁 ========================

type eventLogObserver func(slog.Record)

func (eventLogObserver) Enabled(context.Context, slog.Level) bool { return true }

func (observe eventLogObserver) Handle(_ context.Context, record slog.Record) error {
	observe(record)
	return nil
}

func (observe eventLogObserver) WithAttrs([]slog.Attr) slog.Handler { return observe }

func (observe eventLogObserver) WithGroup(string) slog.Handler { return observe }
