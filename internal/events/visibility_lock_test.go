// SPDX-License-Identifier: AGPL-3.0-only

package events_test

import (
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/qwq-panel/qwq/internal/actor"
	"github.com/qwq-panel/qwq/internal/events"
	"github.com/qwq-panel/qwq/internal/platform/clock"
	"github.com/qwq-panel/qwq/internal/storage"
)

// ======================== 固定权限查询窗口，不用 sleep 猜测锁是否已持有 ========================

type blockedVisibilityFixture struct {
	hub     *events.Hub
	journal *fakeJournal
	sub     *events.Subscription
	release func()
}

var visibilityPhases = [...]struct {
	name   string
	replay bool
}{
	{name: "live"},
	{name: "replay", replay: true},
}

func blockVisibility(t *testing.T, replay bool) blockedVisibilityFixture {
	t.Helper()
	j := newFakeJournal(clock.System{})
	h := newHub(t, j, events.Config{Buffer: 8, MaxSubscribers: 8, Batch: 8})
	entered, gate := make(chan struct{}), make(chan struct{})
	var enterOnce, releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(gate) }) }
	t.Cleanup(release)
	opts := events.SubscribeOptions{
		Since: -1, Actor: testActor,
		Visibility: func(_ actor.Actor, _ events.Event) bool {
			enterOnce.Do(func() {
				close(entered)
				<-gate
			})
			return true
		},
	}
	if replay {
		j.append(storage.Event{Type: "resource.changed", Subject: "plugins/example"})
		opts.Since = 0
	}
	sub, _ := subscribe(t, h, opts)
	if !replay {
		j.append(storage.Event{Type: "resource.changed", Subject: "plugins/example"})
	}
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("visibility callback did not reach the controlled window")
	}
	return blockedVisibilityFixture{hub: h, journal: j, sub: sub, release: release}
}

func TestVisibilityLeavesHubLockAvailable(t *testing.T) {
	for _, test := range visibilityPhases {
		t.Run(test.name, func(t *testing.T) {
			f := blockVisibility(t, test.replay)
			done := make(chan struct{})
			go func() {
				f.hub.Stats()
				close(done)
			}()
			defer func() {
				f.release()
				select {
				case <-done:
				case <-time.After(3 * time.Second):
					t.Error("hub stats worker did not return after releasing visibility")
				}
			}()
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("visibility query held the global hub lock")
			}
			fast, start := subscribe(t, f.hub, events.SubscribeOptions{Since: -1, Actor: testActor, Visibility: events.AllowAll})
			if start.Head != 1 {
				t.Fatalf("new subscriber head = %d, want in-flight event 1", start.Head)
			}
			f.release()
			if got := recv(t, f.sub); got.Seq != 1 {
				t.Fatalf("original event sequence = %d, want 1", got.Seq)
			}
			f.journal.append(storage.Event{Type: "resource.changed", Subject: "plugins/example"})
			if got := recv(t, fast); got.Seq != 2 {
				t.Fatalf("new subscriber saw a stale event or skipped the next event: %d", got.Seq)
			}
		})
	}
}

// ======================== Close 已返回后，迟到的权限结果不能复活订阅 ========================

func TestVisibilityCloseRejectsLateDelivery(t *testing.T) {
	for _, test := range visibilityPhases {
		t.Run(test.name, func(t *testing.T) {
			f := blockVisibility(t, test.replay)
			done := make(chan struct{})
			go func() {
				f.sub.Close()
				close(done)
			}()
			defer func() {
				f.release()
				select {
				case <-done:
				case <-time.After(3 * time.Second):
					t.Error("subscription close worker did not return")
				}
			}()
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("subscription Close waited for the visibility query")
			}
			f.release()
			select {
			case e, ok := <-f.sub.Events():
				if ok {
					t.Fatalf("closed subscription received late event %d", e.Seq)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("closed subscription was not reclaimed after visibility returned")
			}
		})
	}
}

// ======================== 空场检查后入场的订阅不能被跳过新事件 ========================

func TestEmptyHubRechecksSubscribersBeforeAdvancing(t *testing.T) {
	j := newFakeJournal(clock.System{})
	h := newHub(t, j, events.Config{Buffer: 8, Batch: 8})
	entered, gate := make(chan struct{}), make(chan struct{})
	var once sync.Once
	release := func() { once.Do(func() { close(gate) }) }
	t.Cleanup(release)
	j.onNextHead(func() {
		close(entered)
		<-gate
	})
	j.append(storage.Event{Type: "resource.changed", Subject: "plugins/example"})
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("empty hub did not reach its head read")
	}
	sub, start := subscribe(t, h, events.SubscribeOptions{Since: -1, Actor: testActor, Visibility: events.AllowAll})
	if start.Head != 1 {
		t.Fatalf("subscriber head = %d, want 1", start.Head)
	}
	j.append(storage.Event{Type: "resource.changed", Subject: "plugins/example"})
	release()
	if got := recv(t, sub); got.Seq != 2 {
		t.Fatalf("empty hub skipped or replayed the wrong event after admission: %d", got.Seq)
	}
}

// ======================== 确认丢弃的通知和 channel 关闭都能读到终态原因 ========================

func TestOverflowReasonPublishedBeforeNotificationAndClose(t *testing.T) {
	j := newFakeJournal(clock.System{})
	var observed atomic.Pointer[events.Subscription]
	notified := make(chan bool, 1)
	logger := slog.New(eventLogObserver(func(record slog.Record) {
		if record.Message != "event subscriber dropped" {
			return
		}
		if sub := observed.Load(); sub != nil {
			select {
			case notified <- sub.Overflowed():
			default:
			}
		}
	}))
	h := newHub(t, j, events.Config{Buffer: 1, Logger: logger})
	sub, _ := subscribe(t, h, events.SubscribeOptions{Since: -1, Actor: testActor, Visibility: events.AllowAll})
	observed.Store(sub)
	j.append(storage.Event{})
	waitFor(t, "full subscriber buffer", func() bool { return len(sub.Events()) == 1 })
	j.append(storage.Event{})
	select {
	case overflow := <-notified:
		if !overflow {
			t.Error("drop notification preceded publication of its overflow reason")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("subscriber overflow did not notify")
	}
	expectClosed(t, sub)
	if !sub.Overflowed() {
		t.Fatal("closed subscriber did not expose buffer_overflow immediately")
	}
}

// ======================== 被拒绝的回放仍推进；后续授权变化逐次生效 ========================

func TestVisibilityDeniedReplayAdvancesAndRechecks(t *testing.T) {
	j := newFakeJournal(clock.System{})
	j.append(storage.Event{})
	h := newHub(t, j, events.Config{Buffer: 8, Batch: 8})
	var allowed atomic.Bool
	replayed, denied := make(chan struct{}), make(chan struct{})
	var replayOnce, denyOnce sync.Once
	sub, _ := subscribe(t, h, events.SubscribeOptions{
		Since: 0, Actor: testActor,
		Visibility: func(_ actor.Actor, e events.Event) bool {
			permit := allowed.Load()
			switch e.Seq {
			case 1:
				replayOnce.Do(func() { close(replayed) })
			case 3:
				denyOnce.Do(func() { close(denied) })
			}
			return permit
		},
	})
	select {
	case <-replayed:
	case <-time.After(3 * time.Second):
		t.Fatal("denied history was not checked")
	}
	allowed.Store(true)
	j.append(storage.Event{})
	if got := recv(t, sub); got.Seq != 2 {
		t.Fatalf("denied replay did not advance to the next event: %d", got.Seq)
	}
	if h.Stats().Replayed != 0 {
		t.Fatal("live event was replayed after denied history")
	}
	allowed.Store(false)
	j.append(storage.Event{})
	select {
	case <-denied:
	case <-time.After(3 * time.Second):
		t.Fatal("revoked visibility was not checked")
	}
	allowed.Store(true)
	j.append(storage.Event{})
	if got := recv(t, sub); got.Seq != 4 {
		t.Fatalf("visibility cache leaked a revoked event or lost the renewed grant: %d", got.Seq)
	}
}
