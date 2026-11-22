// SPDX-License-Identifier: AGPL-3.0-only

package events_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/qwq-panel/qwq/internal/actor"
	"github.com/qwq-panel/qwq/internal/events"
	"github.com/qwq-panel/qwq/internal/platform/clock"
	"github.com/qwq-panel/qwq/internal/storage"
)

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func TestConvert(t *testing.T) {
	at := time.Date(2026, 11, 1, 10, 20, 30, 400_000_000, time.UTC)
	e := events.Convert(storage.Event{
		Seq:           42,
		EventID:       "evt_1",
		Type:          "resource.changed",
		SchemaVersion: "1",
		Subject:       "users/usr_1",
		OccurredAt:    at,
		ActorKind:     "human",
		ActorID:       "usr_1",
		OnBehalfOf:    "",
		TraceID:       "abc",
		OperationID:   "op_1",
		Payload:       json.RawMessage("{\n \"revision\": \"42\"\n}"),
	})
	if e.Sequence != "42" || e.Seq != 42 {
		t.Fatalf("sequence = %q / %d, want 42", e.Sequence, e.Seq)
	}
	if e.DeliveryClass != events.DeliveryReliable {
		t.Fatalf("delivery class = %q", e.DeliveryClass)
	}
	if e.OccurredAt != "2026-11-01T10:20:30.400Z" {
		t.Fatalf("occurred_at = %q", e.OccurredAt)
	}
	if e.Actor.Kind != "human" || e.Actor.ID != "usr_1" {
		t.Fatalf("actor = %+v", e.Actor)
	}
	if strings.Contains(string(e.Payload), "\n") {
		t.Fatalf("payload was not compacted: %q", e.Payload)
	}
	if empty := events.Convert(storage.Event{Seq: 1}); string(empty.Payload) != "{}" {
		t.Fatalf("empty payload = %q, want {}", empty.Payload)
	}
}

func TestLiveDeliveryAndTopicFilter(t *testing.T) {
	j := newFakeJournal(clock.System{})
	h := newHub(t, j, events.Config{Buffer: 8, MaxSubscribers: 8, Batch: 8})

	sub, start := subscribe(t, h, events.SubscribeOptions{
		Since:      -1,
		Actor:      testActor,
		Visibility: events.AllowAll,
		Filter:     events.Filter{Topics: []string{"resource.*"}},
	})
	if start.Resync || start.Head != 0 {
		t.Fatalf("start = %+v, want live at head 0", start)
	}

	j.append(storage.Event{Type: "resource.changed", Subject: "users/usr_1"})
	e := recv(t, sub)
	if e.Seq != 1 || e.Type != "resource.changed" {
		t.Fatalf("event = %+v", e)
	}

	j.append(storage.Event{Type: "operation.updated", Subject: "operations/op_1"})
	expectNoEvent(t, sub, 150*time.Millisecond)

	j.append(storage.Event{Type: "resource.deleted", Subject: "users/usr_1"})
	if got := recv(t, sub); got.Seq != 3 {
		t.Fatalf("seq = %d, want 3", got.Seq)
	}
}

func TestSubjectPrefixFilter(t *testing.T) {
	j := newFakeJournal(clock.System{})
	h := newHub(t, j, events.Config{Buffer: 8})

	sub, _ := subscribe(t, h, events.SubscribeOptions{
		Since:      -1,
		Actor:      testActor,
		Visibility: events.AllowAll,
		Filter:     events.Filter{SubjectPrefix: "nodes/local/plugins/"},
	})
	j.append(storage.Event{Subject: "users/usr_1"})
	expectNoEvent(t, sub, 150*time.Millisecond)
	j.append(storage.Event{Subject: "nodes/local/plugins/com.example.monitor/resources/a"})
	if got := recv(t, sub); got.Seq != 2 {
		t.Fatalf("seq = %d, want 2", got.Seq)
	}
}

func TestReplayFromSequence(t *testing.T) {
	j := newFakeJournal(clock.System{})
	h := newHub(t, j, events.Config{Buffer: 8, Batch: 8})
	for i := 0; i < 3; i++ {
		j.append(storage.Event{})
	}

	sub, start := subscribe(t, h, events.SubscribeOptions{Since: 1, Actor: testActor, Visibility: events.AllowAll})
	if start.Resync || start.Head != 3 {
		t.Fatalf("start = %+v, want head 3 without resync", start)
	}
	for _, want := range []int64{2, 3} {
		if got := recv(t, sub); got.Seq != want {
			t.Fatalf("replayed seq = %d, want %d", got.Seq, want)
		}
	}
	j.append(storage.Event{})
	if got := recv(t, sub); got.Seq != 4 {
		t.Fatalf("live seq = %d, want 4", got.Seq)
	}
}

func TestReplayOverflowDisconnectsSubscriber(t *testing.T) {
	j := newFakeJournal(clock.System{})
	h := newHub(t, j, events.Config{Buffer: 2, Batch: 8})
	for i := 0; i < 5; i++ {
		j.append(storage.Event{})
	}

	sub, start := subscribe(t, h, events.SubscribeOptions{Since: 1, Buffer: 2, Actor: testActor, Visibility: events.AllowAll})
	if start.Resync {
		t.Fatalf("start = %+v, want replay", start)
	}
	waitFor(t, "buffer overflow", func() bool { return sub.Overflowed() })
	expectClosed(t, sub)
	if got := h.Stats().Dropped; got == 0 {
		t.Fatal("dropped counter was not incremented")
	}
	waitFor(t, "subscriber removal", func() bool { return h.Stats().Subscribers == 0 })
}

func TestResyncWhenRetentionPassed(t *testing.T) {
	j := newFakeJournal(clock.System{})
	h := newHub(t, j, events.Config{Buffer: 8})
	for i := 0; i < 10; i++ {
		j.append(storage.Event{})
	}
	j.dropBefore(5)

	sub, start := subscribe(t, h, events.SubscribeOptions{Since: 2, Actor: testActor, Visibility: events.AllowAll})
	if !start.Resync || start.Reason != events.ReasonRetentionExceeded {
		t.Fatalf("start = %+v, want retention resync", start)
	}
	if start.Head != 10 {
		t.Fatalf("head = %d, want 10", start.Head)
	}
	expectNoEvent(t, sub, 150*time.Millisecond)
	if got := h.Stats().Resyncs; got != 1 {
		t.Fatalf("resyncs = %d, want 1", got)
	}
}

func TestResyncWhenClientAhead(t *testing.T) {
	j := newFakeJournal(clock.System{})
	h := newHub(t, j, events.Config{Buffer: 8})
	j.append(storage.Event{})
	j.append(storage.Event{})

	_, start := subscribe(t, h, events.SubscribeOptions{Since: 99, Actor: testActor, Visibility: events.AllowAll})
	if !start.Resync || start.Reason != events.ReasonServerRestart {
		t.Fatalf("start = %+v, want server restart resync", start)
	}
}

func TestRefusesTooManySubscribers(t *testing.T) {
	j := newFakeJournal(clock.System{})
	h := newHub(t, j, events.Config{Buffer: 4, MaxSubscribers: 1})
	subscribe(t, h, events.SubscribeOptions{Since: -1, Actor: testActor, Visibility: events.AllowAll})

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, _, err := h.Subscribe(ctx, events.SubscribeOptions{Since: -1, Actor: testActor, Visibility: events.AllowAll})
	if !errors.Is(err, events.ErrTooManySubscribers) {
		t.Fatalf("err = %v, want ErrTooManySubscribers", err)
	}
}

func TestVisibilityIsEnforced(t *testing.T) {
	j := newFakeJournal(clock.System{})
	h := newHub(t, j, events.Config{Buffer: 8})

	sub, _ := subscribe(t, h, events.SubscribeOptions{
		Since: -1,
		Actor: testActor,
		Visibility: func(_ actor.Actor, e events.Event) bool {
			return e.Subject == "users/usr_allowed"
		},
	})
	j.append(storage.Event{Subject: "users/usr_denied"})
	expectNoEvent(t, sub, 150*time.Millisecond)
	j.append(storage.Event{Subject: "users/usr_allowed"})
	if got := recv(t, sub); got.Seq != 2 {
		t.Fatalf("seq = %d, want 2", got.Seq)
	}

	// A nil Visibility denies everything: forgetting to wire authorization
	// must not leak events.
	hidden, _ := subscribe(t, h, events.SubscribeOptions{Since: -1, Actor: testActor})
	j.append(storage.Event{Subject: "users/usr_allowed"})
	expectNoEvent(t, hidden, 150*time.Millisecond)
}

func TestCloseEndsSubscription(t *testing.T) {
	j := newFakeJournal(clock.System{})
	h := newHub(t, j, events.Config{Buffer: 8})
	sub, _ := subscribe(t, h, events.SubscribeOptions{Since: -1, Actor: testActor, Visibility: events.AllowAll})
	sub.Close()
	expectClosed(t, sub)
	waitFor(t, "subscriber removal", func() bool { return h.Stats().Subscribers == 0 })
	j.append(storage.Event{})
	expectNoEvent(t, sub, 100*time.Millisecond)
}

func TestSharedTailLoopReadsOnceForAllSubscribers(t *testing.T) {
	j := newFakeJournal(clock.System{})
	h := newHub(t, j, events.Config{Buffer: 8, Batch: 16})
	a, _ := subscribe(t, h, events.SubscribeOptions{Since: -1, Actor: testActor, Visibility: events.AllowAll})
	b, _ := subscribe(t, h, events.SubscribeOptions{Since: -1, Actor: testActor, Visibility: events.AllowAll})
	j.append(storage.Event{})
	if recv(t, a).Seq != 1 || recv(t, b).Seq != 1 {
		t.Fatal("both subscribers should see the event")
	}
	reads, _, _, _, _ := j.stats()
	if reads > 6 {
		t.Fatalf("journal read %d times for 2 subscribers; the tail loop must read once", reads)
	}
	if got := h.Stats().Delivered; got != 2 {
		t.Fatalf("delivered = %d, want 2", got)
	}
}

func TestPruneFollowsClock(t *testing.T) {
	clk := clock.NewFake(time.Unix(1_700_000_000, 0).UTC())
	j := newFakeJournal(clk)
	h := newHub(t, j, events.Config{
		Clock:  clk,
		Buffer: 8,
		Retain: events.Retain{Keep: 2, MaxAge: time.Hour, Interval: time.Minute, Batch: 100},
	})
	for i := 0; i < 5; i++ {
		j.append(storage.Event{})
	}

	waitFor(t, "prune timer armed", func() bool { return clk.Waiters() > 0 })
	clk.Advance(time.Minute)
	waitFor(t, "first prune", func() bool { calls, _, _ := j.pruneState(); return calls >= 1 })
	if _, keep, maxAge := j.pruneState(); keep != 2 || maxAge != time.Hour {
		t.Fatalf("prune(keep=%d, maxAge=%v), want (2, 1h)", keep, maxAge)
	}
	// Nothing is old enough yet: the union of both bounds keeps everything.
	if got := len(j.events); got != 5 {
		t.Fatalf("retained %d events, want 5", got)
	}

	waitFor(t, "prune timer re-armed", func() bool { return clk.Waiters() > 0 })
	clk.Advance(2 * time.Hour)
	waitFor(t, "second prune", func() bool { calls, _, _ := j.pruneState(); return calls >= 2 })
	if got := len(j.events); got != 2 {
		t.Fatalf("retained %d events, want the newest 2", got)
	}
	if got := h.Stats().Pruned; got != 3 {
		t.Fatalf("pruned counter = %d, want 3", got)
	}
}

func TestPruneKeepsEventsNeededByReplay(t *testing.T) {
	clk := clock.NewFake(time.Unix(1_700_000_000, 0).UTC())
	j := newFakeJournal(clk)
	h := newHub(t, j, events.Config{
		Clock:  clk,
		Buffer: 8,
		Retain: events.Retain{Keep: 2, MaxAge: time.Hour, Interval: time.Minute, Batch: 100},
	})
	for i := 0; i < 5; i++ {
		j.append(storage.Event{})
	}

	gate := make(chan struct{})
	j.holdReads(gate)
	sub, _ := subscribe(t, h, events.SubscribeOptions{Since: 2, Actor: testActor, Visibility: events.AllowAll})

	waitFor(t, "prune timer armed", func() bool { return clk.Waiters() > 0 })
	clk.Advance(time.Minute)
	waitFor(t, "prune during replay", func() bool { calls, _, _ := j.pruneState(); return calls >= 1 })
	if _, keep, _ := j.pruneState(); keep != 3 {
		t.Fatalf("keep = %d, want 3 (the replay starts at sequence 3)", keep)
	}
	close(gate)
	for _, want := range []int64{3, 4, 5} {
		if got := recv(t, sub); got.Seq != want {
			t.Fatalf("replayed %d, want %d", got.Seq, want)
		}
	}
}

func TestSubscribeAfterClose(t *testing.T) {
	j := newFakeJournal(clock.System{})
	h := newHub(t, j, events.Config{Buffer: 4})
	sub, _ := subscribe(t, h, events.SubscribeOptions{Since: -1, Actor: testActor, Visibility: events.AllowAll})
	h.Close()
	expectClosed(t, sub)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, _, err := h.Subscribe(ctx, events.SubscribeOptions{Since: -1, Actor: testActor, Visibility: events.AllowAll})
	if !errors.Is(err, events.ErrClosed) {
		t.Fatalf("err = %v, want ErrClosed", err)
	}
}

func TestStatsCounters(t *testing.T) {
	j := newFakeJournal(clock.System{})
	h := newHub(t, j, events.Config{Buffer: 8, Batch: 8})
	subscribe(t, h, events.SubscribeOptions{Since: -1, Actor: testActor, Visibility: events.AllowAll})
	j.append(storage.Event{})
	waitFor(t, "delivery", func() bool { return h.Stats().Delivered == 1 })
	s := h.Stats()
	if s.Subscribers != 1 || s.MaxSubscribers != 1024 {
		t.Fatalf("stats = %+v", s)
	}
}
