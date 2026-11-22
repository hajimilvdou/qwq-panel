// SPDX-License-Identifier: AGPL-3.0-only

package events_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/qwq-panel/qwq/internal/events"
)

func nextSample(t *testing.T, sub *events.LossySubscription) any {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	v, ok := sub.Next(ctx)
	if !ok {
		t.Fatal("lossy subscription ended")
	}
	return v
}

func TestLossyCoalescesPerKey(t *testing.T) {
	l := events.NewLossy(events.LossyConfig{Topics: 2, Subscribers: 2, Keys: 4})
	sub, err := l.Subscribe("metrics.cpu")
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	defer sub.Close()

	l.Publish("metrics.cpu", "host", "v1")
	l.Publish("metrics.cpu", "host", "v2")
	l.Publish("metrics.cpu", "load", "v3")

	got := map[string]int{}
	for i := 0; i < 2; i++ {
		got[nextSample(t, sub).(string)]++
	}
	if _, ok := got["v2"]; !ok {
		t.Fatalf("samples = %v, want the newest value of key host", got)
	}
	if _, ok := got["v1"]; ok {
		t.Fatal("a stale value was delivered")
	}
	stats := l.Stats()
	if stats.Coalesced != 1 {
		t.Fatalf("coalesced = %d, want 1", stats.Coalesced)
	}
	if stats.Published != 3 {
		t.Fatalf("published = %d, want 3", stats.Published)
	}
}

func TestLossyDropsWhenKeySetIsFull(t *testing.T) {
	l := events.NewLossy(events.LossyConfig{Topics: 2, Subscribers: 2, Keys: 1})
	sub, err := l.Subscribe("presence")
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	defer sub.Close()

	l.Publish("presence", "a", 1)
	l.Publish("presence", "b", 2)
	if got := l.Stats().Dropped; got != 1 {
		t.Fatalf("dropped = %d, want 1", got)
	}
	if v := nextSample(t, sub); v.(int) != 1 {
		t.Fatalf("sample = %v, want 1", v)
	}
}

func TestLossyBoundsAndLifecycle(t *testing.T) {
	l := events.NewLossy(events.LossyConfig{Topics: 1, Subscribers: 1, Keys: 2})
	first, err := l.Subscribe("t1")
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	if _, err := l.Subscribe("t2"); !errors.Is(err, events.ErrTooManyTopics) {
		t.Fatalf("err = %v, want ErrTooManyTopics", err)
	}
	if _, err := l.Subscribe("t1"); !errors.Is(err, events.ErrTooManySubscribers) {
		t.Fatalf("err = %v, want ErrTooManySubscribers", err)
	}
	first.Close()
	first.Close() // idempotent
	if got := l.Stats(); got.Topics != 0 || got.Subscribers != 0 {
		t.Fatalf("stats after close = %+v", got)
	}
	if _, err := l.Subscribe("t2"); err != nil {
		t.Fatalf("Subscribe after close: %v", err)
	}
}

func TestLossyNextStopsOnContext(t *testing.T) {
	l := events.NewLossy(events.LossyConfig{})
	sub, err := l.Subscribe("quiet")
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	defer sub.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	if _, ok := sub.Next(ctx); ok {
		t.Fatal("Next succeeded on an idle topic")
	}
}
