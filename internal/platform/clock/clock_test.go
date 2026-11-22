// SPDX-License-Identifier: AGPL-3.0-only

package clock

import (
	"testing"
	"time"
)

func TestFakeAfterFiresInOrder(t *testing.T) {
	start := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	f := NewFake(start)
	late := f.After(2 * time.Second)
	early := f.After(time.Second)
	if f.Waiters() != 2 {
		t.Fatalf("waiters = %d", f.Waiters())
	}

	f.Advance(time.Second)
	select {
	case got := <-early:
		if !got.Equal(start.Add(time.Second)) {
			t.Fatalf("early fired at %v", got)
		}
	default:
		t.Fatal("early timer did not fire")
	}
	select {
	case <-late:
		t.Fatal("late timer fired too soon")
	default:
	}

	f.Advance(time.Second)
	select {
	case <-late:
	default:
		t.Fatal("late timer did not fire")
	}
	if f.Waiters() != 0 {
		t.Fatalf("waiters = %d", f.Waiters())
	}
}

func TestFakeAfterNonPositive(t *testing.T) {
	f := NewFake(time.Unix(0, 0))
	select {
	case <-f.After(0):
	default:
		t.Fatal("After(0) did not fire immediately")
	}
}

func TestSystem(t *testing.T) {
	var c Clock = System{}
	if c.Now().IsZero() {
		t.Fatal("zero time")
	}
	select {
	case <-c.After(time.Millisecond):
	case <-time.After(time.Second):
		t.Fatal("System.After did not fire")
	}
}
