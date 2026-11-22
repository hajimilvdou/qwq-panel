// SPDX-License-Identifier: AGPL-3.0-only

// Package clock abstracts time so that expiry, retention and backoff logic can
// be tested without sleeping.
package clock

import (
	"sort"
	"sync"
	"time"
)

// Clock is the time source used by host code. Code must not call time.Now or
// time.After directly where the result affects behaviour.
type Clock interface {
	Now() time.Time
	// After behaves like time.After.
	After(d time.Duration) <-chan time.Time
}

// System is the real clock.
type System struct{}

// Now returns time.Now.
func (System) Now() time.Time { return time.Now() }

// After returns time.After(d).
func (System) After(d time.Duration) <-chan time.Time { return time.After(d) }

// Fake is a manually advanced clock for tests. The zero value starts at the
// zero time; use NewFake for a fixed start.
type Fake struct {
	mu      sync.Mutex
	now     time.Time
	waiters []waiter
}

type waiter struct {
	at time.Time
	ch chan time.Time
}

// NewFake returns a Fake set to t.
func NewFake(t time.Time) *Fake { return &Fake{now: t} }

// Now returns the fake time.
func (f *Fake) Now() time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.now
}

// After returns a channel that receives once the fake time reaches now+d.
func (f *Fake) After(d time.Duration) <-chan time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	ch := make(chan time.Time, 1)
	at := f.now.Add(d)
	if d <= 0 {
		ch <- f.now
		return ch
	}
	f.waiters = append(f.waiters, waiter{at: at, ch: ch})
	return ch
}

// Advance moves the fake time forward and fires due timers in order.
func (f *Fake) Advance(d time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.now = f.now.Add(d)
	sort.SliceStable(f.waiters, func(i, j int) bool { return f.waiters[i].at.Before(f.waiters[j].at) })
	keep := f.waiters[:0]
	for _, w := range f.waiters {
		if !w.at.After(f.now) {
			w.ch <- f.now // buffered, never blocks
			continue
		}
		keep = append(keep, w)
	}
	f.waiters = keep
}

// Waiters returns the number of pending After channels, so tests can wait
// until the code under test has armed its timer.
func (f *Fake) Waiters() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.waiters)
}
