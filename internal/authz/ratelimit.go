// SPDX-License-Identifier: AGPL-3.0-only

package authz

import (
	"sync"
	"time"
)

// DefaultRateLimiterEntries bounds the memory of the delegation rate limiter;
// a few thousand tokens of state stay well under a megabyte on a 1 GiB host.
const DefaultRateLimiterEntries = 4096

// RateLimiter is a bounded in-memory token bucket per delegation. It enforces
// DelegationPolicy.requests_per_minute (ADR-0004 D10: every delegation has a
// rate limit). State is per process; a restart resets it, which is acceptable
// because a restart cannot be used to make more requests than the policy
// allows in a minute.
type RateLimiter struct {
	mu      sync.Mutex
	now     func() time.Time
	entries map[string]*bucket
	max     int
}

type bucket struct {
	tokens float64
	last   time.Time
}

// NewRateLimiter returns a limiter holding at most max entries (<=0 selects
// DefaultRateLimiterEntries).
func NewRateLimiter(max int, now func() time.Time) *RateLimiter {
	if max <= 0 {
		max = DefaultRateLimiterEntries
	}
	if now == nil {
		now = time.Now
	}
	return &RateLimiter{now: now, entries: make(map[string]*bucket), max: max}
}

// Allow consumes one request from the key's bucket. It returns false and the
// wait until the next token when the bucket is empty. perMinute <= 0 disables
// the limit (the caller decides the default).
func (l *RateLimiter) Allow(key string, perMinute int) (bool, time.Duration) {
	if l == nil || perMinute <= 0 {
		return true, 0
	}
	now := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()
	b, ok := l.entries[key]
	if !ok {
		if len(l.entries) >= l.max {
			l.evictLocked()
		}
		b = &bucket{tokens: float64(perMinute), last: now}
		l.entries[key] = b
	}
	// Refill: capacity is one minute's allowance, i.e. perMinute tokens.
	cap := float64(perMinute)
	refill := float64(perMinute) / 60.0
	if elapsed := now.Sub(b.last).Seconds(); elapsed > 0 {
		b.tokens += elapsed * refill
		if b.tokens > cap {
			b.tokens = cap
		}
		b.last = now
	}
	if b.tokens >= 1 {
		b.tokens--
		return true, 0
	}
	wait := time.Duration((1 - b.tokens) / refill * float64(time.Second))
	if wait < time.Second {
		wait = time.Second
	}
	return false, wait
}

// Len reports the number of tracked tokens (tests and metrics).
func (l *RateLimiter) Len() int {
	if l == nil {
		return 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.entries)
}

// evictLocked drops the least recently used entry. Callers hold l.mu.
func (l *RateLimiter) evictLocked() {
	var oldestKey string
	var oldest time.Time
	for k, b := range l.entries {
		if oldestKey == "" || b.last.Before(oldest) {
			oldestKey, oldest = k, b.last
		}
	}
	if oldestKey != "" {
		delete(l.entries, oldestKey)
	}
}
