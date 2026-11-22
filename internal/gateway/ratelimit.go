// SPDX-License-Identifier: AGPL-3.0-only

package gateway

import (
	"container/list"
	"sync"
	"time"

	"github.com/qwq-panel/qwq/internal/platform/clock"
)

// Limiter decides whether a request may proceed. Implementations must be safe
// for concurrent use and must not block: the gateway calls Allow on the request
// path.
type Limiter interface {
	// Allow reserves one request for key. When it refuses, it also reports how
	// long the caller should wait before retrying.
	Allow(key string) (ok bool, retryAfter time.Duration)
}

// Default limiter settings. internal/controller wires one TokenBuckets per
// limiter field of Config with them; they are exported so that a configuration
// section can start from the same values.
const (
	// DefaultRequestRate and DefaultRequestBurst size Config.RateLimit (per
	// principal after authentication). They are also the TokenBuckets defaults.
	DefaultRequestRate  = 20
	DefaultRequestBurst = 100
	// DefaultPreAuthRate and DefaultPreAuthBurst size Config.PreAuthLimit (per
	// client IP before authentication).
	DefaultPreAuthRate  = 10
	DefaultPreAuthBurst = 50
	// DefaultPublicWriteRate and DefaultPublicWriteBurst size
	// Config.PublicWriteLimit: ten unauthenticated writes per client IP, then
	// one every five seconds.
	DefaultPublicWriteRate  = 0.2
	DefaultPublicWriteBurst = 10
)

// TokenBucketConfig bounds a TokenBuckets limiter.
type TokenBucketConfig struct {
	// Rate is the sustained rate in requests per second (default
	// DefaultRequestRate).
	Rate float64
	// Burst is the bucket size (default DefaultRequestBurst).
	Burst float64
	// MaxKeys bounds the number of tracked keys (default 10000). Beyond it the
	// least recently used bucket is evicted, so memory stays fixed.
	MaxKeys int
}

// TokenBuckets is a bounded in-memory token bucket limiter, the default
// implementation of Limiter. It is deliberately small: the host runs on 1 GiB
// machines, so the table has a hard cap instead of growing with distinct
// callers, and eviction is O(1), so a caller rotating through fresh keys cannot
// turn that cap into a CPU cost.
type TokenBuckets struct {
	clock clock.Clock
	cfg   TokenBucketConfig

	mu      sync.Mutex
	buckets map[string]*list.Element // key -> element of lru
	lru     *list.List               // *bucketState values, most recently used first
}

type bucketState struct {
	key    string
	tokens float64
	last   time.Time // when tokens was last refilled
}

// NewTokenBuckets returns a limiter driven by clk.
func NewTokenBuckets(clk clock.Clock, cfg TokenBucketConfig) *TokenBuckets {
	if clk == nil {
		clk = clock.System{}
	}
	if cfg.Rate <= 0 {
		cfg.Rate = DefaultRequestRate
	}
	if cfg.Burst < 1 {
		cfg.Burst = DefaultRequestBurst
	}
	if cfg.MaxKeys <= 0 {
		cfg.MaxKeys = 10000
	}
	return &TokenBuckets{clock: clk, cfg: cfg, buckets: make(map[string]*list.Element), lru: list.New()}
}

// Allow implements Limiter.
func (t *TokenBuckets) Allow(key string) (bool, time.Duration) {
	now := t.clock.Now()

	t.mu.Lock()
	defer t.mu.Unlock()

	b := t.touchLocked(key, now)
	if elapsed := now.Sub(b.last).Seconds(); elapsed > 0 {
		b.tokens = min(t.cfg.Burst, b.tokens+elapsed*t.cfg.Rate)
		b.last = now
	}

	if b.tokens >= 1 {
		b.tokens--
		return true, 0
	}
	wait := time.Duration((1 - b.tokens) / t.cfg.Rate * float64(time.Second))
	if wait < time.Millisecond {
		wait = time.Millisecond
	}
	return false, wait
}

// Len returns the number of tracked keys (tests and `qwq doctor`).
func (t *TokenBuckets) Len() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.lru.Len()
}

// touchLocked returns the bucket of key and marks it as the most recently used.
// A new key starts with a full bucket; once the table is full it takes over the
// least recently used entry, recycling its memory. t.mu must be held.
func (t *TokenBuckets) touchLocked(key string, now time.Time) *bucketState {
	if el, ok := t.buckets[key]; ok {
		t.lru.MoveToFront(el)
		return el.Value.(*bucketState)
	}
	fresh := bucketState{key: key, tokens: t.cfg.Burst, last: now}
	if t.lru.Len() < t.cfg.MaxKeys {
		b := &fresh
		t.buckets[key] = t.lru.PushFront(b)
		return b
	}
	el := t.lru.Back()
	b := el.Value.(*bucketState)
	delete(t.buckets, b.key)
	*b = fresh
	t.lru.MoveToFront(el)
	t.buckets[key] = el
	return b
}
