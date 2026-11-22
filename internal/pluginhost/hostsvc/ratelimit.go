// SPDX-License-Identifier: AGPL-3.0-only

package hostsvc

import (
	"sync"
	"time"
)

// tokenBucket is a small token bucket with a fractional refill rate. It uses
// the injected clock so tests can move time without sleeping.
type tokenBucket struct {
	mu      sync.Mutex
	perSec  float64
	burst   float64
	tokens  float64
	last    time.Time
	started bool
}

// newTokenBucket returns a bucket that refills perMinute tokens per minute and
// holds at most burst tokens. burst must be positive.
func newTokenBucket(perMinute, burst int) *tokenBucket {
	return &tokenBucket{
		perSec: float64(perMinute) / 60,
		burst:  float64(max(1, burst)),
	}
}

// defaultBurst is the burst of a per-minute quota: a quarter minute of tokens
// (at least one), so a caller can spend a few calls at once but cannot save up
// a whole minute.
func defaultBurst(perMinute int) int { return max(1, perMinute/4) }

// allow takes one token. It reports false when the bucket is empty; a rejected
// call does not consume anything.
func (b *tokenBucket) allow(now time.Time) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.started {
		b.started = true
		b.last = now
		b.tokens = b.burst
	} else if elapsed := now.Sub(b.last).Seconds(); elapsed > 0 {
		b.tokens = min(b.burst, b.tokens+elapsed*b.perSec)
		b.last = now
	}
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}
