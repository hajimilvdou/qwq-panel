// SPDX-License-Identifier: AGPL-3.0-only

package gateway_test

import (
	"fmt"
	"testing"

	"github.com/qwq-panel/qwq/internal/gateway"
)

// TestTokenBucketsEvictionIsLRU checks that a full limiter evicts exactly the
// least recently used key. The clock is frozen, so every bucket carries the
// same timestamp and only the order of the calls tells the keys apart.
func TestTokenBucketsEvictionIsLRU(t *testing.T) {
	const keys = 512
	lim := gateway.NewTokenBuckets(frozenClock(), gateway.TokenBucketConfig{Rate: 1, Burst: 1, MaxKeys: keys})
	key := func(i int) string { return fmt.Sprintf("key-%03d", i) }
	// spend reports whether k still had its token. With a burst of one and no
	// refill, a tracked key is refused after its first request, while an
	// evicted key starts over with a full bucket.
	spend := func(k string) bool {
		ok, _ := lim.Allow(k)
		return ok
	}

	for i := 0; i < keys; i++ {
		if !spend(key(i)) {
			t.Fatalf("first request of %s refused", key(i))
		}
	}
	// Touch every key but key-000, which becomes the least recently used.
	for i := 1; i < keys; i++ {
		if spend(key(i)) {
			t.Fatalf("%s allowed twice with a burst of 1", key(i))
		}
	}

	// A new key evicts exactly one bucket: the least recently used one.
	if !spend("key-new") {
		t.Fatal("request of a new key refused")
	}
	if got := lim.Len(); got != keys {
		t.Fatalf("tracked keys = %d, want %d", got, keys)
	}
	for i := 1; i < keys; i++ {
		if spend(key(i)) {
			t.Fatalf("%s was evicted instead of the least recently used key", key(i))
		}
	}
	if !spend(key(0)) {
		t.Fatalf("%s is still tracked: the least recently used key was not evicted", key(0))
	}
	// Re-adding key-000 evicted key-new: every other key was touched after
	// key-new arrived, so it had become the least recently used.
	if !spend("key-new") {
		t.Fatal("key-new is still tracked: the eviction order does not follow recency")
	}
}
