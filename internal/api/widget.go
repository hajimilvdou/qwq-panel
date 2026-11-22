// SPDX-License-Identifier: AGPL-3.0-only

package api

import (
	"sync"
	"time"
)

// widgetReads enforces the refresh floor of an overview widget per principal and
// keeps at most one call in flight (GAPS gap 7). A card that refreshes every two
// seconds must not turn into a request storm when several tabs show the same
// overview, and a slow plugin must not accumulate concurrent reads.
//
// The key is principal + action: a widget is bound to one read operation, so the
// operation identifies the card without the client having to name it.
type widgetReads struct {
	mu       sync.Mutex
	last     map[string]time.Time
	inflight map[string]struct{}
}

func newWidgetReads() *widgetReads {
	return &widgetReads{last: map[string]time.Time{}, inflight: map[string]struct{}{}}
}

// widgetReadsMax bounds the remembered keys. Principals are real accounts, so the
// map is small; the bound only protects a host with very many of them, and an
// entry older than widgetReadsTTL cannot throttle anything any more.
const (
	widgetReadsMax = 4096
	widgetReadsTTL = time.Hour
)

// begin reserves one call. It returns the wait when the floor has not elapsed or
// another call of the same key is in flight; a reserved call must be ended.
func (w *widgetReads) begin(key string, now time.Time, floor time.Duration) (time.Duration, bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if _, busy := w.inflight[key]; busy {
		return floor, false
	}
	if last, ok := w.last[key]; ok {
		if wait := floor - now.Sub(last); wait > 0 {
			return wait, false
		}
	}
	if len(w.last) >= widgetReadsMax {
		for k, at := range w.last {
			if now.Sub(at) > widgetReadsTTL {
				delete(w.last, k)
			}
		}
	}
	w.inflight[key] = struct{}{}
	w.last[key] = now
	return 0, true
}

// end releases the in-flight reservation of a call.
func (w *widgetReads) end(key string) {
	w.mu.Lock()
	delete(w.inflight, key)
	w.mu.Unlock()
}
