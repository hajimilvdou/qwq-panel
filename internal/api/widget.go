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
type cachedWidgetResp struct {
	body      []byte
	expiresAt time.Time
}

type widgetReads struct {
	mu       sync.Mutex
	last     map[string]time.Time
	inflight map[string]struct{}
	cache    map[string]cachedWidgetResp
}

func newWidgetReads() *widgetReads {
	return &widgetReads{
		last:     map[string]time.Time{},
		inflight: map[string]struct{}{},
		cache:    map[string]cachedWidgetResp{},
	}
}

// lookup returns a still-fresh cached successful 200 response for key so page
// navigation or plugin tab switches inside refresh_seconds render instantly
// instead of tripping HTTP 429 RATE_LIMITED.
func (w *widgetReads) lookup(key string, now time.Time) ([]byte, bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	ent, ok := w.cache[key]
	if !ok || !now.Before(ent.expiresAt) {
		return nil, false
	}
	return append([]byte(nil), ent.body...), true
}

// store caches a successful 200 response for floor so subsequent reads within
// the refresh window receive the cached snapshot cleanly.
func (w *widgetReads) store(key string, body []byte, now time.Time, floor time.Duration) {
	if len(body) == 0 || floor <= 0 {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if len(w.cache) >= widgetReadsMax {
		for k, ent := range w.cache {
			if !now.Before(ent.expiresAt) {
				delete(w.cache, k)
			}
		}
	}
	w.cache[key] = cachedWidgetResp{
		body:      append([]byte(nil), body...),
		expiresAt: now.Add(floor),
	}
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
