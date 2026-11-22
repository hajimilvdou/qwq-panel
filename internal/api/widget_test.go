// SPDX-License-Identifier: AGPL-3.0-only

package api

import (
	"testing"
	"time"
)

// TestWidgetReadsFloorAndSingleFlight: one call per principal and widget at a
// time, and never faster than the refresh floor (GAPS gap 7).
func TestWidgetReadsFloorAndSingleFlight(t *testing.T) {
	w := newWidgetReads()
	now := time.Now()
	const floor = 2 * time.Second
	if wait, ok := w.begin("k", now, floor); !ok || wait != 0 {
		t.Fatalf("first call = %v, %v", wait, ok)
	}
	if wait, ok := w.begin("k", now, floor); ok || wait != floor {
		t.Fatalf("concurrent call = %v, %v; want a wait of %v", wait, ok, floor)
	}
	w.end("k")
	if wait, ok := w.begin("k", now.Add(time.Second), floor); ok || wait != time.Second {
		t.Fatalf("early call = %v, %v; want a wait of 1s", wait, ok)
	}
	if _, ok := w.begin("k", now.Add(floor), floor); !ok {
		t.Fatal("call at the floor was refused")
	}
	w.end("k")
	if _, ok := w.begin("other", now, floor); !ok {
		t.Fatal("another principal was throttled by the first one")
	}
}
