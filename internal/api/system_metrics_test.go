// SPDX-License-Identifier: AGPL-3.0-only

package api

import (
	"testing"
	"time"
)

func TestParseMetricsRange(t *testing.T) {
	cases := []struct {
		in      string
		wantRng string
		wantDur time.Duration
		wantOK  bool
	}{
		{"", "15m", 15 * time.Minute, true},
		{"5m", "5m", 5 * time.Minute, true},
		{"15m", "15m", 15 * time.Minute, true},
		{"1h", "1h", time.Hour, true},
		{"6h", "6h", 6 * time.Hour, true},
		{"24h", "24h", 24 * time.Hour, true},
		{"7d", "", 0, false},
		{"invalid", "", 0, false},
	}
	for _, tc := range cases {
		gotRng, gotDur, _, gotOK := parseMetricsRange(tc.in)
		if gotOK != tc.wantOK || gotRng != tc.wantRng || gotDur != tc.wantDur {
			t.Errorf("parseMetricsRange(%q) = (%q, %v, %v), want (%q, %v, %v)",
				tc.in, gotRng, gotDur, gotOK, tc.wantRng, tc.wantDur, tc.wantOK)
		}
	}
}

func TestHostMetricsMultiResolutionRings(t *testing.T) {
	tr := newHostMetricsTracker()
	base := time.Date(2026, 11, 25, 10, 0, 0, 0, time.UTC)

	// Record 4 hours of 5-second points (2880 points) to exercise fine ring capping,
	// 1-minute coarse rollup, and downsampling monotonicity.
	for i := 0; i < 2880; i++ {
		ts := base.Add(time.Duration(i) * 5 * time.Second).Unix()
		tr.recordPointLocked(systemMetricsPointDTO{
			Ts:    ts,
			CPU:   float64(i%50) + 10,
			Mem:   42.5,
			RxBps: float64(1000 + i*10),
			TxBps: float64(500 + i*5),
		})
	}
	now := base.Add(2880 * 5 * time.Second)

	if len(tr.finePoints) != hostMetricsFineCap {
		t.Fatalf("finePoints len = %d, want %d", len(tr.finePoints), hostMetricsFineCap)
	}
	if len(tr.coarsePoints) < 230 {
		t.Fatalf("coarsePoints len = %d, expected >= 230 one-minute buckets", len(tr.coarsePoints))
	}

	for _, rng := range []string{"5m", "15m", "1h", "6h", "24h"} {
		pts := tr.pointsForRangeLocked(rng, now)
		if len(pts) < 2 {
			t.Fatalf("range %s returned too few points: %d", rng, len(pts))
		}
		if len(pts) > hostMetricsMaxReturnPts {
			t.Fatalf("range %s returned %d points, exceeds cap %d", rng, len(pts), hostMetricsMaxReturnPts)
		}
		for i := 1; i < len(pts); i++ {
			if pts[i].Ts <= pts[i-1].Ts {
				t.Fatalf("range %s points not strictly increasing at %d: %d <= %d", rng, i, pts[i].Ts, pts[i-1].Ts)
			}
		}
	}
}
