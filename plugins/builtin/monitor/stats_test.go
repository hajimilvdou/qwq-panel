// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"math"
	"testing"

	metricsv1 "github.com/qwq-panel/qwq/sdk/gen/qwq/capability/metrics/v1"
)

func sample(at int64, user, idle, rx, sectors uint64) *metricsv1.MetricsSnapshot {
	return &metricsv1.MetricsSnapshot{CollectedAtUnixMs: at, Cpu: &metricsv1.Cpu{User: user, Idle: idle, CoreCount: 1}, Memory: &metricsv1.Memory{TotalBytes: 100, AvailableBytes: 40}, Disks: []*metricsv1.Disk{{Device: "vda", Mount: "/", TotalBytes: 100, UsedBytes: 80, ReadSectors: sectors, WriteSectors: sectors}}, Nets: []*metricsv1.NetIf{{Name: "eth0", RxBytes: rx, TxBytes: rx}, {Name: "lo", RxBytes: rx * 100, TxBytes: rx * 100}}, Load: &metricsv1.Load{Load1: 0.5}}
}
func expectMetric(t *testing.T, value *float64, want float64) {
	t.Helper()
	if value == nil || math.Abs(*value-want) > 1e-8 {
		t.Fatal("unexpected derived metric")
	}
}
func TestMetricsDerivationUsesRealCountersAndUnits(t *testing.T) {
	point := derive(sample(2000, 25, 75, 1000, 2), sample(1000, 0, 0, 0, 0), defaultConfig(), 1)
	expectMetric(t, point.CPU, 25)
	expectMetric(t, point.Memory, 60)
	expectMetric(t, point.Disk, 80)
	expectMetric(t, point.NetRX, 8000)
	expectMetric(t, point.DiskRead, 1024)
	expectMetric(t, point.Load, 0.5)
}
func TestFirstSampleAndCounterResetAreUnavailable(t *testing.T) {
	first := derive(sample(1000, 10, 90, 1000, 20), nil, defaultConfig(), 0)
	if first.CPU != nil || first.NetRX != nil || first.DiskRead != nil {
		t.Fatal("first sample advertised a rate")
	}
	expectMetric(t, first.Memory, 60)
	reset := derive(sample(2000, 1, 9, 1, 1), sample(1000, 10, 90, 1000, 20), defaultConfig(), 1)
	if reset.CPU != nil || reset.NetRX != nil || reset.DiskRead != nil {
		t.Fatal("reset counters produced a fake rate")
	}
	stale := derive(sample(1000, 20, 100, 1200, 30), sample(1000, 10, 90, 1000, 20), defaultConfig(), 1)
	if stale.CPU != nil || stale.NetRX != nil || stale.DiskRead != nil {
		t.Fatal("stale timestamp produced a rate")
	}
}
func TestDisappearingAndNewInterfacesDoNotFabricateAggregate(t *testing.T) {
	previous := sample(1000, 0, 0, 1000, 0)
	current := sample(2000, 10, 90, 1200, 2)
	current.Nets[0].Name = "eth1"
	point := derive(current, previous, defaultConfig(), 1)
	if point.NetRX != nil {
		t.Fatal("different interface identities produced an aggregate")
	}
	config := defaultConfig()
	config.NetInterfaces = []string{"missing"}
	if derive(current, previous, config, 1).NetRX != nil {
		t.Fatal("missing interface was advertised as zero")
	}
}
func TestRingIsBoundedOrderedAndReturnsCopies(t *testing.T) {
	ring := newRing(3)
	for n := range 5 {
		ring.add(Point{T: int64(n)})
	}
	points := ring.latest(3)
	if len(points) != 3 || points[0].T != 2 || points[2].T != 4 {
		t.Fatal("ring order or capacity is invalid")
	}
	points[0].T = 999
	if ring.latest(3)[0].T != 2 {
		t.Fatal("ring returned its mutable storage")
	}
}
func TestConfigRejectsUnknownAndUnsafeRanges(t *testing.T) {
	for _, raw := range []string{`{"fine_points":601}`, `{"sample_interval_ms":0}`, `{"unknown":1}`, `{"net_interfaces":["lo"]}`, `{"thresholds":{"cpu":{"warn":90,"crit":70}}}`} {
		if _, err := parseConfig([]byte(raw)); err == nil {
			t.Fatal("invalid monitoring configuration accepted")
		}
	}
	if _, err := parseConfig([]byte(`{}`)); err != nil {
		t.Fatal(err)
	}
}
