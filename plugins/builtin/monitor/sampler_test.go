// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"sync"
	"testing"
	"time"

	metricsv1 "github.com/qwq-panel/qwq/sdk/gen/qwq/capability/metrics/v1"
)

type sequenceSource struct {
	mu     sync.Mutex
	values []*metricsv1.MetricsSnapshot
}

func mustSampler(t *testing.T, cfg config, source Source) *sampler {
	t.Helper()
	s, err := newSampler(cfg, source)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// TestSamplerEpochSurvivesLifecycleComparison 代次在实例重建后必须可区分。
func TestSamplerEpochSurvivesLifecycleComparison(t *testing.T) {
	first := mustSampler(t, defaultConfig(), nil)
	second := mustSampler(t, defaultConfig(), nil)
	first.reset()
	second.reset()
	if first.resetEpoch == second.resetEpoch {
		t.Fatal("new samplers reused a history epoch")
	}
	before := first.resetEpoch
	first.reset()
	if first.resetEpoch != before+1 || first.resetEpoch > (1<<53)-1 {
		t.Fatal("epoch did not advance as a safe JSON integer")
	}
	thresholds := defaultConfig()
	thresholds.Thresholds.CPU.Warn = 60
	before = first.resetEpoch
	if first.configure(thresholds) || first.resetEpoch != before {
		t.Fatal("threshold-only change altered the history epoch")
	}
}

func (s *sequenceSource) Read(context.Context) (*metricsv1.MetricsSnapshot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	value := s.values[0]
	s.values = s.values[1:]
	return value, nil
}

func TestSamplerCoarseMeanAndConfigReset(t *testing.T) {
	source := &sequenceSource{values: []*metricsv1.MetricsSnapshot{sample(1000, 0, 0, 0, 0), sample(2000, 25, 75, 1000, 2), sample(11000, 50, 150, 2000, 4)}}
	s := mustSampler(t, defaultConfig(), source)
	for range 3 {
		if err := s.collect(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	if s.fine.count != 3 || s.coarse.count != 1 {
		t.Fatal("fine/coarse history did not aggregate")
	}
	expectMetric(t, s.coarse.latest(1)[0].CPU, 25)
	copy := s.fine.latest(1)
	*copy[0].CPU = 999
	expectMetric(t, s.fine.latest(1)[0].CPU, 25)
	config := defaultConfig()
	config.Thresholds.CPU.Warn = 60
	if s.configure(config) || s.fine.count != 3 {
		t.Fatal("threshold-only change discarded history")
	}
	config.FinePoints = 60
	if !s.configure(config) || s.fine.count != 0 || s.previous != nil || s.resetEpoch == 0 {
		t.Fatal("history resize did not reset safely")
	}
}

func TestSamplerStaleSampleAndPauseAreExplicit(t *testing.T) {
	source := &sequenceSource{values: []*metricsv1.MetricsSnapshot{sample(1000, 0, 0, 0, 0), sample(1000, 25, 75, 1000, 2)}}
	s := mustSampler(t, defaultConfig(), source)
	if err := s.collect(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := s.collect(t.Context()); err == nil || s.fine.count != 1 || s.lastError == "" {
		t.Fatal("stale sample was stored or hidden")
	}
	s.pause()
	if s.lastError == "" {
		t.Fatal("paused sampler claimed ready")
	}
	s.reset()
	if s.previous != nil || s.fine.count != 0 {
		t.Fatal("activation did not reset volatile history")
	}
}

func TestWidgetPayloadMatchesCurrentShellContract(t *testing.T) {
	source := &sequenceSource{values: []*metricsv1.MetricsSnapshot{sample(1000, 0, 0, 0, 0), sample(2000, 25, 75, 1000, 2)}}
	s := mustSampler(t, defaultConfig(), source)
	// 受控单调间隔固定为一秒；保留原 widget 速率与单位契约。
	at := time.Now()
	s.now = func() time.Time {
		at = at.Add(time.Second)
		return at
	}
	for range 2 {
		if err := s.collect(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	i := &instance{samples: s}
	stat, err := i.stat(t.Context(), "cpu")
	if err != nil || stat.Value != 25 || stat.Percent != 25 || stat.Level != "ok" || stat.Unit != "%" {
		t.Fatal("stat payload differs from shell contract")
	}
	series, err := i.series(t.Context(), "net")
	if err != nil || len(series.Series) != 2 || len(series.Series[0].Points) != 1 || series.Series[0].Points[0][0] != 2000 || series.Series[0].Points[0][1] != 0.008 {
		t.Fatal("series payload differs from shell contract or unit conversion")
	}
}
