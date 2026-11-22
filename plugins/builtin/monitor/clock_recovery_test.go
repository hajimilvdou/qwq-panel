// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"testing"
	"time"

	metricsv1 "github.com/qwq-panel/qwq/sdk/gen/qwq/capability/metrics/v1"
)

// ======================== 宿主墙钟调整不能卡死采样或改变实际计数速率 ========================

func TestSamplerClockRollbackRebasesBeforeNextSample(t *testing.T) {
	source := &sequenceSource{values: []*metricsv1.MetricsSnapshot{
		sample(10000, 0, 0, 0, 0),
		sample(5000, 25, 75, 1000, 2),
		sample(6000, 50, 150, 2000, 4),
	}}
	s := mustSampler(t, defaultConfig(), source)
	if err := s.collect(t.Context()); err != nil {
		t.Fatal(err)
	}
	epoch := s.resetEpoch
	if err := s.collect(t.Context()); err == nil || s.lastError == "" {
		t.Fatal("回拨未保留明确的采样断点")
	}
	if s.previous == nil || s.previous.CollectedAtUnixMs != 5000 {
		t.Fatal("回拨后仍保留未来时间基线，后续采样将一直被拒绝")
	}
	if s.fine.count != 0 || s.coarse.count != 0 || s.resetEpoch != epoch+1 {
		t.Fatal("回拨后保留了未来历史或未更新断点代次")
	}
	if err := s.collect(t.Context()); err != nil || s.lastError != "" {
		t.Fatal("墙钟重新推进后未立即恢复采样")
	}
	point := s.fine.latest(1)[0]
	if point.T != 6000 || point.NetRX == nil || point.CPU == nil {
		t.Fatal("恢复样本未使用回拨后的当前计数基线")
	}
}

func TestSamplerRepeatedTimestampRebasesCounters(t *testing.T) {
	source := &sequenceSource{values: []*metricsv1.MetricsSnapshot{
		sample(1000, 0, 0, 0, 0),
		sample(1000, 90, 10, 1000, 2),
		sample(2000, 100, 100, 2000, 4),
	}}
	s := mustSampler(t, defaultConfig(), source)
	if err := s.collect(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := s.collect(t.Context()); err == nil {
		t.Fatal("重复时间戳被伪造为新历史点")
	}
	if err := s.collect(t.Context()); err != nil {
		t.Fatal(err)
	}
	expectMetric(t, s.fine.latest(1)[0].CPU, 10)
}

type pacedMetricsSource struct{ *sequenceSource }

func (s pacedMetricsSource) Read(ctx context.Context) (*metricsv1.MetricsSnapshot, error) {
	timer := time.NewTimer(10 * time.Millisecond)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-timer.C:
		return s.sequenceSource.Read(ctx)
	}
}

func TestSamplerClockForwardUsesElapsedTimeForRates(t *testing.T) {
	source := pacedMetricsSource{&sequenceSource{values: []*metricsv1.MetricsSnapshot{
		sample(1000, 0, 0, 0, 0),
		sample(3601000, 25, 75, 1000, 2),
	}}}
	s := mustSampler(t, defaultConfig(), source)
	for range 2 {
		if err := s.collect(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	point := s.fine.latest(1)[0]
	// 两次读取只隔短时单调间隔；不能把 NTP 跳过的一小时计入网络/磁盘速率。
	if point.NetRX == nil || *point.NetRX < 100 || point.DiskRead == nil || *point.DiskRead < 100 {
		t.Fatal("速率分母仍使用可跳变的宿主墙钟")
	}
}
