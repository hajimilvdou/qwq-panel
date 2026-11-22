// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"slices"
	"sync"
	"time"

	metricsv1 "github.com/qwq-panel/qwq/sdk/gen/qwq/capability/metrics/v1"
	"google.golang.org/protobuf/proto"
)

// Source 是宿主能力客户端与测试序列之间的唯一采集接缝。
type Source interface {
	Read(context.Context) (*metricsv1.MetricsSnapshot, error)
}
type sampler struct {
	mu                     sync.Mutex
	source                 Source
	cfg                    config
	generation, resetEpoch uint64
	previous               *metricsv1.MetricsSnapshot
	previousAt             time.Time
	now                    func() time.Time
	fine, coarse           pointRing
	aggregate              meanBucket
	sampling               bool
	lastError              string
	cores                  uint32
	uptime                 uint64
}

func newSampler(cfg config, source Source) (*sampler, error) {
	// -----------------------------------------------------------------------
	// 进程重建不能把历史代次重新从 1 计数。用独立随机种子区分实例生命周期，
	// 进程内仍递增；52 位种子给增量留出空间，JSON 保持 JavaScript 安全整数。
	// -----------------------------------------------------------------------
	var seed [8]byte
	if _, err := rand.Read(seed[:]); err != nil {
		return nil, errors.New("monitor: cannot create a history epoch")
	}
	epoch := binary.LittleEndian.Uint64(seed[:]) & ((1 << 52) - 1)
	return &sampler{source: source, cfg: cfg, resetEpoch: epoch, now: time.Now, fine: newRing(cfg.FinePoints), coarse: newRing(cfg.CoarsePoints)}, nil
}

func (s *sampler) configure(next config) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	reset := s.cfg.FinePoints != next.FinePoints || s.cfg.CoarsePoints != next.CoarsePoints || s.cfg.CoarseInterval != next.CoarseInterval || !slices.Equal(s.cfg.NetInterfaces, next.NetInterfaces) || !slices.Equal(s.cfg.DiskMounts, next.DiskMounts)
	s.cfg = next
	s.generation++
	if reset {
		s.resetHistoryLocked()
	}
	return reset
}

func (s *sampler) reset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.resetHistoryLocked()
	s.lastError = "等待宿主采样"
	s.generation++
}

// resetHistoryLocked 共用历史和计数基线重建；调用方已持有采样锁。
func (s *sampler) resetHistoryLocked() {
	s.fine, s.coarse = newRing(s.cfg.FinePoints), newRing(s.cfg.CoarsePoints)
	s.previous, s.previousAt = nil, time.Time{}
	s.aggregate = meanBucket{}
	s.resetEpoch++
}
func (s *sampler) pause() {
	s.mu.Lock()
	s.lastError = "监控采样已暂停"
	s.generation++
	s.mu.Unlock()
}

func (s *sampler) collect(ctx context.Context) error {
	s.mu.Lock()
	if s.sampling {
		s.mu.Unlock()
		return nil
	}
	if s.source == nil {
		s.lastError = "宿主指标服务未接入"
		s.mu.Unlock()
		return errors.New("monitor: metrics source unavailable")
	}
	s.sampling = true
	generation, cfg, previous, previousAt := s.generation, s.cfg, s.previous, s.previousAt
	s.mu.Unlock()
	deadline, cancel := context.WithTimeout(ctx, 2*time.Second)
	current, err := s.source.Read(deadline)
	cancel()
	monoAt := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sampling = false
	if generation != s.generation {
		return nil
	}
	if err != nil || current == nil || proto.Size(current) > 128<<10 {
		s.lastError = "宿主指标暂不可用"
		return errors.New("monitor: metrics sample unavailable")
	}
	if current.CollectedAtUnixMs <= 0 {
		s.lastError = "宿主采样时间未推进"
		return errors.New("monitor: metrics time is stale")
	}
	current = proto.Clone(current).(*metricsv1.MetricsSnapshot)
	if previous != nil && current.CollectedAtUnixMs <= previous.CollectedAtUnixMs {
		if current.CollectedAtUnixMs < previous.CollectedAtUnixMs {
			// 旧历史已含未来墙钟，重建 epoch 保持时间顺序，避免跨回拨绘制连续线。
			s.resetHistoryLocked()
		}
		s.previous, s.previousAt = current, monoAt
		s.aggregate = meanBucket{}
		s.lastError = "宿主采样时间未推进，已重新建立计数基线"
		return errors.New("monitor: metrics time is stale")
	}
	point := derive(current, previous, cfg, monoAt.Sub(previousAt).Seconds())
	s.fine.add(point)
	bucket := point.T / int64(cfg.CoarseInterval)
	if s.aggregate.count != 0 && bucket != s.aggregate.bucket {
		s.coarse.add(s.aggregate.point())
		s.aggregate = meanBucket{}
	}
	s.aggregate.bucket = bucket
	s.aggregate.add(point)
	s.previous, s.previousAt, s.lastError, s.uptime = current, monoAt, "", current.UptimeSeconds
	if current.Cpu != nil {
		s.cores = current.Cpu.CoreCount
	}
	return nil
}

func (s *sampler) loop(ctx context.Context) {
	for {
		if ctx.Err() != nil {
			return
		}
		_ = s.collect(ctx)
		s.mu.Lock()
		interval := time.Duration(s.cfg.SampleInterval) * time.Millisecond
		s.mu.Unlock()
		timer := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}

type meanBucket struct {
	bucket, t int64
	sums      [8]float64
	valid     [8]int
	count     int
}

func (m *meanBucket) add(p Point) {
	m.t = p.T
	m.count++
	for index, value := range []*float64{p.CPU, p.Memory, p.Disk, p.NetRX, p.NetTX, p.Load, p.DiskRead, p.DiskWrite} {
		if value != nil {
			m.sums[index] += *value
			m.valid[index]++
		}
	}
}
func (m meanBucket) point() Point {
	values := make([]*float64, 8)
	for index := range values {
		if m.valid[index] > 0 {
			values[index] = number(m.sums[index] / float64(m.valid[index]))
		}
	}
	return Point{T: m.t, CPU: values[0], Memory: values[1], Disk: values[2], NetRX: values[3], NetTX: values[4], Load: values[5], DiskRead: values[6], DiskWrite: values[7]}
}
