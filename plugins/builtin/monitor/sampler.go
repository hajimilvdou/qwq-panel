// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"

	metricsv1 "github.com/qwq-panel/qwq/sdk/gen/qwq/capability/metrics/v1"
	"github.com/qwq-panel/qwq/sdk/pluginsdk"
	"google.golang.org/protobuf/proto"
)

const (
	alertConsecutiveSamples = 3
	alertDebounceWindow     = 15 * time.Minute
	coarseHistoryMaxAge     = time.Hour
	coarseHistoryKVKey      = "history/coarse"
)

// Source 是宿主能力客户端与测试序列之间的唯一采集接缝。
type Source interface {
	Read(context.Context) (*metricsv1.MetricsSnapshot, error)
}

type metricAlertState struct {
	consecutive int
	lastFiredAt time.Time
}

type coarseHistorySnapshot struct {
	SavedAtUnixMs  int64    `json:"saved_at_unix_ms"`
	CoarseInterval int      `json:"coarse_interval_ms"`
	DiskMounts     []string `json:"disk_mounts"`
	NetInterfaces  []string `json:"net_interfaces"`
	Points         []Point  `json:"points"`
}

type sampler struct {
	mu                     sync.Mutex
	source                 Source
	publishAlert           func(context.Context, pluginsdk.EventDraft) error
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
	alerts                 map[string]*metricAlertState
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
	return &sampler{
		source:     source,
		cfg:        cfg,
		resetEpoch: epoch,
		now:        time.Now,
		fine:       newRing(cfg.FinePoints),
		coarse:     newRing(cfg.CoarsePoints),
		alerts:     make(map[string]*metricAlertState),
	}, nil
}

func (s *sampler) diskMounts() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.cfg.DiskMounts)
}

func (s *sampler) exportCoarseSnapshot(now time.Time) coarseHistorySnapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	pts := s.coarse.latest(s.cfg.CoarsePoints)
	if s.aggregate.count > 0 {
		pts = append(pts, s.aggregate.point())
		if len(pts) > s.cfg.CoarsePoints {
			pts = pts[len(pts)-s.cfg.CoarsePoints:]
		}
	}
	return coarseHistorySnapshot{
		SavedAtUnixMs:  now.UnixMilli(),
		CoarseInterval: s.cfg.CoarseInterval,
		DiskMounts:     slices.Clone(s.cfg.DiskMounts),
		NetInterfaces:  slices.Clone(s.cfg.NetInterfaces),
		Points:         pts,
	}
}

func (s *sampler) restoreCoarseSnapshot(snap coarseHistorySnapshot, now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if snap.CoarseInterval != s.cfg.CoarseInterval ||
		!slices.Equal(snap.DiskMounts, s.cfg.DiskMounts) ||
		!slices.Equal(snap.NetInterfaces, s.cfg.NetInterfaces) {
		return false
	}
	if snap.SavedAtUnixMs <= 0 || len(snap.Points) == 0 {
		return false
	}
	elapsedMs := now.UnixMilli() - snap.SavedAtUnixMs
	if elapsedMs < 0 || elapsedMs >= coarseHistoryMaxAge.Milliseconds() {
		return false
	}
	ring := newRing(s.cfg.CoarsePoints)
	var lastT int64
	restored := 0
	pts := snap.Points
	if len(pts) > s.cfg.CoarsePoints {
		pts = pts[len(pts)-s.cfg.CoarsePoints:]
	}
	for _, pt := range pts {
		if pt.T <= 0 || pt.T < lastT {
			continue
		}
		lastT = pt.T
		ring.add(pt)
		restored++
	}
	if restored == 0 {
		return false
	}
	s.coarse = ring
	return true
}

func (s *sampler) evaluateAlertsLocked(point Point, now time.Time) []pluginsdk.EventDraft {
	if s.alerts == nil {
		s.alerts = make(map[string]*metricAlertState)
	}
	checks := []struct {
		key   string
		label string
		val   *float64
		crit  float64
	}{
		{key: "cpu", label: "CPU 使用率", val: point.CPU, crit: s.cfg.Thresholds.CPU.Crit},
		{key: "mem", label: "内存使用率", val: point.Memory, crit: s.cfg.Thresholds.Memory.Crit},
		{key: "swap", label: "Swap 使用率", val: point.Swap, crit: s.cfg.Thresholds.Memory.Crit},
		{key: "disk", label: "磁盘使用率", val: point.Disk, crit: s.cfg.Thresholds.Disk.Crit},
	}
	var drafts []pluginsdk.EventDraft
	for _, chk := range checks {
		st := s.alerts[chk.key]
		if st == nil {
			st = &metricAlertState{}
			s.alerts[chk.key] = st
		}
		if chk.val == nil || *chk.val < chk.crit {
			st.consecutive = 0
			continue
		}
		st.consecutive++
		if st.consecutive < alertConsecutiveSamples {
			continue
		}
		if !st.lastFiredAt.IsZero() && now.Sub(st.lastFiredAt) < alertDebounceWindow {
			continue
		}
		st.lastFiredAt = now
		payload, err := json.Marshal(map[string]any{
			"source":    "monitor.basic",
			"severity":  "critical",
			"metric":    chk.key,
			"value":     *chk.val,
			"threshold": chk.crit,
			"title":     fmt.Sprintf("主机 %s 持续超载告警 (%.1f%%)", chk.label, *chk.val),
			"message":   fmt.Sprintf("指标 %s 连续 %d 次采样超过严重阈值 %.1f%%（当前 %.1f%%）。", chk.label, alertConsecutiveSamples, chk.crit, *chk.val),
			"dedup_key": "monitor.crit." + chk.key,
			"timestamp": now.UTC().Format(time.RFC3339),
		})
		if err != nil {
			continue
		}
		drafts = append(drafts, pluginsdk.EventDraft{
			Type:          "monitor.alert",
			SchemaVersion: "1",
			Subject:       "metrics/" + chk.key,
			Payload:       payload,
		})
	}
	return drafts
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
	s.sampling = false
	if generation != s.generation {
		s.mu.Unlock()
		return nil
	}
	if err != nil || current == nil || proto.Size(current) > 128<<10 {
		s.lastError = "宿主指标暂不可用"
		s.mu.Unlock()
		return errors.New("monitor: metrics sample unavailable")
	}
	if current.CollectedAtUnixMs <= 0 {
		s.lastError = "宿主采样时间未推进"
		s.mu.Unlock()
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
		s.mu.Unlock()
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
	alertDrafts := s.evaluateAlertsLocked(point, monoAt)
	publish := s.publishAlert
	s.mu.Unlock()

	if publish != nil && len(alertDrafts) > 0 {
		for _, draft := range alertDrafts {
			pctx, pcancel := context.WithTimeout(ctx, 2*time.Second)
			_ = publish(pctx, draft)
			pcancel()
		}
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
	sums      [13]float64
	valid     [13]int
	count     int
}

func (m *meanBucket) add(p Point) {
	m.t = p.T
	m.count++
	for index, value := range []*float64{
		p.CPU, p.CPUIOWait, p.Memory, p.Swap, p.SwapUsedMB,
		p.Disk, p.NetRX, p.NetTX, p.Load, p.Load5, p.Load15,
		p.DiskRead, p.DiskWrite,
	} {
		if value != nil {
			m.sums[index] += *value
			m.valid[index]++
		}
	}
}
func (m meanBucket) point() Point {
	values := make([]*float64, 13)
	for index := range values {
		if m.valid[index] > 0 {
			values[index] = number(m.sums[index] / float64(m.valid[index]))
		}
	}
	return Point{
		T:          m.t,
		CPU:        values[0],
		CPUIOWait:  values[1],
		Memory:     values[2],
		Swap:       values[3],
		SwapUsedMB: values[4],
		Disk:       values[5],
		NetRX:      values[6],
		NetTX:      values[7],
		Load:       values[8],
		Load5:      values[9],
		Load15:     values[10],
		DiskRead:   values[11],
		DiskWrite:  values[12],
	}
}
