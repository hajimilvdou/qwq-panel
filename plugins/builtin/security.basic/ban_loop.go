// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/netip"
	"slices"
	"strings"
	"time"

	banv1 "github.com/qwq-panel/qwq/sdk/gen/qwq/capability/ban/v1"
	firewallv1 "github.com/qwq-panel/qwq/sdk/gen/qwq/capability/firewall/v1"
	"github.com/qwq-panel/qwq/sdk/pluginsdk"
)

// ======================== 轻量增量防爆破巡检循环与 fail2ban 旁观共存 ========================

type banCursorState struct {
	Cursor    string `json:"cursor"`
	UpdatedAt string `json:"updated_at"`
}

func (i *instance) banScanInterval() time.Duration {
	if i.banIntervalOverride > 0 {
		return i.banIntervalOverride
	}
	sec := i.configSnapshot().BanScanIntervalSeconds
	if sec < 10 {
		sec = defaultBanScanInterval
	}
	return time.Duration(sec) * time.Second
}

func (i *instance) banLoop(ctx context.Context) {
	// 启动后立即巡检一次以填充首页微件缓存，随后按周期增量扫描。
	i.runBanCycle(ctx)
	for {
		timer := time.NewTimer(i.banScanInterval())
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
			i.runBanCycle(ctx)
		}
	}
}

func (i *instance) runBanCycle(ctx context.Context) {
	if ctx.Err() != nil {
		return
	}
	host := i.Host()
	if host == nil || host.Conn() == nil {
		return
	}

	// 第 1 步：探测共存管理器；若 fail2ban 活跃则切入只读旁观模式（ADR-0021），绝不重复下发封禁。
	fail2banActive, activeConflicts, err := i.detectCoexistingManagers(ctx, host)
	if err != nil {
		i.setBanError("管理器探测失败：" + err.Error())
		return
	}
	i.mu.Lock()
	i.fail2banObserver = fail2banActive
	i.activeConflicts = activeConflicts
	i.lastBanError = ""
	i.mu.Unlock()

	if fail2banActive {
		banCount := i.readBanCountBestEffort(ctx, host)
		i.persistOverview(ctx, host, banCount, true, activeConflicts)
		return
	}

	cfg := i.configSnapshot()
	if !cfg.BanEnabled {
		banCount := i.readBanCountBestEffort(ctx, host)
		i.persistOverview(ctx, host, banCount, false, activeConflicts)
		return
	}

	// 第 2 步：按 KV 持久化游标增量扫描 journald SSH 认证失败事件。
	cursor := i.loadBanCursor(ctx, host)
	sinceSec := cfg.BanWindowSeconds
	if sinceSec == 0 || sinceSec > maxBanWindowSeconds {
		sinceSec = defaultBanWindowSeconds
	}
	banRead, banReadMeta, err := banClientReadOnly(ctx, host)
	if err != nil {
		i.setBanError(err.Error())
		return
	}
	scanResp, err := banRead.ScanAuthFailures(ctx, &banv1.ScanAuthFailuresRequest{
		Context:      banReadMeta,
		Cursor:       cursor,
		SinceSeconds: sinceSec,
		Unit:         cfg.BanUnit,
	})
	if err != nil {
		i.setBanError("扫描认证日志失败")
		return
	}
	if err := protoError(scanResp.GetError()); err != nil {
		i.setBanError(err.Error())
		return
	}

	// 第 3 步：窗口内按源 IP 聚合失败次数并过滤白名单，提取达到阈值的攻击源。
	nowMs := i.nowTime().UnixMilli()
	candidates := i.aggregateCandidates(scanResp.GetFailures(), nowMs, cfg)

	// 第 4 步：有候选封禁源时读取当前集合，超 4096 上限前先按最早过期裁剪再下发 ApplyBans。
	activeCount := i.readBanCountBestEffort(ctx, host)
	if len(candidates) > 0 {
		appliedCount, applyErr := i.applyCandidateBans(ctx, host, candidates, cfg.BanTTLSeconds)
		if applyErr != nil {
			i.setBanError(applyErr.Error())
		} else {
			activeCount = appliedCount
			i.clearBannedBuckets(candidates)
		}
	}

	// 第 5 步：更新游标与首页安全概览缓存。
	if nextCur := strings.TrimSpace(scanResp.GetNextCursor()); nextCur != "" && nextCur != cursor {
		i.saveBanCursor(ctx, host, nextCur)
	}
	i.persistOverview(ctx, host, activeCount, false, activeConflicts)
}

func (i *instance) detectCoexistingManagers(ctx context.Context, host *pluginsdk.Host) (bool, []string, error) {
	client, meta, err := firewallClientReadOnly(ctx, host)
	if err != nil {
		return false, nil, err
	}
	resp, err := client.DetectManagers(ctx, &firewallv1.DetectManagersRequest{Context: meta})
	if err != nil {
		return false, nil, err
	}
	if err := protoError(resp.GetError()); err != nil {
		return false, nil, err
	}
	conflicts := make([]string, 0)
	fail2banActive := false
	for _, m := range resp.GetManagers() {
		if m == nil || !m.GetActive() {
			continue
		}
		if strings.EqualFold(m.GetKind(), "fail2ban") {
			fail2banActive = true
		} else {
			conflicts = append(conflicts, m.GetKind())
		}
	}
	slices.Sort(conflicts)
	return fail2banActive, conflicts, nil
}

func (i *instance) aggregateCandidates(failures []*banv1.AuthFailure, nowMs int64, cfg securityConfig) []string {
	cutoffMs := nowMs - int64(cfg.BanWindowSeconds)*1000

	i.mu.Lock()
	defer i.mu.Unlock()

	if i.failureBuckets == nil {
		i.failureBuckets = make(map[string][]failureRecord)
	}
	// 先清理超过时间窗的旧记录，保持低内存占用。
	for ip, records := range i.failureBuckets {
		kept := records[:0]
		for _, rec := range records {
			if rec.OccurredAt >= cutoffMs {
				kept = append(kept, rec)
			}
		}
		if len(kept) == 0 {
			delete(i.failureBuckets, ip)
		} else {
			i.failureBuckets[ip] = kept
		}
	}

	for _, f := range failures {
		if f == nil || f.GetCount() == 0 {
			continue
		}
		addr, err := parseStrictIP(f.GetIp())
		if err != nil || isWhitelisted(addr, cfg.WhitelistPrefixes) {
			continue
		}
		occurredAt := f.GetOccurredAt()
		if occurredAt <= 0 {
			occurredAt = nowMs
		}
		if occurredAt < cutoffMs {
			continue
		}
		key := addr.String()
		if _, exists := i.failureBuckets[key]; !exists && len(i.failureBuckets) >= maxFailureBucketIPs {
			continue
		}
		i.failureBuckets[key] = append(i.failureBuckets[key], failureRecord{
			OccurredAt: occurredAt,
			Count:      f.GetCount(),
		})
	}

	candidates := make([]string, 0)
	for ip, records := range i.failureBuckets {
		var total uint64
		for _, rec := range records {
			total += uint64(rec.Count)
		}
		if total >= uint64(cfg.BanThreshold) {
			candidates = append(candidates, ip)
		}
	}
	slices.Sort(candidates)
	return candidates
}

func (i *instance) applyCandidateBans(ctx context.Context, host *pluginsdk.Host, candidates []string, ttlSec uint32) (int, error) {
	banRead, banReadMeta, err := banClientReadOnly(ctx, host)
	if err != nil {
		return 0, err
	}
	listResp, err := banRead.ListBans(ctx, &banv1.ListBansRequest{Context: banReadMeta})
	if err != nil {
		return 0, err
	}
	if err := protoError(listResp.GetError()); err != nil {
		return 0, err
	}

	existing := listResp.GetBans()
	existingSet := make(map[string]struct{}, len(existing))
	for _, b := range existing {
		if b != nil {
			existingSet[b.GetIp()] = struct{}{}
		}
	}
	toAdd := make([]*banv1.BanEntry, 0, len(candidates))
	for _, ip := range candidates {
		if _, already := existingSet[ip]; already {
			continue
		}
		toAdd = append(toAdd, &banv1.BanEntry{Ip: ip, TtlSeconds: ttlSec})
	}
	if len(toAdd) == 0 {
		return len(existing), nil
	}

	banWrite, banWriteMeta, err := banClientWrite(ctx, host)
	if err != nil {
		return len(existing), err
	}
	revision := listResp.GetRevision()

	// 超出 4096 集合容量上限前，按最早过期顺序主动淘汰旧条目。
	if overflow := len(existing) + len(toAdd) - maxBanEntries; overflow > 0 {
		sorted := append([]*banv1.ActiveBan(nil), existing...)
		slices.SortFunc(sorted, func(a, b *banv1.ActiveBan) int {
			if a.GetExpiresAt() < b.GetExpiresAt() {
				return -1
			}
			if a.GetExpiresAt() > b.GetExpiresAt() {
				return 1
			}
			return strings.Compare(a.GetIp(), b.GetIp())
		})
		for idx := 0; idx < overflow && idx < len(sorted); idx++ {
			victim := sorted[idx]
			if victim == nil || victim.GetIp() == "" {
				continue
			}
			rmResp, err := banWrite.RemoveBan(ctx, &banv1.RemoveBanRequest{
				Context:          banWriteMeta,
				Ip:               victim.GetIp(),
				ExpectedRevision: revision,
			})
			if err != nil {
				return len(existing), err
			}
			if err := protoError(rmResp.GetError()); err != nil {
				return len(existing), err
			}
			if rmResp.GetRevision() != "" {
				revision = rmResp.GetRevision()
			}
		}
	}

	if len(toAdd) > maxBanEntries {
		toAdd = toAdd[:maxBanEntries]
	}
	applyResp, err := banWrite.ApplyBans(ctx, &banv1.ApplyBansRequest{
		Context:          banWriteMeta,
		Entries:          toAdd,
		ExpectedRevision: revision,
	})
	if err != nil {
		return len(existing), err
	}
	if err := protoError(applyResp.GetError()); err != nil {
		return len(existing), err
	}
	return int(applyResp.GetActiveCount()), nil
}

func (i *instance) clearBannedBuckets(ips []string) {
	i.mu.Lock()
	defer i.mu.Unlock()
	for _, ip := range ips {
		delete(i.failureBuckets, ip)
	}
}

func (i *instance) readBanCountBestEffort(ctx context.Context, host *pluginsdk.Host) int {
	banRead, banReadMeta, err := banClientReadOnly(ctx, host)
	if err != nil {
		i.mu.RLock()
		defer i.mu.RUnlock()
		return i.activeBanCount
	}
	resp, err := banRead.ListBans(ctx, &banv1.ListBansRequest{Context: banReadMeta})
	if err != nil || resp.GetError() != nil {
		i.mu.RLock()
		defer i.mu.RUnlock()
		return i.activeBanCount
	}
	return len(resp.GetBans())
}

func (i *instance) loadBanCursor(ctx context.Context, host *pluginsdk.Host) string {
	raw, _, found, err := host.GetState(ctx, kvKeyBanCursor)
	if err != nil || !found || len(bytes.TrimSpace(raw)) == 0 {
		return ""
	}
	var st banCursorState
	if json.Unmarshal(raw, &st) != nil {
		return ""
	}
	return st.Cursor
}

func (i *instance) saveBanCursor(ctx context.Context, host *pluginsdk.Host, cursor string) {
	raw, err := json.Marshal(banCursorState{
		Cursor:    cursor,
		UpdatedAt: i.nowTime().UTC().Format(time.RFC3339),
	})
	if err != nil {
		return
	}
	_, _ = host.PutState(ctx, kvKeyBanCursor, raw, pluginsdk.PutOption{})
}

func (i *instance) setBanError(msg string) {
	i.mu.Lock()
	i.lastBanError = msg
	i.mu.Unlock()
}

func (i *instance) recordActiveBanCount(ctx context.Context, host *pluginsdk.Host, count int) {
	i.mu.RLock()
	observer := i.fail2banObserver
	conflicts := append([]string(nil), i.activeConflicts...)
	i.mu.RUnlock()
	i.persistOverview(ctx, host, count, observer, conflicts)
}

func (i *instance) setOverviewSagaPending(ctx context.Context, host *pluginsdk.Host, pending bool) {
	i.mu.RLock()
	count := i.activeBanCount
	observer := i.fail2banObserver
	conflicts := append([]string(nil), i.activeConflicts...)
	spark := append([]float64(nil), i.spark...)
	i.mu.RUnlock()
	if conflicts == nil {
		conflicts = make([]string, 0)
	}
	if spark == nil {
		spark = make([]float64, 0)
	}
	cache := overviewCache{
		ActiveBanCount:   count,
		Fail2banObserver: observer,
		PortSagaPending:  pending,
		ActiveConflicts:  conflicts,
		Spark:            spark,
		UpdatedAt:        i.nowTime().UTC().Format(time.RFC3339),
	}
	if raw, err := json.Marshal(cache); err == nil {
		_, _ = host.PutState(ctx, kvKeyOverviewCache, raw, pluginsdk.PutOption{})
	}
}

func (i *instance) persistOverview(ctx context.Context, host *pluginsdk.Host, activeCount int, observer bool, conflicts []string) {
	sagaPending := false
	if _, _, found, err := host.GetState(ctx, kvKeyPortSaga); err == nil {
		sagaPending = found
	}
	i.mu.Lock()
	i.activeBanCount = activeCount
	i.fail2banObserver = observer
	i.activeConflicts = append([]string(nil), conflicts...)
	i.spark = append(i.spark, float64(activeCount))
	if len(i.spark) > 12 {
		i.spark = append([]float64(nil), i.spark[len(i.spark)-12:]...)
	}
	sparkCopy := append([]float64(nil), i.spark...)
	i.mu.Unlock()

	if conflicts == nil {
		conflicts = make([]string, 0)
	}
	cache := overviewCache{
		ActiveBanCount:   activeCount,
		Fail2banObserver: observer,
		PortSagaPending:  sagaPending,
		ActiveConflicts:  conflicts,
		Spark:            sparkCopy,
		UpdatedAt:        i.nowTime().UTC().Format(time.RFC3339),
	}
	if raw, err := json.Marshal(cache); err == nil {
		_, _ = host.PutState(ctx, kvKeyOverviewCache, raw, pluginsdk.PutOption{})
	}
}

func isWhitelisted(addr netip.Addr, prefixes []netip.Prefix) bool {
	for _, p := range prefixes {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}
