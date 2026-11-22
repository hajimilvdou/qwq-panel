// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

const maxCooldownKeys = 2048

// DispatchSummary 返回一次事件分发经过路由/静默/冷却与重试后的结果统计。
type DispatchSummary struct {
	EventID    string           `json:"event_id"`
	Matched    int              `json:"matched_rules"`
	Sent       int              `json:"sent"`
	Failed     int              `json:"failed"`
	Suppressed int              `json:"suppressed"`
	Deliveries []DeliveryRecord `json:"deliveries"`
}

type routerEngine struct {
	store        *store
	cfgMu        sync.RWMutex
	client       *http.Client
	allowPrivate bool
	now          func() time.Time
	retryBackoff []time.Duration

	coolMu   sync.Mutex
	cooldown map[string]time.Time
}

func (e *routerEngine) UpdateClient(client *http.Client, allowPrivate bool) {
	e.cfgMu.Lock()
	e.client = client
	e.allowPrivate = allowPrivate
	e.cfgMu.Unlock()
}

func (e *routerEngine) snapshotClient() (*http.Client, bool) {
	e.cfgMu.RLock()
	defer e.cfgMu.RUnlock()
	return e.client, e.allowPrivate
}

func newRouterEngine(st *store, client *http.Client, allowPrivate bool, nowFn func() time.Time) *routerEngine {
	if nowFn == nil {
		nowFn = time.Now
	}
	return &routerEngine{
		store:        st,
		client:       client,
		allowPrivate: allowPrivate,
		now:          nowFn,
		retryBackoff: []time.Duration{200 * time.Millisecond, 600 * time.Millisecond},
		cooldown:     make(map[string]time.Time),
	}
}

func severityRank(s string) int {
	switch s {
	case "critical":
		return 3
	case "warn":
		return 2
	default:
		return 1
	}
}

func matchSource(pattern, source string) bool {
	p := strings.TrimSpace(pattern)
	if p == "" || p == "*" {
		return true
	}
	if strings.HasSuffix(p, "*") {
		return strings.HasPrefix(source, strings.TrimSuffix(p, "*"))
	}
	return p == source
}

// inQuietWindow 判断当前时间是否落入规则配置的静默窗口（支持跨午夜如 23:00-07:30 与 IANA 时区）。
func inQuietWindow(now time.Time, startHHMM, endHHMM, tz string) bool {
	if strings.TrimSpace(startHHMM) == "" || strings.TrimSpace(endHHMM) == "" {
		return false
	}
	startMin, ok1 := parseHHMM(startHHMM)
	endMin, ok2 := parseHHMM(endHHMM)
	if !ok1 || !ok2 || startMin == endMin {
		return false
	}
	loc := time.UTC
	if tz != "" {
		if loaded, err := time.LoadLocation(tz); err == nil {
			loc = loaded
		}
	}
	local := now.In(loc)
	cur := local.Hour()*60 + local.Minute()
	if startMin < endMin {
		return cur >= startMin && cur < endMin
	}
	// 跨午夜区间，如 23:00 -> 07:30
	return cur >= startMin || cur < endMin
}

func parseHHMM(v string) (int, bool) {
	parts := strings.Split(strings.TrimSpace(v), ":")
	if len(parts) != 2 {
		return 0, false
	}
	h, err1 := strconv.Atoi(parts[0])
	m, err2 := strconv.Atoi(parts[1])
	if err1 != nil || err2 != nil || h < 0 || h > 23 || m < 0 || m > 59 {
		return 0, false
	}
	return h*60 + m, true
}

func (e *routerEngine) checkAndTouchCooldown(key string, sec int, now time.Time) bool {
	if sec <= 0 {
		return false
	}
	e.coolMu.Lock()
	defer e.coolMu.Unlock()
	if last, ok := e.cooldown[key]; ok && now.Sub(last) < time.Duration(sec)*time.Second {
		return true
	}
	if len(e.cooldown) >= maxCooldownKeys {
		// 先驱逐过期条目，仍满时按最旧时间腾出空间，保证 1C1G 内存绝对有界。
		var oldestKey string
		var oldestAt time.Time
		for k, t := range e.cooldown {
			if now.Sub(t) >= 24*time.Hour {
				delete(e.cooldown, k)
				continue
			}
			if oldestKey == "" || t.Before(oldestAt) {
				oldestKey, oldestAt = k, t
			}
		}
		if len(e.cooldown) >= maxCooldownKeys && oldestKey != "" {
			delete(e.cooldown, oldestKey)
		}
	}
	e.cooldown[key] = now
	return false
}

func (e *routerEngine) dispatch(ctx context.Context, ev NotifyEvent) (DispatchSummary, error) {
	if ev.EventID == "" {
		ev.EventID = newID("nev")
	}
	if ev.Timestamp.IsZero() {
		ev.Timestamp = e.now().UTC()
	}
	if ev.Severity == "" {
		ev.Severity = "info"
	}
	rules, err := e.store.listRules(ctx)
	if err != nil {
		return DispatchSummary{}, err
	}
	summary := DispatchSummary{
		EventID:    ev.EventID,
		Deliveries: make([]DeliveryRecord, 0),
	}
	dedup := ev.DedupKey
	if dedup == "" {
		dedup = ev.Source + "|" + ev.Title
	}
	seenCh := make(map[string]bool)

	for _, rule := range rules {
		if !rule.Enabled {
			continue
		}
		if !matchSource(rule.SourcePattern, ev.Source) {
			continue
		}
		if severityRank(ev.Severity) < severityRank(rule.MinSeverity) {
			continue
		}
		summary.Matched++

		quiet := inQuietWindow(ev.Timestamp, rule.QuietStart, rule.QuietEnd, rule.QuietTZ) &&
			!(rule.AllowCriticalBypass && ev.Severity == "critical")

		for _, chID := range rule.ChannelIDs {
			if seenCh[chID] {
				continue
			}
			ch, err := e.store.getChannelWithSecret(ctx, chID)
			if err != nil || !ch.Enabled {
				continue
			}
			seenCh[chID] = true

			rec := DeliveryRecord{
				ID:          newID("ndl"),
				EventID:     ev.EventID,
				Source:      ev.Source,
				Severity:    ev.Severity,
				Title:       ev.Title,
				ChannelID:   ch.ID,
				ChannelName: ch.Name,
				Attempts:    0,
				CreatedAt:   ev.Timestamp.Unix(),
			}

			if quiet {
				rec.Status = "suppressed_quiet"
				rec.ErrorMsg = fmt.Sprintf("quiet window %s-%s (%s)", rule.QuietStart, rule.QuietEnd, rule.QuietTZ)
				_ = e.store.recordDelivery(ctx, rec)
				summary.Suppressed++
				summary.Deliveries = append(summary.Deliveries, rec)
				continue
			}

			coolKey := rule.ID + "|" + ch.ID + "|" + dedup
			if e.checkAndTouchCooldown(coolKey, rule.CooldownSec, ev.Timestamp) {
				rec.Status = "suppressed_cooldown"
				rec.ErrorMsg = fmt.Sprintf("dedup cooldown %ds", rule.CooldownSec)
				_ = e.store.recordDelivery(ctx, rec)
				summary.Suppressed++
				summary.Deliveries = append(summary.Deliveries, rec)
				continue
			}

			out, attempts := e.sendWithRetry(ctx, ch, ev)
			rec.Attempts = attempts
			rec.HTTPStatus = out.HTTPStatus
			if out.Err != nil {
				rec.Status = "failed"
				rec.ErrorMsg = out.Err.Error()
				e.store.markChannelStatus(ctx, ch.ID, "error", rec.ErrorMsg)
				summary.Failed++
			} else {
				rec.Status = "sent"
				e.store.markChannelStatus(ctx, ch.ID, "ok", "")
				summary.Sent++
			}
			_ = e.store.recordDelivery(ctx, rec)
			summary.Deliveries = append(summary.Deliveries, rec)
		}
	}
	return summary, nil
}

func (e *routerEngine) sendWithRetry(ctx context.Context, ch channelWithSecret, ev NotifyEvent) (SendOutcome, int) {
	client, allowPrivate := e.snapshotClient()
	maxAttempts := 1 + len(e.retryBackoff)
	var last SendOutcome
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		last = dispatchChannel(ctx, client, allowPrivate, ch, ev)
		if last.Err == nil {
			return last, attempt
		}
		if attempt == maxAttempts || ctx.Err() != nil {
			return last, attempt
		}
		select {
		case <-ctx.Done():
			return last, attempt
		case <-time.After(e.retryBackoff[attempt-1]):
		}
	}
	return last, maxAttempts
}
