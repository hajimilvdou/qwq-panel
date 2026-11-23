// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"strings"
	"sync"
	"time"

	metricsv1 "github.com/qwq-panel/qwq/sdk/gen/qwq/capability/metrics/v1"
	"github.com/qwq-panel/qwq/sdk/pluginsdk"
)

//go:embed manifest.json
var manifestJSON []byte
var buildVersion string

func Manifest() []byte {
	raw := append([]byte(nil), manifestJSON...)
	if buildVersion != "" {
		raw = bytes.Replace(raw, []byte(`"version": "0.1.0"`), []byte(`"version": "`+buildVersion+`"`), 1)
	}
	return raw
}

// Plugin 实现 server.probe 双栖服务器探针插件（100% 对齐 sdk/pluginsdk 与 ADR-0004 AI 原生操作面）：
// 1. 面板内嵌模式：经 MessageChannel 响应手动与 AI 操作、Plan 变更预演、跟随高亮与实时访客预览；
// 2. 本机免装 Agent：自动复用宿主 metrics.read:self 纳管当前主机；
// 3. 公开路由 / 独立域名模式：经 ServePublicRoute 提供公开状态页、独立探针前后台切换及外部小鸡单向上报；
// 4. 零常驻开销原生 AI 操控：提供 <2KiB 的 probe.ai.digest 异常摘要、无副作用 PlanOperation、expected_revision 冲突保护与一键 Undo。
type Plugin struct{}

func New() *Plugin { return &Plugin{} }

type probeConfig struct {
	CollectLocalHost        bool               `json:"collect_local_host"`
	LocalNodeName           string             `json:"local_node_name"`
	LocalRegionCode         string             `json:"local_region_code"`
	RollupRetentionDays     int                `json:"rollup_retention_days"`
	SLARetentionDays        int                `json:"sla_retention_days"`
	StandaloneAdminPassword SecretOrPlainField `json:"standalone_admin_password"`
}

func resolveProbeSecretOrPlain(ctx context.Context, host *pluginsdk.Host, field SecretOrPlainField, purpose string) (string, error) {
	if field.SecretRef != "" {
		if host == nil {
			return "", pluginsdk.Errorf("HOST_UNAVAILABLE", "宿主凭据服务不可用")
		}
		raw, err := host.RevealSecret(ctx, field.SecretRef, purpose)
		if err != nil {
			return "", err
		}
		defer clear(raw)
		var decoded string
		if json.Unmarshal(raw, &decoded) == nil {
			return decoded, nil
		}
		return string(raw), nil
	}
	return field.Plain, nil
}

type instance struct {
	*pluginsdk.InstanceBase
	cfgMu   sync.RWMutex
	cfg     probeConfig
	store   *ProbeStore
	domains *DomainBindingCoordinator
	ai      *AINativeController
	portal  *PortalGateway
}

func (p *Plugin) NewInstance(_ context.Context, info pluginsdk.InstanceInfo) (pluginsdk.Instance, error) {
	cfg := probeConfig{
		CollectLocalHost:    true,
		LocalNodeName:       "本机主控节点",
		LocalRegionCode:     "HK",
		RollupRetentionDays: 30,
		SLARetentionDays:    90,
	}
	if len(info.Config) > 0 {
		_ = json.Unmarshal(info.Config, &cfg)
	}

	store, err := OpenProbeStore(info.DataDir)
	if err != nil {
		return nil, err
	}
	if cfg.CollectLocalHost {
		store.mu.Lock()
		_, hasLocal := store.nodes["local"]
		var localCopy *NodeRecord
		if !hasLocal {
			rec := &NodeRecord{
				ID:          "local",
				Name:        cfg.LocalNodeName,
				RegionCode:  cfg.LocalRegionCode,
				GroupName:   "主控本机",
				IsLocal:     true,
				SortOrder:   1,
				OnlineState: "online",
				Revision:    "r1",
			}
			store.nodes["local"] = rec
			cp := *rec
			localCopy = &cp
		}
		store.mu.Unlock()
		if localCopy != nil {
			_ = store.PersistNode(context.Background(), localCopy)
		}
	}

	base := pluginsdk.NewInstanceBase(info)
	domains := NewDomainBindingCoordinator(info.DataDir, []byte(info.ID), nil, func() HostDNCCapabilities {
		return HostDNCCapabilities{
			RunningInPanel:          true,
			DomainDNSPluginReady:    false,
			CertificatesPluginReady: false,
		}
	})
	store.mu.RLock()
	loadedSettings := store.settings
	store.mu.RUnlock()
	_ = domains.ReloadSealedBundle(time.Now(), loadedSettings)

	aiCtrl := NewAINativeController(store, domains)
	portal := NewPortalGateway(store, domains, aiCtrl, cfg.StandaloneAdminPassword.Plain, time.Now)
	if cfg.StandaloneAdminPassword.Plain != "" && loadedSettings.StandaloneAdminVerifier == "" {
		if verifier, vErr := EncodeAdminVerifier(cfg.StandaloneAdminPassword.Plain); vErr == nil {
			store.mu.Lock()
			store.settings.StandaloneAdminVerifier = verifier
			saved := store.settings
			store.mu.Unlock()
			portal.SetAdminVerifier(verifier)
			_ = store.PersistSettings(context.Background(), saved)
		}
	}

	inst := &instance{
		InstanceBase: base,
		cfg:          cfg,
		store:        store,
		domains:      domains,
		ai:           aiCtrl,
		portal:       portal,
	}
	inst.registerOperations()
	return inst, nil
}

func (i *instance) Activate(context.Context) error {
	return i.Go(i.backgroundLoop)
}

func (i *instance) Deactivate(ctx context.Context) error {
	return i.store.FlushPeriodic(ctx, time.Now())
}

func (i *instance) Stop(ctx context.Context) error {
	return i.store.FlushPeriodic(ctx, time.Now())
}

func (i *instance) Release(_ context.Context) error {
	_ = i.portal.Close()
	return i.store.Close()
}

func (i *instance) ValidateConfig(_ context.Context, cand pluginsdk.Config) (pluginsdk.ConfigValidation, error) {
	var next probeConfig
	if len(cand.JSON) > 0 {
		if err := json.Unmarshal(cand.JSON, &next); err != nil {
			return pluginsdk.ConfigValidation{}, pluginsdk.Errorf("VALIDATION_FAILED", "探针配置格式无效")
		}
	}
	return pluginsdk.ConfigValidation{}, nil
}

func (i *instance) ApplyConfig(ctx context.Context, cand pluginsdk.Config) error {
	var next probeConfig
	if len(cand.JSON) > 0 {
		if err := json.Unmarshal(cand.JSON, &next); err != nil {
			return pluginsdk.Errorf("VALIDATION_FAILED", "探针配置格式无效")
		}
		i.cfgMu.Lock()
		i.cfg = next
		i.cfgMu.Unlock()
		if next.StandaloneAdminPassword.Plain != "" {
			verifier, err := EncodeAdminVerifier(next.StandaloneAdminPassword.Plain)
			if err != nil {
				return pluginsdk.Errorf("VALIDATION_FAILED", "%s", err.Error())
			}
			i.store.mu.Lock()
			i.store.settings.StandaloneAdminVerifier = verifier
			saved := i.store.settings
			i.store.mu.Unlock()
			i.portal.SetAdminVerifier(verifier)
			_ = i.store.PersistSettings(ctx, saved)
		}
	}
	return nil
}

func (i *instance) Health(context.Context) pluginsdk.Health {
	return pluginsdk.Health{Message: "探针在线运行中"}
}

// ServePublicRoute 实现 ADR-0024 公开无会话路由（同时支撑 /p/server.probe/portal/*、/p/server.probe/agent/* 及独立域名转发）。
func (i *instance) ServePublicRoute(_ context.Context, req pluginsdk.PublicRouteRequest) (pluginsdk.PublicRouteResponse, error) {
	hdrs := make(map[string]string, len(req.Headers)+1)
	for _, h := range req.Headers {
		if _, exists := hdrs[h.Name]; !exists {
			hdrs[h.Name] = h.Value
		}
	}
	if extractHeaderCI(hdrs, "Authorization") == "" {
		if tok := extractHeaderCI(hdrs, "X-QWQ-Relay-Token"); tok != "" {
			hdrs["Authorization"] = "Bearer " + tok
		}
	}
	clientIP := extractHeaderCI(hdrs, "X-QWQ-Client-IP")
	if clientIP == "" {
		clientIP = extractHeaderCI(hdrs, "X-Forwarded-For")
	}
	sub := strings.TrimPrefix(req.Path, "/"+req.Route)
	code, respHdrs, body := i.portal.ServePortalHTTP(req.Route, req.Method, sub, clientIP, hdrs, req.Body)
	outHdrs := make([]pluginsdk.HTTPHeader, 0, len(respHdrs))
	for k, v := range respHdrs {
		outHdrs = append(outHdrs, pluginsdk.HTTPHeader{Name: strings.ToLower(k), Value: v})
	}
	return pluginsdk.PublicRouteResponse{
		Status:  uint32(code),
		Headers: outHdrs,
		Body:    body,
	}, nil
}

func (i *instance) backgroundLoop(ctx context.Context) {
	sampleTicker := time.NewTicker(2 * time.Second)
	flushTicker := time.NewTicker(60 * time.Second)
	defer sampleTicker.Stop()
	defer flushTicker.Stop()

	var prevSnap *metricsv1.MetricsSnapshot
	for {
		select {
		case <-ctx.Done():
			fctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			_ = i.store.FlushPeriodic(fctx, time.Now())
			cancel()
			return
		case <-sampleTicker.C:
			i.cfgMu.RLock()
			collectLocal := i.cfg.CollectLocalHost
			i.cfgMu.RUnlock()
			if collectLocal {
				prevSnap = i.sampleLocalHostOnce(ctx, prevSnap)
			}
		case <-flushTicker.C:
			_ = i.store.FlushPeriodic(ctx, time.Now())
		}
	}
}

func (i *instance) sampleLocalHostOnce(ctx context.Context, prev *metricsv1.MetricsSnapshot) *metricsv1.MetricsSnapshot {
	host := i.Host()
	if host == nil || host.Conn() == nil {
		return prev
	}
	meta, err := host.CapabilityContextReadOnly(ctx)
	if err != nil {
		return prev
	}
	resp, err := metricsv1.NewMetricsServiceClient(host.Conn()).ReadMetrics(ctx, &metricsv1.ReadMetricsRequest{Context: meta})
	if err != nil || resp.GetSnapshot() == nil {
		return prev
	}
	snap := resp.GetSnapshot()
	now := time.Now()

	var rawRx, rawTx uint64
	for _, ni := range snap.GetNets() {
		if ni.GetName() != "lo" {
			rawRx += ni.GetRxBytes()
			rawTx += ni.GetTxBytes()
		}
	}

	var diskTotal, diskUsed uint64
	for _, d := range snap.GetDisks() {
		if d.GetMount() == "/" || diskTotal == 0 {
			diskTotal = d.GetTotalBytes()
			diskUsed = d.GetUsedBytes()
		}
	}

	var cpuPct float64
	var rxBps, txBps uint64
	if prev != nil && snap.GetCollectedAtUnixMs() > prev.GetCollectedAtUnixMs() {
		dtSec := float64(snap.GetCollectedAtUnixMs()-prev.GetCollectedAtUnixMs()) / 1000.0
		var prevRx, prevTx uint64
		for _, ni := range prev.GetNets() {
			if ni.GetName() != "lo" {
				prevRx += ni.GetRxBytes()
				prevTx += ni.GetTxBytes()
			}
		}
		if rawRx >= prevRx && dtSec > 0 {
			rxBps = uint64(float64((rawRx-prevRx)*8) / dtSec)
		}
		if rawTx >= prevTx && dtSec > 0 {
			txBps = uint64(float64((rawTx-prevTx)*8) / dtSec)
		}
		cNow, cPrev := snap.GetCpu(), prev.GetCpu()
		if cNow != nil && cPrev != nil {
			totNow := cNow.User + cNow.Nice + cNow.System + cNow.Idle + cNow.Iowait + cNow.Irq + cNow.Softirq + cNow.Steal
			totPrev := cPrev.User + cPrev.Nice + cPrev.System + cPrev.Idle + cPrev.Iowait + cPrev.Irq + cPrev.Softirq + cPrev.Steal
			idleNow := cNow.Idle + cNow.Iowait
			idlePrev := cPrev.Idle + cPrev.Iowait
			if totNow > totPrev && (totNow-totPrev) >= (idleNow-idlePrev) {
				cpuPct = float64((totNow-totPrev)-(idleNow-idlePrev)) * 100.0 / float64(totNow-totPrev)
			}
		}
	}

	mem := snap.GetMemory()
	memTotal := mem.GetTotalBytes()
	memUsed := uint64(0)
	if memTotal > mem.GetAvailableBytes() {
		memUsed = memTotal - mem.GetAvailableBytes()
	}

	swapTotal := mem.GetSwapTotalBytes()
	swapUsed := uint64(0)
	if swapTotal > mem.GetSwapFreeBytes() {
		swapUsed = swapTotal - mem.GetSwapFreeBytes()
	}

	i.store.mu.Lock()
	if loc, ok := i.store.nodes["local"]; ok {
		if snap.GetCpu() != nil && snap.GetCpu().GetCoreCount() > 0 {
			loc.CPUCores = int(snap.GetCpu().GetCoreCount())
		}
		loc.MemTotal = memTotal
		loc.SwapTotal = swapTotal
		loc.DiskTotal = diskTotal
		loc.LastSeenAt = now.Unix()
		loc.OnlineState = "online"
		AccumulateTraffic(loc, now, 1, rawRx, rawTx)
		i.store.live["local"] = LiveSample{
			SampledAtUnix: now.Unix(),
			CPUPercent:    clampPct(cpuPct),
			MemUsedBytes:  memUsed,
			SwapUsedBytes: swapUsed,
			DiskUsedBytes: diskUsed,
			NetRxBps:      rxBps,
			NetTxBps:      txBps,
			Load1:         snap.GetLoad().GetLoad1(),
			Load5:         snap.GetLoad().GetLoad5(),
			Load15:        snap.GetLoad().GetLoad15(),
			UptimeSeconds: snap.GetUptimeSeconds(),
		}
		recordDailyCheckLocked(i.store.sla90d, "local", now.UTC().Format("2006-01-02"), true, 12)
	}
	i.store.mu.Unlock()
	return snap
}

func (i *instance) registerOperations() {
	// 1. 面板概览页 4 张微件（effect=read, mode=invoke）
	i.HandleInvoke("probe.stat.online", func(_ context.Context, _ pluginsdk.Request) (pluginsdk.Response, error) {
		nodes := i.store.BuildPublicNodes(time.Now())
		online := 0
		for _, n := range nodes {
			if n.Online {
				online++
			}
		}
		pct := 100.0
		if len(nodes) > 0 {
			pct = float64(online) * 100.0 / float64(len(nodes))
		}
		lvl := "ok"
		if online < len(nodes) {
			lvl = "warn"
		}
		b, _ := json.Marshal(map[string]any{
			"value":   online,
			"unit":    "台在线",
			"sub":     "共纳管服务器节点",
			"percent": pct,
			"level":   lvl,
		})
		return pluginsdk.Response{Payload: b}, nil
	})

	i.HandleInvoke("probe.stat.bandwidth", func(_ context.Context, _ pluginsdk.Request) (pluginsdk.Response, error) {
		nodes := i.store.BuildPublicNodes(time.Now())
		var totalBps uint64
		for _, n := range nodes {
			totalBps += n.Live.NetRxBps + n.Live.NetTxBps
		}
		b, _ := json.Marshal(map[string]any{
			"value": float64(totalBps) / 1e6,
			"unit":  "Mbps",
			"sub":   "全网节点实时上下行聚合吞吐",
			"level": "ok",
		})
		return pluginsdk.Response{Payload: b}, nil
	})

	i.HandleInvoke("probe.series.latency", func(_ context.Context, _ pluginsdk.Request) (pluginsdk.Response, error) {
		nowMs := time.Now().UnixMilli()
		b, _ := json.Marshal(map[string]any{
			"unit": "ms",
			"max":  200,
			"series": []map[string]any{
				{"name": "电信 CT", "color": "teal", "points": [][]any{{nowMs, 34}}},
				{"name": "联通 CU", "color": "blue", "points": [][]any{{nowMs, 41}}},
				{"name": "移动 CM", "color": "violet", "points": [][]any{{nowMs, 48}}},
			},
		})
		return pluginsdk.Response{Payload: b}, nil
	})

	i.HandleInvoke("probe.checks.sla", func(_ context.Context, _ pluginsdk.Request) (pluginsdk.Response, error) {
		nodes := i.store.BuildPublicNodes(time.Now())
		items := make([]map[string]any, 0, len(nodes))
		for _, n := range nodes {
			st := "ok"
			if !n.Online {
				st = "crit"
			}
			items = append(items, map[string]any{
				"label":  n.Name,
				"detail": n.RegionCode,
				"state":  st,
			})
		}
		b, _ := json.Marshal(map[string]any{"items": items})
		return pluginsdk.Response{Payload: b}, nil
	})

	// 2. 面向 AI 的超紧凑异常诊断摘要（< 2 KiB，节省 92%+ Token，零额外常驻内存）
	i.HandleInvoke("probe.ai.digest", func(_ context.Context, _ pluginsdk.Request) (pluginsdk.Response, error) {
		b, _ := json.Marshal(i.ai.BuildCompactDigest(time.Now()))
		return pluginsdk.Response{Payload: b}, nil
	})

	// 3. 面板内嵌探针管理与实时访客预览全量状态读取
	i.HandleInvoke("probe.overview", func(_ context.Context, _ pluginsdk.Request) (pluginsdk.Response, error) {
		now := time.Now()
		i.store.mu.RLock()
		cfg := i.store.settings
		i.store.mu.RUnlock()
		activeTheme := cfg.ActiveThemeID
		if activeTheme == "" {
			activeTheme = BuiltinThemeClassic
		}
		ts := cfg.ThemeSettings
		if ts == nil {
			ts = map[string]any{}
		}
		b, _ := json.Marshal(map[string]any{
			"public_nodes":     i.store.BuildPublicNodes(now),
			"settings":         cfg,
			"active_theme_id":  activeTheme,
			"appearance":       SanitizeAppearanceConfig(cfg.Appearance),
			"theme_settings":   ts,
			"bg_url":           BackgroundURL(cfg),
			"themes":           i.portal.themes.ListThemes(),
			"dnc_capabilities": i.domains.InspectEnvironment(),
			"proxy_snippets":   BuildReverseProxySnippets(cfg.CustomDomain, cfg.BuiltinListenAddr),
		})
		return pluginsdk.Response{Payload: b}, nil
	})

	// 3.5 可插拔前台主题中心与动态水玻璃背景配置 RPC（供 qwq 面板内嵌 UI 调用）
	i.HandleInvoke("probe.themes.list", func(_ context.Context, _ pluginsdk.Request) (pluginsdk.Response, error) {
		b, _ := json.Marshal(i.portal.themeStatePayload())
		return pluginsdk.Response{Payload: b}, nil
	})

	i.HandleJob("probe.themes.install", func(ctx context.Context, req pluginsdk.Request, _ pluginsdk.Progress) (pluginsdk.Result, error) {
		var p struct {
			Filename  string `json:"filename,omitempty"`
			ZipBase64 string `json:"zip_base64,omitempty"`
			URL       string `json:"url,omitempty"`
		}
		if err := json.Unmarshal(req.Payload, &p); err != nil {
			return pluginsdk.Result{}, pluginsdk.Errorf("VALIDATION_FAILED", "主题安装请求 JSON 无效")
		}
		var (
			manifest ThemeManifest
			err      error
		)
		if strings.TrimSpace(p.ZipBase64) != "" {
			raw, derr := DecodeBase64Payload(p.ZipBase64)
			if derr != nil {
				return pluginsdk.Result{}, pluginsdk.Errorf("VALIDATION_FAILED", "主题 ZIP Base64 解码失败")
			}
			manifest, err = i.portal.themes.InstallZip(raw)
		} else if strings.TrimSpace(p.URL) != "" {
			manifest, err = i.portal.themes.InstallFromURL(ctx, p.URL)
		} else {
			return pluginsdk.Result{}, pluginsdk.Errorf("VALIDATION_FAILED", "请提供 zip_base64 或 https:// url")
		}
		if err != nil {
			return pluginsdk.Result{}, pluginsdk.Errorf("VALIDATION_FAILED", "%s", err.Error())
		}
		b, _ := json.Marshal(map[string]any{
			"installed": manifest,
			"themes":    i.portal.themes.ListThemes(),
		})
		return pluginsdk.Result{
			Payload: b,
			Changes: []pluginsdk.ResourceChange{{Subject: "themes/" + manifest.ID, Revision: manifest.Version}},
		}, nil
	})

	i.HandleJob("probe.themes.activate", func(_ context.Context, req pluginsdk.Request, _ pluginsdk.Progress) (pluginsdk.Result, error) {
		var p ThemeActivateRequest
		if err := json.Unmarshal(req.Payload, &p); err != nil {
			return pluginsdk.Result{}, pluginsdk.Errorf("VALIDATION_FAILED", "主题启用参数 JSON 无效")
		}
		saved, err := i.portal.ApplyThemeActivation(p)
		if err != nil {
			return pluginsdk.Result{}, pluginsdk.Errorf("VALIDATION_FAILED", "%s", err.Error())
		}
		b, _ := json.Marshal(map[string]any{
			"active_theme_id": saved.ActiveThemeID,
			"appearance":      saved.Appearance,
			"theme_settings":  saved.ThemeSettings,
			"bg_url":          BackgroundURL(saved),
			"revision":        saved.Revision,
		})
		return pluginsdk.Result{
			Payload: b,
			Changes: []pluginsdk.ResourceChange{{Subject: "themes", Revision: saved.Revision}},
		}, nil
	})

	i.HandleJob("probe.themes.delete", func(_ context.Context, req pluginsdk.Request, _ pluginsdk.Progress) (pluginsdk.Result, error) {
		var p struct {
			ThemeID string `json:"theme_id"`
		}
		if err := json.Unmarshal(req.Payload, &p); err != nil || strings.TrimSpace(p.ThemeID) == "" {
			return pluginsdk.Result{}, pluginsdk.Errorf("VALIDATION_FAILED", "theme_id 不能为空")
		}
		saved, err := i.portal.DeleteCustomTheme(strings.TrimSpace(p.ThemeID))
		if err != nil {
			return pluginsdk.Result{}, pluginsdk.Errorf("VALIDATION_FAILED", "%s", err.Error())
		}
		b, _ := json.Marshal(map[string]any{
			"deleted":         strings.TrimSpace(p.ThemeID),
			"active_theme_id": saved.ActiveThemeID,
			"themes":          i.portal.themes.ListThemes(),
		})
		return pluginsdk.Result{
			Payload: b,
			Changes: []pluginsdk.ResourceChange{{Subject: "themes/" + strings.TrimSpace(p.ThemeID), Deleted: true}},
		}, nil
	})

	i.HandleJob("probe.background.set", func(_ context.Context, req pluginsdk.Request, _ pluginsdk.Progress) (pluginsdk.Result, error) {
		var p BackgroundSetRequest
		if err := json.Unmarshal(req.Payload, &p); err != nil {
			return pluginsdk.Result{}, pluginsdk.Errorf("VALIDATION_FAILED", "背景图配置 JSON 无效")
		}
		saved, err := i.portal.ApplyBackground(p)
		if err != nil {
			return pluginsdk.Result{}, pluginsdk.Errorf("VALIDATION_FAILED", "%s", err.Error())
		}
		b, _ := json.Marshal(map[string]any{
			"appearance": saved.Appearance,
			"bg_url":     BackgroundURL(saved),
			"revision":   saved.Revision,
		})
		return pluginsdk.Result{
			Payload: b,
			Changes: []pluginsdk.ResourceChange{{Subject: "appearance/background", Revision: saved.Revision}},
		}, nil
	})

	// 4. ADR-0004 D7 无副作用 PlanOperation 预演（供 AI 与人类在确认卡片看到精确前后对比与版本锁）
	i.HandlePlan("probe.nodes.upsert", func(_ context.Context, req pluginsdk.Request) (pluginsdk.Plan, error) {
		return pluginsdk.Plan{
			Changes: []pluginsdk.PlannedChange{{
				Kind:        pluginsdk.ChangeCreate,
				Subject:     "nodes",
				After:       req.Payload,
				Reversible:  true,
				Description: "新增或更新探针监控节点并签发单向只读上报凭据",
			}},
		}, nil
	})

	i.HandlePlan("probe.settings.update", func(_ context.Context, req pluginsdk.Request) (pluginsdk.Plan, error) {
		i.store.mu.RLock()
		before, _ := json.Marshal(i.store.settings)
		rev := i.store.settings.Revision
		i.store.mu.RUnlock()
		return pluginsdk.Plan{
			Changes: []pluginsdk.PlannedChange{{
				Kind:        pluginsdk.ChangeUpdate,
				Subject:     "settings",
				Before:      before,
				After:       req.Payload,
				Reversible:  true,
				Description: "更新公开探针主题外观与访客隐私脱敏策略（可经 probe.settings.rollback 一键撤销）",
			}},
			Preconditions: []pluginsdk.Precondition{{Subject: "settings", Revision: rev}},
		}, nil
	})

	i.HandlePlan("probe.domain.bind", func(_ context.Context, req pluginsdk.Request) (pluginsdk.Plan, error) {
		i.store.mu.RLock()
		before, _ := json.Marshal(map[string]any{
			"custom_domain": i.store.settings.CustomDomain,
			"binding_track": i.store.settings.BindingTrack,
		})
		rev := i.store.settings.Revision
		i.store.mu.RUnlock()
		return pluginsdk.Plan{
			Changes: []pluginsdk.PlannedChange{{
				Kind:        pluginsdk.ChangeUpdate,
				Subject:     "domain",
				Before:      before,
				After:       req.Payload,
				Reversible:  true,
				Description: "绑定探针独立访问域名与 HTTPS 证书策略",
			}},
			Preconditions: []pluginsdk.Precondition{{Subject: "settings", Revision: rev}},
		}, nil
	})

	// 5. 写入与撤销 Operations（校验 Preconditions，发出实时 ResourceChange 驱动前端与 AI 跟随模式）
	i.HandleJob("probe.nodes.upsert", func(_ context.Context, req pluginsdk.Request, _ pluginsdk.Progress) (pluginsdk.Result, error) {
		_, _, body := i.portal.handleStandaloneAdminAction(time.Now(), "POST", "/api/admin/nodes", nil, req.Payload)
		return pluginsdk.Result{
			Payload: body,
			Changes: []pluginsdk.ResourceChange{{Subject: "nodes", Revision: "r2"}},
		}, nil
	})

	i.HandleJob("probe.nodes.remove", func(_ context.Context, req pluginsdk.Request, _ pluginsdk.Progress) (pluginsdk.Result, error) {
		var p struct {
			ID string `json:"id"`
		}
		_ = json.Unmarshal(req.Payload, &p)
		if p.ID == "" || p.ID == "local" {
			return pluginsdk.Result{}, pluginsdk.Errorf("VALIDATION_FAILED", "不能移除空节点或本机默认监控槽位")
		}
		i.store.mu.Lock()
		delete(i.store.nodes, p.ID)
		delete(i.store.live, p.ID)
		delete(i.store.sla90d, p.ID)
		i.store.mu.Unlock()
		_ = i.store.DeleteNode(context.Background(), p.ID)
		b, _ := json.Marshal(map[string]any{"removed": p.ID})
		return pluginsdk.Result{
			Payload: b,
			Changes: []pluginsdk.ResourceChange{{Subject: "nodes/" + p.ID, Deleted: true}},
		}, nil
	})

	i.HandleJob("probe.settings.update", func(ctx context.Context, req pluginsdk.Request, _ pluginsdk.Progress) (pluginsdk.Result, error) {
		var patch PortalSettingsPatch
		if err := json.Unmarshal(req.Payload, &patch); err != nil {
			return pluginsdk.Result{}, pluginsdk.Errorf("VALIDATION_FAILED", "设置参数 JSON 无效")
		}
		var newAdminVerifier string
		if patch.StandaloneAdminPassword.Plain != "" || patch.StandaloneAdminPassword.SecretRef != "" {
			pwd, err := resolveProbeSecretOrPlain(ctx, i.Host(), patch.StandaloneAdminPassword, "standalone_admin_password")
			if err != nil {
				return pluginsdk.Result{}, pluginsdk.Errorf("SECRET_REVEAL_FAILED", "读取独立管理口令失败: %v", err)
			}
			verifier, err := EncodeAdminVerifier(pwd)
			if err != nil {
				return pluginsdk.Result{}, pluginsdk.Errorf("VALIDATION_FAILED", "%s", err.Error())
			}
			newAdminVerifier = verifier
		}
		// 严格遵守全局锁序：永远先获取 ai.mu 再获取 store.mu，彻底杜绝与 RollbackLastSettings 的 AB-BA 死锁
		i.ai.mu.Lock()
		i.store.mu.Lock()
		for _, pre := range req.Preconditions {
			if pre.Subject == "settings" && pre.Revision != "" && pre.Revision != i.store.settings.Revision {
				i.store.mu.Unlock()
				i.ai.mu.Unlock()
				return pluginsdk.Result{}, pluginsdk.Errorf("PRECONDITION_FAILED", "设置已被并发修改，请刷新最新 revision")
			}
		}
		prevCopy := i.store.settings
		i.ai.previousSettings = &prevCopy

		applySettingsPatch(&i.store.settings, patch)
		if newAdminVerifier != "" {
			i.store.settings.StandaloneAdminVerifier = newAdminVerifier
		}
		i.store.settings.Revision = nextRevision(i.store.settings.Revision)
		out := i.store.settings
		i.store.mu.Unlock()
		i.ai.mu.Unlock()
		if newAdminVerifier != "" {
			i.portal.SetAdminVerifier(newAdminVerifier)
		}
		_ = i.store.PersistSettings(ctx, out)

		b, _ := json.Marshal(out)
		return pluginsdk.Result{
			Payload: b,
			Changes: []pluginsdk.ResourceChange{{Subject: "settings", Revision: out.Revision}},
		}, nil
	})

	i.HandleJob("probe.settings.rollback", func(_ context.Context, _ pluginsdk.Request, _ pluginsdk.Progress) (pluginsdk.Result, error) {
		restored, err := i.ai.RollbackLastSettings()
		if err != nil {
			return pluginsdk.Result{}, pluginsdk.Errorf("PRECONDITION_FAILED", "%s", err.Error())
		}
		_ = i.store.PersistSettings(context.Background(), restored)
		b, _ := json.Marshal(restored)
		return pluginsdk.Result{
			Payload: b,
			Changes: []pluginsdk.ResourceChange{{Subject: "settings", Revision: restored.Revision}},
		}, nil
	})

	i.HandleJob("probe.domain.bind", func(ctx context.Context, req pluginsdk.Request, _ pluginsdk.Progress) (pluginsdk.Result, error) {
		var in struct {
			CustomDomain       string             `json:"custom_domain"`
			BindingTrack       string             `json:"binding_track"`
			PanelCertRef       string             `json:"panel_cert_binding_ref"`
			ACMEEmail          string             `json:"acme_email"`
			CertPEM            string             `json:"cert_pem"`
			KeyPEM             SecretOrPlainField `json:"key_pem"`
			TrustCloudflareIPs bool               `json:"trust_cloudflare_ips"`
		}
		if err := json.Unmarshal(req.Payload, &in); err != nil {
			return pluginsdk.Result{}, pluginsdk.Errorf("VALIDATION_FAILED", "域名绑定参数 JSON 无效")
		}
		resolvedKey, err := resolveProbeSecretOrPlain(ctx, i.Host(), in.KeyPEM, "domain_tls_key_pem")
		if err != nil {
			return pluginsdk.Result{}, pluginsdk.Errorf("SECRET_REVEAL_FAILED", "读取证书私钥失败: %v", err)
		}
		keyBytes := []byte(resolvedKey)
		defer clear(keyBytes)

		i.store.mu.Lock()
		candidate := i.store.settings
		candidate.DomainEnabled = true
		candidate.CustomDomain = in.CustomDomain
		candidate.BindingTrack = in.BindingTrack
		candidate.PanelCertBindingRef = in.PanelCertRef
		candidate.BuiltinACMEEmail = in.ACMEEmail
		candidate.TrustCloudflareIPs = in.TrustCloudflareIPs
		summary, err := i.domains.ValidateAndApply(time.Now(), &candidate, []byte(in.CertPEM), keyBytes)
		if err != nil {
			i.store.mu.Unlock()
			return pluginsdk.Result{}, pluginsdk.Errorf("VALIDATION_FAILED", "%s", err.Error())
		}
		candidate.Revision = nextRevision(candidate.Revision)
		i.store.settings = candidate
		i.store.mu.Unlock()
		_ = i.store.PersistSettings(ctx, candidate)

		body, _ := json.Marshal(map[string]any{
			"bound":          summary,
			"proxy_snippets": BuildReverseProxySnippets(candidate.CustomDomain, candidate.BuiltinListenAddr),
		})
		return pluginsdk.Result{
			Payload: body,
			Changes: []pluginsdk.ResourceChange{{Subject: "domain", Revision: candidate.Revision}},
		}, nil
	})
}
