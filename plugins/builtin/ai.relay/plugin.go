// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/qwq-panel/qwq/plugins/builtin/ai.relay/internal/proxy"
	"github.com/qwq-panel/qwq/plugins/builtin/ai.relay/internal/store"
	"github.com/qwq-panel/qwq/sdk/pluginsdk"
)

// ======================== 内置清单、数据库架构与门户静态资源嵌入 ========================

//go:embed manifest.json
var manifestJSON []byte

//go:embed schema.sql
var embeddedSchemaSQL string

//go:embed portal_ui
var embeddedPortalUI embed.FS

var buildVersion string

// Manifest 返回内嵌的 ai.relay 插件清单字节。
func Manifest() []byte {
	raw := append([]byte(nil), manifestJSON...)
	if buildVersion != "" {
		raw = bytes.Replace(raw, []byte(`"version": "0.1.0"`), []byte(`"version": "`+buildVersion+`"`), 1)
	}
	return raw
}

// Plugin 实现节点级 AI API 聚合中转与多源分发门户插件。
type Plugin struct {
	now                 func() time.Time
	maintenanceInterval time.Duration
	linuxDoBaseURL      string
	httpClient          *http.Client
}

// New 构造默认 AI 中转插件。
func New() *Plugin { return &Plugin{} }

func (p *Plugin) NewInstance(ctx context.Context, info pluginsdk.InstanceInfo) (pluginsdk.Instance, error) {
	cfg, err := parseConfig(info.Config)
	if err != nil {
		return nil, err
	}
	nowFn := p.now
	if nowFn == nil {
		nowFn = time.Now
	}
	db, masterKey, err := store.OpenDB(info.DataDir, embeddedSchemaSQL)
	if err != nil {
		return nil, pluginsdk.Errorf("INTERNAL", "初始化 AI 中转数据库失败")
	}

	client := p.httpClient
	if client == nil {
		client = proxy.NewSafeHTTPClient(cfg.AllowPrivateUpstream, time.Duration(cfg.UpstreamTimeoutSeconds)*time.Second)
	}

	ledger := store.NewLedgerEngine(db, masterKey, client, nowFn)
	if p.linuxDoBaseURL != "" {
		ledger.SetLinuxDoBaseURL(p.linuxDoBaseURL)
	}
	if err := ledger.LoadFromDB(ctx); err != nil {
		_ = ledger.Close()
		return nil, pluginsdk.Errorf("INTERNAL", "预热 AI 中转内存账本失败")
	}

	inst := &instance{
		InstanceBase:        pluginsdk.NewInstanceBase(info),
		cfg:                 cfg,
		ledger:              ledger,
		router:              proxy.NewRouter(),
		httpClient:          client,
		customHTTPClient:    p.httpClient != nil,
		now:                 nowFn,
		maintenanceInterval: p.maintenanceInterval,
		spark:               make([]float64, 0, 12),
	}
	if err := inst.reloadRouterSnapshot(ctx); err != nil {
		_ = ledger.Close()
		return nil, pluginsdk.Errorf("INTERNAL", "加载上游路由快照失败")
	}
	inst.register()
	return inst, nil
}

// ======================== 插件配置与实例生命周期 ========================

type relayConfig struct {
	PublicOrigin               string
	AllowPrivateUpstream       bool
	DefaultReserveMicros       int64
	LogRetentionDays           int
	RefillCheckIntervalSeconds int
	UpstreamTimeoutSeconds     int
}

type rawRelayConfig struct {
	PublicOrigin               *string `json:"public_origin"`
	AllowPrivateUpstream       *bool   `json:"allow_private_upstream"`
	DefaultReserveMicros       *int64  `json:"default_reserve_micros"`
	LogRetentionDays           *int    `json:"log_retention_days"`
	RefillCheckIntervalSeconds *int    `json:"refill_check_interval_seconds"`
	UpstreamTimeoutSeconds     *int    `json:"upstream_timeout_seconds"`
}

func defaultRelayConfig() relayConfig {
	return relayConfig{
		AllowPrivateUpstream:       false,
		DefaultReserveMicros:       store.DefaultReserveMicros,
		LogRetentionDays:           30,
		RefillCheckIntervalSeconds: 300,
		UpstreamTimeoutSeconds:     120,
	}
}

func parseConfig(raw []byte) (relayConfig, error) {
	cfg := defaultRelayConfig()
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return cfg, nil
	}
	var in rawRelayConfig
	dec := json.NewDecoder(bytes.NewReader(trimmed))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil {
		return relayConfig{}, invalidField("", "INVALID_CONFIG", "AI 中转插件配置格式无效")
	}
	if err := dec.Decode(new(any)); err != io.EOF {
		return relayConfig{}, invalidField("", "INVALID_CONFIG", "AI 中转插件配置包含多余内容")
	}
	if in.PublicOrigin != nil {
		cfg.PublicOrigin = strings.TrimRight(strings.TrimSpace(*in.PublicOrigin), "/")
	}
	if in.AllowPrivateUpstream != nil {
		cfg.AllowPrivateUpstream = *in.AllowPrivateUpstream
	}
	if in.DefaultReserveMicros != nil {
		if *in.DefaultReserveMicros < 1000 || *in.DefaultReserveMicros > 10_000_000 {
			return relayConfig{}, invalidField("/default_reserve_micros", "OUT_OF_RANGE", "default_reserve_micros 必须在 1000..10000000 之间")
		}
		cfg.DefaultReserveMicros = *in.DefaultReserveMicros
	}
	if in.LogRetentionDays != nil {
		if *in.LogRetentionDays < 1 || *in.LogRetentionDays > 365 {
			return relayConfig{}, invalidField("/log_retention_days", "OUT_OF_RANGE", "log_retention_days 必须在 1..365 之间")
		}
		cfg.LogRetentionDays = *in.LogRetentionDays
	}
	if in.RefillCheckIntervalSeconds != nil {
		if *in.RefillCheckIntervalSeconds < 30 || *in.RefillCheckIntervalSeconds > 86400 {
			return relayConfig{}, invalidField("/refill_check_interval_seconds", "OUT_OF_RANGE", "refill_check_interval_seconds 必须在 30..86400 之间")
		}
		cfg.RefillCheckIntervalSeconds = *in.RefillCheckIntervalSeconds
	}
	if in.UpstreamTimeoutSeconds != nil {
		if *in.UpstreamTimeoutSeconds < 5 || *in.UpstreamTimeoutSeconds > 600 {
			return relayConfig{}, invalidField("/upstream_timeout_seconds", "OUT_OF_RANGE", "upstream_timeout_seconds 必须在 5..600 之间")
		}
		cfg.UpstreamTimeoutSeconds = *in.UpstreamTimeoutSeconds
	}
	return cfg, nil
}

type instance struct {
	*pluginsdk.InstanceBase

	mu                  sync.RWMutex
	cfg                 relayConfig
	httpClient          *http.Client
	customHTTPClient    bool
	spark               []float64
	lastMaintErr        string
	ledger              *store.LedgerEngine
	router              *proxy.Router
	now                 func() time.Time
	maintenanceInterval time.Duration
}

// 编译期断言 *instance 实现 pluginsdk.PublicHTTPStreamer，使 SDK 在 Start 时自动桥接 public-stream.sock。
var _ pluginsdk.PublicHTTPStreamer = (*instance)(nil)

func (i *instance) configSnapshot() relayConfig {
	i.mu.RLock()
	defer i.mu.RUnlock()
	return i.cfg
}

func (i *instance) clientSnapshot() *http.Client {
	i.mu.RLock()
	defer i.mu.RUnlock()
	return i.httpClient
}

func (i *instance) nowTime() time.Time {
	if i.now != nil {
		return i.now()
	}
	return time.Now()
}

func (i *instance) Activate(ctx context.Context) error {
	i.ledger.StartBatcher(ctx)
	return i.Go(i.maintenanceLoop)
}

func (i *instance) Deactivate(ctx context.Context) error {
	return i.ledger.FlushSync(ctx)
}

func (i *instance) Stop(context.Context) error    { return i.ledger.Close() }
func (i *instance) Release(context.Context) error { return i.ledger.Close() }

func (i *instance) ValidateConfig(_ context.Context, cfg pluginsdk.Config) (pluginsdk.ConfigValidation, error) {
	_, err := parseConfig(cfg.JSON)
	return pluginsdk.ConfigValidation{}, err
}

func (i *instance) ApplyConfig(_ context.Context, cfg pluginsdk.Config) error {
	next, err := parseConfig(cfg.JSON)
	if err != nil {
		return err
	}
	var oldClient, newClient *http.Client
	i.mu.Lock()
	i.cfg = next
	if !i.customHTTPClient {
		oldClient = i.httpClient
		newClient = proxy.NewSafeHTTPClient(next.AllowPrivateUpstream, time.Duration(next.UpstreamTimeoutSeconds)*time.Second)
		i.httpClient = newClient
	}
	i.mu.Unlock()
	if newClient != nil && i.ledger != nil {
		i.ledger.SetHTTPClient(newClient)
	}
	if oldClient != nil {
		oldClient.CloseIdleConnections()
	}
	return nil
}

func (i *instance) Health(context.Context) pluginsdk.Health {
	i.mu.RLock()
	errText := i.lastMaintErr
	i.mu.RUnlock()
	if errText != "" {
		return pluginsdk.Health{Message: "后台巡检降级：" + errText}
	}
	return pluginsdk.Health{Message: "AI 聚合中转与分发门户就绪"}
}

func (i *instance) maintenanceLoop(ctx context.Context) {
	interval := i.maintenanceInterval
	if interval <= 0 {
		interval = time.Duration(i.configSnapshot().RefillCheckIntervalSeconds) * time.Second
	}
	if interval <= 0 {
		interval = 5 * time.Minute
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			cfg := i.configSnapshot()
			if err := i.ledger.RunPeriodicAutoRefill(ctx); err != nil {
				i.mu.Lock()
				i.lastMaintErr = err.Error()
				i.mu.Unlock()
				continue
			}
			_ = i.ledger.PruneOldLogs(ctx, cfg.LogRetentionDays)
			i.mu.Lock()
			i.lastMaintErr = ""
			i.mu.Unlock()
		}
	}
}

func (i *instance) reloadRouterSnapshot(ctx context.Context) error {
	chs, err := i.ledger.ListChannels(ctx, "", 256, true)
	if err != nil {
		return err
	}
	prices, err := i.ledger.ListPricings(ctx)
	if err != nil {
		return err
	}

	upstreams := make([]*proxy.UpstreamChannel, 0, len(chs))
	for _, c := range chs {
		if !c.Enabled {
			continue
		}
		maxConc := c.MaxConcurrent
		if maxConc < 1 {
			maxConc = 16
		}
		uc := &proxy.UpstreamChannel{
			ID:           c.ID,
			Name:         c.Name,
			Kind:         proxy.ChannelKind(c.Kind),
			BaseURL:      c.BaseURL,
			Groups:       append([]string(nil), c.Groups...),
			Models:       append([]string(nil), c.Models...),
			ModelMapping: c.ModelMapping,
			Priority:     c.Priority,
			Weight:       c.Weight,
			Sem:          make(chan struct{}, maxConc),
		}
		uc.SetCredential(c.Credential)
		uc.Tripped.Store(c.HealthState == "tripped")
		uc.CooldownUntil.Store(c.CooldownUntil)
		upstreams = append(upstreams, uc)
	}

	priceMap := make(map[string]proxy.ModelPricing, len(prices))
	for _, p := range prices {
		priceMap[p.ModelName] = proxy.ModelPricing{
			BillingMode:       p.BillingMode,
			InputMicrosPer1K:  p.InputMicrosPer1K,
			OutputMicrosPer1K: p.OutputMicrosPer1K,
			CacheReadRatio:    p.CacheReadRatio,
			CacheWriteRatio:   p.CacheWriteRatio,
			PerCallMicros:     p.PerCallMicros,
		}
	}
	i.router.ReplaceSnapshot(upstreams, priceMap)
	return nil
}

// ======================== 12 项管理操作注册与实现 ========================

func (i *instance) register() {
	i.HandleInvoke("relay.overview", i.handleOverview)
	i.HandleInvoke("relay.settings.get", i.handleSettingsGet)
	i.HandleJob("relay.settings.update", i.handleSettingsUpdate)
	i.HandleInvoke("relay.channels.list", i.handleChannelsList)
	i.HandleJob("relay.channels.upsert", i.handleChannelsUpsert)
	i.HandleJob("relay.channels.test", i.handleChannelsTest)
	i.HandleJob("relay.channels.remove", i.handleChannelsRemove)
	i.HandleJob("relay.pricings.upsert", i.handlePricingsUpsert)
	i.HandleInvoke("relay.users.list", i.handleUsersList)
	i.HandleJob("relay.users.create", i.handleUsersCreate)
	i.HandleJob("relay.users.adjust_quota", i.handleUsersAdjustQuota)
	i.HandleJob("relay.codes.generate", i.handleCodesGenerate)
}

func (i *instance) handleOverview(ctx context.Context, req pluginsdk.Request) (pluginsdk.Response, error) {
	var in struct {
		WindowHours int `json:"window_hours"`
	}
	if err := decodeOptionalJSON(req.Payload, &in); err != nil {
		return pluginsdk.Response{}, err
	}
	if in.WindowHours <= 0 {
		in.WindowHours = 24
	}
	stats, err := i.ledger.Overview(ctx, in.WindowHours)
	if err != nil {
		return pluginsdk.Response{}, err
	}
	i.mu.Lock()
	i.spark = append(i.spark, float64(stats.HealthyChannels))
	if len(i.spark) > 12 {
		i.spark = append([]float64(nil), i.spark[len(i.spark)-12:]...)
	}
	sparkCopy := append([]float64(nil), i.spark...)
	i.mu.Unlock()

	pct := 0.0
	if stats.TotalChannels > 0 {
		pct = float64(stats.HealthyChannels) * 100.0 / float64(stats.TotalChannels)
	}
	level := "ok"
	sub := fmt.Sprintf("活跃用户 %d/%d · %dh 调用 %d 次", stats.ActiveUsers, stats.TotalUsers, in.WindowHours, stats.WindowRequests)
	if stats.TotalChannels == 0 {
		level = "muted"
		sub = "尚未配置上游 AI 渠道"
	} else if stats.HealthyChannels == 0 {
		level = "crit"
		sub = "全部上游渠道不可用或已熔断"
	} else if stats.HealthyChannels < stats.TotalChannels {
		level = "warn"
	}

	return marshalResponse(map[string]any{
		"value":              float64(stats.HealthyChannels),
		"unit":               "条健康渠道",
		"percent":            pct,
		"sub":                sub,
		"level":              level,
		"spark":              sparkCopy,
		"total_channels":     stats.TotalChannels,
		"healthy_channels":   stats.HealthyChannels,
		"total_users":        stats.TotalUsers,
		"active_users":       stats.ActiveUsers,
		"window_requests":    stats.WindowRequests,
		"window_cost_micros": stats.WindowCostMicros,
	})
}

func (i *instance) handleSettingsGet(ctx context.Context, req pluginsdk.Request) (pluginsdk.Response, error) {
	var in struct {
		IncludeTierRules *bool `json:"include_tier_rules"`
	}
	if err := decodeOptionalJSON(req.Payload, &in); err != nil {
		return pluginsdk.Response{}, err
	}
	view, err := i.ledger.GetSettings(ctx)
	if err != nil {
		return pluginsdk.Response{}, err
	}
	if in.IncludeTierRules != nil && !*in.IncludeTierRules {
		view.LinuxDoTierRules = map[string]store.LinuxDoTierRule{}
	}
	return marshalResponse(view)
}

func (i *instance) handleSettingsUpdate(ctx context.Context, req pluginsdk.Request, _ pluginsdk.Progress) (pluginsdk.Result, error) {
	type smtpPatchInput struct {
		Host        string                `json:"host"`
		Port        int                   `json:"port"`
		Username    string                `json:"username"`
		Password    pluginsdk.SecretField `json:"password"`
		FromAddress string                `json:"from_address"`
	}
	var in struct {
		SiteTitle               *string                          `json:"site_title"`
		SiteAnnouncement        *string                          `json:"site_announcement"`
		AllowInviteSignup       *bool                            `json:"allow_invite_signup"`
		AllowEmailSignup        *bool                            `json:"allow_email_signup"`
		EmailDomainAllowlist    []string                         `json:"email_domain_allowlist"`
		AllowLinuxDoSignup      *bool                            `json:"allow_linuxdo_signup"`
		LinuxDoClientID         *string                          `json:"linuxdo_client_id"`
		LinuxDoClientSecret     pluginsdk.SecretField            `json:"linuxdo_client_secret"`
		LinuxDoMinTrustLevel    *int                             `json:"linuxdo_min_trust_level"`
		LinuxDoTierRules        map[string]store.LinuxDoTierRule `json:"linuxdo_tier_rules"`
		DefaultSignupMicros     *int64                           `json:"default_signup_micros"`
		InviterRewardMicros     *int64                           `json:"inviter_reward_micros"`
		InviteeRewardMicros     *int64                           `json:"invitee_reward_micros"`
		MaxInviteRewardsPerUser *int                             `json:"max_invite_rewards_per_user"`
		CheckinEnabled          *bool                            `json:"checkin_enabled"`
		CheckinMinMicros        *int64                           `json:"checkin_min_micros"`
		CheckinMaxMicros        *int64                           `json:"checkin_max_micros"`
		CheckinDripBelowMicros  *int64                           `json:"checkin_drip_below_micros"`
		SMTP                    *smtpPatchInput                  `json:"smtp"`
	}
	if err := decodeStrictJSON(req.Payload, &in); err != nil {
		return pluginsdk.Result{}, err
	}
	if in.LinuxDoMinTrustLevel != nil && (*in.LinuxDoMinTrustLevel < 0 || *in.LinuxDoMinTrustLevel > 4) {
		return pluginsdk.Result{}, invalidField("/linuxdo_min_trust_level", "OUT_OF_RANGE", "linuxdo_min_trust_level 必须在 0..4 之间")
	}

	ldSecret, keepLDSecret, err := in.LinuxDoClientSecret.ResolveString(ctx, req.Host(), "plugin.operation")
	if err != nil {
		return pluginsdk.Result{}, err
	}
	if keepLDSecret {
		ldSecret = ""
	}

	var smtpCfg *store.SMTPConfig
	if in.SMTP != nil {
		smtpPass, keepSMTPPass, err := in.SMTP.Password.ResolveString(ctx, req.Host(), "plugin.operation")
		if err != nil {
			return pluginsdk.Result{}, err
		}
		if keepSMTPPass {
			smtpPass = ""
		}
		smtpCfg = &store.SMTPConfig{
			Host:        strings.TrimSpace(in.SMTP.Host),
			Port:        in.SMTP.Port,
			Username:    strings.TrimSpace(in.SMTP.Username),
			Password:    smtpPass,
			FromAddress: strings.TrimSpace(in.SMTP.FromAddress),
		}
	}

	view, err := i.ledger.UpdateSettings(ctx, store.SettingsPatch{
		SiteTitle:               in.SiteTitle,
		SiteAnnouncement:        in.SiteAnnouncement,
		AllowInviteSignup:       in.AllowInviteSignup,
		AllowEmailSignup:        in.AllowEmailSignup,
		EmailDomainAllowlist:    in.EmailDomainAllowlist,
		HasEmailDomainAllowlist: in.EmailDomainAllowlist != nil,
		AllowLinuxDoSignup:      in.AllowLinuxDoSignup,
		LinuxDoClientID:         in.LinuxDoClientID,
		LinuxDoClientSecret:     ldSecret,
		LinuxDoMinTrustLevel:    in.LinuxDoMinTrustLevel,
		LinuxDoTierRules:        in.LinuxDoTierRules,
		DefaultSignupMicros:     in.DefaultSignupMicros,
		InviterRewardMicros:     in.InviterRewardMicros,
		InviteeRewardMicros:     in.InviteeRewardMicros,
		MaxInviteRewardsPerUser: in.MaxInviteRewardsPerUser,
		CheckinEnabled:          in.CheckinEnabled,
		CheckinMinMicros:        in.CheckinMinMicros,
		CheckinMaxMicros:        in.CheckinMaxMicros,
		CheckinDripBelowMicros:  in.CheckinDripBelowMicros,
		SMTP:                    smtpCfg,
	})
	if err != nil {
		return pluginsdk.Result{}, mapStoreError(err)
	}
	return marshalResult(map[string]any{
		"updated_at":                       view.UpdatedAt,
		"linuxdo_client_secret_configured": view.LinuxDoClientSecretConfigured,
		"smtp_configured":                  view.SMTPConfigured,
	})
}

func (i *instance) handleChannelsList(ctx context.Context, req pluginsdk.Request) (pluginsdk.Response, error) {
	var in struct {
		Kind  string `json:"kind"`
		Limit int    `json:"limit"`
	}
	if err := decodeOptionalJSON(req.Payload, &in); err != nil {
		return pluginsdk.Response{}, err
	}
	channels, err := i.ledger.ListChannels(ctx, in.Kind, in.Limit, false)
	if err != nil {
		return pluginsdk.Response{}, err
	}
	return marshalResponse(map[string]any{"channels": channels})
}

func (i *instance) handleChannelsUpsert(ctx context.Context, req pluginsdk.Request, _ pluginsdk.Progress) (pluginsdk.Result, error) {
	var in struct {
		ID            string                `json:"id"`
		Name          string                `json:"name"`
		Kind          string                `json:"kind"`
		BaseURL       string                `json:"base_url"`
		Credential    pluginsdk.SecretField `json:"credential"`
		Groups        []string              `json:"groups"`
		Models        []string              `json:"models"`
		ModelMapping  map[string]string     `json:"model_mapping"`
		Priority      int                   `json:"priority"`
		Weight        int                   `json:"weight"`
		MaxConcurrent int                   `json:"max_concurrent"`
		Enabled       *bool                 `json:"enabled"`
	}
	if err := decodeStrictJSON(req.Payload, &in); err != nil {
		return pluginsdk.Result{}, err
	}
	if strings.TrimSpace(in.Name) == "" {
		return pluginsdk.Result{}, invalidField("/name", "REQUIRED", "渠道名称不能为空")
	}
	if !validChannelKind(in.Kind) {
		return pluginsdk.Result{}, invalidField("/kind", "INVALID_VALUE", "不支持的上游渠道类型")
	}
	if u, err := url.Parse(strings.TrimSpace(in.BaseURL)); err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return pluginsdk.Result{}, invalidField("/base_url", "INVALID_URL", "base_url 必须是合法的 http/https 地址")
	}
	credPlain, keepCred, err := in.Credential.ResolveString(ctx, req.Host(), "plugin.operation")
	if err != nil {
		return pluginsdk.Result{}, err
	}
	if keepCred {
		credPlain = ""
	}
	enabled := true
	if in.Enabled != nil {
		enabled = *in.Enabled
	}
	saved, err := i.ledger.UpsertChannel(ctx, store.ChannelRecord{
		ID:            strings.TrimSpace(in.ID),
		Name:          strings.TrimSpace(in.Name),
		Kind:          in.Kind,
		BaseURL:       proxy.NormalizeUpstreamBaseURL(in.BaseURL),
		Credential:    credPlain,
		Groups:        in.Groups,
		Models:        in.Models,
		ModelMapping:  in.ModelMapping,
		Priority:      in.Priority,
		Weight:        in.Weight,
		MaxConcurrent: in.MaxConcurrent,
		Enabled:       enabled,
	})
	if err != nil {
		return pluginsdk.Result{}, mapStoreError(err)
	}
	_ = i.reloadRouterSnapshot(ctx)
	return marshalResult(map[string]any{
		"id":           saved.ID,
		"name":         saved.Name,
		"kind":         saved.Kind,
		"enabled":      saved.Enabled,
		"health_state": saved.HealthState,
		"updated_at":   saved.UpdatedAt,
	})
}

func (i *instance) handleChannelsTest(ctx context.Context, req pluginsdk.Request, _ pluginsdk.Progress) (pluginsdk.Result, error) {
	var in struct {
		ID    string `json:"id"`
		Model string `json:"model"`
	}
	if err := decodeStrictJSON(req.Payload, &in); err != nil {
		return pluginsdk.Result{}, err
	}
	chs, err := i.ledger.ListChannels(ctx, "", 256, true)
	if err != nil {
		return pluginsdk.Result{}, err
	}
	var target *store.ChannelRecord
	for idx := range chs {
		if chs[idx].ID == strings.TrimSpace(in.ID) {
			target = &chs[idx]
			break
		}
	}
	if target == nil {
		return pluginsdk.Result{}, pluginsdk.Errorf("NOT_FOUND", "上游渠道不存在")
	}

	probeModel := strings.TrimSpace(in.Model)
	if probeModel == "" && len(target.Models) > 0 {
		probeModel = target.Models[0]
	}
	if probeModel == "" {
		probeModel = "gpt-4o-mini"
	}

	uc := &proxy.UpstreamChannel{
		ID:           target.ID,
		Name:         target.Name,
		Kind:         proxy.ChannelKind(target.Kind),
		BaseURL:      target.BaseURL,
		ModelMapping: target.ModelMapping,
	}
	uc.SetCredential(target.Credential)
	ir := proxy.CanonicalRequest{
		Model:     probeModel,
		Messages:  []proxy.CanonicalMessage{{Role: "user", Content: "ping"}},
		MaxTokens: 1,
		Stream:    true,
	}
	targetURL, hdrs, body, err := proxy.EncodeUpstreamRequest(uc, proxy.ProtoOpenAIChat, nil, ir)
	if err != nil {
		return pluginsdk.Result{}, err
	}
	probeReq, err := http.NewRequestWithContext(ctx, http.MethodPost, targetURL, bytes.NewReader(body))
	if err != nil {
		return pluginsdk.Result{}, err
	}
	for k, v := range hdrs {
		probeReq.Header.Set(k, v)
	}

	started := time.Now()
	resp, err := i.clientSnapshot().Do(probeReq)
	ttft := time.Since(started).Milliseconds()
	if err != nil {
		_ = i.ledger.UpdateChannelHealth(ctx, target.ID, "cooling", i.nowTime().Add(60*time.Second).UnixMilli(), ttft, err.Error())
		_ = i.reloadRouterSnapshot(ctx)
		return marshalResult(map[string]any{
			"id":           target.ID,
			"ok":           false,
			"http_status":  0,
			"ttft_ms":      ttft,
			"health_state": "cooling",
			"error":        err.Error(),
		})
	}
	defer resp.Body.Close()
	_, _ = io.CopyN(io.Discard, resp.Body, 4096)

	ok := resp.StatusCode >= 200 && resp.StatusCode < 300
	healthState := "healthy"
	var cooldownUntil int64
	errMsg := ""
	if !ok {
		errMsg = fmt.Sprintf("upstream status %d", resp.StatusCode)
		if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
			healthState = "tripped"
		} else {
			healthState = "cooling"
			cooldownUntil = i.nowTime().Add(60 * time.Second).UnixMilli()
		}
	}
	_ = i.ledger.UpdateChannelHealth(ctx, target.ID, healthState, cooldownUntil, ttft, errMsg)
	_ = i.reloadRouterSnapshot(ctx)

	return marshalResult(map[string]any{
		"id":           target.ID,
		"ok":           ok,
		"http_status":  resp.StatusCode,
		"ttft_ms":      ttft,
		"health_state": healthState,
		"error":        errMsg,
	})
}

func (i *instance) handleChannelsRemove(ctx context.Context, req pluginsdk.Request, _ pluginsdk.Progress) (pluginsdk.Result, error) {
	var in struct {
		ID string `json:"id"`
	}
	if err := decodeStrictJSON(req.Payload, &in); err != nil {
		return pluginsdk.Result{}, err
	}
	removed, err := i.ledger.RemoveChannel(ctx, strings.TrimSpace(in.ID))
	if err != nil {
		return pluginsdk.Result{}, err
	}
	_ = i.reloadRouterSnapshot(ctx)
	return marshalResult(map[string]any{"id": strings.TrimSpace(in.ID), "removed": removed})
}

func (i *instance) handlePricingsUpsert(ctx context.Context, req pluginsdk.Request, _ pluginsdk.Progress) (pluginsdk.Result, error) {
	var in struct {
		ModelName         string   `json:"model_name"`
		BillingMode       string   `json:"billing_mode"`
		InputMicrosPer1K  int64    `json:"input_micros_per_1k"`
		OutputMicrosPer1K int64    `json:"output_micros_per_1k"`
		CacheReadRatio    *float64 `json:"cache_read_ratio"`
		CacheWriteRatio   *float64 `json:"cache_write_ratio"`
		PerCallMicros     int64    `json:"per_call_micros"`
	}
	if err := decodeStrictJSON(req.Payload, &in); err != nil {
		return pluginsdk.Result{}, err
	}
	if strings.TrimSpace(in.ModelName) == "" {
		return pluginsdk.Result{}, invalidField("/model_name", "REQUIRED", "model_name 不能为空")
	}
	if in.BillingMode == "" {
		in.BillingMode = "token"
	}
	if in.BillingMode != "token" && in.BillingMode != "per_call" {
		return pluginsdk.Result{}, invalidField("/billing_mode", "INVALID_VALUE", "billing_mode 仅支持 token 或 per_call")
	}
	cr, cw := 0.1, 1.25
	if in.CacheReadRatio != nil {
		cr = *in.CacheReadRatio
	}
	if in.CacheWriteRatio != nil {
		cw = *in.CacheWriteRatio
	}
	saved, err := i.ledger.UpsertPricing(ctx, store.PricingRecord{
		ModelName:         strings.TrimSpace(in.ModelName),
		BillingMode:       in.BillingMode,
		InputMicrosPer1K:  in.InputMicrosPer1K,
		OutputMicrosPer1K: in.OutputMicrosPer1K,
		CacheReadRatio:    cr,
		CacheWriteRatio:   cw,
		PerCallMicros:     in.PerCallMicros,
	})
	if err != nil {
		return pluginsdk.Result{}, mapStoreError(err)
	}
	_ = i.reloadRouterSnapshot(ctx)
	return marshalResult(saved)
}

func (i *instance) handleUsersList(ctx context.Context, req pluginsdk.Request) (pluginsdk.Response, error) {
	var in struct {
		GroupName    string `json:"group_name"`
		Status       string `json:"status"`
		SignupSource string `json:"signup_source"`
		Limit        int    `json:"limit"`
	}
	if err := decodeOptionalJSON(req.Payload, &in); err != nil {
		return pluginsdk.Response{}, err
	}
	users, err := i.ledger.ListUsers(ctx, strings.TrimSpace(in.GroupName), strings.TrimSpace(in.Status), strings.TrimSpace(in.SignupSource), in.Limit)
	if err != nil {
		return pluginsdk.Response{}, err
	}
	return marshalResponse(map[string]any{"users": users})
}

func (i *instance) handleUsersCreate(ctx context.Context, req pluginsdk.Request, _ pluginsdk.Progress) (pluginsdk.Result, error) {
	var in struct {
		Username          string                `json:"username"`
		Password          pluginsdk.SecretField `json:"password"`
		Email             string                `json:"email"`
		GroupName         string                `json:"group_name"`
		InitMicros        *int64                `json:"init_micros"`
		DailyRefillMicros int64                 `json:"daily_refill_micros"`
		AutoRefillCycle   string                `json:"auto_refill_cycle"`
	}
	if err := decodeStrictJSON(req.Payload, &in); err != nil {
		return pluginsdk.Result{}, err
	}
	passwordPlain, _, err := in.Password.ResolveString(ctx, req.Host(), "plugin.operation")
	if err != nil {
		return pluginsdk.Result{}, err
	}
	initM := int64(5_000_000)
	if in.InitMicros != nil {
		initM = *in.InitMicros
	}
	user, err := i.ledger.CreateUserByAdmin(ctx, in.Username, passwordPlain, in.Email, in.GroupName, initM, in.DailyRefillMicros, in.AutoRefillCycle)
	if err != nil {
		return pluginsdk.Result{}, mapStoreError(err)
	}
	return marshalResult(map[string]any{
		"id":                     user.ID,
		"username":               user.Username,
		"group_name":             user.GroupName,
		"status":                 user.Status,
		"signup_source":          user.SignupSource,
		"balance_micros":         user.BalanceMicros,
		"auto_refill_cap_micros": user.AutoRefillCapMicros,
		"auto_refill_cycle":      user.AutoRefillCycle,
		"personal_invite_code":   user.PersonalInviteCode,
		"created_at":             user.CreatedAt,
	})
}

func (i *instance) handleUsersAdjustQuota(ctx context.Context, req pluginsdk.Request, _ pluginsdk.Progress) (pluginsdk.Result, error) {
	var in struct {
		UserID              string `json:"user_id"`
		DeltaMicros         int64  `json:"delta_micros"`
		GroupName           string `json:"group_name"`
		Status              string `json:"status"`
		AutoRefillCapMicros *int64 `json:"auto_refill_cap_micros"`
		AutoRefillCycle     string `json:"auto_refill_cycle"`
		Note                string `json:"note"`
	}
	if err := decodeStrictJSON(req.Payload, &in); err != nil {
		return pluginsdk.Result{}, err
	}
	if strings.TrimSpace(in.UserID) == "" {
		return pluginsdk.Result{}, invalidField("/user_id", "REQUIRED", "user_id 不能为空")
	}
	user, err := i.ledger.AdjustUserQuota(ctx, strings.TrimSpace(in.UserID), in.DeltaMicros, in.GroupName, in.Status, in.AutoRefillCapMicros, in.AutoRefillCycle, in.Note)
	if err != nil {
		return pluginsdk.Result{}, mapStoreError(err)
	}
	return marshalResult(map[string]any{
		"user_id":                user.ID,
		"group_name":             user.GroupName,
		"status":                 user.Status,
		"balance_micros":         user.BalanceMicros,
		"auto_refill_cap_micros": user.AutoRefillCapMicros,
		"auto_refill_cycle":      user.AutoRefillCycle,
		"updated_at":             user.UpdatedAt,
	})
}

func (i *instance) handleCodesGenerate(ctx context.Context, req pluginsdk.Request, _ pluginsdk.Progress) (pluginsdk.Result, error) {
	var in struct {
		Kind           string `json:"kind"`
		Title          string `json:"title"`
		AmountMicros   int64  `json:"amount_micros"`
		Count          int    `json:"count"`
		MaxUses        int    `json:"max_uses"`
		GrantGroup     string `json:"grant_group"`
		CustomCode     string `json:"custom_code"`
		ExpiresInHours int    `json:"expires_in_hours"`
	}
	if err := decodeStrictJSON(req.Payload, &in); err != nil {
		return pluginsdk.Result{}, err
	}
	if in.Count == 0 {
		in.Count = 1
	}
	codes, expMs, err := i.ledger.GenerateCodes(ctx, in.Kind, in.Title, in.AmountMicros, in.Count, in.MaxUses, in.GrantGroup, in.CustomCode, in.ExpiresInHours)
	if err != nil {
		return pluginsdk.Result{}, mapStoreError(err)
	}
	return marshalResult(map[string]any{
		"kind":          in.Kind,
		"codes":         codes,
		"amount_micros": in.AmountMicros,
		"expires_at":    expMs,
	})
}

// ======================== 公开路由（ServePublicRoute + 零缓冲 ServeHTTP SSE） ========================

const maxBufferedPublicRespBytes = 16 << 20

type boundedResponseWriter struct {
	hdr     http.Header
	status  int
	buf     bytes.Buffer
	limit   int
	clipped bool
}

func newBoundedResponseWriter(limit int) *boundedResponseWriter {
	return &boundedResponseWriter{
		hdr:    make(http.Header),
		status: http.StatusOK,
		limit:  limit,
	}
}

func (b *boundedResponseWriter) Header() http.Header { return b.hdr }

func (b *boundedResponseWriter) WriteHeader(code int) {
	if code > 0 {
		b.status = code
	}
}

func (b *boundedResponseWriter) Write(p []byte) (int, error) {
	rem := b.limit - b.buf.Len()
	if rem <= 0 {
		b.clipped = true
		return len(p), nil
	}
	if len(p) > rem {
		b.clipped = true
		_, _ = b.buf.Write(p[:rem])
		return len(p), nil
	}
	return b.buf.Write(p)
}

func buildPublicHTTPRequest(ctx context.Context, req pluginsdk.PublicRouteRequest, body io.Reader) (*http.Request, error) {
	path := req.Path
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	// 若宿主剥离了路由前缀，则按 req.Route 补齐标准路径供统一路由器派发。
	if req.Route != "" && !strings.HasPrefix(path, "/"+req.Route+"/") && path != "/"+req.Route {
		path = "/" + req.Route + path
	}
	target := path
	if req.RawQuery != "" {
		target += "?" + req.RawQuery
	}
	httpReq, err := http.NewRequestWithContext(ctx, req.Method, target, body)
	if err != nil {
		return nil, err
	}
	for _, h := range req.Headers {
		httpReq.Header.Add(h.Name, h.Value)
	}
	return httpReq, nil
}

// ServePublicStream 零缓冲直接向 http.ResponseWriter 流式转发公开路由响应（供流式 SSE / 长思考使用）。
func (i *instance) ServePublicStream(ctx context.Context, req pluginsdk.PublicRouteRequest, body io.Reader, w http.ResponseWriter) error {
	if body == nil {
		body = bytes.NewReader(req.Body)
	}
	httpReq, err := buildPublicHTTPRequest(ctx, req, body)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad_request"})
		return nil
	}
	i.ServeHTTP(w, httpReq)
	return nil
}

// ServePublicRoute 实现 pluginsdk.PublicRouteHandler，复用同一 HTTP 路由器服务 v1/v1beta/portal，
// 并使用有界写入器替代无上限 httptest.NewRecorder() 防止大响应击穿插件内存限制。
func (i *instance) ServePublicRoute(ctx context.Context, req pluginsdk.PublicRouteRequest) (pluginsdk.PublicRouteResponse, error) {
	httpReq, err := buildPublicHTTPRequest(ctx, req, bytes.NewReader(req.Body))
	if err != nil {
		return pluginsdk.PublicRouteResponse{Status: 400, Body: []byte("bad request")}, nil
	}

	bw := newBoundedResponseWriter(maxBufferedPublicRespBytes)
	i.ServeHTTP(bw, httpReq)

	hdrs := make([]pluginsdk.HTTPHeader, 0, len(bw.hdr))
	for name, vals := range bw.hdr {
		lower := strings.ToLower(name)
		for _, v := range vals {
			hdrs = append(hdrs, pluginsdk.HTTPHeader{Name: lower, Value: v})
		}
	}
	return pluginsdk.PublicRouteResponse{
		Status:  uint32(bw.status),
		Headers: hdrs,
		Body:    bw.buf.Bytes(),
	}, nil
}

// ServeHTTP 实现标准 http.Handler，支持零缓冲 SSE 流式转发与独立分发用户门户 SPA。
func (i *instance) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p := r.URL.Path
	p = strings.TrimPrefix(p, "/p/ai.relay")
	if p == "" {
		p = "/"
	}

	switch {
	case strings.HasPrefix(p, "/v1/"), p == "/v1":
		i.handleRelayAPI(w, r, p)
	case strings.HasPrefix(p, "/v1beta/"), p == "/v1beta":
		i.handleRelayAPI(w, r, p)
	case strings.HasPrefix(p, "/portal/"), p == "/portal":
		i.handlePortalHTTP(w, r, p)
	default:
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not_found", "message": "route not found"})
	}
}

func (i *instance) handleRelayAPI(w http.ResponseWriter, r *http.Request, cleanPath string) {
	rawKey := extractRelayAPIKey(r)
	if rawKey == "" || strings.HasPrefix(rawKey, "qwq_") {
		writeJSON(w, http.StatusUnauthorized, map[string]string{
			"error":   "unauthorized",
			"message": "需要合法的 sk-qwq-* 分发令牌（绝不接受面板凭据）",
		})
		return
	}

	if cleanPath == "/v1/models" && r.Method == http.MethodGet {
		tok, resv, err := i.ledger.AuthorizeAndReserve(rawKey, "", ExtractTrustedClientIP(r), 1)
		if err != nil {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized", "message": err.Error()})
			return
		}
		resv.Settle(0, store.UsageLogRecord{})
		chs, _ := i.ledger.ListChannels(r.Context(), "", 256, false)
		modelSet := make(map[string]struct{})
		for _, ch := range chs {
			if !ch.Enabled || !slices.Contains(ch.Groups, tok.EffectiveGroup()) {
				continue
			}
			for _, m := range ch.Models {
				modelSet[m] = struct{}{}
			}
		}
		data := make([]map[string]any, 0, len(modelSet))
		for m := range modelSet {
			data = append(data, map[string]any{"id": m, "object": "model", "owned_by": "ai.relay"})
		}
		writeJSON(w, http.StatusOK, map[string]any{"object": "list", "data": data})
		return
	}

	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method_not_allowed"})
		return
	}

	protoIn, urlModel, ok := detectDownstreamProtocol(cleanPath)
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not_found", "message": "unsupported AI endpoint"})
		return
	}

	rawBody, err := io.ReadAll(io.LimitReader(r.Body, 16<<20))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad_request", "message": "failed to read body"})
		return
	}
	ir, err := proxy.ParseDownstreamRequest(protoIn, urlModel, rawBody)
	if err != nil || ir.Model == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request", "message": "invalid protocol payload or missing model"})
		return
	}
	if protoIn == proxy.ProtoGeminiNative && strings.HasSuffix(cleanPath, ":generateContent") {
		ir.Stream = false
	}

	cfg := i.configSnapshot()
	pricing := i.router.PricingFor(ir.Model)
	reserveMicros := ComputeDynamicReserveMicros(DynamicReserveInput{
		DefaultReserveMicros: cfg.DefaultReserveMicros,
		EstimatedInputTokens: ir.EstimatedInputTokens,
		RequestedMaxTokens:   ir.MaxTokens,
		InputMicrosPer1K:     pricing.InputMicrosPer1K,
		OutputMicrosPer1K:    pricing.OutputMicrosPer1K,
		PerCallMicros:        pricing.PerCallMicros,
		BillingMode:          pricing.BillingMode,
	})
	tok, reservation, err := i.ledger.AuthorizeAndReserve(rawKey, ir.Model, ExtractTrustedClientIP(r), reserveMicros)
	if err != nil {
		status := http.StatusUnauthorized
		if strings.HasPrefix(err.Error(), "QUOTA_EXHAUSTED") {
			status = http.StatusPaymentRequired
		} else if strings.HasPrefix(err.Error(), "RATE_LIMITED") {
			status = http.StatusTooManyRequests
		} else if strings.HasPrefix(err.Error(), "MODEL_NOT_ALLOWED") || strings.HasPrefix(err.Error(), "IP_DENIED") || strings.HasPrefix(err.Error(), "USER_DISABLED") {
			status = http.StatusForbidden
		}
		writeJSON(w, status, map[string]string{"error": "rejected", "message": err.Error()})
		return
	}

	candidates := i.router.SelectCandidates(tok.EffectiveGroup(), ir.Model, ir.SessionHint, i.nowTime())
	if len(candidates) == 0 {
		reservation.Settle(0, store.UsageLogRecord{})
		i.publishAllChannelsTrippedAlert(r.Context(), tok.EffectiveGroup(), ir.Model, "当前分组无可用健康上游渠道")
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "no_upstream", "message": "当前分组无可用健康上游渠道"})
		return
	}

	startedAt := time.Now()
	client := i.clientSnapshot()
	var lastErrMsg string

	for _, ch := range candidates {
		if err := ch.AcquireSlot(r.Context()); err != nil {
			lastErrMsg = err.Error()
			continue
		}
		if refreshed, _ := ch.RefreshOAuthIfNeeded(r.Context(), client, i.nowTime()); refreshed {
			if bundleJSON, ok := ch.OAuthBundleJSON(); ok {
				if persistErr := i.ledger.PersistRefreshedChannelCredential(r.Context(), ch.ID, bundleJSON); persistErr != nil {
					log.Printf("ai.relay: persist refreshed oauth token failed (channel=%s): %v", ch.ID, persistErr)
				}
			}
		}
		upURL, hdrs, upBody, encErr := proxy.EncodeUpstreamRequest(ch, protoIn, rawBody, ir)
		if encErr != nil {
			ch.ReleaseSlot()
			lastErrMsg = encErr.Error()
			continue
		}
		upReq, reqErr := http.NewRequestWithContext(r.Context(), http.MethodPost, upURL, bytes.NewReader(upBody))
		if reqErr != nil {
			ch.ReleaseSlot()
			lastErrMsg = reqErr.Error()
			continue
		}
		for k, v := range hdrs {
			upReq.Header.Set(k, v)
		}
		upResp, doErr := client.Do(upReq)
		if doErr != nil {
			ch.ReleaseSlot()
			lastErrMsg = doErr.Error()
			continue
		}
		if upResp.StatusCode < 200 || upResp.StatusCode >= 300 {
			_, _ = io.CopyN(io.Discard, upResp.Body, 4096)
			_ = upResp.Body.Close()
			ch.MarkUpstreamStatus(upResp.StatusCode, 60*time.Second, i.nowTime())
			ch.ReleaseSlot()
			lastErrMsg = fmt.Sprintf("upstream %s returned %d", ch.ID, upResp.StatusCode)
			continue
		}

		var usage proxy.StreamUsage
		var relayErr error
		upCT := strings.ToLower(upResp.Header.Get("Content-Type"))
		if ch.NativeProtocol() == protoIn && (!ir.Stream || strings.Contains(upCT, "application/json")) {
			tw := &headerTrackingResponseWriter{ResponseWriter: w}
			usage, relayErr = proxy.RelayJSONResponseBridge(startedAt, upResp.Body, upResp.StatusCode, upResp.Header.Get("Content-Type"), ir.EstimatedInputTokens, tw)
			if relayErr != nil {
				log.Printf("ai.relay: non-stream relay failed (channel=%s model=%s): %v", ch.ID, ir.Model, relayErr)
				if !tw.wroteHeader {
					writeJSON(w, http.StatusBadGateway, map[string]string{"error": "upstream_relay_failed", "message": relayErr.Error()})
				}
			}
		} else if ch.NativeProtocol() != protoIn && !ir.Stream {
			tw := &headerTrackingResponseWriter{ResponseWriter: w}
			usage, relayErr = proxy.AggregateCanonicalNonStreamResponse(startedAt, upResp.Body, ch.NativeProtocol(), protoIn, ir.Model, ir.EstimatedInputTokens, tw)
			if relayErr != nil {
				log.Printf("ai.relay: cross-protocol non-stream aggregation failed (channel=%s model=%s): %v", ch.ID, ir.Model, relayErr)
				if !tw.wroteHeader {
					writeJSON(w, http.StatusBadGateway, map[string]string{"error": "upstream_relay_failed", "message": relayErr.Error()})
				}
			}
		} else {
			usage, _ = proxy.RelayStreamBridge(startedAt, upResp.Body, ch.NativeProtocol(), protoIn, ir.Model, w)
			if usage.InputTokens <= 0 && ir.EstimatedInputTokens > 0 {
				usage.InputTokens = ir.EstimatedInputTokens
			}
		}
		_ = upResp.Body.Close()
		ch.ReleaseSlot()

		settlePricing := i.router.PricingFor(ir.Model)
		cost := settlePricing.CalculateMicros(usage.InputTokens, usage.CachedReadTokens, usage.CacheWriteTokens, usage.OutputTokens, 1.0)
		reservation.Settle(cost, store.UsageLogRecord{
			UserID:           tok.User.UserID,
			TokenID:          tok.TokenID,
			TokenName:        tok.TokenName,
			ModelName:        ir.Model,
			ProtocolIn:       string(protoIn),
			InputTokens:      usage.InputTokens,
			CachedReadTokens: usage.CachedReadTokens,
			CacheWriteTokens: usage.CacheWriteTokens,
			OutputTokens:     usage.OutputTokens,
			TTFTMs:           usage.TTFTMs,
			DurationMs:       time.Since(startedAt).Milliseconds(),
			CreatedAtMs:      i.nowTime().UTC().UnixMilli(),
		})
		return
	}

	reservation.Settle(0, store.UsageLogRecord{})
	if len(i.router.SelectCandidates(tok.EffectiveGroup(), ir.Model, "", i.nowTime())) == 0 {
		i.publishAllChannelsTrippedAlert(r.Context(), tok.EffectiveGroup(), ir.Model, lastErrMsg)
	}
	writeJSON(w, http.StatusBadGateway, map[string]string{"error": "upstream_failed", "message": lastErrMsg})
}

func (i *instance) publishAllChannelsTrippedAlert(ctx context.Context, group, model, reason string) {
	host := i.Host()
	if host == nil || host.Conn() == nil {
		return
	}
	nowUTC := i.nowTime().UTC()
	nowMs := nowUTC.UnixMilli()
	payload, err := json.Marshal(map[string]any{
		"source":    "ai.relay",
		"severity":  "critical",
		"title":     fmt.Sprintf("AI 中转模型 %s 全部上游渠道熔断", model),
		"message":   fmt.Sprintf("分组 %s 下模型 %s 已无可用健康上游渠道：%s", group, model, reason),
		"dedup_key": fmt.Sprintf("ai.relay:all_tripped:%s:%s", group, model),
		"tags": map[string]string{
			"group":   group,
			"model":   model,
			"reason":  reason,
			"time_ms": fmt.Sprintf("%d", nowMs),
		},
		"timestamp": nowUTC,
		"group":     group,
		"model":     model,
		"reason":    reason,
		"time_ms":   nowMs,
	})
	if err != nil {
		return
	}
	pctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	if _, err := host.PublishEvent(pctx, pluginsdk.EventDraft{
		Type:          "relay.alert",
		SchemaVersion: "1",
		Subject:       "channels/all_tripped",
		Payload:       payload,
	}); err != nil {
		log.Printf("ai.relay: publish relay.alert failed (group=%s model=%s): %v", group, model, err)
	}
}

func (i *instance) handlePortalHTTP(w http.ResponseWriter, r *http.Request, cleanPath string) {
	subPath := strings.TrimPrefix(cleanPath, "/portal")
	if subPath == "" || subPath == "/" || subPath == "/index.html" {
		raw, err := fs.ReadFile(embeddedPortalUI, "portal_ui/index.html")
		if err != nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(raw)
		return
	}
	if subPath == "/portal.css" {
		raw, err := fs.ReadFile(embeddedPortalUI, "portal_ui/portal.css")
		if err != nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/css; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(raw)
		return
	}
	if subPath == "/portal.js" {
		raw, err := fs.ReadFile(embeddedPortalUI, "portal_ui/portal.js")
		if err != nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(raw)
		return
	}

	switch {
	case subPath == "/api/auth/send-email-code" && r.Method == http.MethodPost:
		var in struct {
			Email string `json:"email"`
		}
		if json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&in) != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"message": "请求格式无效"})
			return
		}
		if err := i.ledger.SendEmailOTPWithDelivery(r.Context(), in.Email, ExtractTrustedClientIP(r)); err != nil {
			code := http.StatusBadRequest
			if strings.HasPrefix(err.Error(), "RATE_LIMITED") {
				code = http.StatusTooManyRequests
			} else if strings.HasPrefix(err.Error(), "SMTP_NOT_CONFIGURED") {
				code = http.StatusServiceUnavailable
			}
			writeJSON(w, code, map[string]string{"message": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"sent": true})

	case subPath == "/api/auth/submit" && r.Method == http.MethodPost:
		var in struct {
			Mode       string `json:"mode"`
			Username   string `json:"username"`
			Password   string `json:"password"`
			InviteCode string `json:"invite_code"`
			Email      string `json:"email"`
			EmailCode  string `json:"email_code"`
		}
		if json.NewDecoder(io.LimitReader(r.Body, 8192)).Decode(&in) != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"message": "请求格式无效"})
			return
		}
		var userID string
		var err error
		switch in.Mode {
		case "invite":
			userID, err = i.ledger.SignupWithInviteCode(r.Context(), in.Username, in.Password, in.InviteCode)
		case "email":
			userID, err = i.ledger.SignupWithEmailOTP(r.Context(), in.Username, in.Password, in.Email, in.EmailCode)
		default:
			userID, err = i.ledger.AuthenticatePassword(r.Context(), in.Username, in.Password)
		}
		if err != nil {
			code := http.StatusBadRequest
			if strings.HasPrefix(err.Error(), "UNAUTHENTICATED") {
				code = http.StatusUnauthorized
			} else if strings.HasPrefix(err.Error(), "RATE_LIMITED") {
				code = http.StatusTooManyRequests
			}
			writeJSON(w, code, map[string]string{"message": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"user_id":       userID,
			"session_token": i.ledger.CreateSession(userID),
		})

	case subPath == "/api/oauth/linuxdo/start" && r.Method == http.MethodGet:
		clientID, _, err := i.ledger.GetLinuxDoCredentials(r.Context())
		if err != nil || clientID == "" {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"message": "未配置 LinuxDo OAuth2 Client ID"})
			return
		}
		state, _, challenge := i.ledger.CreateOAuthState()
		redirectURI := i.oauthCallbackURL(r)
		authURL := fmt.Sprintf("https://connect.linux.do/oauth2/authorize?response_type=code&client_id=%s&redirect_uri=%s&state=%s&code_challenge=%s&code_challenge_method=S256",
			url.QueryEscape(clientID), url.QueryEscape(redirectURI), url.QueryEscape(state), url.QueryEscape(challenge))
		http.Redirect(w, r, authURL, http.StatusFound)

	case subPath == "/api/oauth/linuxdo/callback" && r.Method == http.MethodGet:
		state := r.URL.Query().Get("state")
		code := r.URL.Query().Get("code")
		verifier, ok := i.ledger.ConsumeOAuthState(state)
		if !ok || code == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"message": "无效或已过期的 OAuth state"})
			return
		}
		clientID, clientSecret, err := i.ledger.GetLinuxDoCredentials(r.Context())
		if err != nil || clientID == "" {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"message": "未配置 LinuxDo 凭据"})
			return
		}
		userID, _, _, err := i.ledger.LoginOrSignupWithLinuxDo(r.Context(), clientID, clientSecret, i.oauthCallbackURL(r), code, verifier)
		if err != nil {
			writeJSON(w, http.StatusForbidden, map[string]string{"message": err.Error()})
			return
		}
		sess := i.ledger.CreateSession(userID)
		http.Redirect(w, r, "/p/ai.relay/portal/#relay_session="+url.QueryEscape(sess), http.StatusFound)

	default:
		// 其余门户接口严格校验 rly_sess_* 隔离会话，兼容宿主转发的 X-QWQ-Relay-Token，绝不接受 qwq_* 面板令牌！
		sessTok, err := ExtractPortalSessionToken(r)
		if err != nil {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"message": err.Error()})
			return
		}
		userID, ok := i.ledger.ValidateSession(sessTok)
		if !ok {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"message": "请先登录分发门户"})
			return
		}
		i.handlePortalAuthed(w, r, subPath, userID, sessTok)
	}
}

func (i *instance) handlePortalAuthed(w http.ResponseWriter, r *http.Request, subPath, userID, sessTok string) {
	switch {
	case subPath == "/api/auth/logout" && r.Method == http.MethodPost:
		i.ledger.DeleteSession(sessTok)
		writeJSON(w, http.StatusOK, map[string]any{"logged_out": true})

	case subPath == "/api/me" && r.Method == http.MethodGet:
		user, err := i.ledger.GetUserByID(r.Context(), userID)
		if err != nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"message": err.Error()})
			return
		}
		tokens, _ := i.ledger.ListUserTokens(r.Context(), userID)
		models, _ := i.ledger.ListPricings(r.Context())
		logs, _ := i.ledger.ListUserRecentLogs(r.Context(), userID, 20)
		writeJSON(w, http.StatusOK, map[string]any{
			"user":        user,
			"tokens":      tokens,
			"models":      models,
			"recent_logs": logs,
		})

	case subPath == "/api/quota/checkin" && r.Method == http.MethodPost:
		granted, bal, err := i.ledger.DailyCheckIn(r.Context(), userID)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"message": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"granted_micros": granted, "balance_micros": bal})

	case subPath == "/api/quota/redeem" && r.Method == http.MethodPost:
		var in struct {
			Code string `json:"code"`
		}
		if json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&in) != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"message": "请求格式无效"})
			return
		}
		granted, bal, err := i.ledger.RedeemCode(r.Context(), userID, in.Code)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"message": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"granted_micros": granted, "balance_micros": bal})

	case subPath == "/api/tokens" && r.Method == http.MethodPost:
		var in struct {
			Name             string   `json:"name"`
			QuotaLimitMicros int64    `json:"quota_limit_micros"`
			AllowedModels    []string `json:"allowed_models"`
			AllowedIPs       []string `json:"allowed_ips"`
			RPMLimit         int      `json:"rpm_limit"`
			ExpiresAt        int64    `json:"expires_at"`
		}
		if json.NewDecoder(io.LimitReader(r.Body, 8192)).Decode(&in) != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"message": "请求格式无效"})
			return
		}
		plainKey, err := i.ledger.MintSubKey(r.Context(), userID, in.Name, in.QuotaLimitMicros, in.AllowedModels, in.AllowedIPs, in.RPMLimit, in.ExpiresAt)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"message": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"plain_key": plainKey})

	case strings.HasPrefix(subPath, "/api/tokens/") && r.Method == http.MethodDelete:
		tokID := strings.TrimSpace(strings.TrimPrefix(subPath, "/api/tokens/"))
		if tokID == "" || strings.Contains(tokID, "/") {
			writeJSON(w, http.StatusBadRequest, map[string]string{"message": "无效的令牌 ID"})
			return
		}
		revoked, err := i.ledger.RevokeUserToken(r.Context(), userID, tokID)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"message": err.Error()})
			return
		}
		if !revoked {
			writeJSON(w, http.StatusNotFound, map[string]string{"message": "未找到该子令牌"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"id": tokID, "revoked": true})

	default:
		writeJSON(w, http.StatusNotFound, map[string]string{"message": "portal api not found"})
	}
}

// ======================== 协议识别、凭据提取与通用编解码辅助 ========================

func extractRelayAPIKey(r *http.Request) string {
	if v := strings.TrimSpace(r.Header.Get("X-QWQ-Relay-Token")); v != "" {
		return v
	}
	if auth := strings.TrimSpace(r.Header.Get("Authorization")); auth != "" {
		if after, ok := strings.CutPrefix(auth, "Bearer "); ok {
			return strings.TrimSpace(after)
		}
		if after, ok := strings.CutPrefix(auth, "bearer "); ok {
			return strings.TrimSpace(after)
		}
	}
	if v := strings.TrimSpace(r.Header.Get("x-api-key")); v != "" {
		return v
	}
	if v := strings.TrimSpace(r.Header.Get("x-goog-api-key")); v != "" {
		return v
	}
	return strings.TrimSpace(r.URL.Query().Get("key"))
}

func detectDownstreamProtocol(cleanPath string) (proxy.ProtocolKind, string, bool) {
	switch cleanPath {
	case "/v1/chat/completions":
		return proxy.ProtoOpenAIChat, "", true
	case "/v1/responses":
		return proxy.ProtoOpenAIResponses, "", true
	case "/v1/messages":
		return proxy.ProtoAnthropicMessages, "", true
	}
	if after, ok := strings.CutPrefix(cleanPath, "/v1beta/models/"); ok {
		model, action, found := strings.Cut(after, ":")
		if found && model != "" && (action == "streamGenerateContent" || action == "generateContent") {
			return proxy.ProtoGeminiNative, model, true
		}
	}
	return "", "", false
}

func (i *instance) oauthCallbackURL(r *http.Request) string {
	if origin := strings.TrimRight(strings.TrimSpace(i.configSnapshot().PublicOrigin), "/"); origin != "" {
		return origin + "/p/ai.relay/portal/api/oauth/linuxdo/callback"
	}
	scheme := strings.ToLower(strings.TrimSpace(r.Header.Get("X-Forwarded-Proto")))
	if scheme != "https" && scheme != "http" {
		if r.TLS != nil {
			scheme = "https"
		} else {
			scheme = "http"
		}
	}
	host := strings.TrimSpace(r.Host)
	if host == "" {
		host = "localhost"
	}
	return scheme + "://" + host + "/p/ai.relay/portal/api/oauth/linuxdo/callback"
}

func validChannelKind(k string) bool {
	switch proxy.ChannelKind(k) {
	case proxy.ChanOpenAICompat, proxy.ChanAnthropicNative, proxy.ChanGeminiNative,
		proxy.ChanSub2ClaudeOAuth, proxy.ChanSub2CodexOAuth, proxy.ChanSub2GeminiOAuth:
		return true
	default:
		return false
	}
}

func mapStoreError(err error) error {
	if err == nil {
		return nil
	}
	var pe *pluginsdk.Error
	if errors.As(err, &pe) {
		return pe
	}
	msg := err.Error()
	if code, rest, ok := strings.Cut(msg, ":"); ok && code == strings.ToUpper(code) && len(code) <= 32 {
		return &pluginsdk.Error{Code: strings.TrimSpace(code), Message: strings.TrimSpace(rest)}
	}
	return pluginsdk.Errorf("INTERNAL", "%s", msg)
}

type headerTrackingResponseWriter struct {
	http.ResponseWriter
	wroteHeader bool
}

func (w *headerTrackingResponseWriter) WriteHeader(code int) {
	w.wroteHeader = true
	w.ResponseWriter.WriteHeader(code)
}

func (w *headerTrackingResponseWriter) Write(p []byte) (int, error) {
	w.wroteHeader = true
	return w.ResponseWriter.Write(p)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func invalidField(pointer, code, message string) error {
	return pluginsdk.Validation(pluginsdk.FieldViolation{
		Pointer: pointer,
		Code:    code,
		Message: message,
	})
}

func decodeOptionalJSON(raw []byte, dst any) error {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return nil
	}
	return decodeStrictJSON(trimmed, dst)
}

func decodeStrictJSON(raw []byte, dst any) error {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return invalidField("", "REQUIRED", "请求体不能为空")
	}
	dec := json.NewDecoder(bytes.NewReader(trimmed))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return invalidField("", "INVALID_JSON", "请求参数 JSON 格式无效或包含未知字段")
	}
	if err := dec.Decode(new(any)); err != io.EOF {
		return invalidField("", "INVALID_JSON", "请求参数包含多余内容")
	}
	return nil
}

func marshalResponse(v any) (pluginsdk.Response, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return pluginsdk.Response{}, fmt.Errorf("encode response: %w", err)
	}
	return pluginsdk.Response{Payload: raw}, nil
}

func marshalResult(v any) (pluginsdk.Result, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return pluginsdk.Result{}, fmt.Errorf("encode result: %w", err)
	}
	return pluginsdk.Result{Payload: raw}, nil
}
