// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/qwq-panel/qwq/sdk/pluginsdk"
)

//go:embed manifest.json
var manifestJSON []byte

//go:embed schema.sql
var embeddedSchemaSQL string

var buildVersion string

// Manifest 返回内嵌的 notify.hub 插件清单字节。
func Manifest() []byte {
	raw := append([]byte(nil), manifestJSON...)
	if buildVersion != "" {
		raw = bytes.Replace(raw, []byte(`"version": "0.1.0"`), []byte(`"version": "`+buildVersion+`"`), 1)
	}
	return raw
}

type pluginConfig struct {
	AllowPrivateEndpoints bool `json:"allow_private_endpoints"`
	HTTPTimeoutSeconds    int  `json:"http_timeout_seconds"`
}

func parseConfig(raw []byte) (pluginConfig, error) {
	cfg := pluginConfig{HTTPTimeoutSeconds: 10}
	if len(bytes.TrimSpace(raw)) == 0 {
		return cfg, nil
	}
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return cfg, pluginsdk.Errorf("INVALID_ARGUMENT", "解析 notify.hub 配置失败: %s", err.Error())
	}
	if cfg.HTTPTimeoutSeconds <= 0 || cfg.HTTPTimeoutSeconds > 60 {
		cfg.HTTPTimeoutSeconds = 10
	}
	return cfg, nil
}

// Plugin 实现统一告警与通知中枢插件。
type Plugin struct {
	now        func() time.Time
	httpClient *http.Client
}

// New 构造默认 notify.hub 插件。
func New() *Plugin { return &Plugin{} }

func (p *Plugin) NewInstance(_ context.Context, info pluginsdk.InstanceInfo) (pluginsdk.Instance, error) {
	cfg, err := parseConfig(info.Config)
	if err != nil {
		return nil, err
	}
	nowFn := p.now
	if nowFn == nil {
		nowFn = time.Now
	}
	st, err := openStore(info.DataDir, embeddedSchemaSQL, nowFn)
	if err != nil {
		return nil, pluginsdk.Errorf("INTERNAL", "初始化通知中枢数据库失败: %s", err.Error())
	}
	client := p.httpClient
	if client == nil {
		client = newSafeHTTPClient(cfg.AllowPrivateEndpoints, time.Duration(cfg.HTTPTimeoutSeconds)*time.Second)
	}
	inst := &instance{
		InstanceBase: pluginsdk.NewInstanceBase(info),
		cfg:          cfg,
		store:        st,
		engine:       newRouterEngine(st, client, cfg.AllowPrivateEndpoints, nowFn),
		customClient: p.httpClient,
		now:          nowFn,
	}
	for _, op := range []string{
		"notify.stat.summary",
		"notify.checks.channels",
		"notify.overview",
		"notify.ai.digest",
		"notify.channel.upsert",
		"notify.channel.delete",
		"notify.channel.test",
		"notify.rule.upsert",
		"notify.rule.delete",
		"notify.dispatch",
	} {
		opName := op
		inst.HandleInvoke(opName, func(c context.Context, req pluginsdk.Request) (pluginsdk.Response, error) {
			req.Operation = opName
			return inst.Invoke(c, req)
		})
	}
	return inst, nil
}

type instance struct {
	*pluginsdk.InstanceBase
	cfgMu        sync.RWMutex
	cfg          pluginConfig
	customClient *http.Client
	store        *store
	engine       *routerEngine
	now          func() time.Time
}

func (i *instance) Deactivate(_ context.Context) error {
	return nil
}

func (i *instance) Stop(_ context.Context) error {
	return i.store.Close()
}

func (i *instance) Release(_ context.Context) error {
	return i.store.Close()
}

func (i *instance) ValidateConfig(_ context.Context, cand pluginsdk.Config) (pluginsdk.ConfigValidation, error) {
	if _, err := parseConfig(cand.JSON); err != nil {
		return pluginsdk.ConfigValidation{}, err
	}
	return pluginsdk.ConfigValidation{}, nil
}

func (i *instance) ApplyConfig(_ context.Context, cand pluginsdk.Config) error {
	cfg, err := parseConfig(cand.JSON)
	if err != nil {
		return err
	}
	i.cfgMu.Lock()
	i.cfg = cfg
	client := i.customClient
	i.cfgMu.Unlock()
	if client == nil {
		client = newSafeHTTPClient(cfg.AllowPrivateEndpoints, time.Duration(cfg.HTTPTimeoutSeconds)*time.Second)
	}
	i.engine.UpdateClient(client, cfg.AllowPrivateEndpoints)
	return nil
}

func (i *instance) Health(context.Context) pluginsdk.Health {
	return pluginsdk.Health{Message: "notify.hub 运行正常"}
}

func (i *instance) Invoke(ctx context.Context, req pluginsdk.Request) (pluginsdk.Response, error) {
	switch req.Operation {
	case "notify.stat.summary":
		return i.handleStatSummary(ctx)
	case "notify.checks.channels":
		return i.handleChecksChannels(ctx)
	case "notify.overview":
		return i.handleOverview(ctx)
	case "notify.ai.digest":
		return i.handleAIDigest(ctx)
	case "notify.channel.upsert":
		return i.handleChannelUpsert(ctx, req.Payload)
	case "notify.channel.delete":
		return i.handleChannelDelete(ctx, req.Payload)
	case "notify.channel.test":
		return i.handleChannelTest(ctx, req.Payload)
	case "notify.rule.upsert":
		return i.handleRuleUpsert(ctx, req.Payload)
	case "notify.rule.delete":
		return i.handleRuleDelete(ctx, req.Payload)
	case "notify.dispatch":
		return i.handleDispatch(ctx, req.Payload)
	default:
		return pluginsdk.Response{}, pluginsdk.Errorf("NOT_FOUND", "未知操作: %s", req.Operation)
	}
}

func jsonResp(v any) (pluginsdk.Response, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return pluginsdk.Response{}, pluginsdk.Errorf("INTERNAL", "序列化响应失败")
	}
	return pluginsdk.Response{Payload: raw}, nil
}

func (i *instance) handleStatSummary(ctx context.Context) (pluginsdk.Response, error) {
	channels, err := i.store.listChannels(ctx)
	if err != nil {
		return pluginsdk.Response{}, pluginsdk.Errorf("INTERNAL", "%s", err.Error())
	}
	enabled := 0
	for _, c := range channels {
		if c.Enabled {
			enabled++
		}
	}
	sent, failed, suppressed := i.store.stats24h(ctx)
	status := "ok"
	if failed > 0 {
		status = "warn"
	}
	return jsonResp(map[string]any{
		"value":  fmt.Sprintf("%d 渠道", enabled),
		"unit":   fmt.Sprintf("24h 发出 %d / 失败 %d", sent, failed),
		"status": status,
		"detail": fmt.Sprintf("总渠道 %d，降噪静默 %d", len(channels), suppressed),
	})
}

func (i *instance) handleChecksChannels(ctx context.Context) (pluginsdk.Response, error) {
	channels, err := i.store.listChannels(ctx)
	if err != nil {
		return pluginsdk.Response{}, pluginsdk.Errorf("INTERNAL", "%s", err.Error())
	}
	items := make([]map[string]any, 0, len(channels))
	for _, c := range channels {
		st := "ok"
		msg := c.Kind
		if !c.Enabled {
			st = "unknown"
			msg = c.Kind + " (已停用)"
		} else if c.LastStatus == "error" {
			st = "error"
			msg = c.LastError
		}
		items = append(items, map[string]any{
			"name":    c.Name,
			"status":  st,
			"message": msg,
		})
	}
	return jsonResp(map[string]any{"items": items})
}

func (i *instance) handleOverview(ctx context.Context) (pluginsdk.Response, error) {
	channels, err := i.store.listChannels(ctx)
	if err != nil {
		return pluginsdk.Response{}, pluginsdk.Errorf("INTERNAL", "%s", err.Error())
	}
	rules, err := i.store.listRules(ctx)
	if err != nil {
		return pluginsdk.Response{}, pluginsdk.Errorf("INTERNAL", "%s", err.Error())
	}
	deliveries, err := i.store.listDeliveries(ctx, 50)
	if err != nil {
		return pluginsdk.Response{}, pluginsdk.Errorf("INTERNAL", "%s", err.Error())
	}
	sent, failed, suppressed := i.store.stats24h(ctx)
	return jsonResp(map[string]any{
		"channels":       channels,
		"rules":          rules,
		"deliveries":     deliveries,
		"sent_24h":       sent,
		"failed_24h":     failed,
		"suppressed_24h": suppressed,
	})
}

func (i *instance) handleAIDigest(ctx context.Context) (pluginsdk.Response, error) {
	channels, _ := i.store.listChannels(ctx)
	rules, _ := i.store.listRules(ctx)
	deliveries, _ := i.store.listDeliveries(ctx, 20)
	sent, failed, suppressed := i.store.stats24h(ctx)

	unhealthy := make([]map[string]any, 0)
	enabledCh := 0
	for _, c := range channels {
		if c.Enabled {
			enabledCh++
		}
		if c.LastStatus == "error" {
			unhealthy = append(unhealthy, map[string]any{
				"id": c.ID, "name": c.Name, "kind": c.Kind, "error": c.LastError,
			})
		}
	}
	recentFails := make([]map[string]any, 0)
	for _, d := range deliveries {
		if d.Status == "failed" && len(recentFails) < 5 {
			recentFails = append(recentFails, map[string]any{
				"channel": d.ChannelName, "source": d.Source, "title": d.Title, "error": d.ErrorMsg,
			})
		}
	}
	return jsonResp(map[string]any{
		"channels_total":     len(channels),
		"channels_enabled":   enabledCh,
		"rules_total":        len(rules),
		"sent_24h":           sent,
		"failed_24h":         failed,
		"suppressed_24h":     suppressed,
		"unhealthy_channels": unhealthy,
		"recent_failures":    recentFails,
	})
}

// DefaultNotifyRuleSeed 描述首次添加通知渠道时自动生成的默认全局告警规则。
type DefaultNotifyRuleSeed struct {
	ID            string   `json:"id"`
	Name          string   `json:"name"`
	SourcePattern string   `json:"source_pattern"`
	MinSeverity   string   `json:"min_severity"`
	ChannelIDs    []string `json:"channel_ids"`
	CooldownSec   int      `json:"cooldown_sec"`
	Enabled       bool     `json:"enabled"`
}

// BuildAutoCatchAllNotifyRuleIfEmpty 当规则表为空且首次创建启用渠道时生成默认全局路由，
// 消除“测试渠道能收到，真实系统告警却静默丢弃”的反直觉陷阱。
func BuildAutoCatchAllNotifyRuleIfEmpty(existingRuleCount int, firstChannelID string) *DefaultNotifyRuleSeed {
	if existingRuleCount > 0 || strings.TrimSpace(firstChannelID) == "" {
		return nil
	}
	return &DefaultNotifyRuleSeed{
		ID:            "rule-default-all",
		Name:          "默认全局重要告警转发（自动创建）",
		SourcePattern: "*",
		MinSeverity:   "warn",
		ChannelIDs:    []string{strings.TrimSpace(firstChannelID)},
		CooldownSec:   300,
		Enabled:       true,
	}
}

func (i *instance) handleChannelUpsert(ctx context.Context, payload []byte) (pluginsdk.Response, error) {
	var req struct {
		ID       string        `json:"id"`
		Name     string        `json:"name"`
		Kind     string        `json:"kind"`
		Enabled  *bool         `json:"enabled"`
		AutoRule *bool         `json:"auto_rule"`
		Config   ChannelConfig `json:"config"`
	}
	if err := json.Unmarshal(payload, &req); err != nil {
		return pluginsdk.Response{}, pluginsdk.Errorf("INVALID_ARGUMENT", "请求格式错误: %s", err.Error())
	}
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" || len(req.Name) > 64 {
		return pluginsdk.Response{}, pluginsdk.Errorf("INVALID_ARGUMENT", "渠道名称必须为 1-64 个字符")
	}
	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}
	autoRule := true
	if req.AutoRule != nil {
		autoRule = *req.AutoRule
	}
	rec, autoCreated, err := i.store.upsertChannelWithAutoRule(ctx, strings.TrimSpace(req.ID), req.Name, req.Kind, enabled, req.Config, autoRule)
	if err != nil {
		return pluginsdk.Response{}, pluginsdk.Errorf("INVALID_ARGUMENT", "%s", err.Error())
	}
	out := map[string]any{"channel": rec}
	if autoCreated != nil {
		out["auto_created_rule"] = *autoCreated
	}
	return jsonResp(out)
}

func (i *instance) handleChannelDelete(ctx context.Context, payload []byte) (pluginsdk.Response, error) {
	var req struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(payload, &req); err != nil || strings.TrimSpace(req.ID) == "" {
		return pluginsdk.Response{}, pluginsdk.Errorf("INVALID_ARGUMENT", "缺少渠道 id")
	}
	deleted, err := i.store.deleteChannel(ctx, strings.TrimSpace(req.ID))
	if err != nil {
		return pluginsdk.Response{}, pluginsdk.Errorf("INTERNAL", "%s", err.Error())
	}
	return jsonResp(map[string]any{"deleted": deleted, "id": strings.TrimSpace(req.ID)})
}

func (i *instance) handleChannelTest(ctx context.Context, payload []byte) (pluginsdk.Response, error) {
	var req struct {
		ID      string `json:"id"`
		Message string `json:"message"`
	}
	if err := json.Unmarshal(payload, &req); err != nil || strings.TrimSpace(req.ID) == "" {
		return pluginsdk.Response{}, pluginsdk.Errorf("INVALID_ARGUMENT", "缺少渠道 id")
	}
	ch, err := i.store.getChannelWithSecret(ctx, strings.TrimSpace(req.ID))
	if err != nil {
		return pluginsdk.Response{}, pluginsdk.Errorf("NOT_FOUND", "通知渠道不存在")
	}
	msg := strings.TrimSpace(req.Message)
	if msg == "" {
		msg = "这是一条来自 qwq 统一通知中枢（notify.hub）的连通性测试消息。"
	}
	ev := NotifyEvent{
		EventID:   newID("ntst"),
		Source:    "notify.hub",
		Severity:  "info",
		Title:     "通道连通性测试 · " + ch.Name,
		Message:   msg,
		Timestamp: i.now().UTC(),
	}
	client, allowPrivate := i.engine.snapshotClient()
	out := dispatchChannel(ctx, client, allowPrivate, ch, ev)
	rec := DeliveryRecord{
		ID:          newID("ndl"),
		EventID:     ev.EventID,
		Source:      ev.Source,
		Severity:    ev.Severity,
		Title:       ev.Title,
		ChannelID:   ch.ID,
		ChannelName: ch.Name,
		Attempts:    1,
		HTTPStatus:  out.HTTPStatus,
		CreatedAt:   ev.Timestamp.Unix(),
	}
	if out.Err != nil {
		rec.Status = "failed"
		rec.ErrorMsg = out.Err.Error()
		i.store.markChannelStatus(ctx, ch.ID, "error", rec.ErrorMsg)
		_ = i.store.recordDelivery(ctx, rec)
		return jsonResp(map[string]any{"ok": false, "http_status": out.HTTPStatus, "error": rec.ErrorMsg})
	}
	rec.Status = "sent"
	i.store.markChannelStatus(ctx, ch.ID, "ok", "")
	_ = i.store.recordDelivery(ctx, rec)
	return jsonResp(map[string]any{"ok": true, "http_status": out.HTTPStatus})
}

func (i *instance) handleRuleUpsert(ctx context.Context, payload []byte) (pluginsdk.Response, error) {
	var req struct {
		ID                  string   `json:"id"`
		Name                string   `json:"name"`
		Enabled             *bool    `json:"enabled"`
		SourcePattern       string   `json:"source_pattern"`
		MinSeverity         string   `json:"min_severity"`
		ChannelIDs          []string `json:"channel_ids"`
		CooldownSec         int      `json:"cooldown_sec"`
		QuietStart          string   `json:"quiet_start"`
		QuietEnd            string   `json:"quiet_end"`
		QuietTZ             string   `json:"quiet_tz"`
		AllowCriticalBypass *bool    `json:"allow_critical_bypass"`
	}
	if err := json.Unmarshal(payload, &req); err != nil {
		return pluginsdk.Response{}, pluginsdk.Errorf("INVALID_ARGUMENT", "请求格式错误: %s", err.Error())
	}
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" || len(req.Name) > 64 {
		return pluginsdk.Response{}, pluginsdk.Errorf("INVALID_ARGUMENT", "规则名称必须为 1-64 个字符")
	}
	if req.SourcePattern == "" {
		req.SourcePattern = "*"
	}
	if req.MinSeverity == "" {
		req.MinSeverity = "warn"
	}
	if req.MinSeverity != "info" && req.MinSeverity != "warn" && req.MinSeverity != "critical" {
		return pluginsdk.Response{}, pluginsdk.Errorf("INVALID_ARGUMENT", "min_severity 仅支持 info/warn/critical")
	}
	if req.CooldownSec < 0 || req.CooldownSec > 86400 {
		return pluginsdk.Response{}, pluginsdk.Errorf("INVALID_ARGUMENT", "cooldown_sec 须在 0 到 86400 秒之间")
	}
	if req.QuietStart != "" || req.QuietEnd != "" {
		if _, ok := parseHHMM(req.QuietStart); !ok {
			return pluginsdk.Response{}, pluginsdk.Errorf("INVALID_ARGUMENT", "quiet_start 须为 HH:MM 格式")
		}
		if _, ok := parseHHMM(req.QuietEnd); !ok {
			return pluginsdk.Response{}, pluginsdk.Errorf("INVALID_ARGUMENT", "quiet_end 须为 HH:MM 格式")
		}
	}
	if req.QuietTZ == "" {
		req.QuietTZ = "UTC"
	}
	if _, err := time.LoadLocation(req.QuietTZ); err != nil {
		return pluginsdk.Response{}, pluginsdk.Errorf("INVALID_ARGUMENT", "无效时区: %s", req.QuietTZ)
	}
	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}
	bypass := true
	if req.AllowCriticalBypass != nil {
		bypass = *req.AllowCriticalBypass
	}
	rec, err := i.store.upsertRule(ctx, RuleRecord{
		ID:                  strings.TrimSpace(req.ID),
		Name:                req.Name,
		Enabled:             enabled,
		SourcePattern:       strings.TrimSpace(req.SourcePattern),
		MinSeverity:         req.MinSeverity,
		ChannelIDs:          req.ChannelIDs,
		CooldownSec:         req.CooldownSec,
		QuietStart:          strings.TrimSpace(req.QuietStart),
		QuietEnd:            strings.TrimSpace(req.QuietEnd),
		QuietTZ:             req.QuietTZ,
		AllowCriticalBypass: bypass,
	})
	if err != nil {
		return pluginsdk.Response{}, pluginsdk.Errorf("INVALID_ARGUMENT", "%s", err.Error())
	}
	return jsonResp(map[string]any{"rule": rec})
}

func (i *instance) handleRuleDelete(ctx context.Context, payload []byte) (pluginsdk.Response, error) {
	var req struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(payload, &req); err != nil || strings.TrimSpace(req.ID) == "" {
		return pluginsdk.Response{}, pluginsdk.Errorf("INVALID_ARGUMENT", "缺少规则 id")
	}
	deleted, err := i.store.deleteRule(ctx, strings.TrimSpace(req.ID))
	if err != nil {
		return pluginsdk.Response{}, pluginsdk.Errorf("INTERNAL", "%s", err.Error())
	}
	return jsonResp(map[string]any{"deleted": deleted, "id": strings.TrimSpace(req.ID)})
}

func (i *instance) handleDispatch(ctx context.Context, payload []byte) (pluginsdk.Response, error) {
	var req struct {
		Source   string            `json:"source"`
		Severity string            `json:"severity"`
		Title    string            `json:"title"`
		Message  string            `json:"message"`
		DedupKey string            `json:"dedup_key"`
		Tags     map[string]string `json:"tags"`
	}
	if err := json.Unmarshal(payload, &req); err != nil {
		return pluginsdk.Response{}, pluginsdk.Errorf("INVALID_ARGUMENT", "请求格式错误: %s", err.Error())
	}
	req.Source = strings.TrimSpace(req.Source)
	req.Title = strings.TrimSpace(req.Title)
	if req.Source == "" || req.Title == "" {
		return pluginsdk.Response{}, pluginsdk.Errorf("INVALID_ARGUMENT", "source 与 title 不能为空")
	}
	if req.Severity == "" {
		req.Severity = "warn"
	}
	summary, err := i.engine.dispatch(ctx, NotifyEvent{
		Source:    req.Source,
		Severity:  req.Severity,
		Title:     req.Title,
		Message:   req.Message,
		DedupKey:  strings.TrimSpace(req.DedupKey),
		Tags:      req.Tags,
		Timestamp: i.now().UTC(),
	})
	if err != nil {
		return pluginsdk.Response{}, pluginsdk.Errorf("INTERNAL", "%s", err.Error())
	}
	return jsonResp(summary)
}
