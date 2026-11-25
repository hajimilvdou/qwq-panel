// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/tls"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	corev2 "github.com/qwq-panel/qwq/sdk/coreapi/v2"
	platformv1 "github.com/qwq-panel/qwq/sdk/gen/qwq/platform/v1"
	"github.com/qwq-panel/qwq/sdk/pluginsdk"
)

// ======================== v0.1.24 增强功能：套餐节点绑定/倍率/删除、30天日流量、批量测速/去重、规则集与证书联动 ========================

type dailyTrafficPoint struct {
	Date       string `json:"date"`
	UpBytes    int64  `json:"up_bytes"`
	DownBytes  int64  `json:"down_bytes"`
	TotalBytes int64  `json:"total_bytes"`
	Avg7Bytes  int64  `json:"avg7_bytes"`
}

type overviewAlert struct {
	Level  string `json:"level"` // "bad" | "warn" | "info"
	Title  string `json:"title"`
	Detail string `json:"detail"`
	Route  string `json:"route"`
}

type subscriptionRulesConfig struct {
	Preset               string   `json:"preset"`
	EnableAdBlock        bool     `json:"enable_ad_block"`
	EnableAIGroup        bool     `json:"enable_ai_group"`
	EnableStreamingGroup bool     `json:"enable_streaming_group"`
	CustomDirectDomains  []string `json:"custom_direct_domains"`
	CustomProxyDomains   []string `json:"custom_proxy_domains"`
	CustomRejectDomains  []string `json:"custom_reject_domains"`
	UpdatedAt            int64    `json:"updated_at"`
}

type rulePresetInfo struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Recommended bool   `json:"recommended"`
}

type availableTLSCert struct {
	ID         string   `json:"id"`
	BindingRef string   `json:"binding_ref"`
	Domains    []string `json:"domains"`
	Issuer     string   `json:"issuer"`
	NotAfter   string   `json:"not_after"`
	Status     string   `json:"status"`
	IsWildcard bool     `json:"is_wildcard"`
}

func normalizeTrafficMode(mode string) string {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "both_2x":
		return "both_2x"
	case "down_only":
		return "down_only"
	default:
		return "both"
	}
}

func normalizeRulePreset(preset string, allowEmpty bool) string {
	switch strings.ToLower(strings.TrimSpace(preset)) {
	case "global", "balanced", "ai_streaming", "minimal":
		return strings.ToLower(strings.TrimSpace(preset))
	case "":
		if allowEmpty {
			return ""
		}
		return "global"
	default:
		if allowEmpty {
			return ""
		}
		return "global"
	}
}

// effectiveUsageBytes 根据套餐流量统计方式折算当期计费流量。
func effectiveUsageBytes(up, down int64, trafficMode string) int64 {
	if up < 0 {
		up = 0
	}
	if down < 0 {
		down = 0
	}
	switch normalizeTrafficMode(trafficMode) {
	case "down_only":
		return down
	case "both_2x":
		return (up + down) * 2
	default:
		return up + down
	}
}

func sanitizeStringList(in []string, maxItems, maxLen int) []string {
	out := make([]string, 0, len(in))
	seen := make(map[string]struct{}, len(in))
	for _, raw := range in {
		s := strings.TrimSpace(raw)
		if s == "" || len(s) > maxLen {
			continue
		}
		if _, dup := seen[s]; dup {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
		if len(out) >= maxItems {
			break
		}
	}
	return out
}

func decodeStringArrayJSON(raw string) []string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" || trimmed == "[]" {
		return []string{}
	}
	var out []string
	if err := json.Unmarshal([]byte(trimmed), &out); err != nil || out == nil {
		return []string{}
	}
	return out
}

func (s *proxyStore) encryptToken(plain string) ([]byte, error) {
	if plain == "" {
		return []byte{}, nil
	}
	block, err := aes.NewCipher(s.masterKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, []byte(plain), nil), nil
}

func (s *proxyStore) decryptToken(blob []byte) (string, error) {
	if len(blob) == 0 {
		return "", nil
	}
	block, err := aes.NewCipher(s.masterKey)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	if len(blob) < gcm.NonceSize() {
		return "", errors.New("corrupted encrypted token")
	}
	nonce := blob[:gcm.NonceSize()]
	plain, err := gcm.Open(nil, nonce, blob[gcm.NonceSize():], nil)
	if err != nil {
		return "", err
	}
	return string(plain), nil
}

// ======================== Store 扩展：删除套餐/用户、读取加密订阅、30天日流量、规则集 ========================

func (s *proxyStore) DeletePlan(ctx context.Context, planID string) (bool, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer func() { _ = tx.Rollback() }()

	var refCount int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(1) FROM proxy_users WHERE plan_id = ?`, planID).Scan(&refCount); err != nil {
		return false, err
	}
	if refCount > 0 {
		return false, pluginsdk.Errorf("CONFLICT", "套餐 %s 仍被 %d 位用户绑定，请先切换用户套餐或删除用户后再删", planID, refCount)
	}
	res, err := tx.ExecContext(ctx, `DELETE FROM plans WHERE id = ?`, planID)
	if err != nil {
		return false, err
	}
	aff, _ := res.RowsAffected()
	if err := tx.Commit(); err != nil {
		return false, err
	}
	return aff > 0, nil
}

func (s *proxyStore) DeleteUser(ctx context.Context, userID, expectedRev string) (bool, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer func() { _ = tx.Rollback() }()

	var rev int64
	err = tx.QueryRowContext(ctx, `SELECT revision FROM proxy_users WHERE id = ?`, userID).Scan(&rev)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if expectedRev != "" && expectedRev != strconv.FormatInt(rev, 10) {
		return false, pluginsdk.PreconditionFailed("users/"+userID, strconv.FormatInt(rev, 10))
	}
	res, err := tx.ExecContext(ctx, `DELETE FROM proxy_users WHERE id = ?`, userID)
	if err != nil {
		return false, err
	}
	aff, _ := res.RowsAffected()
	if err := tx.Commit(); err != nil {
		return false, err
	}
	return aff > 0, nil
}

func (s *proxyStore) GetStoredSubscriptionToken(ctx context.Context, userID string) (string, bool, error) {
	var enc []byte
	err := s.readDB().QueryRowContext(ctx, `SELECT sub_token_enc FROM proxy_users WHERE id = ?`, userID).Scan(&enc)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, pluginsdk.Errorf("NOT_FOUND", "代理用户 %s 不存在", userID)
	}
	if err != nil {
		return "", false, err
	}
	if len(enc) == 0 {
		return "", false, nil
	}
	tok, err := s.decryptToken(enc)
	if err != nil || tok == "" {
		return "", false, nil
	}
	return tok, true, nil
}

func (s *proxyStore) GetDailyTraffic30d(ctx context.Context) ([]dailyTrafficPoint, error) {
	now := s.now().UTC()
	today := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
	startDay := today.AddDate(0, 0, -29)

	rows, err := s.readDB().QueryContext(ctx, `
		SELECT bucket_hour_ms, up_bytes, down_bytes
		FROM usage_hourly_rollups
		WHERE bucket_hour_ms >= ?`, startDay.UnixMilli())
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	type dayAgg struct {
		up   int64
		down int64
	}
	byDay := make(map[string]*dayAgg, 30)
	for rows.Next() {
		var ms, up, down int64
		if err := rows.Scan(&ms, &up, &down); err != nil {
			return nil, err
		}
		key := time.UnixMilli(ms).UTC().Format("2006-01-02")
		agg := byDay[key]
		if agg == nil {
			agg = &dayAgg{}
			byDay[key] = agg
		}
		agg.up += up
		agg.down += down
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	out := make([]dailyTrafficPoint, 0, 30)
	for i := 0; i < 30; i++ {
		d := startDay.AddDate(0, 0, i)
		key := d.Format("2006-01-02")
		var up, down int64
		if agg := byDay[key]; agg != nil {
			up = agg.up
			down = agg.down
		}
		tot := up + down
		out = append(out, dailyTrafficPoint{
			Date:       d.Format("01-02"),
			UpBytes:    up,
			DownBytes:  down,
			TotalBytes: tot,
		})
	}
	// 计算 7 日滑动均值
	for i := range out {
		lo := max(0, i-6)
		var sum int64
		for j := lo; j <= i; j++ {
			sum += out[j].TotalBytes
		}
		out[i].Avg7Bytes = sum / int64(i-lo+1)
	}
	return out, nil
}

func defaultSubscriptionRules() subscriptionRulesConfig {
	return subscriptionRulesConfig{
		Preset:               "global",
		EnableAdBlock:        false,
		EnableAIGroup:        true,
		EnableStreamingGroup: true,
		CustomDirectDomains:  []string{},
		CustomProxyDomains:   []string{},
		CustomRejectDomains:  []string{},
	}
}

func (s *proxyStore) GetSubscriptionRules(ctx context.Context) (subscriptionRulesConfig, error) {
	cfg := defaultSubscriptionRules()
	var adInt, aiInt, stInt int
	var dirJSON, prxJSON, rejJSON string
	err := s.readDB().QueryRowContext(ctx, `
		SELECT preset, enable_ad_block, enable_ai_group, enable_streaming_group,
		       custom_direct_json, custom_proxy_json, custom_reject_json, updated_at
		FROM subscription_rules WHERE id = 'default'`).Scan(
		&cfg.Preset, &adInt, &aiInt, &stInt, &dirJSON, &prxJSON, &rejJSON, &cfg.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return cfg, nil
	}
	if err != nil {
		return cfg, err
	}
	cfg.Preset = normalizeRulePreset(cfg.Preset, false)
	cfg.EnableAdBlock = adInt == 1
	cfg.EnableAIGroup = aiInt == 1
	cfg.EnableStreamingGroup = stInt == 1
	cfg.CustomDirectDomains = decodeStringArrayJSON(dirJSON)
	cfg.CustomProxyDomains = decodeStringArrayJSON(prxJSON)
	cfg.CustomRejectDomains = decodeStringArrayJSON(rejJSON)
	return cfg, nil
}

func (s *proxyStore) SaveSubscriptionRules(ctx context.Context, in subscriptionRulesConfig) (subscriptionRulesConfig, error) {
	clean := subscriptionRulesConfig{
		Preset:               normalizeRulePreset(in.Preset, false),
		EnableAdBlock:        in.EnableAdBlock,
		EnableAIGroup:        in.EnableAIGroup,
		EnableStreamingGroup: in.EnableStreamingGroup,
		CustomDirectDomains:  sanitizeStringList(in.CustomDirectDomains, 200, 128),
		CustomProxyDomains:   sanitizeStringList(in.CustomProxyDomains, 200, 128),
		CustomRejectDomains:  sanitizeStringList(in.CustomRejectDomains, 200, 128),
		UpdatedAt:            s.now().UTC().UnixMilli(),
	}
	dirB, _ := json.Marshal(clean.CustomDirectDomains)
	prxB, _ := json.Marshal(clean.CustomProxyDomains)
	rejB, _ := json.Marshal(clean.CustomRejectDomains)
	btoi := func(b bool) int {
		if b {
			return 1
		}
		return 0
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO subscription_rules(id, preset, enable_ad_block, enable_ai_group, enable_streaming_group,
		                               custom_direct_json, custom_proxy_json, custom_reject_json, updated_at)
		VALUES('default', ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			preset = excluded.preset,
			enable_ad_block = excluded.enable_ad_block,
			enable_ai_group = excluded.enable_ai_group,
			enable_streaming_group = excluded.enable_streaming_group,
			custom_direct_json = excluded.custom_direct_json,
			custom_proxy_json = excluded.custom_proxy_json,
			custom_reject_json = excluded.custom_reject_json,
			updated_at = excluded.updated_at`,
		clean.Preset, btoi(clean.EnableAdBlock), btoi(clean.EnableAIGroup), btoi(clean.EnableStreamingGroup),
		string(dirB), string(prxB), string(rejB), clean.UpdatedAt)
	if err != nil {
		return subscriptionRulesConfig{}, err
	}
	return clean, nil
}

// ======================== 内置分流规则集渲染（Clash / sing-box） ========================

var (
	builtinDirectSuffixes = []string{
		"cn", "baidu.com", "qq.com", "weixin.qq.com", "taobao.com", "tmall.com", "jd.com",
		"bilibili.com", "zhihu.com", "douyin.com", "163.com", "126.com", "aliyun.com", "aliyuncs.com",
		"tencent.com", "meituan.com", "pinduoduo.com", "xiaohongshu.com", "weibo.com", "mi.com", "huawei.com",
	}
	builtinAISuffixes = []string{
		"openai.com", "chatgpt.com", "oaistatic.com", "oaiusercontent.com",
		"anthropic.com", "claude.ai", "gemini.google.com", "generativelanguage.googleapis.com",
		"aistudio.google.com", "perplexity.ai", "cursor.sh", "cursor.com", "githubcopilot.com", "poe.com",
	}
	builtinStreamingSuffixes = []string{
		"netflix.com", "nflxvideo.net", "youtube.com", "googlevideo.com", "ytimg.com",
		"disneyplus.com", "spotify.com", "scdn.co", "tiktok.com", "tiktokv.com", "hulu.com", "twitch.tv",
	}
	builtinAdBlockSuffixes = []string{
		"doubleclick.net", "googlesyndication.com", "googleadservices.com", "adservice.google.com",
		"pagead2.googlesyndication.com", "ads.youtube.com", "umeng.com", "cnzz.com", "adnxs.com",
	}
)

func builtinRulePresetInfos() []rulePresetInfo {
	return []rulePresetInfo{
		{
			ID:          "balanced",
			Name:        "智能分流（国内直连 + 境外代理）",
			Description: "局域网与常见国内站点自动直连、支持自动测速优选，境外流量走代理，适合日常主力使用。",
			Recommended: true,
		},
		{
			ID:          "ai_streaming",
			Name:        "AI 与流媒体分组分流",
			Description: "在智能分流基础上单独拆分「AI 服务（ChatGPT / Claude / Gemini）」与「流媒体」策略组，便于指定不同落地节点。",
			Recommended: false,
		},
		{
			ID:          "global",
			Name:        "全局代理（全流量走节点）",
			Description: "除私有局域网外全部流量默认走 Proxy 节点，适合需要纯全局或客户端自带分流规则的场景。",
			Recommended: false,
		},
		{
			ID:          "minimal",
			Name:        "极简模式（仅节点列表）",
			Description: "仅导出代理节点与默认 Proxy 选择组，最小化规则体积。",
			Recommended: false,
		},
	}
}

func renderClashSubscriptionWithRules(nodes []subNode, rules subscriptionRulesConfig) string {
	preset := normalizeRulePreset(rules.Preset, false)
	if preset == "global" || preset == "minimal" {
		if len(rules.CustomDirectDomains) == 0 && len(rules.CustomProxyDomains) == 0 && len(rules.CustomRejectDomains) == 0 && !rules.EnableAdBlock {
			return renderClashSubscription(nodes)
		}
	}

	var b strings.Builder
	b.WriteString("proxies:\n")
	names := make([]string, 0, len(nodes))
	for _, n := range nodes {
		names = append(names, n.Name)
		writeYAMLListItemMap(&b, n.ClashNode, 2)
	}

	b.WriteString("proxy-groups:\n")
	b.WriteString("  - name: Proxy\n")
	b.WriteString("    type: select\n")
	b.WriteString("    proxies:\n")
	if (preset == "balanced" || preset == "ai_streaming") && len(names) > 1 {
		b.WriteString("      - Auto\n")
	}
	for _, name := range names {
		b.WriteString("      - ")
		b.WriteString(formatYAMLScalar(name))
		b.WriteByte('\n')
	}
	b.WriteString("      - DIRECT\n")

	if (preset == "balanced" || preset == "ai_streaming") && len(names) > 1 {
		b.WriteString("  - name: Auto\n")
		b.WriteString("    type: url-test\n")
		b.WriteString("    url: http://www.gstatic.com/generate_204\n")
		b.WriteString("    interval: 300\n")
		b.WriteString("    proxies:\n")
		for _, name := range names {
			b.WriteString("      - ")
			b.WriteString(formatYAMLScalar(name))
			b.WriteByte('\n')
		}
	}

	hasAI := preset == "ai_streaming" && rules.EnableAIGroup
	hasStream := preset == "ai_streaming" && rules.EnableStreamingGroup
	if hasAI {
		b.WriteString("  - name: AI-Services\n")
		b.WriteString("    type: select\n")
		b.WriteString("    proxies:\n")
		b.WriteString("      - Proxy\n")
		for _, name := range names {
			b.WriteString("      - ")
			b.WriteString(formatYAMLScalar(name))
			b.WriteByte('\n')
		}
	}
	if hasStream {
		b.WriteString("  - name: Streaming\n")
		b.WriteString("    type: select\n")
		b.WriteString("    proxies:\n")
		b.WriteString("      - Proxy\n")
		for _, name := range names {
			b.WriteString("      - ")
			b.WriteString(formatYAMLScalar(name))
			b.WriteByte('\n')
		}
	}

	b.WriteString("rules:\n")
	// 1. 广告拦截 / 自定义拒绝
	for _, d := range rules.CustomRejectDomains {
		b.WriteString("  - DOMAIN-SUFFIX,")
		b.WriteString(d)
		b.WriteString(",REJECT\n")
	}
	if rules.EnableAdBlock {
		for _, d := range builtinAdBlockSuffixes {
			b.WriteString("  - DOMAIN-SUFFIX,")
			b.WriteString(d)
			b.WriteString(",REJECT\n")
		}
	}
	// 2. 自定义直连与自定义代理
	for _, d := range rules.CustomDirectDomains {
		b.WriteString("  - DOMAIN-SUFFIX,")
		b.WriteString(d)
		b.WriteString(",DIRECT\n")
	}
	for _, d := range rules.CustomProxyDomains {
		b.WriteString("  - DOMAIN-SUFFIX,")
		b.WriteString(d)
		b.WriteString(",Proxy\n")
	}
	// 3. AI 与流媒体分组
	if hasAI {
		for _, d := range builtinAISuffixes {
			b.WriteString("  - DOMAIN-SUFFIX,")
			b.WriteString(d)
			b.WriteString(",AI-Services\n")
		}
	}
	if hasStream {
		for _, d := range builtinStreamingSuffixes {
			b.WriteString("  - DOMAIN-SUFFIX,")
			b.WriteString(d)
			b.WriteString(",Streaming\n")
		}
	}
	// 4. 局域网与常见国内直连
	if preset == "balanced" || preset == "ai_streaming" {
		b.WriteString("  - IP-CIDR,127.0.0.0/8,DIRECT,no-resolve\n")
		b.WriteString("  - IP-CIDR,10.0.0.0/8,DIRECT,no-resolve\n")
		b.WriteString("  - IP-CIDR,172.16.0.0/12,DIRECT,no-resolve\n")
		b.WriteString("  - IP-CIDR,192.168.0.0/16,DIRECT,no-resolve\n")
		for _, d := range builtinDirectSuffixes {
			b.WriteString("  - DOMAIN-SUFFIX,")
			b.WriteString(d)
			b.WriteString(",DIRECT\n")
		}
	}
	b.WriteString("  - MATCH,Proxy\n")
	return b.String()
}

func appendSingboxRouteRules(base []map[string]any, rules subscriptionRulesConfig, hasBlockOutbound bool) []map[string]any {
	preset := normalizeRulePreset(rules.Preset, false)
	out := append([]map[string]any(nil), base...)
	if hasBlockOutbound {
		rejects := append([]string(nil), rules.CustomRejectDomains...)
		if rules.EnableAdBlock {
			rejects = append(rejects, builtinAdBlockSuffixes...)
		}
		if len(rejects) > 0 {
			out = append(out, map[string]any{"domain_suffix": rejects, "outbound": "block"})
		}
	}
	if len(rules.CustomDirectDomains) > 0 {
		out = append(out, map[string]any{"domain_suffix": rules.CustomDirectDomains, "outbound": "direct"})
	}
	if len(rules.CustomProxyDomains) > 0 {
		out = append(out, map[string]any{"domain_suffix": rules.CustomProxyDomains, "outbound": "proxy"})
	}
	if preset == "ai_streaming" && rules.EnableAIGroup {
		out = append(out, map[string]any{"domain_suffix": builtinAISuffixes, "outbound": "ai-services"})
	}
	if preset == "ai_streaming" && rules.EnableStreamingGroup {
		out = append(out, map[string]any{"domain_suffix": builtinStreamingSuffixes, "outbound": "streaming"})
	}
	if preset == "balanced" || preset == "ai_streaming" {
		out = append(out, map[string]any{"domain_suffix": builtinDirectSuffixes, "outbound": "direct"})
	}
	return out
}

// ======================== 概览告警引擎 ========================

func buildOverviewAlerts(users []userRecord, nodes []proxyNodeRecord, shapingOK bool, shapingReason string) []overviewAlert {
	alerts := make([]overviewAlert, 0, 6)
	if len(nodes) == 0 {
		alerts = append(alerts, overviewAlert{
			Level:  "info",
			Title:  "尚未创建任何代理节点",
			Detail: "前往「节点管理」一键生成 VLESS Reality / Hysteria2 / AnyTLS 节点即可开始使用。",
			Route:  "/proxy/nodes",
		})
	}
	missingCert := 0
	for _, n := range nodes {
		if n.Source == "managed" && n.Enabled &&
			(n.Protocol == corev2.ProtocolHysteria2 || n.Protocol == corev2.ProtocolAnyTLS || n.SecurityMode == "tls") &&
			strings.TrimSpace(n.Config.BindingRef) == "" {
			missingCert++
		}
	}
	if missingCert > 0 {
		alerts = append(alerts, overviewAlert{
			Level:  "warn",
			Title:  fmt.Sprintf("%d 个 TLS 节点未绑定证书", missingCert),
			Detail: "需要绑定 TLS 证书后才会同步下发至内置 Xray 引擎监听。",
			Route:  "/proxy/nodes",
		})
	}
	suspended, expired, nearQuota := 0, 0, 0
	for _, u := range users {
		switch u.Status {
		case "suspended_quota":
			suspended++
		case "expired":
			expired++
		case "active":
			if u.QuotaBytes > 0 {
				eff := effectiveUsageBytes(u.PeriodUpBytes, u.PeriodDownBytes, u.TrafficMode)
				if eff*100 >= u.QuotaBytes*80 {
					nearQuota++
				}
			}
		}
	}
	if suspended > 0 {
		alerts = append(alerts, overviewAlert{
			Level:  "bad",
			Title:  fmt.Sprintf("%d 位用户流量超额已暂停", suspended),
			Detail: "用户将在下一个账单重置日自动恢复，也可手动调整套餐额度或重新启用。",
			Route:  "/proxy/users",
		})
	}
	if expired > 0 {
		alerts = append(alerts, overviewAlert{
			Level:  "warn",
			Title:  fmt.Sprintf("%d 位用户订阅已到期", expired),
			Detail: "前往「用户管理」续期或调整套餐有效期。",
			Route:  "/proxy/users",
		})
	}
	if nearQuota > 0 {
		alerts = append(alerts, overviewAlert{
			Level:  "warn",
			Title:  fmt.Sprintf("%d 位活跃用户配额使用率已达 80%%+", nearQuota),
			Detail: "建议关注流量消耗走势，必要时提前扩容套餐。",
			Route:  "/proxy/users",
		})
	}
	if !shapingOK && shapingReason != "" {
		alerts = append(alerts, overviewAlert{
			Level:  "info",
			Title:  "内核 HTB 限速处于降级状态",
			Detail: shapingReason,
			Route:  "/proxy/tuning",
		})
	}
	return alerts
}

// ======================== 8 项新增 Operation 处理器 ========================

func (i *instance) registerV2Operations() {
	i.HandleJob("plans.delete", i.handlePlansDelete)
	i.HandleJob("users.delete", i.handleUsersDelete)
	i.HandleInvoke("users.get_subscription", i.handleUsersGetSubscription)
	i.HandleInvoke("nodes.batch_test", i.handleNodesBatchTest)
	i.HandleInvoke("nodes.deduplicate", i.handleNodesDeduplicate)
	i.HandleInvoke("rules.get", i.handleRulesGet)
	i.HandleInvoke("rules.save", i.handleRulesSave)
	i.HandleInvoke("tls.certs.available", i.handleTLSCertsAvailable)
}

func (i *instance) handlePlansDelete(ctx context.Context, req pluginsdk.Request, _ pluginsdk.Progress) (pluginsdk.Result, error) {
	var in struct {
		ID string `json:"id"`
	}
	if err := decodeStrictJSON(req.Payload, &in); err != nil {
		return pluginsdk.Result{}, err
	}
	id := strings.TrimSpace(in.ID)
	if !validEntityIDPattern.MatchString(id) {
		return pluginsdk.Result{}, invalidField("/id", "INVALID_ID", "套餐 ID 格式无效")
	}
	deleted, err := i.store.DeletePlan(ctx, id)
	if err != nil {
		return pluginsdk.Result{}, err
	}
	return marshalResult(map[string]any{"deleted": deleted, "id": id})
}

func (i *instance) handleUsersDelete(ctx context.Context, req pluginsdk.Request, _ pluginsdk.Progress) (pluginsdk.Result, error) {
	var in struct {
		UserID           string `json:"user_id"`
		ExpectedRevision string `json:"expected_revision"`
	}
	if err := decodeStrictJSON(req.Payload, &in); err != nil {
		return pluginsdk.Result{}, err
	}
	uid := strings.TrimSpace(in.UserID)
	if !validEntityIDPattern.MatchString(uid) {
		return pluginsdk.Result{}, invalidField("/user_id", "INVALID_ID", "用户 ID 格式无效")
	}
	expectedRev := resolveRevision(in.ExpectedRevision, req, "users/"+uid)
	deleted, err := i.store.DeleteUser(ctx, uid, expectedRev)
	if err != nil {
		return pluginsdk.Result{}, err
	}
	coreRev := ""
	if deleted {
		if syncOut, serr := i.syncCoreAndTraffic(ctx, req.Host()); serr == nil {
			coreRev = syncOut.CoreRevision
		}
	}
	return marshalResult(map[string]any{
		"deleted":       deleted,
		"user_id":       uid,
		"core_revision": coreRev,
	})
}

func (i *instance) handleUsersGetSubscription(ctx context.Context, req pluginsdk.Request) (pluginsdk.Response, error) {
	var in struct {
		UserID string `json:"user_id"`
	}
	if err := decodeStrictJSON(req.Payload, &in); err != nil {
		return pluginsdk.Response{}, err
	}
	uid := strings.TrimSpace(in.UserID)
	if !validEntityIDPattern.MatchString(uid) {
		return pluginsdk.Response{}, invalidField("/user_id", "INVALID_ID", "用户 ID 格式无效")
	}
	tok, available, err := i.store.GetStoredSubscriptionToken(ctx, uid)
	if err != nil {
		return pluginsdk.Response{}, err
	}
	cfg := i.configSnapshot()
	resp := map[string]any{
		"user_id":   uid,
		"available": available,
	}
	if available && tok != "" {
		resp["subscription_token"] = tok
		resp["subscription_path"] = cfg.PublicBasePath + "/sub/" + tok
	}
	return marshalResponse(resp)
}

func (i *instance) handleNodesBatchTest(ctx context.Context, req pluginsdk.Request) (pluginsdk.Response, error) {
	var in struct {
		TimeoutMS   int   `json:"timeout_ms"`
		OnlyEnabled *bool `json:"only_enabled"`
	}
	if err := decodeOptionalJSON(req.Payload, &in); err != nil {
		return pluginsdk.Response{}, err
	}
	onlyEnabled := true
	if in.OnlyEnabled != nil {
		onlyEnabled = *in.OnlyEnabled
	}
	timeout := 2500 * time.Millisecond
	if in.TimeoutMS >= 300 && in.TimeoutMS <= 8000 {
		timeout = time.Duration(in.TimeoutMS) * time.Millisecond
	}

	nodes, err := i.store.ListNodes(ctx, "", "", "", "", onlyEnabled)
	if err != nil {
		return pluginsdk.Response{}, err
	}
	if len(nodes) > 48 {
		nodes = nodes[:48]
	}

	type batchItem struct {
		ID        string `json:"id"`
		OK        bool   `json:"ok"`
		LatencyMS int64  `json:"latency_ms"`
		Error     string `json:"error,omitempty"`
	}
	results := make([]batchItem, len(nodes))
	cfg := i.configSnapshot()
	testedAt := i.now().UTC().UnixMilli()

	sem := make(chan struct{}, 6)
	var wg sync.WaitGroup
	for idx, node := range nodes {
		wg.Add(1)
		go func(pos int, n proxyNodeRecord) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			host := strings.TrimSpace(n.Server)
			if n.Source == "managed" {
				if host == "" {
					host = strings.TrimSpace(cfg.PublicHost)
				}
				if host == "" || n.Listen == "127.0.0.1" || n.Listen == "::1" {
					host = "127.0.0.1"
				}
			}
			if host == "" {
				host = "127.0.0.1"
			}
			target := net.JoinHostPort(strings.Trim(host, "[]"), strconv.Itoa(n.Port))
			start := time.Now()
			ok := false
			var lat int64 = -1
			errMsg := ""

			conn, derr := ProbeExternalOrManagedNode(ctx, n, target, timeout)
			if derr != nil {
				errMsg = derr.Error()
			} else {
				if n.Protocol == corev2.ProtocolHysteria2 || n.Protocol == "tuic" || n.Protocol == "wireguard" {
					_ = conn.SetDeadline(time.Now().Add(timeout))
					_, werr := conn.Write([]byte{0x00})
					_ = conn.Close()
					if werr != nil {
						errMsg = werr.Error()
					} else {
						ok = true
						lat = max(time.Since(start).Milliseconds(), 1)
					}
				} else if n.SecurityMode == "tls" {
					sni := firstNonEmpty(n.Config.SNI, host)
					tc := tls.Client(conn, &tls.Config{ServerName: sni, InsecureSkipVerify: true, MinVersion: tls.VersionTLS12})
					_ = tc.SetDeadline(time.Now().Add(timeout))
					_ = tc.HandshakeContext(ctx)
					_ = tc.Close()
					ok = true
					lat = max(time.Since(start).Milliseconds(), 1)
				} else {
					_ = conn.Close()
					ok = true
					lat = max(time.Since(start).Milliseconds(), 1)
				}
			}
			_ = i.store.UpdateNodeLatency(ctx, n.ID, lat, testedAt)
			results[pos] = batchItem{ID: n.ID, OK: ok, LatencyMS: lat, Error: errMsg}
		}(idx, node)
	}
	wg.Wait()

	reachable, failed := 0, 0
	for _, r := range results {
		if r.OK {
			reachable++
		} else {
			failed++
		}
	}
	return marshalResponse(map[string]any{
		"tested":    len(results),
		"reachable": reachable,
		"failed":    failed,
		"results":   results,
	})
}

func nodeDedupFingerprint(n proxyNodeRecord) string {
	cred := firstNonEmpty(n.Config.UUID, n.Config.Password, n.Config.UserKey, n.Config.ServerKey)
	return strings.ToLower(strings.Join([]string{
		n.Protocol,
		strings.TrimSpace(n.Server),
		strconv.Itoa(n.Port),
		n.Transport,
		n.SecurityMode,
		strings.TrimSpace(n.Config.SNI),
		strings.TrimSpace(n.Config.Path),
		strings.TrimSpace(n.Config.ServiceName),
		cred,
	}, "|"))
}

func (i *instance) handleNodesDeduplicate(ctx context.Context, req pluginsdk.Request) (pluginsdk.Response, error) {
	var in struct {
		DryRun bool `json:"dry_run"`
	}
	if err := decodeOptionalJSON(req.Payload, &in); err != nil {
		return pluginsdk.Response{}, err
	}
	nodes, err := i.store.ListNodes(ctx, "", "", "", "", false)
	if err != nil {
		return pluginsdk.Response{}, err
	}
	// 托管节点优先保留，其次保留创建时间更早的节点。
	sort.SliceStable(nodes, func(a, b int) bool {
		if nodes[a].Source != nodes[b].Source {
			return nodes[a].Source == "managed"
		}
		if nodes[a].CreatedAt != nodes[b].CreatedAt {
			return nodes[a].CreatedAt < nodes[b].CreatedAt
		}
		return nodes[a].ID < nodes[b].ID
	})

	seen := make(map[string]string, len(nodes))
	removedIDs := make([]string, 0)
	removedManaged := make([]string, 0)
	for _, n := range nodes {
		fp := nodeDedupFingerprint(n)
		if _, exists := seen[fp]; exists {
			removedIDs = append(removedIDs, n.ID)
			if n.Source == "managed" {
				removedManaged = append(removedManaged, n.ID)
			}
			continue
		}
		seen[fp] = n.ID
	}
	if !in.DryRun && len(removedIDs) > 0 {
		for _, id := range removedIDs {
			_, _ = i.store.DeleteNode(ctx, id)
		}
		if len(removedManaged) > 0 {
			_, _, _ = i.trySyncManagedNodesToCore(ctx, req.Host(), removedManaged...)
		}
	}
	return marshalResponse(map[string]any{
		"removed_count": len(removedIDs),
		"removed_ids":   removedIDs,
	})
}

func buildRulesPreviewSnippets(cfg subscriptionRulesConfig) (string, string) {
	sampleNodes := []subNode{
		{
			Name:            "示例节点-VLESS",
			Protocol:        "vless",
			Transport:       "raw",
			ClashNode:       map[string]any{"name": "示例节点-VLESS", "type": "vless", "server": "example.com", "port": 443, "uuid": "00000000-0000-4000-8000-000000000000"},
			SingboxOutbound: map[string]any{"type": "vless", "tag": "示例节点-VLESS", "server": "example.com", "server_port": 443, "uuid": "00000000-0000-4000-8000-000000000000"},
		},
	}
	clashText := renderClashSubscriptionWithRules(sampleNodes, cfg)
	sbRules := appendSingboxRouteRules([]map[string]any{
		{"action": "sniff"},
		{"protocol": "dns", "action": "hijack-dns"},
		{"ip_is_private": true, "outbound": "direct"},
	}, cfg, cfg.EnableAdBlock || len(cfg.CustomRejectDomains) > 0)
	sbRaw, _ := json.MarshalIndent(map[string]any{
		"route": map[string]any{
			"rules": sbRules,
			"final": "proxy",
		},
	}, "", "  ")
	return clashText, string(sbRaw)
}

func (i *instance) handleRulesGet(ctx context.Context, _ pluginsdk.Request) (pluginsdk.Response, error) {
	cfg, err := i.store.GetSubscriptionRules(ctx)
	if err != nil {
		return pluginsdk.Response{}, err
	}
	clashPrev, sbPrev := buildRulesPreviewSnippets(cfg)
	return marshalResponse(map[string]any{
		"config":          cfg,
		"presets":         builtinRulePresetInfos(),
		"clash_preview":   clashPrev,
		"singbox_preview": sbPrev,
	})
}

func (i *instance) handleRulesSave(ctx context.Context, req pluginsdk.Request) (pluginsdk.Response, error) {
	var in subscriptionRulesConfig
	if err := decodeStrictJSON(req.Payload, &in); err != nil {
		return pluginsdk.Response{}, err
	}
	saved, err := i.store.SaveSubscriptionRules(ctx, in)
	if err != nil {
		return pluginsdk.Response{}, err
	}
	clashPrev, sbPrev := buildRulesPreviewSnippets(saved)
	return marshalResponse(map[string]any{
		"config":          saved,
		"clash_preview":   clashPrev,
		"singbox_preview": sbPrev,
	})
}

func (i *instance) handleTLSCertsAvailable(ctx context.Context, req pluginsdk.Request) (pluginsdk.Response, error) {
	certs := make([]availableTLSCert, 0)
	host := req.Host()
	if host == nil || host.Conn() == nil {
		return marshalResponse(map[string]any{
			"certs_installed": false,
			"certificates":    certs,
		})
	}
	callCtx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()

	resp, err := host.InvokePlugin(callCtx, pluginsdk.InvokeRequest{
		TargetPluginID:   "tls.certificates",
		TargetInstanceID: "default",
		Operation:        "certificates.list",
		APIVersion:       "v1",
		Payload:          []byte(`{}`),
	})
	if err != nil || (resp.GetError() != nil && resp.GetError().GetCode() != "") {
		return marshalResponse(map[string]any{
			"certs_installed": false,
			"certificates":    certs,
		})
	}
	raw := resp.GetPayloadJson()
	if opID := resp.GetOperationId(); opID != "" && len(raw) == 0 {
		switch resp.GetState() {
		case platformv1.OperationState_OPERATION_STATE_PENDING,
			platformv1.OperationState_OPERATION_STATE_APPROVED,
			platformv1.OperationState_OPERATION_STATE_RUNNING:
			if final, werr := host.AwaitOperation(callCtx, opID); werr == nil && final.GetState() == platformv1.OperationState_OPERATION_STATE_SUCCEEDED {
				raw = final.GetResultJson()
			}
		}
	}

	var parsed struct {
		Certificates []struct {
			ID               string   `json:"id"`
			SANs             []string `json:"sans"`
			Domains          []string `json:"domains"`
			Issuer           string   `json:"issuer"`
			NotAfter         string   `json:"not_after"`
			Status           string   `json:"status"`
			LatestGeneration int      `json:"latest_generation"`
			Generations      []struct {
				Number   int    `json:"number"`
				Issuer   string `json:"issuer"`
				NotAfter string `json:"not_after"`
			} `json:"generations"`
			Bindings []struct {
				BindingRef string `json:"binding_ref"`
				PluginID   string `json:"plugin_id"`
			} `json:"bindings"`
		} `json:"certificates"`
	}
	if len(raw) > 0 && json.Unmarshal(raw, &parsed) == nil {
		for _, c := range parsed.Certificates {
			if c.ID == "" {
				continue
			}
			domains := c.SANs
			if len(domains) == 0 {
				domains = c.Domains
			}
			if domains == nil {
				domains = []string{}
			}
			issuer := c.Issuer
			notAfter := c.NotAfter
			if len(c.Generations) > 0 {
				chosen := c.Generations[len(c.Generations)-1]
				for _, g := range c.Generations {
					if g.Number == c.LatestGeneration {
						chosen = g
						break
					}
				}
				if chosen.Issuer != "" {
					issuer = chosen.Issuer
				}
				if chosen.NotAfter != "" {
					notAfter = chosen.NotAfter
				}
			}
			bindingRef := c.ID
			for _, b := range c.Bindings {
				if b.BindingRef != "" && (b.PluginID == "proxy.advanced" || bindingRef == c.ID) {
					bindingRef = b.BindingRef
					if b.PluginID == "proxy.advanced" {
						break
					}
				}
			}
			isWild := false
			for _, d := range domains {
				if strings.HasPrefix(d, "*.") {
					isWild = true
					break
				}
			}
			certs = append(certs, availableTLSCert{
				ID:         c.ID,
				BindingRef: bindingRef,
				Domains:    domains,
				Issuer:     issuer,
				NotAfter:   notAfter,
				Status:     c.Status,
				IsWildcard: isWild,
			})
		}
	}
	return marshalResponse(map[string]any{
		"certs_installed": true,
		"certificates":    certs,
	})
}
