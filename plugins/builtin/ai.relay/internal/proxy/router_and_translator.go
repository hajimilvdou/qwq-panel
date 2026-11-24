// SPDX-License-Identifier: AGPL-3.0-only

// Package proxy 实现 SSRF 防护传输层、Sticky Session 亲和路由器、Sub2API OAuth 池无锁刷新与
// OpenAI Chat / Responses / Anthropic Messages / Gemini Native 四协议零缓冲流式双向互转引擎。
package proxy

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"io"
	"math"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ======================== 协议类型、渠道类型与 SSRF 防护传输层 ========================

type ProtocolKind string

const (
	ProtoOpenAIChat        ProtocolKind = "openai_chat"
	ProtoOpenAIResponses   ProtocolKind = "openai_responses"
	ProtoAnthropicMessages ProtocolKind = "anthropic_messages"
	ProtoGeminiNative      ProtocolKind = "gemini_native"
)

type ChannelKind string

const (
	ChanOpenAICompat    ChannelKind = "openai_compatible"
	ChanAnthropicNative ChannelKind = "anthropic_native"
	ChanGeminiNative    ChannelKind = "gemini_native"
	ChanSub2ClaudeOAuth ChannelKind = "sub2api_claude_oauth"
	ChanSub2CodexOAuth  ChannelKind = "sub2api_codex_oauth"
	ChanSub2GeminiOAuth ChannelKind = "sub2api_gemini_oauth"
)

var alwaysBlockedUpstreamPrefixes = []netip.Prefix{
	netip.MustParsePrefix("169.254.0.0/16"),    // AWS/GCP/Azure/OpenStack IMDS & Link-Local
	netip.MustParsePrefix("100.64.0.0/10"),     // 阿里云 100.100.100.200 元数据 & CGNAT
	netip.MustParsePrefix("0.0.0.0/8"),         // 本网络保留段
	netip.MustParsePrefix("fd00:ec2::254/128"), // AWS IPv6 IMDS
	netip.MustParsePrefix("fe80::/10"),         // IPv6 Link-Local
	netip.MustParsePrefix("64:ff9b::/96"),      // NAT64 well-known
	netip.MustParsePrefix("64:ff9b:1::/48"),    // NAT64 local
	netip.MustParsePrefix("2002::/16"),         // 6to4
	netip.MustParsePrefix("2001::/32"),         // Teredo
}

// NewSafeHTTPClient 构造具备 SSRF 防护的 HTTP 客户端：
//   - 禁用环境变量代理（Proxy: nil）与自动重定向跟随（防止 307/308 跨源泄漏 API Key）；
//   - 无论 allowPrivate 为何值，均无条件阻断云元数据（169.254.0.0/16、100.64.0.0/10、fd00:ec2::254、fe80::/10、metadata.google.internal）、0.0.0.0/8、NAT64、6to4 与 Teredo；
//   - allowPrivate 为 false 时额外拒绝回环与私网地址。
func NewSafeHTTPClient(allowPrivate bool, timeout time.Duration) *http.Client {
	if timeout <= 0 {
		timeout = 120 * time.Second
	}
	dialer := &net.Dialer{
		Timeout:   15 * time.Second,
		KeepAlive: 30 * time.Second,
	}
	checkIP := func(ip netip.Addr) bool {
		if allowPrivate {
			return isAlwaysBlockedUpstreamIP(ip)
		}
		return isBlockedUpstreamIP(ip)
	}
	transport := &http.Transport{
		Proxy:                 nil,
		MaxIdleConns:          64,
		MaxIdleConnsPerHost:   16,
		IdleConnTimeout:       90 * time.Second,
		ResponseHeaderTimeout: timeout,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, fmt.Errorf("ssrf: invalid target %q", addr)
			}
			cleanHost := strings.Trim(strings.TrimSpace(host), "[]")
			if strings.EqualFold(cleanHost, "metadata.google.internal") || strings.EqualFold(cleanHost, "metadata.goog") {
				return nil, fmt.Errorf("SSRF_BLOCKED: refusing cloud metadata host %s", cleanHost)
			}
			if ip, err := netip.ParseAddr(cleanHost); err == nil {
				if checkIP(ip) {
					return nil, fmt.Errorf("SSRF_BLOCKED: refusing blocked upstream %s", ip.String())
				}
				return dialer.DialContext(ctx, network, net.JoinHostPort(ip.Unmap().String(), port))
			}
			return DialSafeMultiIP(ctx, network, cleanHost, port, allowPrivate, checkIP)
		},
	}
	return &http.Client{
		Transport: transport,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// DialSafeMultiIP 先校验目标域名解析出的全部 IP（阻断 DNS Rebinding 与内网/元数据地址），
// 再逐一以有界超时尝试连接，避免纯 IPv4 主机因双栈域名首条 AAAA 不可达而直接失败。
func DialSafeMultiIP(
	ctx context.Context,
	network, host, port string,
	allowPrivate bool,
	isBlockedIP func(netip.Addr) bool,
) (net.Conn, error) {
	ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, err
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("ssrf: no ip resolved for %s", host)
	}
	validIPs := make([]netip.Addr, 0, len(ips))
	for _, raw := range ips {
		ip := raw.Unmap()
		if isBlockedIP != nil && isBlockedIP(ip) {
			return nil, fmt.Errorf("SSRF_BLOCKED: upstream %s resolved to blocked ip %s", host, ip.String())
		}
		validIPs = append(validIPs, ip)
	}
	dialer := &net.Dialer{Timeout: 6 * time.Second, KeepAlive: 30 * time.Second}
	var lastErr error
	for _, ip := range validIPs {
		attemptCtx, cancel := context.WithTimeout(ctx, 6*time.Second)
		conn, derr := dialer.DialContext(attemptCtx, network, net.JoinHostPort(ip.String(), port))
		cancel()
		if derr == nil {
			return conn, nil
		}
		lastErr = derr
		if ctx.Err() != nil {
			break
		}
	}
	return nil, fmt.Errorf("dial upstream %s:%s failed: %w", host, port, lastErr)
}

func isAlwaysBlockedUpstreamIP(addr netip.Addr) bool {
	a := addr.Unmap()
	if !a.IsValid() || a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast() || a.IsMulticast() || a.IsUnspecified() {
		return true
	}
	for _, p := range alwaysBlockedUpstreamPrefixes {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

func isBlockedUpstreamIP(addr netip.Addr) bool {
	a := addr.Unmap()
	return isAlwaysBlockedUpstreamIP(a) || a.IsLoopback() || a.IsPrivate()
}

// ======================== 模型倍率、Sub2API OAuth 自动刷新与并发信号量 ========================

type ModelPricing struct {
	BillingMode       string // "token" | "per_call"
	InputMicrosPer1K  int64
	OutputMicrosPer1K int64
	CacheReadRatio    float64
	CacheWriteRatio   float64
	PerCallMicros     int64
}

// CalculateMicros 计算常规输入、Prompt Cache 读折扣、缓存写倍率与输出 Token 的微点折算额。
func (p ModelPricing) CalculateMicros(inTok, cacheReadTok, cacheWriteTok, outTok int, groupRatio float64) int64 {
	if groupRatio <= 0 {
		groupRatio = 1.0
	}
	if p.BillingMode == "per_call" {
		return int64(math.Ceil(float64(p.PerCallMicros) * groupRatio))
	}
	normalIn := max(0, inTok-cacheReadTok-cacheWriteTok)
	inRate := float64(p.InputMicrosPer1K) / 1000.0
	outRate := float64(p.OutputMicrosPer1K) / 1000.0
	crRatio := p.CacheReadRatio
	if crRatio <= 0 {
		crRatio = 0.1
	}
	cwRatio := p.CacheWriteRatio
	if cwRatio <= 0 {
		cwRatio = 1.25
	}
	raw := float64(normalIn)*inRate +
		float64(cacheReadTok)*inRate*crRatio +
		float64(cacheWriteTok)*inRate*cwRatio +
		float64(outTok)*outRate
	return int64(math.Ceil(raw * groupRatio))
}

// OAuthTokenBundle 描述 Sub2API OAuth 渠道的可自动刷新凭据结构。
type OAuthTokenBundle struct {
	AccessToken   string `json:"access_token"`
	RefreshToken  string `json:"refresh_token"`
	ExpiresAtUnix int64  `json:"expires_at"`
	TokenURL      string `json:"token_url,omitempty"`
	ClientID      string `json:"client_id,omitempty"`
	ClientSecret  string `json:"client_secret,omitempty"`
}

type UpstreamChannel struct {
	ID            string
	Name          string
	Kind          ChannelKind
	BaseURL       string
	APIKeyOrToken atomic.Pointer[string]
	Groups        []string
	Models        []string
	ModelMapping  map[string]string
	Priority      int
	Weight        int
	Sem           chan struct{}

	Tripped       atomic.Bool
	CooldownUntil atomic.Int64 // UnixMilli

	oauthMu sync.Mutex
	oauth   *OAuthTokenBundle
}

// SetCredential 注入标准 API Key 或 Sub2API OAuth JSON 凭据。
func (c *UpstreamChannel) SetCredential(raw string) {
	trimmed := strings.TrimSpace(raw)
	if strings.HasPrefix(trimmed, "{") {
		var bundle OAuthTokenBundle
		if json.Unmarshal([]byte(trimmed), &bundle) == nil && bundle.AccessToken != "" {
			c.oauthMu.Lock()
			c.oauth = &bundle
			c.oauthMu.Unlock()
			tok := bundle.AccessToken
			c.APIKeyOrToken.Store(&tok)
			return
		}
	}
	c.APIKeyOrToken.Store(&trimmed)
}

// RefreshOAuthIfNeeded 在 OAuth AccessToken 距过期不足 5 分钟时通过 refresh_token 自动续期并原子热替换。
func (c *UpstreamChannel) RefreshOAuthIfNeeded(ctx context.Context, client *http.Client, now time.Time) (bool, error) {
	c.oauthMu.Lock()
	defer c.oauthMu.Unlock()
	if c.oauth == nil || c.oauth.RefreshToken == "" || c.oauth.TokenURL == "" {
		return false, nil
	}
	if c.oauth.ExpiresAtUnix > 0 && now.Add(5*time.Minute).Unix() < c.oauth.ExpiresAtUnix {
		return false, nil
	}
	if client == nil {
		client = NewSafeHTTPClient(false, 20*time.Second)
	}
	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", c.oauth.RefreshToken)
	if c.oauth.ClientID != "" {
		form.Set("client_id", c.oauth.ClientID)
	}
	if c.oauth.ClientSecret != "" {
		form.Set("client_secret", c.oauth.ClientSecret)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.oauth.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return false, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("oauth refresh status %d", resp.StatusCode)
	}
	var refreshed struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    int64  `json:"expires_in"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&refreshed); err != nil || refreshed.AccessToken == "" {
		return false, errors.New("oauth refresh returned empty access_token")
	}
	c.oauth.AccessToken = refreshed.AccessToken
	if refreshed.RefreshToken != "" {
		c.oauth.RefreshToken = refreshed.RefreshToken
	}
	if refreshed.ExpiresIn > 0 {
		c.oauth.ExpiresAtUnix = now.Unix() + refreshed.ExpiresIn
	}
	tok := c.oauth.AccessToken
	c.APIKeyOrToken.Store(&tok)
	return true, nil
}

// OAuthBundleJSON 返回当前渠道最新 OAuth 凭据包的 JSON 字符串副本，供刷新后加密回写数据库。
func (c *UpstreamChannel) OAuthBundleJSON() (string, bool) {
	c.oauthMu.Lock()
	defer c.oauthMu.Unlock()
	if c.oauth == nil {
		return "", false
	}
	raw, err := json.Marshal(c.oauth)
	if err != nil {
		return "", false
	}
	return string(raw), true
}

// AcquireSlot 获取渠道并发保护信号量槽位，避免 Sub2API OAuth 账号池并发超载触发风控。
func (c *UpstreamChannel) AcquireSlot(ctx context.Context) error {
	if c.Sem == nil {
		return nil
	}
	select {
	case c.Sem <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// ReleaseSlot 归还渠道并发信号量槽位。
func (c *UpstreamChannel) ReleaseSlot() {
	if c.Sem == nil {
		return
	}
	select {
	case <-c.Sem:
	default:
	}
}

// MarkUpstreamStatus 根据上游 HTTP 状态码执行 429 冷却、500/502/503/504 短暂冷却熔断或 401/403 熔断保护。
func (c *UpstreamChannel) MarkUpstreamStatus(statusCode int, retryAfter time.Duration, now time.Time) {
	switch statusCode {
	case http.StatusTooManyRequests:
		if retryAfter <= 0 {
			retryAfter = 60 * time.Second
		}
		c.CooldownUntil.Store(now.Add(retryAfter).UnixMilli())
	case http.StatusInternalServerError, http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		cd := 15 * time.Second
		if retryAfter > 0 && retryAfter < 30*time.Second {
			cd = retryAfter
		}
		c.CooldownUntil.Store(now.Add(cd).UnixMilli())
	case http.StatusUnauthorized, http.StatusForbidden:
		c.Tripped.Store(true)
	}
}

func (c *UpstreamChannel) NativeProtocol() ProtocolKind {
	switch c.Kind {
	case ChanAnthropicNative, ChanSub2ClaudeOAuth:
		return ProtoAnthropicMessages
	case ChanSub2CodexOAuth:
		return ProtoOpenAIResponses
	case ChanGeminiNative, ChanSub2GeminiOAuth:
		return ProtoGeminiNative
	default:
		return ProtoOpenAIChat
	}
}

func (c *UpstreamChannel) UpstreamModel(requested string) string {
	if mapped, ok := c.ModelMapping[requested]; ok && mapped != "" {
		return mapped
	}
	return requested
}

// ======================== Sticky Session 缓存亲和路由器 ========================

type Router struct {
	mu       sync.RWMutex
	channels []*UpstreamChannel
	pricings map[string]ModelPricing
	rrSeq    atomic.Uint64
}

func NewRouter() *Router {
	return &Router{
		pricings: make(map[string]ModelPricing),
	}
}

func (r *Router) ReplaceSnapshot(chs []*UpstreamChannel, prices map[string]ModelPricing) {
	r.mu.Lock()
	r.channels = chs
	r.pricings = prices
	r.mu.Unlock()
}

func (r *Router) PricingFor(model string) ModelPricing {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if p, ok := r.pricings[model]; ok {
		return p
	}
	return ModelPricing{
		BillingMode:       "token",
		InputMicrosPer1K:  2000,
		OutputMicrosPer1K: 8000,
		CacheReadRatio:    0.1,
		CacheWriteRatio:   1.25,
	}
}

// HasConfiguredChannels 报告指定分组与模型是否存在至少一条已配置的上游渠道（无论是否熔断或冷却），
// 避免客户端请求未配置/拼写错误的模型时误报“全部上游渠道熔断”告警。
func (r *Router) HasConfiguredChannels(group, model string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, ch := range r.channels {
		if len(ch.Groups) > 0 && !slices.Contains(ch.Groups, group) {
			continue
		}
		if len(ch.Models) > 0 && model != "" && !slices.Contains(ch.Models, model) {
			continue
		}
		return true
	}
	return false
}

// SelectCandidates 按分组与模型筛选健康渠道；最高优先级层内通过 Sticky Session 哈希锁定上游账号以命中 Prompt Cache。
func (r *Router) SelectCandidates(group, model, sessionAffinityKey string, now time.Time) []*UpstreamChannel {
	nowMs := now.UnixMilli()
	r.mu.RLock()
	var matched []*UpstreamChannel
	for _, ch := range r.channels {
		if ch.Tripped.Load() || ch.CooldownUntil.Load() > nowMs {
			continue
		}
		if len(ch.Groups) > 0 && !slices.Contains(ch.Groups, group) {
			continue
		}
		if len(ch.Models) > 0 && model != "" && !slices.Contains(ch.Models, model) {
			continue
		}
		matched = append(matched, ch)
	}
	r.mu.RUnlock()

	if len(matched) <= 1 {
		return matched
	}
	sort.SliceStable(matched, func(i, j int) bool {
		return matched[i].Priority > matched[j].Priority
	})

	topPrio := matched[0].Priority
	tierEnd := 1
	for tierEnd < len(matched) && matched[tierEnd].Priority == topPrio {
		tierEnd++
	}
	topTier := matched[:tierEnd]
	if len(topTier) > 1 {
		var idx uint64
		if sessionAffinityKey != "" {
			h := fnv.New64a()
			_, _ = h.Write([]byte(sessionAffinityKey))
			idx = h.Sum64() % uint64(len(topTier))
		} else {
			idx = r.rrSeq.Add(1) % uint64(len(topTier))
		}
		if idx != 0 {
			rotated := make([]*UpstreamChannel, 0, len(matched))
			rotated = append(rotated, topTier[idx:]...)
			rotated = append(rotated, topTier[:idx]...)
			rotated = append(rotated, matched[tierEnd:]...)
			return rotated
		}
	}
	return matched
}

// ======================== 四协议中立消息 IR 与 32KiB 池化零缓冲流式双向互转 ========================

var sseLineBufPool = sync.Pool{
	New: func() any {
		b := make([]byte, 32*1024)
		return &b
	},
}

type CanonicalToolCall struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Arguments string `json:"arguments"`
}

type CanonicalToolResult struct {
	ToolCallID string `json:"tool_call_id"`
	Content    string `json:"content"`
	IsError    bool   `json:"is_error,omitempty"`
}

type CanonicalMessage struct {
	Role        string                `json:"role"`
	Content     string                `json:"content"`
	Reasoning   string                `json:"reasoning,omitempty"`
	ToolCalls   []CanonicalToolCall   `json:"tool_calls,omitempty"`
	ToolResults []CanonicalToolResult `json:"tool_results,omitempty"`
}

type CanonicalRequest struct {
	Model                string             `json:"model"`
	System               string             `json:"system,omitempty"`
	Messages             []CanonicalMessage `json:"messages"`
	MaxTokens            int                `json:"max_tokens,omitempty"`
	Temperature          *float64           `json:"temperature,omitempty"`
	Tools                []json.RawMessage  `json:"tools,omitempty"`
	ToolChoice           json.RawMessage    `json:"tool_choice,omitempty"`
	Stream               bool               `json:"stream"`
	SessionHint          string             `json:"-"`
	EstimatedInputTokens int                `json:"-"`
}

type StreamUsage struct {
	InputTokens      int
	CachedReadTokens int
	CacheWriteTokens int
	OutputTokens     int
	TTFTMs           int64
}

// ParseDownstreamRequest 解析 OpenAI Chat / Responses / Anthropic Messages / Gemini 原生请求为统一中立 IR。
func ParseDownstreamRequest(protoIn ProtocolKind, urlModel string, raw []byte) (CanonicalRequest, error) {
	var cr CanonicalRequest
	switch protoIn {
	case ProtoAnthropicMessages:
		var in struct {
			Model       string            `json:"model"`
			System      json.RawMessage   `json:"system"`
			MaxTokens   int               `json:"max_tokens"`
			Temperature *float64          `json:"temperature"`
			Tools       []json.RawMessage `json:"tools"`
			ToolChoice  json.RawMessage   `json:"tool_choice"`
			Stream      bool              `json:"stream"`
			Metadata    struct {
				UserID string `json:"user_id"`
			} `json:"metadata"`
			Messages []struct {
				Role    string          `json:"role"`
				Content json.RawMessage `json:"content"`
			} `json:"messages"`
		}
		if err := json.Unmarshal(raw, &in); err != nil {
			return cr, err
		}
		cr.Model = in.Model
		cr.MaxTokens = in.MaxTokens
		cr.Temperature = in.Temperature
		cr.Tools = in.Tools
		cr.ToolChoice = in.ToolChoice
		cr.Stream = in.Stream
		cr.System = extractFlexibleText(in.System)
		cr.SessionHint = in.Metadata.UserID
		for _, m := range in.Messages {
			txt, tcs, trs := parseAnthropicContentBlocks(m.Content)
			cr.Messages = append(cr.Messages, CanonicalMessage{
				Role:        m.Role,
				Content:     txt,
				ToolCalls:   tcs,
				ToolResults: trs,
			})
		}

	case ProtoOpenAIResponses:
		var in struct {
			Model        string            `json:"model"`
			Instructions string            `json:"instructions"`
			Input        json.RawMessage   `json:"input"`
			Temperature  *float64          `json:"temperature"`
			Tools        []json.RawMessage `json:"tools"`
			ToolChoice   json.RawMessage   `json:"tool_choice"`
			Stream       bool              `json:"stream"`
		}
		if err := json.Unmarshal(raw, &in); err != nil {
			return cr, err
		}
		cr.Model = in.Model
		cr.System = in.Instructions
		cr.Temperature = in.Temperature
		cr.Tools = in.Tools
		cr.ToolChoice = in.ToolChoice
		cr.Stream = in.Stream
		cr.Messages = []CanonicalMessage{{Role: "user", Content: extractFlexibleText(in.Input)}}

	case ProtoGeminiNative:
		cr.Model = urlModel
		cr.Stream = true
		var in struct {
			SystemInstruction struct {
				Parts []struct {
					Text string `json:"text"`
				} `json:"parts"`
			} `json:"systemInstruction"`
			Contents []struct {
				Role  string `json:"role"`
				Parts []struct {
					Text string `json:"text"`
				} `json:"parts"`
			} `json:"contents"`
		}
		if err := json.Unmarshal(raw, &in); err != nil {
			return cr, err
		}
		for _, p := range in.SystemInstruction.Parts {
			cr.System += p.Text
		}
		for _, c := range in.Contents {
			role := "user"
			if c.Role == "model" {
				role = "assistant"
			}
			var sb strings.Builder
			for _, p := range c.Parts {
				sb.WriteString(p.Text)
			}
			cr.Messages = append(cr.Messages, CanonicalMessage{Role: role, Content: sb.String()})
		}

	default: // ProtoOpenAIChat
		var in struct {
			Model       string            `json:"model"`
			MaxTokens   int               `json:"max_tokens"`
			Temperature *float64          `json:"temperature"`
			Tools       []json.RawMessage `json:"tools"`
			ToolChoice  json.RawMessage   `json:"tool_choice"`
			Stream      bool              `json:"stream"`
			User        string            `json:"user"`
			Messages    []struct {
				Role       string          `json:"role"`
				Content    json.RawMessage `json:"content"`
				ToolCallID string          `json:"tool_call_id"`
				ToolCalls  []struct {
					ID       string `json:"id"`
					Type     string `json:"type"`
					Function struct {
						Name      string `json:"name"`
						Arguments string `json:"arguments"`
					} `json:"function"`
				} `json:"tool_calls"`
			} `json:"messages"`
		}
		if err := json.Unmarshal(raw, &in); err != nil {
			return cr, err
		}
		cr.Model = in.Model
		cr.MaxTokens = in.MaxTokens
		cr.Temperature = in.Temperature
		cr.Tools = in.Tools
		cr.ToolChoice = in.ToolChoice
		cr.Stream = in.Stream
		cr.SessionHint = in.User
		for _, m := range in.Messages {
			txt := extractFlexibleText(m.Content)
			if m.Role == "system" || m.Role == "developer" {
				if cr.System != "" {
					cr.System += "\n"
				}
				cr.System += txt
			} else if m.Role == "tool" {
				cr.Messages = append(cr.Messages, CanonicalMessage{
					Role: "tool",
					ToolResults: []CanonicalToolResult{{
						ToolCallID: m.ToolCallID,
						Content:    txt,
					}},
				})
			} else {
				cm := CanonicalMessage{Role: m.Role, Content: txt}
				for _, tc := range m.ToolCalls {
					if tc.Function.Name != "" {
						cm.ToolCalls = append(cm.ToolCalls, CanonicalToolCall{
							ID:        tc.ID,
							Name:      tc.Function.Name,
							Arguments: tc.Function.Arguments,
						})
					}
				}
				cr.Messages = append(cr.Messages, cm)
			}
		}
	}

	if cr.SessionHint == "" && len(cr.Messages) > 0 {
		prefix := cr.System + "|" + cr.Messages[0].Content
		if len(prefix) > 256 {
			prefix = prefix[:256]
		}
		cr.SessionHint = prefix
	}
	textBytes := len(cr.System)
	for _, m := range cr.Messages {
		textBytes += len(m.Content)
	}
	est := max(textBytes/4, len(raw)/6)
	if est < 1 && len(raw) > 0 {
		est = 1
	}
	cr.EstimatedInputTokens = est
	return cr, nil
}

func extractFlexibleText(raw json.RawMessage) string {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return ""
	}
	var s string
	if json.Unmarshal(trimmed, &s) == nil {
		return s
	}
	var blocks []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	}
	if json.Unmarshal(trimmed, &blocks) == nil {
		var sb strings.Builder
		for _, b := range blocks {
			if b.Text != "" {
				sb.WriteString(b.Text)
			}
		}
		return sb.String()
	}
	return string(trimmed)
}

func parseAnthropicContentBlocks(raw json.RawMessage) (string, []CanonicalToolCall, []CanonicalToolResult) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return "", nil, nil
	}
	var s string
	if json.Unmarshal(trimmed, &s) == nil {
		return s, nil, nil
	}
	var blocks []struct {
		Type      string          `json:"type"`
		Text      string          `json:"text"`
		ID        string          `json:"id"`
		Name      string          `json:"name"`
		Input     json.RawMessage `json:"input"`
		ToolUseID string          `json:"tool_use_id"`
		Content   json.RawMessage `json:"content"`
		IsError   bool            `json:"is_error"`
	}
	if json.Unmarshal(trimmed, &blocks) != nil {
		return string(trimmed), nil, nil
	}
	var sb strings.Builder
	var tcs []CanonicalToolCall
	var trs []CanonicalToolResult
	for _, b := range blocks {
		switch b.Type {
		case "tool_use":
			args := strings.TrimSpace(string(b.Input))
			if args == "" {
				args = "{}"
			}
			tcs = append(tcs, CanonicalToolCall{ID: b.ID, Name: b.Name, Arguments: args})
		case "tool_result":
			trs = append(trs, CanonicalToolResult{
				ToolCallID: b.ToolUseID,
				Content:    extractFlexibleText(b.Content),
				IsError:    b.IsError,
			})
		default:
			if b.Text != "" {
				sb.WriteString(b.Text)
			}
		}
	}
	return sb.String(), tcs, trs
}

// EncodeUpstreamRequest 将中立 IR 编码为目标渠道原生协议请求（同协议同模型时原样零损耗直通）。
func EncodeUpstreamRequest(ch *UpstreamChannel, protoIn ProtocolKind, rawOriginal []byte, ir CanonicalRequest) (urlStr string, headers map[string]string, body []byte, err error) {
	upProto := ch.NativeProtocol()
	upModel := ch.UpstreamModel(ir.Model)
	tokPtr := ch.APIKeyOrToken.Load()
	cred := ""
	if tokPtr != nil {
		cred = *tokPtr
	}
	base := NormalizeUpstreamBaseURL(ch.BaseURL)

	if protoIn == upProto && len(rawOriginal) > 0 {
		passthroughBody := rawOriginal
		if upModel != ir.Model && upProto != ProtoGeminiNative {
			var rawMap map[string]json.RawMessage
			if err := json.Unmarshal(rawOriginal, &rawMap); err == nil && rawMap != nil {
				if encodedModel, mErr := json.Marshal(upModel); mErr == nil {
					rawMap["model"] = encodedModel
					if patched, mErr := json.Marshal(rawMap); mErr == nil {
						passthroughBody = patched
					}
				}
			}
		}
		switch upProto {
		case ProtoAnthropicMessages:
			hdrs := map[string]string{
				"Content-Type":      "application/json",
				"anthropic-version": "2023-06-01",
			}
			if ch.Kind == ChanSub2ClaudeOAuth {
				hdrs["Authorization"] = "Bearer " + cred
				hdrs["anthropic-beta"] = "oauth-2025-04-20,prompt-caching-2024-07-31"
			} else {
				hdrs["x-api-key"] = cred
			}
			return base + "/v1/messages", hdrs, passthroughBody, nil
		case ProtoOpenAIResponses:
			return base + "/v1/responses", map[string]string{
				"Content-Type":  "application/json",
				"Authorization": "Bearer " + cred,
			}, passthroughBody, nil
		case ProtoGeminiNative:
			endpoint := fmt.Sprintf("%s/v1beta/models/%s:streamGenerateContent?alt=sse", base, upModel)
			if !ir.Stream {
				endpoint = fmt.Sprintf("%s/v1beta/models/%s:generateContent", base, upModel)
			}
			return endpoint, map[string]string{
				"Content-Type":   "application/json",
				"x-goog-api-key": cred,
			}, passthroughBody, nil
		case ProtoOpenAIChat:
			return base + "/v1/chat/completions", map[string]string{
				"Content-Type":  "application/json",
				"Authorization": "Bearer " + cred,
			}, passthroughBody, nil
		}
	}

	switch upProto {
	case ProtoAnthropicMessages:
		maxTok := ir.MaxTokens
		if maxTok <= 0 {
			maxTok = 8192
		}
		msgs := make([]map[string]any, 0, len(ir.Messages))
		appendAnthropicMsg := func(role string, blocks []map[string]any) {
			if len(blocks) == 0 {
				return
			}
			if len(msgs) > 0 && msgs[len(msgs)-1]["role"] == role {
				prev := msgs[len(msgs)-1]
				switch existing := prev["content"].(type) {
				case []map[string]any:
					prev["content"] = append(existing, blocks...)
					return
				case string:
					merged := make([]map[string]any, 0, 1+len(blocks))
					if existing != "" {
						merged = append(merged, map[string]any{"type": "text", "text": existing})
					}
					prev["content"] = append(merged, blocks...)
					return
				}
			}
			if len(blocks) == 1 && blocks[0]["type"] == "text" {
				if txt, ok := blocks[0]["text"].(string); ok {
					msgs = append(msgs, map[string]any{"role": role, "content": txt})
					return
				}
			}
			msgs = append(msgs, map[string]any{"role": role, "content": blocks})
		}
		for _, m := range ir.Messages {
			role := m.Role
			if role == "tool" || len(m.ToolResults) > 0 {
				role = "user"
			}
			blocks := make([]map[string]any, 0, len(m.ToolCalls)+len(m.ToolResults)+1)
			if m.Content != "" || (len(m.ToolCalls) == 0 && len(m.ToolResults) == 0) {
				blocks = append(blocks, map[string]any{"type": "text", "text": m.Content})
			}
			for idx, tc := range m.ToolCalls {
				id := tc.ID
				if id == "" {
					id = fmt.Sprintf("toolu_qwq_%d", idx)
				}
				var inputObj map[string]any
				if err := json.Unmarshal([]byte(tc.Arguments), &inputObj); err != nil || inputObj == nil {
					inputObj = map[string]any{}
				}
				blocks = append(blocks, map[string]any{
					"type":  "tool_use",
					"id":    id,
					"name":  tc.Name,
					"input": inputObj,
				})
			}
			for _, tr := range m.ToolResults {
				item := map[string]any{
					"type":        "tool_result",
					"tool_use_id": tr.ToolCallID,
					"content":     tr.Content,
				}
				if tr.IsError {
					item["is_error"] = true
				}
				blocks = append(blocks, item)
			}
			appendAnthropicMsg(role, blocks)
		}
		payload := map[string]any{
			"model":      upModel,
			"max_tokens": maxTok,
			"messages":   msgs,
			"stream":     true,
		}
		if ir.System != "" {
			payload["system"] = ir.System
		}
		if ir.Temperature != nil {
			payload["temperature"] = *ir.Temperature
		}
		if len(ir.Tools) > 0 {
			payload["tools"] = translateToolsToAnthropic(ir.Tools)
		}
		if len(bytes.TrimSpace(ir.ToolChoice)) > 0 {
			if tc := translateToolChoiceToAnthropic(ir.ToolChoice); tc != nil {
				payload["tool_choice"] = tc
			}
		}
		b, _ := json.Marshal(payload)
		hdrs := map[string]string{
			"Content-Type":      "application/json",
			"anthropic-version": "2023-06-01",
		}
		if ch.Kind == ChanSub2ClaudeOAuth {
			hdrs["Authorization"] = "Bearer " + cred
			hdrs["anthropic-beta"] = "oauth-2025-04-20,prompt-caching-2024-07-31"
		} else {
			hdrs["x-api-key"] = cred
		}
		return base + "/v1/messages", hdrs, b, nil

	case ProtoOpenAIResponses:
		var inputBuf strings.Builder
		for _, m := range ir.Messages {
			if inputBuf.Len() > 0 {
				inputBuf.WriteByte('\n')
			}
			inputBuf.WriteString(m.Content)
		}
		payload := map[string]any{
			"model":  upModel,
			"input":  inputBuf.String(),
			"stream": true,
		}
		if ir.System != "" {
			payload["instructions"] = ir.System
		}
		if ir.Temperature != nil {
			payload["temperature"] = *ir.Temperature
		}
		if len(ir.Tools) > 0 {
			payload["tools"] = translateToolsToOpenAI(ir.Tools)
		}
		if len(bytes.TrimSpace(ir.ToolChoice)) > 0 {
			if tc := translateToolChoiceToOpenAI(ir.ToolChoice); tc != nil {
				payload["tool_choice"] = tc
			}
		}
		b, _ := json.Marshal(payload)
		return base + "/v1/responses", map[string]string{
			"Content-Type":  "application/json",
			"Authorization": "Bearer " + cred,
		}, b, nil

	case ProtoGeminiNative:
		contents := make([]map[string]any, 0, len(ir.Messages))
		for _, m := range ir.Messages {
			role := "user"
			if m.Role == "assistant" {
				role = "model"
			}
			contents = append(contents, map[string]any{
				"role":  role,
				"parts": []map[string]string{{"text": m.Content}},
			})
		}
		payload := map[string]any{"contents": contents}
		if ir.System != "" {
			payload["systemInstruction"] = map[string]any{
				"parts": []map[string]string{{"text": ir.System}},
			}
		}
		b, _ := json.Marshal(payload)
		return fmt.Sprintf("%s/v1beta/models/%s:streamGenerateContent?alt=sse", base, upModel),
			map[string]string{"Content-Type": "application/json", "x-goog-api-key": cred}, b, nil

	default:
		msgs := make([]map[string]any, 0, len(ir.Messages)+1)
		if ir.System != "" {
			msgs = append(msgs, map[string]any{"role": "system", "content": ir.System})
		}
		for _, m := range ir.Messages {
			if len(m.ToolResults) > 0 {
				for _, tr := range m.ToolResults {
					msgs = append(msgs, map[string]any{
						"role":         "tool",
						"tool_call_id": tr.ToolCallID,
						"content":      tr.Content,
					})
				}
				if m.Content != "" {
					msgs = append(msgs, map[string]any{"role": "user", "content": m.Content})
				}
				continue
			}
			if len(m.ToolCalls) > 0 {
				tcs := make([]map[string]any, 0, len(m.ToolCalls))
				for idx, tc := range m.ToolCalls {
					id := tc.ID
					if id == "" {
						id = fmt.Sprintf("call_qwq_%d", idx)
					}
					args := tc.Arguments
					if strings.TrimSpace(args) == "" {
						args = "{}"
					}
					tcs = append(tcs, map[string]any{
						"id":   id,
						"type": "function",
						"function": map[string]any{
							"name":      tc.Name,
							"arguments": args,
						},
					})
				}
				msg := map[string]any{
					"role":       "assistant",
					"tool_calls": tcs,
				}
				if m.Content != "" {
					msg["content"] = m.Content
				} else {
					msg["content"] = nil
				}
				msgs = append(msgs, msg)
				continue
			}
			msgs = append(msgs, map[string]any{"role": m.Role, "content": m.Content})
		}
		payload := map[string]any{
			"model":          upModel,
			"messages":       msgs,
			"stream":         true,
			"stream_options": map[string]bool{"include_usage": true},
		}
		if ir.MaxTokens > 0 {
			payload["max_tokens"] = ir.MaxTokens
		}
		if ir.Temperature != nil {
			payload["temperature"] = *ir.Temperature
		}
		if len(ir.Tools) > 0 {
			payload["tools"] = translateToolsToOpenAI(ir.Tools)
		}
		if len(bytes.TrimSpace(ir.ToolChoice)) > 0 {
			if tc := translateToolChoiceToOpenAI(ir.ToolChoice); tc != nil {
				payload["tool_choice"] = tc
			}
		}
		b, _ := json.Marshal(payload)
		return base + "/v1/chat/completions", map[string]string{
			"Content-Type":  "application/json",
			"Authorization": "Bearer " + cred,
		}, b, nil
	}
}

const maxStreamToolArgsBytes = 2 << 20

// RelayStreamBridge 零全量缓冲地边读上游 SSE 边向下游写出四协议转换帧并提取精确 Token 与 Prompt Cache 用量。
func RelayStreamBridge(
	startedAt time.Time,
	upBody io.Reader,
	upProto, downProto ProtocolKind,
	reqModel string,
	w http.ResponseWriter,
) (StreamUsage, error) {
	w.Header().Set("Content-Type", "text/event-stream; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	flusher, _ := w.(http.Flusher)

	bufPtr := sseLineBufPool.Get().(*[]byte)
	defer sseLineBufPool.Put(bufPtr)

	sc := bufio.NewScanner(upBody)
	sc.Buffer(*bufPtr, 2<<20)

	var usage StreamUsage
	var estOutChars int
	var writeErr error
	var anthropicSM *AnthropicSSEStateMachine
	if upProto != downProto && downProto == ProtoAnthropicMessages {
		anthropicSM = NewAnthropicSSEStateMachine(w, reqModel)
	}
	toolAccum := make(map[int]*CanonicalToolCall)
	var toolOrder []int
	openAIToolSlot := make(map[int]int)
	var emittedToolCalls bool

	writeFormatted := func(format string, args ...any) {
		if writeErr != nil {
			return
		}
		if _, err := fmt.Fprintf(w, format, args...); err != nil {
			writeErr = err
		}
	}

	recordToolDelta := func(td streamToolCallDelta) {
		if writeErr != nil {
			return
		}
		if usage.TTFTMs == 0 {
			usage.TTFTMs = time.Since(startedAt).Milliseconds()
		}
		estOutChars += len(td.Name) + len(td.ArgsDelta)
		acc, ok := toolAccum[td.Index]
		if !ok {
			if len(toolAccum) >= 64 {
				return
			}
			acc = &CanonicalToolCall{ID: td.ID, Name: td.Name}
			toolAccum[td.Index] = acc
			toolOrder = append(toolOrder, td.Index)
		}
		if td.ID != "" && acc.ID == "" {
			acc.ID = td.ID
		}
		if td.Name != "" && acc.Name == "" {
			acc.Name = td.Name
		}
		if len(acc.Arguments)+len(td.ArgsDelta) <= maxStreamToolArgsBytes {
			acc.Arguments += td.ArgsDelta
		}

		// OpenAI Chat 下游支持边收边流式推送 tool_calls 增量块。
		if downProto == ProtoOpenAIChat {
			slot, exists := openAIToolSlot[td.Index]
			if !exists {
				slot = len(openAIToolSlot)
				openAIToolSlot[td.Index] = slot
			}
			fnObj := map[string]any{}
			if td.Name != "" {
				fnObj["name"] = td.Name
			}
			if td.ArgsDelta != "" {
				fnObj["arguments"] = td.ArgsDelta
			}
			tcObj := map[string]any{
				"index": slot,
			}
			if td.ID != "" || td.Start {
				id := acc.ID
				if id == "" {
					id = fmt.Sprintf("call_qwq_%d", slot)
				}
				tcObj["id"] = id
				tcObj["type"] = "function"
			}
			if len(fnObj) > 0 {
				tcObj["function"] = fnObj
			}
			chunk, _ := json.Marshal(map[string]any{
				"id":     "chatcmpl-qwq",
				"object": "chat.completion.chunk",
				"model":  reqModel,
				"choices": []map[string]any{{
					"index": 0,
					"delta": map[string]any{
						"tool_calls": []map[string]any{tcObj},
					},
				}},
			})
			writeFormatted("data: %s\n\n", chunk)
			emittedToolCalls = true
			if writeErr == nil && flusher != nil {
				flusher.Flush()
			}
		}
	}

	emitDownstreamDelta := func(textDelta, reasoningDelta string) {
		if (textDelta == "" && reasoningDelta == "") || writeErr != nil {
			return
		}
		if usage.TTFTMs == 0 {
			usage.TTFTMs = time.Since(startedAt).Milliseconds()
		}
		estOutChars += len(textDelta) + len(reasoningDelta)

		switch downProto {
		case ProtoAnthropicMessages:
			if anthropicSM != nil {
				anthropicSM.EmitDelta(usage.InputTokens, reasoningDelta, textDelta)
				if err := anthropicSM.Err(); err != nil {
					writeErr = err
				}
			}

		case ProtoOpenAIResponses:
			if reasoningDelta != "" {
				chunk, _ := json.Marshal(map[string]any{
					"type":  "response.reasoning_summary_text.delta",
					"delta": reasoningDelta,
				})
				writeFormatted("event: response.reasoning_summary_text.delta\ndata: %s\n\n", chunk)
			}
			if textDelta != "" {
				chunk, _ := json.Marshal(map[string]any{
					"type":  "response.output_text.delta",
					"delta": textDelta,
				})
				writeFormatted("event: response.output_text.delta\ndata: %s\n\n", chunk)
			}

		case ProtoGeminiNative:
			parts := make([]map[string]any, 0, 2)
			if reasoningDelta != "" {
				parts = append(parts, map[string]any{"text": reasoningDelta, "thought": true})
			}
			if textDelta != "" {
				parts = append(parts, map[string]any{"text": textDelta})
			}
			chunk, _ := json.Marshal(map[string]any{
				"candidates": []map[string]any{
					{"content": map[string]any{"role": "model", "parts": parts}},
				},
			})
			writeFormatted("data: %s\n\n", chunk)

		default: // ProtoOpenAIChat
			deltaObj := map[string]any{}
			if textDelta != "" {
				deltaObj["content"] = textDelta
			}
			if reasoningDelta != "" {
				deltaObj["reasoning_content"] = reasoningDelta
			}
			chunk, _ := json.Marshal(map[string]any{
				"id":      "chatcmpl-qwq",
				"object":  "chat.completion.chunk",
				"model":   reqModel,
				"choices": []map[string]any{{"index": 0, "delta": deltaObj}},
			})
			writeFormatted("data: %s\n\n", chunk)
		}
		if writeErr == nil && flusher != nil {
			flusher.Flush()
		}
	}

	for sc.Scan() {
		line := sc.Bytes()
		if upProto == downProto {
			if usage.TTFTMs == 0 && bytes.HasPrefix(line, []byte("data:")) {
				usage.TTFTMs = time.Since(startedAt).Milliseconds()
			}
			if _, err := w.Write(line); err != nil {
				writeErr = err
				break
			}
			if _, err := w.Write([]byte("\n")); err != nil {
				writeErr = err
				break
			}
			if len(line) == 0 && flusher != nil {
				flusher.Flush()
			}
			if after, ok := bytes.CutPrefix(line, []byte("data:")); ok {
				sniffUsageFromDataFrame(bytes.TrimSpace(after), upProto, &usage, &estOutChars)
			}
			continue
		}

		after, ok := bytes.CutPrefix(line, []byte("data:"))
		if !ok {
			continue
		}
		payload := bytes.TrimSpace(after)
		if len(payload) == 0 || bytes.Equal(payload, []byte("[DONE]")) {
			continue
		}
		textD, reasonD, toolDeltas := parseUpstreamEvent(payload, upProto, &usage)
		emitDownstreamDelta(textD, reasonD)
		if writeErr != nil {
			break
		}
		for _, td := range toolDeltas {
			recordToolDelta(td)
			if writeErr != nil {
				break
			}
		}
		if writeErr != nil {
			break
		}
	}

	if upProto != downProto && writeErr == nil {
		switch downProto {
		case ProtoAnthropicMessages:
			if anthropicSM != nil {
				for _, idx := range toolOrder {
					tc := toolAccum[idx]
					if tc != nil && tc.Name != "" {
						anthropicSM.EmitToolUseBlock(usage.InputTokens, tc.ID, tc.Name, tc.Arguments)
						emittedToolCalls = true
					}
				}
				stopReason := "end_turn"
				if emittedToolCalls {
					stopReason = "tool_use"
				}
				anthropicSM.Finish(usage.InputTokens, max(usage.OutputTokens, estOutChars/4), stopReason)
				if err := anthropicSM.Err(); err != nil {
					writeErr = err
				}
			}
		case ProtoOpenAIResponses:
			for _, idx := range toolOrder {
				tc := toolAccum[idx]
				if tc == nil || tc.Name == "" {
					continue
				}
				itemDone, _ := json.Marshal(map[string]any{
					"type": "response.output_item.done",
					"item": map[string]any{
						"type":      "function_call",
						"call_id":   tc.ID,
						"name":      tc.Name,
						"arguments": tc.Arguments,
					},
				})
				writeFormatted("event: response.output_item.done\ndata: %s\n\n", itemDone)
			}
			completed, _ := json.Marshal(map[string]any{
				"type": "response.completed",
				"response": map[string]any{
					"status": "completed",
					"usage": map[string]any{
						"input_tokens":  usage.InputTokens,
						"output_tokens": max(usage.OutputTokens, estOutChars/4),
					},
				},
			})
			writeFormatted("event: response.completed\ndata: %s\n\n", completed)
		case ProtoGeminiNative:
			if len(toolOrder) > 0 {
				parts := make([]map[string]any, 0, len(toolOrder))
				for _, idx := range toolOrder {
					tc := toolAccum[idx]
					if tc == nil || tc.Name == "" {
						continue
					}
					var argsObj map[string]any
					if err := json.Unmarshal([]byte(tc.Arguments), &argsObj); err != nil || argsObj == nil {
						argsObj = map[string]any{}
					}
					parts = append(parts, map[string]any{
						"functionCall": map[string]any{
							"name": tc.Name,
							"args": argsObj,
						},
					})
				}
				if len(parts) > 0 {
					chunk, _ := json.Marshal(map[string]any{
						"candidates": []map[string]any{
							{"content": map[string]any{"role": "model", "parts": parts}},
						},
					})
					writeFormatted("data: %s\n\n", chunk)
				}
			}
		case ProtoOpenAIChat:
			finishReason := "stop"
			if emittedToolCalls {
				finishReason = "tool_calls"
			}
			finChunk, _ := json.Marshal(map[string]any{
				"id":     "chatcmpl-qwq",
				"object": "chat.completion.chunk",
				"model":  reqModel,
				"choices": []map[string]any{{
					"index":         0,
					"delta":         map[string]any{},
					"finish_reason": finishReason,
				}},
			})
			writeFormatted("data: %s\n\n", finChunk)
			if writeErr == nil {
				if _, err := io.WriteString(w, "data: [DONE]\n\n"); err != nil {
					writeErr = err
				}
			}
		}
		if writeErr == nil && flusher != nil {
			flusher.Flush()
		}
	}

	if usage.OutputTokens == 0 && estOutChars > 0 {
		usage.OutputTokens = max(1, estOutChars/4)
	}
	if writeErr != nil {
		return usage, writeErr
	}
	return usage, sc.Err()
}

func sniffUsageFromDataFrame(payload []byte, proto ProtocolKind, u *StreamUsage, estChars *int) {
	if len(payload) == 0 || payload[0] != '{' {
		return
	}
	parseUpstreamDeltaAndUsage(payload, proto, u)
	*estChars += len(payload) / 12
}

type streamToolCallDelta struct {
	Index     int
	ID        string
	Name      string
	ArgsDelta string
	Start     bool
}

func parseUpstreamDeltaAndUsage(payload []byte, proto ProtocolKind, u *StreamUsage) (textDelta string, reasonDelta string) {
	t, r, _ := parseUpstreamEvent(payload, proto, u)
	return t, r
}

func parseUpstreamEvent(payload []byte, proto ProtocolKind, u *StreamUsage) (textDelta string, reasonDelta string, toolDeltas []streamToolCallDelta) {
	switch proto {
	case ProtoAnthropicMessages:
		var ev struct {
			Type         string `json:"type"`
			Index        int    `json:"index"`
			ContentBlock struct {
				Type string `json:"type"`
				ID   string `json:"id"`
				Name string `json:"name"`
			} `json:"content_block"`
			Message struct {
				Usage struct {
					InputTokens              int `json:"input_tokens"`
					CacheReadInputTokens     int `json:"cache_read_input_tokens"`
					CacheCreationInputTokens int `json:"cache_creation_input_tokens"`
					OutputTokens             int `json:"output_tokens"`
				} `json:"usage"`
			} `json:"message"`
			Delta struct {
				Type        string `json:"type"`
				Text        string `json:"text"`
				Thinking    string `json:"thinking"`
				PartialJSON string `json:"partial_json"`
			} `json:"delta"`
			Usage struct {
				OutputTokens int `json:"output_tokens"`
			} `json:"usage"`
		}
		if json.Unmarshal(payload, &ev) == nil {
			if ev.Message.Usage.InputTokens > 0 || ev.Message.Usage.CacheReadInputTokens > 0 || ev.Message.Usage.CacheCreationInputTokens > 0 {
				u.InputTokens = ev.Message.Usage.InputTokens + ev.Message.Usage.CacheReadInputTokens + ev.Message.Usage.CacheCreationInputTokens
				u.CachedReadTokens = ev.Message.Usage.CacheReadInputTokens
				u.CacheWriteTokens = ev.Message.Usage.CacheCreationInputTokens
			}
			if ev.Usage.OutputTokens > 0 {
				u.OutputTokens = ev.Usage.OutputTokens
			}
			if ev.Type == "content_block_start" && ev.ContentBlock.Type == "tool_use" {
				toolDeltas = append(toolDeltas, streamToolCallDelta{
					Index: ev.Index,
					ID:    ev.ContentBlock.ID,
					Name:  ev.ContentBlock.Name,
					Start: true,
				})
			} else if ev.Delta.Type == "input_json_delta" && ev.Delta.PartialJSON != "" {
				toolDeltas = append(toolDeltas, streamToolCallDelta{
					Index:     ev.Index,
					ArgsDelta: ev.Delta.PartialJSON,
				})
			}
			return ev.Delta.Text, ev.Delta.Thinking, toolDeltas
		}

	case ProtoGeminiNative:
		var ev struct {
			Candidates []struct {
				Content struct {
					Parts []struct {
						Text         string `json:"text"`
						Thought      bool   `json:"thought"`
						FunctionCall *struct {
							Name string          `json:"name"`
							Args json.RawMessage `json:"args"`
						} `json:"functionCall"`
					} `json:"parts"`
				} `json:"content"`
			} `json:"candidates"`
			UsageMetadata struct {
				PromptTokenCount        int `json:"promptTokenCount"`
				CachedContentTokenCount int `json:"cachedContentTokenCount"`
				CandidatesTokenCount    int `json:"candidatesTokenCount"`
			} `json:"usageMetadata"`
		}
		if json.Unmarshal(payload, &ev) == nil {
			if ev.UsageMetadata.PromptTokenCount > 0 {
				u.InputTokens = ev.UsageMetadata.PromptTokenCount
				u.CachedReadTokens = ev.UsageMetadata.CachedContentTokenCount
			}
			if ev.UsageMetadata.CandidatesTokenCount > 0 {
				u.OutputTokens = ev.UsageMetadata.CandidatesTokenCount
			}
			if len(ev.Candidates) > 0 {
				for idx, p := range ev.Candidates[0].Content.Parts {
					if p.FunctionCall != nil && p.FunctionCall.Name != "" {
						args := strings.TrimSpace(string(p.FunctionCall.Args))
						if args == "" {
							args = "{}"
						}
						toolDeltas = append(toolDeltas, streamToolCallDelta{
							Index:     idx,
							ID:        fmt.Sprintf("call_gem_%d", idx),
							Name:      p.FunctionCall.Name,
							ArgsDelta: args,
							Start:     true,
						})
					} else if p.Thought {
						reasonDelta += p.Text
					} else {
						textDelta += p.Text
					}
				}
			}
			return textDelta, reasonDelta, toolDeltas
		}

	case ProtoOpenAIResponses:
		var ev struct {
			Type     string `json:"type"`
			Delta    string `json:"delta"`
			Response struct {
				Usage struct {
					InputTokens        int `json:"input_tokens"`
					OutputTokens       int `json:"output_tokens"`
					InputTokensDetails struct {
						CachedTokens int `json:"cached_tokens"`
					} `json:"input_tokens_details"`
				} `json:"usage"`
			} `json:"response"`
		}
		if json.Unmarshal(payload, &ev) == nil {
			switch ev.Type {
			case "response.output_text.delta":
				return ev.Delta, "", nil
			case "response.reasoning_summary_text.delta":
				return "", ev.Delta, nil
			case "response.completed":
				if ev.Response.Usage.InputTokens > 0 {
					u.InputTokens = ev.Response.Usage.InputTokens
					u.CachedReadTokens = ev.Response.Usage.InputTokensDetails.CachedTokens
				}
				if ev.Response.Usage.OutputTokens > 0 {
					u.OutputTokens = ev.Response.Usage.OutputTokens
				}
			}
		}

	default: // ProtoOpenAIChat
		var ev struct {
			Choices []struct {
				Delta struct {
					Content          string `json:"content"`
					ReasoningContent string `json:"reasoning_content"`
					ToolCalls        []struct {
						Index    int    `json:"index"`
						ID       string `json:"id"`
						Function struct {
							Name      string `json:"name"`
							Arguments string `json:"arguments"`
						} `json:"function"`
					} `json:"tool_calls"`
				} `json:"delta"`
			} `json:"choices"`
			Usage struct {
				PromptTokens        int `json:"prompt_tokens"`
				CompletionTokens    int `json:"completion_tokens"`
				PromptTokensDetails struct {
					CachedTokens int `json:"cached_tokens"`
				} `json:"prompt_tokens_details"`
			} `json:"usage"`
		}
		if json.Unmarshal(payload, &ev) == nil {
			if ev.Usage.PromptTokens > 0 {
				u.InputTokens = ev.Usage.PromptTokens
				u.CachedReadTokens = ev.Usage.PromptTokensDetails.CachedTokens
			}
			if ev.Usage.CompletionTokens > 0 {
				u.OutputTokens = ev.Usage.CompletionTokens
			}
			if len(ev.Choices) > 0 {
				for _, tc := range ev.Choices[0].Delta.ToolCalls {
					toolDeltas = append(toolDeltas, streamToolCallDelta{
						Index:     tc.Index,
						ID:        tc.ID,
						Name:      tc.Function.Name,
						ArgsDelta: tc.Function.Arguments,
						Start:     tc.ID != "" || tc.Function.Name != "",
					})
				}
				return ev.Choices[0].Delta.Content, ev.Choices[0].Delta.ReasoningContent, toolDeltas
			}
		}
	}
	return "", "", nil
}

func translateToolsToAnthropic(tools []json.RawMessage) []any {
	out := make([]any, 0, len(tools))
	for _, raw := range tools {
		var openAI struct {
			Type     string `json:"type"`
			Function *struct {
				Name        string          `json:"name"`
				Description string          `json:"description"`
				Parameters  json.RawMessage `json:"parameters"`
			} `json:"function"`
		}
		if json.Unmarshal(raw, &openAI) == nil && openAI.Function != nil && openAI.Function.Name != "" {
			schema := openAI.Function.Parameters
			if len(bytes.TrimSpace(schema)) == 0 {
				schema = json.RawMessage(`{"type":"object","properties":{}}`)
			}
			item := map[string]any{
				"name":         openAI.Function.Name,
				"input_schema": schema,
			}
			if openAI.Function.Description != "" {
				item["description"] = openAI.Function.Description
			}
			out = append(out, item)
			continue
		}
		out = append(out, raw)
	}
	return out
}

func translateToolsToOpenAI(tools []json.RawMessage) []any {
	out := make([]any, 0, len(tools))
	for _, raw := range tools {
		var ant struct {
			Name        string          `json:"name"`
			Description string          `json:"description"`
			InputSchema json.RawMessage `json:"input_schema"`
			Type        string          `json:"type"`
		}
		if json.Unmarshal(raw, &ant) == nil && ant.Name != "" && len(bytes.TrimSpace(ant.InputSchema)) > 0 {
			fn := map[string]any{
				"name":       ant.Name,
				"parameters": ant.InputSchema,
			}
			if ant.Description != "" {
				fn["description"] = ant.Description
			}
			out = append(out, map[string]any{
				"type":     "function",
				"function": fn,
			})
			continue
		}
		out = append(out, raw)
	}
	return out
}

func translateToolChoiceToAnthropic(raw json.RawMessage) any {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return nil
	}
	var str string
	if json.Unmarshal(trimmed, &str) == nil {
		switch str {
		case "auto":
			return map[string]any{"type": "auto"}
		case "required":
			return map[string]any{"type": "any"}
		case "none":
			return map[string]any{"type": "none"}
		}
	}
	var obj struct {
		Type     string `json:"type"`
		Name     string `json:"name"`
		Function *struct {
			Name string `json:"name"`
		} `json:"function"`
	}
	if json.Unmarshal(trimmed, &obj) == nil && obj.Type == "function" && obj.Function != nil && obj.Function.Name != "" {
		return map[string]any{"type": "tool", "name": obj.Function.Name}
	}
	return raw
}

func translateToolChoiceToOpenAI(raw json.RawMessage) any {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return nil
	}
	var obj struct {
		Type string `json:"type"`
		Name string `json:"name"`
	}
	if json.Unmarshal(trimmed, &obj) == nil {
		switch obj.Type {
		case "auto":
			return "auto"
		case "any":
			return "required"
		case "none":
			return "none"
		case "tool":
			if obj.Name != "" {
				return map[string]any{
					"type":     "function",
					"function": map[string]string{"name": obj.Name},
				}
			}
		}
	}
	return raw
}
