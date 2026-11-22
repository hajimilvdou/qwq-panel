// SPDX-License-Identifier: AGPL-3.0-only

package proxy

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// ======================== SSRF 传输层防护测试 ========================

func TestSSRFProtectionAndAllowPrivate(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	strictClient := NewSafeHTTPClient(false, 2*time.Second)
	if _, err := strictClient.Get(srv.URL); err == nil || !strings.Contains(err.Error(), "SSRF_BLOCKED") {
		t.Fatalf("默认安全客户端应拦截 127.0.0.1 回环请求，实际: %v", err)
	}
	if _, err := strictClient.Get("http://169.254.169.254/latest/meta-data/"); err == nil || !strings.Contains(err.Error(), "SSRF_BLOCKED") {
		t.Fatalf("默认安全客户端应拦截 169.254.169.254 云元数据地址，实际: %v", err)
	}

	privClient := NewSafeHTTPClient(true, 2*time.Second)
	resp, err := privClient.Get(srv.URL)
	if err != nil {
		t.Fatalf("allowPrivate=true 应允许访问本地测试上游: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("期望 200，实际 %d", resp.StatusCode)
	}
}

// ======================== Sticky Session、冷却熔断与并发信号量测试 ========================

func TestRouterStickySessionCircuitBreakerAndSemaphore(t *testing.T) {
	now := time.Date(2026, 6, 15, 10, 0, 0, 0, time.UTC)
	c1 := &UpstreamChannel{ID: "ch-top-1", Kind: ChanAnthropicNative, Groups: []string{"default"}, Models: []string{"claude-sonnet-4-5"}, Priority: 20, Sem: make(chan struct{}, 1)}
	c2 := &UpstreamChannel{ID: "ch-top-2", Kind: ChanSub2ClaudeOAuth, Groups: []string{"default"}, Models: []string{"claude-sonnet-4-5"}, Priority: 20, Sem: make(chan struct{}, 1)}
	c3 := &UpstreamChannel{ID: "ch-backup", Kind: ChanOpenAICompat, Groups: []string{"default"}, Models: []string{"claude-sonnet-4-5"}, Priority: 10, Sem: make(chan struct{}, 2)}

	router := NewRouter()
	router.ReplaceSnapshot([]*UpstreamChannel{c3, c1, c2}, nil)

	// 同会话键必须稳定亲和到同一个顶层渠道，且备选池顺序正确。
	firstList := router.SelectCandidates("default", "claude-sonnet-4-5", "session-user-42", now)
	if len(firstList) != 3 {
		t.Fatalf("期望返回 3 条候选渠道，实际 %d", len(firstList))
	}
	pinnedID := firstList[0].ID
	if pinnedID != "ch-top-1" && pinnedID != "ch-top-2" {
		t.Fatalf("最高优先级渠道应在首位，实际 %s", pinnedID)
	}
	if firstList[2].ID != "ch-backup" {
		t.Fatalf("低优先级备选渠道应在末位，实际 %s", firstList[2].ID)
	}
	for i := 0; i < 20; i++ {
		again := router.SelectCandidates("default", "claude-sonnet-4-5", "session-user-42", now)
		if again[0].ID != pinnedID {
			t.Fatalf("Sticky Session 亲和漂移: got %s want %s", again[0].ID, pinnedID)
		}
	}

	// 429 冷却应临时跳过该渠道，401 应直接熔断。
	c1.MarkUpstreamStatus(http.StatusTooManyRequests, 60*time.Second, now)
	c2.MarkUpstreamStatus(http.StatusUnauthorized, 0, now)
	afterFail := router.SelectCandidates("default", "claude-sonnet-4-5", "session-user-42", now.Add(10*time.Second))
	if len(afterFail) != 1 || afterFail[0].ID != "ch-backup" {
		t.Fatalf("429 冷却与 401 熔断后应仅剩 ch-backup，实际 %+v", afterFail)
	}

	// 冷却期过后 c1 自动恢复，c2 仍处于熔断状态。
	afterRecover := router.SelectCandidates("default", "claude-sonnet-4-5", "session-user-42", now.Add(65*time.Second))
	if len(afterRecover) != 2 || afterRecover[0].ID != "ch-top-1" {
		t.Fatalf("冷却到期后 c1 应恢复至首位，实际 %+v", afterRecover)
	}

	// 信号量并发槽位保护：容量为 1 时第二次获取应阻塞直至 ctx 超时，释放后可立即获取。
	if err := c1.AcquireSlot(context.Background()); err != nil {
		t.Fatalf("首次 AcquireSlot 失败: %v", err)
	}
	shortCtx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := c1.AcquireSlot(shortCtx); err == nil {
		t.Fatal("信号量占满时应阻塞至超时")
	}
	c1.ReleaseSlot()
	if err := c1.AcquireSlot(context.Background()); err != nil {
		t.Fatalf("ReleaseSlot 后再次获取应成功: %v", err)
	}
	c1.ReleaseSlot()
}

// ======================== Sub2API OAuth 无锁自动刷新测试 ========================

func TestSub2APIOAuthRefresh(t *testing.T) {
	var refreshCalls int
	oauthSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		refreshCalls++
		if err := r.ParseForm(); err != nil || r.FormValue("refresh_token") != "rt-old" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token":  "at-fresh-999",
			"refresh_token": "rt-fresh-999",
			"expires_in":    3600,
		})
	}))
	defer oauthSrv.Close()

	now := time.Date(2026, 6, 15, 10, 0, 0, 0, time.UTC)
	bundleJSON, _ := json.Marshal(OAuthTokenBundle{
		AccessToken:   "at-expiring",
		RefreshToken:  "rt-old",
		ExpiresAtUnix: now.Add(2 * time.Minute).Unix(),
		TokenURL:      oauthSrv.URL,
		ClientID:      "cid-1",
	})
	ch := &UpstreamChannel{ID: "sub-claude", Kind: ChanSub2ClaudeOAuth, BaseURL: "https://api.anthropic.com"}
	ch.SetCredential(string(bundleJSON))

	client := NewSafeHTTPClient(true, 5*time.Second)
	refreshed, err := ch.RefreshOAuthIfNeeded(context.Background(), client, now)
	if err != nil || !refreshed {
		t.Fatalf("距过期不足 5 分钟时应触发刷新: refreshed=%v err=%v", refreshed, err)
	}
	if got := *ch.APIKeyOrToken.Load(); got != "at-fresh-999" {
		t.Fatalf("原子替换后的 AccessToken 不正确: got %q", got)
	}

	// 新令牌有效期充足（1 小时），再次调用不应发网络请求。
	refreshed2, err := ch.RefreshOAuthIfNeeded(context.Background(), client, now.Add(1*time.Minute))
	if err != nil || refreshed2 || refreshCalls != 1 {
		t.Fatalf("未临期不应重复刷新: refreshed2=%v calls=%d err=%v", refreshed2, refreshCalls, err)
	}
}

// ======================== Prompt Cache 差价统计计费测试 ========================

func TestModelPricingPromptCacheAndPerCall(t *testing.T) {
	p := ModelPricing{
		BillingMode:       "token",
		InputMicrosPer1K:  3000,
		OutputMicrosPer1K: 15000,
		CacheReadRatio:    0.1,
		CacheWriteRatio:   1.25,
	}
	// normalIn=500 -> 1500; cacheRead=1000 -> 300; cacheWrite=500 -> 1875; out=1000 -> 15000; sum = 18675
	got := p.CalculateMicros(2000, 1000, 500, 1000, 1.0)
	if got != 18675 {
		t.Fatalf("Prompt Cache 差价折算不符: got %d want 18675", got)
	}

	perCall := ModelPricing{BillingMode: "per_call", PerCallMicros: 20_000}
	if gotCall := perCall.CalculateMicros(9999, 0, 0, 9999, 1.5); gotCall != 30_000 {
		t.Fatalf("per_call 按次计费不符: got %d want 30000", gotCall)
	}
}

// ======================== 四协议双向零缓冲 SSE 互转与请求编解码测试 ========================

func TestFourProtocolBidirectionalSSETranslation(t *testing.T) {
	t.Run("AnthropicToOpenAIChat", func(t *testing.T) {
		upSSE := strings.Join([]string{
			`event: message_start`,
			`data: {"type":"message_start","message":{"usage":{"input_tokens":500,"cache_read_input_tokens":1000,"cache_creation_input_tokens":200,"output_tokens":0}}}`,
			``,
			`event: content_block_delta`,
			`data: {"type":"content_block_delta","delta":{"type":"thinking_delta","thinking":"step-1"}}`,
			``,
			`event: content_block_delta`,
			`data: {"type":"content_block_delta","delta":{"type":"text_delta","text":"Hello world"}}`,
			``,
			`event: message_delta`,
			`data: {"type":"message_delta","usage":{"output_tokens":42}}`,
			``,
		}, "\n")

		rec := httptest.NewRecorder()
		usage, err := RelayStreamBridge(time.Now(), strings.NewReader(upSSE), ProtoAnthropicMessages, ProtoOpenAIChat, "claude-sonnet-4-5", rec)
		if err != nil {
			t.Fatalf("RelayStreamBridge 失败: %v", err)
		}
		if usage.InputTokens != 1700 || usage.CachedReadTokens != 1000 || usage.CacheWriteTokens != 200 || usage.OutputTokens != 42 {
			t.Fatalf("Anthropic Prompt Cache 用量提取错误: %+v", usage)
		}
		body := rec.Body.String()
		if !strings.Contains(body, `"reasoning_content":"step-1"`) || !strings.Contains(body, `"content":"Hello world"`) || !strings.Contains(body, "data: [DONE]") {
			t.Fatalf("OpenAI Chat 转换输出不完整:\n%s", body)
		}
	})

	t.Run("OpenAIChatToAnthropic", func(t *testing.T) {
		upSSE := strings.Join([]string{
			`data: {"choices":[{"delta":{"reasoning_content":"think-x"}}]}`,
			``,
			`data: {"choices":[{"delta":{"content":"Answer!"}}]}`,
			``,
			`data: {"choices":[],"usage":{"prompt_tokens":300,"completion_tokens":20,"prompt_tokens_details":{"cached_tokens":120}}}`,
			``,
			`data: [DONE]`,
			``,
		}, "\n")

		rec := httptest.NewRecorder()
		usage, err := RelayStreamBridge(time.Now(), strings.NewReader(upSSE), ProtoOpenAIChat, ProtoAnthropicMessages, "gpt-4o", rec)
		if err != nil {
			t.Fatalf("RelayStreamBridge 失败: %v", err)
		}
		if usage.InputTokens != 300 || usage.CachedReadTokens != 120 || usage.OutputTokens != 20 {
			t.Fatalf("OpenAI Chat 用量提取错误: %+v", usage)
		}
		body := rec.Body.String()
		for _, want := range []string{"event: message_start", `"type":"thinking_delta"`, `"thinking":"think-x"`, `"type":"text_delta"`, `"text":"Answer!"`, "event: message_stop"} {
			if !strings.Contains(body, want) {
				t.Fatalf("Anthropic 输出缺少 %q:\n%s", want, body)
			}
		}
	})

	t.Run("GeminiToOpenAIResponses", func(t *testing.T) {
		upSSE := strings.Join([]string{
			`data: {"candidates":[{"content":{"parts":[{"text":"gem-reason","thought":true},{"text":"gem-ans"}]}}],"usageMetadata":{"promptTokenCount":800,"cachedContentTokenCount":500,"candidatesTokenCount":33}}`,
			``,
		}, "\n")

		rec := httptest.NewRecorder()
		usage, err := RelayStreamBridge(time.Now(), strings.NewReader(upSSE), ProtoGeminiNative, ProtoOpenAIResponses, "gemini-2.5-pro", rec)
		if err != nil {
			t.Fatalf("RelayStreamBridge 失败: %v", err)
		}
		if usage.InputTokens != 800 || usage.CachedReadTokens != 500 || usage.OutputTokens != 33 {
			t.Fatalf("Gemini 用量提取错误: %+v", usage)
		}
		body := rec.Body.String()
		for _, want := range []string{"event: response.reasoning_summary_text.delta", `"delta":"gem-reason"`, "event: response.output_text.delta", `"delta":"gem-ans"`, "event: response.completed"} {
			if !strings.Contains(body, want) {
				t.Fatalf("Responses 输出缺少 %q:\n%s", want, body)
			}
		}
	})

	t.Run("OpenAIResponsesToGemini", func(t *testing.T) {
		upSSE := strings.Join([]string{
			`event: response.reasoning_summary_text.delta`,
			`data: {"type":"response.reasoning_summary_text.delta","delta":"plan-a"}`,
			``,
			`event: response.output_text.delta`,
			`data: {"type":"response.output_text.delta","delta":"done-b"}`,
			``,
			`event: response.completed`,
			`data: {"type":"response.completed","response":{"usage":{"input_tokens":400,"output_tokens":18,"input_tokens_details":{"cached_tokens":100}}}}`,
			``,
		}, "\n")

		rec := httptest.NewRecorder()
		usage, err := RelayStreamBridge(time.Now(), strings.NewReader(upSSE), ProtoOpenAIResponses, ProtoGeminiNative, "gpt-5.2-codex", rec)
		if err != nil {
			t.Fatalf("RelayStreamBridge 失败: %v", err)
		}
		if usage.InputTokens != 400 || usage.CachedReadTokens != 100 || usage.OutputTokens != 18 {
			t.Fatalf("Responses 用量提取错误: %+v", usage)
		}
		body := rec.Body.String()
		if !strings.Contains(body, `"thought":true`) || !strings.Contains(body, `"text":"done-b"`) {
			t.Fatalf("Gemini 输出不完整:\n%s", body)
		}
	})

	t.Run("RequestParseAndEncodeHeaders", func(t *testing.T) {
		rawOpenAI := []byte(`{"model":"claude-sonnet-4-5","messages":[{"role":"system","content":"sys"},{"role":"user","content":"hi"}],"stream":true}`)
		ir, err := ParseDownstreamRequest(ProtoOpenAIChat, "", rawOpenAI)
		if err != nil || ir.Model != "claude-sonnet-4-5" || ir.System != "sys" || len(ir.Messages) != 1 {
			t.Fatalf("ParseDownstreamRequest 解析异常: %+v err=%v", ir, err)
		}

		subCh := &UpstreamChannel{
			ID:           "sub-1",
			Kind:         ChanSub2ClaudeOAuth,
			BaseURL:      "https://api.anthropic.com",
			ModelMapping: map[string]string{"claude-sonnet-4-5": "claude-3-7-sonnet"},
		}
		subCh.SetCredential("oauth-access-token")

		targetURL, hdrs, upBody, err := EncodeUpstreamRequest(subCh, ProtoOpenAIChat, rawOpenAI, ir)
		if err != nil {
			t.Fatalf("EncodeUpstreamRequest 失败: %v", err)
		}
		if targetURL != "https://api.anthropic.com/v1/messages" {
			t.Fatalf("上游地址错误: %s", targetURL)
		}
		if hdrs["Authorization"] != "Bearer oauth-access-token" || !strings.Contains(hdrs["anthropic-beta"], "oauth-2025-04-20") {
			t.Fatalf("Sub2API Claude OAuth 请求头缺失: %+v", hdrs)
		}
		if !strings.Contains(string(upBody), `"model":"claude-3-7-sonnet"`) {
			t.Fatalf("模型映射未生效: %s", upBody)
		}
	})
}
