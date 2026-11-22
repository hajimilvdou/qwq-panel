// SPDX-License-Identifier: AGPL-3.0-only

package pluginpublic

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type fakePublicDispatcher struct {
	lastPlugin string
	lastReq    PublicRequest
	resp       PublicResponse
	err        error
}

func (f *fakePublicDispatcher) ServePublicRoute(_ context.Context, pluginID string, req PublicRequest) (PublicResponse, error) {
	f.lastPlugin = pluginID
	f.lastReq = req
	return f.resp, f.err
}

func (f *fakePublicDispatcher) ServePublicStream(_ context.Context, pluginID string, req PublicRequest, body io.Reader, w http.ResponseWriter) error {
	f.lastPlugin = pluginID
	f.lastReq = req
	raw, _ := io.ReadAll(body)
	w.Header().Set("Content-Type", "text/event-stream")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("data: " + string(raw) + "\n\n"))
	return nil
}

func TestGatewayStripsHostAuthEnforcesCSPAndRateLimits(t *testing.T) {
	now := time.Date(2026, 11, 21, 15, 0, 0, 0, time.UTC)
	disp := &fakePublicDispatcher{
		resp: PublicResponse{
			StatusCode: http.StatusOK,
			Headers: map[string]string{
				"Content-Type":          "text/plain; charset=utf-8",
				"Subscription-Userinfo": "upload=1; download=2; total=100; expire=0",
				"Set-Cookie":            "evil=1",
			},
			Body: []byte("vless://demo"),
		},
	}
	gw := NewGateway(disp, func() time.Time { return now })
	gw.ReplaceRoutes([]RouteSpec{
		{
			PluginID:        "proxy.advanced",
			Route:           "sub",
			RateLimitPerMin: 20,
		},
		{
			PluginID:        "ai.relay",
			Route:           "v1",
			Streaming:       true,
			AllowCORS:       true,
			RateLimitPerMin: 60,
		},
	})

	// 1. 订阅路由剥离 Cookie 与面板 Authorization 令牌，并禁止 Set-Cookie 回传
	req := httptest.NewRequest(http.MethodGet, "/p/proxy.advanced/sub/qsub_abc?format=clash", nil)
	req.RemoteAddr = "203.0.113.10:50000"
	req.Header.Set("Cookie", "qwq_session=secret-panel-cookie")
	req.Header.Set("Authorization", "Bearer qwq_admin_panel_token")
	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if disp.lastPlugin != "proxy.advanced" || disp.lastReq.Route != "sub" || disp.lastReq.Subpath != "qsub_abc" || disp.lastReq.Path != "/sub/qsub_abc" {
		t.Fatalf("unexpected dispatched request: %+v", disp.lastReq)
	}
	if disp.lastReq.RelayAuthBearer != "" {
		t.Fatalf("panel token leaked into RelayAuthBearer: %q", disp.lastReq.RelayAuthBearer)
	}
	if rec.Header().Get("Set-Cookie") != "" {
		t.Fatal("Set-Cookie header was not stripped")
	}
	if rec.Header().Get("Subscription-Userinfo") == "" {
		t.Fatal("Subscription-Userinfo header missing")
	}
	if !strings.Contains(rec.Header().Get("Content-Security-Policy"), "sandbox") {
		t.Fatalf("unexpected CSP: %q", rec.Header().Get("Content-Security-Policy"))
	}

	// 2. 流式 AI 路由仅接受 sk-qwq-*，过滤面板 qwq_* 令牌
	sReq1 := httptest.NewRequest(http.MethodPost, "/p/ai.relay/v1/chat/completions", strings.NewReader(`{"model":"gpt"}`))
	sReq1.RemoteAddr = "203.0.113.11:50001"
	sReq1.Header.Set("Authorization", "Bearer qwq_admin_token_must_drop")
	sRec1 := httptest.NewRecorder()
	gw.ServeHTTP(sRec1, sReq1)
	if sRec1.Code != http.StatusOK || disp.lastReq.RelayAuthBearer != "" {
		t.Fatalf("panel token must be dropped on streaming route: code=%d tok=%q", sRec1.Code, disp.lastReq.RelayAuthBearer)
	}

	sReq2 := httptest.NewRequest(http.MethodPost, "/p/ai.relay/v1/chat/completions", strings.NewReader(`{"model":"gpt"}`))
	sReq2.RemoteAddr = "203.0.113.11:50002"
	sReq2.Header.Set("Authorization", "Bearer sk-qwq-valid-relay-key")
	sRec2 := httptest.NewRecorder()
	gw.ServeHTTP(sRec2, sReq2)
	if sRec2.Code != http.StatusOK || disp.lastReq.RelayAuthBearer != "sk-qwq-valid-relay-key" || !strings.Contains(sRec2.Body.String(), `"model":"gpt"`) {
		t.Fatalf("streaming relay failed: code=%d tok=%q body=%q", sRec2.Code, disp.lastReq.RelayAuthBearer, sRec2.Body.String())
	}

	// 3. 路径穿越与未注册路由一律 404
	badRec := httptest.NewRecorder()
	gw.ServeHTTP(badRec, httptest.NewRequest(http.MethodGet, "/p/proxy.advanced/../secret", nil))
	if badRec.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for traversal, got %d", badRec.Code)
	}

	// 4. 触发每 IP 限流返回 429
	got429 := false
	for i := 0; i < 15; i++ {
		r := httptest.NewRequest(http.MethodGet, "/p/proxy.advanced/sub/qsub_abc", nil)
		r.RemoteAddr = "203.0.113.99:40000"
		w := httptest.NewRecorder()
		gw.ServeHTTP(w, r)
		if w.Code == http.StatusTooManyRequests {
			got429 = true
			break
		}
	}
	if !got429 {
		t.Fatal("expected 429 rate limit trigger")
	}
}

func TestGatewayEncodedTraversalAndBucketPruning(t *testing.T) {
	now := time.Date(2026, 11, 21, 16, 0, 0, 0, time.UTC)
	disp := &fakePublicDispatcher{
		resp: PublicResponse{StatusCode: http.StatusOK, Body: []byte("ok")},
	}
	gw := NewGateway(disp, func() time.Time { return now })
	gw.ReplaceRoutes([]RouteSpec{{PluginID: "proxy.advanced", Route: "sub", RateLimitPerMin: 20}})

	// 1. 编码路径穿越 (%2e%2e) 必须被拒绝为 404
	req := httptest.NewRequest(http.MethodGet, "/p/proxy.advanced/sub/a", nil)
	req.URL.RawPath = "/p/proxy.advanced/sub/%2e%2e/secret"
	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("encoded traversal returned %d, want 404", rec.Code)
	}

	// 2. 桶满 8192 时：活跃桶不被重置，超过 5 分钟的陈旧桶被清理
	gw.mu.Lock()
	staleTime := now.Add(-10 * time.Minute).UnixNano()
	gw.buckets["stale-ip|proxy.advanced|sub"] = &ipBucket{tokens: 1, lastNano: staleTime}
	gw.buckets["abuser-ip|proxy.advanced|sub"] = &ipBucket{tokens: 0, lastNano: now.UnixNano()}
	for i := 0; i < 8190; i++ {
		gw.buckets["fill-"+string(rune('a'+i%26))+"-"+time.Duration(i).String()] = &ipBucket{tokens: 5, lastNano: now.UnixNano()}
	}
	gw.mu.Unlock()

	// 新 IP 触发陈旧桶清理后被放行，但 abuser-ip 仍被严格限流（未被重置！）
	if !gw.allowClientIP("brand-new-ip|proxy.advanced|sub", 20) {
		t.Fatal("expected stale bucket eviction to admit new client")
	}
	if gw.allowClientIP("abuser-ip|proxy.advanced|sub", 20) {
		t.Fatal("abuser-ip bucket must NOT be reset during pruning")
	}
}
