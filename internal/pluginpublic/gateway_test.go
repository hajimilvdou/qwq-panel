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

func TestGatewayTrailingSlashRedirectThemeSandboxAndUploadLimit(t *testing.T) {
	now := time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC)
	disp := &fakePublicDispatcher{
		resp: PublicResponse{
			StatusCode: http.StatusOK,
			Headers: map[string]string{
				"Content-Type": "text/html; charset=utf-8",
			},
			Body: []byte("<html>ok</html>"),
		},
	}
	gw := NewGateway(disp, func() time.Time { return now })
	gw.ReplaceRoutes([]RouteSpec{
		{
			PluginID:        "server.probe",
			Route:           "portal",
			PortalSPA:       true,
			RateLimitPerMin: 120,
		},
	})

	// 1. GET /p/server.probe/portal?tab=nodes (no trailing slash) -> 308 Permanent Redirect preserving query.
	reqNoSlash := httptest.NewRequest(http.MethodGet, "/p/server.probe/portal?tab=nodes", nil)
	recNoSlash := httptest.NewRecorder()
	gw.ServeHTTP(recNoSlash, reqNoSlash)
	if recNoSlash.Code != http.StatusPermanentRedirect || recNoSlash.Header().Get("Location") != "/p/server.probe/portal/?tab=nodes" {
		t.Fatalf("no-slash redirect = %d %q, want 308 /p/server.probe/portal/?tab=nodes", recNoSlash.Code, recNoSlash.Header().Get("Location"))
	}

	// 2. GET /p/server.probe/portal/ -> 200 with external HTTPS wallpaper img-src allowed.
	reqPortal := httptest.NewRequest(http.MethodGet, "/p/server.probe/portal/", nil)
	recPortal := httptest.NewRecorder()
	gw.ServeHTTP(recPortal, reqPortal)
	if recPortal.Code != http.StatusOK {
		t.Fatalf("portal root = %d, want 200", recPortal.Code)
	}
	if csp := recPortal.Header().Get("Content-Security-Policy"); !strings.Contains(csp, "img-src 'self' data: blob: https:;") {
		t.Fatalf("server.probe portal CSP = %q, want external HTTPS img-src", csp)
	}

	// 3. Response header X-QWQ-Theme-Sandbox: 1 upgrades response to opaque sandbox CSP and strips the internal header.
	disp.resp = PublicResponse{
		StatusCode: http.StatusOK,
		Headers: map[string]string{
			"Content-Type":        "text/html; charset=utf-8",
			"X-QWQ-Theme-Sandbox": "1",
		},
		Body: []byte("<html>theme</html>"),
	}
	reqTheme := httptest.NewRequest(http.MethodGet, "/p/server.probe/portal/themes/neon/index.html", nil)
	recTheme := httptest.NewRecorder()
	gw.ServeHTTP(recTheme, reqTheme)
	if recTheme.Code != http.StatusOK {
		t.Fatalf("theme response = %d, want 200", recTheme.Code)
	}
	if recTheme.Header().Get("X-QWQ-Theme-Sandbox") != "" {
		t.Fatal("X-QWQ-Theme-Sandbox header must be stripped before reaching client")
	}
	themeCSP := recTheme.Header().Get("Content-Security-Policy")
	for _, want := range []string{"sandbox allow-scripts;", "script-src http://example.com;", "connect-src 'none';", "frame-ancestors 'self'"} {
		if !strings.Contains(themeCSP, want) {
			t.Fatalf("theme sandbox CSP %q missing %q", themeCSP, want)
		}
	}
	if strings.Contains(themeCSP, "script-src https:") || strings.Contains(themeCSP, "script-src 'unsafe-inline'") || strings.Contains(themeCSP, "img-src data: blob: https:") {
		t.Fatalf("theme sandbox CSP must not allow wildcard scripts/images or inline scripts: %q", themeCSP)
	}

	// 4. /theme-frame/ subpath enforces same-origin sandbox CSP for iframes,
	// and redirects top-level document navigation (Sec-Fetch-Dest: document) back to portal root.
	disp.resp = PublicResponse{
		StatusCode: http.StatusOK,
		Headers:    map[string]string{"Content-Type": "text/html; charset=utf-8"},
		Body:       []byte("<html>frame</html>"),
	}
	reqFrame := httptest.NewRequest(http.MethodGet, "/p/server.probe/portal/theme-frame/custom/index.html", nil)
	reqFrame.Header.Set("Sec-Fetch-Dest", "iframe")
	recFrame := httptest.NewRecorder()
	gw.ServeHTTP(recFrame, reqFrame)
	if recFrame.Code != http.StatusOK || !strings.Contains(recFrame.Header().Get("Content-Security-Policy"), "script-src http://example.com;") {
		t.Fatalf("theme-frame CSP = %d %q", recFrame.Code, recFrame.Header().Get("Content-Security-Policy"))
	}

	reqPhish := httptest.NewRequest(http.MethodGet, "/p/server.probe/portal/theme-frame/custom/admin.html", nil)
	reqPhish.Header.Set("Sec-Fetch-Dest", "document")
	recPhish := httptest.NewRecorder()
	gw.ServeHTTP(recPhish, reqPhish)
	if recPhish.Code != http.StatusFound || recPhish.Header().Get("Location") != "/p/server.probe/portal/" {
		t.Fatalf("top-level theme-frame doc = %d %q, want 302 /p/server.probe/portal/", recPhish.Code, recPhish.Header().Get("Location"))
	}

	// 5. server.probe /api/admin/themes/upload caps body at 3 MiB (compatible with 4 MiB ABI limit).
	okThemeBody := make([]byte, (2<<20)+(512<<10))
	reqUpload := httptest.NewRequest(http.MethodPost, "/p/server.probe/portal/api/admin/themes/upload", strings.NewReader(string(okThemeBody)))
	recUpload := httptest.NewRecorder()
	gw.ServeHTTP(recUpload, reqUpload)
	if recUpload.Code != http.StatusOK || len(disp.lastReq.Body) != len(okThemeBody) {
		t.Fatalf("theme upload 2.5 MiB = %d (len=%d), want 200", recUpload.Code, len(disp.lastReq.Body))
	}

	tooBigTheme := make([]byte, (3<<20)+1024)
	reqTooBigTheme := httptest.NewRequest(http.MethodPost, "/p/server.probe/portal/api/admin/themes/upload", strings.NewReader(string(tooBigTheme)))
	recTooBigTheme := httptest.NewRecorder()
	gw.ServeHTTP(recTooBigTheme, reqTooBigTheme)
	if recTooBigTheme.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("theme upload >3 MiB = %d, want 413", recTooBigTheme.Code)
	}

	// 5b. Admin paths use an isolated rate-limit bucket so public portal traffic cannot lock out /admin.
	gwLow := NewGateway(disp, func() time.Time { return now })
	gwLow.ReplaceRoutes([]RouteSpec{{PluginID: "server.probe", Route: "portal", PortalSPA: true, RateLimitPerMin: 20}})
	for i := 0; i < 15; i++ {
		r := httptest.NewRequest(http.MethodGet, "/p/server.probe/portal/", nil)
		r.RemoteAddr = "198.51.100.7:12345"
		w := httptest.NewRecorder()
		gwLow.ServeHTTP(w, r)
	}
	adminReq := httptest.NewRequest(http.MethodGet, "/p/server.probe/portal/admin", nil)
	adminReq.RemoteAddr = "198.51.100.7:12346"
	adminRec := httptest.NewRecorder()
	gwLow.ServeHTTP(adminRec, adminReq)
	if adminRec.Code != http.StatusOK {
		t.Fatalf("admin path should use isolated rate-limit bucket, got %d", adminRec.Code)
	}

	// 6. CustomDomainRouter root rewrite does NOT trigger 308 redirect to /p/server.probe/portal/.
	cdr := NewCustomDomainRouter([]string{"https://panel.example.com"}, nil, gw, http.NotFoundHandler())
	if err := cdr.ValidateAndReplace([]DomainBinding{{Domain: "status.example.com", PluginID: "server.probe"}}); err != nil {
		t.Fatalf("ValidateAndReplace: %v", err)
	}
	reqCustom := httptest.NewRequest(http.MethodGet, "/", nil)
	reqCustom.Host = "status.example.com"
	recCustom := httptest.NewRecorder()
	cdr.ServeHTTP(recCustom, reqCustom)
	if recCustom.Code != http.StatusOK {
		t.Fatalf("custom domain root = %d (loc=%q), want 200", recCustom.Code, recCustom.Header().Get("Location"))
	}
}
