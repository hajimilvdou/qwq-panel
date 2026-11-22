// SPDX-License-Identifier: AGPL-3.0-only

package gateway

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestMountPublicRoutesExemptsCSRFAndEnforcesHost(t *testing.T) {
	gw, err := New(Config{
		PublicOrigins: []string{"https://panel.example.test"},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(gw.Close)
	gw.MountPublicRoutes(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Public-Hit", r.URL.Path)
		w.WriteHeader(http.StatusOK)
	}))

	// 1. 允许跨站订阅/API 请求（豁免 Origin / Sec-Fetch-Site），同时校验 Host 白名单
	req := httptest.NewRequest(http.MethodGet, "https://panel.example.test/p/proxy.advanced/sub/tok123", nil)
	req.Host = "panel.example.test"
	req.Header.Set("Origin", "https://external.client.test")
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || rec.Header().Get("X-Public-Hit") != "/p/proxy.advanced/sub/tok123" {
		t.Fatalf("expected 200 on /p/ route, got code=%d hit=%q", rec.Code, rec.Header().Get("X-Public-Hit"))
	}

	// 2. 非白名单 Host 仍必须被拒绝
	badHost := httptest.NewRequest(http.MethodGet, "https://evil.example.test/p/proxy.advanced/sub/tok123", nil)
	badHost.Host = "evil.example.test"
	badRec := httptest.NewRecorder()
	gw.ServeHTTP(badRec, badHost)
	if badRec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for disallowed Host on /p/, got %d", badRec.Code)
	}
}
