// SPDX-License-Identifier: AGPL-3.0-only

package pluginpublic

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCustomDomainRouterIsolationAndRewriting(t *testing.T) {
	var gotPanel, gotPublic bool
	var gotPath, gotCookie, gotAuth string

	panelNext := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPanel = true
		w.WriteHeader(http.StatusOK)
	})
	publicGW := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPublic = true
		gotPath = r.URL.Path
		gotCookie = r.Header.Get("Cookie")
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	})

	router := NewCustomDomainRouter([]string{"https://panel.example.com:8443"}, nil, publicGW, panelNext)

	// 1. 严禁抢占主面板管理域名
	if err := router.ValidateAndReplace([]DomainBinding{{Domain: "panel.example.com", PluginID: "server.probe"}}); err != ErrDomainConflictsPanelOrigin {
		t.Fatalf("expected ErrDomainConflictsPanelOrigin, got %v", err)
	}
	// 2. 绑定合法独立域名
	if err := router.ValidateAndReplace([]DomainBinding{{Domain: "status.example.com", PluginID: "server.probe"}}); err != nil {
		t.Fatalf("ValidateAndReplace: %v", err)
	}

	// 3. 未命中独立域名的请求直通主面板
	reqPanel := httptest.NewRequest(http.MethodGet, "/api/v1/system", nil)
	reqPanel.Host = "panel.example.com"
	router.ServeHTTP(httptest.NewRecorder(), reqPanel)
	if !gotPanel || gotPublic {
		t.Fatalf("panel host should pass through: gotPanel=%v gotPublic=%v", gotPanel, gotPublic)
	}

	// 4. 独立域名访问 /api/v1 或穿越路径必须 404 屏蔽
	for _, p := range []string{"/api/v1/users", "/foo/../api/v1/users", "/healthz", "/plugin-ui/x"} {
		gotPublic = false
		reqBad := httptest.NewRequest(http.MethodGet, p, nil)
		reqBad.Host = "status.example.com"
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, reqBad)
		if rec.Code != http.StatusNotFound || gotPublic {
			t.Fatalf("path %q on custom domain returned %d (gotPublic=%v), want 404", p, rec.Code, gotPublic)
		}
	}

	// 5. 独立域名根路径重写到 /p/server.probe/portal 并剥离 Cookie 与 qwq_* 令牌
	gotPublic = false
	reqRoot := httptest.NewRequest(http.MethodGet, "/", nil)
	reqRoot.Host = "status.example.com"
	reqRoot.Header.Set("Cookie", "qwq_session=secret")
	reqRoot.Header.Set("Authorization", "Bearer qwq_admin_tok")
	recRoot := httptest.NewRecorder()
	router.ServeHTTP(recRoot, reqRoot)
	if recRoot.Code != http.StatusOK || !gotPublic || gotPath != "/p/server.probe/portal" || gotCookie != "" || gotAuth != "" {
		t.Fatalf("root rewrite failed: code=%d path=%q cookie=%q auth=%q", recRoot.Code, gotPath, gotCookie, gotAuth)
	}

	// 6. 独立域名 /api/probe/v1/report 重写到 /p/server.probe/agent/v1/report 并保留探针上报令牌
	gotPublic = false
	reqAgent := httptest.NewRequest(http.MethodPost, "/api/probe/v1/report", nil)
	reqAgent.Host = "status.example.com"
	reqAgent.Header.Set("Authorization", "Bearer prb_agt_demo")
	recAgent := httptest.NewRecorder()
	router.ServeHTTP(recAgent, reqAgent)
	if recAgent.Code != http.StatusOK || !gotPublic || gotPath != "/p/server.probe/agent/v1/report" || gotAuth != "Bearer prb_agt_demo" {
		t.Fatalf("agent rewrite failed: code=%d path=%q auth=%q", recAgent.Code, gotPath, gotAuth)
	}
}
