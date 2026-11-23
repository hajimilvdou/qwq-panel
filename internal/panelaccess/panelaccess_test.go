// SPDX-License-Identifier: AGPL-3.0-only

package panelaccess

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/qwq-panel/qwq/internal/platform/config"
)

func dummyPanelHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Request-Id", "req_secret_leak_check")
		w.Header().Set("Content-Security-Policy", "frame-ancestors 'none'")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("PANEL:" + r.URL.Path))
	})
}

func TestDisguiseDropResetsRealTCPConnection(t *testing.T) {
	mgr, err := NewManager(context.Background(), Options{
		Bootstrap: config.HTTP{
			Listen:    "127.0.0.1:41234",
			TLS:       config.TLS{Mode: config.TLSSelfSigned},
			EntryPath: "jsnsjx8k",
			Disguise:  config.DisguiseDrop,
		},
	})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}

	ts := httptest.NewServer(mgr.Wrap(dummyPanelHandler()))
	t.Cleanup(ts.Close)

	// Wrong path must drop the connection with zero HTTP response bytes.
	client := &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	for _, badPath := range []string{"/", "/login", "/api/v1/setup", "/wrongpath", "/favicon.ico"} {
		resp, rerr := client.Get(ts.URL + badPath)
		if rerr == nil {
			resp.Body.Close()
			t.Fatalf("GET %s succeeded with status %d, want dropped connection", badPath, resp.StatusCode)
		}
	}

	// Direct API / health prefix (/jsnsjx8k/readyz) passes through without cookie.
	resp, err := client.Get(ts.URL + "/jsnsjx8k/readyz")
	if err != nil {
		t.Fatalf("GET /jsnsjx8k/readyz: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || string(body) != "PANEL:/readyz" {
		t.Fatalf("direct subpath = %d %q", resp.StatusCode, string(body))
	}

	// Browser entry (/jsnsjx8k/setup) sets HttpOnly gate cookie and redirects to /setup.
	resp, err = client.Get(ts.URL + "/jsnsjx8k/setup?from=init")
	if err != nil {
		t.Fatalf("GET /jsnsjx8k/setup: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != "/setup?from=init" {
		t.Fatalf("entry redirect = %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	var gateCookie *http.Cookie
	for _, c := range resp.Cookies() {
		if c.Name == GateCookieName {
			gateCookie = c
		}
	}
	if gateCookie == nil || !gateCookie.HttpOnly {
		t.Fatalf("missing HttpOnly gate cookie: %+v", resp.Cookies())
	}

	// With the valid gate cookie, normal SPA and API paths work seamlessly.
	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/v1/system", nil)
	req.AddCookie(gateCookie)
	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("GET with gate cookie: %v", err)
	}
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || string(body) != "PANEL:/api/v1/system" {
		t.Fatalf("gated request = %d %q", resp.StatusCode, string(body))
	}

	// Rotating entry path immediately invalidates the old gate cookie!
	newPath := "newsecret99"
	if _, _, err := mgr.Update(context.Background(), UpdateInput{EntryPath: &newPath}); err != nil {
		t.Fatalf("Update entry_path: %v", err)
	}
	req2, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/v1/system", nil)
	req2.AddCookie(gateCookie)
	if resp2, rerr := client.Do(req2); rerr == nil {
		resp2.Body.Close()
		t.Fatalf("old gate cookie still worked after entry_path rotation (status %d)", resp2.StatusCode)
	}
}

func TestDisguiseNginx404AndAutoDisableOnDomain(t *testing.T) {
	mgr, err := NewManager(context.Background(), Options{
		Bootstrap: config.HTTP{
			Listen:    "127.0.0.1:41235",
			TLS:       config.TLS{Mode: config.TLSSelfSigned},
			EntryPath: "secretpath1",
			Disguise:  config.DisguiseNginx404,
		},
	})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}

	h := mgr.Wrap(dummyPanelHandler())
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("nginx_404 status = %d, want 404", rec.Code)
	}
	if rec.Header().Get("Server") != "nginx" {
		t.Fatalf("Server = %q, want nginx", rec.Header().Get("Server"))
	}
	// Verify zero qwq fingerprint headers leak into F12 DevTools!
	for _, forbidden := range []string{"X-Request-Id", "Content-Security-Policy", "Set-Cookie", "X-Frame-Options"} {
		if v := rec.Header().Get(forbidden); v != "" {
			t.Errorf("disguise leaked header %s: %q", forbidden, v)
		}
	}
	if !strings.Contains(rec.Body.String(), "404 Not Found") {
		t.Fatalf("unexpected body: %q", rec.Body.String())
	}

	// Configuring a reverse-proxy panel_domain automatically disables the secret
	// entry path ONLY when accessed via that authorized domain; direct bare-IP
	// probes MUST remain disguised (BUG-H03)!
	dom := "panel.example.com"
	snap, _, err := mgr.Update(context.Background(), UpdateInput{PanelDomain: &dom})
	if err != nil {
		t.Fatalf("Update panel_domain: %v", err)
	}
	if snap.DomainAutoBypassReason() != "panel_domain" || snap.EntryGateActive() {
		t.Fatalf("expected auto-bypass, got reason=%q active=%v", snap.DomainAutoBypassReason(), snap.EntryGateActive())
	}

	reqDomain := httptest.NewRequest(http.MethodGet, "/", nil)
	reqDomain.Host = "panel.example.com"
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, reqDomain)
	if rec2.Code != http.StatusOK || rec2.Body.String() != "PANEL:/" {
		t.Fatalf("after panel_domain bypass on authorized host: %d %q, want 200 PANEL:/", rec2.Code, rec2.Body.String())
	}

	// Bare IP probe must still receive nginx 404 disguise!
	reqIP := httptest.NewRequest(http.MethodGet, "/", nil)
	reqIP.Host = "203.0.113.10:41235"
	recIP := httptest.NewRecorder()
	h.ServeHTTP(recIP, reqIP)
	if recIP.Code != http.StatusNotFound || recIP.Header().Get("Server") != "nginx" {
		t.Fatalf("bare IP probe leaked panel: status=%d server=%q", recIP.Code, recIP.Header().Get("Server"))
	}

	// Emergency rescue via bare IP + secret path still works and issues _g cookie.
	reqRescue := httptest.NewRequest(http.MethodGet, "/secretpath1/login", nil)
	reqRescue.Host = "203.0.113.10:41235"
	recRescue := httptest.NewRecorder()
	h.ServeHTTP(recRescue, reqRescue)
	if recRescue.Code != http.StatusFound || recRescue.Header().Get("Location") != "/login" {
		t.Fatalf("bare IP emergency rescue = %d %q, want 302 /login", recRescue.Code, recRescue.Header().Get("Location"))
	}

	// Plugin UI HMAC capability prefix /_u/<tok>/plugin-ui/... works without _g cookie.
	decorated := snap.DecoratePluginUIEntryURL("/plugin-ui/core.xray/1.0.0/ui/index.html")
	if !strings.HasPrefix(decorated, "/_u/") {
		t.Fatalf("DecoratePluginUIEntryURL = %q, want /_u/<tok>/...", decorated)
	}
	reqUI := httptest.NewRequest(http.MethodGet, decorated, nil)
	reqUI.Host = "203.0.113.10:41235"
	recUI := httptest.NewRecorder()
	h.ServeHTTP(recUI, reqUI)
	if recUI.Code != http.StatusOK || recUI.Body.String() != "PANEL:/plugin-ui/core.xray/1.0.0/ui/index.html" {
		t.Fatalf("plugin UI token route = %d %q", recUI.Code, recUI.Body.String())
	}

	// Open redirect attempt /secretpath1//evil.com collapses leading slashes to single /evil.com.
	reqRedir := httptest.NewRequest(http.MethodGet, "/secretpath1//evil.com", nil)
	reqRedir.Host = "203.0.113.10:41235"
	recRedir := httptest.NewRecorder()
	h.ServeHTTP(recRedir, reqRedir)
	if strings.HasPrefix(recRedir.Header().Get("Location"), "//") {
		t.Fatalf("open redirect leaked protocol-relative Location: %q", recRedir.Header().Get("Location"))
	}

	// Public plugin route /p/... is exempt from admin gate.
	reqPub := httptest.NewRequest(http.MethodGet, "/p/proxy.advanced/sub/token1", nil)
	reqPub.Host = "203.0.113.10:41235"
	recPub := httptest.NewRecorder()
	h.ServeHTTP(recPub, reqPub)
	if recPub.Code != http.StatusOK || recPub.Body.String() != "PANEL:/p/proxy.advanced/sub/token1" {
		t.Fatalf("public plugin route blocked: %d %q", recPub.Code, recPub.Body.String())
	}

	// Custom HTML disguise must carry CSP sandbox header.
	mode := config.DisguiseCustomHTML
	html := "<h1>hello</h1>"
	if _, _, err := mgr.Update(context.Background(), UpdateInput{Disguise: &mode, DisguiseHTML: &html}); err != nil {
		t.Fatalf("Update custom_html: %v", err)
	}
	recHTML := httptest.NewRecorder()
	h.ServeHTTP(recHTML, reqIP)
	if !strings.Contains(recHTML.Header().Get("Content-Security-Policy"), "sandbox") {
		t.Fatalf("custom_html missing CSP sandbox: %q", recHTML.Header().Get("Content-Security-Policy"))
	}
}

func TestOnPortChangeWritesCapabilityPanelPortAtomically(t *testing.T) {
	portFile := filepath.Join(t.TempDir(), "panel-port.json")
	var observed []int
	mgr, err := NewManager(context.Background(), Options{
		Bootstrap: config.HTTP{
			Listen: "127.0.0.1:41236",
			TLS:    config.TLS{Mode: config.TLSSelfSigned},
		},
		OnPortChange: func(port int) {
			observed = append(observed, port)
			if err := WriteCapabilityPanelPort(portFile, port); err != nil {
				t.Errorf("WriteCapabilityPanelPort(%d): %v", port, err)
			}
		},
	})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	if len(observed) != 1 || observed[0] != 41236 {
		t.Fatalf("initial OnPortChange = %v, want [41236]", observed)
	}
	newPort := 41999
	if _, changed, err := mgr.Update(context.Background(), UpdateInput{Port: &newPort}); err != nil || !changed {
		t.Fatalf("Update port: changed=%v err=%v", changed, err)
	}
	if len(observed) != 2 || observed[1] != 41999 {
		t.Fatalf("OnPortChange after update = %v, want [41236 41999]", observed)
	}
	raw, err := os.ReadFile(portFile)
	if err != nil || strings.TrimSpace(string(raw)) != `{"port":41999}` {
		t.Fatalf("panel-port.json = %q (err=%v), want {\"port\":41999}", string(raw), err)
	}
}
