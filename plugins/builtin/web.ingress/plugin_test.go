// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
	"google.golang.org/grpc"

	pb "github.com/qwq-panel/qwq/sdk/gen/qwq/platform/v1"
	"github.com/qwq-panel/qwq/sdk/pluginsdk"
)

func startIngressTestServer(t *testing.T, p *Plugin, cfgJSON []byte) *pluginsdk.Server {
	t.Helper()
	srv, err := pluginsdk.Serve(t.Context(), pluginsdk.Options{
		Plugin:             p,
		Manifest:           Manifest(),
		Registrar:          grpc.NewServer(),
		DefaultGracePeriod: time.Second,
	})
	if err != nil {
		t.Fatalf("pluginsdk.Serve: %v", err)
	}
	t.Cleanup(srv.Close)

	rc := &pb.RequestContext{InstanceId: "default", NodeId: "local", Locale: "zh-CN"}
	if _, err := srv.Initialize(t.Context(), &pb.InitializeRequest{
		Context:        rc,
		InstanceHandle: "web-ingress-test",
		DataDir:        t.TempDir(),
		ConfigJson:     cfgJSON,
		ConfigRevision: "1",
	}); err != nil {
		t.Fatalf("Initialize: %v", err)
	}
	if _, err := srv.Start(t.Context(), &pb.StartRequest{Context: rc}); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if _, err := srv.Activate(t.Context(), &pb.ActivateRequest{Context: rc}); err != nil {
		t.Fatalf("Activate: %v", err)
	}
	return srv
}

func invokeIngressRaw(t *testing.T, srv *pluginsdk.Server, op string, req any) *pb.InvokeResponse {
	t.Helper()
	raw, _ := json.Marshal(req)
	resp, err := srv.Invoke(t.Context(), &pb.InvokeRequest{
		Context:     &pb.RequestContext{InstanceId: "default", NodeId: "local", OperationId: "op-" + op, Locale: "zh-CN"},
		Operation:   op,
		ApiVersion:  "v1",
		PayloadJson: raw,
	})
	if err != nil {
		t.Fatalf("invoke %s transport error: %v", op, err)
	}
	return resp
}

func invokeIngress(t *testing.T, srv *pluginsdk.Server, op string, req any) map[string]any {
	t.Helper()
	resp := invokeIngressRaw(t, srv, op, req)
	if resp.GetError() != nil {
		t.Fatalf("invoke %s business error: %+v", op, resp.GetError())
	}
	var out map[string]any
	if err := json.Unmarshal(resp.GetPayloadJson(), &out); err != nil {
		t.Fatalf("unmarshal %s: %v", op, err)
	}
	return out
}

func TestWebIngressLiveProxyAuthRateLimitAndRollback(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Upstream-Echo", r.URL.Path)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("hello-from-upstream:" + r.URL.Path))
	}))
	defer upstream.Close()

	fixedNow := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)
	srv := startIngressTestServer(t, &Plugin{now: func() time.Time { return fixedNow }}, []byte(`{"preferred_engine":"builtin-go","listen_addr":"127.0.0.1:0"}`))

	// 1. 注入与云元数据 SSRF 负例必须被严格拒绝
	for _, bad := range []map[string]any{
		{"domain": "evil.com\nreverse_proxy 127.0.0.1:80", "upstream_url": upstream.URL},
		{"domain": "imds.example.com", "upstream_url": "http://169.254.169.254/latest/meta-data"},
		{"domain": "hdr.example.com", "upstream_url": upstream.URL, "extra_headers": map[string]string{"X-Test": "ok; evil { }"}},
		{"domain": "path.example.com", "upstream_url": upstream.URL, "path_prefix": "/../etc"},
	} {
		resp := invokeIngressRaw(t, srv, "ingress.site.upsert", bad)
		if resp.GetError() == nil {
			t.Fatalf("expected invalid site %+v to be rejected", bad)
		}
	}

	// 2. 创建带 BasicAuth + 限流（2 burst）+ 自定义头的反代站点并热重载
	created := invokeIngress(t, srv, "ingress.site.upsert", map[string]any{
		"domain":           "app.example.com",
		"upstream_url":     upstream.URL,
		"path_prefix":      "/",
		"tls_mode":         "off",
		"websocket":        true,
		"rate_limit_rps":   1,
		"rate_limit_burst": 3,
		"basic_auth_user":  "ops",
		"basic_auth_pass":  "SuperSecret#2026",
		"extra_headers":    map[string]string{"X-Served-By": "qwq-ingress"},
	})
	siteID := created["site"].(map[string]any)["id"].(string)
	rawCreated, _ := json.Marshal(created)
	if strings.Contains(string(rawCreated), "SuperSecret#2026") {
		t.Fatalf("plaintext basic auth password leaked in response: %s", rawCreated)
	}

	applied := invokeIngress(t, srv, "ingress.apply", map[string]any{})
	if applied["applied"] != true || int(applied["active_routes"].(float64)) != 1 {
		t.Fatalf("unexpected apply result: %+v", applied)
	}
	for _, wf := range applied["written_files"].([]any) {
		if _, err := os.Stat(wf.(string)); err != nil {
			t.Fatalf("expected rendered config file %s: %v", wf, err)
		}
	}

	// 3. 验证真实 TCP 监听的纯 Go 内置反代转发、BasicAuth 401/200 与 429 限流
	ov := invokeIngress(t, srv, "ingress.overview", map[string]any{})
	boundAddr := ov["bound_addr"].(string)
	if boundAddr == "" {
		t.Fatalf("expected non-empty bound_addr")
	}

	doReq := func(withAuth bool) (*http.Response, string) {
		req, _ := http.NewRequest(http.MethodGet, "http://"+boundAddr+"/api/ping", nil)
		req.Host = "app.example.com"
		if withAuth {
			req.SetBasicAuth("ops", "SuperSecret#2026")
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("proxy request failed: %v", err)
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		return resp, string(body)
	}

	r401, _ := doReq(false)
	if r401.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 without basic auth, got %d", r401.StatusCode)
	}
	r200a, bodyA := doReq(true)
	if r200a.StatusCode != http.StatusOK || !strings.Contains(bodyA, "hello-from-upstream:/api/ping") || r200a.Header.Get("X-Served-By") != "qwq-ingress" {
		t.Fatalf("unexpected proxied response #1: status=%d body=%q hdr=%q", r200a.StatusCode, bodyA, r200a.Header.Get("X-Served-By"))
	}
	r200b, _ := doReq(true)
	if r200b.StatusCode != http.StatusOK {
		t.Fatalf("expected burst #2 to pass, got %d", r200b.StatusCode)
	}
	r429, _ := doReq(true)
	if r429.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("expected 429 on burst exhaustion, got %d", r429.StatusCode)
	}

	// 4. 上游探测、Caddy/Nginx 渲染预览与快照回滚
	probeRes := invokeIngress(t, srv, "ingress.upstream.probe", map[string]any{"id": siteID})
	if probeRes["reachable"] != true {
		t.Fatalf("expected reachable upstream, got %+v", probeRes)
	}
	preview := invokeIngress(t, srv, "ingress.config.preview", map[string]any{})
	if !strings.Contains(preview["caddyfile"].(string), "reverse_proxy "+upstream.URL) ||
		!strings.Contains(preview["nginx"].(string), "proxy_pass "+upstream.URL) {
		t.Fatalf("unexpected rendered configs: %+v", preview)
	}

	// 删除站点后再从版本 1 快照回滚，验证站点与路由完整恢复
	invokeIngress(t, srv, "ingress.site.delete", map[string]any{"id": siteID})
	invokeIngress(t, srv, "ingress.apply", map[string]any{})
	rb := invokeIngress(t, srv, "ingress.rollback", map[string]any{"revision": 1})
	if rb["rolled_back"] != true || int(rb["active_routes"].(float64)) != 1 {
		t.Fatalf("rollback failed: %+v", rb)
	}

	digest := invokeIngress(t, srv, "ingress.ai.digest", map[string]any{})
	if int(digest["sites_enabled"].(float64)) != 1 {
		t.Fatalf("unexpected ai digest: %+v", digest)
	}

	// 5. 验证禁止导出到敏感系统路径与 Plan 明文 HTTP 风险预警
	valResp, err := srv.ValidateConfig(t.Context(), &pb.ValidateConfigRequest{
		Context:    &pb.RequestContext{InstanceId: "default", NodeId: "local", Locale: "zh-CN"},
		ConfigJson: []byte(`{"export_config_path":"/etc/shadow"}`),
	})
	if err == nil && valResp.GetError() == nil && len(valResp.GetViolations()) == 0 {
		t.Fatalf("expected export_config_path=/etc/shadow to be rejected, got %+v", valResp)
	}
	planRaw, _ := json.Marshal(map[string]any{
		"domain": "plain.example.com", "upstream_url": upstream.URL, "tls_mode": "off",
	})
	planResp, err := srv.PlanOperation(t.Context(), &pb.PlanOperationRequest{
		Context:     &pb.RequestContext{InstanceId: "default", NodeId: "local", OperationId: "plan-1", Locale: "zh-CN"},
		Operation:   "ingress.site.upsert",
		ApiVersion:  "v1",
		PayloadJson: planRaw,
	})
	if err != nil || planResp.GetError() != nil || len(planResp.GetWarnings()) == 0 {
		t.Fatalf("expected plain HTTP warning in Plan response, got resp=%+v err=%v", planResp, err)
	}
}

func generateSelfSignedCertPEM(t *testing.T, dnsNames ...string) (certPEM, keyPEM []byte) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ecdsa key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: dnsNames[0]},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     dnsNames,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatalf("marshal private key: %v", err)
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM
}

func TestWebIngressMultiPathSameDomainAndLegacyMigration(t *testing.T) {
	// 1. 先构造旧版单列 domain UNIQUE 的数据库并写入一条记录，验证无损迁移至 UNIQUE(domain, path_prefix)
	dataDir := t.TempDir()
	dbPath := filepath.Join(dataDir, "ingress.db")
	legacyDB, err := sql.Open("sqlite", "file:"+filepath.ToSlash(dbPath))
	if err != nil {
		t.Fatalf("open legacy sqlite: %v", err)
	}
	legacySchema := `CREATE TABLE ingress_sites (
		id                 TEXT PRIMARY KEY,
		domain             TEXT NOT NULL UNIQUE,
		enabled            INTEGER NOT NULL DEFAULT 1,
		upstream_url       TEXT NOT NULL,
		path_prefix        TEXT NOT NULL DEFAULT '/',
		websocket          INTEGER NOT NULL DEFAULT 1,
		tls_mode           TEXT NOT NULL DEFAULT 'managed',
		cert_id            TEXT NOT NULL DEFAULT '',
		force_https        INTEGER NOT NULL DEFAULT 1,
		rate_limit_rps     INTEGER NOT NULL DEFAULT 0,
		rate_limit_burst   INTEGER NOT NULL DEFAULT 0,
		basic_auth_user    TEXT NOT NULL DEFAULT '',
		basic_auth_hash    TEXT NOT NULL DEFAULT '',
		extra_headers_json TEXT NOT NULL DEFAULT '{}',
		notes              TEXT NOT NULL DEFAULT '',
		revision           INTEGER NOT NULL DEFAULT 1,
		created_at         INTEGER NOT NULL,
		updated_at         INTEGER NOT NULL
	) STRICT;`
	if _, err := legacyDB.Exec(legacySchema); err != nil {
		t.Fatalf("create legacy table: %v", err)
	}
	if _, err := legacyDB.Exec(`INSERT INTO ingress_sites (id, domain, upstream_url, path_prefix, created_at, updated_at) VALUES ('ing_legacy', 'multi.example.com', 'http://127.0.0.1:3000', '/', 1700000000, 1700000000)`); err != nil {
		t.Fatalf("insert legacy row: %v", err)
	}
	_ = legacyDB.Close()

	// 重新通过 openIngressStore 打开，触发 MigrateIngressSitesCompositeUnique
	st, err := openIngressStore(dataDir, embeddedSchemaSQL, time.Now)
	if err != nil {
		t.Fatalf("openIngressStore after legacy db: %v", err)
	}
	defer func() { _ = st.Close() }()

	// 同域名再写入 /api 规则，不得冲突且不得覆盖 /
	apiSite, err := st.upsertSite(t.Context(), siteUpsertParams{
		Domain:      "multi.example.com",
		Enabled:     true,
		UpstreamURL: "http://127.0.0.1:4000",
		PathPrefix:  "/api",
		TLSMode:     "managed",
		CertID:      "certbind_demo",
		ForceHTTPS:  true,
	})
	if err != nil {
		t.Fatalf("upsert /api on same domain failed: %v", err)
	}
	if apiSite.PathPrefix != "/api" {
		t.Fatalf("unexpected api site: %+v", apiSite)
	}
	sites, err := st.listSites(t.Context())
	if err != nil || len(sites) != 2 {
		t.Fatalf("expected 2 coexisting rules for multi.example.com, got len=%d err=%v", len(sites), err)
	}

	// 验证 Nginx 渲染含 80->443 跳转、HSTS 与物化证书路径
	nginxCfg := renderNginxConfig(sites, dataDir)
	if !strings.Contains(nginxCfg, "return 308 https://$host$request_uri;") ||
		!strings.Contains(nginxCfg, "Strict-Transport-Security") ||
		!strings.Contains(nginxCfg, "tls/bindings/certbind_demo/active_fullchain.pem") {
		t.Fatalf("nginx config missing expected HTTPS redirect, HSTS, or materialized cert path:\n%s", nginxCfg)
	}
}

func TestWebIngressSNITLSHandshakeAndReloadOperation(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("tls-backend-ok"))
	}))
	defer upstream.Close()

	dataDir := t.TempDir()
	bindingRef := "certbind_tls01"
	certPEM, keyPEM := generateSelfSignedCertPEM(t, "secure.example.com")
	fullPath, keyPath := MaterializedCertPaths(dataDir, bindingRef)
	if err := os.MkdirAll(filepath.Dir(fullPath), 0o700); err != nil {
		t.Fatalf("mkdir binding dir: %v", err)
	}
	if err := os.WriteFile(fullPath, certPEM, 0o600); err != nil {
		t.Fatalf("write fullchain: %v", err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatalf("write privkey: %v", err)
	}

	srv, err := pluginsdk.Serve(t.Context(), pluginsdk.Options{
		Plugin:             New(),
		Manifest:           Manifest(),
		Registrar:          grpc.NewServer(),
		DefaultGracePeriod: time.Second,
	})
	if err != nil {
		t.Fatalf("pluginsdk.Serve: %v", err)
	}
	t.Cleanup(srv.Close)

	rc := &pb.RequestContext{InstanceId: "default", NodeId: "local", Locale: "zh-CN"}
	if _, err := srv.Initialize(t.Context(), &pb.InitializeRequest{
		Context:        rc,
		InstanceHandle: "web-ingress-tls-test",
		DataDir:        dataDir,
		ConfigJson:     []byte(`{"preferred_engine":"builtin-go","https_listen_addr":"127.0.0.1:0"}`),
		ConfigRevision: "1",
	}); err != nil {
		t.Fatalf("Initialize: %v", err)
	}
	if _, err := srv.Start(t.Context(), &pb.StartRequest{Context: rc}); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if _, err := srv.Activate(t.Context(), &pb.ActivateRequest{Context: rc}); err != nil {
		t.Fatalf("Activate: %v", err)
	}

	// 新增站点（自动 reloadAndRenderLocked 生效）
	invokeIngress(t, srv, "ingress.site.upsert", map[string]any{
		"domain":       "secure.example.com",
		"upstream_url": upstream.URL,
		"path_prefix":  "/",
		"tls_mode":     "managed",
		"cert_id":      bindingRef,
		"force_https":  true,
	})

	// 调用 v2 ingress.tls.reload & ingress.tls.inspect
	reloadPayload, _ := json.Marshal(map[string]any{
		"binding_ref":        bindingRef,
		"profile_id":         "site-secure",
		"generation":         2,
		"policy_revision":    "pol_1",
		"fullchain_sha256":   sha256Hex(certPEM),
		"private_key_sha256": sha256Hex(keyPEM),
		"sni":                "secure.example.com",
	})
	reloadResp, err := srv.Invoke(t.Context(), &pb.InvokeRequest{
		Context:     &pb.RequestContext{InstanceId: "default", NodeId: "local", OperationId: "op-tls-reload", Locale: "zh-CN"},
		Operation:   "ingress.tls.reload",
		ApiVersion:  "v2",
		PayloadJson: reloadPayload,
	})
	if err != nil || reloadResp.GetError() != nil {
		t.Fatalf("ingress.tls.reload failed: resp=%+v err=%v", reloadResp, err)
	}
	var reloadOut tlsBindingObservation
	if err := json.Unmarshal(reloadResp.GetPayloadJson(), &reloadOut); err != nil {
		t.Fatalf("unmarshal reload resp: %v", err)
	}
	if !reloadOut.Running || reloadOut.Generation != 2 || reloadOut.Endpoint == "" {
		t.Fatalf("unexpected tls reload observation: %+v", reloadOut)
	}

	// 发起真实本地 TLS 握手与 HTTPS 请求验证 SNICertStore
	tlsClient := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				ServerName:         "secure.example.com",
				InsecureSkipVerify: true,
			},
		},
	}
	req, _ := http.NewRequest(http.MethodGet, "https://"+reloadOut.Endpoint+"/", nil)
	req.Host = "secure.example.com"
	resp, err := tlsClient.Do(req)
	if err != nil {
		t.Fatalf("real local TLS handshake/request failed: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || string(body) != "tls-backend-ok" {
		t.Fatalf("unexpected HTTPS response: status=%d body=%q", resp.StatusCode, string(body))
	}
	if resp.TLS == nil || len(resp.TLS.PeerCertificates) == 0 || resp.TLS.PeerCertificates[0].Subject.CommonName != "secure.example.com" {
		t.Fatalf("unexpected TLS peer cert: %+v", resp.TLS)
	}
}

func TestSafeIngressTransportBlocksMetadataAndDNSRebinding(t *testing.T) {
	// 1. 域名解析到 169.254.169.254（模拟 DNS Rebinding）必须被实时拦截
	tr := newSafeIngressTransportWithResolver(true, func(_ context.Context, _, host string) ([]netip.Addr, error) {
		if host == "rebind.example.com" {
			return []netip.Addr{netip.MustParseAddr("169.254.169.254")}, nil
		}
		if host == "aliyun-meta.example.com" {
			return []netip.Addr{netip.MustParseAddr("100.100.100.200")}, nil
		}
		return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
	})
	if tr.Proxy != nil {
		t.Fatal("SafeIngressTransport must set Proxy=nil")
	}
	client := &http.Client{Transport: tr, Timeout: 2 * time.Second}
	for _, rawURL := range []string{
		"http://rebind.example.com/latest/meta-data",
		"http://aliyun-meta.example.com/latest/meta-data",
		"http://169.254.169.254/latest/meta-data",
		"http://100.100.100.200/latest/meta-data",
	} {
		resp, err := client.Get(rawURL)
		if err == nil {
			_ = resp.Body.Close()
			t.Fatalf("expected SSRF block for %s, but request succeeded", rawURL)
		}
		if !strings.Contains(err.Error(), "SSRF_") {
			t.Fatalf("expected SSRF error for %s, got: %v", rawURL, err)
		}
	}
}

func TestShouldRedirectHTTPSAvoidsLoopWithoutActiveListener(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://example.com/app", nil)
	req.RemoteAddr = "203.0.113.10:54321"
	trusted := []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}

	// 无活跃 HTTPS 监听时，即使 force_https=true 也绝不返回 308（防死循环）
	if ShouldRedirectHTTPS(req, true, false, trusted) {
		t.Fatal("ShouldRedirectHTTPS must return false when no HTTPS listener is active")
	}
	// 有活跃 HTTPS 监听且来源非受信代理时，即使伪造 X-Forwarded-Proto: https 也必须跳转
	req.Header.Set("X-Forwarded-Proto", "https")
	if !ShouldRedirectHTTPS(req, true, true, trusted) {
		t.Fatal("ShouldRedirectHTTPS must ignore untrusted X-Forwarded-Proto and redirect")
	}
	// 来源为受信代理且携带 X-Forwarded-Proto: https 时不再重复跳转
	req.RemoteAddr = "127.0.0.1:44444"
	if ShouldRedirectHTTPS(req, true, true, trusted) {
		t.Fatal("ShouldRedirectHTTPS must honor X-Forwarded-Proto from trusted proxy")
	}

	// 验证 RealClientIP 仅信任 trustedProxies 的 X-Forwarded-For
	req.Header.Set("X-Forwarded-For", "198.51.100.25, 127.0.0.1")
	if got := RealClientIP(req, trusted); got != "198.51.100.25" {
		t.Fatalf("expected real client IP 198.51.100.25, got %q", got)
	}
	req.RemoteAddr = "203.0.113.99:12345"
	if got := RealClientIP(req, trusted); got != "203.0.113.99" {
		t.Fatalf("expected untrusted peer IP 203.0.113.99, got %q", got)
	}
}

func TestWebIngressUpstreamTLSInsecureAndMaxBodyMB(t *testing.T) {
	// 自签 HTTPS 上游（模拟 Portainer 9443 等容器）
	tlsUpstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("self-signed-ok:" + r.Method + ":" + string(body[:min(len(body), 16)])))
	}))
	defer tlsUpstream.Close()

	srv := startIngressTestServer(t, New(), []byte(`{"preferred_engine":"builtin-go","listen_addr":"127.0.0.1:0"}`))

	// 1. max_body_mb 超界拒绝
	for _, badMB := range []int{-1, 102401} {
		resp := invokeIngressRaw(t, srv, "ingress.site.upsert", map[string]any{
			"domain":       "badmb.example.com",
			"upstream_url": tlsUpstream.URL,
			"max_body_mb":  badMB,
		})
		if resp.GetError() == nil {
			t.Fatalf("expected max_body_mb=%d to be rejected", badMB)
		}
	}

	// 2. 先配置 upstream_tls_insecure=false，验证对自签 HTTPS 上游返回 502（严格校验证书）
	strictSite := invokeIngress(t, srv, "ingress.site.upsert", map[string]any{
		"domain":                "strict-tls.example.com",
		"upstream_url":          tlsUpstream.URL,
		"tls_mode":              "off",
		"upstream_tls_insecure": false,
		"max_body_mb":           0,
	})
	strictSiteID := strictSite["site"].(map[string]any)["id"].(string)

	// 3. 再配置 upstream_tls_insecure=true + max_body_mb=1，验证可正常反代自签 HTTPS 并拦截超限请求体
	insecSite := invokeIngress(t, srv, "ingress.site.upsert", map[string]any{
		"domain":                "portainer.example.com",
		"upstream_url":          tlsUpstream.URL,
		"tls_mode":              "off",
		"upstream_tls_insecure": true,
		"max_body_mb":           1,
	})
	insecSiteID := insecSite["site"].(map[string]any)["id"].(string)
	if insecSite["site"].(map[string]any)["upstream_tls_insecure"] != true ||
		int(insecSite["site"].(map[string]any)["max_body_mb"].(float64)) != 1 {
		t.Fatalf("unexpected site record fields: %+v", insecSite["site"])
	}

	ov := invokeIngress(t, srv, "ingress.overview", map[string]any{})
	boundAddr := ov["bound_addr"].(string)

	// 严格站点访问自签 HTTPS 上游必须 502
	reqStrict, _ := http.NewRequest(http.MethodGet, "http://"+boundAddr+"/", nil)
	reqStrict.Host = "strict-tls.example.com"
	respStrict, err := http.DefaultClient.Do(reqStrict)
	if err != nil {
		t.Fatalf("strict request transport error: %v", err)
	}
	_ = respStrict.Body.Close()
	if respStrict.StatusCode != http.StatusBadGateway {
		t.Fatalf("expected 502 for strict TLS against self-signed upstream, got %d", respStrict.StatusCode)
	}

	// 开启 upstream_tls_insecure 的站点小请求体应 200
	reqOK, _ := http.NewRequest(http.MethodPost, "http://"+boundAddr+"/upload", strings.NewReader("hello-small"))
	reqOK.Host = "portainer.example.com"
	respOK, err := http.DefaultClient.Do(reqOK)
	if err != nil {
		t.Fatalf("insecure request failed: %v", err)
	}
	bodyOK, _ := io.ReadAll(respOK.Body)
	_ = respOK.Body.Close()
	if respOK.StatusCode != http.StatusOK || !strings.Contains(string(bodyOK), "self-signed-ok:POST:hello-small") {
		t.Fatalf("expected 200 from self-signed upstream, got %d body=%q", respOK.StatusCode, string(bodyOK))
	}

	// 超过 1 MiB 请求体应被 413 拒绝
	oversize := strings.Repeat("A", (1<<20)+1024)
	reqBig, _ := http.NewRequest(http.MethodPost, "http://"+boundAddr+"/upload", strings.NewReader(oversize))
	reqBig.Host = "portainer.example.com"
	respBig, err := http.DefaultClient.Do(reqBig)
	if err != nil {
		t.Fatalf("oversize request failed: %v", err)
	}
	_ = respBig.Body.Close()
	if respBig.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected 413 for >1MiB body, got %d", respBig.StatusCode)
	}

	// 验证上游探测对自签 HTTPS 同样遵循站点开关
	strictProbe := invokeIngress(t, srv, "ingress.upstream.probe", map[string]any{"id": strictSiteID})
	if strictProbe["reachable"] != false {
		t.Fatalf("expected strict self-signed upstream probe to fail, got %+v", strictProbe)
	}
	insecProbe := invokeIngress(t, srv, "ingress.upstream.probe", map[string]any{"id": insecSiteID})
	if insecProbe["reachable"] != true {
		t.Fatalf("expected insecure self-signed upstream probe to succeed, got %+v", insecProbe)
	}

	// 4. 验证 Caddyfile 与 Nginx 渲染输出
	preview := invokeIngress(t, srv, "ingress.config.preview", map[string]any{})
	caddy := preview["caddyfile"].(string)
	nginx := preview["nginx"].(string)
	if !strings.Contains(caddy, "tls_insecure_skip_verify") || !strings.Contains(caddy, "max_size 1MB") {
		t.Fatalf("caddyfile missing insecure transport or request_body limit:\n%s", caddy)
	}
	if !strings.Contains(nginx, "proxy_ssl_verify off;") ||
		!strings.Contains(nginx, "client_max_body_size 1m;") ||
		!strings.Contains(nginx, "client_max_body_size 0;") {
		t.Fatalf("nginx config missing proxy_ssl_verify or client_max_body_size:\n%s", nginx)
	}
}

func TestWebIngressLegacyColumnMigrationIdempotent(t *testing.T) {
	dataDir := t.TempDir()
	dbPath := filepath.Join(dataDir, "ingress.db")
	legacyDB, err := sql.Open("sqlite", "file:"+filepath.ToSlash(dbPath))
	if err != nil {
		t.Fatalf("open legacy db: %v", err)
	}
	// 已带复合唯一键但缺少 upstream_tls_insecure 和 max_body_mb 的旧库
	if _, err := legacyDB.Exec(`CREATE TABLE ingress_sites (
		id                 TEXT PRIMARY KEY,
		domain             TEXT NOT NULL,
		enabled            INTEGER NOT NULL DEFAULT 1,
		upstream_url       TEXT NOT NULL,
		path_prefix        TEXT NOT NULL DEFAULT '/',
		websocket          INTEGER NOT NULL DEFAULT 1,
		tls_mode           TEXT NOT NULL DEFAULT 'managed',
		cert_id            TEXT NOT NULL DEFAULT '',
		force_https        INTEGER NOT NULL DEFAULT 1,
		rate_limit_rps     INTEGER NOT NULL DEFAULT 0,
		rate_limit_burst   INTEGER NOT NULL DEFAULT 0,
		basic_auth_user    TEXT NOT NULL DEFAULT '',
		basic_auth_hash    TEXT NOT NULL DEFAULT '',
		extra_headers_json TEXT NOT NULL DEFAULT '{}',
		notes              TEXT NOT NULL DEFAULT '',
		revision           INTEGER NOT NULL DEFAULT 1,
		created_at         INTEGER NOT NULL,
		updated_at         INTEGER NOT NULL,
		UNIQUE (domain, path_prefix)
	) STRICT;`); err != nil {
		t.Fatalf("create old v2 table: %v", err)
	}
	if _, err := legacyDB.Exec(`INSERT INTO ingress_sites (id, domain, upstream_url, created_at, updated_at) VALUES ('ing_old', 'old.example.com', 'http://127.0.0.1:8080', 1700000000, 1700000000)`); err != nil {
		t.Fatalf("insert old row: %v", err)
	}
	_ = legacyDB.Close()

	// 首次打开：应自动补齐两列且老数据保留默认值
	st1, err := openIngressStore(dataDir, embeddedSchemaSQL, time.Now)
	if err != nil {
		t.Fatalf("first openIngressStore: %v", err)
	}
	sites, err := st1.listSites(t.Context())
	if err != nil || len(sites) != 1 || sites[0].UpstreamTLSInsecure || sites[0].MaxBodyMB != 0 {
		t.Fatalf("unexpected migrated sites: %+v err=%v", sites, err)
	}
	_ = st1.Close()

	// 二次打开：幂等无报错
	st2, err := openIngressStore(dataDir, embeddedSchemaSQL, time.Now)
	if err != nil {
		t.Fatalf("second openIngressStore (idempotency): %v", err)
	}
	_ = st2.Close()
}

func TestWebIngressPathPrefixSegmentBoundary(t *testing.T) {
	apiBackend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("api:" + r.URL.Path))
	}))
	defer apiBackend.Close()
	rootBackend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("root:" + r.URL.Path))
	}))
	defer rootBackend.Close()

	p := newBuiltinProxy(time.Now, nil)
	defer p.Close()
	p.Reload([]SiteRecord{
		{ID: "s-root", Domain: "boundary.example.com", Enabled: true, UpstreamURL: rootBackend.URL, PathPrefix: "/", TLSMode: "off"},
		{ID: "s-api", Domain: "boundary.example.com", Enabled: true, UpstreamURL: apiBackend.URL, PathPrefix: "/api", TLSMode: "off"},
	})

	cases := []struct {
		path string
		want string
	}{
		{"/api", "api:/api"},
		{"/api/", "api:/api/"},
		{"/api/v1/items", "api:/api/v1/items"},
		{"/api-admin", "root:/api-admin"},
		{"/apiv2", "root:/apiv2"},
	}
	for _, tc := range cases {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "http://boundary.example.com"+tc.path, nil)
		req.Host = "boundary.example.com"
		p.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK || rec.Body.String() != tc.want {
			t.Fatalf("path %q: got status=%d body=%q, want %q", tc.path, rec.Code, rec.Body.String(), tc.want)
		}
	}
}

func TestSNICertStorePartialFailureAndEviction(t *testing.T) {
	dataDir := t.TempDir()
	sni := NewSNICertStore(dataDir)

	writeBinding := func(ref, domain string) {
		certPEM, keyPEM := generateSelfSignedCertPEM(t, domain)
		fullPath, keyPath := MaterializedCertPaths(dataDir, ref)
		if err := os.MkdirAll(filepath.Dir(fullPath), 0o700); err != nil {
			t.Fatalf("mkdir %s: %v", ref, err)
		}
		if err := os.WriteFile(fullPath, certPEM, 0o600); err != nil {
			t.Fatalf("write cert %s: %v", ref, err)
		}
		if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
			t.Fatalf("write key %s: %v", ref, err)
		}
	}
	writeBinding("certbind_good", "good.example.com")
	writeBinding("certbind_old", "old.example.com")

	// 初始加载 good + old + 缺失证书的 missing：缺失项不得阻断有效项加载
	loaded, err := sni.ReloadFromBindings(map[string]string{
		"good.example.com":    "certbind_good",
		"old.example.com":     "certbind_old",
		"missing.example.com": "certbind_nonexistent",
	})
	if err == nil {
		t.Fatal("expected partial error when one binding is missing")
	}
	if loaded != 2 {
		t.Fatalf("expected 2 valid certs loaded despite 1 missing, got %d", loaded)
	}
	if !sni.HasCertForDomain("good.example.com") || !sni.HasCertForDomain("old.example.com") {
		t.Fatal("expected good.example.com and old.example.com to be loaded")
	}

	// 移除 old.example.com 后重载：旧域名必须被立即驱逐
	loaded, err = sni.ReloadFromBindings(map[string]string{
		"good.example.com": "certbind_good",
	})
	if err != nil || loaded != 1 {
		t.Fatalf("reload after removal: loaded=%d err=%v", loaded, err)
	}
	if !sni.HasCertForDomain("good.example.com") || sni.HasCertForDomain("old.example.com") {
		t.Fatal("expected old.example.com to be evicted and good.example.com retained")
	}

	// 清空全部 TLS 站点后通过 syncSiteBindingsToSNI 同步：最后一个域名也必须被清空
	syncSiteBindingsToSNI(sni, nil)
	if sni.HasCertForDomain("good.example.com") {
		t.Fatal("expected last TLS domain to be evicted when active bindings become empty")
	}
}

func TestBasicAuthUserChangeInvalidatesCache(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer backend.Close()

	hash, err := bcrypt.GenerateFromPassword([]byte("SecretPass#1"), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("bcrypt: %v", err)
	}
	fixedNow := time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC)
	p := newBuiltinProxy(func() time.Time { return fixedNow }, nil)
	defer p.Close()

	site := SiteRecord{
		ID:            "site-auth",
		Domain:        "auth.example.com",
		Enabled:       true,
		UpstreamURL:   backend.URL,
		PathPrefix:    "/",
		TLSMode:       "off",
		HasBasicAuth:  true,
		BasicAuthUser: "alice",
		BasicAuthHash: string(hash),
	}
	p.Reload([]SiteRecord{site})

	// alice 认证通过并写入 basicAuthCache
	req1 := httptest.NewRequest(http.MethodGet, "http://auth.example.com/", nil)
	req1.Host = "auth.example.com"
	req1.SetBasicAuth("alice", "SecretPass#1")
	rec1 := httptest.NewRecorder()
	p.ServeHTTP(rec1, req1)
	if rec1.Code != http.StatusOK {
		t.Fatalf("expected 200 for alice, got %d", rec1.Code)
	}

	// 仅修改 BasicAuthUser 为 bob（保持同一 BasicAuthHash 与同一时钟），旧的 alice 凭证必须立即 401
	site.BasicAuthUser = "bob"
	p.Reload([]SiteRecord{site})

	req2 := httptest.NewRequest(http.MethodGet, "http://auth.example.com/", nil)
	req2.Host = "auth.example.com"
	req2.SetBasicAuth("alice", "SecretPass#1")
	rec2 := httptest.NewRecorder()
	p.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 after BasicAuthUser changed to bob, got %d", rec2.Code)
	}

	// bob 使用同一密码应立即 200
	req3 := httptest.NewRequest(http.MethodGet, "http://auth.example.com/", nil)
	req3.Host = "auth.example.com"
	req3.SetBasicAuth("bob", "SecretPass#1")
	rec3 := httptest.NewRecorder()
	p.ServeHTTP(rec3, req3)
	if rec3.Code != http.StatusOK {
		t.Fatalf("expected 200 for bob, got %d", rec3.Code)
	}
}

func TestDialSafeUpstreamProbeGuardsEmptyDNSAndRebinding(t *testing.T) {
	// 1. LookupNetIP 返回空切片且 err == nil 时，必须返回非 nil error，不能返回 (nil, nil)
	conn, err := dialSafeUpstreamProbeWithResolver(t.Context(), "tcp", "empty.example.com:80", func(context.Context, string, string) ([]netip.Addr, error) {
		return nil, nil
	})
	if err == nil || conn != nil {
		t.Fatalf("expected non-nil error for empty DNS result, got conn=%v err=%v", conn, err)
	}

	// 2. 域名解析到 loopback / private IP 必须被拦截（防 DNS Rebinding）
	for _, targetIP := range []string{"127.0.0.1", "10.0.0.5", "192.168.1.10", "::1"} {
		conn, err := dialSafeUpstreamProbeWithResolver(t.Context(), "tcp", "rebind.example.com:80", func(context.Context, string, string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr(targetIP)}, nil
		})
		if err == nil || conn != nil || !strings.Contains(err.Error(), "SSRF_DNS_REBIND_BLOCKED") {
			t.Fatalf("expected DNS rebinding block for %s, got conn=%v err=%v", targetIP, conn, err)
		}
	}

	// 3. 字面量 127.0.0.1 本地容器上游仍允许探测
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		if c, aerr := ln.Accept(); aerr == nil {
			_ = c.Close()
		}
	}()
	conn, err = dialSafeUpstreamProbeWithResolver(t.Context(), "tcp", ln.Addr().String(), nil)
	if err != nil || conn == nil {
		t.Fatalf("expected literal loopback probe to succeed, got conn=%v err=%v", conn, err)
	}
	_ = conn.Close()
}

func TestWebIngressApplyConfigFailurePreservesOldListener(t *testing.T) {
	srv := startIngressTestServer(t, New(), []byte(`{"preferred_engine":"builtin-go","listen_addr":"127.0.0.1:0"}`))
	ovBefore := invokeIngress(t, srv, "ingress.overview", map[string]any{})
	oldBound := ovBefore["bound_addr"].(string)
	if oldBound == "" {
		t.Fatal("expected initial bound_addr")
	}

	// 占用一个端口使 HTTPS 绑定失败，同时尝试变更 HTTP listen_addr（置空关闭 HTTP 或切换端口）
	busy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen busy: %v", err)
	}
	defer busy.Close()

	for _, nextHTTP := range []string{"", "localhost:0"} {
		cfgRaw, _ := json.Marshal(map[string]any{
			"preferred_engine":  "builtin-go",
			"listen_addr":       nextHTTP,
			"https_listen_addr": busy.Addr().String(),
		})
		resp, err := srv.ApplyConfig(t.Context(), &pb.ApplyConfigRequest{
			Context:          &pb.RequestContext{InstanceId: "default", NodeId: "local", Locale: "zh-CN"},
			ConfigJson:       cfgRaw,
			ProposedRevision: "2",
		})
		if err == nil && resp.GetError() == nil {
			t.Fatalf("expected ApplyConfig(listen_addr=%q) to fail when https_listen_addr is already in use", nextHTTP)
		}

		ovAfter := invokeIngress(t, srv, "ingress.overview", map[string]any{})
		if ovAfter["bound_addr"].(string) != oldBound {
			t.Fatalf("bound_addr corrupted after failed ApplyConfig(listen_addr=%q): before=%q after=%q", nextHTTP, oldBound, ovAfter["bound_addr"])
		}
		// 确认旧 HTTP 监听仍在正常服务
		r, gerr := http.Get("http://" + oldBound + "/")
		if gerr != nil {
			t.Fatalf("old HTTP listener stopped accepting after failed ApplyConfig: %v", gerr)
		}
		_ = r.Body.Close()
	}
}

func TestNormalizeIngressListenAddrsAndACMEHTTP01Challenge(t *testing.T) {
	h, s := NormalizeIngressListenAddrs("", "")
	if h != ":80" || s != ":443" {
		t.Fatalf("empty config should default to :80/:443, got http=%q https=%q", h, s)
	}
	h, s = NormalizeIngressListenAddrs("off", "disabled")
	if h != "" || s != "" {
		t.Fatalf("off/disabled should turn off listeners, got http=%q https=%q", h, s)
	}

	srv := startIngressTestServer(t, New(), []byte(`{"preferred_engine":"builtin-go","listen_addr":"127.0.0.1:0","https_listen_addr":"off"}`))
	ov := invokeIngress(t, srv, "ingress.overview", map[string]any{})
	if ov["running"] != true {
		t.Fatalf("expected running=true, got %+v", ov)
	}
	boundAddr := ov["bound_addr"].(string)

	// 即使站点配置了强制 HTTPS 或不存在站点，ACME HTTP-01 challenge 也必须直接返回 200 text/plain
	presentRes := invokeIngress(t, srv, "ingress.acme.present", map[string]any{
		"token":       "tok_abc123",
		"key_auth":    "tok_abc123.thumbprint999",
		"ttl_seconds": 120,
	})
	if presentRes["ok"] != true {
		t.Fatalf("expected present ok, got %+v", presentRes)
	}

	resp, err := http.Get("http://" + boundAddr + "/.well-known/acme-challenge/tok_abc123")
	if err != nil {
		t.Fatalf("GET acme challenge failed: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || string(body) != "tok_abc123.thumbprint999" {
		t.Fatalf("unexpected acme challenge response: status=%d body=%q", resp.StatusCode, string(body))
	}

	// CleanUp 后必须回退 404
	invokeIngress(t, srv, "ingress.acme.cleanup", map[string]any{"token": "tok_abc123"})
	resp2, err := http.Get("http://" + boundAddr + "/.well-known/acme-challenge/tok_abc123")
	if err != nil {
		t.Fatalf("GET after cleanup failed: %v", err)
	}
	_ = resp2.Body.Close()
	if resp2.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404 after cleanup, got %d", resp2.StatusCode)
	}
}
