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
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

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
