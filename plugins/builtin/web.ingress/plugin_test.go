// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
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
