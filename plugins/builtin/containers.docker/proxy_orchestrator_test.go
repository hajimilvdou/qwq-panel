// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

type recordedInvokeCall struct {
	Plugin    string
	Operation string
	Payload   map[string]any
}

type fakePluginInvoker struct {
	calls   []recordedInvokeCall
	handler func(plugin, op string, payload map[string]any) ([]byte, error)
}

func (f *fakePluginInvoker) Invoke(_ context.Context, targetPlugin, operation, _ string, payload []byte) ([]byte, error) {
	var body map[string]any
	if len(payload) > 0 {
		_ = json.Unmarshal(payload, &body)
	}
	f.calls = append(f.calls, recordedInvokeCall{
		Plugin:    targetPlugin,
		Operation: operation,
		Payload:   body,
	})
	if f.handler != nil {
		return f.handler(targetPlugin, operation, body)
	}
	return []byte(`{}`), nil
}

func TestFindMatchingExistingCertWildcardAndExact(t *testing.T) {
	certs := []CertCandidate{
		{CertID: "certbind_wild", Domains: []string{"*.example.com"}, IsWildcard: true},
		{CertID: "certbind_exact", Domains: []string{"exact.example.com"}},
	}

	if id, ok := FindMatchingExistingCert(certs, "exact.example.com"); !ok || id != "certbind_exact" {
		t.Fatalf("expected exact match certbind_exact, got id=%q ok=%v", id, ok)
	}
	if id, ok := FindMatchingExistingCert(certs, "APP.EXAMPLE.COM."); !ok || id != "certbind_wild" {
		t.Fatalf("expected wildcard match certbind_wild, got id=%q ok=%v", id, ok)
	}
	if id, ok := FindMatchingExistingCert(certs, "a.b.example.com"); ok || id != "" {
		t.Fatalf("wildcard *.example.com must NOT match multi-level a.b.example.com, got id=%q ok=%v", id, ok)
	}
	if id, ok := FindMatchingExistingCert(certs, "example.com"); ok || id != "" {
		t.Fatalf("wildcard *.example.com must NOT match apex example.com, got id=%q ok=%v", id, ok)
	}
}

func TestRewriteComposeServicePortsPreservesUnrelatedServicesAndComments(t *testing.T) {
	origYAML := `# Production stack comment
services:
  db:
    image: postgres:16-alpine
    environment:
      POSTGRES_DB: app
      POSTGRES_USER: qwq
    volumes:
      - db_data:/var/lib/postgresql/data
  web:
    image: nginx:alpine
    ports:
      - "8080:80/tcp"
    environment:
      APP_ENV: prod
    volumes:
      - ./html:/usr/share/nginx/html:ro
  worker:
    image: busybox:latest
    command: ["sleep", "3600"]
volumes:
  db_data:
`

	specs := FormatComposePortItems([]PortMappingRule{
		{BindMode: "loopback", BindIP: "127.0.0.1", HostPort: 32080, ContainerPort: 80, Protocol: "tcp"},
		{BindMode: "public", BindIP: "0.0.0.0", HostPort: 8443, ContainerPort: 443, Protocol: "both"},
	})
	rewritten, err := RewriteComposeServicePorts(origYAML, "web", specs)
	if err != nil {
		t.Fatalf("RewriteComposeServicePorts(web): %v", err)
	}
	if _, err := ValidateComposeYAMLStrict(rewritten); err != nil {
		t.Fatalf("rewritten compose YAML failed strict validation: %v\n%s", err, rewritten)
	}
	for _, mustKeep := range []string{
		"# Production stack comment",
		"POSTGRES_DB: app",
		"db_data:/var/lib/postgresql/data",
		"APP_ENV: prod",
		"./html:/usr/share/nginx/html:ro",
		`"127.0.0.1:32080:80/tcp"`,
		`"0.0.0.0:8443:443/tcp"`,
		`"0.0.0.0:8443:443/udp"`,
	} {
		if !strings.Contains(rewritten, mustKeep) {
			t.Fatalf("rewritten YAML missing expected fragment %q:\n%s", mustKeep, rewritten)
		}
	}
	if strings.Contains(rewritten, `"8080:80/tcp"`) {
		t.Fatalf("old port mapping was not replaced:\n%s", rewritten)
	}

	// 插入原本没有 ports: 块的服务
	withWorkerPort, err := RewriteComposeServicePorts(rewritten, "worker", FormatComposePortItems([]PortMappingRule{
		{BindMode: "loopback", HostPort: 32090, ContainerPort: 9090, Protocol: "tcp"},
	}))
	if err != nil {
		t.Fatalf("RewriteComposeServicePorts(worker): %v", err)
	}
	if !strings.Contains(withWorkerPort, `"127.0.0.1:32090:9090/tcp"`) {
		t.Fatalf("worker ports not inserted:\n%s", withWorkerPort)
	}
}

func TestContainerIngressLinksSyncAfterPortChangeAndCleanup(t *testing.T) {
	st, err := openStackStore(t.TempDir(), embeddedSchemaSQL, time.Now)
	if err != nil {
		t.Fatalf("openStackStore: %v", err)
	}
	defer func() { _ = st.Close() }()

	inv := &fakePluginInvoker{
		handler: func(plugin, op string, payload map[string]any) ([]byte, error) {
			switch plugin + "/" + op {
			case "web.ingress/ingress.overview":
				return []byte(`{
					"bound_addr": "127.0.0.1:80",
					"backend": {"builtin_ready": true},
					"sites": [{
						"id": "ing_site_001",
						"domain": "portainer.example.com",
						"enabled": false,
						"websocket": false,
						"force_https": false,
						"rate_limit_rps": 120,
						"rate_limit_burst": 240,
						"extra_headers": {"X-Custom-Header": "keep-me", "X-Env": "prod"}
					}]
				}`), nil
			case "tls.certificates/certificates.list":
				return []byte(`{
					"certificates": [{
						"id": "cert_wild01",
						"sans": ["*.example.com"],
						"latest_generation": 2,
						"generations": [
							{"number": 1, "issuer": "Old CA", "not_after": "2026-01-01T00:00:00Z"},
							{"number": 2, "issuer": "Let's Encrypt", "not_after": "2027-06-01T00:00:00Z"}
						],
						"bindings": [
							{"binding_ref": "certbind_wild01", "plugin_id": "web.ingress"}
						]
					}]
				}`), nil
			case "domain.dns/providers.status":
				return []byte(`{"total":1,"enabled":1,"zones":2}`), nil
			case "web.ingress/ingress.site.upsert":
				id := "ing_site_001"
				if existing, ok := payload["id"].(string); ok && existing != "" {
					id = existing
				}
				return json.Marshal(map[string]any{"site": map[string]any{"id": id}})
			case "web.ingress/ingress.site.delete":
				return []byte(`{"deleted":true}`), nil
			case "web.ingress/ingress.apply":
				return []byte(`{"applied":true}`), nil
			default:
				return nil, errors.New("unexpected call " + plugin + "/" + op)
			}
		},
	}

	// 1. 验证联动状态探测及真实 tls.certificates 字段解析
	readiness := probeProxyIntegrationStatusWithInvoker(t.Context(), inv)
	if !readiness.IngressInstalled || !readiness.CertsInstalled || !readiness.DNSInstalled {
		t.Fatalf("unexpected readiness: %+v", readiness)
	}
	if len(readiness.AvailableCerts) != 1 || readiness.AvailableCerts[0].CertID != "certbind_wild01" || !readiness.AvailableCerts[0].IsWildcard {
		t.Fatalf("unexpected parsed certs: %+v", readiness.AvailableCerts)
	}

	// 2. 一键编排容器反代（自动匹配泛域名证书 + 透传 upstream_tls_insecure & max_body_mb）
	wsTrue := true
	link, warns, err := UpsertContainerProxyAndCert(t.Context(), st.db, inv, nil, ContainerProxyUpsertRequest{
		ContainerID:      "ct_portainer",
		ContainerPort:    9443,
		Domain:           "portainer.example.com",
		PathPrefix:       "/",
		UpstreamScheme:   "https",
		UpstreamInsecure: true,
		WebSocket:        &wsTrue,
		MaxBodyMB:        2048,
		CertStrategy:     "auto_acme",
	}, resolvedProxyTarget{
		ContainerName: "/portainer",
		ContainerPort: 9443,
		HostBindIP:    "127.0.0.1",
		HostPort:      32001,
	})
	if err != nil {
		t.Fatalf("UpsertContainerProxyAndCert: %v (warns=%v)", err, warns)
	}
	if link.IngressSiteID != "ing_site_001" || link.CertID != "certbind_wild01" || link.TLSMode != "managed" || !link.UpstreamInsecure || link.MaxBodyMB != 2048 {
		t.Fatalf("unexpected saved link: %+v", link)
	}

	// 校验 overview 聚合映射
	allByName, err := ListAllContainerIngressLinksByName(t.Context(), st.db)
	if err != nil || len(allByName["portainer"]) != 1 {
		t.Fatalf("expected 1 link for portainer in overview map, got %+v err=%v", allByName, err)
	}

	// 3. 容器回环端口从 32001 改为 32002，验证 SyncContainerProxyAfterPortChange 自动更新 web.ingress 上游地址并保留自签/体积开关
	inv.calls = nil
	synced, err := SyncContainerProxyAfterPortChange(t.Context(), st.db, inv, "/portainer", map[uint16]PortTarget{
		9443: {BindIP: "127.0.0.1", HostPort: 32002},
	})
	if err != nil || synced != 1 {
		t.Fatalf("SyncContainerProxyAfterPortChange: synced=%d err=%v", synced, err)
	}
	var sawUpsert, sawApply bool
	for _, c := range inv.calls {
		if c.Plugin == "web.ingress" && c.Operation == "ingress.site.upsert" {
			sawUpsert = true
			if c.Payload["upstream_url"] != "https://127.0.0.1:32002" {
				t.Fatalf("expected updated upstream_url https://127.0.0.1:32002, got %v", c.Payload["upstream_url"])
			}
			if c.Payload["upstream_tls_insecure"] != true || int(c.Payload["max_body_mb"].(float64)) != 2048 {
				t.Fatalf("sync lost upstream_tls_insecure or max_body_mb: %+v", c.Payload)
			}
			if c.Payload["enabled"] != false || c.Payload["websocket"] != false || c.Payload["force_https"] != false {
				t.Fatalf("sync did not preserve enabled/websocket/force_https: %+v", c.Payload)
			}
			if int(c.Payload["rate_limit_rps"].(float64)) != 120 || int(c.Payload["rate_limit_burst"].(float64)) != 240 {
				t.Fatalf("sync lost rate_limit_rps or rate_limit_burst: %+v", c.Payload)
			}
			hdrs, ok := c.Payload["extra_headers"].(map[string]any)
			if !ok || hdrs["X-Custom-Header"] != "keep-me" || hdrs["X-Env"] != "prod" {
				t.Fatalf("sync lost extra_headers: %+v", c.Payload["extra_headers"])
			}
		}
		if c.Plugin == "web.ingress" && c.Operation == "ingress.apply" {
			sawApply = true
		}
	}
	if !sawUpsert || !sawApply {
		t.Fatalf("expected both ingress.site.upsert and ingress.apply calls, got %+v", inv.calls)
	}

	// 4. 删除容器联动清理关联反代站点
	inv.calls = nil
	removed, err := CleanupProxiesForContainer(t.Context(), st.db, inv, "portainer")
	if err != nil || removed != 1 {
		t.Fatalf("CleanupProxiesForContainer: removed=%d err=%v", removed, err)
	}
	var sawDelete, sawApplyAfterDel bool
	for _, c := range inv.calls {
		if c.Plugin == "web.ingress" && c.Operation == "ingress.site.delete" && c.Payload["id"] == "ing_site_001" {
			sawDelete = true
		}
		if c.Plugin == "web.ingress" && c.Operation == "ingress.apply" {
			sawApplyAfterDel = true
		}
	}
	if !sawDelete || !sawApplyAfterDel {
		t.Fatalf("expected delete + apply during cleanup, got %+v", inv.calls)
	}
	remaining, err := ListContainerIngressLinks(t.Context(), st.db, "portainer")
	if err != nil || len(remaining) != 0 {
		t.Fatalf("expected 0 remaining links after cleanup, got %+v err=%v", remaining, err)
	}
}

func TestBuildSafeDockerUpdatePayloadWithRestart(t *testing.T) {
	raw, err := BuildSafeDockerUpdatePayloadWithRestart(0, 0, "unless-stopped", 0)
	if err != nil {
		t.Fatalf("restart-only update failed: %v", err)
	}
	var body struct {
		RestartPolicy struct {
			Name              string `json:"Name"`
			MaximumRetryCount int    `json:"MaximumRetryCount"`
		} `json:"RestartPolicy"`
	}
	if err := json.Unmarshal(raw, &body); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if body.RestartPolicy.Name != "unless-stopped" || body.RestartPolicy.MaximumRetryCount != 0 {
		t.Fatalf("unexpected restart policy payload: %+v", body)
	}

	rawFail, err := BuildSafeDockerUpdatePayloadWithRestart(0, 0, "on-failure", 0)
	if err != nil {
		t.Fatalf("on-failure update failed: %v", err)
	}
	if err := json.Unmarshal(rawFail, &body); err != nil {
		t.Fatalf("unmarshal on-failure: %v", err)
	}
	if body.RestartPolicy.Name != "on-failure" || body.RestartPolicy.MaximumRetryCount != 5 {
		t.Fatalf("expected default max retry 5 for on-failure, got %+v", body)
	}

	if _, err := BuildSafeDockerUpdatePayloadWithRestart(0, 0, "invalid-policy", 0); err == nil {
		t.Fatal("expected invalid restart policy to be rejected")
	}
}
