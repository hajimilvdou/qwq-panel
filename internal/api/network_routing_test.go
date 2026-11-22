// SPDX-License-Identifier: AGPL-3.0-only

package api_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/qwq-panel/qwq/internal/api"
	"github.com/qwq-panel/qwq/internal/identity"
	"github.com/qwq-panel/qwq/internal/netfacts"
	"github.com/qwq-panel/qwq/internal/platform/problem"
)

// ======================== Track 05：双栈网络策略与分流 API 契约测试 ========================

func TestNetworkFactsAndPolicyGuardAndCAS(t *testing.T) {
	facts := netfacts.HostNetworkFacts{
		HasPublicIPv4:     true,
		HasPublicIPv6:     false,
		HasDefaultRouteV4: true,
		HasDefaultRouteV6: false,
		DefaultIfV4:       "eth0",
		Addresses: []netfacts.AddressFact{
			{Interface: "eth0", Address: "203.0.113.10", Family: "ipv4", Scope: "global"},
		},
	}

	e := newEnvWith(t, func(d *api.Deps) {
		d.NetFacts = func() (netfacts.HostNetworkFacts, error) { return facts, nil }
	})
	admin := e.setupAdmin(adminUser)
	viewer := e.signIn("net-viewer", identity.RoleViewer)

	// 未登录访问必须被拒。
	e.do(newRequest(http.MethodGet, "/api/v1/network/facts", "")).
		expectProblem(t, http.StatusUnauthorized, problem.Unauthenticated)

	// Viewer 可读 facts 和 policy，但不可写 policy。
	gotFacts := e.do(viewer.sign(http.MethodGet, "/api/v1/network/facts", "")).
		expect(t, http.StatusOK).decodeMap(t)
	if gotFacts["default_if_v4"] != "eth0" {
		t.Fatalf("default_if_v4 = %v, want eth0", gotFacts["default_if_v4"])
	}
	e.do(viewer.sign(http.MethodGet, "/api/v1/network/policy", "")).expect(t, http.StatusOK)
	e.do(viewer.sign(http.MethodPut, "/api/v1/network/policy", `{
		"inbound_family_mode":"prefer_ipv4",
		"outbound_family_mode":"prefer_ipv4"
	}`)).expectProblem(t, http.StatusForbidden, problem.PermissionDenied)

	// 无 IPv6 默认路由时强制 ipv6_only 出站必须返回 PRECONDITION_FAILED。
	e.do(admin.sign(http.MethodPut, "/api/v1/network/policy", `{
		"inbound_family_mode":"prefer_ipv4",
		"inbound_candidates":[{"id":"c1","host":"203.0.113.10","port":8443,"priority":1}],
		"outbound_family_mode":"ipv6_only",
		"outbound_overrides":[]
	}`)).expectProblem(t, http.StatusConflict, problem.PreconditionFailed)

	// 端口 < 1024 校验拦截。
	e.do(admin.sign(http.MethodPut, "/api/v1/network/policy", `{
		"inbound_family_mode":"prefer_ipv4",
		"inbound_candidates":[{"id":"c1","host":"203.0.113.10","port":443,"priority":1}],
		"outbound_family_mode":"prefer_ipv4"
	}`)).expectProblem(t, http.StatusBadRequest, problem.ValidationFailed)

	// 保存 prefer_ipv6 出站策略时允许落盘，并在 GET 中带出降级警告。
	saved := e.do(admin.sign(http.MethodPut, "/api/v1/network/policy", `{
		"inbound_family_mode":"prefer_ipv4",
		"inbound_candidates":[
			{"id":"v4","host":"203.0.113.10","port":8443,"priority":1},
			{"id":"v6","host":"2001:db8::10","port":8443,"priority":2}
		],
		"outbound_family_mode":"prefer_ipv6",
		"outbound_bind_ipv4":"203.0.113.10",
		"outbound_overrides":[
			{"domain_suffix":"openai.com","mode":"ipv4_only"}
		],
		"expected_revision":"0"
	}`)).expect(t, http.StatusOK).decodeMap(t)

	rev, _ := saved["revision"].(string)
	if !strings.HasPrefix(rev, "net_") {
		t.Fatalf("unexpected revision = %q", rev)
	}
	eff, _ := saved["effective_outbound_mode"].(string)
	if !strings.Contains(eff, "fallback") {
		t.Fatalf("expected fallback effective_outbound_mode, got %q", eff)
	}
	warnings, _ := saved["warnings"].([]any)
	if len(warnings) == 0 {
		t.Fatalf("expected fallback warnings, got %v", saved["warnings"])
	}

	// 过期 revision 更新必须触发 CAS 409 REVISION_CONFLICT。
	e.do(admin.sign(http.MethodPut, "/api/v1/network/policy", `{
		"inbound_family_mode":"prefer_ipv4",
		"inbound_candidates":[{"id":"v4","host":"203.0.113.10","port":8443,"priority":1}],
		"outbound_family_mode":"prefer_ipv4",
		"expected_revision":"stale_rev"
	}`)).expectProblem(t, http.StatusConflict, problem.RevisionConflict)

	// 携带正确 revision 可成功更新。
	updated := e.do(admin.sign(http.MethodPut, "/api/v1/network/policy", `{
		"inbound_family_mode":"prefer_ipv4",
		"inbound_candidates":[{"id":"v4","host":"203.0.113.10","port":8443,"priority":1}],
		"outbound_family_mode":"prefer_ipv4",
		"outbound_overrides":[{"domain_suffix":"openai.com","mode":"ipv4_only"}],
		"expected_revision":"`+rev+`"
	}`)).expect(t, http.StatusOK).decodeMap(t)
	if updated["outbound_family_mode"] != "prefer_ipv4" {
		t.Fatalf("updated outbound_family_mode = %v", updated["outbound_family_mode"])
	}
}

func TestRoutingProfileBundleSwapAndTwoHopPreview(t *testing.T) {
	facts := netfacts.HostNetworkFacts{
		HasPublicIPv4:     true,
		HasPublicIPv6:     true,
		HasDefaultRouteV4: true,
		HasDefaultRouteV6: true,
		DefaultIfV4:       "eth0",
		DefaultIfV6:       "eth0",
		Addresses: []netfacts.AddressFact{
			{Interface: "eth0", Address: "203.0.113.10", Family: "ipv4", Scope: "global"},
			{Interface: "eth0", Address: "2001:db8::10", Family: "ipv6", Scope: "global"},
		},
	}
	e := newEnvWith(t, func(d *api.Deps) {
		d.NetFacts = func() (netfacts.HostNetworkFacts, error) { return facts, nil }
	})
	admin := e.setupAdmin(adminUser)
	viewer := e.signIn("route-viewer", identity.RoleViewer)

	// 初始化网络策略（包含域名级出站覆盖）。
	e.do(admin.sign(http.MethodPut, "/api/v1/network/policy", `{
		"inbound_family_mode":"prefer_ipv6",
		"inbound_candidates":[
			{"id":"v4","host":"203.0.113.10","port":8443,"priority":2},
			{"id":"v6","host":"2001:db8::10","port":8443,"priority":1}
		],
		"outbound_family_mode":"prefer_ipv4",
		"outbound_bind_ipv4":"203.0.113.10",
		"outbound_bind_ipv6":"2001:db8::10",
		"outbound_overrides":[
			{"domain_suffix":"chatgpt.com","mode":"ipv6_only"}
		]
	}`)).expect(t, http.StatusOK)

	// Viewer 不可更新策略或规则包。
	e.do(viewer.sign(http.MethodPut, "/api/v1/routing/profile", `{
		"mode":"rule_cn_split","block_ads":true,"dns_anti_poison":true
	}`)).expectProblem(t, http.StatusForbidden, problem.PermissionDenied)
	e.do(viewer.sign(http.MethodPost, "/api/v1/routing/update-bundle", `{
		"version":"v2","bundle_text":"cn_domain:example.cn\n"
	}`)).expectProblem(t, http.StatusForbidden, problem.PermissionDenied)

	// 非法自定义规则拦截。
	e.do(admin.sign(http.MethodPut, "/api/v1/routing/profile", `{
		"mode":"rule_cn_split",
		"block_ads":true,
		"dns_anti_poison":true,
		"custom_rules":[{"kind":"ip_cidr","value":"not-a-cidr","action":"DIRECT"}]
	}`)).expectProblem(t, http.StatusBadRequest, problem.ValidationFailed)

	// 保存合法分流策略并校验 CAS 冲突。
	prof := e.do(admin.sign(http.MethodPut, "/api/v1/routing/profile", `{
		"name":"办公分流策略",
		"mode":"rule_cn_split",
		"block_ads":true,
		"dns_anti_poison":true,
		"custom_rules":[
			{"kind":"domain_suffix","value":"corp.internal","action":"DIRECT"}
		],
		"expected_revision":"0"
	}`)).expect(t, http.StatusOK).decodeMap(t)
	rev, _ := prof["revision"].(string)
	if rev == "" || rev == "0" {
		t.Fatalf("expected non-zero profile revision, got %q", rev)
	}
	e.do(admin.sign(http.MethodPut, "/api/v1/routing/profile", `{
		"mode":"global_proxy",
		"expected_revision":"wrong"
	}`)).expectProblem(t, http.StatusConflict, problem.RevisionConflict)

	// 原子更新规则包：SHA-256 不匹配必须失败，匹配必须成功并刷新 profile 元数据。
	bundleText := strings.Join([]string{
		"# test MIT routing bundle",
		"cn_domain:mycn.test",
		"proxy_domain:chatgpt.com",
		"ad_domain:ads.tracker.test",
		"cn_cidr:223.5.5.0/24",
	}, "\n") + "\n"
	sumBytes := sha256.Sum256([]byte(bundleText))
	wantSHA := "sha256:" + hex.EncodeToString(sumBytes[:])

	badReq, _ := json.Marshal(map[string]any{
		"version":         "2026.11.21-r1",
		"bundle_text":     bundleText,
		"expected_sha256": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
	})
	e.do(admin.sign(http.MethodPost, "/api/v1/routing/update-bundle", string(badReq))).
		expectProblem(t, http.StatusBadRequest, problem.ValidationFailed)

	goodReq, _ := json.Marshal(map[string]any{
		"version":         "2026.11.21-r1",
		"bundle_text":     bundleText,
		"expected_sha256": wantSHA,
	})
	bundleResp := e.do(admin.sign(http.MethodPost, "/api/v1/routing/update-bundle", string(goodReq))).
		expect(t, http.StatusOK).decodeMap(t)
	if bundleResp["sha256"] != wantSHA {
		t.Fatalf("bundle sha256 = %v, want %s", bundleResp["sha256"], wantSHA)
	}
	if int(bundleResp["rule_count"].(float64)) != 4 {
		t.Fatalf("bundle rule_count = %v, want 4", bundleResp["rule_count"])
	}

	// 两跳预演器：Viewer 可调用，验证 CN 直连、广告拦截与代理+域名出站覆盖。
	cnPreview := e.do(viewer.sign(http.MethodPost, "/api/v1/routing/preview", `{"target":"www.mycn.test"}`)).
		expect(t, http.StatusOK).decodeMap(t)
	cnDecision := cnPreview["client_decision"].(map[string]any)
	if cnDecision["action"] != "DIRECT" {
		t.Fatalf("cn preview action = %v, want DIRECT", cnDecision["action"])
	}

	adPreview := e.do(viewer.sign(http.MethodPost, "/api/v1/routing/preview", `{"target":"ads.tracker.test"}`)).
		expect(t, http.StatusOK).decodeMap(t)
	adDecision := adPreview["client_decision"].(map[string]any)
	if adDecision["action"] != "BLOCK" {
		t.Fatalf("ad preview action = %v, want BLOCK", adDecision["action"])
	}

	proxyPreview := e.do(viewer.sign(http.MethodPost, "/api/v1/routing/preview", `{"target":"https://api.chatgpt.com/v1/responses"}`)).
		expect(t, http.StatusOK).decodeMap(t)
	proxyDecision := proxyPreview["client_decision"].(map[string]any)
	if proxyDecision["action"] != "PROXY" {
		t.Fatalf("proxy preview action = %v, want PROXY", proxyDecision["action"])
	}
	if proxyPreview["second_hop_mode"] != "ipv6_only" {
		t.Fatalf("second_hop_mode = %v, want ipv6_only", proxyPreview["second_hop_mode"])
	}
	if proxyPreview["second_hop_bind_ip"] != "2001:db8::10" {
		t.Fatalf("second_hop_bind_ip = %v, want 2001:db8::10", proxyPreview["second_hop_bind_ip"])
	}
	eps := proxyPreview["first_hop_endpoints"].([]any)
	if len(eps) != 2 || eps[0] != "[2001:db8::10]:8443" {
		t.Fatalf("first_hop_endpoints = %v, want [2001:db8::10]:8443 first", eps)
	}
}
