// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net"
	"strings"
	"testing"
	"time"

	corev2 "github.com/qwq-panel/qwq/sdk/coreapi/v2"
	pb "github.com/qwq-panel/qwq/sdk/gen/qwq/platform/v1"
)

func TestNodesUpsertSimplifiedExpertListPreviewAndDelete(t *testing.T) {
	h := newProxyTestHarness(t, `{"public_host":"edge.example.com"}`, time.Hour)

	// 1. 极简模式创建 9 种协议节点，自动分配高位端口与生成凭据/密钥/填充方案
	protocols := []string{"vless", "vmess", "trojan", "shadowsocks", "shadowsocks2022", "hysteria2", "anytls", "socks5", "http"}
	createdIDs := make([]string, 0, len(protocols))
	seenPorts := make(map[int]bool)
	for _, proto := range protocols {
		resp := invokeProxy(t, h.srv, "nodes.upsert", map[string]any{
			"mode":      "simplified",
			"protocol":  proto,
			"name":      "auto-" + proto,
			"sync_core": false,
		})
		if resp.GetError() != nil {
			t.Fatalf("nodes.upsert(%s) 失败: %+v", proto, resp.GetError())
		}
		var out struct {
			Node     proxyNodeRecord `json:"node"`
			Created  bool            `json:"created"`
			XrayJSON string          `json:"xray_json"`
			ShareURI string          `json:"share_uri"`
		}
		if err := json.Unmarshal(resp.GetPayloadJson(), &out); err != nil {
			t.Fatal(err)
		}
		if !out.Created || out.Node.Port < 20000 || out.Node.Port > 59999 {
			t.Fatalf("极简模式端口或创建状态不符(%s): %+v", proto, out.Node)
		}
		if seenPorts[out.Node.Port] {
			t.Fatalf("极简模式分配了重复端口: %d", out.Node.Port)
		}
		seenPorts[out.Node.Port] = true
		if out.XrayJSON == "" || out.ShareURI == "" {
			t.Fatalf("节点 %s 缺少预览 JSON 或分享链接", proto)
		}
		if proto == "vless" && (out.Node.Config.UUID == "" || out.Node.Config.PublicKey == "" || out.Node.Config.ShortID == "") {
			t.Fatalf("VLESS 极简模式未生成完整 Reality 材料: %+v", out.Node.Config)
		}
		if proto == "anytls" && len(out.Node.Config.PaddingScheme) != 9 {
			t.Fatalf("AnyTLS 极简模式未填充默认 8 阶方案: %+v", out.Node.Config.PaddingScheme)
		}
		createdIDs = append(createdIDs, out.Node.ID)
	}

	// 2. 列表查询与筛选
	listResp := invokeProxy(t, h.srv, "nodes.list", map[string]any{"source": "managed"})
	if listResp.GetError() != nil {
		t.Fatalf("nodes.list 失败: %+v", listResp.GetError())
	}
	var listOut struct {
		Nodes         []proxyNodeRecord `json:"nodes"`
		Total         int               `json:"total"`
		ManagedCount  int               `json:"managed_count"`
		ExternalCount int               `json:"external_count"`
	}
	if err := json.Unmarshal(listResp.GetPayloadJson(), &listOut); err != nil {
		t.Fatal(err)
	}
	if listOut.Total != 9 || listOut.ManagedCount != 9 || listOut.ExternalCount != 0 {
		t.Fatalf("nodes.list 数量不符: %+v", listOut)
	}

	// 3. 专家模式预览 VLESS XHTTP + Reality（纯函数，不入库）
	prevResp := invokeProxy(t, h.srv, "nodes.preview_json", map[string]any{
		"mode":          "expert",
		"protocol":      "vless",
		"transport":     "xhttp",
		"security_mode": "reality",
		"port":          24443,
		"config": map[string]any{
			"path":       "/xhttp-custom",
			"host":       "cdn.example.com",
			"xhttp_mode": "packet-up",
			"sni":        "www.apple.com",
		},
	})
	if prevResp.GetError() != nil {
		t.Fatalf("nodes.preview_json 失败: %+v", prevResp.GetError())
	}
	var prevOut struct {
		Engine     string `json:"engine"`
		NativeJSON string `json:"native_json"`
		ShareURI   string `json:"share_uri"`
		ClashYAML  string `json:"clash_yaml"`
	}
	if err := json.Unmarshal(prevResp.GetPayloadJson(), &prevOut); err != nil {
		t.Fatal(err)
	}
	if prevOut.Engine != "xray" || !strings.Contains(prevOut.NativeJSON, `"xhttpSettings"`) || !strings.Contains(prevOut.ShareURI, "type=xhttp") {
		t.Fatalf("nodes.preview_json 输出异常: %+v", prevOut)
	}

	// 验证 preview_json 未写入数据库
	listAgain := invokeProxy(t, h.srv, "nodes.list", map[string]any{})
	var listAgainOut struct {
		Total int `json:"total"`
	}
	_ = json.Unmarshal(listAgain.GetPayloadJson(), &listAgainOut)
	if listAgainOut.Total != 9 {
		t.Fatalf("preview_json 不应修改数据库节点数，实际 %d", listAgainOut.Total)
	}

	// 4. 删除节点
	delResp := invokeProxy(t, h.srv, "nodes.delete", map[string]any{"id": createdIDs[0], "sync_core": false})
	if delResp.GetError() != nil {
		t.Fatalf("nodes.delete 失败: %+v", delResp.GetError())
	}
	var delOut struct {
		Deleted bool `json:"deleted"`
	}
	_ = json.Unmarshal(delResp.GetPayloadJson(), &delOut)
	if !delOut.Deleted {
		t.Fatal("nodes.delete 未返回 deleted=true")
	}
}

func TestNodesProbeSNIImportURIAndLatencyTest(t *testing.T) {
	h := newProxyTestHarness(t, `{"public_host":"edge.example.com"}`, time.Hour)

	// 1. 测试 SNI 并发探测排序与推荐
	origProbe := sniProbeFunc
	t.Cleanup(func() { sniProbeFunc = origProbe })
	sniProbeFunc = func(_ context.Context, domain string, _ time.Duration) sniProbeResult {
		switch domain {
		case "fast.example.test":
			return sniProbeResult{Domain: domain, OK: true, LatencyMS: 12, TLSVersion: "TLS 1.3", TLS13: true, ALPN: "h2"}
		case "slow.example.test":
			return sniProbeResult{Domain: domain, OK: true, LatencyMS: 88, TLSVersion: "TLS 1.3", TLS13: true, ALPN: "h2"}
		default:
			return sniProbeResult{Domain: domain, OK: false, LatencyMS: -1, Error: "dial timeout"}
		}
	}
	sniResp := invokeProxy(t, h.srv, "nodes.probe_sni", map[string]any{
		"domains": []string{"dead.example.test", "slow.example.test", "fast.example.test"},
	})
	if sniResp.GetError() != nil {
		t.Fatalf("nodes.probe_sni 失败: %+v", sniResp.GetError())
	}
	var sniOut struct {
		Results     []sniProbeResult `json:"results"`
		Recommended string           `json:"recommended"`
	}
	if err := json.Unmarshal(sniResp.GetPayloadJson(), &sniOut); err != nil {
		t.Fatal(err)
	}
	if sniOut.Recommended != "fast.example.test" || len(sniOut.Results) != 3 || sniOut.Results[0].Domain != "fast.example.test" {
		t.Fatalf("nodes.probe_sni 排序或推荐错误: %+v", sniOut)
	}

	// 2. 启动本地 TCP 监听器用于 nodes.test 真实连通性测试
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	tcpPort := ln.Addr().(*net.TCPAddr).Port

	// 3. 批量导入全部 11 种协议 URI
	vmessPayload := base64.StdEncoding.EncodeToString([]byte(`{"v":"2","ps":"ext-vmess","add":"1.1.1.1","port":"443","id":"11111111-1111-4111-8111-111111111111","aid":"0","net":"ws","path":"/vm","tls":"tls","sni":"vm.example.com"}`))
	ssUserInfo := base64.RawURLEncoding.EncodeToString([]byte("aes-256-gcm:ss-secret-pass"))
	uris := strings.Join([]string{
		"vless://22222222-2222-4222-8222-222222222222@vless.example.com:443?security=reality&sni=www.microsoft.com&pbk=pub123&sid=abcd&type=tcp&flow=xtls-rprx-vision#ext-vless",
		"vmess://" + vmessPayload,
		"trojan://tr-pass@trojan.example.com:443?security=tls&sni=trojan.example.com&type=grpc&serviceName=tr#ext-trojan",
		"ss://" + ssUserInfo + "@ss.example.com:8388#ext-ss",
		"hysteria2://hy2-pass@hy2.example.com:8443?sni=hy2.example.com&obfs=salamander&obfs-password=obfs123&mport=20000-21000#ext-hy2",
		"anytls://anytls-pass@anytls.example.com:443?sni=anytls.example.com&insecure=0#ext-anytls",
		"socks5://u1:p1@127.0.0.1:" + itoaPort(tcpPort) + "#ext-socks5",
		"http://u2:p2@http.example.com:8080#ext-http",
		"tuic://33333333-3333-4333-8333-333333333333:tuic-pass@tuic.example.com:443?sni=tuic.example.com&congestion_control=bbr#ext-tuic",
		"wireguard://privkeybase64@wg.example.com:51820?publickey=peerpubkey&address=172.16.0.2/32&mtu=1280#ext-wg",
	}, "\n")

	impResp := invokeProxy(t, h.srv, "nodes.import_uri", map[string]any{
		"uris": uris,
		"tags": []string{"batch-1"},
	})
	if impResp.GetError() != nil {
		t.Fatalf("nodes.import_uri 失败: %+v", impResp.GetError())
	}
	var impOut struct {
		Imported      []proxyNodeRecord `json:"imported"`
		ImportedCount int               `json:"imported_count"`
		Errors        []map[string]any  `json:"errors"`
	}
	if err := json.Unmarshal(impResp.GetPayloadJson(), &impOut); err != nil {
		t.Fatal(err)
	}
	if impOut.ImportedCount != 10 || len(impOut.Errors) != 0 {
		t.Fatalf("nodes.import_uri 导入数不符: count=%d errors=%+v", impOut.ImportedCount, impOut.Errors)
	}

	// 4. 对刚导入的外部 127.0.0.1 socks5 节点执行延迟测试：必须被公网探测策略拦截防 SSRF！
	var socksID string
	for _, n := range impOut.Imported {
		if n.Protocol == "socks5" {
			socksID = n.ID
			break
		}
	}
	testResp := invokeProxy(t, h.srv, "nodes.test", map[string]any{"id": socksID})
	if testResp.GetError() != nil {
		t.Fatalf("nodes.test 失败: %+v", testResp.GetError())
	}
	var testOut struct {
		OK        bool   `json:"ok"`
		LatencyMS int64  `json:"latency_ms"`
		Error     string `json:"error"`
	}
	_ = json.Unmarshal(testResp.GetPayloadJson(), &testOut)
	if testOut.OK || testOut.Error == "" {
		t.Fatalf("外部节点探测 127.0.0.1 必须被 SSRF 策略拦截，实际: %+v", testOut)
	}

	// 4b. 本机已登记托管节点允许对本机监听端口执行连通性测试
	mResp := invokeProxy(t, h.srv, "nodes.upsert", map[string]any{
		"id":        "managed-socks-loop",
		"mode":      "expert",
		"protocol":  "socks5",
		"name":      "managed-loop",
		"listen":    "127.0.0.1",
		"port":      tcpPort,
		"sync_core": false,
	})
	if mResp.GetError() != nil {
		t.Fatalf("managed socks5 upsert 失败: %+v", mResp.GetError())
	}
	mTestResp := invokeProxy(t, h.srv, "nodes.test", map[string]any{"id": "managed-socks-loop"})
	if mTestResp.GetError() != nil {
		t.Fatalf("managed nodes.test 失败: %+v", mTestResp.GetError())
	}
	var mTestOut struct {
		OK        bool  `json:"ok"`
		LatencyMS int64 `json:"latency_ms"`
	}
	_ = json.Unmarshal(mTestResp.GetPayloadJson(), &mTestOut)
	if !mTestOut.OK || mTestOut.LatencyMS < 1 {
		t.Fatalf("托管节点本地探测期望成功且延迟 >= 1ms，实际: %+v", mTestOut)
	}

	// 5. 创建套餐和用户，验证多协议订阅（raw / clash / singbox）包含 AnyTLS、TUIC、WireGuard、VMess、Trojan 等所有节点
	pJob := runProxyJob(t, h.srv, "plans.upsert", map[string]any{"id": "p1", "name": "基础套餐", "quota_bytes": 1073741824}, nil)
	if pJob.GetError() != nil {
		t.Fatalf("plans.upsert 失败: %+v", pJob.GetError())
	}
	uJob := runProxyJob(t, h.srv, "users.create", map[string]any{"id": "subuser", "display_name": "SubUser", "plan_id": "p1"}, nil)
	if uJob.GetError() != nil {
		t.Fatalf("users.create 失败: %+v", uJob.GetError())
	}
	var uOut struct {
		SubscriptionToken string `json:"subscription_token"`
	}
	_ = json.Unmarshal(uJob.GetResultJson(), &uOut)

	for _, format := range []string{"raw", "clash", "singbox"} {
		pubResp, err := h.srv.ServePublicRoute(t.Context(), &pb.ServePublicRouteRequest{
			Context:  &pb.RequestContext{InstanceId: "default", NodeId: "local"},
			Route:    "sub",
			Method:   "GET",
			Path:     "/sub/" + uOut.SubscriptionToken,
			RawQuery: "format=" + format,
		})
		if err != nil || pubResp.GetStatus() != 200 {
			t.Fatalf("订阅拉取(%s)失败: err=%v status=%d body=%s", format, err, pubResp.GetStatus(), string(pubResp.GetBody()))
		}
		body := string(pubResp.GetBody())
		switch format {
		case "raw":
			decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(body))
			if err != nil {
				t.Fatalf("raw 订阅 Base64 解码失败: %v", err)
			}
			txt := string(decoded)
			for _, prefix := range []string{"vless://", "vmess://", "trojan://", "ss://", "hysteria2://", "anytls://", "socks5://", "http://", "tuic://", "wireguard://"} {
				if !strings.Contains(txt, prefix) {
					t.Fatalf("raw 订阅缺少 %s 协议节点:\n%s", prefix, txt)
				}
			}
		case "clash":
			for _, want := range []string{"type: anytls", "type: tuic", "type: wireguard", "type: vmess", "type: trojan", "type: socks5", "type: http"} {
				if !strings.Contains(body, want) {
					t.Fatalf("clash 订阅缺少 %s:\n%s", want, body)
				}
			}
		case "singbox":
			for _, want := range []string{`"type": "anytls"`, `"type": "tuic"`, `"type": "wireguard"`, `"type": "vmess"`, `"type": "trojan"`, `"type": "socks"`} {
				if !strings.Contains(body, want) {
					t.Fatalf("singbox 订阅缺少 %s:\n%s", want, body)
				}
			}
		}
	}
}

func itoaPort(p int) string {
	b, _ := json.Marshal(p)
	return string(b)
}

func TestNodesEncryptionRedactionMultiProfileSyncAndBrutalPPV2(t *testing.T) {
	h := newProxyTestHarness(t, `{"public_host":"edge.example.com"}`, time.Hour)

	// 1. 创建套餐与共享用户，验证多 profile（VLESS + SS2022 + AnyTLS）共享同一用户可通过 corev2.Validate
	pJob := runProxyJob(t, h.srv, "plans.upsert", map[string]any{"id": "p-multi", "name": "MultiPlan", "quota_bytes": 0}, nil)
	if pJob.GetError() != nil {
		t.Fatalf("plans.upsert 失败: %+v", pJob.GetError())
	}
	uJob := runProxyJob(t, h.srv, "users.create", map[string]any{"id": "alice", "display_name": "Alice", "plan_id": "p-multi"}, nil)
	if uJob.GetError() != nil {
		t.Fatalf("users.create 失败: %+v", uJob.GetError())
	}

	// 创建 VLESS Reality 节点和 SS2022 节点
	vResp := invokeProxy(t, h.srv, "nodes.upsert", map[string]any{
		"mode":      "simplified",
		"protocol":  "vless",
		"name":      "vless-multi",
		"port":      24441,
		"sync_core": false,
	})
	if vResp.GetError() != nil {
		t.Fatalf("vless upsert 失败: %+v", vResp.GetError())
	}
	var vOut struct {
		Node proxyNodeRecord `json:"node"`
	}
	_ = json.Unmarshal(vResp.GetPayloadJson(), &vOut)

	sResp := invokeProxy(t, h.srv, "nodes.upsert", map[string]any{
		"mode":      "simplified",
		"protocol":  "shadowsocks2022",
		"name":      "ss2022-multi",
		"port":      24442,
		"sync_core": false,
	})
	if sResp.GetError() != nil {
		t.Fatalf("ss2022 upsert 失败: %+v", sResp.GetError())
	}
	var sOut struct {
		Node proxyNodeRecord `json:"node"`
	}
	_ = json.Unmarshal(sResp.GetPayloadJson(), &sOut)

	// 2. 验证 nodes.upsert 响应已脱敏服务端独占私钥，且 SQLite config_json 加密落盘不含明文私钥
	if vOut.Node.Config.PrivateKey != "" {
		t.Fatalf("nodes.upsert 响应不应返回服务端独占 PrivateKey: %+v", vOut.Node.Config)
	}
	st, err := openStore(h.dataDir, nil)
	if err != nil {
		t.Fatalf("openStore(%s) 失败: %v", h.dataDir, err)
	}
	defer st.Close()
	storedBefore, err := st.GetNode(t.Context(), vOut.Node.ID)
	if err != nil || storedBefore == nil || storedBefore.Config.PrivateKey == "" {
		t.Fatalf("GetNode 应能解密服务端私钥: rec=%+v err=%v", storedBefore, err)
	}
	origPriv := storedBefore.Config.PrivateKey
	var rawCfgJSON string
	if err := st.readDB().QueryRow(`SELECT config_json FROM proxy_nodes WHERE id = ?`, vOut.Node.ID).Scan(&rawCfgJSON); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(rawCfgJSON, `"$enc":"enc:`) || strings.Contains(rawCfgJSON, origPriv) {
		t.Fatalf("proxy_nodes.config_json 未加密落盘或包含明文私钥: %s", rawCfgJSON)
	}

	// 2b. 验证 nodes.preview_json 传已有 id 时复用真实公钥/UUID 且脱敏 privateKey
	pvResp := invokeProxy(t, h.srv, "nodes.preview_json", map[string]any{
		"id":       vOut.Node.ID,
		"protocol": "vless",
	})
	if pvResp.GetError() != nil {
		t.Fatalf("nodes.preview_json(existing) 失败: %+v", pvResp.GetError())
	}
	var pvOut struct {
		NativeJSON string `json:"native_json"`
		ShareURI   string `json:"share_uri"`
	}
	_ = json.Unmarshal(pvResp.GetPayloadJson(), &pvOut)
	if strings.Contains(pvOut.NativeJSON, origPriv) || !strings.Contains(pvOut.NativeJSON, "<REDACTED>") || !strings.Contains(pvOut.ShareURI, storedBefore.Config.PublicKey) {
		t.Fatalf("nodes.preview_json 未复用真实公钥或泄露私钥: json=%s uri=%s", pvOut.NativeJSON, pvOut.ShareURI)
	}

	// 3. 验证 nodes.list 脱敏私钥/服务端密钥，同时保留公钥与 UUID
	lResp := invokeProxy(t, h.srv, "nodes.list", map[string]any{"source": "managed"})
	var lOut struct {
		Nodes []proxyNodeRecord `json:"nodes"`
	}
	_ = json.Unmarshal(lResp.GetPayloadJson(), &lOut)
	for _, n := range lOut.Nodes {
		if n.Config.PrivateKey != "" || n.Config.ServerKey != "" || n.Config.Password != "" || n.Config.ObfsPassword != "" || n.Config.Decryption != "" {
			t.Fatalf("nodes.list 未脱敏节点 %s 敏感字段: %+v", n.ID, n.Config)
		}
		if n.ID == vOut.Node.ID && n.Config.PublicKey == "" {
			t.Fatalf("nodes.list 应保留派生公钥: %+v", n.Config)
		}
	}

	// 4. 验证专家模式编辑时可关闭 Flow 与 Insecure，同时保留未提交的加密私钥
	editResp := invokeProxy(t, h.srv, "nodes.upsert", map[string]any{
		"id":            vOut.Node.ID,
		"mode":          "expert",
		"protocol":      "vless",
		"transport":     "raw",
		"security_mode": "reality",
		"port":          24441,
		"config": map[string]any{
			"flow":     "",
			"insecure": false,
		},
		"sync_core": false,
	})
	if editResp.GetError() != nil {
		t.Fatalf("expert edit 失败: %+v", editResp.GetError())
	}
	storedAfter, err := st.GetNode(t.Context(), vOut.Node.ID)
	if err != nil || storedAfter == nil {
		t.Fatalf("GetNode 失败: %v", err)
	}
	if storedAfter.Config.PrivateKey != origPriv {
		t.Fatal("省略私钥编辑节点后原有私钥丢失")
	}
	if storedAfter.Config.Flow != "" {
		t.Fatalf("专家模式清空 flow 失败，仍为 %q", storedAfter.Config.Flow)
	}
	if storedAfter.Config.isInsecure() {
		t.Fatal("专家模式显式关闭 insecure 失败")
	}

	// 5. 验证多 profile 共享同一 active 用户构建的 Core Intent v2 通过 corev2.Validate
	managed, err := st.ListNodes(t.Context(), "managed", "", "", "", false)
	if err != nil {
		t.Fatal(err)
	}
	activeUsers, err := st.ListUsers(t.Context(), "active", "", 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(managed) < 2 || len(activeUsers) < 1 {
		t.Fatalf("预期 >=2 托管节点与 >=1 活跃用户，实际 nodes=%d users=%d", len(managed), len(activeUsers))
	}
	secretCounter := 1
	replaceRawSecretsWithRefs := func(m map[string]any) {
		nextRef := func() map[string]any {
			const alphabet = "0123456789abcdefghjkmnpqrstvwxyz"
			id := "sec_0000000000000000000000000" + string(alphabet[secretCounter%len(alphabet)])
			secretCounter++
			return map[string]any{"$secret": id}
		}
		if vless, ok := m["vless"].(map[string]any); ok {
			if sec, ok := vless["security"].(map[string]any); ok {
				sec["private_key"] = nextRef()
			}
		}
		if ss22, ok := m["shadowsocks2022"].(map[string]any); ok {
			ss22["server_key"] = nextRef()
		}
		if users, ok := m["users"].([]any); ok {
			for _, u := range users {
				um := u.(map[string]any)
				for _, k := range []string{"uuid", "psk", "auth"} {
					if _, exists := um[k]; exists {
						um[k] = nextRef()
					}
				}
			}
		}
	}
	var profiles []any
	for _, n := range managed {
		prof, ok := buildCoreV2ProfileFromNodeWithSlots(n, activeUsers, nil)
		if !ok {
			t.Fatalf("构建 profile 失败: %+v", n)
		}
		replaceRawSecretsWithRefs(prof)
		profiles = append(profiles, prof)
	}
	intentRaw, err := json.Marshal(map[string]any{
		"schema_version": "2",
		"enabled":        true,
		"outbound":       map[string]any{"type": "direct"},
		"profiles":       profiles,
	})
	if err != nil {
		t.Fatal(err)
	}
	intent, err := corev2.Decode(intentRaw)
	if err != nil {
		t.Fatalf("corev2.Decode 失败: %v\n%s", err, string(intentRaw))
	}
	if err := corev2.Validate(intent); err != nil {
		t.Fatalf("多 profile 共享用户 corev2.Validate 失败: %v", err)
	}

	// 6. 验证 brutal_bindings.proxy_protocol_v2 持久化
	ppv2True := true
	savedBrutal, created, err := st.UpsertBrutalBinding(t.Context(), brutalBindingUpsertRequest{
		ID:              "brutal-ppv2",
		InboundTag:      "vless-main",
		Protocol:        "vless",
		ListenPort:      25443,
		TargetPort:      24441,
		BandwidthMbps:   200,
		ProxyProtocolV2: &ppv2True,
	})
	if err != nil || !created || !savedBrutal.ProxyProtocolV2 {
		t.Fatalf("UpsertBrutalBinding(ppv2=true) 失败: created=%v rec=%+v err=%v", created, savedBrutal, err)
	}
	listBrutal, err := st.ListBrutalBindings(t.Context())
	if err != nil || len(listBrutal) != 1 || !listBrutal[0].ProxyProtocolV2 {
		t.Fatalf("ListBrutalBindings 未持久化 proxy_protocol_v2: %+v err=%v", listBrutal, err)
	}
}

func TestNormalizeRealityPrivateKeyFromXUIStandardBase64(t *testing.T) {
	// 32-byte key whose standard base64 contains '+', '/', and '=' padding.
	raw := make([]byte, 32)
	for i := range raw {
		raw[i] = byte(0xfb - i)
	}
	stdPadded := base64.StdEncoding.EncodeToString(raw)
	wantRawURL := base64.RawURLEncoding.EncodeToString(raw)

	cfg := nodeConfig{PrivateKey: stdPadded}
	if err := fillRealityDefaults(&cfg); err != nil {
		t.Fatalf("fillRealityDefaults(std base64) failed: %v", err)
	}
	if cfg.PrivateKey != wantRawURL {
		t.Fatalf("PrivateKey = %q, want canonical RawURLEncoding %q", cfg.PrivateKey, wantRawURL)
	}
	if cfg.PublicKey == "" {
		t.Fatal("expected derived Reality PublicKey")
	}
}
