// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"

	pluginconfigv1 "github.com/qwq-panel/qwq/sdk/gen/qwq/capability/pluginconfig/v1"
	trafficv1 "github.com/qwq-panel/qwq/sdk/gen/qwq/capability/traffic/v1"
	pb "github.com/qwq-panel/qwq/sdk/gen/qwq/platform/v1"
	"github.com/qwq-panel/qwq/sdk/pluginsdk"
)

// newExtProxyHarness 构造隔离 sysctl 落盘路径与 127.0.0.1 Brutal 绑定的完整 gRPC 夹具。
func newExtProxyHarness(t *testing.T, configJSON string) (*proxyHarness, string) {
	t.Helper()
	listener := bufconn.Listen(256 << 10)
	hostServer := grpc.NewServer()
	h := &proxyHarness{
		cfgSvc:   newFakePluginConfigService(),
		traffic:  newFakeTrafficService(),
		invoke:   &fakeHostInvokeService{},
		dataDir:  t.TempDir(),
		clockSec: &atomic.Int64{},
	}
	h.clockSec.Store(time.Date(2026, 11, 22, 4, 0, 0, 0, time.UTC).Unix())

	pluginconfigv1.RegisterPluginConfigServiceServer(hostServer, h.cfgSvc)
	trafficv1.RegisterTrafficServiceServer(hostServer, h.traffic)
	pb.RegisterHostInvokeServiceServer(hostServer, h.invoke)
	go func() { _ = hostServer.Serve(listener) }()
	t.Cleanup(func() { hostServer.Stop(); _ = listener.Close() })

	conn, err := grpc.NewClient("passthrough:///proxy-ext-host",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return listener.Dial() }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	sysctlFile := filepath.Join(t.TempDir(), "99-qwq-tcpfit.conf")
	plugin := &Plugin{
		now:              func() time.Time { return time.Unix(h.clockSec.Load(), 0).UTC() },
		syncInterval:     time.Hour,
		brutalBindHost:   "127.0.0.1",
		sysctlTargetPath: sysctlFile,
	}
	srv, err := pluginsdk.Serve(t.Context(), pluginsdk.Options{
		Plugin:             plugin,
		Manifest:           Manifest(),
		Registrar:          grpc.NewServer(),
		Host:               conn,
		DefaultGracePeriod: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(srv.Close)

	if configJSON == "" {
		configJSON = `{}`
	}
	rc := &pb.RequestContext{InstanceId: "default", NodeId: "local", Locale: "zh-CN"}
	if _, err := srv.Initialize(t.Context(), &pb.InitializeRequest{
		Context:        rc,
		InstanceHandle: "proxy-handle",
		DataDir:        h.dataDir,
		ConfigJson:     []byte(configJSON),
		ConfigRevision: "1",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := srv.Start(t.Context(), &pb.StartRequest{Context: rc}); err != nil {
		t.Fatal(err)
	}
	h.srv = srv
	return h, sysctlFile
}

// ======================== 1. 套餐与单用户并发连接数 / 同时在线 IP 限制 ========================

func TestUserConnectionAndIPLimitsAndNftables(t *testing.T) {
	h, _ := newExtProxyHarness(t, `{"public_host":"proxy.example.com","vless_port":443}`)

	// 创建携带默认 max_connections=64、max_ips=2 的套餐。
	pProg := runProxyJob(t, h.srv, "plans.upsert", map[string]any{
		"id":              "conn-plan",
		"name":            "连接限制套餐",
		"quota_bytes":     10737418240,
		"down_limit_kbps": 50000,
		"up_limit_kbps":   20000,
		"max_connections": 64,
		"max_ips":         2,
	}, nil)
	if pProg.GetError() != nil {
		t.Fatalf("plans.upsert failed: %+v", pProg.GetError())
	}
	var pOut struct {
		Plan planRecord `json:"plan"`
	}
	if err := json.Unmarshal(pProg.GetResultJson(), &pOut); err != nil {
		t.Fatal(err)
	}
	if pOut.Plan.MaxConnections != 64 || pOut.Plan.MaxIPs != 2 {
		t.Fatalf("套餐连接限制未持久化: %+v", pOut.Plan)
	}

	// 新建用户默认继承套餐 (-1)。
	uProg := runProxyJob(t, h.srv, "users.create", map[string]any{
		"id":           "u-conn",
		"display_name": "ConnUser",
		"plan_id":      "conn-plan",
	}, nil)
	if uProg.GetError() != nil {
		t.Fatalf("users.create failed: %+v", uProg.GetError())
	}
	var uOut struct {
		User userRecord `json:"user"`
	}
	if err := json.Unmarshal(uProg.GetResultJson(), &uOut); err != nil {
		t.Fatal(err)
	}
	if uOut.User.EffectiveMaxConnections != 64 || uOut.User.EffectiveMaxIPs != 2 {
		t.Fatalf("用户应继承套餐限制 64/2，实际 %d/%d", uOut.User.EffectiveMaxConnections, uOut.User.EffectiveMaxIPs)
	}

	// 单用户覆盖为 max_connections=12, max_ips=0(不限)。
	setResp := invokeProxy(t, h.srv, "users.set_limits", map[string]any{
		"user_id":                  "u-conn",
		"max_connections_override": 12,
		"max_ips_override":         0,
	})
	if setResp.GetError() != nil {
		t.Fatalf("users.set_limits failed: %+v", setResp.GetError())
	}
	var setOut struct {
		User userRecord `json:"user"`
	}
	if err := json.Unmarshal(setResp.GetPayloadJson(), &setOut); err != nil {
		t.Fatal(err)
	}
	if setOut.User.EffectiveMaxConnections != 12 || setOut.User.EffectiveMaxIPs != 0 {
		t.Fatalf("单用户覆盖后生效值应为 12/0，实际 %d/%d", setOut.User.EffectiveMaxConnections, setOut.User.EffectiveMaxIPs)
	}

	// 查询实时状态并渲染 nftables ct count 规则。
	stResp := invokeProxy(t, h.srv, "users.connections.status", map[string]any{"include_nftables": true})
	if stResp.GetError() != nil {
		t.Fatalf("users.connections.status failed: %+v", stResp.GetError())
	}
	var stOut struct {
		Items         []userConnSnapshot `json:"items"`
		NftablesRules string             `json:"nftables_rules"`
	}
	if err := json.Unmarshal(stResp.GetPayloadJson(), &stOut); err != nil {
		t.Fatal(err)
	}
	if len(stOut.Items) != 1 || stOut.Items[0].MaxConnections != 12 {
		t.Fatalf("connections.status 快照不符: %+v", stOut.Items)
	}
	if !strings.Contains(stOut.NftablesRules, "ct count over 12") || !strings.Contains(stOut.NftablesRules, "meta mark") {
		t.Fatalf("nftables 规则缺少 ct count over 12:\n%s", stOut.NftablesRules)
	}

	// 验证 connLimiter 线程安全并发连接数与在线 IP 数准入与释放。
	lim := newConnLimiter()
	ok1, _, rel1 := lim.Admit("u-conn", "203.0.113.1:50001", 3, 2)
	ok2, _, rel2 := lim.Admit("u-conn", "203.0.113.1:50002", 3, 2)
	ok3, _, rel3 := lim.Admit("u-conn", "203.0.113.2:50003", 3, 2)
	if !ok1 || !ok2 || !ok3 {
		t.Fatalf("前 3 条合法连接应放行")
	}
	// 第 4 条触发并发上限。
	if ok4, reason, _ := lim.Admit("u-conn", "203.0.113.1:50004", 3, 2); ok4 || !strings.Contains(reason, "并发连接数") {
		t.Fatalf("超并发上限应拒绝: ok=%v reason=%q", ok4, reason)
	}
	// 释放一条 203.0.113.1 连接后，换第 3 个 IP 触发最大在线 IP 限制。
	rel1()
	if ok5, reason, _ := lim.Admit("u-conn", "203.0.113.3:50005", 3, 2); ok5 || !strings.Contains(reason, "同时在线 IP") {
		t.Fatalf("超最大 IP 数应拒绝: ok=%v reason=%q", ok5, reason)
	}
	// 释放全部后清零。
	rel2()
	rel3()
	snap := lim.SnapshotUser("u-conn", 3, 2)
	if snap.ActiveConnections != 0 || snap.ActiveIPs != 0 || snap.RejectedTotal != 2 {
		t.Fatalf("释放后统计异常: %+v", snap)
	}
}

// ======================== 2. 链式代理 CRUD、密文脱敏、环检测、TCP 探测、Xray/Clash/sing-box 输出 ========================

func TestProxyChainsCRUDCycleDetectionProbeAndSubscriptionExport(t *testing.T) {
	cfg := `{
		"public_host":"proxy.example.com",
		"vless_port":443,"reality_sni":"www.apple.com","reality_public_key":"PubKeyBase64","reality_short_id":"a1b2c3d4",
		"ss_port":18388,"ss_method":"2022-blake3-aes-128-gcm","ss_server_key":"c2VydmVya2V5MTIzNDU2Nw=="
	}`
	h, _ := newExtProxyHarness(t, cfg)

	// 启动一个本地 TCP listener 作为链式落地节点用于实测 TCP 探测。
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
	probePort := ln.Addr().(*net.TCPAddr).Port

	// 1. 拒绝云元数据 SSRF 地址。
	badSSRF := invokeProxy(t, h.srv, "chains.upsert", map[string]any{
		"id": "bad-ssrf", "name": "Metadata", "protocol": "socks5", "server": "169.254.169.254", "port": 80,
	})
	if badSSRF.GetError() == nil {
		t.Fatalf("应拒绝云元数据 SSRF 地址 169.254.169.254")
	}

	// 2. 创建第一跳与第二跳，确认凭据加密且脱敏不回显明文密码。
	c2Resp := invokeProxy(t, h.srv, "chains.upsert", map[string]any{
		"id": "hop-exit", "name": "最终家宽落地", "mode": "both", "protocol": "socks5",
		"server": "127.0.0.1", "port": probePort,
		"config": map[string]any{"username": "homeuser", "password": "SuperSecretPassword!"},
	})
	if c2Resp.GetError() != nil {
		t.Fatalf("chains.upsert hop-exit failed: %+v", c2Resp.GetError())
	}
	if strings.Contains(string(c2Resp.GetPayloadJson()), "SuperSecretPassword!") {
		t.Fatalf("chains.upsert 响应绝不能泄漏明文密码!")
	}

	c1Resp := invokeProxy(t, h.srv, "chains.upsert", map[string]any{
		"id": "hop-mid", "name": "中继跳板", "mode": "both", "protocol": "trojan",
		"server": "relay.example.com", "port": 8443,
		"next_hop_id": "hop-exit", "apply_default": true,
		"config": map[string]any{"password": "MidTrojanSecret", "sni": "relay.example.com", "tls": true},
	})
	if c1Resp.GetError() != nil {
		t.Fatalf("chains.upsert hop-mid failed: %+v", c1Resp.GetError())
	}

	// 3. 检测环路：让 hop-exit 指向 hop-mid 必须被拒绝！
	cycleResp := invokeProxy(t, h.srv, "chains.upsert", map[string]any{
		"id": "hop-exit", "name": "最终家宽落地", "mode": "both", "protocol": "socks5",
		"server": "127.0.0.1", "port": probePort, "next_hop_id": "hop-mid",
	})
	if cycleResp.GetError() == nil {
		t.Fatalf("环路引用 hop-exit -> hop-mid -> hop-exit 必须被拒绝")
	}

	// 4. 实时 TCP 延迟探测。
	probeResp := invokeProxy(t, h.srv, "chains.probe", map[string]any{"id": "hop-exit"})
	if probeResp.GetError() != nil {
		t.Fatalf("chains.probe failed: %+v", probeResp.GetError())
	}
	var probeOut struct {
		Reachable bool  `json:"reachable"`
		LatencyMS int64 `json:"latency_ms"`
	}
	if err := json.Unmarshal(probeResp.GetPayloadJson(), &probeOut); err != nil || !probeOut.Reachable {
		t.Fatalf("chains.probe 应探测到本地监听可达: %+v err=%v", probeOut, err)
	}

	// 5. 预览 Xray 服务端链式出口 JSON（含 proxySettings.tag 且不含明文密码）。
	prevResp := invokeProxy(t, h.srv, "chains.preview", map[string]any{})
	if prevResp.GetError() != nil {
		t.Fatalf("chains.preview failed: %+v", prevResp.GetError())
	}
	prevText := string(prevResp.GetPayloadJson())
	if !strings.Contains(prevText, "proxySettings") || !strings.Contains(prevText, "chain-hop-exit") {
		t.Fatalf("chains.preview 缺少 proxySettings 多跳链式配置:\n%s", prevText)
	}
	if strings.Contains(prevText, "SuperSecretPassword!") || strings.Contains(prevText, "MidTrojanSecret") {
		t.Fatalf("chains.preview 绝不能泄漏明文密码!")
	}

	// 6. 验证客户端订阅导出 Clash dialer-proxy 与 sing-box detour！
	if prog := runProxyJob(t, h.srv, "plans.upsert", map[string]any{"id": "std", "name": "标准"}, nil); prog.GetError() != nil {
		t.Fatal(prog.GetError())
	}
	uProg := runProxyJob(t, h.srv, "users.create", map[string]any{
		"id": "chain-user", "display_name": "ChainUser", "plan_id": "std", "chain_id": "hop-mid",
	}, nil)
	if uProg.GetError() != nil {
		t.Fatal(uProg.GetError())
	}
	var created struct {
		Token string `json:"subscription_token"`
	}
	_ = json.Unmarshal(uProg.GetResultJson(), &created)

	rc := &pb.RequestContext{InstanceId: "default", NodeId: "local", Locale: "zh-CN"}
	clashResp, err := h.srv.ServePublicRoute(t.Context(), &pb.ServePublicRouteRequest{
		Context: rc, Route: "sub", Method: "GET", Path: "/sub/" + created.Token, RawQuery: "format=clash",
	})
	if err != nil || clashResp.GetStatus() != 200 {
		t.Fatalf("Clash 链式订阅失败: status=%d err=%v", clashResp.GetStatus(), err)
	}
	clashText := string(clashResp.GetBody())
	if !strings.Contains(clashText, "dialer-proxy:") || !strings.Contains(clashText, "chain-中继跳板") || !strings.Contains(clashText, "chain-最终家宽落地") {
		t.Fatalf("Clash 订阅缺少 dialer-proxy 多跳链式落地节点:\n%s", clashText)
	}

	sbResp, err := h.srv.ServePublicRoute(t.Context(), &pb.ServePublicRouteRequest{
		Context: rc, Route: "sub", Method: "GET", Path: "/sub/" + created.Token, RawQuery: "format=singbox",
	})
	if err != nil || sbResp.GetStatus() != 200 {
		t.Fatalf("sing-box 链式订阅失败: status=%d err=%v", sbResp.GetStatus(), err)
	}
	sbText := string(sbResp.GetBody())
	if !strings.Contains(sbText, `"detour": "ChainUser-vless"`) || !strings.Contains(sbText, `"detour": "chain-中继跳板"`) {
		t.Fatalf("sing-box 订阅缺少多跳 detour 链式落地:\n%s", sbText)
	}

	// 7. 删除链式节点并验证删除成功。
	delResp := invokeProxy(t, h.srv, "chains.delete", map[string]any{"id": "hop-mid"})
	if delResp.GetError() != nil {
		t.Fatalf("chains.delete failed: %+v", delResp.GetError())
	}
}

// ======================== 3. TCP Brutal + Brutal Custom 选择性 TCP 接管与超发倍率手调 ========================

func TestBrutalSelectivePortTakeoverOversendAndLiveEcho(t *testing.T) {
	// 启动真实后端 TCP Echo 服务，模拟 Xray VLESS TCP 端口。
	backendLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer backendLn.Close()
	go func() {
		for {
			c, err := backendLn.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}(c)
		}
	}()
	vlessBackendPort := backendLn.Addr().(*net.TCPAddr).Port

	// 预先探测一个空闲端口作为 Brutal 对外透明接管端口。
	probeLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	brutalListenPort := probeLn.Addr().(*net.TCPAddr).Port
	_ = probeLn.Close()

	cfg := fmt.Sprintf(`{
		"public_host":"proxy.example.com",
		"vless_port":%d,"reality_sni":"www.apple.com","reality_public_key":"PubKeyBase64","reality_short_id":"a1b2c3d4",
		"ss_port":18388,"ss_method":"2022-blake3-aes-128-gcm","ss_server_key":"c2VydmVya2V5MTIzNDU2Nw=="
	}`, vlessBackendPort)
	h, _ := newExtProxyHarness(t, cfg)

	// 1. 验证 PlanOperation 对高超发倍率(>160%)给出告警。
	planPayload, _ := json.Marshal(map[string]any{
		"id": "brutal-vless", "inbound_tag": "vless-tcp", "protocol": "vless",
		"listen_port": brutalListenPort, "target_port": vlessBackendPort,
		"bandwidth_mbps": 100, "oversend_pct": 180, "cwnd_gain": 25, "enable_in_sub": true,
	})
	planResp, err := h.srv.PlanOperation(t.Context(), &pb.PlanOperationRequest{
		Context:     &pb.RequestContext{InstanceId: "default", NodeId: "local", Locale: "zh-CN"},
		Operation:   "brutal.binding.upsert",
		ApiVersion:  "v1",
		PayloadJson: planPayload,
	})
	if err != nil || planResp.GetError() != nil {
		t.Fatalf("PlanOperation brutal.binding.upsert failed: %v %+v", err, planResp.GetError())
	}
	hasHighWarn := false
	for _, w := range planResp.GetWarnings() {
		if w.GetCode() == "HIGH_OVERSEND" {
			hasHighWarn = true
		}
	}
	if !hasHighWarn {
		t.Fatalf("oversend_pct=180 应返回 HIGH_OVERSEND 警告，实际: %+v", planResp.GetWarnings())
	}

	// 2. 只为 vless-tcp 创建 Brutal 接管（默认超发 125% -> 125.0 Mbps），保持 ss2022-tcp 原端口不变！
	upResp := invokeProxy(t, h.srv, "brutal.binding.upsert", map[string]any{
		"id": "brutal-vless", "inbound_tag": "vless-tcp", "protocol": "vless",
		"listen_port": brutalListenPort, "target_port": vlessBackendPort,
		"bandwidth_mbps": 100, "enable_in_sub": true, "enabled": true,
	})
	if upResp.GetError() != nil {
		t.Fatalf("brutal.binding.upsert failed: %+v", upResp.GetError())
	}
	var upOut struct {
		Binding brutalBindingRecord `json:"binding"`
	}
	_ = json.Unmarshal(upResp.GetPayloadJson(), &upOut)
	if upOut.Binding.OversendPct != 125 || upOut.Binding.EffectiveMbps != 125.0 {
		t.Fatalf("默认超发倍率应为 125%% (125.0 Mbps)，实际: %+v", upOut.Binding)
	}

	// 3. 热调超发倍率至 150% -> 150.0 Mbps。
	hotResp := invokeProxy(t, h.srv, "brutal.binding.upsert", map[string]any{
		"id": "brutal-vless", "inbound_tag": "vless-tcp", "protocol": "vless",
		"listen_port": brutalListenPort, "target_port": vlessBackendPort,
		"bandwidth_mbps": 100, "oversend_pct": 150, "cwnd_gain": 25, "enable_in_sub": true, "enabled": true,
	})
	if hotResp.GetError() != nil {
		t.Fatalf("brutal hot update failed: %+v", hotResp.GetError())
	}
	_ = json.Unmarshal(hotResp.GetPayloadJson(), &upOut)
	if upOut.Binding.OversendPct != 150 || upOut.Binding.EffectiveMbps != 150.0 {
		t.Fatalf("手调超发倍率 150%% 未生效: %+v", upOut.Binding)
	}

	// 4. 应用并启动真实透明接管 TCP 端口，发起真实全双工 Echo 通信验证数据透传与遥测！
	appResp := invokeProxy(t, h.srv, "brutal.apply", map[string]any{})
	if appResp.GetError() != nil {
		t.Fatalf("brutal.apply failed: %+v", appResp.GetError())
	}
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", brutalListenPort), 2*time.Second)
	if err != nil {
		t.Fatalf("连接 Brutal 透明接管端口失败: %v", err)
	}
	msg := "hello-tcp-brutal-custom-150pct"
	if _, err := conn.Write([]byte(msg)); err != nil {
		t.Fatal(err)
	}
	_ = conn.(*net.TCPConn).CloseWrite()
	echoed, err := io.ReadAll(conn)
	_ = conn.Close()
	if err != nil || string(echoed) != msg {
		t.Fatalf("透明接管全双工转发内容不符: got %q want %q err=%v", string(echoed), msg, err)
	}

	// 等待接管 goroutine 刷新统计。
	time.Sleep(50 * time.Millisecond)
	stResp := invokeProxy(t, h.srv, "brutal.status", map[string]any{})
	if stResp.GetError() != nil {
		t.Fatalf("brutal.status failed: %+v", stResp.GetError())
	}
	var stOut struct {
		Env           brutalEnvInfo          `json:"env"`
		LiveListeners []brutalBindingMetrics `json:"live_listeners"`
	}
	_ = json.Unmarshal(stResp.GetPayloadJson(), &stOut)
	if len(stOut.LiveListeners) != 1 || stOut.LiveListeners[0].TotalConns < 1 || stOut.LiveListeners[0].BytesTX == 0 {
		t.Fatalf("Brutal 实时遥测异常: %+v", stOut.LiveListeners)
	}
	if stOut.Env.BrutalAvailable {
		if stOut.LiveListeners[0].BrutalAppliedConns < 1 {
			t.Fatalf("内核支持 brutal 时应记录 brutal_applied_conns >= 1: %+v", stOut.LiveListeners[0])
		}
	} else {
		if stOut.LiveListeners[0].FallbackConns < 1 {
			t.Fatalf("内核未加载 brutal 时应诚实记录 fallback_conns >= 1: %+v", stOut.LiveListeners[0])
		}
	}

	// 5. 验证订阅选择性切换：VLESS 切换至 brutalListenPort，而 SS2022 保持原 18388 不受影响！
	if prog := runProxyJob(t, h.srv, "plans.upsert", map[string]any{"id": "b-plan", "name": "B"}, nil); prog.GetError() != nil {
		t.Fatal(prog.GetError())
	}
	uProg := runProxyJob(t, h.srv, "users.create", map[string]any{
		"id": "b-user", "display_name": "BUser", "plan_id": "b-plan",
	}, nil)
	var created struct {
		Token string `json:"subscription_token"`
	}
	_ = json.Unmarshal(uProg.GetResultJson(), &created)
	rc := &pb.RequestContext{InstanceId: "default", NodeId: "local", Locale: "zh-CN"}
	v2Resp, err := h.srv.ServePublicRoute(t.Context(), &pb.ServePublicRouteRequest{
		Context: rc, Route: "sub", Method: "GET", Path: "/sub/" + created.Token, RawQuery: "format=v2ray",
	})
	if err != nil || v2Resp.GetStatus() != 200 {
		t.Fatalf("v2ray 订阅失败: status=%d err=%v", v2Resp.GetStatus(), err)
	}
	decoded, _ := base64.StdEncoding.DecodeString(string(v2Resp.GetBody()))
	subText := string(decoded)
	wantVLESS := fmt.Sprintf("@proxy.example.com:%d?", brutalListenPort)
	wantSS := "@proxy.example.com:18388#"
	if !strings.Contains(subText, wantVLESS) || !strings.Contains(subText, wantSS) {
		t.Fatalf("应仅切换 VLESS 至 Brutal 端口 %d 而保持 SS 原端口 18388:\n%s", brutalListenPort, subText)
	}
}

// ======================== 4. tcpfit 动态网络栈调优、1C1G 防 OOM 封顶、基线快照回滚与 iperf3 诚实探测 ========================

func TestTcpfitDynamicPlanOOMCapApplyRollbackAndIperf3Honesty(t *testing.T) {
	// 1. 直接单元测试 1C1G 内存防 OOM 封顶与无 Swap 建议。
	lowMemProfile := hostTuningProfile{
		OS: "linux", KernelVersion: "5.15.0", CPUs: 1, TotalRAMMB: 1024, SwapTotalMB: 0,
		CurrentSysctl: map[string]string{"net.ipv4.tcp_congestion_control": "cubic"},
	}
	lowPlan, err := computeTcpfitPlan(lowMemProfile, brutalEnvInfo{AvailableCC: []string{"cubic", "bbr"}}, tcpfitPlanRequest{
		Role: "proxy", BandwidthMbps: 10000, RTTMs: 300, MemBudgetPct: 12, PreferCC: "auto",
	})
	if err != nil {
		t.Fatalf("computeTcpfitPlan failed: %v", err)
	}
	// 10Gbps * 300ms BDP = 375 MiB，但 1C1G 下必须被安全预算封顶 <= 16 MiB 防止 OOM！
	if lowPlan.MaxBufferBytes > 16*1024*1024 {
		t.Fatalf("1C1G 主机单流缓冲应被防 OOM 封顶 <= 16MiB，实际 %d", lowPlan.MaxBufferBytes)
	}
	if lowPlan.SwapRecommendation == "" {
		t.Fatalf("1C1G 且 Swap=0 时应输出 Swap 建议")
	}
	if lowPlan.SelectedCC != "bbr" {
		t.Fatalf("可用 bbr 且 prefer=auto 时应选择 bbr，实际 %s", lowPlan.SelectedCC)
	}

	// 2. 通过真实 gRPC 测试 tuning.status / tuning.plan / PlanOperation / tuning.apply(dry_run + temp file) / tuning.rollback / tuning.sweep。
	h, sysctlFile := newExtProxyHarness(t, `{"public_host":"proxy.example.com"}`)

	stResp := invokeProxy(t, h.srv, "tuning.status", map[string]any{})
	if stResp.GetError() != nil {
		t.Fatalf("tuning.status failed: %+v", stResp.GetError())
	}

	planResp := invokeProxy(t, h.srv, "tuning.plan", map[string]any{
		"role": "proxy", "bandwidth_mbps": 500, "rtt_ms": 180, "mem_budget_pct": 12, "prefer_cc": "auto",
	})
	if planResp.GetError() != nil {
		t.Fatalf("tuning.plan failed: %+v", planResp.GetError())
	}
	var pRes tcpfitPlanResult
	if err := json.Unmarshal(planResp.GetPayloadJson(), &pRes); err != nil || !strings.Contains(pRes.RenderedConf, "net.core.rmem_max") {
		t.Fatalf("tuning.plan 输出异常: %+v err=%v", pRes, err)
	}

	// Dry-run 保存基线快照但不写宿主机文件。
	dryResp := invokeProxy(t, h.srv, "tuning.apply", map[string]any{
		"role": "proxy", "bandwidth_mbps": 500, "rtt_ms": 180, "dry_run": true,
	})
	if dryResp.GetError() != nil {
		t.Fatalf("tuning.apply dry_run failed: %+v", dryResp.GetError())
	}
	var dryOut struct {
		DryRun           bool                 `json:"dry_run"`
		BaselineSnapshot tuningSnapshotRecord `json:"baseline_snapshot"`
	}
	_ = json.Unmarshal(dryResp.GetPayloadJson(), &dryOut)
	if !dryOut.DryRun || dryOut.BaselineSnapshot.ID == "" {
		t.Fatalf("dry_run 应保存基线快照: %+v", dryOut)
	}
	if _, err := os.Stat(sysctlFile); err == nil {
		t.Fatalf("dry_run 不应落盘目标文件 %s", sysctlFile)
	}

	// 回滚到基线快照（dry_run=true 验证快照查询与渲染）。
	rbResp := invokeProxy(t, h.srv, "tuning.rollback", map[string]any{
		"snapshot_id": dryOut.BaselineSnapshot.ID,
		"dry_run":     true,
	})
	if rbResp.GetError() != nil {
		t.Fatalf("tuning.rollback failed: %+v", rbResp.GetError())
	}
	var rbOut struct {
		RolledBack   bool   `json:"rolled_back"`
		RenderedConf string `json:"rendered_conf"`
	}
	_ = json.Unmarshal(rbResp.GetPayloadJson(), &rbOut)
	if !rbOut.RolledBack || !strings.Contains(rbOut.RenderedConf, "tcpfit dynamic tuner") {
		t.Fatalf("tuning.rollback 输出异常: %+v", rbOut)
	}

	// 验证 renderSysctlConf 白名单过滤，阻止未授权键与注入换行写入宿主机配置。
	safeConf := renderSysctlConf("proxy", 100, 50, map[string]string{
		"net.core.rmem_max":      "4194304",
		"kernel.core_pattern":    "|/bin/evil",
		"net.core.default_qdisc": "fq\nkernel.panic = 1",
		"net.core.somaxconn":     "",
	})
	if strings.Contains(safeConf, "kernel.core_pattern") || strings.Contains(safeConf, "kernel.panic") || strings.Contains(safeConf, "somaxconn") {
		t.Fatalf("renderSysctlConf 未过滤非法 sysctl 键值:\n%s", safeConf)
	}

	// 验证 iperf3 sweep 参数注入拦截与诚实回报。
	badSweep := invokeProxy(t, h.srv, "tuning.sweep", map[string]any{"peer_host": "1.1.1.1; rm -rf /"})
	if badSweep.GetError() == nil {
		t.Fatalf("tuning.sweep 必须拦截非法命令注入 peer_host")
	}
	okSweep := invokeProxy(t, h.srv, "tuning.sweep", map[string]any{"peer_host": "127.0.0.1", "peer_port": 1, "duration_sec": 1})
	if okSweep.GetError() != nil {
		t.Fatalf("tuning.sweep 合法主机不应报系统异常: %+v", okSweep.GetError())
	}
}

func TestWARPRegisterConfigureAndCoreSync(t *testing.T) {
	// 1. 启动本地模拟 Cloudflare WARP 注册与 Trace 服务。
	var gotLicense string
	mockCF := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/reg":
			var req struct {
				Key string `json:"key"`
			}
			_ = json.NewDecoder(r.Body).Decode(&req)
			if len(req.Key) != 44 {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{
				"id": "warp-acct-001",
				"token": "tok-secret-12345",
				"config": {
					"client_id": "DAoV",
					"interface": {"addresses": {"v4": "172.16.0.2", "v6": "2606:4700:110:8a00::2"}},
					"peers": [{"public_key": "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=", "endpoint": {"host": "engage.cloudflareclient.com:2408"}}]
				}
			}`))
		case r.Method == http.MethodPut && r.URL.Path == "/reg/warp-acct-001/account":
			var req struct {
				License string `json:"license"`
			}
			_ = json.NewDecoder(r.Body).Decode(&req)
			gotLicense = req.License
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"account_type":"plus"}`))
		case r.Method == http.MethodGet && r.URL.Path == "/cdn-cgi/trace":
			_, _ = w.Write([]byte("ip=203.0.113.10\nloc=US\ncolo=SJC\nwarp=off\n"))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer mockCF.Close()

	prevAPI, prevTrace := warpAPIBaseOverride, warpTraceURLOverride
	warpAPIBaseOverride = mockCF.URL
	warpTraceURLOverride = mockCF.URL + "/cdn-cgi/trace"
	defer func() {
		warpAPIBaseOverride = prevAPI
		warpTraceURLOverride = prevTrace
	}()

	h, _ := newExtProxyHarness(t, `{"vless_port":443,"hy2_port":8443,"ss_port":9443}`)

	// 2. 一键注册 Cloudflare WARP（带 WARP+ License 并绑定入站端口）。
	regResp := invokeProxy(t, h.srv, "warp.register", map[string]any{
		"license_key":       "ABCD-1234-EFGH-5678-IJKL",
		"routing_mode":      "bound_ports",
		"bound_profile_ids": []string{"vless-main", "hy2-main"},
		"sync_core":         false,
	})
	if regResp.GetError() != nil {
		t.Fatalf("warp.register failed: %+v", regResp.GetError())
	}
	if gotLicense != "ABCD-1234-EFGH-5678-IJKL" {
		t.Fatalf("license not sent to Cloudflare mock: %q", gotLicense)
	}
	regPayload := string(regResp.GetPayloadJson())
	if strings.Contains(regPayload, "tok-secret-12345") || strings.Contains(regPayload, "ABCD-1234-EFGH-5678-IJKL") {
		t.Fatalf("warp.register response leaked secret token or license key!")
	}

	// 3. 查询 warp.status：验证 client_id -> reserved 解码正确，且私钥永不明文返回。
	stResp := invokeProxy(t, h.srv, "warp.status", map[string]any{})
	if stResp.GetError() != nil {
		t.Fatalf("warp.status failed: %+v", stResp.GetError())
	}
	var stOut struct {
		WARP     warpRecord            `json:"warp"`
		Inbounds []xrayInboundPortInfo `json:"inbounds"`
	}
	if err := json.Unmarshal(stResp.GetPayloadJson(), &stOut); err != nil {
		t.Fatal(err)
	}
	if !stOut.WARP.Registered || !stOut.WARP.Enabled || stOut.WARP.AccountType != "plus" || !stOut.WARP.HasPrivateKey {
		t.Fatalf("unexpected warp status: %+v", stOut.WARP)
	}
	// base64("DAoV") = [12, 10, 21]
	if len(stOut.WARP.Reserved) != 3 || stOut.WARP.Reserved[0] != 12 || stOut.WARP.Reserved[1] != 10 || stOut.WARP.Reserved[2] != 21 {
		t.Fatalf("reserved decode mismatch: %v", stOut.WARP.Reserved)
	}
	if len(stOut.Inbounds) < 2 {
		t.Fatalf("expected discovered inbound ports, got %+v", stOut.Inbounds)
	}

	// 4. 修改绑定为解锁域名模式，并验证合并 core.xray 配置生成完整 warp 段。
	cfgResp := invokeProxy(t, h.srv, "warp.configure", map[string]any{
		"routing_mode":      "domains",
		"bound_profile_ids": []string{"vless-main"},
		"domains":           []string{"openai.com", "netflix.com"},
		"sync_core":         false,
	})
	if cfgResp.GetError() != nil {
		t.Fatalf("warp.configure failed: %+v", cfgResp.GetError())
	}
	stInspect, err := openStore(h.dataDir, nil)
	if err != nil {
		t.Fatalf("openStore: %v", err)
	}
	defer stInspect.Close()

	savedWARP, err := stInspect.GetWARP(t.Context())
	if err != nil || savedWARP == nil || savedWARP.PrivateKey == "" {
		t.Fatalf("GetWARP decrypted private key missing: %v", err)
	}
	// 确保 warp.status 从未泄漏私钥明文
	if strings.Contains(string(stResp.GetPayloadJson()), savedWARP.PrivateKey) {
		t.Fatalf("warp.status leaked plaintext WireGuard private key!")
	}

	redactedXray := []byte(`{
		"schema_version":"2",
		"enabled":true,
		"outbound":{"type":"direct"},
		"profiles":[
			{"id":"vless-main","enabled":true,"listen":"0.0.0.0","port":443,"protocol":"vless","users":[{"id":"u1","uuid":{"$secret_present":true}}],"vless":{"transport":"raw","flow":"xtls-rprx-vision","security":{"mode":"reality","target":"example.com:443","server_names":["example.com"],"private_key":{"$secret_present":true},"short_ids":["1234"]}}}
		]
	}`)
	merged, err := mergeCoreXrayConfigWithWARP(redactedXray, []userRecord{{ID: "u1", VLESSUUID: "11111111-1111-1111-1111-111111111111", Status: "active"}}, savedWARP, true)
	if err != nil {
		t.Fatalf("mergeCoreXrayConfigWithWARP failed: %v", err)
	}
	var mergedDoc map[string]any
	if err := json.Unmarshal(merged, &mergedDoc); err != nil {
		t.Fatal(err)
	}
	warpSec, ok := mergedDoc["warp"].(map[string]any)
	if !ok || warpSec["enabled"] != true || warpSec["routing_mode"] != "domains" || warpSec["private_key"] != savedWARP.PrivateKey {
		t.Fatalf("merged core.xray warp section mismatch: %+v", warpSec)
	}

	// 5. 注销清除 WARP。
	delResp := invokeProxy(t, h.srv, "warp.delete", map[string]any{})
	if delResp.GetError() != nil {
		t.Fatalf("warp.delete failed: %+v", delResp.GetError())
	}
	afterDel, err := stInspect.GetWARP(t.Context())
	if err != nil || afterDel != nil {
		t.Fatalf("WARP record should be deleted: %+v, err=%v", afterDel, err)
	}
}
