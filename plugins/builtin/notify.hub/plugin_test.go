// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bufio"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc"

	pb "github.com/qwq-panel/qwq/sdk/gen/qwq/platform/v1"
	"github.com/qwq-panel/qwq/sdk/pluginsdk"
)

func startNotifyTestServer(t *testing.T, p *Plugin, cfgJSON []byte) *pluginsdk.Server {
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
		InstanceHandle: "notify-hub-test",
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

func invokeNotify(t *testing.T, srv *pluginsdk.Server, op string, req any) map[string]any {
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
	if resp.GetError() != nil {
		t.Fatalf("invoke %s business error: %+v", op, resp.GetError())
	}
	var out map[string]any
	if err := json.Unmarshal(resp.GetPayloadJson(), &out); err != nil {
		t.Fatalf("unmarshal %s: %v", op, err)
	}
	return out
}

func TestNotifyHubEndToEndRoutingQuietCooldownAndHMAC(t *testing.T) {
	var mu sync.Mutex
	var lastWebhookSig string
	var lastWebhookTS string
	var lastWebhookBody []byte
	var feishuSigned atomic.Bool
	var dingSigned atomic.Bool
	var tgReceived atomic.Bool

	httpSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		switch {
		case strings.HasPrefix(r.URL.Path, "/bot"):
			tgReceived.Store(true)
		case r.URL.Path == "/feishu":
			var m map[string]any
			if json.Unmarshal(body, &m) == nil && m["sign"] != "" && m["timestamp"] != "" {
				feishuSigned.Store(true)
			}
		case r.URL.Path == "/dingtalk":
			if r.URL.Query().Get("sign") != "" && r.URL.Query().Get("timestamp") != "" {
				dingSigned.Store(true)
			}
		case r.URL.Path == "/webhook":
			mu.Lock()
			lastWebhookSig = r.Header.Get("X-QWQ-Notify-Signature")
			lastWebhookTS = r.Header.Get("X-QWQ-Notify-Timestamp")
			lastWebhookBody = append([]byte(nil), body...)
			mu.Unlock()
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer httpSrv.Close()

	var clockMu sync.Mutex
	now := time.Date(2026, 11, 22, 14, 0, 0, 0, time.UTC) // 22:00 Asia/Shanghai
	p := &Plugin{now: func() time.Time {
		clockMu.Lock()
		defer clockMu.Unlock()
		return now
	}}
	srv := startNotifyTestServer(t, p, []byte(`{"allow_private_endpoints":true,"http_timeout_seconds":5}`))

	// 1. 注册 4 类真实通道并验证响应不泄露明文密钥
	chTG := invokeNotify(t, srv, "notify.channel.upsert", map[string]any{
		"name": "ops-tg", "kind": "telegram",
		"config": map[string]any{"bot_token": "tok_secret_123", "chat_id": "-1009988", "api_base": httpSrv.URL},
	})
	chTGID := chTG["channel"].(map[string]any)["id"].(string)
	rawTG, _ := json.Marshal(chTG)
	if strings.Contains(string(rawTG), "tok_secret_123") {
		t.Fatalf("plaintext bot token leaked in channel response: %s", rawTG)
	}

	chFS := invokeNotify(t, srv, "notify.channel.upsert", map[string]any{
		"name": "ops-feishu", "kind": "feishu",
		"config": map[string]any{"webhook_url": httpSrv.URL + "/feishu", "secret": "fs_sec"},
	})
	chFSID := chFS["channel"].(map[string]any)["id"].(string)

	chDT := invokeNotify(t, srv, "notify.channel.upsert", map[string]any{
		"name": "ops-ding", "kind": "dingtalk",
		"config": map[string]any{"webhook_url": httpSrv.URL + "/dingtalk", "secret": "dt_sec"},
	})
	chDTID := chDT["channel"].(map[string]any)["id"].(string)

	chWH := invokeNotify(t, srv, "notify.channel.upsert", map[string]any{
		"name": "ops-wh", "kind": "webhook",
		"config": map[string]any{"webhook_url": httpSrv.URL + "/webhook", "secret": "wh_hmac_key"},
	})
	chWHID := chWH["channel"].(map[string]any)["id"].(string)

	// 2. 测试连通性测试操作
	testRes := invokeNotify(t, srv, "notify.channel.test", map[string]any{"id": chTGID})
	if testRes["ok"] != true || !tgReceived.Load() {
		t.Fatalf("telegram channel test failed: %+v", testRes)
	}

	// 3. 创建带冷却与跨午夜静默时段（23:00-07:30 Asia/Shanghai）的路由规则
	invokeNotify(t, srv, "notify.rule.upsert", map[string]any{
		"name":                  "probe-alerts",
		"source_pattern":        "server.*",
		"min_severity":          "warn",
		"channel_ids":           []string{chFSID, chDTID, chWHID},
		"cooldown_sec":          300,
		"quiet_start":           "23:00",
		"quiet_end":             "07:30",
		"quiet_tz":              "Asia/Shanghai",
		"allow_critical_bypass": true,
	})

	// 4. 22:00（非静默窗口）首次 warn 告警应命中全部 3 渠道并验证 HMAC 签名
	d1 := invokeNotify(t, srv, "notify.dispatch", map[string]any{
		"source": "server.probe", "severity": "warn",
		"title": "hk-01 离线", "message": "连续 3 次心跳超时", "dedup_key": "hk-01-down",
	})
	if int(d1["sent"].(float64)) != 3 || !feishuSigned.Load() || !dingSigned.Load() {
		t.Fatalf("expected 3 signed deliveries, got %+v", d1)
	}
	mu.Lock()
	mac := hmac.New(sha256.New, []byte("wh_hmac_key"))
	_, _ = mac.Write([]byte(lastWebhookTS + "."))
	_, _ = mac.Write(lastWebhookBody)
	wantSig := "sha256=" + hex.EncodeToString(mac.Sum(nil))
	gotSig := lastWebhookSig
	mu.Unlock()
	if gotSig != wantSig {
		t.Fatalf("webhook HMAC mismatch: got %q want %q", gotSig, wantSig)
	}

	// 5. 10 秒后同一 dedup_key 重复发送应全部被冷却抑制
	clockMu.Lock()
	now = now.Add(10 * time.Second)
	clockMu.Unlock()
	d2 := invokeNotify(t, srv, "notify.dispatch", map[string]any{
		"source": "server.probe", "severity": "warn",
		"title": "hk-01 离线", "message": "重复告警", "dedup_key": "hk-01-down",
	})
	if int(d2["suppressed"].(float64)) != 3 || int(d2["sent"].(float64)) != 0 {
		t.Fatalf("expected cooldown suppression of 3, got %+v", d2)
	}

	// 6. 23:30 Asia/Shanghai（跨午夜静默窗口内）：warn 被静默抑制，critical 穿透静默
	clockMu.Lock()
	now = time.Date(2026, 11, 22, 15, 30, 0, 0, time.UTC)
	clockMu.Unlock()
	d3 := invokeNotify(t, srv, "notify.dispatch", map[string]any{
		"source": "server.probe", "severity": "warn",
		"title": "磁盘 85%", "dedup_key": "disk-warn",
	})
	if int(d3["suppressed"].(float64)) != 3 || int(d3["sent"].(float64)) != 0 {
		t.Fatalf("expected quiet-window suppression of warn, got %+v", d3)
	}
	d4 := invokeNotify(t, srv, "notify.dispatch", map[string]any{
		"source": "server.probe", "severity": "critical",
		"title": "核心节点宕机", "dedup_key": "node-crit",
	})
	if int(d4["sent"].(float64)) != 3 {
		t.Fatalf("expected critical to bypass quiet window, got %+v", d4)
	}

	// 7. AI 紧凑摘要与微件均返回合法数据
	digest := invokeNotify(t, srv, "notify.ai.digest", map[string]any{})
	if int(digest["channels_enabled"].(float64)) != 4 || int(digest["sent_24h"].(float64)) < 7 {
		t.Fatalf("unexpected ai digest: %+v", digest)
	}
	stat := invokeNotify(t, srv, "notify.stat.summary", map[string]any{})
	if stat["status"] != "ok" {
		t.Fatalf("unexpected stat: %+v", stat)
	}
}

func TestNotifyHubSSRFBlocksLoopbackByDefault(t *testing.T) {
	httpSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer httpSrv.Close()

	// 默认 allow_private_endpoints=false 必须拦截回环地址
	srv := startNotifyTestServer(t, New(), []byte(`{}`))
	out := invokeNotify(t, srv, "notify.channel.upsert", map[string]any{
		"name": "local-ssrf", "kind": "webhook",
		"config": map[string]any{"webhook_url": httpSrv.URL + "/hook"},
	})
	chID := out["channel"].(map[string]any)["id"].(string)

	tOut := invokeNotify(t, srv, "notify.channel.test", map[string]any{"id": chID})
	if tOut["ok"] != false || !strings.Contains(tOut["error"].(string), "egress blocked") {
		t.Fatalf("expected SSRF egress block on loopback, got %+v", tOut)
	}

	// 验证 Telegram 投递失败时，*url.Error 绝不将 Bot Token 泄漏到错误返回或投递审计表
	const sensitiveToken = "99887766:AAH_SECRET_BOT_TOKEN_DO_NOT_LEAK"
	tgCh := invokeNotify(t, srv, "notify.channel.upsert", map[string]any{
		"name": "tg-ssrf", "kind": "telegram",
		"config": map[string]any{"bot_token": sensitiveToken, "chat_id": "12345", "api_base": httpSrv.URL},
	})
	tgID := tgCh["channel"].(map[string]any)["id"].(string)
	tgTest := invokeNotify(t, srv, "notify.channel.test", map[string]any{"id": tgID})
	if tgTest["ok"] != false {
		t.Fatalf("expected telegram loopback test to be blocked by SSRF guard")
	}
	if strings.Contains(tgTest["error"].(string), sensitiveToken) {
		t.Fatalf("P1 secret leak: Telegram bot token appeared in error message: %s", tgTest["error"])
	}
	ovRaw, _ := json.Marshal(invokeNotify(t, srv, "notify.overview", map[string]any{}))
	if strings.Contains(string(ovRaw), sensitiveToken) {
		t.Fatalf("P1 secret leak: Telegram bot token persisted in overview/deliveries: %s", ovRaw)
	}
}

func startNotifyTestServerAtDir(t *testing.T, p *Plugin, dataDir string, cfgJSON []byte) *pluginsdk.Server {
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
	rc := &pb.RequestContext{InstanceId: "default", NodeId: "local", Locale: "zh-CN"}
	if _, err := srv.Initialize(t.Context(), &pb.InitializeRequest{
		Context:        rc,
		InstanceHandle: "notify-hub-test",
		DataDir:        dataDir,
		ConfigJson:     cfgJSON,
		ConfigRevision: "1",
	}); err != nil {
		srv.Close()
		t.Fatalf("Initialize: %v", err)
	}
	if _, err := srv.Start(t.Context(), &pb.StartRequest{Context: rc}); err != nil {
		srv.Close()
		t.Fatalf("Start: %v", err)
	}
	if _, err := srv.Activate(t.Context(), &pb.ActivateRequest{Context: rc}); err != nil {
		srv.Close()
		t.Fatalf("Activate: %v", err)
	}
	return srv
}

func TestNotifyHubMultiRuleCooldownDoesNotBlockOtherRule(t *testing.T) {
	var hits atomic.Int32
	httpSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer httpSrv.Close()

	var clockMu sync.Mutex
	now := time.Date(2026, 11, 22, 10, 0, 0, 0, time.UTC)
	p := &Plugin{now: func() time.Time {
		clockMu.Lock()
		defer clockMu.Unlock()
		return now
	}}
	srv := startNotifyTestServer(t, p, []byte(`{"allow_private_endpoints":true,"http_timeout_seconds":5}`))

	chRes := invokeNotify(t, srv, "notify.channel.upsert", map[string]any{
		"name": "shared-wh", "kind": "webhook",
		"config": map[string]any{"webhook_url": httpSrv.URL + "/hook"},
	})
	chID := chRes["channel"].(map[string]any)["id"].(string)

	// 规则 B（无冷却，仅匹配 critical），先创建（ORDER BY created_at DESC 排在后）
	invokeNotify(t, srv, "notify.rule.upsert", map[string]any{
		"name": "crit-direct", "source_pattern": "*", "min_severity": "critical",
		"channel_ids": []string{chID}, "cooldown_sec": 0,
	})
	clockMu.Lock()
	now = now.Add(2 * time.Second)
	clockMu.Unlock()
	// 规则 A（带 300s 冷却，匹配 warn 及以上），后创建（ORDER BY created_at DESC 排在前）
	invokeNotify(t, srv, "notify.rule.upsert", map[string]any{
		"name": "warn-cooldown", "source_pattern": "*", "min_severity": "warn",
		"channel_ids": []string{chID}, "cooldown_sec": 300,
	})

	// 首次 warn 告警命中规则 A 并进入 300s 冷却。
	d1 := invokeNotify(t, srv, "notify.dispatch", map[string]any{
		"source": "security.basic", "severity": "warn",
		"title": "SSH 异常", "dedup_key": "ssh-evt",
	})
	if int(d1["sent"].(float64)) != 1 || hits.Load() != 1 {
		t.Fatalf("expected initial warn send=1, got %+v hits=%d", d1, hits.Load())
	}

	// 10s 后升级为 critical 告警且同 dedup_key：
	// 规则 A 处于冷却抑制，但绝不能通过 seenCh 误杀排在后面的无冷却规则 B！
	clockMu.Lock()
	now = now.Add(10 * time.Second)
	clockMu.Unlock()
	d2 := invokeNotify(t, srv, "notify.dispatch", map[string]any{
		"source": "security.basic", "severity": "critical",
		"title": "SSH 严重入侵", "dedup_key": "ssh-evt",
	})
	if int(d2["sent"].(float64)) != 1 || hits.Load() != 2 {
		t.Fatalf("suppressed rule A must not block rule B delivery, got %+v hits=%d", d2, hits.Load())
	}
}

func TestNotifyHubPersistentCooldownSurvivesRestart(t *testing.T) {
	var hits atomic.Int32
	httpSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer httpSrv.Close()

	dataDir := t.TempDir()
	now := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)

	// 实例 1：创建渠道、规则并派发首次事件，写入 SQLite 冷却记录。
	p1 := &Plugin{now: func() time.Time { return now }}
	srv1 := startNotifyTestServerAtDir(t, p1, dataDir, []byte(`{"allow_private_endpoints":true,"http_timeout_seconds":5}`))
	chRes := invokeNotify(t, srv1, "notify.channel.upsert", map[string]any{
		"name": "persist-wh", "kind": "webhook",
		"config": map[string]any{"webhook_url": httpSrv.URL + "/hook"},
	})
	chID := chRes["channel"].(map[string]any)["id"].(string)
	invokeNotify(t, srv1, "notify.rule.upsert", map[string]any{
		"name": "persist-rule", "source_pattern": "*", "min_severity": "warn",
		"channel_ids": []string{chID}, "cooldown_sec": 600,
	})
	d1 := invokeNotify(t, srv1, "notify.dispatch", map[string]any{
		"source": "monitor.basic", "severity": "warn", "title": "CPU 高", "dedup_key": "cpu-high",
	})
	if int(d1["sent"].(float64)) != 1 {
		t.Fatalf("first dispatch expected sent=1, got %+v", d1)
	}
	_, _ = srv1.Deactivate(t.Context(), &pb.DeactivateRequest{Context: &pb.RequestContext{InstanceId: "default", NodeId: "local", Locale: "zh-CN"}})
	srv1.Close() // 模拟 180s on_demand 空闲休眠进程退出

	// 实例 2：200 秒后重新唤醒并打开同一 DataDir，冷却窗口（600s）必须依然生效。
	now2 := now.Add(200 * time.Second)
	p2 := &Plugin{now: func() time.Time { return now2 }}
	srv2 := startNotifyTestServerAtDir(t, p2, dataDir, []byte(`{"allow_private_endpoints":true,"http_timeout_seconds":5}`))
	defer srv2.Close()

	d2 := invokeNotify(t, srv2, "notify.dispatch", map[string]any{
		"source": "monitor.basic", "severity": "warn", "title": "CPU 高", "dedup_key": "cpu-high",
	})
	if int(d2["sent"].(float64)) != 0 || int(d2["suppressed"].(float64)) != 1 || hits.Load() != 1 {
		t.Fatalf("expected persisted cooldown suppression after restart, got %+v hits=%d", d2, hits.Load())
	}
}

func TestNotifyHubMetadataSSRFBlockedEvenWithAllowPrivate(t *testing.T) {
	for _, rawIP := range []string{"169.254.169.254", "169.254.0.1", "100.100.100.200", "fe80::1", "fd00:ec2::254"} {
		addr := netip.MustParseAddr(rawIP)
		if !isAlwaysBlockedMetadataIP(addr) {
			t.Fatalf("expected metadata/link-local IP %s to be unconditionally blocked", rawIP)
		}
	}
	// 普通企业内网地址不应被元数据守卫误杀
	for _, rawIP := range []string{"10.0.0.5", "192.168.1.10", "172.16.0.2"} {
		addr := netip.MustParseAddr(rawIP)
		if isAlwaysBlockedMetadataIP(addr) {
			t.Fatalf("private LAN IP %s must not be blocked by metadata guard when allowPrivate=true", rawIP)
		}
	}

	// 验证 allow_private_endpoints=true 时 HTTP 客户端与 SMTP 拨号器均硬拒绝云元数据地址。
	client := newSafeHTTPClient(true, 2*time.Second)
	for _, target := range []string{"http://169.254.169.254/latest/meta-data/", "http://100.100.100.200/latest/meta-data/"} {
		out := postJSON(t.Context(), client, target, map[string]string{"k": "v"}, nil)
		if out.Err == nil || !strings.Contains(out.Err.Error(), "cloud metadata or link-local") {
			t.Fatalf("expected HTTP metadata SSRF block for %s, got %+v", target, out)
		}
	}

	for _, smtpHost := range []string{"169.254.169.254", "100.100.100.200", "fd00:ec2::254"} {
		out := sendSMTP(t.Context(), true, 2*time.Second, ChannelConfig{
			SMTPHost: smtpHost,
			SMTPPort: 25,
			SMTPFrom: "ops@example.com",
			SMTPTo:   []string{"admin@example.com"},
		}, NotifyEvent{Title: "test", Severity: "warn", Source: "notify.hub", Timestamp: time.Now()})
		if out.Err == nil || !strings.Contains(out.Err.Error(), "cloud metadata or link-local") {
			t.Fatalf("expected SMTP metadata SSRF block for %s, got %+v", smtpHost, out)
		}
	}
}

func TestNotifyHubSMTPRFC2047SubjectAndDeadline(t *testing.T) {
	// 1. 单元测试 RFC 2047 UTF-8 Base64 编码
	encoded := encodeRFC2047Subject("[WARN] 磁盘空间告警\r\n注入防御")
	if !strings.HasPrefix(encoded, "=?UTF-8?B?") || !strings.HasSuffix(encoded, "?=") || strings.ContainsAny(encoded, "\r\n") {
		t.Fatalf("invalid RFC 2047 subject: %q", encoded)
	}
	inner := strings.TrimSuffix(strings.TrimPrefix(encoded, "=?UTF-8?B?"), "?=")
	decoded, err := base64.StdEncoding.DecodeString(inner)
	if err != nil || string(decoded) != "[WARN] 磁盘空间告警 注入防御" {
		t.Fatalf("unexpected decoded subject: %q err=%v", string(decoded), err)
	}

	// 2. 真实回环最小 SMTP 服务器验证发送出的 Subject 为 RFC 2047 编码
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	var receivedData strings.Builder
	var dataMu sync.Mutex
	doneCh := make(chan struct{})
	go func() {
		defer close(doneCh)
		conn, aErr := ln.Accept()
		if aErr != nil {
			return
		}
		defer conn.Close()
		_, _ = io.WriteString(conn, "220 mock.local ESMTP\r\n")
		sc := bufio.NewScanner(conn)
		inData := false
		for sc.Scan() {
			line := sc.Text()
			if inData {
				if line == "." {
					inData = false
					_, _ = io.WriteString(conn, "250 OK\r\n")
					continue
				}
				dataMu.Lock()
				receivedData.WriteString(line + "\n")
				dataMu.Unlock()
				continue
			}
			upper := strings.ToUpper(line)
			switch {
			case strings.HasPrefix(upper, "EHLO"), strings.HasPrefix(upper, "HELO"):
				_, _ = io.WriteString(conn, "250 mock.local\r\n")
			case strings.HasPrefix(upper, "MAIL FROM:"), strings.HasPrefix(upper, "RCPT TO:"):
				_, _ = io.WriteString(conn, "250 OK\r\n")
			case upper == "DATA":
				inData = true
				_, _ = io.WriteString(conn, "354 End data with <CR><LF>.<CR><LF>\r\n")
			case upper == "QUIT":
				_, _ = io.WriteString(conn, "221 Bye\r\n")
				return
			default:
				_, _ = io.WriteString(conn, "250 OK\r\n")
			}
		}
	}()

	_, portStr, _ := net.SplitHostPort(ln.Addr().String())
	portNum, _ := strconv.Atoi(portStr)
	out := sendSMTP(t.Context(), true, 3*time.Second, ChannelConfig{
		SMTPHost: "127.0.0.1",
		SMTPPort: portNum,
		SMTPFrom: "alerts@example.com",
		SMTPTo:   []string{"ops@example.com"},
	}, NotifyEvent{
		Source:    "security.basic",
		Severity:  "critical",
		Title:     "SSH 暴力破解自动封禁通知",
		Message:   "已封禁来源 IP 198.51.100.10",
		Timestamp: time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC),
	})
	if out.Err != nil || out.HTTPStatus != 250 {
		t.Fatalf("mock SMTP send failed: %+v", out)
	}
	<-doneCh
	dataMu.Lock()
	body := receivedData.String()
	dataMu.Unlock()
	wantSubj := "Subject: " + encodeRFC2047Subject("[CRITICAL] SSH 暴力破解自动封禁通知")
	if !strings.Contains(body, wantSubj) {
		t.Fatalf("SMTP payload missing RFC 2047 subject %q, got:\n%s", wantSubj, body)
	}

	// 3. 验证挂起无响应的 SMTP 服务器会因 conn.SetDeadline 在有界时间内退出而不是永久阻塞
	stallLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer stallLn.Close()
	stallStop := make(chan struct{})
	defer close(stallStop)
	go func() {
		if c, err := stallLn.Accept(); err == nil {
			defer c.Close()
			select {
			case <-stallStop:
			case <-time.After(2 * time.Second):
			}
		}
	}()
	_, stallPortStr, _ := net.SplitHostPort(stallLn.Addr().String())
	stallPort, _ := strconv.Atoi(stallPortStr)
	start := time.Now()
	stallOut := sendSMTP(t.Context(), true, 250*time.Millisecond, ChannelConfig{
		SMTPHost: "127.0.0.1",
		SMTPPort: stallPort,
		SMTPFrom: "alerts@example.com",
		SMTPTo:   []string{"ops@example.com"},
	}, NotifyEvent{Title: "timeout-check", Severity: "info", Source: "notify.hub", Timestamp: time.Now()})
	if stallOut.Err == nil || time.Since(start) > 1500*time.Millisecond {
		t.Fatalf("expected bounded SMTP deadline error, got err=%v elapsed=%v", stallOut.Err, time.Since(start))
	}
}
