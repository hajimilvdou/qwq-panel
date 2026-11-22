// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
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
