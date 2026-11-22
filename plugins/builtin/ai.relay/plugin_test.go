// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"

	pb "github.com/qwq-panel/qwq/sdk/gen/qwq/platform/v1"
	"github.com/qwq-panel/qwq/sdk/manifest"
	"github.com/qwq-panel/qwq/sdk/pluginsdk"
)

// ======================== 测试夹具与调用辅助 ========================

type captureJobStream struct {
	ctx      context.Context
	messages []*pb.RunJobResponse
}

func (s *captureJobStream) Send(msg *pb.RunJobResponse) error {
	s.messages = append(s.messages, msg)
	return nil
}
func (s *captureJobStream) SetHeader(metadata.MD) error  { return nil }
func (s *captureJobStream) SendHeader(metadata.MD) error { return nil }
func (s *captureJobStream) SetTrailer(metadata.MD)       {}
func (s *captureJobStream) Context() context.Context     { return s.ctx }
func (s *captureJobStream) SendMsg(any) error            { return nil }
func (s *captureJobStream) RecvMsg(any) error            { return nil }

func invokeRelay(t *testing.T, srv *pluginsdk.Server, op string, payload any) *pb.InvokeResponse {
	t.Helper()
	var raw []byte
	if payload != nil {
		var err error
		raw, err = json.Marshal(payload)
		if err != nil {
			t.Fatal(err)
		}
	}
	resp, err := srv.Invoke(t.Context(), &pb.InvokeRequest{
		Context:     &pb.RequestContext{InstanceId: "default", NodeId: "local", OperationId: "inv-" + op, Locale: "zh-CN"},
		Operation:   op,
		ApiVersion:  "v1",
		PayloadJson: raw,
	})
	if err != nil {
		t.Fatalf("Invoke(%s) 传输错误: %v", op, err)
	}
	if resp.GetError() != nil {
		t.Fatalf("Invoke(%s) 业务错误: %+v", op, resp.GetError())
	}
	return resp
}

func runRelayJob(t *testing.T, srv *pluginsdk.Server, op string, payload any) *pb.JobProgress {
	t.Helper()
	var raw []byte
	if payload != nil {
		var err error
		raw, err = json.Marshal(payload)
		if err != nil {
			t.Fatal(err)
		}
	}
	stream := &captureJobStream{ctx: t.Context()}
	if err := srv.RunJob(&pb.RunJobRequest{
		Context:     &pb.RequestContext{InstanceId: "default", NodeId: "local", OperationId: "job-" + op, Locale: "zh-CN"},
		Operation:   op,
		ApiVersion:  "v1",
		PayloadJson: raw,
	}, stream); err != nil {
		t.Fatalf("RunJob(%s) 传输错误: %v", op, err)
	}
	if len(stream.messages) == 0 || stream.messages[len(stream.messages)-1].GetProgress() == nil {
		t.Fatalf("RunJob(%s) 缺少终态进度消息", op)
	}
	prog := stream.messages[len(stream.messages)-1].GetProgress()
	if prog.GetError() != nil {
		t.Fatalf("RunJob(%s) 业务错误: %+v", op, prog.GetError())
	}
	return prog
}

// ======================== 清单与全量文件 SHA-256 验证 ========================

func TestAIRelayManifestAndPackageDigests(t *testing.T) {
	parsed, err := manifest.Parse(Manifest())
	if err != nil {
		t.Fatalf("manifest.Parse 失败: %v", err)
	}
	if parsed.ID != "ai.relay" || parsed.Placement != "node" || parsed.Lifecycle.Startup != "eager" ||
		!parsed.Lifecycle.Background || parsed.Lifecycle.UpdateStrategy != "restart" || parsed.Lifecycle.EffectiveOverlapSafe() {
		t.Fatalf("manifest 生命周期或定位不符: id=%s placement=%s lifecycle=%+v", parsed.ID, parsed.Placement, parsed.Lifecycle)
	}
	if parsed.Resources.MemoryMaxMB != 64 || parsed.Resources.CPUQuotaPercent != 50 ||
		parsed.Resources.PIDsMax != 64 || parsed.Resources.FDsMax != 512 ||
		parsed.Resources.DiskMaxMB != 256 || parsed.Resources.KVMaxKB != 512 {
		t.Fatalf("1C1G 资源预算不符: %+v", parsed.Resources)
	}
	if len(parsed.Operations) != 12 {
		t.Fatalf("管理操作数量=%d，期望=12", len(parsed.Operations))
	}

	for relPath, wantDigest := range parsed.Files {
		if relPath == "bin/plugin" {
			continue
		}
		raw, err := os.ReadFile(relPath)
		if err != nil {
			t.Fatalf("读取清单声明文件 %s 失败: %v", relPath, err)
		}
		sum := sha256.Sum256(raw)
		gotDigest := "sha256:" + hex.EncodeToString(sum[:])
		if gotDigest != wantDigest {
			t.Fatalf("文件 %s SHA-256 摘要不匹配: got %s want %s", relPath, gotDigest, wantDigest)
		}
	}
}

// ======================== 12 项管理操作、门户自服务、鉴权隔离与端到端 SSE 中转测试 ========================

func TestAIRelayAll12OperationsPortalAndPublicRouteE2E(t *testing.T) {
	const upstreamSecret = "sk-ant-mock-secret-value-xyz"

	mockAnthropic := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/messages" {
			http.NotFound(w, r)
			return
		}
		if r.Header.Get("x-api-key") != upstreamSecret {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, strings.Join([]string{
			`event: message_start`,
			`data: {"type":"message_start","message":{"usage":{"input_tokens":400,"cache_read_input_tokens":1000,"cache_creation_input_tokens":100,"output_tokens":0}}}`,
			``,
			`event: content_block_delta`,
			`data: {"type":"content_block_delta","delta":{"type":"thinking_delta","thinking":"verify"}}`,
			``,
			`event: content_block_delta`,
			`data: {"type":"content_block_delta","delta":{"type":"text_delta","text":"hello from mock anthropic"}}`,
			``,
			`event: message_delta`,
			`data: {"type":"message_delta","usage":{"output_tokens":50}}`,
			``,
		}, "\n"))
	}))
	defer mockAnthropic.Close()

	fixedNow := time.Date(2026, 6, 15, 10, 0, 0, 0, time.UTC)
	srv, err := pluginsdk.Serve(t.Context(), pluginsdk.Options{
		Plugin: &Plugin{
			now:                 func() time.Time { return fixedNow },
			maintenanceInterval: time.Hour,
		},
		Manifest:           Manifest(),
		Registrar:          grpc.NewServer(),
		DefaultGracePeriod: time.Second,
	})
	if err != nil {
		t.Fatalf("pluginsdk.Serve 失败: %v", err)
	}
	t.Cleanup(srv.Close)

	rc := &pb.RequestContext{InstanceId: "default", NodeId: "local", Locale: "zh-CN"}
	if _, err := srv.Initialize(t.Context(), &pb.InitializeRequest{
		Context:        rc,
		InstanceHandle: "ai-relay-handle",
		DataDir:        t.TempDir(),
		ConfigJson:     []byte(`{"allow_private_upstream":true,"default_reserve_micros":50000}`),
		ConfigRevision: "1",
	}); err != nil {
		t.Fatalf("Initialize 失败: %v", err)
	}
	if _, err := srv.Start(t.Context(), &pb.StartRequest{Context: rc}); err != nil {
		t.Fatalf("Start 失败: %v", err)
	}
	if _, err := srv.Activate(t.Context(), &pb.ActivateRequest{Context: rc}); err != nil {
		t.Fatalf("Activate 失败: %v", err)
	}

	// 验证配置校验、热更新与健康检查。
	badVal, err := srv.ValidateConfig(t.Context(), &pb.ValidateConfigRequest{
		Context:    rc,
		ConfigJson: []byte(`{"default_reserve_micros":10}`),
	})
	if err != nil || len(badVal.GetViolations()) == 0 {
		t.Fatalf("非法配置应返回校验违规: resp=%+v err=%v", badVal, err)
	}
	if ap, err := srv.ApplyConfig(t.Context(), &pb.ApplyConfigRequest{
		Context:          rc,
		ConfigJson:       []byte(`{"allow_private_upstream":true,"default_reserve_micros":40000,"log_retention_days":14}`),
		ProposedRevision: "2",
	}); err != nil || ap.GetError() != nil {
		t.Fatalf("ApplyConfig 失败: resp=%+v err=%v", ap, err)
	}
	if hResp, err := srv.CheckHealth(t.Context(), &pb.CheckHealthRequest{Context: rc}); err != nil || hResp.GetMessage() == "" {
		t.Fatalf("CheckHealth 异常: resp=%+v err=%v", hResp, err)
	}

	// 1 & 2) relay.settings.update + relay.settings.get（确认敏感凭据不回显）。
	updProg := runRelayJob(t, srv, "relay.settings.update", map[string]any{
		"site_title":                "Lab AI Gateway",
		"allow_invite_signup":       true,
		"linuxdo_client_id":         "cid-lab",
		"linuxdo_client_secret":     "ld-secret-never-echo",
		"checkin_enabled":           true,
		"checkin_min_micros":        200_000,
		"checkin_max_micros":        200_000,
		"checkin_drip_below_micros": 0,
		"smtp": map[string]any{
			"host":         "smtp.example.com",
			"port":         587,
			"username":     "bot@example.com",
			"password":     "smtp-secret-never-echo",
			"from_address": "bot@example.com",
		},
	})
	if strings.Contains(string(updProg.GetResultJson()), "never-echo") {
		t.Fatalf("settings.update 返回泄漏了敏感凭据: %s", updProg.GetResultJson())
	}
	setResp := invokeRelay(t, srv, "relay.settings.get", map[string]any{"include_tier_rules": true})
	if strings.Contains(string(setResp.GetPayloadJson()), "never-echo") || !strings.Contains(string(setResp.GetPayloadJson()), `"smtp_configured":true`) {
		t.Fatalf("settings.get 返回异常或泄漏密文: %s", setResp.GetPayloadJson())
	}

	// 3, 4, 5) relay.channels.upsert + relay.channels.list + relay.channels.test。
	chProg := runRelayJob(t, srv, "relay.channels.upsert", map[string]any{
		"name":           "Mock Anthropic",
		"kind":           "anthropic_native",
		"base_url":       mockAnthropic.URL,
		"credential":     upstreamSecret,
		"groups":         []string{"default"},
		"models":         []string{"claude-sonnet-4-5"},
		"priority":       20,
		"weight":         10,
		"max_concurrent": 4,
		"enabled":        true,
	})
	var chOut struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(chProg.GetResultJson(), &chOut); err != nil || chOut.ID == "" {
		t.Fatalf("解析渠道创建结果失败: %s", chProg.GetResultJson())
	}
	listChResp := invokeRelay(t, srv, "relay.channels.list", map[string]any{"limit": 10})
	if strings.Contains(string(listChResp.GetPayloadJson()), upstreamSecret) || !strings.Contains(string(listChResp.GetPayloadJson()), chOut.ID) {
		t.Fatalf("channels.list 缺少渠道或泄漏上游凭据: %s", listChResp.GetPayloadJson())
	}
	testChProg := runRelayJob(t, srv, "relay.channels.test", map[string]any{"id": chOut.ID, "model": "claude-sonnet-4-5"})
	var testOut struct {
		OK          bool   `json:"ok"`
		HTTPStatus  int    `json:"http_status"`
		HealthState string `json:"health_state"`
	}
	if err := json.Unmarshal(testChProg.GetResultJson(), &testOut); err != nil || !testOut.OK || testOut.HTTPStatus != 200 || testOut.HealthState != "healthy" {
		t.Fatalf("channels.test 探活失败: %s", testChProg.GetResultJson())
	}

	// 6) relay.pricings.upsert。
	runRelayJob(t, srv, "relay.pricings.upsert", map[string]any{
		"model_name":           "claude-sonnet-4-5",
		"billing_mode":         "token",
		"input_micros_per_1k":  3000,
		"output_micros_per_1k": 15000,
		"cache_read_ratio":     0.1,
		"cache_write_ratio":    1.25,
	})

	// 7, 8, 9) relay.users.create + relay.users.list + relay.users.adjust_quota。
	uProg := runRelayJob(t, srv, "relay.users.create", map[string]any{
		"username":    "alice",
		"password":    "AliceStrong123!",
		"group_name":  "default",
		"init_micros": 2_000_000,
	})
	var uOut struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(uProg.GetResultJson(), &uOut); err != nil || uOut.ID == "" {
		t.Fatalf("解析创建用户结果失败: %s", uProg.GetResultJson())
	}
	usersListResp := invokeRelay(t, srv, "relay.users.list", map[string]any{"group_name": "default"})
	if !strings.Contains(string(usersListResp.GetPayloadJson()), `"username":"alice"`) {
		t.Fatalf("users.list 未包含 alice: %s", usersListResp.GetPayloadJson())
	}
	runRelayJob(t, srv, "relay.users.adjust_quota", map[string]any{
		"user_id":      uOut.ID,
		"delta_micros": 1_000_000,
		"note":         "team grant",
	})

	// 10) relay.codes.generate。
	codeProg := runRelayJob(t, srv, "relay.codes.generate", map[string]any{
		"kind":             "cdk_single",
		"title":            "Welcome Bonus",
		"amount_micros":    500_000,
		"count":            1,
		"custom_code":      "CDK-E2E-001",
		"expires_in_hours": 24,
	})
	if !strings.Contains(string(codeProg.GetResultJson()), "CDK-E2E-001") {
		t.Fatalf("codes.generate 返回异常: %s", codeProg.GetResultJson())
	}

	// 鉴权隔离硬红线：/v1/* 与 /portal/api/* 绝不接受面板 qwq_* 凭据。
	badAPI, err := srv.ServePublicRoute(t.Context(), &pb.ServePublicRouteRequest{
		Context: rc,
		Route:   "v1",
		Method:  http.MethodPost,
		Path:    "/v1/chat/completions",
		Headers: []*pb.HttpHeader{{Name: "x-qwq-relay-token", Value: "qwq_panel_root_token_123456"}},
		Body:    []byte(`{"model":"claude-sonnet-4-5","messages":[{"role":"user","content":"hi"}]}`),
	})
	if err != nil || badAPI.GetStatus() != http.StatusUnauthorized {
		t.Fatalf("面板令牌访问 /v1 必须被 401 拒绝，实际 status=%d err=%v", badAPI.GetStatus(), err)
	}
	badPortal, err := srv.ServePublicRoute(t.Context(), &pb.ServePublicRouteRequest{
		Context: rc,
		Route:   "portal",
		Method:  http.MethodGet,
		Path:    "/portal/api/me",
		Headers: []*pb.HttpHeader{{Name: "x-relay-session", Value: "qwq_panel_root_token_123456"}},
	})
	if err != nil || badPortal.GetStatus() != http.StatusUnauthorized {
		t.Fatalf("面板令牌访问 /portal/api 必须被 401 拒绝，实际 status=%d err=%v", badPortal.GetStatus(), err)
	}

	// 门户静态资源与登录、签到、核销 CDK、签发 sk-qwq-* 子令牌。
	spaResp, err := srv.ServePublicRoute(t.Context(), &pb.ServePublicRouteRequest{
		Context: rc, Route: "portal", Method: http.MethodGet, Path: "/portal/",
	})
	if err != nil || spaResp.GetStatus() != http.StatusOK || !strings.Contains(string(spaResp.GetBody()), "portal.js") {
		t.Fatalf("门户 HTML 响应异常: status=%d err=%v", spaResp.GetStatus(), err)
	}
	jsResp, err := srv.ServePublicRoute(t.Context(), &pb.ServePublicRouteRequest{
		Context: rc, Route: "portal", Method: http.MethodGet, Path: "/portal/portal.js",
	})
	if err != nil || jsResp.GetStatus() != http.StatusOK || !strings.Contains(string(jsResp.GetBody()), "X-Relay-Session") {
		t.Fatalf("门户 JS 响应异常: status=%d err=%v", jsResp.GetStatus(), err)
	}

	loginResp, err := srv.ServePublicRoute(t.Context(), &pb.ServePublicRouteRequest{
		Context: rc, Route: "portal", Method: http.MethodPost, Path: "/portal/api/auth/submit",
		Body: []byte(`{"mode":"login","username":"alice","password":"AliceStrong123!"}`),
	})
	if err != nil || loginResp.GetStatus() != http.StatusOK {
		t.Fatalf("门户登录失败: status=%d body=%s err=%v", loginResp.GetStatus(), loginResp.GetBody(), err)
	}
	var loginOut struct {
		SessionToken string `json:"session_token"`
	}
	if err := json.Unmarshal(loginResp.GetBody(), &loginOut); err != nil || !strings.HasPrefix(loginOut.SessionToken, "rly_sess_") {
		t.Fatalf("门户会话令牌格式异常: %s", loginResp.GetBody())
	}
	sessHdr := []*pb.HttpHeader{{Name: "x-relay-session", Value: loginOut.SessionToken}}

	if chkResp, err := srv.ServePublicRoute(t.Context(), &pb.ServePublicRouteRequest{
		Context: rc, Route: "portal", Method: http.MethodPost, Path: "/portal/api/quota/checkin", Headers: sessHdr,
	}); err != nil || chkResp.GetStatus() != http.StatusOK {
		t.Fatalf("门户签到失败: status=%d body=%s err=%v", chkResp.GetStatus(), chkResp.GetBody(), err)
	}
	if cdkResp, err := srv.ServePublicRoute(t.Context(), &pb.ServePublicRouteRequest{
		Context: rc, Route: "portal", Method: http.MethodPost, Path: "/portal/api/quota/redeem", Headers: sessHdr,
		Body: []byte(`{"code":"CDK-E2E-001"}`),
	}); err != nil || cdkResp.GetStatus() != http.StatusOK {
		t.Fatalf("门户核销 CDK 失败: status=%d body=%s err=%v", cdkResp.GetStatus(), cdkResp.GetBody(), err)
	}

	tokResp, err := srv.ServePublicRoute(t.Context(), &pb.ServePublicRouteRequest{
		Context: rc, Route: "portal", Method: http.MethodPost, Path: "/portal/api/tokens", Headers: sessHdr,
		Body: []byte(`{"name":"ide-key","rpm_limit":60}`),
	})
	if err != nil || tokResp.GetStatus() != http.StatusOK {
		t.Fatalf("门户签发子令牌失败: status=%d body=%s err=%v", tokResp.GetStatus(), tokResp.GetBody(), err)
	}
	var tokOut struct {
		PlainKey string `json:"plain_key"`
	}
	if err := json.Unmarshal(tokResp.GetBody(), &tokOut); err != nil || !strings.HasPrefix(tokOut.PlainKey, "sk-qwq-") {
		t.Fatalf("子令牌前缀异常: %s", tokResp.GetBody())
	}

	// GET /v1/models + POST /v1/chat/completions（跨协议互转至 Anthropic 上游并统计落账）。
	modelsResp, err := srv.ServePublicRoute(t.Context(), &pb.ServePublicRouteRequest{
		Context: rc, Route: "v1", Method: http.MethodGet, Path: "/v1/models",
		Headers: []*pb.HttpHeader{{Name: "x-qwq-relay-token", Value: tokOut.PlainKey}},
	})
	if err != nil || modelsResp.GetStatus() != http.StatusOK || !strings.Contains(string(modelsResp.GetBody()), "claude-sonnet-4-5") {
		t.Fatalf("/v1/models 响应异常: status=%d body=%s err=%v", modelsResp.GetStatus(), modelsResp.GetBody(), err)
	}

	chatResp, err := srv.ServePublicRoute(t.Context(), &pb.ServePublicRouteRequest{
		Context: rc, Route: "v1", Method: http.MethodPost, Path: "/v1/chat/completions",
		Headers: []*pb.HttpHeader{{Name: "x-qwq-relay-token", Value: tokOut.PlainKey}},
		Body:    []byte(`{"model":"claude-sonnet-4-5","stream":true,"messages":[{"role":"user","content":"ping"}]}`),
	})
	if err != nil || chatResp.GetStatus() != http.StatusOK {
		t.Fatalf("/v1/chat/completions 中转失败: status=%d body=%s err=%v", chatResp.GetStatus(), chatResp.GetBody(), err)
	}
	chatBody := string(chatResp.GetBody())
	if !strings.Contains(chatBody, `"reasoning_content":"verify"`) ||
		!strings.Contains(chatBody, `"content":"hello from mock anthropic"`) ||
		!strings.Contains(chatBody, "data: [DONE]") {
		t.Fatalf("跨协议 SSE 转换输出不完整:\n%s", chatBody)
	}

	// Deactivate 主动排空微批缓冲器，确保调用日志零丢账写入 SQLite。
	if _, err := srv.Deactivate(t.Context(), &pb.DeactivateRequest{Context: rc}); err != nil {
		t.Fatalf("Deactivate 失败: %v", err)
	}

	// 11) relay.overview 校验落账统计 + /portal/api/me 校验最近调用明细。
	ovResp := invokeRelay(t, srv, "relay.overview", map[string]any{"window_hours": 24})
	var ovOut struct {
		TotalChannels    int   `json:"total_channels"`
		HealthyChannels  int   `json:"healthy_channels"`
		TotalUsers       int   `json:"total_users"`
		WindowRequests   int64 `json:"window_requests"`
		WindowCostMicros int64 `json:"window_cost_micros"`
	}
	if err := json.Unmarshal(ovResp.GetPayloadJson(), &ovOut); err != nil {
		t.Fatalf("解析 overview 失败: %v", err)
	}
	if ovOut.TotalChannels != 1 || ovOut.HealthyChannels != 1 || ovOut.TotalUsers != 1 || ovOut.WindowRequests != 1 || ovOut.WindowCostMicros <= 0 {
		t.Fatalf("overview 统计异常: %+v", ovOut)
	}

	meResp, err := srv.ServePublicRoute(t.Context(), &pb.ServePublicRouteRequest{
		Context: rc, Route: "portal", Method: http.MethodGet, Path: "/portal/api/me", Headers: sessHdr,
	})
	if err != nil || meResp.GetStatus() != http.StatusOK || !strings.Contains(string(meResp.GetBody()), `"cached_read_tokens":1000`) {
		t.Fatalf("/portal/api/me 未包含落盘后的调用日志: status=%d body=%s err=%v", meResp.GetStatus(), meResp.GetBody(), err)
	}

	// 12) relay.channels.remove。
	rmProg := runRelayJob(t, srv, "relay.channels.remove", map[string]any{"id": chOut.ID})
	if !strings.Contains(string(rmProg.GetResultJson()), `"removed":true`) {
		t.Fatalf("channels.remove 结果异常: %s", rmProg.GetResultJson())
	}
}
