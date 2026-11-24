// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

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
	if len(parsed.Operations) != 13 {
		t.Fatalf("管理操作数量=%d，期望=13", len(parsed.Operations))
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

// ======================== SecretField 信封、门户令牌兼容/登出/吊销、动态预扣与熔断告警测试 ========================

type fakeHostSecretsAndEvents struct {
	pb.UnimplementedHostSecretsServiceServer
	pb.UnimplementedHostEventsServiceServer

	mu      sync.Mutex
	secrets map[string][]byte
	events  []*pb.EventDraft
}

func (f *fakeHostSecretsAndEvents) RevealSecret(_ context.Context, req *pb.RevealSecretRequest) (*pb.RevealSecretResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	v, ok := f.secrets[req.GetSecretRef()]
	if !ok {
		return nil, status.Errorf(codes.NotFound, "secret %q not found", req.GetSecretRef())
	}
	return &pb.RevealSecretResponse{Value: append([]byte(nil), v...)}, nil
}

func (f *fakeHostSecretsAndEvents) PublishEvent(_ context.Context, req *pb.PublishEventRequest) (*pb.PublishEventResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if req.GetEvent() != nil {
		f.events = append(f.events, req.GetEvent())
	}
	return &pb.PublishEventResponse{EventId: "evt_relay_1", Sequence: uint64(len(f.events))}, nil
}

func TestAIRelaySecretFieldPortalHeadersLogoutRevokeAndDynamicReserve(t *testing.T) {
	// 1) 验证大上下文动态预扣逻辑远高于默认下限。
	largeReserve := ComputeDynamicReserveMicros(DynamicReserveInput{
		DefaultReserveMicros: 50_000,
		EstimatedInputTokens: 200_000,
		RequestedMaxTokens:   4096,
		BillingMode:          "token",
		InputMicrosPer1K:     3000,
		OutputMicrosPer1K:    15000,
	})
	if largeReserve < 600_000 {
		t.Fatalf("200K 输入动态预扣应 >= 600000 micros，实际 %d", largeReserve)
	}
	perCallReserve := ComputeDynamicReserveMicros(DynamicReserveInput{
		DefaultReserveMicros: 50_000,
		BillingMode:          "per_call",
		PerCallMicros:        120_000,
	})
	if perCallReserve != 120_000 {
		t.Fatalf("per_call 动态预扣应为 120000，实际 %d", perCallReserve)
	}

	// 2) 搭建带 HostSecrets + HostEvents 的 bufconn 宿主夹具，验证 $secret / $keep_secret 与 relay.alert。
	lis := bufconn.Listen(256 << 10)
	hostSrv := grpc.NewServer()
	fakeHost := &fakeHostSecretsAndEvents{
		secrets: map[string][]byte{
			"sec-ch-1":     []byte(`"sk-upstream-revealed-1"`),
			"sec-ld-1":     []byte("ld-revealed-secret"),
			"sec-smtp-1":   []byte("smtp-revealed-pass"),
			"sec-u-pass-1": []byte("PortalUserPass123!"),
		},
	}
	pb.RegisterHostSecretsServiceServer(hostSrv, fakeHost)
	pb.RegisterHostEventsServiceServer(hostSrv, fakeHost)
	go func() { _ = hostSrv.Serve(lis) }()
	t.Cleanup(func() {
		hostSrv.Stop()
		_ = lis.Close()
	})

	hostConn, err := grpc.NewClient("passthrough:///ai-relay-host",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return lis.Dial() }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("连接 fakeHost 失败: %v", err)
	}
	t.Cleanup(func() { _ = hostConn.Close() })

	var sawSecret string
	failUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawSecret = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer failUpstream.Close()

	srv, err := pluginsdk.Serve(t.Context(), pluginsdk.Options{
		Plugin:             &Plugin{maintenanceInterval: time.Hour},
		Manifest:           Manifest(),
		Registrar:          grpc.NewServer(),
		Host:               hostConn,
		DefaultGracePeriod: time.Second,
	})
	if err != nil {
		t.Fatalf("pluginsdk.Serve 失败: %v", err)
	}
	t.Cleanup(srv.Close)

	rc := &pb.RequestContext{InstanceId: "default", NodeId: "local", Locale: "zh-CN"}
	if _, err := srv.Initialize(t.Context(), &pb.InitializeRequest{
		Context:        rc,
		InstanceHandle: "ai-relay-sec-handle",
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

	// SecretField $secret 信封用于 settings.update / channels.upsert / users.create。
	runRelayJob(t, srv, "relay.settings.update", map[string]any{
		"site_title":            "Secret Relay",
		"linuxdo_client_id":     "cid-sec",
		"linuxdo_client_secret": map[string]any{"$secret": "sec-ld-1"},
		"smtp": map[string]any{
			"host":         "smtp.example.com",
			"port":         587,
			"username":     "mailer@example.com",
			"password":     map[string]any{"$secret": "sec-smtp-1"},
			"from_address": "mailer@example.com",
		},
	})

	chProg := runRelayJob(t, srv, "relay.channels.upsert", map[string]any{
		"name":       "Upstream-Secret",
		"kind":       "openai_compatible",
		"base_url":   failUpstream.URL,
		"credential": map[string]any{"$secret": "sec-ch-1"},
		"groups":     []string{"default"},
		"models":     []string{"gpt-4o"},
	})
	var chOut struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(chProg.GetResultJson(), &chOut); err != nil || chOut.ID == "" {
		t.Fatalf("channels.upsert($secret) 失败: %s", chProg.GetResultJson())
	}

	// 使用 $keep_secret 更新渠道名称，保留已落盘密文。
	runRelayJob(t, srv, "relay.channels.upsert", map[string]any{
		"id":         chOut.ID,
		"name":       "Upstream-Secret-Renamed",
		"kind":       "openai_compatible",
		"base_url":   failUpstream.URL,
		"credential": map[string]any{"$keep_secret": true},
		"groups":     []string{"default"},
		"models":     []string{"gpt-4o"},
	})

	runRelayJob(t, srv, "relay.users.create", map[string]any{
		"username":    "bob_portal",
		"password":    map[string]any{"$secret": "sec-u-pass-1"},
		"group_name":  "default",
		"init_micros": 5_000_000,
	})

	// 校验 portal.css 静态外链可正常返回。
	cssResp, err := srv.ServePublicRoute(t.Context(), &pb.ServePublicRouteRequest{
		Context: rc, Route: "portal", Method: http.MethodGet, Path: "/portal/portal.css",
	})
	if err != nil || cssResp.GetStatus() != http.StatusOK || !strings.Contains(string(cssResp.GetBody()), ".auth-box") {
		t.Fatalf("/portal/portal.css 响应异常: status=%d err=%v", cssResp.GetStatus(), err)
	}

	// 登录并改用宿主转发的 X-QWQ-Relay-Token 请求 /portal/api/me。
	loginResp, err := srv.ServePublicRoute(t.Context(), &pb.ServePublicRouteRequest{
		Context: rc, Route: "portal", Method: http.MethodPost, Path: "/portal/api/auth/submit",
		Body: []byte(`{"mode":"login","username":"bob_portal","password":"PortalUserPass123!"}`),
	})
	if err != nil || loginResp.GetStatus() != http.StatusOK {
		t.Fatalf("portal login 失败: status=%d body=%s err=%v", loginResp.GetStatus(), loginResp.GetBody(), err)
	}
	var loginOut struct {
		SessionToken string `json:"session_token"`
	}
	if err := json.Unmarshal(loginResp.GetBody(), &loginOut); err != nil || !strings.HasPrefix(loginOut.SessionToken, "rly_sess_") {
		t.Fatalf("session_token 异常: %s", loginResp.GetBody())
	}
	relaySessHdr := []*pb.HttpHeader{{Name: "x-qwq-relay-token", Value: loginOut.SessionToken}}

	// 签发子令牌（仅创建时返回一次明文）。
	mintResp, err := srv.ServePublicRoute(t.Context(), &pb.ServePublicRouteRequest{
		Context: rc, Route: "portal", Method: http.MethodPost, Path: "/portal/api/tokens", Headers: relaySessHdr,
		Body: []byte(`{"name":"cursor-key","rpm_limit":30}`),
	})
	if err != nil || mintResp.GetStatus() != http.StatusOK {
		t.Fatalf("mint token 失败: status=%d body=%s err=%v", mintResp.GetStatus(), mintResp.GetBody(), err)
	}
	var mintOut struct {
		PlainKey string `json:"plain_key"`
	}
	if err := json.Unmarshal(mintResp.GetBody(), &mintOut); err != nil || !strings.HasPrefix(mintOut.PlainKey, "sk-qwq-") {
		t.Fatalf("mint plain_key 异常: %s", mintResp.GetBody())
	}

	// 通过 X-QWQ-Relay-Token 访问 /portal/api/me：必须返回 200 且仅返回掩码前缀，绝不回显 plain_key。
	meResp, err := srv.ServePublicRoute(t.Context(), &pb.ServePublicRouteRequest{
		Context: rc, Route: "portal", Method: http.MethodGet, Path: "/portal/api/me", Headers: relaySessHdr,
	})
	if err != nil || meResp.GetStatus() != http.StatusOK {
		t.Fatalf("使用 X-QWQ-Relay-Token 访问 /portal/api/me 应返回 200，实际 status=%d body=%s err=%v", meResp.GetStatus(), meResp.GetBody(), err)
	}
	if strings.Contains(string(meResp.GetBody()), mintOut.PlainKey) {
		t.Fatalf("/portal/api/me 泄漏了完整子令牌明文: %s", meResp.GetBody())
	}
	var meOut struct {
		Tokens []struct {
			ID        string `json:"id"`
			KeyMasked string `json:"key_masked"`
			PlainKey  string `json:"plain_key"`
		} `json:"tokens"`
	}
	if err := json.Unmarshal(meResp.GetBody(), &meOut); err != nil || len(meOut.Tokens) != 1 {
		t.Fatalf("解析 /portal/api/me tokens 失败: %s", meResp.GetBody())
	}
	if !strings.HasSuffix(meOut.Tokens[0].KeyMasked, "****") || meOut.Tokens[0].PlainKey != "" {
		t.Fatalf("子令牌脱敏格式不符: %+v", meOut.Tokens[0])
	}

	// 触发唯一上游返回 502：验证 $secret 真实解封为 Bearer sk-upstream-revealed-1，并触发熔断与 relay.alert 事件。
	failResp, err := srv.ServePublicRoute(t.Context(), &pb.ServePublicRouteRequest{
		Context: rc, Route: "v1", Method: http.MethodPost, Path: "/v1/chat/completions",
		Headers: []*pb.HttpHeader{{Name: "x-qwq-relay-token", Value: mintOut.PlainKey}},
		Body:    []byte(`{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}]}`),
	})
	if err != nil || failResp.GetStatus() != http.StatusBadGateway {
		t.Fatalf("上游 502 应返回 502，实际 status=%d body=%s err=%v", failResp.GetStatus(), failResp.GetBody(), err)
	}
	if sawSecret != "Bearer sk-upstream-revealed-1" {
		t.Fatalf("$secret/$keep_secret 上游凭据未正确生效，实际 Authorization=%q", sawSecret)
	}
	fakeHost.mu.Lock()
	eventCount := len(fakeHost.events)
	var firstEvtType string
	var firstEvtPayload []byte
	if eventCount > 0 {
		firstEvtType = fakeHost.events[0].GetType()
		firstEvtPayload = fakeHost.events[0].GetPayloadJson()
	}
	fakeHost.mu.Unlock()
	if eventCount == 0 || firstEvtType != "relay.alert" {
		t.Fatalf("全部上游 502 熔断后应发布 relay.alert 事件，实际 count=%d type=%q", eventCount, firstEvtType)
	}
	var alertBody struct {
		Severity string            `json:"severity"`
		Title    string            `json:"title"`
		Message  string            `json:"message"`
		DedupKey string            `json:"dedup_key"`
		Tags     map[string]string `json:"tags"`
	}
	if err := json.Unmarshal(firstEvtPayload, &alertBody); err != nil {
		t.Fatalf("解析 relay.alert 载荷失败: %v", err)
	}
	if alertBody.Severity != "critical" || alertBody.Title == "" || alertBody.Message == "" || alertBody.DedupKey == "" || alertBody.Tags["model"] != "gpt-4o" {
		t.Fatalf("relay.alert 缺少 AlertEventRelay 必需字段: %+v", alertBody)
	}

	// 吊销子令牌：DELETE /portal/api/tokens/{id} 后再调 /v1/models 必须返回 401。
	delResp, err := srv.ServePublicRoute(t.Context(), &pb.ServePublicRouteRequest{
		Context: rc, Route: "portal", Method: http.MethodDelete, Path: "/portal/api/tokens/" + meOut.Tokens[0].ID, Headers: relaySessHdr,
	})
	if err != nil || delResp.GetStatus() != http.StatusOK {
		t.Fatalf("DELETE /portal/api/tokens/{id} 失败: status=%d body=%s err=%v", delResp.GetStatus(), delResp.GetBody(), err)
	}
	afterRevoke, err := srv.ServePublicRoute(t.Context(), &pb.ServePublicRouteRequest{
		Context: rc, Route: "v1", Method: http.MethodGet, Path: "/v1/models",
		Headers: []*pb.HttpHeader{{Name: "x-qwq-relay-token", Value: mintOut.PlainKey}},
	})
	if err != nil || afterRevoke.GetStatus() != http.StatusUnauthorized {
		t.Fatalf("吊销后的子令牌应返回 401，实际 status=%d err=%v", afterRevoke.GetStatus(), err)
	}

	// 退出登录：POST /portal/api/auth/logout 后再调 /portal/api/me 必须返回 401。
	logoutResp, err := srv.ServePublicRoute(t.Context(), &pb.ServePublicRouteRequest{
		Context: rc, Route: "portal", Method: http.MethodPost, Path: "/portal/api/auth/logout", Headers: relaySessHdr,
	})
	if err != nil || logoutResp.GetStatus() != http.StatusOK {
		t.Fatalf("POST /portal/api/auth/logout 失败: status=%d body=%s err=%v", logoutResp.GetStatus(), logoutResp.GetBody(), err)
	}
	afterLogout, err := srv.ServePublicRoute(t.Context(), &pb.ServePublicRouteRequest{
		Context: rc, Route: "portal", Method: http.MethodGet, Path: "/portal/api/me", Headers: relaySessHdr,
	})
	if err != nil || afterLogout.GetStatus() != http.StatusUnauthorized {
		t.Fatalf("登出后的会话应返回 401，实际 status=%d err=%v", afterLogout.GetStatus(), err)
	}
}
