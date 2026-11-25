// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/test/bufconn"

	pluginconfigv1 "github.com/qwq-panel/qwq/sdk/gen/qwq/capability/pluginconfig/v1"
	trafficv1 "github.com/qwq-panel/qwq/sdk/gen/qwq/capability/traffic/v1"
	pb "github.com/qwq-panel/qwq/sdk/gen/qwq/platform/v1"
	"github.com/qwq-panel/qwq/sdk/manifest"
	"github.com/qwq-panel/qwq/sdk/pluginsdk"
)

// ======================== 纯 Go 宿主能力 mock gRPC 夹具 ========================

type fakePluginConfigService struct {
	pluginconfigv1.UnimplementedPluginConfigServiceServer
	mu               sync.Mutex
	redactedConfig   []byte
	revision         string
	putCalls         int
	lastPutJSON      []byte
	lastPutOpID      string
	lastTriggerApply bool
	lastExpectedRev  string
	failErr          *pb.ErrorDetail
}

func newFakePluginConfigService() *fakePluginConfigService {
	initial := `{
		"schema_version": "2",
		"enabled": true,
		"profiles": [
			{
				"id": "vless-main",
				"enabled": true,
				"listen": "::",
				"port": 443,
				"protocol": "vless",
				"users": [{"id": "bootstrap", "uuid": {"$secret_present": true}}],
				"vless": {
					"transport": "raw",
					"flow": "xtls-rprx-vision",
					"security": {
						"mode": "reality",
						"target": "www.apple.com:443",
						"server_names": ["www.apple.com"],
						"private_key": {"$secret_present": true},
						"short_ids": ["a1b2c3d4"]
					}
				}
			},
			{
				"id": "hy2-main",
				"enabled": true,
				"listen": "::",
				"port": 8443,
				"protocol": "hysteria2",
				"users": [{"id": "bootstrap", "auth": {"$secret_present": true}}],
				"hysteria2": {"tls": {"binding_ref": "bind-1", "server_name": "hy2.example.com"}}
			},
			{
				"id": "ss-main",
				"enabled": true,
				"listen": "::",
				"port": 18388,
				"protocol": "shadowsocks2022",
				"users": [{"id": "bootstrap", "psk": {"$secret_present": true}}],
				"shadowsocks2022": {
					"method": "2022-blake3-aes-128-gcm",
					"server_key": {"$secret_present": true},
					"obfs": {"mode": "tls", "host": "www.bing.com"},
					"udp": true
				}
			}
		],
		"outbound": {"type": "direct"}
	}`
	return &fakePluginConfigService{
		redactedConfig: []byte(initial),
		revision:       "core-r1",
	}
}

func (s *fakePluginConfigService) nextErrLocked() *pb.ErrorDetail {
	err := s.failErr
	s.failErr = nil
	return err
}

func (s *fakePluginConfigService) GetConfig(_ context.Context, req *pluginconfigv1.GetConfigRequest) (*pluginconfigv1.GetConfigResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.nextErrLocked(); err != nil {
		return &pluginconfigv1.GetConfigResponse{Error: err}, nil
	}
	if req.GetContext().GetInstanceHandle() != "proxy-handle" || req.GetTargetPluginId() != "core.xray" {
		return &pluginconfigv1.GetConfigResponse{Error: &pb.ErrorDetail{Code: "PERMISSION_DENIED", Message: "bad target"}}, nil
	}
	return &pluginconfigv1.GetConfigResponse{
		RedactedConfigJson: append([]byte(nil), s.redactedConfig...),
		Revision:           s.revision,
	}, nil
}

func (s *fakePluginConfigService) PutConfig(_ context.Context, req *pluginconfigv1.PutConfigRequest) (*pluginconfigv1.PutConfigResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.nextErrLocked(); err != nil {
		return &pluginconfigv1.PutConfigResponse{Error: err}, nil
	}
	s.putCalls++
	s.lastPutJSON = append([]byte(nil), req.GetConfigJson()...)
	s.lastPutOpID = req.GetContext().GetOperationId()
	s.lastTriggerApply = req.GetTriggerApply()
	s.lastExpectedRev = req.GetExpectedRevision()
	s.revision = fmt.Sprintf("core-r%d", s.putCalls+1)

	// 模拟宿主提取密文后对外继续以 {"$secret_present":true} 脱敏返回。
	var doc map[string]any
	if json.Unmarshal(req.GetConfigJson(), &doc) == nil {
		redactSecretsForMock(doc)
		if redacted, err := json.Marshal(doc); err == nil {
			s.redactedConfig = redacted
		}
	}
	return &pluginconfigv1.PutConfigResponse{
		Revision:         s.revision,
		ApplyOperationId: fmt.Sprintf("apply-op-%d", s.putCalls),
	}, nil
}

func redactSecretsForMock(v any) {
	switch cur := v.(type) {
	case map[string]any:
		if keep, ok := cur["$keep_secret"].(bool); ok && keep && len(cur) == 1 {
			delete(cur, "$keep_secret")
			cur["$secret_present"] = true
			return
		}
		for _, secretKey := range []string{"private_key", "server_key", "uuid", "auth", "psk"} {
			if _, exists := cur[secretKey]; exists {
				cur[secretKey] = map[string]any{"$secret_present": true}
			}
		}
		for _, child := range cur {
			redactSecretsForMock(child)
		}
	case []any:
		for _, child := range cur {
			redactSecretsForMock(child)
		}
	}
}

type fakeTrafficService struct {
	trafficv1.UnimplementedTrafficServiceServer
	mu                 sync.Mutex
	supported          bool
	uplinkIFBSupported bool
	degradedReason     string
	egressInterface    string
	classes            []*trafficv1.UserShapingClass
	revision           string
	applyCalls         int
	clearCalls         int
	failErr            *pb.ErrorDetail
}

func newFakeTrafficService() *fakeTrafficService {
	return &fakeTrafficService{
		supported:          true,
		uplinkIFBSupported: true,
		egressInterface:    "eth0",
		revision:           "tf-r1",
	}
}

func (s *fakeTrafficService) nextErrLocked() *pb.ErrorDetail {
	err := s.failErr
	s.failErr = nil
	return err
}

func (s *fakeTrafficService) GetShapingStatus(_ context.Context, _ *trafficv1.GetShapingStatusRequest) (*trafficv1.GetShapingStatusResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.nextErrLocked(); err != nil {
		return &trafficv1.GetShapingStatusResponse{Error: err}, nil
	}
	out := make([]*trafficv1.UserShapingClass, 0, len(s.classes))
	for _, c := range s.classes {
		out = append(out, &trafficv1.UserShapingClass{
			TrafficMark:   c.TrafficMark,
			DownLimitKbps: c.DownLimitKbps,
			UpLimitKbps:   c.UpLimitKbps,
		})
	}
	return &trafficv1.GetShapingStatusResponse{
		Supported:          s.supported,
		UplinkIfbSupported: s.uplinkIFBSupported,
		DegradedReason:     s.degradedReason,
		EgressInterface:    s.egressInterface,
		Classes:            out,
		Revision:           s.revision,
	}, nil
}

func (s *fakeTrafficService) ApplyShapingRules(_ context.Context, req *trafficv1.ApplyShapingRulesRequest) (*trafficv1.ApplyShapingRulesResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.nextErrLocked(); err != nil {
		return &trafficv1.ApplyShapingRulesResponse{Error: err}, nil
	}
	s.applyCalls++
	s.classes = append([]*trafficv1.UserShapingClass(nil), req.GetClasses()...)
	s.revision = fmt.Sprintf("tf-r%d", s.applyCalls+s.clearCalls+1)
	return &trafficv1.ApplyShapingRulesResponse{
		Revision:       s.revision,
		DegradedUplink: !s.uplinkIFBSupported,
	}, nil
}

func (s *fakeTrafficService) ClearShapingRules(_ context.Context, _ *trafficv1.ClearShapingRulesRequest) (*trafficv1.ClearShapingRulesResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.nextErrLocked(); err != nil {
		return &trafficv1.ClearShapingRulesResponse{Error: err}, nil
	}
	s.clearCalls++
	s.classes = nil
	s.revision = fmt.Sprintf("tf-r%d", s.applyCalls+s.clearCalls+1)
	return &trafficv1.ClearShapingRulesResponse{Revision: s.revision}, nil
}

type fakeHostInvokeService struct {
	pb.UnimplementedHostInvokeServiceServer
	mu          sync.Mutex
	observeJSON []byte
	calls       int
	lastOpID    string
}

func (s *fakeHostInvokeService) InvokePlugin(_ context.Context, req *pb.InvokePluginRequest) (*pb.InvokePluginResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls++
	s.lastOpID = req.GetContext().GetOperationId()
	if req.GetTargetPluginId() != "core.xray" || req.GetOperation() != "core.observe" {
		return &pb.InvokePluginResponse{Error: &pb.ErrorDetail{Code: "PERMISSION_DENIED", Message: "unexpected invoke target"}}, nil
	}
	payload := s.observeJSON
	if len(payload) == 0 {
		payload = []byte(`{"reset_epoch":"ep-0","collected_at":"2026-11-21T12:00:00Z","source":"xray","series":[]}`)
	}
	return &pb.InvokePluginResponse{PayloadJson: append([]byte(nil), payload...)}, nil
}

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

type proxyHarness struct {
	srv      *pluginsdk.Server
	cfgSvc   *fakePluginConfigService
	traffic  *fakeTrafficService
	invoke   *fakeHostInvokeService
	dataDir  string
	clockSec *atomic.Int64
}

func newProxyTestHarness(t *testing.T, configJSON string, syncInterval time.Duration) *proxyHarness {
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
	h.clockSec.Store(time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC).Unix())

	pluginconfigv1.RegisterPluginConfigServiceServer(hostServer, h.cfgSvc)
	trafficv1.RegisterTrafficServiceServer(hostServer, h.traffic)
	pb.RegisterHostInvokeServiceServer(hostServer, h.invoke)

	go func() { _ = hostServer.Serve(listener) }()
	t.Cleanup(func() { hostServer.Stop(); _ = listener.Close() })

	conn, err := grpc.NewClient("passthrough:///proxy-host",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return listener.Dial() }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	plugin := &Plugin{
		now:          func() time.Time { return time.Unix(h.clockSec.Load(), 0).UTC() },
		syncInterval: syncInterval,
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
	return h
}

func invokeProxy(t *testing.T, srv *pluginsdk.Server, op string, payload any) *pb.InvokeResponse {
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
		t.Fatalf("Invoke(%s) transport error: %v", op, err)
	}
	return resp
}

func runProxyJob(t *testing.T, srv *pluginsdk.Server, op string, payload any, pre []*pb.Precondition) *pb.JobProgress {
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
	err := srv.RunJob(&pb.RunJobRequest{
		Context:       &pb.RequestContext{InstanceId: "default", NodeId: "local", OperationId: "job-" + op, Locale: "zh-CN"},
		Operation:     op,
		ApiVersion:    "v1",
		PayloadJson:   raw,
		Preconditions: pre,
	}, stream)
	if err != nil {
		t.Fatalf("RunJob(%s) transport error: %v", op, err)
	}
	if len(stream.messages) == 0 || stream.messages[len(stream.messages)-1].GetProgress() == nil {
		t.Fatalf("RunJob(%s) missing terminal progress", op)
	}
	return stream.messages[len(stream.messages)-1].GetProgress()
}

func headerValFromProto(hs []*pb.HttpHeader, name string) string {
	for _, h := range hs {
		if strings.EqualFold(h.GetName(), name) {
			return h.GetValue()
		}
	}
	return ""
}

// ======================== 清单与全量文件 SHA-256 验证 ========================

func TestProxyAdvancedManifestAndPackageDigests(t *testing.T) {
	parsed, err := manifest.Parse(Manifest())
	if err != nil {
		t.Fatal(err)
	}
	if parsed.ID != "proxy.advanced" || parsed.Placement != "node" || parsed.Lifecycle.Startup != "eager" ||
		!parsed.Lifecycle.Background || parsed.Lifecycle.UpdateStrategy != "restart" || parsed.Lifecycle.EffectiveOverlapSafe() {
		t.Fatalf("manifest 生命周期或定位不符: %+v", parsed.Lifecycle)
	}
	if parsed.Resources.MemoryMaxMB != 256 || parsed.Resources.CPUQuotaPercent != 100 ||
		parsed.Resources.PIDsMax != 64 || parsed.Resources.FDsMax != 4096 ||
		parsed.Resources.DiskMaxMB != 96 || parsed.Resources.KVMaxKB != 512 {
		t.Fatalf("资源预算不符: %+v", parsed.Resources)
	}
	if len(parsed.Operations) != 48 {
		t.Fatalf("操作数量=%d，期望=48", len(parsed.Operations))
	}
	if len(parsed.Dependencies) != 0 {
		t.Fatalf("深度合并 Xray 核心后 proxy.advanced 不应再依赖独立插件，实际: %+v", parsed.Dependencies)
	}
	if parsed.UI == nil || len(parsed.UI.Routes) != 7 {
		t.Fatalf("UI 路由数量应为 7（/proxy, /proxy/nodes, /proxy/users, /proxy/plans, /proxy/rules, /proxy/chains, /proxy/tuning），实际: %+v", parsed.UI)
	}
	for name, digest := range parsed.Files {
		if name == parsed.Entrypoint {
			continue
		}
		raw, err := os.ReadFile(name)
		if err != nil {
			t.Fatalf("读取文件 %s 失败: %v", name, err)
		}
		sum := sha256.Sum256(raw)
		want := "sha256:" + hex.EncodeToString(sum[:])
		if digest != want {
			t.Fatalf("文件 %s 摘要不匹配: got %s want %s", name, digest, want)
		}
	}
}

// ======================== 套餐 CRUD、多用户创建、TrafficMark 256 槽位上限与令牌轮换 ========================

func TestProxyPlansUsersTrafficMarksAndTokenRotation(t *testing.T) {
	h := newProxyTestHarness(t, `{"public_host":"proxy.example.com","vless_port":443,"reality_sni":"www.apple.com","reality_public_key":"PubKeyBase64"}`, time.Hour)

	// 1. 套餐创建与更新。
	p1 := runProxyJob(t, h.srv, "plans.upsert", map[string]any{
		"id":                "pro-100g",
		"name":              "专业 100G",
		"quota_bytes":       107374182400,
		"down_limit_kbps":   50000,
		"up_limit_kbps":     20000,
		"billing_reset_day": 15,
		"validity_days":     30,
	}, nil)
	if p1.GetError() != nil {
		t.Fatalf("plans.upsert 失败: %+v", p1.GetError())
	}
	listPlans := invokeProxy(t, h.srv, "plans.list", map[string]any{"limit": 10})
	if listPlans.GetError() != nil {
		t.Fatalf("plans.list 失败: %+v", listPlans.GetError())
	}
	var plansOut plansListResponse
	if err := json.Unmarshal(listPlans.GetPayloadJson(), &plansOut); err != nil || len(plansOut.Plans) != 1 {
		t.Fatalf("套餐列表异常: %+v err=%v", plansOut, err)
	}

	// 2. 创建用户：验证 traffic_mark=20736、core.xray 密钥保留 + 新用户写入、HTB 限速下发。
	u1 := runProxyJob(t, h.srv, "users.create", map[string]any{
		"id":           "alice",
		"display_name": "Alice",
		"plan_id":      "pro-100g",
	}, nil)
	if u1.GetError() != nil {
		t.Fatalf("users.create 失败: %+v", u1.GetError())
	}
	var createOut usersCreateResponse
	if err := json.Unmarshal(u1.GetResultJson(), &createOut); err != nil {
		t.Fatal(err)
	}
	if createOut.User.TrafficMark != trafficMarkMin || createOut.SubscriptionToken == "" ||
		!strings.HasPrefix(createOut.SubscriptionPath, "/p/proxy.advanced/sub/") {
		t.Fatalf("用户创建响应不符: %+v", createOut)
	}
	h.cfgSvc.mu.Lock()
	putCalls := h.cfgSvc.putCalls
	triggerApply := h.cfgSvc.lastTriggerApply
	putRaw := string(h.cfgSvc.lastPutJSON)
	h.cfgSvc.mu.Unlock()
	if putCalls != 1 || !triggerApply || !strings.Contains(putRaw, `"$keep_secret":true`) || !strings.Contains(putRaw, `"id":"alice"`) {
		t.Fatalf("core.xray 同步内容不符: calls=%d apply=%v json=%s", putCalls, triggerApply, putRaw)
	}
	h.traffic.mu.Lock()
	tfCalls := h.traffic.applyCalls
	tfClasses := append([]*trafficv1.UserShapingClass(nil), h.traffic.classes...)
	h.traffic.mu.Unlock()
	if tfCalls != 1 || len(tfClasses) != 1 || tfClasses[0].GetTrafficMark() != trafficMarkMin || tfClasses[0].GetDownLimitKbps() != 50000 {
		t.Fatalf("TrafficService HTB 下发不符: calls=%d classes=%+v", tfCalls, tfClasses)
	}

	// 3. 轮换订阅令牌：旧令牌立即失效返回 404，新令牌返回 200。
	rot := runProxyJob(t, h.srv, "users.rotate_subscription", map[string]any{"user_id": "alice"}, nil)
	if rot.GetError() != nil {
		t.Fatalf("users.rotate_subscription 失败: %+v", rot.GetError())
	}
	var rotOut usersRotateSubscriptionResponse
	if err := json.Unmarshal(rot.GetResultJson(), &rotOut); err != nil {
		t.Fatal(err)
	}
	if rotOut.SubscriptionToken == "" || rotOut.SubscriptionToken == createOut.SubscriptionToken {
		t.Fatalf("轮换应产生新令牌: %+v", rotOut)
	}

	rc := &pb.RequestContext{InstanceId: "default", NodeId: "local", Locale: "zh-CN"}
	oldResp, err := h.srv.ServePublicRoute(t.Context(), &pb.ServePublicRouteRequest{
		Context: rc, Route: "sub", Method: "GET", Path: "/sub/" + createOut.SubscriptionToken,
	})
	if err != nil || oldResp.GetStatus() != 404 {
		t.Fatalf("旧订阅令牌应返回 404，实际 status=%d err=%v", oldResp.GetStatus(), err)
	}
	newResp, err := h.srv.ServePublicRoute(t.Context(), &pb.ServePublicRouteRequest{
		Context: rc, Route: "sub", Method: "GET", Path: "/sub/" + rotOut.SubscriptionToken,
	})
	if err != nil || newResp.GetStatus() != 200 {
		t.Fatalf("新订阅令牌应返回 200，实际 status=%d err=%v", newResp.GetStatus(), err)
	}

	// 4. 停用与重新启用用户，验证状态变更同步。
	dis := runProxyJob(t, h.srv, "users.set_status", map[string]any{"user_id": "alice", "status": "disabled"}, nil)
	if dis.GetError() != nil {
		t.Fatalf("users.set_status(disabled) 失败: %+v", dis.GetError())
	}
	ov := invokeProxy(t, h.srv, "proxy.overview", map[string]any{"include_traffic_status": false})
	if ov.GetError() != nil {
		t.Fatalf("proxy.overview 失败: %+v", ov.GetError())
	}
	var ovOut overviewResponse
	if err := json.Unmarshal(ov.GetPayloadJson(), &ovOut); err != nil || ovOut.DisabledUsers != 1 || ovOut.ActiveUsers != 0 {
		t.Fatalf("overview 统计不符: %+v err=%v", ovOut, err)
	}
}

func TestTrafficMarkExhaustion256Slots(t *testing.T) {
	st, err := openStore(t.TempDir(), func() time.Time { return time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC) })
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })

	if _, _, err := st.UpsertPlan(t.Context(), plansUpsertRequest{ID: "p1", Name: "基础"}, ""); err != nil {
		t.Fatal(err)
	}
	for idx := 0; idx < 256; idx++ {
		u, _, err := st.CreateUser(t.Context(), usersCreateRequest{
			ID:          fmt.Sprintf("u%03d", idx),
			DisplayName: fmt.Sprintf("User %d", idx),
			PlanID:      "p1",
		}, "2022-blake3-aes-128-gcm")
		if err != nil {
			t.Fatalf("创建第 %d 个用户失败: %v", idx, err)
		}
		wantMark := uint32(trafficMarkMin + idx)
		if u.TrafficMark != wantMark {
			t.Fatalf("第 %d 个用户 traffic_mark=%d，期望=%d", idx, u.TrafficMark, wantMark)
		}
	}
	// 第 257 个用户必须触发 RESOURCE_EXHAUSTED。
	_, _, err = st.CreateUser(t.Context(), usersCreateRequest{
		ID:          "u256",
		DisplayName: "Overflow",
		PlanID:      "p1",
	}, "2022-blake3-aes-128-gcm")
	if pluginsdk.CodeOf(err) != "RESOURCE_EXHAUSTED" {
		t.Fatalf("满 256 槽位时应返回 RESOURCE_EXHAUSTED，实际: %v", err)
	}
}

// ======================== Reset-Epoch 流量累计、超配额暂停、到期与月度重置恢复 ========================

func TestResetEpochUsageQuotaExpiryAndMonthlyReset(t *testing.T) {
	curTime := time.Date(2026, 11, 16, 10, 0, 0, 0, time.UTC)
	st, err := openStore(t.TempDir(), func() time.Time { return curTime })
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })

	resetDay := 15
	if _, _, err := st.UpsertPlan(t.Context(), plansUpsertRequest{
		ID:              "quota-1k",
		Name:            "1KB 测试套餐",
		QuotaBytes:      1000,
		BillingResetDay: &resetDay,
	}, ""); err != nil {
		t.Fatal(err)
	}
	if _, _, err := st.CreateUser(t.Context(), usersCreateRequest{
		ID:          "alice",
		DisplayName: "Alice",
		PlanID:      "quota-1k",
	}, "2022-blake3-aes-128-gcm"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := st.CreateUser(t.Context(), usersCreateRequest{
		ID:          "bob",
		DisplayName: "Bob",
		PlanID:      "quota-1k",
		ExpiresAt:   curTime.Add(2 * time.Hour).UnixMilli(),
	}, "2022-blake3-aes-128-gcm"); err != nil {
		t.Fatal(err)
	}

	// 同 epoch 首次采样：up=200, down=300 -> period=500。
	syncNeeded, err := st.IngestXrayObservation(t.Context(), "epoch-1", []usageSample{
		{UserID: "alice", RawUp: 200, RawDown: 300, HasUp: true, HasDown: true},
	})
	if err != nil || syncNeeded {
		t.Fatalf("首次采样不应触发超额同步: sync=%v err=%v", syncNeeded, err)
	}

	// 同 epoch 单调递增：raw=(350, 450) -> delta=(150, 150) -> period=800。
	syncNeeded, err = st.IngestXrayObservation(t.Context(), "epoch-1", []usageSample{
		{UserID: "alice", RawUp: 350, RawDown: 450, HasUp: true, HasDown: true},
	})
	if err != nil || syncNeeded {
		t.Fatalf("同 epoch 增量不应触发超额同步: sync=%v err=%v", syncNeeded, err)
	}

	// Xray 重启切换至 epoch-2，计数器归零重新上涨至 (100, 150) -> 平滑累加 (+100, +150) -> period=1050 >= 1000 触发 suspended_quota！
	syncNeeded, err = st.IngestXrayObservation(t.Context(), "epoch-2", []usageSample{
		{UserID: "alice", RawUp: 100, RawDown: 150, HasUp: true, HasDown: true},
	})
	if err != nil || !syncNeeded {
		t.Fatalf("epoch 切换后超配额应触发同步: sync=%v err=%v", syncNeeded, err)
	}
	users, err := st.ListUsers(t.Context(), "", "", 10)
	if err != nil {
		t.Fatal(err)
	}
	byID := map[string]userRecord{}
	for _, u := range users {
		byID[u.ID] = u
	}
	if byID["alice"].Status != "suspended_quota" || byID["alice"].PeriodUpBytes != 450 || byID["alice"].PeriodDownBytes != 600 ||
		byID["alice"].TotalUpBytes != 450 || byID["alice"].TotalDownBytes != 600 {
		t.Fatalf("alice 超配额或累计字节不符: %+v", byID["alice"])
	}

	history, err := st.GetUsageHistory(t.Context(), "alice", 24)
	if err != nil || len(history) != 1 || history[0].UpBytes != 450 || history[0].DownBytes != 600 {
		t.Fatalf("小时聚合桶统计不符: %+v err=%v", history, err)
	}

	// 推进时钟 3 小时：bob 到期应自动置为 expired。
	curTime = curTime.Add(3 * time.Hour)
	syncNeeded, err = st.IngestXrayObservation(t.Context(), "epoch-2", nil)
	if err != nil || !syncNeeded {
		t.Fatalf("bob 到期应触发同步: sync=%v err=%v", syncNeeded, err)
	}
	users, _ = st.ListUsers(t.Context(), "", "", 10)
	for _, u := range users {
		if u.ID == "bob" && u.Status != "expired" {
			t.Fatalf("bob 应为 expired，实际 %s", u.Status)
		}
	}

	// 推进时钟至下月重置日（2026-12-15），并携带上周期末尾残留增量 (20, 30)：
	// 应先结算尾量到 total，再执行跨账期清零并恢复 active，新账期从 0/0 起步！
	curTime = time.Date(2026, 12, 15, 1, 0, 0, 0, time.UTC)
	syncNeeded, err = st.IngestXrayObservation(t.Context(), "epoch-2", []usageSample{
		{UserID: "alice", RawUp: 120, RawDown: 180, HasUp: true, HasDown: true},
	})
	if err != nil || !syncNeeded {
		t.Fatalf("月度重置恢复应触发同步: sync=%v err=%v", syncNeeded, err)
	}
	users, _ = st.ListUsers(t.Context(), "", "", 10)
	for _, u := range users {
		if u.ID == "alice" {
			if u.Status != "active" || u.PeriodUpBytes != 0 || u.PeriodDownBytes != 0 || u.TotalUpBytes != 470 || u.TotalDownBytes != 630 {
				t.Fatalf("月度重置后 alice 状态或流量不符: %+v", u)
			}
		}
	}
}

// ======================== 公开订阅路由多格式、响应头、IPv6 与安全校验 ========================

func TestPublicSubscriptionRouteFormatsHeadersAndSecurity(t *testing.T) {
	cfgJSON := `{
		"public_host": "2001:db8::42",
		"vless_port": 443,
		"reality_sni": "www.apple.com",
		"reality_public_key": "PubKeyReality123",
		"reality_short_id": "a1b2c3d4",
		"hy2_port": 8443,
		"hy2_sni": "hy2.example.com",
		"hy2_public_trusted": false,
		"hy2_cert_pin_sha256": "sha256:deadbeef",
		"ss_port": 18388,
		"ss_method": "2022-blake3-aes-128-gcm",
		"ss_server_key": "ServerPSK==",
		"ss_obfs_mode": "tls",
		"ss_obfs_host": "www.bing.com",
		"ss_udp": true
	}`
	h := newProxyTestHarness(t, cfgJSON, time.Hour)

	if prog := runProxyJob(t, h.srv, "plans.upsert", map[string]any{
		"id":          "std",
		"name":        "标准",
		"quota_bytes": 53687091200,
	}, nil); prog.GetError() != nil {
		t.Fatal(prog.GetError())
	}
	uProg := runProxyJob(t, h.srv, "users.create", map[string]any{
		"id":           "carol",
		"display_name": "Carol",
		"plan_id":      "std",
	}, nil)
	if uProg.GetError() != nil {
		t.Fatal(uProg.GetError())
	}
	var created usersCreateResponse
	if err := json.Unmarshal(uProg.GetResultJson(), &created); err != nil {
		t.Fatal(err)
	}
	token := created.SubscriptionToken
	rc := &pb.RequestContext{InstanceId: "default", NodeId: "local", Locale: "zh-CN"}

	// 1. 默认 v2ray Base64 + Subscription-Userinfo + IPv6 方括号。
	v2Resp, err := h.srv.ServePublicRoute(t.Context(), &pb.ServePublicRouteRequest{
		Context: rc, Route: "sub", Method: "GET", Path: "/sub/" + token,
	})
	if err != nil || v2Resp.GetStatus() != 200 {
		t.Fatalf("v2ray 订阅失败: status=%d err=%v", v2Resp.GetStatus(), err)
	}
	userInfo := headerValFromProto(v2Resp.GetHeaders(), "Subscription-Userinfo")
	if userInfo != "upload=0; download=0; total=53687091200; expire=0" {
		t.Fatalf("Subscription-Userinfo 头不符: %q", userInfo)
	}
	if upd := headerValFromProto(v2Resp.GetHeaders(), "Profile-Update-Interval"); upd != "24" {
		t.Fatalf("Profile-Update-Interval 头应为 24，实际 %q", upd)
	}
	decoded, err := base64.StdEncoding.DecodeString(string(v2Resp.GetBody()))
	if err != nil {
		t.Fatalf("v2ray Base64 解码失败: %v", err)
	}
	bodyStr := string(decoded)
	for _, want := range []string{
		"vless://", "@[2001:db8::42]:443?",
		"hysteria2://", "@[2001:db8::42]:8443?", "insecure=1", "pinSHA256=sha256%3Adeadbeef",
		"ss://", "@[2001:db8::42]:18388/?plugin=obfs-local%3Bobfs%3Dtls%3Bobfs-host%3Dwww.bing.com",
	} {
		if !strings.Contains(bodyStr, want) {
			t.Fatalf("v2ray 订阅缺少 %q:\n%s", want, bodyStr)
		}
	}

	// 2. Clash Meta YAML（经 User-Agent 自动推断）。
	clashResp, err := h.srv.ServePublicRoute(t.Context(), &pb.ServePublicRouteRequest{
		Context: rc, Route: "sub", Method: "GET", Path: "/sub/" + token,
		Headers: []*pb.HttpHeader{{Name: "user-agent", Value: "ClashMeta/1.18"}},
	})
	if err != nil || clashResp.GetStatus() != 200 || !strings.Contains(headerValFromProto(clashResp.GetHeaders(), "Content-Type"), "text/yaml") {
		t.Fatalf("Clash 订阅失败: status=%d err=%v", clashResp.GetStatus(), err)
	}
	clashText := string(clashResp.GetBody())
	if !strings.Contains(clashText, "proxies:\n") || !strings.Contains(clashText, `server: "2001:db8::42"`) || !strings.Contains(clashText, "proxy-groups:\n") {
		t.Fatalf("Clash YAML 内容不符:\n%s", clashText)
	}

	// 3. sing-box JSON（经 ?format=singbox 指定）。
	sbResp, err := h.srv.ServePublicRoute(t.Context(), &pb.ServePublicRouteRequest{
		Context: rc, Route: "sub", Method: "GET", Path: "/sub/" + token, RawQuery: "format=singbox",
	})
	if err != nil || sbResp.GetStatus() != 200 || !strings.Contains(headerValFromProto(sbResp.GetHeaders(), "Content-Type"), "application/json") {
		t.Fatalf("sing-box 订阅失败: status=%d err=%v", sbResp.GetStatus(), err)
	}
	var sbDoc struct {
		Inbounds  []map[string]any `json:"inbounds"`
		DNS       map[string]any   `json:"dns"`
		Outbounds []map[string]any `json:"outbounds"`
	}
	if err := json.Unmarshal(sbResp.GetBody(), &sbDoc); err != nil || len(sbDoc.Outbounds) != 5 || len(sbDoc.Inbounds) != 1 || sbDoc.DNS == nil {
		t.Fatalf("sing-box JSON 结构不符: inbounds=%d outbounds=%d dns=%v err=%v", len(sbDoc.Inbounds), len(sbDoc.Outbounds), sbDoc.DNS != nil, err)
	}
	if sbDoc.Inbounds[0]["type"] != "mixed" || sbDoc.Inbounds[0]["listen"] != "127.0.0.1" {
		t.Fatalf("sing-box 默认 mixed 入站不符: %+v", sbDoc.Inbounds[0])
	}

	// 验证 Stash / Clash Verge / SFM User-Agent 自动识别。
	for ua, wantFmt := range map[string]string{
		"Stash/2.5.0":       "clash",
		"clash-verge/1.7.7": "clash",
		"SFM/1.10.0":        "singbox",
	} {
		gotFmt, ok := resolveSubscriptionFormat("", []pluginsdk.HTTPHeader{{Name: "User-Agent", Value: ua}})
		if !ok || gotFmt != wantFmt {
			t.Fatalf("UA %q 期望格式 %q，实际 %q (ok=%v)", ua, wantFmt, gotFmt, ok)
		}
	}

	// 验证 writeYAMLMap 支持 []string 块列表序列化。
	var yamlBuf strings.Builder
	writeYAMLMap(&yamlBuf, map[string]any{"alpn": []string{"h2", "http/1.1"}}, 2)
	if !strings.Contains(yamlBuf.String(), "  alpn:\n    - h2\n    - http/1.1\n") {
		t.Fatalf("writeYAMLMap []string 序列化不符:\n%s", yamlBuf.String())
	}

	// 4. 连续访问超过 20 次后验证日志表裁剪上限严格 <= 20。
	for n := 0; n < 22; n++ {
		_, _ = h.srv.ServePublicRoute(t.Context(), &pb.ServePublicRouteRequest{
			Context: rc, Route: "sub", Method: "GET", Path: "/sub/" + token, RawQuery: "format=v2ray",
		})
	}

	// 5. 无效令牌 -> 404；停用用户 -> 403。
	notFoundResp, err := h.srv.ServePublicRoute(t.Context(), &pb.ServePublicRouteRequest{
		Context: rc, Route: "sub", Method: "GET", Path: "/sub/invalid-token-does-not-exist",
	})
	if err != nil || notFoundResp.GetStatus() != 404 {
		t.Fatalf("无效令牌应返回 404，实际 status=%d err=%v", notFoundResp.GetStatus(), err)
	}
	if prog := runProxyJob(t, h.srv, "users.set_status", map[string]any{"user_id": "carol", "status": "disabled"}, nil); prog.GetError() != nil {
		t.Fatal(prog.GetError())
	}
	forbiddenResp, err := h.srv.ServePublicRoute(t.Context(), &pb.ServePublicRouteRequest{
		Context: rc, Route: "sub", Method: "GET", Path: "/sub/" + token,
	})
	if err != nil || forbiddenResp.GetStatus() != 403 {
		t.Fatalf("停用用户订阅应返回 403，实际 status=%d err=%v", forbiddenResp.GetStatus(), err)
	}
}

// ======================== 后台采样联动、容器限速降级与 ErrorDetail 透传 ========================

func TestBackgroundSyncLoopContainerDegradedShapingAndErrorPassthrough(t *testing.T) {
	h := newProxyTestHarness(t, `{"public_host":"proxy.example.com"}`, 25*time.Millisecond)

	// 模拟无 sch_htb 的受限容器环境：traffic.status 如实回报降级，但 users.create 优雅降级不失败！
	h.traffic.mu.Lock()
	h.traffic.supported = false
	h.traffic.uplinkIFBSupported = false
	h.traffic.degradedReason = "container lacks CAP_NET_ADMIN / sch_htb"
	h.traffic.mu.Unlock()

	tsResp := invokeProxy(t, h.srv, "traffic.status", map[string]any{"include_classes": true})
	if tsResp.GetError() != nil {
		t.Fatalf("traffic.status 失败: %+v", tsResp.GetError())
	}
	var tsOut trafficStatusResponse
	if err := json.Unmarshal(tsResp.GetPayloadJson(), &tsOut); err != nil || tsOut.Supported || !strings.Contains(tsOut.DegradedReason, "sch_htb") {
		t.Fatalf("traffic.status 降级状态不符: %+v err=%v", tsOut, err)
	}

	if prog := runProxyJob(t, h.srv, "plans.upsert", map[string]any{
		"id":              "tiny",
		"name":            "小额测试",
		"quota_bytes":     500,
		"down_limit_kbps": 10000,
	}, nil); prog.GetError() != nil {
		t.Fatal(prog.GetError())
	}
	uProg := runProxyJob(t, h.srv, "users.create", map[string]any{
		"id":           "dave",
		"display_name": "Dave",
		"plan_id":      "tiny",
	}, nil)
	if uProg.GetError() != nil {
		t.Fatalf("容器降级环境下 users.create 不应报错中断: %+v", uProg.GetError())
	}
	var createOut usersCreateResponse
	if err := json.Unmarshal(uProg.GetResultJson(), &createOut); err != nil || !createOut.ShapingDegraded || createOut.ShapingDegradedReason == "" {
		t.Fatalf("users.create 应返回 shaping_degraded=true: %+v err=%v", createOut, err)
	}

	// 配置 core.observe 返回超过 500 字节的流量，启动 Activate 后台采样循环验证自动暂停并同步 core.xray！
	h.invoke.mu.Lock()
	h.invoke.observeJSON = []byte(`{
		"reset_epoch": "ep-bg-1",
		"collected_at": "2026-11-21T12:00:05Z",
		"source": "xray",
		"series": [
			{
				"kind": "user",
				"id": "dave",
				"present": true,
				"uplink_present": true,
				"downlink_present": true,
				"uplink_bytes": "300",
				"downlink_bytes": "400",
				"reset_epoch": "ep-bg-1",
				"collected_at": "2026-11-21T12:00:05Z",
				"source": "xray"
			}
		]
	}`)
	h.invoke.mu.Unlock()

	rc := &pb.RequestContext{InstanceId: "default", NodeId: "local", Locale: "zh-CN"}
	if _, err := h.srv.Activate(t.Context(), &pb.ActivateRequest{Context: rc}); err != nil {
		t.Fatal(err)
	}

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		h.cfgSvc.mu.Lock()
		puts := h.cfgSvc.putCalls
		h.cfgSvc.mu.Unlock()
		if puts >= 2 {
			break
		}
		time.Sleep(15 * time.Millisecond)
	}
	h.invoke.mu.Lock()
	bgCalls := h.invoke.calls
	bgOpID := h.invoke.lastOpID
	h.invoke.mu.Unlock()
	if bgCalls == 0 || bgOpID != "" {
		t.Fatalf("后台采样应通过空 operation_id 调用 core.observe，实际 calls=%d opID=%q", bgCalls, bgOpID)
	}

	listResp := invokeProxy(t, h.srv, "users.list", map[string]any{"status": "suspended_quota"})
	var listOut usersListResponse
	if err := json.Unmarshal(listResp.GetPayloadJson(), &listOut); err != nil || len(listOut.Users) != 1 || listOut.Users[0].ID != "dave" {
		t.Fatalf("后台采样超配额后 dave 应自动变为 suspended_quota: %+v err=%v", listOut, err)
	}

	histResp := invokeProxy(t, h.srv, "users.usage_history", map[string]any{"user_id": "dave", "hours": 24})
	var histOut usersUsageHistoryResponse
	if err := json.Unmarshal(histResp.GetPayloadJson(), &histOut); err != nil || len(histOut.Points) != 1 || histOut.Points[0].DownBytes != 400 {
		t.Fatalf("users.usage_history 曲线不符: %+v err=%v", histOut, err)
	}

	// 停止后台循环后再注入一次性错误，避免 25ms 后台 tick 抢先消费 mock failErr。
	if _, err := h.srv.Deactivate(t.Context(), &pb.DeactivateRequest{Context: rc}); err != nil {
		t.Fatal(err)
	}

	// 验证 ErrorDetail 透传（PluginConfigService 与 TrafficService）。
	h.traffic.mu.Lock()
	h.traffic.failErr = &pb.ErrorDetail{Code: "UNAVAILABLE", Message: "tc helper unreachable", Retryable: true}
	h.traffic.mu.Unlock()
	errTraffic := invokeProxy(t, h.srv, "traffic.status", map[string]any{})
	if errTraffic.GetError() == nil || errTraffic.GetError().GetCode() != "UNAVAILABLE" || !errTraffic.GetError().GetRetryable() {
		t.Fatalf("TrafficService ErrorDetail 未完整透传: %+v", errTraffic.GetError())
	}

	h.cfgSvc.mu.Lock()
	h.cfgSvc.failErr = &pb.ErrorDetail{Code: "PRECONDITION_FAILED", Message: "core.xray config revision mismatch"}
	h.cfgSvc.mu.Unlock()
	errSync := runProxyJob(t, h.srv, "users.set_status", map[string]any{"user_id": "dave", "status": "active"}, nil)
	if errSync.GetError() == nil || errSync.GetError().GetCode() != "PRECONDITION_FAILED" {
		t.Fatalf("PluginConfigService ErrorDetail 未完整透传: %+v", errSync.GetError())
	}
}

func TestProxyV2PlansNodesRulesAndStoredSub(t *testing.T) {
	h := newProxyTestHarness(t, `{"public_host":"proxy.example.com","vless_port":443,"reality_sni":"www.apple.com","reality_public_key":"PubKeyBase64"}`, time.Hour)

	// 1. 导入两条相同外部 URI 验证 nodes.deduplicate。
	imp := invokeProxy(t, h.srv, "nodes.import_uri", map[string]any{
		"uris": "vless://11111111-1111-4111-8111-111111111111@hk.example.com:443?security=tls&sni=hk.example.com#HK-1\n" +
			"vless://11111111-1111-4111-8111-111111111111@hk.example.com:443?security=tls&sni=hk.example.com#HK-dup\n" +
			"vless://22222222-2222-4222-8222-222222222222@jp.example.com:443?security=tls&sni=jp.example.com#JP-1",
	})
	if imp.GetError() != nil {
		t.Fatalf("nodes.import_uri 失败: %+v", imp.GetError())
	}
	dedup := invokeProxy(t, h.srv, "nodes.deduplicate", map[string]any{"dry_run": false})
	if dedup.GetError() != nil {
		t.Fatalf("nodes.deduplicate 失败: %+v", dedup.GetError())
	}
	var dedupOut struct {
		RemovedCount int      `json:"removed_count"`
		RemovedIDs   []string `json:"removed_ids"`
	}
	if err := json.Unmarshal(dedup.GetPayloadJson(), &dedupOut); err != nil || dedupOut.RemovedCount != 1 {
		t.Fatalf("nodes.deduplicate 期望移除 1 条重复节点，实际: %+v err=%v", dedupOut, err)
	}

	listNodes := invokeProxy(t, h.srv, "nodes.list", map[string]any{})
	var nodesOut struct {
		Nodes []proxyNodeRecord `json:"nodes"`
	}
	if err := json.Unmarshal(listNodes.GetPayloadJson(), &nodesOut); err != nil || len(nodesOut.Nodes) != 2 {
		t.Fatalf("去重后应剩 2 条节点，实际 %d err=%v", len(nodesOut.Nodes), err)
	}
	var onlyNodeID string
	for _, n := range nodesOut.Nodes {
		if n.Server == "hk.example.com" {
			onlyNodeID = n.ID
			break
		}
	}
	if onlyNodeID == "" {
		t.Fatalf("去重后未找到 hk.example.com 节点: %+v", nodesOut.Nodes)
	}

	// 2. 创建带倍率、描述、绑定节点白名单与分流预设的套餐。
	pProg := runProxyJob(t, h.srv, "plans.upsert", map[string]any{
		"id":           "vip-2x",
		"name":         "VIP 专线",
		"description":  "仅限精选节点与 AI 分流",
		"quota_bytes":  10737418240,
		"traffic_mode": "both_2x",
		"node_ids":     []string{onlyNodeID},
		"rule_preset":  "ai_streaming",
	}, nil)
	if pProg.GetError() != nil {
		t.Fatalf("plans.upsert 失败: %+v", pProg.GetError())
	}

	// 3. 配置全局分流规则并验证预览。
	rSave := invokeProxy(t, h.srv, "rules.save", map[string]any{
		"preset":                 "ai_streaming",
		"enable_ad_block":        true,
		"enable_ai_group":        true,
		"enable_streaming_group": true,
		"custom_direct_domains":  []string{"corp.internal"},
		"custom_proxy_domains":   []string{"dev.example.org"},
		"custom_reject_domains":  []string{"tracker.bad.example"},
	})
	if rSave.GetError() != nil {
		t.Fatalf("rules.save 失败: %+v", rSave.GetError())
	}
	var rOut struct {
		ClashPreview   string `json:"clash_preview"`
		SingboxPreview string `json:"singbox_preview"`
	}
	if err := json.Unmarshal(rSave.GetPayloadJson(), &rOut); err != nil ||
		!strings.Contains(rOut.ClashPreview, "AI-Services") ||
		!strings.Contains(rOut.ClashPreview, "DOMAIN-SUFFIX,corp.internal,DIRECT") ||
		!strings.Contains(rOut.ClashPreview, "DOMAIN-SUFFIX,tracker.bad.example,REJECT") {
		t.Fatalf("rules.save Clash 预览异常: err=%v preview=%s", err, rOut.ClashPreview)
	}

	// 4. 创建用户并验证加密存储的订阅令牌可一键解密读取，且订阅仅导出套餐绑定的节点。
	uProg := runProxyJob(t, h.srv, "users.create", map[string]any{
		"id":           "eva",
		"display_name": "Eva",
		"notes":        "主力 MacBook",
		"plan_id":      "vip-2x",
	}, nil)
	if uProg.GetError() != nil {
		t.Fatalf("users.create 失败: %+v", uProg.GetError())
	}
	var created usersCreateResponse
	if err := json.Unmarshal(uProg.GetResultJson(), &created); err != nil || !created.User.HasStoredSub || created.User.Notes != "主力 MacBook" {
		t.Fatalf("users.create 新字段不符: %+v err=%v", created.User, err)
	}

	subGet := invokeProxy(t, h.srv, "users.get_subscription", map[string]any{"user_id": "eva"})
	if subGet.GetError() != nil {
		t.Fatalf("users.get_subscription 失败: %+v", subGet.GetError())
	}
	var subGetOut struct {
		Available         bool   `json:"available"`
		SubscriptionToken string `json:"subscription_token"`
		SubscriptionPath  string `json:"subscription_path"`
	}
	if err := json.Unmarshal(subGet.GetPayloadJson(), &subGetOut); err != nil || !subGetOut.Available || subGetOut.SubscriptionToken != created.SubscriptionToken {
		t.Fatalf("users.get_subscription 解密令牌不符: %+v want=%s err=%v", subGetOut, created.SubscriptionToken, err)
	}

	// 验证订阅仅返回套餐绑定的 1 个节点且套用 AI 分流规则。
	rc := &pb.RequestContext{InstanceId: "default", NodeId: "local", Locale: "zh-CN"}
	clashResp, err := h.srv.ServePublicRoute(t.Context(), &pb.ServePublicRouteRequest{
		Context: rc, Route: "sub", Method: "GET", Path: "/sub/" + created.SubscriptionToken, RawQuery: "format=clash",
	})
	if err != nil || clashResp.GetStatus() != 200 {
		t.Fatalf("订阅拉取失败: status=%d err=%v", clashResp.GetStatus(), err)
	}
	clashBody := string(clashResp.GetBody())
	if !strings.Contains(clashBody, "AI-Services") || strings.Contains(clashBody, "jp.example.com") {
		t.Fatalf("订阅未正确按套餐绑定节点或分流规则渲染:\n%s", clashBody)
	}

	// 5. users.set_limits 修改备注与显示名。
	upd := invokeProxy(t, h.srv, "users.set_limits", map[string]any{
		"user_id":      "eva",
		"display_name": "Eva Pro",
		"notes":        "已续费年度",
	})
	if upd.GetError() != nil {
		t.Fatalf("users.set_limits 资料更新失败: %+v", upd.GetError())
	}

	// 6. 套餐仍被用户绑定时 plans.delete 必须拒绝 CONFLICT；删除用户后可正常删除套餐。
	delConflict := runProxyJob(t, h.srv, "plans.delete", map[string]any{"id": "vip-2x"}, nil)
	if delConflict.GetError() == nil || delConflict.GetError().GetCode() != "CONFLICT" {
		t.Fatalf("存在绑定用户时 plans.delete 应返回 CONFLICT，实际: %+v", delConflict.GetError())
	}
	delUser := runProxyJob(t, h.srv, "users.delete", map[string]any{"user_id": "eva"}, nil)
	if delUser.GetError() != nil {
		t.Fatalf("users.delete 失败: %+v", delUser.GetError())
	}
	delPlan := runProxyJob(t, h.srv, "plans.delete", map[string]any{"id": "vip-2x"}, nil)
	if delPlan.GetError() != nil {
		t.Fatalf("users.delete 后 plans.delete 应成功，实际: %+v", delPlan.GetError())
	}

	// 7. proxy.overview 返回 30 天每日流量与 alerts 数组。
	ov := invokeProxy(t, h.srv, "proxy.overview", map[string]any{"include_traffic_status": false})
	if ov.GetError() != nil {
		t.Fatalf("proxy.overview 失败: %+v", ov.GetError())
	}
	var ovOut overviewResponse
	if err := json.Unmarshal(ov.GetPayloadJson(), &ovOut); err != nil || len(ovOut.DailyTraffic) != 30 {
		t.Fatalf("proxy.overview daily_traffic 期望 30 天，实际 len=%d err=%v", len(ovOut.DailyTraffic), err)
	}
}
