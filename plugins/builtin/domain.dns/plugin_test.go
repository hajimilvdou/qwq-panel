// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/test/bufconn"

	dnsv1 "github.com/qwq-panel/qwq/sdk/gen/qwq/capability/dns/v1"
	pb "github.com/qwq-panel/qwq/sdk/gen/qwq/platform/v1"
	"github.com/qwq-panel/qwq/sdk/manifest"
	"github.com/qwq-panel/qwq/sdk/pluginsdk"
)

// ======================== 宿主 DNS 能力与状态 KV 测试夹具 ========================

type fakeHostState struct {
	pb.UnimplementedHostStateServiceServer
	mu   sync.Mutex
	data map[string][]byte
}

func (s *fakeHostState) GetState(_ context.Context, req *pb.GetStateRequest) (*pb.GetStateResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	val, ok := s.data[req.GetKey()]
	if !ok {
		return &pb.GetStateResponse{Found: false}, nil
	}
	return &pb.GetStateResponse{Found: true, Revision: "1", ValueJson: append([]byte(nil), val...)}, nil
}

func (s *fakeHostState) PutState(_ context.Context, req *pb.PutStateRequest) (*pb.PutStateResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.data == nil {
		s.data = make(map[string][]byte)
	}
	s.data[req.GetKey()] = append([]byte(nil), req.GetValueJson()...)
	return &pb.PutStateResponse{Revision: "2"}, nil
}

type fakeDNSService struct {
	dnsv1.UnimplementedDnsServiceServer
	mu      sync.Mutex
	calls   []string
	lastRev string
	failErr *pb.ErrorDetail
}

func (s *fakeDNSService) record(method, rev string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls = append(s.calls, method)
	s.lastRev = rev
}

func (s *fakeDNSService) getLastRev() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastRev
}

func (s *fakeDNSService) nextErr() *pb.ErrorDetail {
	s.mu.Lock()
	defer s.mu.Unlock()
	e := s.failErr
	s.failErr = nil
	return e
}

func (s *fakeDNSService) ListProviders(_ context.Context, req *dnsv1.ListProvidersRequest) (*dnsv1.ListProvidersResponse, error) {
	s.record("ListProviders", "")
	if e := s.nextErr(); e != nil {
		return &dnsv1.ListProvidersResponse{Error: e}, nil
	}
	if req.GetContext() == nil || req.GetContext().GetInstanceHandle() != "dns-handle" {
		return &dnsv1.ListProvidersResponse{Error: &pb.ErrorDetail{Code: "PERMISSION_DENIED", Message: "bad handle"}}, nil
	}
	return &dnsv1.ListProvidersResponse{
		Providers: []*dnsv1.ProviderView{
			{Id: "cf-main", Kind: "cloudflare", Name: "主账号", Revision: "rev-1", Enabled: true, ZoneCount: 2},
			{Id: "ali-bak", Kind: "aliyun", Name: "备用", Revision: "rev-2", Enabled: false, ZoneCount: 1},
		},
	}, nil
}

func (s *fakeDNSService) RegisterProvider(_ context.Context, req *dnsv1.RegisterProviderRequest) (*dnsv1.RegisterProviderResponse, error) {
	s.record("RegisterProvider", req.GetExpectedRevision())
	if e := s.nextErr(); e != nil {
		return &dnsv1.RegisterProviderResponse{Error: e}, nil
	}
	return &dnsv1.RegisterProviderResponse{
		Provider: &dnsv1.ProviderView{Id: req.GetProviderId(), Kind: "cloudflare", Name: "主账号", Revision: "rev-2", Enabled: true, ZoneCount: 1},
		Zones:    []*dnsv1.ZoneView{{ProviderId: req.GetProviderId(), ZoneId: "zone-1", Name: "example.com", Revision: "z-1", Authorized: false}},
	}, nil
}

func (s *fakeDNSService) DiscoverZones(_ context.Context, req *dnsv1.DiscoverZonesRequest) (*dnsv1.DiscoverZonesResponse, error) {
	s.record("DiscoverZones", "")
	return &dnsv1.DiscoverZonesResponse{
		Zones: []*dnsv1.ZoneView{{ProviderId: req.GetProviderId(), ZoneId: "zone-1", Name: "example.com", Revision: "z-1", Authorized: true}},
	}, nil
}

func (s *fakeDNSService) RevokeProvider(_ context.Context, req *dnsv1.RevokeProviderRequest) (*dnsv1.RevokeProviderResponse, error) {
	s.record("RevokeProvider", req.GetExpectedRevision())
	return &dnsv1.RevokeProviderResponse{
		Provider: &dnsv1.ProviderView{Id: req.GetProviderId(), Kind: "cloudflare", Name: "主账号", Revision: "rev-3", Enabled: false, ZoneCount: 1},
	}, nil
}

func (s *fakeDNSService) AuthorizeZone(_ context.Context, req *dnsv1.AuthorizeZoneRequest) (*dnsv1.AuthorizeZoneResponse, error) {
	s.record("AuthorizeZone", req.GetExpectedRevision())
	return &dnsv1.AuthorizeZoneResponse{
		Zone: &dnsv1.ZoneView{ProviderId: req.GetProviderId(), ZoneId: req.GetZoneId(), Name: "example.com", Revision: "z-2", Authorized: true},
	}, nil
}

func (s *fakeDNSService) RevokeZone(_ context.Context, req *dnsv1.RevokeZoneRequest) (*dnsv1.RevokeZoneResponse, error) {
	s.record("RevokeZone", req.GetExpectedRevision())
	return &dnsv1.RevokeZoneResponse{
		Zone: &dnsv1.ZoneView{ProviderId: req.GetProviderId(), ZoneId: req.GetZoneId(), Name: "example.com", Revision: "z-3", Authorized: false},
	}, nil
}

func (s *fakeDNSService) ListRecords(_ context.Context, _ *dnsv1.ListRecordsRequest) (*dnsv1.ListRecordsResponse, error) {
	s.record("ListRecords", "")
	return &dnsv1.ListRecordsResponse{
		Revision: "snap-1",
		Records:  []*dnsv1.RecordView{{Id: "rec-1", Type: "A", Name: "app.example.com", Value: "198.51.100.10", Ttl: 120, Revision: "r-1"}},
	}, nil
}

func (s *fakeDNSService) ApplyRecord(_ context.Context, req *dnsv1.ApplyRecordRequest) (*dnsv1.ApplyRecordResponse, error) {
	s.record("ApplyRecord", req.GetExpectedRevision())
	return &dnsv1.ApplyRecordResponse{
		State:    "applied",
		Revision: "snap-2",
		Record:   &dnsv1.RecordView{Id: "rec-2", Type: "A", Name: "api.example.com", Value: "198.51.100.20", Ttl: 120, Revision: "r-2"},
	}, nil
}

func (s *fakeDNSService) ReconcileRecord(_ context.Context, _ *dnsv1.ReconcileRecordRequest) (*dnsv1.ReconcileRecordResponse, error) {
	s.record("ReconcileRecord", "")
	return &dnsv1.ReconcileRecordResponse{
		State:    "applied",
		Revision: "snap-2",
		Record:   &dnsv1.RecordView{Id: "rec-2", Type: "A", Name: "api.example.com", Value: "198.51.100.20", Ttl: 120, Revision: "r-2"},
	}, nil
}

func (s *fakeDNSService) CheckDns(_ context.Context, _ *dnsv1.CheckDnsRequest) (*dnsv1.CheckDnsResponse, error) {
	s.record("CheckDns", "")
	return &dnsv1.CheckDnsResponse{
		Propagated: true,
		Observations: []*dnsv1.ObservationView{
			{Source: "1.1.1.1", Kind: "public", Values: []string{"198.51.100.20"}, CollectedAt: "2026-11-21T00:00:00Z"},
		},
	}, nil
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

func newDNSTestServer(t *testing.T) (*pluginsdk.Server, *fakeDNSService, *fakeHostState) {
	t.Helper()
	listener := bufconn.Listen(128 << 10)
	hostServer := grpc.NewServer()
	dnsSvc := &fakeDNSService{}
	kvSvc := &fakeHostState{}
	dnsv1.RegisterDnsServiceServer(hostServer, dnsSvc)
	pb.RegisterHostStateServiceServer(hostServer, kvSvc)
	go func() { _ = hostServer.Serve(listener) }()
	t.Cleanup(func() { hostServer.Stop(); _ = listener.Close() })

	conn, err := grpc.NewClient("passthrough:///dns-host",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return listener.Dial() }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	plugin := &Plugin{now: func() time.Time { return time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC) }}
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

	rc := &pb.RequestContext{InstanceId: "default", NodeId: "local", Locale: "zh-CN"}
	if _, err := srv.Initialize(t.Context(), &pb.InitializeRequest{Context: rc, InstanceHandle: "dns-handle", ConfigJson: []byte(`{}`), ConfigRevision: "1"}); err != nil {
		t.Fatal(err)
	}
	if _, err := srv.Start(t.Context(), &pb.StartRequest{Context: rc}); err != nil {
		t.Fatal(err)
	}
	return srv, dnsSvc, kvSvc
}

func runDNSJob(t *testing.T, srv *pluginsdk.Server, op string, payload any, pre []*pb.Precondition) *pb.JobProgress {
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
		Context:       &pb.RequestContext{InstanceId: "default", NodeId: "local", OperationId: "op-" + op, Locale: "zh-CN"},
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

// ======================== Manifest 与全部 11 项操作验证 ========================

func TestDNSManifestAndPackageDigests(t *testing.T) {
	parsed, err := manifest.Parse(Manifest())
	if err != nil {
		t.Fatal(err)
	}
	if parsed.ID != "domain.dns" || parsed.Placement != "controller" || parsed.Lifecycle.Startup != "on_demand" || parsed.Lifecycle.Background {
		t.Fatalf("manifest 元数据不符：%+v", parsed)
	}
	if parsed.Resources.MemoryMaxMB != 32 || parsed.Resources.PIDsMax != 16 || parsed.Resources.FDsMax != 128 {
		t.Fatalf("资源上限不符：%+v", parsed.Resources)
	}
	if len(parsed.Operations) != 11 {
		t.Fatalf("操作数量=%d，期望=11", len(parsed.Operations))
	}
	for name, digest := range parsed.Files {
		if name == parsed.Entrypoint {
			continue
		}
		raw, err := os.ReadFile(name)
		if err != nil {
			t.Fatalf("缺失文件 %s：%v", name, err)
		}
		sum := sha256.Sum256(raw)
		if digest != "sha256:"+hex.EncodeToString(sum[:]) {
			t.Fatalf("文件摘要漂移：%s", name)
		}
	}
}

func TestDNSAllOperationsSummaryAndErrorPassthrough(t *testing.T) {
	srv, dnsSvc, kvSvc := newDNSTestServer(t)
	rc := &pb.RequestContext{InstanceId: "default", NodeId: "local", Locale: "zh-CN"}

	// 1. providers.status（初始空 KV）
	statusResp, err := srv.Invoke(t.Context(), &pb.InvokeRequest{Context: rc, Operation: "providers.status", ApiVersion: "v1", PayloadJson: []byte(`{}`)})
	if err != nil || statusResp.GetError() != nil {
		t.Fatalf("providers.status 失败：%v %v", err, statusResp.GetError())
	}
	var statusOut providerStatusResponse
	if err := json.Unmarshal(statusResp.GetPayloadJson(), &statusOut); err != nil || statusOut.Total != 0 || statusOut.Value != 0 {
		t.Fatalf("初始 providers.status 异常：%s %v", statusResp.GetPayloadJson(), err)
	}

	// 2. providers.list（刷新本地脱敏摘要 KV）
	listProg := runDNSJob(t, srv, "providers.list", map[string]any{}, nil)
	if !listProg.GetCompleted() || listProg.GetError() != nil {
		t.Fatalf("providers.list 失败：%+v", listProg)
	}
	statusResp, err = srv.Invoke(t.Context(), &pb.InvokeRequest{Context: rc, Operation: "providers.status", ApiVersion: "v1", PayloadJson: []byte(`{}`)})
	if err != nil || statusResp.GetError() != nil {
		t.Fatalf("更新后 providers.status 失败：%v %v", err, statusResp.GetError())
	}
	if err := json.Unmarshal(statusResp.GetPayloadJson(), &statusOut); err != nil || statusOut.Total != 2 || statusOut.Enabled != 1 || statusOut.Zones != 3 {
		t.Fatalf("摘要未同步：%+v", statusOut)
	}

	// 3. providers.register（传入凭据字段，确保不落入 KV 摘要）
	regProg := runDNSJob(t, srv, "providers.register", map[string]any{
		"provider_id": "cf-new",
		"kind":        "cloudflare",
		"name":        "新账号",
		"credential":  map[string]string{"token": "should-never-enter-kv"},
	}, []*pb.Precondition{{Subject: "providers/cf-new", Revision: "absent"}})
	if !regProg.GetCompleted() || regProg.GetError() != nil || dnsSvc.getLastRev() != "absent" {
		t.Fatalf("providers.register 失败：%+v rev=%q", regProg, dnsSvc.getLastRev())
	}
	kvSvc.mu.Lock()
	kvSnapshot := string(kvSvc.data[providerSummaryKey])
	kvSvc.mu.Unlock()
	if strings.Contains(kvSnapshot, "should-never-enter-kv") {
		t.Fatal("KV 摘要意外包含敏感凭据文本")
	}

	// 4. providers.zones
	zonesProg := runDNSJob(t, srv, "providers.zones", map[string]any{"provider_id": "cf-new"}, nil)
	if !zonesProg.GetCompleted() || zonesProg.GetError() != nil {
		t.Fatalf("providers.zones 失败：%+v", zonesProg)
	}

	// 5. providers.revoke
	revokeProvProg := runDNSJob(t, srv, "providers.revoke", map[string]any{"provider_id": "cf-new"}, []*pb.Precondition{{Subject: "providers/cf-new", Revision: "rev-2"}})
	if !revokeProvProg.GetCompleted() || revokeProvProg.GetError() != nil || dnsSvc.getLastRev() != "rev-2" {
		t.Fatalf("providers.revoke 失败：%+v rev=%q", revokeProvProg, dnsSvc.getLastRev())
	}

	// 6. zones.authorize
	authZoneProg := runDNSJob(t, srv, "zones.authorize", map[string]any{"provider_id": "cf-main", "zone_id": "zone-1"}, []*pb.Precondition{{Subject: "zones/cf-main/zone-1", Revision: "absent"}})
	if !authZoneProg.GetCompleted() || authZoneProg.GetError() != nil || dnsSvc.getLastRev() != "absent" {
		t.Fatalf("zones.authorize 失败：%+v", authZoneProg)
	}

	// 7. zones.revoke
	revZoneProg := runDNSJob(t, srv, "zones.revoke", map[string]any{"provider_id": "cf-main", "zone_id": "zone-1"}, []*pb.Precondition{{Subject: "zones/cf-main/zone-1", Revision: "z-2"}})
	if !revZoneProg.GetCompleted() || revZoneProg.GetError() != nil || dnsSvc.getLastRev() != "z-2" {
		t.Fatalf("zones.revoke 失败：%+v", revZoneProg)
	}

	// 8. records.list
	listRecProg := runDNSJob(t, srv, "records.list", map[string]any{"provider_id": "cf-main", "zone_id": "zone-1"}, nil)
	if !listRecProg.GetCompleted() || listRecProg.GetError() != nil {
		t.Fatalf("records.list 失败：%+v", listRecProg)
	}

	// 9. records.apply
	applyRecProg := runDNSJob(t, srv, "records.apply", map[string]any{
		"provider_id": "cf-main",
		"zone_id":     "zone-1",
		"attempt_id":  "att-1",
		"change":      map[string]any{"action": "create", "record": map[string]any{"type": "A", "name": "api.example.com", "value": "198.51.100.20"}},
	}, []*pb.Precondition{{Subject: "zones/cf-main/zone-1", Revision: "snap-1"}})
	if !applyRecProg.GetCompleted() || applyRecProg.GetError() != nil || dnsSvc.getLastRev() != "snap-1" {
		t.Fatalf("records.apply 失败：%+v", applyRecProg)
	}

	// 10. records.reconcile
	recRecProg := runDNSJob(t, srv, "records.reconcile", map[string]any{"provider_id": "cf-main", "zone_id": "zone-1", "attempt_id": "att-1"}, nil)
	if !recRecProg.GetCompleted() || recRecProg.GetError() != nil {
		t.Fatalf("records.reconcile 失败：%+v", recRecProg)
	}

	// 11. dns.check
	checkProg := runDNSJob(t, srv, "dns.check", map[string]any{
		"provider_id": "cf-main", "zone_id": "zone-1", "name": "api.example.com", "type": "A", "value": "198.51.100.20",
	}, nil)
	if !checkProg.GetCompleted() || checkProg.GetError() != nil {
		t.Fatalf("dns.check 失败：%+v", checkProg)
	}

	// 12. proto ErrorDetail 透传为 pluginsdk.Error
	dnsSvc.mu.Lock()
	dnsSvc.failErr = &pb.ErrorDetail{Code: "REVISION_CONFLICT", Message: "提供商版本已变化"}
	dnsSvc.mu.Unlock()
	errProg := runDNSJob(t, srv, "providers.register", map[string]any{"provider_id": "cf-main"}, nil)
	if errProg.GetError() == nil || errProg.GetError().GetCode() != "REVISION_CONFLICT" {
		t.Fatalf("proto 错误未正确透传：%+v", errProg.GetError())
	}
}
