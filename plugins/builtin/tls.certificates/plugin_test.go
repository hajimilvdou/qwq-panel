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

	certificatesv1 "github.com/qwq-panel/qwq/sdk/gen/qwq/capability/certificates/v1"
	pb "github.com/qwq-panel/qwq/sdk/gen/qwq/platform/v1"
	"github.com/qwq-panel/qwq/sdk/manifest"
	"github.com/qwq-panel/qwq/sdk/pluginsdk"
)

// ======================== 宿主证书能力与 KV 夹具 ========================

type fakeCertHostState struct {
	pb.UnimplementedHostStateServiceServer
	mu   sync.Mutex
	data map[string][]byte
}

func (s *fakeCertHostState) GetState(_ context.Context, req *pb.GetStateRequest) (*pb.GetStateResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	val, ok := s.data[req.GetKey()]
	if !ok {
		return &pb.GetStateResponse{Found: false}, nil
	}
	return &pb.GetStateResponse{Found: true, Revision: "1", ValueJson: append([]byte(nil), val...)}, nil
}

func (s *fakeCertHostState) PutState(_ context.Context, req *pb.PutStateRequest) (*pb.PutStateResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.data == nil {
		s.data = make(map[string][]byte)
	}
	s.data[req.GetKey()] = append([]byte(nil), req.GetValueJson()...)
	return &pb.PutStateResponse{Revision: "2"}, nil
}

type fakeCertsService struct {
	certificatesv1.UnimplementedCertificatesServiceServer
	mu           sync.Mutex
	lastRev      string
	getTaskSteps []*certificatesv1.TaskView
	getTaskIdx   int
	blockTask    bool
	taskStarted  chan struct{}
	canceledIDs  []string
	cancelDone   chan string
	failErr      *pb.ErrorDetail
}

func (s *fakeCertsService) nextErr() *pb.ErrorDetail {
	s.mu.Lock()
	defer s.mu.Unlock()
	e := s.failErr
	s.failErr = nil
	return e
}

func (s *fakeCertsService) getLastRev() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastRev
}

func sampleCertView(id string) *certificatesv1.CertificateView {
	return &certificatesv1.CertificateView{
		Id:               id,
		Revision:         "rev-1",
		Sans:             []string{"app.example.com"},
		Purpose:          "tls_server",
		Status:           "ready",
		LatestGeneration: 1,
		Generations: []*certificatesv1.GenerationView{
			{Number: 1, Fingerprint: strings.Repeat("a", 64), Issuer: "Test CA", NotBefore: "2026-11-21T00:00:00Z", NotAfter: "2027-02-19T00:00:00Z", Trust: "public"},
		},
		Bindings: []*certificatesv1.BindingView{
			{BindingRef: "bind-1", PluginId: "core.xray", ProfileId: "h2-a", NodeId: "local", ServerName: "app.example.com", Purpose: "proxy.hysteria2", Generation: 1, RunningGeneration: 1, PolicyRevision: "p-1", Status: "deployed"},
		},
	}
}

func (s *fakeCertsService) ListCertificates(_ context.Context, req *certificatesv1.ListCertificatesRequest) (*certificatesv1.ListCertificatesResponse, error) {
	if req.GetContext() == nil || req.GetContext().GetInstanceHandle() != "certs-handle" {
		return &certificatesv1.ListCertificatesResponse{Error: &pb.ErrorDetail{Code: "PERMISSION_DENIED", Message: "bad handle"}}, nil
	}
	c1 := sampleCertView("cert-ready")
	c2 := sampleCertView("cert-attention")
	c2.Status = "issued_deployment_failed"
	return &certificatesv1.ListCertificatesResponse{Certificates: []*certificatesv1.CertificateView{c1, c2}}, nil
}

func (s *fakeCertsService) GetCertificate(_ context.Context, req *certificatesv1.GetCertificateRequest) (*certificatesv1.GetCertificateResponse, error) {
	if e := s.nextErr(); e != nil {
		return &certificatesv1.GetCertificateResponse{Error: e}, nil
	}
	return &certificatesv1.GetCertificateResponse{Certificate: sampleCertView(req.GetCertificateId())}, nil
}

func (s *fakeCertsService) SubmitIssue(_ context.Context, req *certificatesv1.SubmitIssueRequest) (*certificatesv1.SubmitIssueResponse, error) {
	s.mu.Lock()
	s.lastRev = req.GetExpectedRevision()
	s.mu.Unlock()
	if e := s.nextErr(); e != nil {
		return &certificatesv1.SubmitIssueResponse{Error: e}, nil
	}
	return &certificatesv1.SubmitIssueResponse{
		Task: &certificatesv1.TaskView{
			Id: "task-issue-1", CertificateId: req.GetCertificateId(), Status: "queued", Stage: "queued", Percent: 5, Revision: "t-1",
		},
	}, nil
}

func (s *fakeCertsService) SubmitImport(_ context.Context, req *certificatesv1.SubmitImportRequest) (*certificatesv1.SubmitImportResponse, error) {
	s.mu.Lock()
	s.lastRev = req.GetExpectedRevision()
	s.mu.Unlock()
	return &certificatesv1.SubmitImportResponse{
		Task: &certificatesv1.TaskView{
			Id: "task-import-1", CertificateId: req.GetCertificateId(), Status: "succeeded", Stage: "completed", Percent: 100, Revision: "t-1",
		},
	}, nil
}

func (s *fakeCertsService) SubmitTestCertificate(_ context.Context, req *certificatesv1.SubmitTestCertificateRequest) (*certificatesv1.SubmitTestCertificateResponse, error) {
	s.mu.Lock()
	s.lastRev = req.GetExpectedRevision()
	s.mu.Unlock()
	return &certificatesv1.SubmitTestCertificateResponse{
		Task: &certificatesv1.TaskView{
			Id: "task-test-1", CertificateId: req.GetCertificateId(), Status: "succeeded", Stage: "completed", Percent: 100, Revision: "t-1",
		},
	}, nil
}

func (s *fakeCertsService) GetTask(_ context.Context, req *certificatesv1.GetTaskRequest) (*certificatesv1.GetTaskResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.blockTask {
		if s.taskStarted != nil {
			select {
			case <-s.taskStarted:
			default:
				close(s.taskStarted)
			}
		}
		return &certificatesv1.GetTaskResponse{
			Task: &certificatesv1.TaskView{Id: req.GetTaskId(), CertificateId: "cert-cancel", Status: "running", Stage: "waiting_dns", Percent: 40, Revision: "t-2"},
		}, nil
	}
	if s.getTaskIdx < len(s.getTaskSteps) {
		step := s.getTaskSteps[s.getTaskIdx]
		s.getTaskIdx++
		return &certificatesv1.GetTaskResponse{Task: step}, nil
	}
	return &certificatesv1.GetTaskResponse{
		Task: &certificatesv1.TaskView{Id: req.GetTaskId(), CertificateId: "cert-1", Status: "succeeded", Stage: "completed", Percent: 100, Revision: "t-end"},
	}, nil
}

func (s *fakeCertsService) CancelTask(_ context.Context, req *certificatesv1.CancelTaskRequest) (*certificatesv1.CancelTaskResponse, error) {
	s.mu.Lock()
	s.canceledIDs = append(s.canceledIDs, req.GetTaskId())
	ch := s.cancelDone
	s.mu.Unlock()
	if ch != nil {
		select {
		case ch <- req.GetTaskId():
		default:
		}
	}
	return &certificatesv1.CancelTaskResponse{
		Task: &certificatesv1.TaskView{Id: req.GetTaskId(), Status: "cancelled", Stage: "cleaning_dns", Percent: 100, Revision: "t-cancel"},
	}, nil
}

func (s *fakeCertsService) ReserveBinding(_ context.Context, req *certificatesv1.ReserveBindingRequest) (*certificatesv1.ReserveBindingResponse, error) {
	s.mu.Lock()
	s.lastRev = req.GetExpectedRevision()
	s.mu.Unlock()
	return &certificatesv1.ReserveBindingResponse{
		BindingRef:    "certbind_reserved_1",
		CertificateId: req.GetCertificateId(),
		Revision:      "1",
		Status:        "reserved",
	}, nil
}

func (s *fakeCertsService) BindCertificate(_ context.Context, req *certificatesv1.BindCertificateRequest) (*certificatesv1.BindCertificateResponse, error) {
	s.mu.Lock()
	s.lastRev = req.GetExpectedRevision()
	s.mu.Unlock()
	return &certificatesv1.BindCertificateResponse{Certificate: sampleCertView(req.GetCertificateId())}, nil
}

func (s *fakeCertsService) DeployBinding(_ context.Context, req *certificatesv1.DeployBindingRequest) (*certificatesv1.DeployBindingResponse, error) {
	s.mu.Lock()
	s.lastRev = req.GetExpectedRevision()
	s.mu.Unlock()
	return &certificatesv1.DeployBindingResponse{Certificate: sampleCertView(req.GetCertificateId())}, nil
}

func (s *fakeCertsService) RollbackBinding(_ context.Context, req *certificatesv1.RollbackBindingRequest) (*certificatesv1.RollbackBindingResponse, error) {
	s.mu.Lock()
	s.lastRev = req.GetExpectedRevision()
	s.mu.Unlock()
	return &certificatesv1.RollbackBindingResponse{Certificate: sampleCertView(req.GetCertificateId())}, nil
}

func (s *fakeCertsService) UnbindCertificate(_ context.Context, req *certificatesv1.UnbindCertificateRequest) (*certificatesv1.UnbindCertificateResponse, error) {
	s.mu.Lock()
	s.lastRev = req.GetExpectedRevision()
	s.mu.Unlock()
	return &certificatesv1.UnbindCertificateResponse{Certificate: sampleCertView(req.GetCertificateId())}, nil
}

func (s *fakeCertsService) RemoveGeneration(_ context.Context, req *certificatesv1.RemoveGenerationRequest) (*certificatesv1.RemoveGenerationResponse, error) {
	s.mu.Lock()
	s.lastRev = req.GetExpectedRevision()
	s.mu.Unlock()
	return &certificatesv1.RemoveGenerationResponse{Certificate: sampleCertView(req.GetCertificateId())}, nil
}

func (s *fakeCertsService) RemoveCertificate(_ context.Context, req *certificatesv1.RemoveCertificateRequest) (*certificatesv1.RemoveCertificateResponse, error) {
	s.mu.Lock()
	s.lastRev = req.GetExpectedRevision()
	s.mu.Unlock()
	return &certificatesv1.RemoveCertificateResponse{}, nil
}

func (s *fakeCertsService) ConfigureRenewal(_ context.Context, req *certificatesv1.ConfigureRenewalRequest) (*certificatesv1.ConfigureRenewalResponse, error) {
	s.mu.Lock()
	s.lastRev = req.GetExpectedRevision()
	s.mu.Unlock()
	return &certificatesv1.ConfigureRenewalResponse{
		Renewal: &certificatesv1.RenewalView{Id: "pol-1", CertificateId: req.GetCertificateId(), Revision: "p-rev-1", Enabled: false, Status: "awaiting_service"},
	}, nil
}

func (s *fakeCertsService) RevokeRenewal(_ context.Context, req *certificatesv1.RevokeRenewalRequest) (*certificatesv1.RevokeRenewalResponse, error) {
	s.mu.Lock()
	s.lastRev = req.GetExpectedRevision()
	s.mu.Unlock()
	return &certificatesv1.RevokeRenewalResponse{
		Renewal: &certificatesv1.RenewalView{Id: req.GetPolicyId(), CertificateId: "cert-1", Revision: "p-rev-2", Enabled: false, Status: "revoked"},
	}, nil
}

func (s *fakeCertsService) GetRenewal(_ context.Context, req *certificatesv1.GetRenewalRequest) (*certificatesv1.GetRenewalResponse, error) {
	return &certificatesv1.GetRenewalResponse{
		Renewal: &certificatesv1.RenewalView{Id: "pol-1", CertificateId: req.GetCertificateId(), Revision: "p-rev-1", Enabled: true, Status: "active", NextAt: "2027-01-20T00:00:00Z"},
	}, nil
}

type captureCertJobStream struct {
	ctx      context.Context
	mu       sync.Mutex
	messages []*pb.RunJobResponse
}

func (s *captureCertJobStream) Send(msg *pb.RunJobResponse) error {
	s.mu.Lock()
	s.messages = append(s.messages, msg)
	s.mu.Unlock()
	return nil
}
func (s *captureCertJobStream) SetHeader(metadata.MD) error  { return nil }
func (s *captureCertJobStream) SendHeader(metadata.MD) error { return nil }
func (s *captureCertJobStream) SetTrailer(metadata.MD)       {}
func (s *captureCertJobStream) Context() context.Context     { return s.ctx }
func (s *captureCertJobStream) SendMsg(any) error            { return nil }
func (s *captureCertJobStream) RecvMsg(any) error            { return nil }

func newCertsTestServer(t *testing.T) (*pluginsdk.Server, *fakeCertsService, *fakeCertHostState) {
	t.Helper()
	listener := bufconn.Listen(128 << 10)
	hostServer := grpc.NewServer()
	certsSvc := &fakeCertsService{}
	kvSvc := &fakeCertHostState{}
	certificatesv1.RegisterCertificatesServiceServer(hostServer, certsSvc)
	pb.RegisterHostStateServiceServer(hostServer, kvSvc)
	go func() { _ = hostServer.Serve(listener) }()
	t.Cleanup(func() { hostServer.Stop(); _ = listener.Close() })

	conn, err := grpc.NewClient("passthrough:///certs-host",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return listener.Dial() }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	plugin := &Plugin{
		now:          func() time.Time { return time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC) },
		pollInterval: 10 * time.Millisecond,
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

	rc := &pb.RequestContext{InstanceId: "default", NodeId: "local", Locale: "zh-CN"}
	if _, err := srv.Initialize(t.Context(), &pb.InitializeRequest{Context: rc, InstanceHandle: "certs-handle", ConfigJson: []byte(`{}`), ConfigRevision: "1"}); err != nil {
		t.Fatal(err)
	}
	if _, err := srv.Start(t.Context(), &pb.StartRequest{Context: rc}); err != nil {
		t.Fatal(err)
	}
	return srv, certsSvc, kvSvc
}

func runCertJob(t *testing.T, ctx context.Context, srv *pluginsdk.Server, op string, payload any, pre []*pb.Precondition) []*pb.JobProgress {
	t.Helper()
	var raw []byte
	if payload != nil {
		var err error
		raw, err = json.Marshal(payload)
		if err != nil {
			t.Fatal(err)
		}
	}
	stream := &captureCertJobStream{ctx: ctx}
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
	out := make([]*pb.JobProgress, 0, len(stream.messages))
	for _, msg := range stream.messages {
		if msg.GetProgress() != nil {
			out = append(out, msg.GetProgress())
		}
	}
	return out
}

// ======================== Manifest、全部 16 操作与任务取消联动验证 ========================

func TestCertificatesManifestAndPackageDigests(t *testing.T) {
	parsed, err := manifest.Parse(Manifest())
	if err != nil {
		t.Fatal(err)
	}
	if parsed.ID != "tls.certificates" || parsed.Placement != "controller" || parsed.Lifecycle.Startup != "on_demand" || parsed.Lifecycle.Background {
		t.Fatalf("manifest 元数据不符：%+v", parsed)
	}
	if parsed.Resources.MemoryMaxMB != 32 || parsed.Resources.PIDsMax != 16 || parsed.Resources.FDsMax != 128 {
		t.Fatalf("资源上限不符：%+v", parsed.Resources)
	}
	if len(parsed.Operations) != 17 {
		t.Fatalf("操作数量=%d，期望=17", len(parsed.Operations))
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

func TestCertificatesAllOperationsAndSummaryCache(t *testing.T) {
	srv, certsSvc, kvSvc := newCertsTestServer(t)
	rc := &pb.RequestContext{InstanceId: "default", NodeId: "local", Locale: "zh-CN"}

	// 1. certificates.summary（初始空）
	sumResp, err := srv.Invoke(t.Context(), &pb.InvokeRequest{Context: rc, Operation: "certificates.summary", ApiVersion: "v1", PayloadJson: []byte(`{}`)})
	if err != nil || sumResp.GetError() != nil {
		t.Fatalf("certificates.summary 失败：%v %v", err, sumResp.GetError())
	}
	var sumOut certificateSummaryResponse
	if err := json.Unmarshal(sumResp.GetPayloadJson(), &sumOut); err != nil || sumOut.Total != 0 {
		t.Fatalf("初始摘要不符：%+v %v", sumOut, err)
	}

	// 2. certificates.list（刷新脱敏摘要 KV）
	listMsgs := runCertJob(t, t.Context(), srv, "certificates.list", map[string]any{}, nil)
	if len(listMsgs) == 0 || !listMsgs[len(listMsgs)-1].GetCompleted() {
		t.Fatalf("certificates.list 失败：%+v", listMsgs)
	}
	sumResp, err = srv.Invoke(t.Context(), &pb.InvokeRequest{Context: rc, Operation: "certificates.summary", ApiVersion: "v1", PayloadJson: []byte(`{}`)})
	if err != nil || sumResp.GetError() != nil {
		t.Fatalf("刷新后 summary 失败：%v %v", err, sumResp.GetError())
	}
	if err := json.Unmarshal(sumResp.GetPayloadJson(), &sumOut); err != nil || sumOut.Total != 2 || sumOut.Ready != 1 || sumOut.Attention != 1 || sumOut.Level != "warn" {
		t.Fatalf("同步后摘要不符：%+v", sumOut)
	}
	kvSvc.mu.Lock()
	kvText := string(kvSvc.data[certificateSummaryKey])
	kvSvc.mu.Unlock()
	if strings.Contains(kvText, "fingerprint") || strings.Contains(kvText, "private") {
		t.Fatal("KV 摘要包含非计数敏感字段")
	}

	// 3. certificates.get
	getMsgs := runCertJob(t, t.Context(), srv, "certificates.get", map[string]any{"certificate_id": "cert-1"}, nil)
	if len(getMsgs) == 0 || !getMsgs[len(getMsgs)-1].GetCompleted() {
		t.Fatalf("certificates.get 失败")
	}

	// 4. certificates.issue（多阶段进度上报 -> succeeded）
	certsSvc.mu.Lock()
	certsSvc.getTaskSteps = []*certificatesv1.TaskView{
		{Id: "task-issue-1", CertificateId: "cert-1", Status: "running", Stage: "publishing_dns", Percent: 35, Revision: "t-2"},
		{Id: "task-issue-1", CertificateId: "cert-1", Status: "running", Stage: "verifying", Percent: 70, Revision: "t-3"},
		{Id: "task-issue-1", CertificateId: "cert-1", Status: "succeeded", Stage: "completed", Percent: 100, Revision: "t-4"},
	}
	certsSvc.getTaskIdx = 0
	certsSvc.mu.Unlock()
	issueMsgs := runCertJob(t, t.Context(), srv, "certificates.issue", map[string]any{
		"certificate_id": "cert-1", "attempt_id": "att-issue-1",
	}, []*pb.Precondition{{Subject: "certificates/cert-1", Revision: "absent"}})
	if len(issueMsgs) < 4 || !issueMsgs[len(issueMsgs)-1].GetCompleted() || certsSvc.getLastRev() != "absent" {
		t.Fatalf("certificates.issue 进度或完成状态不符：count=%d rev=%q", len(issueMsgs), certsSvc.getLastRev())
	}
	var issueResult taskResultDTO
	if err := json.Unmarshal(issueMsgs[len(issueMsgs)-1].GetResultJson(), &issueResult); err != nil || issueResult.Certificate == nil || issueResult.Task.Status != "succeeded" {
		t.Fatalf("certificates.issue 终态载荷不符：%s %v", issueMsgs[len(issueMsgs)-1].GetResultJson(), err)
	}

	// 5. certificates.import（不解析明文私钥，仅传占位字符串验证透传）
	importMsgs := runCertJob(t, t.Context(), srv, "certificates.import", map[string]any{
		"certificate_id": "cert-imp", "attempt_id": "att-imp-1", "private_key": "redacted-secret-ref",
	}, []*pb.Precondition{{Subject: "certificates/cert-imp", Revision: "absent"}})
	if len(importMsgs) == 0 || !importMsgs[len(importMsgs)-1].GetCompleted() {
		t.Fatalf("certificates.import 失败")
	}

	// 6. certificates.test
	testMsgs := runCertJob(t, t.Context(), srv, "certificates.test", map[string]any{
		"certificate_id": "cert-test", "attempt_id": "att-test-1",
	}, []*pb.Precondition{{Subject: "certificates/cert-test", Revision: "absent"}})
	if len(testMsgs) == 0 || !testMsgs[len(testMsgs)-1].GetCompleted() {
		t.Fatalf("certificates.test 失败")
	}

	// 7. bindings.reserve
	reserveMsgs := runCertJob(t, t.Context(), srv, "bindings.reserve", map[string]any{
		"certificate_id":           "cert-1",
		"expected_config_revision": "0",
		"consumer": map[string]any{
			"node_id":     "local",
			"plugin_id":   "web.ingress",
			"profile_id":  "site-app",
			"server_name": "app.example.com",
			"purpose":     "ingress.https",
		},
	}, []*pb.Precondition{{Subject: "certificates/cert-1", Revision: "rev-1"}})
	if len(reserveMsgs) == 0 || !reserveMsgs[len(reserveMsgs)-1].GetCompleted() || certsSvc.getLastRev() != "rev-1" {
		t.Fatalf("bindings.reserve 失败：%+v", reserveMsgs)
	}

	// 8-11. bindings.{bind,deploy,rollback,unbind}
	for _, op := range []string{"bindings.bind", "bindings.deploy", "bindings.rollback", "bindings.unbind"} {
		msgs := runCertJob(t, t.Context(), srv, op, map[string]any{
			"certificate_id": "cert-1", "binding_ref": "bind-1", "attempt_id": "att-" + op, "generation": 1,
		}, []*pb.Precondition{{Subject: "certificates/cert-1", Revision: "rev-1"}})
		if len(msgs) == 0 || !msgs[len(msgs)-1].GetCompleted() || certsSvc.getLastRev() != "rev-1" {
			t.Fatalf("%s 失败：%+v", op, msgs)
		}
	}

	// 11-12. generations.remove & certificates.remove
	for _, op := range []string{"generations.remove", "certificates.remove"} {
		msgs := runCertJob(t, t.Context(), srv, op, map[string]any{
			"certificate_id": "cert-1", "attempt_id": "att-" + op, "generation": 1,
		}, []*pb.Precondition{{Subject: "certificates/cert-1", Revision: "rev-2"}})
		if len(msgs) == 0 || !msgs[len(msgs)-1].GetCompleted() || certsSvc.getLastRev() != "rev-2" {
			t.Fatalf("%s 失败：%+v", op, msgs)
		}
	}

	// 13-15. renewal.{configure,revoke,get}
	for _, op := range []string{"renewal.configure", "renewal.revoke", "renewal.get"} {
		msgs := runCertJob(t, t.Context(), srv, op, map[string]any{
			"policy_id": "pol-1", "certificate_id": "cert-1",
		}, []*pb.Precondition{{Subject: "policies/pol-1", Revision: "p-rev-1"}})
		if len(msgs) == 0 || !msgs[len(msgs)-1].GetCompleted() {
			t.Fatalf("%s 失败：%+v", op, msgs)
		}
	}

	// 16. renew_existing 若被插件进程直接收到必须返回 HOST_MANAGED
	renewMsgs := runCertJob(t, t.Context(), srv, "renew_existing", map[string]any{
		"policy_id": "pol-1", "policy_revision": "1", "certificate_id": "cert-1", "run_attempt_id": "run-1", "attempt_id": "att-1",
	}, nil)
	if len(renewMsgs) == 0 || renewMsgs[len(renewMsgs)-1].GetError() == nil || renewMsgs[len(renewMsgs)-1].GetError().GetCode() != "HOST_MANAGED" {
		t.Fatalf("renew_existing 应返回 HOST_MANAGED：%+v", renewMsgs)
	}

	// proto 错误透传验证
	certsSvc.mu.Lock()
	certsSvc.failErr = &pb.ErrorDetail{Code: "PERMISSION_DENIED", Message: "越权访问"}
	certsSvc.mu.Unlock()
	errMsgs := runCertJob(t, t.Context(), srv, "certificates.get", map[string]any{"certificate_id": "cert-1"}, nil)
	if len(errMsgs) == 0 || errMsgs[len(errMsgs)-1].GetError() == nil || errMsgs[len(errMsgs)-1].GetError().GetCode() != "PERMISSION_DENIED" {
		t.Fatalf("proto 错误透传失败：%+v", errMsgs)
	}
}

func TestCertificatesAwaitTaskCancellationTriggersCancelTask(t *testing.T) {
	srv, certsSvc, _ := newCertsTestServer(t)
	certsSvc.mu.Lock()
	certsSvc.blockTask = true
	certsSvc.taskStarted = make(chan struct{})
	certsSvc.cancelDone = make(chan string, 1)
	certsSvc.mu.Unlock()

	ctx, cancel := context.WithCancel(t.Context())
	runErr := make(chan error, 1)
	go func() {
		raw, err := json.Marshal(map[string]any{
			"certificate_id": "cert-cancel", "attempt_id": "att-cancel-1",
		})
		if err != nil {
			runErr <- err
			return
		}
		stream := &captureCertJobStream{ctx: ctx}
		runErr <- srv.RunJob(&pb.RunJobRequest{
			Context:       &pb.RequestContext{InstanceId: "default", NodeId: "local", OperationId: "op-certificates.issue", Locale: "zh-CN"},
			Operation:     "certificates.issue",
			ApiVersion:    "v1",
			PayloadJson:   raw,
			Preconditions: []*pb.Precondition{{Subject: "certificates/cert-cancel", Revision: "absent"}},
		}, stream)
	}()

	select {
	case <-certsSvc.taskStarted:
	case <-time.After(3 * time.Second):
		t.Fatal("任务轮询未启动")
	}
	cancel()

	select {
	case canceledID := <-certsSvc.cancelDone:
		if canceledID != "task-issue-1" {
			t.Fatalf("CancelTask 收到错误任务 ID：%q", canceledID)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("外层 context 取消后未在 5s 独立上下文中调用 CancelTask")
	}

	select {
	case err := <-runErr:
		if err != nil {
			t.Fatalf("取消后 RunJob 返回传输错误：%v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("取消后 RunJob 未及时退出")
	}
}
