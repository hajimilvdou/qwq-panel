// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/test/bufconn"

	accountv1 "github.com/qwq-panel/qwq/sdk/gen/qwq/capability/account/v1"
	banv1 "github.com/qwq-panel/qwq/sdk/gen/qwq/capability/ban/v1"
	firewallv1 "github.com/qwq-panel/qwq/sdk/gen/qwq/capability/firewall/v1"
	sshdv1 "github.com/qwq-panel/qwq/sdk/gen/qwq/capability/sshd/v1"
	pb "github.com/qwq-panel/qwq/sdk/gen/qwq/platform/v1"
	"github.com/qwq-panel/qwq/sdk/manifest"
	"github.com/qwq-panel/qwq/sdk/pluginsdk"
)

// ======================== 宿主安全能力与状态 KV 真实 gRPC/bufconn 测试夹具 ========================

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

func (s *fakeHostState) DeleteState(_ context.Context, req *pb.DeleteStateRequest) (*pb.DeleteStateResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.data, req.GetKey())
	return &pb.DeleteStateResponse{}, nil
}

func (s *fakeHostState) hasKey(key string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.data[key]
	return ok
}

func (s *fakeHostState) rawValue(key string) ([]byte, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	val, ok := s.data[key]
	if !ok {
		return nil, false
	}
	return append([]byte(nil), val...), true
}

type fakeHostEvents struct {
	pb.UnimplementedHostEventsServiceServer
	mu        sync.Mutex
	published []*pb.EventDraft
}

func (e *fakeHostEvents) PublishEvent(_ context.Context, req *pb.PublishEventRequest) (*pb.PublishEventResponse, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if req.GetEvent() != nil {
		e.published = append(e.published, req.GetEvent())
	}
	return &pb.PublishEventResponse{
		EventId:  fmt.Sprintf("evt_%d", len(e.published)),
		Sequence: uint64(len(e.published)),
	}, nil
}

func (e *fakeHostEvents) snapshot() []*pb.EventDraft {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]*pb.EventDraft(nil), e.published...)
}

type fakeFirewallService struct {
	firewallv1.UnimplementedFirewallServiceServer
	mu             sync.Mutex
	ruleset        []byte
	revision       string
	preservedPorts []uint32
	managers       []*firewallv1.Manager
	appliedHistory [][]uint32
	lastExpected   string
	lastApplyOpID  string
	resetCalls     int
	failErr        *pb.ErrorDetail
}

func newFakeFirewallService() *fakeFirewallService {
	return &fakeFirewallService{
		ruleset:        rulesetOrMinimal(nil),
		revision:       "fw-r1",
		preservedPorts: []uint32{22, 8443},
		managers:       []*firewallv1.Manager{{Kind: "ufw", Active: false, Detail: "inactive"}},
	}
}

func (s *fakeFirewallService) nextErrLocked() *pb.ErrorDetail {
	err := s.failErr
	s.failErr = nil
	return err
}

func (s *fakeFirewallService) GetRuleset(_ context.Context, req *firewallv1.GetRulesetRequest) (*firewallv1.GetRulesetResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.nextErrLocked(); err != nil {
		return &firewallv1.GetRulesetResponse{Error: err}, nil
	}
	if req.GetContext().GetInstanceHandle() != "sec-handle" {
		return &firewallv1.GetRulesetResponse{Error: &pb.ErrorDetail{Code: "PERMISSION_DENIED", Message: "bad handle"}}, nil
	}
	return &firewallv1.GetRulesetResponse{
		RulesetJson:        append([]byte(nil), s.ruleset...),
		Revision:           s.revision,
		PreservedPorts:     append([]uint32(nil), s.preservedPorts...),
		PersistencePending: false,
	}, nil
}

func (s *fakeFirewallService) ApplyRuleset(_ context.Context, req *firewallv1.ApplyRulesetRequest) (*firewallv1.ApplyRulesetResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.nextErrLocked(); err != nil {
		return &firewallv1.ApplyRulesetResponse{Error: err}, nil
	}
	s.lastExpected = req.GetExpectedRevision()
	s.lastApplyOpID = req.GetContext().GetOperationId()
	s.ruleset = append([]byte(nil), req.GetRulesetJson()...)
	s.preservedPorts = append([]uint32(nil), req.GetPreservedPorts()...)
	s.appliedHistory = append(s.appliedHistory, append([]uint32(nil), req.GetPreservedPorts()...))
	s.revision = fmt.Sprintf("fw-r%d", len(s.appliedHistory)+1)
	return &firewallv1.ApplyRulesetResponse{Revision: s.revision}, nil
}

func (s *fakeFirewallService) ResetRuleset(_ context.Context, req *firewallv1.ResetRulesetRequest) (*firewallv1.ResetRulesetResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.nextErrLocked(); err != nil {
		return &firewallv1.ResetRulesetResponse{Error: err}, nil
	}
	s.lastExpected = req.GetExpectedRevision()
	s.resetCalls++
	s.revision = fmt.Sprintf("fw-reset-%d", s.resetCalls)
	return &firewallv1.ResetRulesetResponse{Revision: s.revision}, nil
}

func (s *fakeFirewallService) DetectManagers(_ context.Context, _ *firewallv1.DetectManagersRequest) (*firewallv1.DetectManagersResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.nextErrLocked(); err != nil {
		return &firewallv1.DetectManagersResponse{Error: err}, nil
	}
	out := make([]*firewallv1.Manager, 0, len(s.managers))
	for _, m := range s.managers {
		out = append(out, &firewallv1.Manager{Kind: m.Kind, Active: m.Active, Detail: m.Detail})
	}
	return &firewallv1.DetectManagersResponse{Managers: out}, nil
}

type fakeSSHDService struct {
	sshdv1.UnimplementedSshdServiceServer
	mu               sync.Mutex
	listeningPorts   []uint32
	revision         string
	verifyReachable  bool
	hasExternalConn  bool
	stages           []sshdv1.PortChangeStage
	lastSetPortOpID  string
	lastPolicyReq    *sshdv1.SetLoginPolicyRequest
	txSeq            int
	activeTxRef      string
	pendingOldPort   uint32
	dropInTxPort     uint32
	lastRollbackPort uint32
	failErr          *pb.ErrorDetail
}

func newFakeSSHDService() *fakeSSHDService {
	return &fakeSSHDService{
		listeningPorts:  []uint32{22},
		revision:        "sshd-r1",
		verifyReachable: true,
	}
}

func (s *fakeSSHDService) nextErrLocked() *pb.ErrorDetail {
	err := s.failErr
	s.failErr = nil
	return err
}

func (s *fakeSSHDService) GetEffectiveConfig(_ context.Context, _ *sshdv1.GetEffectiveConfigRequest) (*sshdv1.GetEffectiveConfigResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.nextErrLocked(); err != nil {
		return &sshdv1.GetEffectiveConfigResponse{Error: err}, nil
	}
	settings := make([]*sshdv1.Setting, 0, len(s.listeningPorts)+2)
	for _, p := range s.listeningPorts {
		settings = append(settings, &sshdv1.Setting{Key: "port", Value: strconv.FormatUint(uint64(p), 10), SourceFile: "/etc/ssh/sshd_config.d/00-qwq.conf"})
	}
	settings = append(settings,
		&sshdv1.Setting{Key: "passwordauthentication", Value: "no", SourceFile: "/etc/ssh/sshd_config.d/00-qwq.conf"},
		&sshdv1.Setting{Key: "permitrootlogin", Value: "prohibit-password", SourceFile: "/etc/ssh/sshd_config.d/00-qwq.conf"},
	)
	return &sshdv1.GetEffectiveConfigResponse{Settings: settings, Revision: s.revision}, nil
}

func (s *fakeSSHDService) GetDropIn(_ context.Context, _ *sshdv1.GetDropInRequest) (*sshdv1.GetDropInResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.nextErrLocked(); err != nil {
		return &sshdv1.GetDropInResponse{Error: err}, nil
	}
	return &sshdv1.GetDropInResponse{
		Exists:             true,
		Revision:           s.revision,
		Content:            "Port 22\n",
		TransactionPending: s.dropInTxPort > 0,
		TransactionPort:    s.dropInTxPort,
	}, nil
}

func (s *fakeSSHDService) SetPort(_ context.Context, req *sshdv1.SetPortRequest) (*sshdv1.SetPortResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.nextErrLocked(); err != nil {
		return &sshdv1.SetPortResponse{Error: err}, nil
	}
	s.stages = append(s.stages, req.GetStage())
	s.lastSetPortOpID = req.GetContext().GetOperationId()
	switch req.GetStage() {
	case sshdv1.PortChangeStage_PORT_CHANGE_STAGE_ADD_NEW:
		s.txSeq++
		s.activeTxRef = fmt.Sprintf("tx-%d", s.txSeq)
		s.pendingOldPort = s.listeningPorts[0]
		s.listeningPorts = mergePorts(s.listeningPorts, req.GetNewPort())
		s.revision = fmt.Sprintf("sshd-add-%d", s.txSeq)
	case sshdv1.PortChangeStage_PORT_CHANGE_STAGE_COMMIT_NEW:
		s.listeningPorts = []uint32{req.GetNewPort()}
		s.revision = fmt.Sprintf("sshd-commit-%d", s.txSeq)
		s.activeTxRef = ""
	case sshdv1.PortChangeStage_PORT_CHANGE_STAGE_ROLLBACK:
		s.lastRollbackPort = req.GetNewPort()
		if s.pendingOldPort != 0 {
			s.listeningPorts = []uint32{s.pendingOldPort}
		}
		s.revision = fmt.Sprintf("sshd-rb-%d", len(s.stages))
		s.activeTxRef = ""
	}
	return &sshdv1.SetPortResponse{
		Revision:       s.revision,
		ListeningPorts: append([]uint32(nil), s.listeningPorts...),
		TransactionRef: s.activeTxRef,
	}, nil
}

func (s *fakeSSHDService) VerifyPort(_ context.Context, req *sshdv1.VerifyPortRequest) (*sshdv1.VerifyPortResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.nextErrLocked(); err != nil {
		return &sshdv1.VerifyPortResponse{Error: err}, nil
	}
	if !s.verifyReachable || !slices.Contains(s.listeningPorts, req.GetPort()) {
		return &sshdv1.VerifyPortResponse{Reachable: false}, nil
	}
	return &sshdv1.VerifyPortResponse{
		Reachable:             true,
		Banner:                "SSH-2.0-OpenSSH_9.6",
		HasExternalConnection: s.hasExternalConn,
	}, nil
}

func (s *fakeSSHDService) SetLoginPolicy(_ context.Context, req *sshdv1.SetLoginPolicyRequest) (*sshdv1.SetLoginPolicyResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.nextErrLocked(); err != nil {
		return &sshdv1.SetLoginPolicyResponse{Error: err}, nil
	}
	s.lastPolicyReq = req
	s.revision = "sshd-policy-2"
	return &sshdv1.SetLoginPolicyResponse{
		Revision: s.revision,
		Effective: []*sshdv1.Setting{
			{Key: "passwordauthentication", Value: "no", SourceFile: "/etc/ssh/sshd_config.d/00-qwq.conf"},
			{Key: "permitrootlogin", Value: "prohibit-password", SourceFile: "/etc/ssh/sshd_config.d/00-qwq.conf"},
		},
	}, nil
}

func (s *fakeSSHDService) stageSnapshot() []sshdv1.PortChangeStage {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]sshdv1.PortChangeStage(nil), s.stages...)
}

type fakeAccountService struct {
	accountv1.UnimplementedAccountServiceServer
	mu            sync.Mutex
	lastSecretRef string
	lastRemovedFP string
	failErr       *pb.ErrorDetail
}

func (s *fakeAccountService) nextErrLocked() *pb.ErrorDetail {
	err := s.failErr
	s.failErr = nil
	return err
}

func (s *fakeAccountService) ListKeys(_ context.Context, _ *accountv1.ListKeysRequest) (*accountv1.ListKeysResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.nextErrLocked(); err != nil {
		return &accountv1.ListKeysResponse{Error: err}, nil
	}
	return &accountv1.ListKeysResponse{
		Revision: "keys-r1",
		Keys: []*accountv1.Key{
			{Type: "ssh-ed25519", Bits: 256, FingerprintSha256: "SHA256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Comment: "ops@host", LineIndex: 1},
		},
	}, nil
}

func (s *fakeAccountService) ImportKey(_ context.Context, _ *accountv1.ImportKeyRequest) (*accountv1.ImportKeyResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.nextErrLocked(); err != nil {
		return &accountv1.ImportKeyResponse{Error: err}, nil
	}
	return &accountv1.ImportKeyResponse{
		FingerprintSha256: "SHA256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		Type:              "ssh-ed25519",
		Bits:              256,
		Comment:           "browser",
		Revision:          "keys-r2",
	}, nil
}

func (s *fakeAccountService) RemoveKey(_ context.Context, req *accountv1.RemoveKeyRequest) (*accountv1.RemoveKeyResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.nextErrLocked(); err != nil {
		return &accountv1.RemoveKeyResponse{Error: err}, nil
	}
	s.lastRemovedFP = req.GetFingerprintSha256()
	return &accountv1.RemoveKeyResponse{Revision: "keys-r3"}, nil
}

func (s *fakeAccountService) GenerateKey(_ context.Context, _ *accountv1.GenerateKeyRequest) (*accountv1.GenerateKeyResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.nextErrLocked(); err != nil {
		return &accountv1.GenerateKeyResponse{Error: err}, nil
	}
	// 运行时动态生成合成私钥 PEM，绝不在源码中存放明文私钥字面量。
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return nil, err
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  strings.Join([]string{"EC", "PRIVATE", "KEY"}, " "),
		Bytes: der,
	})
	return &accountv1.GenerateKeyResponse{
		PublicKey:         "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMockKeyDataForFallbackTest fallback@qwq",
		FingerprintSha256: "SHA256:ccccccccccccccccccccccccccccccccccccccccccc",
		PrivateKeyPem:     pemBytes,
		Revision:          "keys-r4",
	}, nil
}

func (s *fakeAccountService) SetPassword(_ context.Context, req *accountv1.SetPasswordRequest) (*accountv1.SetPasswordResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.nextErrLocked(); err != nil {
		return &accountv1.SetPasswordResponse{Error: err}, nil
	}
	s.lastSecretRef = req.GetSecretRef()
	return &accountv1.SetPasswordResponse{Revision: "pwd-r2"}, nil
}

type fakeBanService struct {
	banv1.UnimplementedBanServiceServer
	mu                sync.Mutex
	bans              map[string]int64
	revision          string
	failures          []*banv1.AuthFailure
	replayUntilCursor bool
	nextCursor        string
	scanCalls         int
	applyCalls        int
	lastApplyOpID     string
	removedIPs        []string
	appliedIPs        []string
	failErr           *pb.ErrorDetail
	applyFailErr      *pb.ErrorDetail
	revSequence       int
}

func newFakeBanService() *fakeBanService {
	return &fakeBanService{
		bans:     make(map[string]int64),
		revision: "ban-r1",
	}
}

func (s *fakeBanService) nextErrLocked() *pb.ErrorDetail {
	err := s.failErr
	s.failErr = nil
	return err
}

func (s *fakeBanService) ScanAuthFailures(_ context.Context, req *banv1.ScanAuthFailuresRequest) (*banv1.ScanAuthFailuresResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.scanCalls++
	if err := s.nextErrLocked(); err != nil {
		return &banv1.ScanAuthFailuresResponse{Error: err}, nil
	}
	if s.replayUntilCursor {
		if req.GetCursor() == s.nextCursor {
			return &banv1.ScanAuthFailuresResponse{NextCursor: s.nextCursor}, nil
		}
		return &banv1.ScanAuthFailuresResponse{
			Failures:   append([]*banv1.AuthFailure(nil), s.failures...),
			NextCursor: s.nextCursor,
		}, nil
	}
	out := append([]*banv1.AuthFailure(nil), s.failures...)
	s.failures = nil
	return &banv1.ScanAuthFailuresResponse{
		Failures:   out,
		NextCursor: s.nextCursor,
	}, nil
}

func (s *fakeBanService) ApplyBans(_ context.Context, req *banv1.ApplyBansRequest) (*banv1.ApplyBansResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.applyCalls++
	s.lastApplyOpID = req.GetContext().GetOperationId()
	if s.applyFailErr != nil {
		err := s.applyFailErr
		s.applyFailErr = nil
		return &banv1.ApplyBansResponse{Error: err}, nil
	}
	if err := s.nextErrLocked(); err != nil {
		return &banv1.ApplyBansResponse{Error: err}, nil
	}
	for _, entry := range req.GetEntries() {
		s.bans[entry.GetIp()] = time.Now().Add(time.Duration(entry.GetTtlSeconds()) * time.Second).UnixMilli()
		s.appliedIPs = append(s.appliedIPs, entry.GetIp())
	}
	s.revSequence++
	s.revision = fmt.Sprintf("ban-r%d", s.revSequence+1)
	return &banv1.ApplyBansResponse{
		Revision:    s.revision,
		ActiveCount: uint32(len(s.bans)),
	}, nil
}

func (s *fakeBanService) RemoveBan(_ context.Context, req *banv1.RemoveBanRequest) (*banv1.RemoveBanResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.nextErrLocked(); err != nil {
		return &banv1.RemoveBanResponse{Error: err}, nil
	}
	delete(s.bans, req.GetIp())
	s.removedIPs = append(s.removedIPs, req.GetIp())
	s.revSequence++
	s.revision = fmt.Sprintf("ban-r%d", s.revSequence+1)
	return &banv1.RemoveBanResponse{Revision: s.revision}, nil
}

func (s *fakeBanService) ListBans(_ context.Context, _ *banv1.ListBansRequest) (*banv1.ListBansResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.nextErrLocked(); err != nil {
		return &banv1.ListBansResponse{Error: err}, nil
	}
	out := make([]*banv1.ActiveBan, 0, len(s.bans))
	for ip, exp := range s.bans {
		out = append(out, &banv1.ActiveBan{Ip: ip, ExpiresAt: exp})
	}
	return &banv1.ListBansResponse{Bans: out, Revision: s.revision}, nil
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

type testHarness struct {
	srv      *pluginsdk.Server
	fw       *fakeFirewallService
	sshd     *fakeSSHDService
	account  *fakeAccountService
	ban      *fakeBanService
	kv       *fakeHostState
	events   *fakeHostEvents
	clockSec *atomic.Int64
}

func newSecurityTestHarness(t *testing.T, configJSON string, banInterval, sagaInterval time.Duration) *testHarness {
	t.Helper()
	listener := bufconn.Listen(256 << 10)
	hostServer := grpc.NewServer()
	h := &testHarness{
		fw:       newFakeFirewallService(),
		sshd:     newFakeSSHDService(),
		account:  &fakeAccountService{},
		ban:      newFakeBanService(),
		kv:       &fakeHostState{},
		events:   &fakeHostEvents{},
		clockSec: &atomic.Int64{},
	}
	h.clockSec.Store(time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC).Unix())

	firewallv1.RegisterFirewallServiceServer(hostServer, h.fw)
	sshdv1.RegisterSshdServiceServer(hostServer, h.sshd)
	accountv1.RegisterAccountServiceServer(hostServer, h.account)
	banv1.RegisterBanServiceServer(hostServer, h.ban)
	pb.RegisterHostStateServiceServer(hostServer, h.kv)
	pb.RegisterHostEventsServiceServer(hostServer, h.events)

	go func() { _ = hostServer.Serve(listener) }()
	t.Cleanup(func() { hostServer.Stop(); _ = listener.Close() })

	conn, err := grpc.NewClient("passthrough:///security-host",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return listener.Dial() }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	plugin := &Plugin{
		now:               func() time.Time { return time.Unix(h.clockSec.Load(), 0).UTC() },
		banScanInterval:   banInterval,
		sagaCheckInterval: sagaInterval,
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
	// 后注册先执行：先停插件实例后台协程，再关闭连接与宿主 gRPC。
	t.Cleanup(srv.Close)

	if configJSON == "" {
		configJSON = `{}`
	}
	rc := &pb.RequestContext{InstanceId: "default", NodeId: "local", Locale: "zh-CN"}
	if _, err := srv.Initialize(t.Context(), &pb.InitializeRequest{
		Context:        rc,
		InstanceHandle: "sec-handle",
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

func invokeSecurity(t *testing.T, srv *pluginsdk.Server, op string, payload any) *pb.InvokeResponse {
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

func runSecurityJob(t *testing.T, srv *pluginsdk.Server, op string, payload any, pre []*pb.Precondition) *pb.JobProgress {
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

func waitUntil(t *testing.T, timeout time.Duration, desc string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("等待条件超时：%s", desc)
}

// ======================== 清单与全部 18 项操作端到端验证 ========================

func TestSecurityManifestAndPackageDigests(t *testing.T) {
	parsed, err := manifest.Parse(Manifest())
	if err != nil {
		t.Fatal(err)
	}
	if parsed.ID != "security.basic" || parsed.Placement != "node" || parsed.Lifecycle.Startup != "eager" ||
		!parsed.Lifecycle.Background || parsed.Lifecycle.UpdateStrategy != "restart" || parsed.Lifecycle.EffectiveOverlapSafe() {
		t.Fatalf("manifest 生命周期或定位不符：%+v", parsed.Lifecycle)
	}
	if parsed.Resources.MemoryMaxMB != 32 || parsed.Resources.CPUQuotaPercent != 20 ||
		parsed.Resources.PIDsMax != 16 || parsed.Resources.FDsMax != 128 || parsed.Resources.DiskMaxMB != 16 {
		t.Fatalf("资源配额不符：%+v", parsed.Resources)
	}
	if len(parsed.Operations) != 18 {
		t.Fatalf("操作数量=%d，期望=18", len(parsed.Operations))
	}
	for name, digest := range parsed.Files {
		if name == parsed.Entrypoint {
			continue
		}
		raw, err := os.ReadFile(name)
		if err != nil {
			t.Fatalf("读取清单文件 %s 失败: %v", name, err)
		}
		sum := sha256.Sum256(raw)
		want := "sha256:" + hex.EncodeToString(sum[:])
		if digest != want {
			t.Fatalf("清单文件 %s 摘要不匹配: got %s want %s", name, digest, want)
		}
	}
}

func TestSecurityAllOperationsAndErrorPassthrough(t *testing.T) {
	h := newSecurityTestHarness(t, `{"ban_enabled":true}`, 0, 0)

	// 1. 6 项只读 invoke 操作。
	for _, tc := range []struct {
		op      string
		payload any
	}{
		{"security.overview", map[string]any{}},
		{"security.firewall.status", map[string]any{}},
		{"security.sshd.status", map[string]any{}},
		{"security.keys.list", map[string]any{"user": "root"}},
		{"security.bans.list", map[string]any{}},
		{"security.conflicts.detect", map[string]any{}},
	} {
		resp := invokeSecurity(t, h.srv, tc.op, tc.payload)
		if resp.GetError() != nil {
			t.Fatalf("Invoke(%s) unexpected error: %+v", tc.op, resp.GetError())
		}
	}

	// 2. 防火墙应用与重置（自动继承宿主保留端口并透传 precondition revision）。
	prog := runSecurityJob(t, h.srv, "security.firewall.apply", map[string]any{
		"ruleset": json.RawMessage(rulesetOrMinimal(nil)),
	}, []*pb.Precondition{{Subject: "firewall/ruleset", Revision: "fw-r1"}})
	if prog.GetError() != nil {
		t.Fatalf("firewall.apply failed: %+v", prog.GetError())
	}
	h.fw.mu.Lock()
	gotExpected := h.fw.lastExpected
	gotPorts := append([]uint32(nil), h.fw.preservedPorts...)
	h.fw.mu.Unlock()
	if gotExpected != "fw-r1" || !slices.Equal(gotPorts, []uint32{22, 8443}) {
		t.Fatalf("firewall.apply precondition/preservedPorts 不符: rev=%s ports=%v", gotExpected, gotPorts)
	}

	prog = runSecurityJob(t, h.srv, "security.firewall.reset", map[string]any{"expected_revision": "fw-r2"}, nil)
	if prog.GetError() != nil {
		t.Fatalf("firewall.reset failed: %+v", prog.GetError())
	}

	// 3. SSH 登录策略：校验互斥拒绝与合法写入。
	badPolicy := runSecurityJob(t, h.srv, "security.sshd.set_login_policy", map[string]any{
		"permit_root_login": true,
		"root_login_mode":   "keys_only",
	}, nil)
	if badPolicy.GetError() == nil || badPolicy.GetError().GetCode() != "VALIDATION_FAILED" {
		t.Fatalf("互斥参数应返回 VALIDATION_FAILED，实际: %+v", badPolicy.GetError())
	}
	pwFalse := false
	okPolicy := runSecurityJob(t, h.srv, "security.sshd.set_login_policy", map[string]any{
		"password_auth":   pwFalse,
		"root_login_mode": "keys_only",
		"recovery_user":   "root",
	}, nil)
	if okPolicy.GetError() != nil {
		t.Fatalf("sshd.set_login_policy failed: %+v", okPolicy.GetError())
	}

	// 4. 账号公钥导入、服务端回退生成、移除与密文口令修改。
	if prog := runSecurityJob(t, h.srv, "security.keys.import", map[string]any{
		"user":       "root",
		"public_key": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestKey user@host",
	}, nil); prog.GetError() != nil {
		t.Fatalf("keys.import failed: %+v", prog.GetError())
	}
	genProg := runSecurityJob(t, h.srv, "security.keys.generate_fallback", map[string]any{
		"user": "root",
		"type": "ed25519",
	}, nil)
	if genProg.GetError() != nil {
		t.Fatalf("keys.generate_fallback failed: %+v", genProg.GetError())
	}
	var genOut keysGenerateResponse
	if err := json.Unmarshal(genProg.GetResultJson(), &genOut); err != nil || genOut.PrivateKeyPEM == "" || genOut.Revision != "keys-r4" {
		t.Fatalf("keys.generate_fallback 响应异常: %+v err=%v", genOut, err)
	}
	if prog := runSecurityJob(t, h.srv, "security.keys.remove", map[string]any{
		"user":               "root",
		"fingerprint_sha256": "SHA256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
	}, nil); prog.GetError() != nil {
		t.Fatalf("keys.remove failed: %+v", prog.GetError())
	}
	if prog := runSecurityJob(t, h.srv, "security.account.set_password", map[string]any{
		"user":     "root",
		"password": "sec_ref_opaque_001",
	}, nil); prog.GetError() != nil {
		t.Fatalf("account.set_password failed: %+v", prog.GetError())
	}
	h.account.mu.Lock()
	gotSecretRef := h.account.lastSecretRef
	h.account.mu.Unlock()
	if gotSecretRef != "sec_ref_opaque_001" {
		t.Fatalf("期望透传密文引用 sec_ref_opaque_001，实际 %q", gotSecretRef)
	}

	// 5. 手动添加与解除封禁。
	if prog := runSecurityJob(t, h.srv, "security.bans.add", map[string]any{
		"ip":          "198.51.100.77",
		"ttl_seconds": 1800,
	}, nil); prog.GetError() != nil {
		t.Fatalf("bans.add failed: %+v", prog.GetError())
	}
	if prog := runSecurityJob(t, h.srv, "security.bans.remove", map[string]any{
		"ip": "198.51.100.77",
	}, nil); prog.GetError() != nil {
		t.Fatalf("bans.remove failed: %+v", prog.GetError())
	}

	// 6. ErrorDetail 透传验证（含 Retryable 与 FieldViolation）。
	h.fw.mu.Lock()
	h.fw.failErr = &pb.ErrorDetail{
		Code:      "CONFLICT",
		Message:   "检测到未接管的 ufw 管理器",
		Retryable: true,
		Violations: []*pb.FieldViolation{
			{Pointer: "/ruleset", Code: "MANAGER_CONFLICT", Message: "请先接管 ufw"},
		},
	}
	h.fw.mu.Unlock()
	errResp := invokeSecurity(t, h.srv, "security.firewall.status", map[string]any{})
	if errResp.GetError() == nil || errResp.GetError().GetCode() != "CONFLICT" || !errResp.GetError().GetRetryable() || len(errResp.GetError().GetViolations()) != 1 {
		t.Fatalf("Invoke ErrorDetail 未完整透传: %+v", errResp.GetError())
	}

	h.account.mu.Lock()
	h.account.failErr = &pb.ErrorDetail{
		Code:    "PRECONDITION_FAILED",
		Message: "密码登录已禁用，拒绝移除最后一把公钥",
	}
	h.account.mu.Unlock()
	errJob := runSecurityJob(t, h.srv, "security.keys.remove", map[string]any{
		"user":               "root",
		"fingerprint_sha256": "SHA256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	}, nil)
	if errJob.GetError() == nil || errJob.GetError().GetCode() != "PRECONDITION_FAILED" {
		t.Fatalf("RunJob ErrorDetail 未完整透传: %+v", errJob.GetError())
	}
}

// ======================== 7 步双端口 SSH 改端口 Saga 验证 ========================

func TestSSHDPortSagaPrepareCommitAndRollback(t *testing.T) {
	h := newSecurityTestHarness(t, `{}`, 0, 0)

	// 非法端口拒绝。
	if prog := runSecurityJob(t, h.srv, "security.sshd.change_port_prepare", map[string]any{"new_port": 22}, nil); prog.GetError() == nil || prog.GetError().GetCode() != "VALIDATION_FAILED" {
		t.Fatalf("特权端口 22 应被拒绝，实际: %+v", prog.GetError())
	}

	// Prepare: 22 -> 2222。
	prep := runSecurityJob(t, h.srv, "security.sshd.change_port_prepare", map[string]any{
		"new_port":        2222,
		"timeout_seconds": 300,
	}, nil)
	if prep.GetError() != nil {
		t.Fatalf("prepare 失败: %+v", prep.GetError())
	}
	var prepOut sshdPortSagaResponse
	if err := json.Unmarshal(prep.GetResultJson(), &prepOut); err != nil {
		t.Fatal(err)
	}
	if prepOut.Stage != "prepared" || prepOut.OldPort != 22 || prepOut.NewPort != 2222 || prepOut.TransactionRef == "" || !prepOut.FirewallManaged {
		t.Fatalf("prepare 响应异常: %+v", prepOut)
	}
	if !h.kv.hasKey(kvKeyPortSaga) {
		t.Fatal("prepare 后未在 KV 写入 sshd/port_saga")
	}
	h.fw.mu.Lock()
	fwAfterPrep := append([]uint32(nil), h.fw.preservedPorts...)
	h.fw.mu.Unlock()
	if !slices.Equal(fwAfterPrep, []uint32{22, 2222, 8443}) {
		t.Fatalf("prepare 阶段防火墙应同时放行旧新端口与面板端口，实际: %v", fwAfterPrep)
	}

	// 错误 transaction_ref 提交必须被拒绝。
	badCommit := runSecurityJob(t, h.srv, "security.sshd.change_port_commit", map[string]any{"transaction_ref": "wrong-ref"}, nil)
	if badCommit.GetError() == nil || badCommit.GetError().GetCode() != "PRECONDITION_FAILED" {
		t.Fatalf("错误 transaction_ref 应返回 PRECONDITION_FAILED，实际: %+v", badCommit.GetError())
	}

	// 无外部 ESTABLISHED 连接且未显式二次确认时，应返回 PRECONDITION_FAILED 防止云安全组锁死。
	unconfirmedCommit := runSecurityJob(t, h.srv, "security.sshd.change_port_commit", map[string]any{"transaction_ref": prepOut.TransactionRef}, nil)
	if unconfirmedCommit.GetError() == nil || unconfirmedCommit.GetError().GetCode() != "PRECONDITION_FAILED" {
		t.Fatalf("未确认外部可达时应返回 PRECONDITION_FAILED，实际: %+v", unconfirmedCommit.GetError())
	}

	// 正确 Commit（携带 confirm_external_reachable）：移除旧端口放行并清理 KV 事务。
	commit := runSecurityJob(t, h.srv, "security.sshd.change_port_commit", map[string]any{
		"transaction_ref":            prepOut.TransactionRef,
		"confirm_external_reachable": true,
	}, nil)
	if commit.GetError() != nil {
		t.Fatalf("commit 失败: %+v", commit.GetError())
	}
	if h.kv.hasKey(kvKeyPortSaga) {
		t.Fatal("commit 后 KV 事务应已清理")
	}
	h.fw.mu.Lock()
	fwAfterCommit := append([]uint32(nil), h.fw.preservedPorts...)
	h.fw.mu.Unlock()
	if !slices.Equal(fwAfterCommit, []uint32{2222, 8443}) {
		t.Fatalf("commit 后防火墙应移除旧端口 22 并保留新端口 2222，实际: %v", fwAfterCommit)
	}

	// Prepare -> Manual Rollback: 2222 -> 2223 -> 回滚至 2222。
	prep2 := runSecurityJob(t, h.srv, "security.sshd.change_port_prepare", map[string]any{"new_port": 2223}, nil)
	if prep2.GetError() != nil {
		t.Fatalf("第二次 prepare 失败: %+v", prep2.GetError())
	}
	var prep2Out sshdPortSagaResponse
	if err := json.Unmarshal(prep2.GetResultJson(), &prep2Out); err != nil {
		t.Fatal(err)
	}
	rb := runSecurityJob(t, h.srv, "security.sshd.change_port_rollback", map[string]any{"transaction_ref": prep2Out.TransactionRef}, nil)
	if rb.GetError() != nil {
		t.Fatalf("rollback 失败: %+v", rb.GetError())
	}
	if h.kv.hasKey(kvKeyPortSaga) {
		t.Fatal("rollback 后 KV 事务应已清理")
	}
	h.fw.mu.Lock()
	fwAfterRB := append([]uint32(nil), h.fw.preservedPorts...)
	h.fw.mu.Unlock()
	if !slices.Equal(fwAfterRB, []uint32{2222, 8443}) {
		t.Fatalf("rollback 后防火墙应撤销新端口 2223 并保留旧端口 2222，实际: %v", fwAfterRB)
	}

	// VerifyPort 不可达时 Prepare 立即自动回滚且返回 PORT_VERIFY_FAILED。
	h.sshd.mu.Lock()
	h.sshd.verifyReachable = false
	h.sshd.mu.Unlock()
	failPrep := runSecurityJob(t, h.srv, "security.sshd.change_port_prepare", map[string]any{"new_port": 2224}, nil)
	if failPrep.GetError() == nil || failPrep.GetError().GetCode() != "PORT_VERIFY_FAILED" {
		t.Fatalf("探测失败应返回 PORT_VERIFY_FAILED，实际: %+v", failPrep.GetError())
	}
	if h.kv.hasKey(kvKeyPortSaga) {
		t.Fatal("探测失败自动回滚后不应残留 KV 事务")
	}
}

func TestSSHDPortSagaTimeoutAutoRollback(t *testing.T) {
	h := newSecurityTestHarness(t, `{"ban_enabled":false}`, time.Hour, 15*time.Millisecond)
	rc := &pb.RequestContext{InstanceId: "default", NodeId: "local", Locale: "zh-CN"}
	if _, err := h.srv.Activate(t.Context(), &pb.ActivateRequest{Context: rc}); err != nil {
		t.Fatal(err)
	}

	prep := runSecurityJob(t, h.srv, "security.sshd.change_port_prepare", map[string]any{
		"new_port":        2299,
		"timeout_seconds": 5,
	}, nil)
	if prep.GetError() != nil {
		t.Fatalf("prepare 失败: %+v", prep.GetError())
	}
	if !h.kv.hasKey(kvKeyPortSaga) {
		t.Fatal("prepare 后应存在挂起事务")
	}

	// 推进模拟时钟超过 5 秒，触发后台守护协程自动回滚。
	h.clockSec.Add(10)

	waitUntil(t, 3*time.Second, "后台超时自动回滚完成", func() bool {
		if h.kv.hasKey(kvKeyPortSaga) {
			return false
		}
		stages := h.sshd.stageSnapshot()
		return slices.Contains(stages, sshdv1.PortChangeStage_PORT_CHANGE_STAGE_ROLLBACK)
	})

	h.fw.mu.Lock()
	fwPorts := append([]uint32(nil), h.fw.preservedPorts...)
	fwOpID := h.fw.lastApplyOpID
	h.fw.mu.Unlock()
	if !slices.Equal(fwPorts, []uint32{22, 8443}) {
		t.Fatalf("超时自动回滚后防火墙应恢复旧端口集合，实际: %v", fwPorts)
	}
	h.sshd.mu.Lock()
	sshdOpID := h.sshd.lastSetPortOpID
	h.sshd.mu.Unlock()
	if sshdOpID != "auton:sshd_saga_rollback" || fwOpID != "auton:sshd_saga_rollback" {
		t.Fatalf("超时自动回滚应使用自治上下文 auton:sshd_saga_rollback，实际 sshd=%q fw=%q", sshdOpID, fwOpID)
	}
	waitUntil(t, 2*time.Second, "超时自动回滚发布 security.alert 事件", func() bool {
		for _, ev := range h.events.snapshot() {
			if ev.GetType() == "security.alert" && ev.GetSubject() == "sshd/port_saga" {
				return true
			}
		}
		return false
	})
}

func TestSSHDPortSagaCommitAcceptsHostExternalConnectionProbe(t *testing.T) {
	h := newSecurityTestHarness(t, `{}`, 0, 0)
	prep := runSecurityJob(t, h.srv, "security.sshd.change_port_prepare", map[string]any{
		"new_port":        2288,
		"timeout_seconds": 300,
	}, nil)
	if prep.GetError() != nil {
		t.Fatalf("prepare 失败: %+v", prep.GetError())
	}
	var prepOut sshdPortSagaResponse
	if err := json.Unmarshal(prep.GetResultJson(), &prepOut); err != nil {
		t.Fatal(err)
	}

	// 宿主 VerifyPort 报告检测到非回环外部连接时，sshd.status 应回显且无需手动 confirm_external_reachable 即可提交。
	h.sshd.mu.Lock()
	h.sshd.hasExternalConn = true
	h.sshd.mu.Unlock()

	stResp := invokeSecurity(t, h.srv, "security.sshd.status", map[string]any{})
	var st sshdStatusResponse
	if err := json.Unmarshal(stResp.GetPayloadJson(), &st); err != nil {
		t.Fatal(err)
	}
	if st.PortSaga == nil || !st.PortSaga.ExternalConnectionDetected {
		t.Fatalf("sshd.status 应回显 port_saga.external_connection_detected=true，实际: %+v", st.PortSaga)
	}

	commit := runSecurityJob(t, h.srv, "security.sshd.change_port_commit", map[string]any{
		"transaction_ref": prepOut.TransactionRef,
	}, nil)
	if commit.GetError() != nil {
		t.Fatalf("宿主探测到外部连接后应允许直接提交，实际错误: %+v", commit.GetError())
	}
	if h.kv.hasKey(kvKeyPortSaga) {
		t.Fatal("commit 完成后 KV 事务应已清理")
	}
}

// ======================== fail2ban 共存旁观模式与增量防爆破巡检验证 ========================

func TestBanLoopFail2banObserverMode(t *testing.T) {
	h := newSecurityTestHarness(t, `{"ban_enabled":true}`, 20*time.Millisecond, time.Hour)
	h.fw.mu.Lock()
	h.fw.managers = []*firewallv1.Manager{
		{Kind: "fail2ban", Active: true, Detail: "fail2ban.service active"},
	}
	h.fw.mu.Unlock()

	rc := &pb.RequestContext{InstanceId: "default", NodeId: "local", Locale: "zh-CN"}
	if _, err := h.srv.Activate(t.Context(), &pb.ActivateRequest{Context: rc}); err != nil {
		t.Fatal(err)
	}

	waitUntil(t, 3*time.Second, "进入 fail2ban 只读旁观模式", func() bool {
		raw, ok := h.kv.rawValue(kvKeyOverviewCache)
		if !ok {
			return false
		}
		var cache overviewCache
		return json.Unmarshal(raw, &cache) == nil && cache.Fail2banObserver
	})

	h.ban.mu.Lock()
	scans := h.ban.scanCalls
	applies := h.ban.applyCalls
	h.ban.mu.Unlock()
	if scans != 0 || applies != 0 {
		t.Fatalf("fail2ban 活跃时绝不能执行扫描或下发封禁，实际 scan=%d apply=%d", scans, applies)
	}

	ovResp := invokeSecurity(t, h.srv, "security.overview", map[string]any{})
	var ov overviewResponse
	if err := json.Unmarshal(ovResp.GetPayloadJson(), &ov); err != nil || !ov.Fail2banObserver {
		t.Fatalf("overview 应返回 fail2ban_observer=true: %+v err=%v", ov, err)
	}
}

func TestBanLoopIncrementalScanApplyAndEviction(t *testing.T) {
	cfg := `{"ban_enabled":true,"ban_threshold":5,"ban_window_seconds":600,"ban_ttl_seconds":3600,"ban_whitelist":["203.0.113.0/24"]}`
	h := newSecurityTestHarness(t, cfg, 25*time.Millisecond, time.Hour)

	nowMs := time.Unix(h.clockSec.Load(), 0).UTC().UnixMilli()
	h.ban.mu.Lock()
	// 预置 4096 条封禁验证超上限时按最早过期淘汰（192.0.2.1 过期最早）。
	for idx := 0; idx < maxBanEntries; idx++ {
		ip := fmt.Sprintf("10.%d.%d.%d", (idx>>16)&0xff, (idx>>8)&0xff, idx&0xff)
		exp := nowMs + int64(100000+idx*1000)
		if idx == 0 {
			ip = "192.0.2.1"
			exp = nowMs + 1000
		}
		h.ban.bans[ip] = exp
	}
	h.ban.failures = []*banv1.AuthFailure{
		{Ip: "198.51.100.10", User: "root", OccurredAt: nowMs - 1000, Count: 5},
		{Ip: "198.51.100.20", User: "admin", OccurredAt: nowMs - 1000, Count: 3},
		{Ip: "203.0.113.5", User: "root", OccurredAt: nowMs - 1000, Count: 9},
	}
	h.ban.nextCursor = "cursor-seq-42"
	h.ban.mu.Unlock()

	rc := &pb.RequestContext{InstanceId: "default", NodeId: "local", Locale: "zh-CN"}
	if _, err := h.srv.Activate(t.Context(), &pb.ActivateRequest{Context: rc}); err != nil {
		t.Fatal(err)
	}

	waitUntil(t, 3*time.Second, "增量扫描触发淘汰与 ApplyBans 并更新游标", func() bool {
		h.ban.mu.Lock()
		applied := slices.Contains(h.ban.appliedIPs, "198.51.100.10")
		h.ban.mu.Unlock()
		return applied && h.kv.hasKey(kvKeyBanCursor)
	})

	h.ban.mu.Lock()
	applied := append([]string(nil), h.ban.appliedIPs...)
	removed := append([]string(nil), h.ban.removedIPs...)
	banOpID := h.ban.lastApplyOpID
	h.ban.mu.Unlock()

	if !slices.Equal(applied, []string{"198.51.100.10"}) {
		t.Fatalf("仅应封禁超阈值且非白名单的 198.51.100.10，实际: %v", applied)
	}
	if !slices.Equal(removed, []string{"192.0.2.1"}) {
		t.Fatalf("超 4096 上限应先淘汰最早过期条目 192.0.2.1，实际: %v", removed)
	}
	if banOpID != "auton:ban_loop" {
		t.Fatalf("后台防爆破封禁应使用自治上下文 auton:ban_loop，实际: %q", banOpID)
	}

	rawCur, ok := h.kv.rawValue(kvKeyBanCursor)
	if !ok || !strings.Contains(string(rawCur), "cursor-seq-42") {
		t.Fatalf("KV ban/cursor 未更新: %s", string(rawCur))
	}

	waitUntil(t, 2*time.Second, "自动封禁发布 security.alert 事件", func() bool {
		for _, ev := range h.events.snapshot() {
			if ev.GetType() == "security.alert" && ev.GetSubject() == "bans/auto" && strings.Contains(string(ev.GetPayloadJson()), "198.51.100.10") {
				return true
			}
		}
		return false
	})
}

func TestAccountSetPasswordAcceptsSealedSecretEnvelope(t *testing.T) {
	h := newSecurityTestHarness(t, `{"ban_enabled":false}`, time.Hour, time.Hour)

	// 1. OperationProtector 封存的 {"$secret":"sec_123"} password 信封必须成功解析并透传 secret_ref
	res1 := runSecurityJob(t, h.srv, "security.account.set_password", map[string]any{
		"user":     "root",
		"password": map[string]any{"$secret": "sec_123"},
	}, nil)
	if res1.GetError() != nil {
		t.Fatalf("password $secret envelope 应被接受，实际错误: %+v", res1.GetError())
	}
	h.account.mu.Lock()
	got1 := h.account.lastSecretRef
	h.account.mu.Unlock()
	if got1 != "sec_123" {
		t.Fatalf("期望透传 secret_ref=sec_123，实际 %q", got1)
	}

	// 2. secret_ref 字段同样支持 {"$secret":"sec_456"} 信封
	res2 := runSecurityJob(t, h.srv, "security.account.set_password", map[string]any{
		"user":       "root",
		"secret_ref": map[string]any{"$secret": "sec_456"},
	}, nil)
	if res2.GetError() != nil {
		t.Fatalf("secret_ref $secret envelope 应被接受，实际错误: %+v", res2.GetError())
	}
	h.account.mu.Lock()
	got2 := h.account.lastSecretRef
	h.account.mu.Unlock()
	if got2 != "sec_456" {
		t.Fatalf("期望透传 secret_ref=sec_456，实际 %q", got2)
	}
}

func TestSSHDPortSagaRollbackIntermediateStageAndKVLessDropIn(t *testing.T) {
	h := newSecurityTestHarness(t, `{"ban_enabled":false}`, time.Hour, time.Hour)

	// Part A: 防火墙恢复短暂失败时，已持久化 SSHD_ROLLED_BACK，重试不再重复调用 SetPort(ROLLBACK)
	prep := runSecurityJob(t, h.srv, "security.sshd.change_port_prepare", map[string]any{"new_port": 2244}, nil)
	if prep.GetError() != nil {
		t.Fatalf("prepare 失败: %+v", prep.GetError())
	}
	var prepOut sshdPortSagaResponse
	if err := json.Unmarshal(prep.GetResultJson(), &prepOut); err != nil {
		t.Fatal(err)
	}

	// 注入一次防火墙读取错误，使 restoreFirewallPorts 短暂失败
	h.fw.mu.Lock()
	h.fw.failErr = &pb.ErrorDetail{Code: "UNAVAILABLE", Message: "transient firewall error"}
	h.fw.mu.Unlock()

	rbFail := runSecurityJob(t, h.srv, "security.sshd.change_port_rollback", map[string]any{"transaction_ref": prepOut.TransactionRef}, nil)
	if rbFail.GetError() == nil {
		t.Fatal("预期防火墙恢复短暂失败时 rollback 返回错误")
	}
	rawSaga, ok := h.kv.rawValue(kvKeyPortSaga)
	if !ok {
		t.Fatal("防火墙恢复失败时 KV 应保留中间态以便重试")
	}
	var midSaga portSagaState
	if err := json.Unmarshal(rawSaga, &midSaga); err != nil || midSaga.Stage != sagaStageSSHDRolledBack {
		t.Fatalf("期望持久化中间态 %s，实际 %+v err=%v", sagaStageSSHDRolledBack, midSaga, err)
	}

	// 第二次重试回滚应跳过 SetPort(ROLLBACK)，直接完成防火墙恢复与 KV 清理
	rbOK := runSecurityJob(t, h.srv, "security.sshd.change_port_rollback", map[string]any{"transaction_ref": prepOut.TransactionRef}, nil)
	if rbOK.GetError() != nil {
		t.Fatalf("二次重试 rollback 失败: %+v", rbOK.GetError())
	}
	if h.kv.hasKey(kvKeyPortSaga) {
		t.Fatal("二次重试 rollback 完成后 KV 应已清理")
	}
	rollbackCount := 0
	for _, st := range h.sshd.stageSnapshot() {
		if st == sshdv1.PortChangeStage_PORT_CHANGE_STAGE_ROLLBACK {
			rollbackCount++
		}
	}
	if rollbackCount != 1 {
		t.Fatalf("SetPort(ROLLBACK) 只能执行 1 次，实际执行 %d 次", rollbackCount)
	}

	// Part B: KV 缺失但操作员传入 transaction_ref 时，应先查询 sshd.GetDropIn 填充 TransactionPort
	h.sshd.mu.Lock()
	h.sshd.dropInTxPort = 2255
	h.sshd.lastRollbackPort = 0
	h.sshd.mu.Unlock()
	kvLessRB := runSecurityJob(t, h.srv, "security.sshd.change_port_rollback", map[string]any{"transaction_ref": "tx-orphan-99"}, nil)
	if kvLessRB.GetError() != nil {
		t.Fatalf("KV 缺失手动回滚失败: %+v", kvLessRB.GetError())
	}
	var kvLessOut sshdPortSagaResponse
	if err := json.Unmarshal(kvLessRB.GetResultJson(), &kvLessOut); err != nil {
		t.Fatal(err)
	}
	h.sshd.mu.Lock()
	gotPort := h.sshd.lastRollbackPort
	h.sshd.mu.Unlock()
	if gotPort != 2255 || kvLessOut.NewPort != 2255 {
		t.Fatalf("KV 缺失回滚应从 GetDropIn 填充 TransactionPort=2255，实际 rpc=%d resp=%d", gotPort, kvLessOut.NewPort)
	}
}

func TestBanLoopEvictionBudgetCapAndCursorAdvancesIndependently(t *testing.T) {
	// 1. 满 4096 条目且单轮出现 10 个超阈值攻击源时，单轮最多淘汰 maxEvictionsPerBanTick(6) 条并封禁 6 个，避免耗尽 12/min 自治写配额
	cfg := `{"ban_enabled":true,"ban_threshold":5,"ban_window_seconds":600,"ban_ttl_seconds":3600}`
	h := newSecurityTestHarness(t, cfg, 40*time.Millisecond, time.Hour)
	nowMs := time.Unix(h.clockSec.Load(), 0).UTC().UnixMilli()

	h.ban.mu.Lock()
	for idx := 0; idx < maxBanEntries; idx++ {
		ip := fmt.Sprintf("10.%d.%d.%d", (idx>>16)&0xff, (idx>>8)&0xff, idx&0xff)
		h.ban.bans[ip] = nowMs + int64(1000+idx*10)
	}
	for i := 1; i <= 10; i++ {
		h.ban.failures = append(h.ban.failures, &banv1.AuthFailure{
			Ip:         fmt.Sprintf("198.51.100.%d", i),
			User:       "root",
			OccurredAt: nowMs - 1000,
			Count:      5,
		})
	}
	h.ban.nextCursor = "cursor-burst-1"
	h.ban.mu.Unlock()

	rc := &pb.RequestContext{InstanceId: "default", NodeId: "local", Locale: "zh-CN"}
	if _, err := h.srv.Activate(t.Context(), &pb.ActivateRequest{Context: rc}); err != nil {
		t.Fatal(err)
	}

	// 经过两轮巡检，10 个攻击源分批完成封禁（第一轮 6 个、第二轮 4 个），总计淘汰 10 个且每轮不超预算
	waitUntil(t, 3*time.Second, "10 个攻击源分批完成淘汰与封禁", func() bool {
		h.ban.mu.Lock()
		defer h.ban.mu.Unlock()
		return len(h.ban.appliedIPs) == 10 && len(h.ban.removedIPs) == 10 && h.ban.applyCalls >= 2
	})

	// 2. ApplyBans 短暂失败时，游标仍独立推进（已摄取日志不再重复累加），因此低于阈值的 IP 不会被重复计数误封
	h2 := newSecurityTestHarness(t, cfg, 30*time.Millisecond, time.Hour)
	nowMs2 := time.Unix(h2.clockSec.Load(), 0).UTC().UnixMilli()
	h2.ban.mu.Lock()
	h2.ban.failures = []*banv1.AuthFailure{
		{Ip: "198.51.100.50", User: "root", OccurredAt: nowMs2 - 1000, Count: 5}, // 达阈值
		{Ip: "198.51.100.51", User: "root", OccurredAt: nowMs2 - 1000, Count: 3}, // 低于阈值，若被重复读取则会变 6 误封
	}
	h2.ban.replayUntilCursor = true
	h2.ban.nextCursor = "cursor-once-1"
	h2.ban.applyFailErr = &pb.ErrorDetail{Code: "UNAVAILABLE", Message: "transient apply failure"}
	h2.ban.mu.Unlock()

	if _, err := h2.srv.Activate(t.Context(), &pb.ActivateRequest{Context: rc}); err != nil {
		t.Fatal(err)
	}

	// 首轮 ApplyBans 失败但游标立即推进到 cursor-once-1，次轮重试仅封禁 198.51.100.50 而绝不误封 198.51.100.51
	waitUntil(t, 3*time.Second, "次轮重试仅封禁达阈值 IP 并推进游标", func() bool {
		h2.ban.mu.Lock()
		applied := slices.Contains(h2.ban.appliedIPs, "198.51.100.50") && h2.ban.applyCalls >= 2
		h2.ban.mu.Unlock()
		rawCur, ok := h2.kv.rawValue(kvKeyBanCursor)
		return applied && ok && strings.Contains(string(rawCur), "cursor-once-1")
	})
	h2.ban.mu.Lock()
	applied2 := append([]string(nil), h2.ban.appliedIPs...)
	h2.ban.mu.Unlock()
	if !slices.Equal(applied2, []string{"198.51.100.50"}) {
		t.Fatalf("低于阈值的 IP 不应因 ApplyBans 失败重试而被重复计数误封，实际: %v", applied2)
	}
}
