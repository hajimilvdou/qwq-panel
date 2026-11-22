// SPDX-License-Identifier: AGPL-3.0-only

package cluster

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"

	"github.com/qwq-panel/qwq/internal/nodespool"
	"github.com/qwq-panel/qwq/internal/storage"
	nodev1 "github.com/qwq-panel/qwq/sdk/gen/qwq/node/v1"
	platformv1 "github.com/qwq-panel/qwq/sdk/gen/qwq/platform/v1"
)

// ======================== 真实 gRPC TLS / mTLS 集群测试夹具 ========================

type clusterHarness struct {
	db          *storage.DB
	ca          *CA
	srv         *Server
	enrollAddr  string
	sessionAddr string
	clockMs     atomic.Int64

	eventsMu sync.Mutex
	events   []*platformv1.Event
}

func newClusterHarness(t *testing.T) *clusterHarness {
	t.Helper()
	dir := t.TempDir()
	db, err := storage.Open(t.Context(), storage.Options{
		Path: filepath.Join(dir, "controller.db"),
	})
	if err != nil {
		t.Fatalf("storage.Open 失败: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	ca, err := OpenCA(dir)
	if err != nil {
		t.Fatalf("OpenCA 失败: %v", err)
	}

	h := &clusterHarness{db: db, ca: ca}
	h.clockMs.Store(time.Now().UTC().UnixMilli())

	srv, err := NewServer(ServerOptions{
		DB:                db,
		CA:                ca,
		ServerDNSNames:    []string{"localhost"},
		ServerIPs:         []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
		HeartbeatInterval: 40 * time.Millisecond,
		Now:               func() time.Time { return time.UnixMilli(h.clockMs.Load()).UTC() },
		OnEvent: func(_ string, ev *platformv1.Event) {
			h.eventsMu.Lock()
			h.events = append(h.events, ev)
			h.eventsMu.Unlock()
		},
	})
	if err != nil {
		t.Fatalf("NewServer 失败: %v", err)
	}
	h.srv = srv

	enrollLis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen enroll: %v", err)
	}
	enrollGRPC := grpc.NewServer(grpc.Creds(credentials.NewTLS(srv.ServerTLSConfig(false))))
	srv.RegisterEnrollment(enrollGRPC)
	go func() { _ = enrollGRPC.Serve(enrollLis) }()
	t.Cleanup(func() {
		enrollGRPC.Stop()
		_ = enrollLis.Close()
	})
	h.enrollAddr = enrollLis.Addr().String()

	sessLis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen session: %v", err)
	}
	sessGRPC := grpc.NewServer(grpc.Creds(credentials.NewTLS(srv.ServerTLSConfig(true))))
	srv.RegisterSession(sessGRPC)
	go func() { _ = sessGRPC.Serve(sessLis) }()
	t.Cleanup(func() {
		sessGRPC.Stop()
		_ = sessLis.Close()
	})
	h.sessionAddr = sessLis.Addr().String()

	return h
}

func waitUntil(t *testing.T, timeout time.Duration, cond func() bool, desc string) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(15 * time.Millisecond)
	}
	t.Fatalf("等待超时 (%s)", desc)
}

// ======================== 独立 CA 持久化与 CSR SAN 剥离安全测试 ========================

func TestCAPersistenceAndCSRSANStripping(t *testing.T) {
	dir := t.TempDir()
	ca1, err := OpenCA(dir)
	if err != nil {
		t.Fatalf("首次 OpenCA 失败: %v", err)
	}
	pin1 := ca1.SPKIPinSHA256()
	if !strings.HasPrefix(pin1, "sha256:") || len(pin1) != 7+64 {
		t.Fatalf("SPKIPinSHA256 格式异常: %q", pin1)
	}
	if runtime.GOOS != "windows" {
		st, err := os.Stat(filepath.Join(dir, "cluster", caKeyFileName))
		if err != nil || st.Mode().Perm() != 0o600 {
			t.Fatalf("ca.key 权限应为 0600，实际 err=%v perm=%o", err, st.Mode().Perm())
		}
	}

	ca2, err := OpenCA(dir)
	if err != nil {
		t.Fatalf("重新加载 OpenCA 失败: %v", err)
	}
	if ca2.SPKIPinSHA256() != pin1 {
		t.Fatalf("重开 CA 后 SPKI 摘要变化: got %s want %s", ca2.SPKIPinSHA256(), pin1)
	}

	// 恶意 CSR 伪造 Subject/DNS/URI SAN，控制面签发必须完全忽略并仅写入分配的 qwq://node/<id>。
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	spoofURI, _ := url.Parse("qwq://node/spoofed-root")
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: "spoofed-root"},
		DNSNames: []string{"evil.example.com"},
		URIs:     []*url.URL{spoofURI},
	}, priv)
	if err != nil {
		t.Fatal(err)
	}

	signed, err := ca2.SignNodeCSR(csrDER, "node_real001", DefaultCertTTL)
	if err != nil {
		t.Fatalf("SignNodeCSR 失败: %v", err)
	}
	cert, err := x509.ParseCertificate(signed.CertDER)
	if err != nil {
		t.Fatal(err)
	}
	if len(cert.DNSNames) != 0 || len(cert.IPAddresses) != 0 {
		t.Fatalf("节点客户端证书不应继承 CSR 的 DNS/IP SAN: dns=%v ip=%v", cert.DNSNames, cert.IPAddresses)
	}
	if !slices.Contains(cert.ExtKeyUsage, x509.ExtKeyUsageClientAuth) || slices.Contains(cert.ExtKeyUsage, x509.ExtKeyUsageServerAuth) {
		t.Fatalf("节点证书 ExtKeyUsage 异常: %+v", cert.ExtKeyUsage)
	}
	gotNodeID, err := ExtractNodeID(cert)
	if err != nil || gotNodeID != "node_real001" {
		t.Fatalf("ExtractNodeID 应提取控制面分配 ID，实际 id=%q err=%v", gotNodeID, err)
	}
}

// ======================== 端到端入网、重放防护、mTLS 会话、Spool 续传、换证与实时吊销 ========================

func TestClusterE2EEnrollSessionRotateAndRevoke(t *testing.T) {
	h := newClusterHarness(t)
	ctx := t.Context()

	tok, err := h.srv.CreateEnrollmentToken(ctx, "edge-tokyo-1", ModeFull, "usr_admin", 10*time.Minute)
	if err != nil {
		t.Fatalf("CreateEnrollmentToken 失败: %v", err)
	}

	agentDir := t.TempDir()

	// 1) 错误 --ca-hash 必须被 SPKI 钉扎在 TLS 握手阶段拦截（防 MITM）。
	wrongHash := "sha256:" + strings.Repeat("a", 64)
	if _, err := EnrollAgent(ctx, EnrollOptions{
		ControllerAddr: h.enrollAddr,
		CAHash:         wrongHash,
		Token:          tok.Token,
		DataDir:        agentDir,
		AgentVersion:   "0.1.0-test",
		DialTimeout:    3 * time.Second,
	}); err == nil {
		t.Fatal("错误的 --ca-hash 应当被 SPKI 钉扎拒绝")
	}

	// 2) 正确 --ca-hash 成功入网，本地生成 0600 私钥并落盘证书。
	enrollRes, err := EnrollAgent(ctx, EnrollOptions{
		ControllerAddr: h.enrollAddr,
		CAHash:         h.ca.SPKIPinSHA256(),
		Token:          tok.Token,
		DataDir:        agentDir,
		AgentVersion:   "0.1.0-test",
		DialTimeout:    5 * time.Second,
	})
	if err != nil {
		t.Fatalf("正确 --ca-hash 入网失败: %v", err)
	}
	if !strings.HasPrefix(enrollRes.NodeID, "node_") {
		t.Fatalf("node_id 前缀异常: %q", enrollRes.NodeID)
	}
	if runtime.GOOS != "windows" {
		st, err := os.Stat(enrollRes.KeyPath)
		if err != nil || st.Mode().Perm() != 0o600 {
			t.Fatalf("node.key 权限应为 0600，实际 err=%v perm=%o", err, st.Mode().Perm())
		}
	}

	// 3) 一次性入网令牌严禁重放。
	if _, err := EnrollAgent(ctx, EnrollOptions{
		ControllerAddr: h.enrollAddr,
		CAHash:         h.ca.SPKIPinSHA256(),
		Token:          tok.Token,
		DataDir:        t.TempDir(),
		AgentVersion:   "0.1.0-test",
		DialTimeout:    3 * time.Second,
	}); err == nil || status.Code(err) != codes.FailedPrecondition && !strings.Contains(err.Error(), "already redeemed") {
		t.Fatalf("重复使用一次性入网令牌应被拒绝，实际: %v", err)
	}

	// 4) mTLS 双向长连接会话：离线 Spool 积压事件按序续传 + EventAck 自动清理 + 心跳刷新 last_heartbeat_at。
	spool, err := nodespool.Open(ctx, filepath.Join(agentDir, "spool.db"), nodespool.DefaultMaxBytes)
	if err != nil {
		t.Fatalf("打开 nodespool 失败: %v", err)
	}
	defer spool.Close()

	for _, id := range []string{"evt-off-1", "evt-off-2", "evt-off-3"} {
		if _, err := spool.Append(ctx, id, "op.completed", nodespool.PriorityCritical, []byte(`{"ok":true}`), time.Now()); err != nil {
			t.Fatalf("写入离线事件 %s 失败: %v", id, err)
		}
	}

	beforeRec, err := h.srv.GetNode(ctx, enrollRes.NodeID)
	if err != nil {
		t.Fatalf("查询节点记录失败: %v", err)
	}
	// 推进模拟时钟 2 秒，验证心跳更新 last_heartbeat_at。
	h.clockMs.Add(2000)

	var (
		welcomed atomic.Bool
		ackedSeq atomic.Uint64
	)
	sessCtx, cancelSess := context.WithCancel(ctx)
	sessDone := make(chan error, 1)
	go func() {
		sessDone <- AgentSession(sessCtx, SessionOptions{
			ControllerAddr:    h.sessionAddr,
			DataDir:           agentDir,
			Mode:              ModeFull,
			AgentVersion:      "0.1.0-test",
			Spool:             spool,
			HeartbeatInterval: 40 * time.Millisecond,
			SpoolPollInterval: 30 * time.Millisecond,
			OnWelcome: func(w *nodev1.Welcome) {
				if w.GetNodeId() == enrollRes.NodeID {
					welcomed.Store(true)
				}
			},
			OnEventAck: func(seq uint64) {
				ackedSeq.Store(seq)
			},
		})
	}()

	waitUntil(t, 5*time.Second, func() bool {
		return welcomed.Load() && slices.Contains(h.srv.ConnectedNodes(), enrollRes.NodeID)
	}, "节点上线完成 Hello/Welcome")

	waitUntil(t, 5*time.Second, func() bool {
		st, serr := spool.Stats(ctx)
		return serr == nil && ackedSeq.Load() >= 3 && st.Count == 0
	}, "离线 Spool 事件全部送达并经 EventAck 截断")

	h.eventsMu.Lock()
	evCount := len(h.events)
	h.eventsMu.Unlock()
	if evCount != 3 {
		t.Fatalf("控制面应收到 3 条续传事件，实际 %d", evCount)
	}

	waitUntil(t, 5*time.Second, func() bool {
		rec, gerr := h.srv.GetNode(ctx, enrollRes.NodeID)
		return gerr == nil && rec.LastAckSeq >= 3 && rec.LastHeartbeatAt > beforeRec.LastHeartbeatAt
	}, "控制面持久化 last_ack_seq 与刷新 last_heartbeat_at")

	cancelSess()
	<-sessDone

	// 5) RotateCertificate 无感换证：更新 cert_serial 且旧证书立即失效。
	oldDir := t.TempDir()
	copyIdentityDir(t, agentDir, oldDir)

	tlsCfg, leafBefore, _, err := LoadClientTLSConfig(agentDir, "")
	if err != nil {
		t.Fatalf("LoadClientTLSConfig 失败: %v", err)
	}
	if ShouldRotateCert(leafBefore, leafBefore.NotAfter.Add(-20*24*time.Hour)) {
		t.Fatal("距过期 20 天不应触发轮换")
	}
	if !ShouldRotateCert(leafBefore, leafBefore.NotAfter.Add(-9*24*time.Hour)) {
		t.Fatal("距过期 9 天（<10 天）应触发轮换")
	}

	rotConn, err := dialGRPC(h.sessionAddr, tlsCfg)
	if err != nil {
		t.Fatalf("dial rotate: %v", err)
	}
	newLeaf, err := RotateLocalCert(ctx, nodev1.NewNodeSessionServiceClient(rotConn), agentDir)
	_ = rotConn.Close()
	if err != nil {
		t.Fatalf("RotateLocalCert 失败: %v", err)
	}
	if formatSerialHex(newLeaf.SerialNumber) == enrollRes.CertSerial {
		t.Fatal("换证后证书序列号未更新")
	}
	recAfterRot, err := h.srv.GetNode(ctx, enrollRes.NodeID)
	if err != nil || recAfterRot.CertSerial != formatSerialHex(newLeaf.SerialNumber) {
		t.Fatalf("数据库 cert_serial 未更新: db=%q want=%q err=%v", recAfterRot.CertSerial, formatSerialHex(newLeaf.SerialNumber), err)
	}

	// 旧证书必须被 VerifyConnection 立即拒连！
	oldCtx, oldCancel := context.WithTimeout(ctx, 2*time.Second)
	defer oldCancel()
	if err := AgentSession(oldCtx, SessionOptions{
		ControllerAddr: h.sessionAddr,
		DataDir:        oldDir,
		Mode:           ModeFull,
	}); err == nil {
		t.Fatal("已被替换的旧证书必须无法通过 mTLS 握手建立会话")
	}

	// 6) 新证书上线后执行 RevokeNode：毫秒级踢断在线流并拦截后续 mTLS 重连。
	liveWelcomed := make(chan struct{}, 1)
	liveCtx, liveCancel := context.WithCancel(ctx)
	defer liveCancel()
	liveDone := make(chan error, 1)
	go func() {
		liveDone <- AgentSession(liveCtx, SessionOptions{
			ControllerAddr:    h.sessionAddr,
			DataDir:           agentDir,
			Mode:              ModeFull,
			HeartbeatInterval: time.Second,
			OnWelcome: func(*nodev1.Welcome) {
				select {
				case liveWelcomed <- struct{}{}:
				default:
				}
			},
		})
	}()

	select {
	case <-liveWelcomed:
	case <-time.After(5 * time.Second):
		t.Fatal("换证后新证书未能上线")
	}

	if err := h.srv.RevokeNode(ctx, enrollRes.NodeID); err != nil {
		t.Fatalf("RevokeNode 失败: %v", err)
	}

	select {
	case kickErr := <-liveDone:
		if kickErr == nil {
			t.Fatal("被吊销节点的在途流应以非空错误被踢断")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("RevokeNode 未在预期时间内踢断在线会话")
	}

	waitUntil(t, 2*time.Second, func() bool {
		return !slices.Contains(h.srv.ConnectedNodes(), enrollRes.NodeID)
	}, "在线节点注册表清除已吊销节点")

	// 吊销后的重连必须在 mTLS 握手层直接被拒绝。
	reconnCtx, reconnCancel := context.WithTimeout(ctx, 2*time.Second)
	defer reconnCancel()
	if err := AgentSession(reconnCtx, SessionOptions{
		ControllerAddr: h.sessionAddr,
		DataDir:        agentDir,
		Mode:           ModeFull,
	}); err == nil {
		t.Fatal("已吊销节点的后续 mTLS 重连应当被拦截")
	}
}

// ======================== probe_512m 档位资源硬闸门测试 ========================

func TestProbe512MPolicyGate(t *testing.T) {
	if DefaultProbe512MPolicy.MemoryLimitBytes != 24<<20 {
		t.Fatalf("probe_512m 内存上限应为 24 MiB，实际 %d", DefaultProbe512MPolicy.MemoryLimitBytes)
	}
	if err := AllowPluginInMode(ModeProbe512M, 64); err != nil {
		t.Fatalf("64 MiB 插件在 probe_512m 下应放行: %v", err)
	}
	if err := AllowPluginInMode(ModeProbe512M, 65); err == nil || !strings.Contains(err.Error(), "NODE_POLICY_DENIED") {
		t.Fatalf(">64 MiB 插件在 probe_512m 下必须返回 NODE_POLICY_DENIED，实际: %v", err)
	}
	if err := AllowPluginInMode(ModeFull, 256); err != nil {
		t.Fatalf("full 模式应允许 256 MiB 插件: %v", err)
	}
	if err := AllowPluginInMode("unknown", 32); err == nil {
		t.Fatal("非法运行档位应当被拒绝")
	}
}

func copyIdentityDir(t *testing.T, srcRoot, dstRoot string) {
	t.Helper()
	srcDir := filepath.Join(srcRoot, identityDirName)
	dstDir := filepath.Join(dstRoot, identityDirName)
	if err := os.MkdirAll(dstDir, 0o700); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(srcDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(srcDir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dstDir, e.Name()), raw, 0o600); err != nil {
			t.Fatal(err)
		}
	}
}
