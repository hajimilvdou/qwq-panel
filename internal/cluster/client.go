// SPDX-License-Identifier: AGPL-3.0-only

package cluster

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/qwq-panel/qwq/internal/nodespool"
	nodev1 "github.com/qwq-panel/qwq/sdk/gen/qwq/node/v1"
	platformv1 "github.com/qwq-panel/qwq/sdk/gen/qwq/platform/v1"
)

// ======================== probe_512m 档位硬策略与身份文件路径 ========================

const (
	// Probe512MMemoryLimitBytes 是 512MB 低配探针节点的 Go 软内存上限（24 MiB）。
	Probe512MMemoryLimitBytes int64 = 24 << 20

	// Probe512MMaxPluginMemoryMB 是 512MB 档位允许运行的单插件最大内存预算（64 MiB）。
	Probe512MMaxPluginMemoryMB = 64

	// DefaultRotateBeforeExpiry 触发证书无感自动轮换的临期窗口（到期前 10 天内）。
	DefaultRotateBeforeExpiry = 10 * 24 * time.Hour

	identityDirName = "identity"
	nodeKeyFileName = "node.key"
	nodeCertName    = "node.crt"
	clusterCAName   = "cluster-ca.pem"
	nodeIDFileName  = "node_id"
)

// Probe512MPolicy 定义 512MB 边缘探针档位的资源硬闸门。
type Probe512MPolicy struct {
	MemoryLimitBytes  int64
	MaxPluginMemoryMB int
}

// DefaultProbe512MPolicy 返回默认 512MB 探针档位策略（GOMEMLIMIT=24MiB，单插件 <= 64MB）。
var DefaultProbe512MPolicy = Probe512MPolicy{
	MemoryLimitBytes:  Probe512MMemoryLimitBytes,
	MaxPluginMemoryMB: Probe512MMaxPluginMemoryMB,
}

// AllowPluginInMode 校验给定内存配额的插件是否允许在目标节点运行档位下部署。
func AllowPluginInMode(mode string, pluginMemoryMB int) error {
	switch mode {
	case ModeFull:
		return nil
	case ModeProbe512M:
		if pluginMemoryMB > DefaultProbe512MPolicy.MaxPluginMemoryMB {
			return fmt.Errorf("NODE_POLICY_DENIED: plugin memory_max_mb=%d exceeds probe_512m limit (%d MiB)",
				pluginMemoryMB, DefaultProbe512MPolicy.MaxPluginMemoryMB)
		}
		return nil
	default:
		return fmt.Errorf("cluster: unsupported agent mode %q (want full or probe_512m)", mode)
	}
}

// ======================== SPKI 钉扎入网（EnrollAgent） ========================

// EnrollOptions 配置边缘节点首次入网参数。
type EnrollOptions struct {
	ControllerAddr string
	CAHash         string
	Token          string
	DataDir        string
	AgentVersion   string
	Facts          *nodev1.NodeFacts
	DialTimeout    time.Duration
}

// EnrollResult 描述入网成功后落盘的本地节点身份材料位置与证书元数据。
type EnrollResult struct {
	NodeID        string
	KeyPath       string
	CertPath      string
	CAPath        string
	NodeIDPath    string
	CertSerial    string
	CertExpiresAt time.Time
}

// EnrollAgent 在本机生成 ECDSA P-256 私钥并写入 <dataDir>/identity/node.key（0600，私钥永不离开本机），
// 以 SPKI 钉扎校验控制面 TLS 身份后提交 CSR 完成入网并原子落盘证书与 CA 信任锚。
func EnrollAgent(ctx context.Context, opts EnrollOptions) (*EnrollResult, error) {
	if strings.TrimSpace(opts.ControllerAddr) == "" {
		return nil, errors.New("cluster: controller address is required")
	}
	if strings.TrimSpace(opts.CAHash) == "" {
		return nil, errors.New("cluster: ca-hash is required for SPKI pinning")
	}
	if strings.TrimSpace(opts.Token) == "" {
		return nil, errors.New("cluster: enrollment token is required")
	}
	if strings.TrimSpace(opts.DataDir) == "" {
		return nil, errors.New("cluster: dataDir is required")
	}

	idDir := filepath.Join(opts.DataDir, identityDirName)
	if err := os.MkdirAll(idDir, 0o700); err != nil {
		return nil, fmt.Errorf("cluster: create identity dir: %w", err)
	}

	priv, keyPEM, csrDER, err := generateLocalKeyAndCSR()
	if err != nil {
		return nil, err
	}
	defer clear(keyPEM)

	// #nosec G402 -- 首次入网阶段无预置私有 CA，通过 VerifySPKIPin 强制校验服务端证书链 SPKI SHA-256 钉扎防 MITM。
	tlsCfg := &tls.Config{
		MinVersion:            tls.VersionTLS13,
		InsecureSkipVerify:    true,
		VerifyPeerCertificate: VerifySPKIPin(opts.CAHash),
	}

	conn, err := dialGRPC(opts.ControllerAddr, tlsCfg)
	if err != nil {
		return nil, fmt.Errorf("cluster: dial enrollment endpoint: %w", err)
	}
	defer conn.Close()

	callCtx := ctx
	if opts.DialTimeout > 0 {
		var cancel context.CancelFunc
		callCtx, cancel = context.WithTimeout(ctx, opts.DialTimeout)
		defer cancel()
	}

	facts := opts.Facts
	if facts == nil {
		facts = defaultNodeFacts()
	}
	client := nodev1.NewNodeEnrollmentServiceClient(conn)
	resp, err := client.Enroll(callCtx, &nodev1.EnrollRequest{
		Token:        strings.TrimSpace(opts.Token),
		CsrDer:       csrDER,
		AgentVersion: strings.TrimSpace(opts.AgentVersion),
		Facts:        facts,
	})
	if err != nil {
		return nil, fmt.Errorf("cluster: enroll rpc: %w", err)
	}

	leaf, err := x509.ParseCertificate(resp.GetCertificateDer())
	if err != nil {
		return nil, fmt.Errorf("cluster: parse issued node cert: %w", err)
	}
	certNodeID, err := ExtractNodeID(leaf)
	if err != nil {
		return nil, fmt.Errorf("cluster: verify issued node cert uri: %w", err)
	}
	if certNodeID != resp.GetNodeId() {
		return nil, errors.New("cluster: issued certificate node_id mismatch")
	}
	if !pubKeysEqual(&priv.PublicKey, leaf.PublicKey) {
		return nil, errors.New("cluster: issued certificate public key does not match local private key")
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: pemTypeCert, Bytes: resp.GetCertificateDer()})
	var caPEM []byte
	for _, caDER := range resp.GetCaCertificatesDer() {
		caPEM = append(caPEM, pem.EncodeToMemory(&pem.Block{Type: pemTypeCert, Bytes: caDER})...)
	}
	if len(caPEM) == 0 {
		return nil, errors.New("cluster: enrollment response missing cluster CA certificate")
	}

	keyPath := filepath.Join(idDir, nodeKeyFileName)
	certPath := filepath.Join(idDir, nodeCertName)
	caPath := filepath.Join(idDir, clusterCAName)
	nodeIDPath := filepath.Join(idDir, nodeIDFileName)

	if err := writeFileAtomic(keyPath, keyPEM, 0o600); err != nil {
		return nil, fmt.Errorf("cluster: write node key: %w", err)
	}
	if err := writeFileAtomic(certPath, certPEM, 0o644); err != nil {
		return nil, fmt.Errorf("cluster: write node cert: %w", err)
	}
	if err := writeFileAtomic(caPath, caPEM, 0o644); err != nil {
		return nil, fmt.Errorf("cluster: write cluster ca: %w", err)
	}
	if err := writeFileAtomic(nodeIDPath, []byte(certNodeID+"\n"), 0o644); err != nil {
		return nil, fmt.Errorf("cluster: write node_id: %w", err)
	}

	return &EnrollResult{
		NodeID:        certNodeID,
		KeyPath:       keyPath,
		CertPath:      certPath,
		CAPath:        caPath,
		NodeIDPath:    nodeIDPath,
		CertSerial:    formatSerialHex(leaf.SerialNumber),
		CertExpiresAt: leaf.NotAfter,
	}, nil
}

// ======================== 证书临期检查与无感自动轮换 ========================

// ShouldRotateCert 判断节点客户端证书是否已进入到期前 10 天内的轮换窗口。
func ShouldRotateCert(cert *x509.Certificate, now time.Time) bool {
	if cert == nil {
		return true
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	return cert.NotAfter.Sub(now) <= DefaultRotateBeforeExpiry
}

// RotateLocalCert 在已认证的 mTLS 连接上生成全新 ECDSA P-256 密钥与 CSR，
// 调用 RotateCertificate 获取新 30 天证书后原子替换本地 node.key 与 node.crt。
func RotateLocalCert(ctx context.Context, client nodev1.NodeSessionServiceClient, dataDir string) (*x509.Certificate, error) {
	if client == nil {
		return nil, errors.New("cluster: session client is required")
	}
	if strings.TrimSpace(dataDir) == "" {
		return nil, errors.New("cluster: dataDir is required")
	}
	priv, keyPEM, csrDER, err := generateLocalKeyAndCSR()
	if err != nil {
		return nil, err
	}
	defer clear(keyPEM)

	resp, err := client.RotateCertificate(ctx, &nodev1.RotateCertificateRequest{
		CsrDer: csrDER,
	})
	if err != nil {
		return nil, fmt.Errorf("cluster: rotate certificate rpc: %w", err)
	}
	leaf, err := x509.ParseCertificate(resp.GetCertificateDer())
	if err != nil {
		return nil, fmt.Errorf("cluster: parse rotated cert: %w", err)
	}
	if !pubKeysEqual(&priv.PublicKey, leaf.PublicKey) {
		return nil, errors.New("cluster: rotated certificate public key mismatch")
	}

	idDir := filepath.Join(dataDir, identityDirName)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: pemTypeCert, Bytes: resp.GetCertificateDer()})
	if err := writeFileAtomic(filepath.Join(idDir, nodeKeyFileName), keyPEM, 0o600); err != nil {
		return nil, fmt.Errorf("cluster: write rotated key: %w", err)
	}
	if err := writeFileAtomic(filepath.Join(idDir, nodeCertName), certPEM, 0o644); err != nil {
		return nil, fmt.Errorf("cluster: write rotated cert: %w", err)
	}
	if len(resp.GetCaCertificatesDer()) > 0 {
		var caPEM []byte
		for _, caDER := range resp.GetCaCertificatesDer() {
			caPEM = append(caPEM, pem.EncodeToMemory(&pem.Block{Type: pemTypeCert, Bytes: caDER})...)
		}
		if len(caPEM) > 0 {
			if err := writeFileAtomic(filepath.Join(idDir, clusterCAName), caPEM, 0o644); err != nil {
				return nil, fmt.Errorf("cluster: write rotated ca: %w", err)
			}
		}
	}
	return leaf, nil
}

// LoadClientTLSConfig 从 <dataDir>/identity/ 加载 mTLS 1.3 客户端证书、私钥与集群 CA 信任池。
func LoadClientTLSConfig(dataDir, serverName string) (*tls.Config, *x509.Certificate, string, error) {
	idDir := filepath.Join(dataDir, identityDirName)
	certPEM, err := os.ReadFile(filepath.Join(idDir, nodeCertName))
	if err != nil {
		return nil, nil, "", fmt.Errorf("cluster: read node cert: %w", err)
	}
	keyPEM, err := os.ReadFile(filepath.Join(idDir, nodeKeyFileName))
	if err != nil {
		return nil, nil, "", fmt.Errorf("cluster: read node key: %w", err)
	}
	defer clear(keyPEM)

	caPEM, err := os.ReadFile(filepath.Join(idDir, clusterCAName))
	if err != nil {
		return nil, nil, "", fmt.Errorf("cluster: read cluster ca: %w", err)
	}

	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, nil, "", fmt.Errorf("cluster: load client keypair: %w", err)
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return nil, nil, "", fmt.Errorf("cluster: parse client leaf cert: %w", err)
	}
	nodeID, err := ExtractNodeID(leaf)
	if err != nil {
		return nil, nil, "", err
	}

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, nil, "", errors.New("cluster: invalid cluster CA PEM")
	}

	cfg := &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{pair},
		RootCAs:      pool,
		ServerName:   strings.TrimSpace(serverName),
	}
	return cfg, leaf, nodeID, nil
}

// ======================== mTLS 双向长连接会话与离线 Spool 续传 ========================

// SessionOptions 配置边缘节点与控制面的 mTLS 双向长连接会话。
type SessionOptions struct {
	ControllerAddr    string
	DataDir           string
	Mode              string
	AgentVersion      string
	ServerName        string
	Spool             *nodespool.Spool
	Facts             *nodev1.NodeFacts
	HeartbeatInterval time.Duration
	SpoolPollInterval time.Duration
	Now               func() time.Time
	OnWelcome         func(*nodev1.Welcome)
	OnEventAck        func(uint64)
}

// AgentSession 建立 mTLS 1.3 长连接，按需自动轮换临期证书，完成 Hello/Welcome 握手，
// 周期发送心跳，并将 nodespool 中 last_event_sequence 之后的离线事件按序续传并在收到 EventAck 后安全截断。
func AgentSession(ctx context.Context, opts SessionOptions) error {
	if strings.TrimSpace(opts.ControllerAddr) == "" {
		return errors.New("cluster: controller address is required")
	}
	if strings.TrimSpace(opts.DataDir) == "" {
		return errors.New("cluster: dataDir is required")
	}
	nowFn := opts.Now
	if nowFn == nil {
		nowFn = time.Now
	}

	tlsCfg, leaf, nodeID, err := LoadClientTLSConfig(opts.DataDir, opts.ServerName)
	if err != nil {
		return err
	}
	conn, err := dialGRPC(opts.ControllerAddr, tlsCfg)
	if err != nil {
		return fmt.Errorf("cluster: dial session endpoint: %w", err)
	}

	client := nodev1.NewNodeSessionServiceClient(conn)
	if ShouldRotateCert(leaf, nowFn().UTC()) {
		if _, rerr := RotateLocalCert(ctx, client, opts.DataDir); rerr != nil {
			_ = conn.Close()
			return rerr
		}
		_ = conn.Close()
		tlsCfg, _, nodeID, err = LoadClientTLSConfig(opts.DataDir, opts.ServerName)
		if err != nil {
			return err
		}
		conn, err = dialGRPC(opts.ControllerAddr, tlsCfg)
		if err != nil {
			return fmt.Errorf("cluster: redial after cert rotation: %w", err)
		}
		client = nodev1.NewNodeSessionServiceClient(conn)
	}
	defer conn.Close()

	stream, err := client.Session(ctx)
	if err != nil {
		return fmt.Errorf("cluster: open session stream: %w", err)
	}

	var firstSpooled uint64
	if opts.Spool != nil {
		if st, serr := opts.Spool.Stats(ctx); serr == nil {
			firstSpooled = st.FirstSeq
		}
	}
	facts := opts.Facts
	if facts == nil {
		facts = defaultNodeFacts()
	}

	if err := stream.Send(&nodev1.SessionRequest{
		Frame: &nodev1.SessionRequest_Hello{
			Hello: &nodev1.Hello{
				MinProtocolVersion:        NodeProtocolVersion,
				MaxProtocolVersion:        NodeProtocolVersion,
				AgentVersion:              strings.TrimSpace(opts.AgentVersion),
				Facts:                     facts,
				FirstSpooledEventSequence: firstSpooled,
			},
		},
	}); err != nil {
		return fmt.Errorf("cluster: send hello: %w", err)
	}

	firstResp, err := stream.Recv()
	if err != nil {
		return fmt.Errorf("cluster: recv welcome: %w", err)
	}
	welcome := firstResp.GetWelcome()
	if welcome == nil {
		return errors.New("cluster: expected Welcome as first controller frame")
	}
	if opts.OnWelcome != nil {
		opts.OnWelcome(welcome)
	}

	var sendMu sync.Mutex
	sendFrame := func(req *nodev1.SessionRequest) error {
		sendMu.Lock()
		defer sendMu.Unlock()
		return stream.Send(req)
	}

	sentUpTo := welcome.GetLastEventSequence()
	flushSpool := func() error {
		if opts.Spool == nil {
			return nil
		}
		for {
			entries, rerr := opts.Spool.ReadAfter(ctx, sentUpTo, 64)
			if rerr != nil {
				return rerr
			}
			if len(entries) == 0 {
				return nil
			}
			events := make([]*platformv1.Event, 0, len(entries))
			for _, e := range entries {
				events = append(events, &platformv1.Event{
					EventId:          e.EventID,
					Sequence:         e.Seq,
					Type:             e.Topic,
					OccurredAtUnixMs: e.CreatedAt,
					NodeId:           nodeID,
					PayloadJson:      e.Payload,
				})
				if e.Seq > sentUpTo {
					sentUpTo = e.Seq
				}
			}
			var dropped uint64
			if st, serr := opts.Spool.Stats(ctx); serr == nil && st.DroppedMetrics > 0 {
				dropped = uint64(st.DroppedMetrics)
			}
			if err := sendFrame(&nodev1.SessionRequest{
				Frame: &nodev1.SessionRequest_EventBatch{
					EventBatch: &nodev1.EventBatch{
						Events:       events,
						DroppedLossy: dropped,
					},
				},
			}); err != nil {
				return err
			}
			if len(entries) < 64 {
				return nil
			}
		}
	}

	recvErrCh := make(chan error, 1)
	go func() {
		for {
			resp, rerr := stream.Recv()
			if rerr != nil {
				recvErrCh <- rerr
				return
			}
			switch f := resp.GetFrame().(type) {
			case *nodev1.SessionResponse_EventAck:
				ackSeq := f.EventAck.GetSequence()
				if opts.Spool != nil && ackSeq > 0 {
					_, _ = opts.Spool.Ack(ctx, ackSeq)
				}
				if opts.OnEventAck != nil {
					opts.OnEventAck(ackSeq)
				}
			case *nodev1.SessionResponse_ResyncRequest:
				_ = sendFrame(&nodev1.SessionRequest{
					Frame: &nodev1.SessionRequest_StateReport{
						StateReport: &nodev1.StateReport{},
					},
				})
			}
		}
	}()

	// 握手成功后第一时间补传离线期间积压的 Spool 事件。
	if err := flushSpool(); err != nil {
		return err
	}

	hbInterval := opts.HeartbeatInterval
	if hbInterval <= 0 {
		if ms := welcome.GetHeartbeatIntervalMs(); ms > 0 {
			hbInterval = time.Duration(ms) * time.Millisecond
		} else {
			hbInterval = DefaultHeartbeatInterval
		}
	}
	pollInterval := opts.SpoolPollInterval
	if pollInterval <= 0 {
		pollInterval = 250 * time.Millisecond
	}

	hbTicker := time.NewTicker(hbInterval)
	defer hbTicker.Stop()
	pollTicker := time.NewTicker(pollInterval)
	defer pollTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			sendMu.Lock()
			_ = stream.CloseSend()
			sendMu.Unlock()
			return ctx.Err()
		case rerr := <-recvErrCh:
			if errors.Is(rerr, io.EOF) {
				return nil
			}
			return rerr
		case <-hbTicker.C:
			if err := sendFrame(&nodev1.SessionRequest{
				Frame: &nodev1.SessionRequest_Heartbeat{
					Heartbeat: &nodev1.Heartbeat{SentAtUnixMs: nowFn().UTC().UnixMilli()},
				},
			}); err != nil {
				return err
			}
		case <-pollTicker.C:
			if err := flushSpool(); err != nil {
				return err
			}
		}
	}
}

// ======================== 客户端内部辅助 ========================

func dialGRPC(addr string, tlsCfg *tls.Config) (*grpc.ClientConn, error) {
	target := strings.TrimSpace(addr)
	if !strings.Contains(target, "://") {
		target = "passthrough:///" + target
	}
	return grpc.NewClient(target, grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)))
}

func generateLocalKeyAndCSR() (*ecdsa.PrivateKey, []byte, []byte, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("cluster: generate node key: %w", err)
	}
	pkcs8DER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("cluster: marshal node key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: pemTypePrivateKey, Bytes: pkcs8DER})
	clear(pkcs8DER)

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "qwq-agent-enroll"},
	}, priv)
	if err != nil {
		clear(keyPEM)
		return nil, nil, nil, fmt.Errorf("cluster: create csr: %w", err)
	}
	return priv, keyPEM, csrDER, nil
}

func pubKeysEqual(a, b any) bool {
	ea, okA := a.(*ecdsa.PublicKey)
	eb, okB := b.(*ecdsa.PublicKey)
	return okA && okB && ea.Equal(eb)
}

func defaultNodeFacts() *nodev1.NodeFacts {
	host, _ := os.Hostname()
	return &nodev1.NodeFacts{
		Hostname: host,
		Os:       runtime.GOOS,
		Arch:     runtime.GOOS + "/" + runtime.GOARCH,
		CpuCount: uint32(runtime.NumCPU()),
	}
}
