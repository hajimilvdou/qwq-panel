// SPDX-License-Identifier: AGPL-3.0-only

package cluster

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	"github.com/qwq-panel/qwq/internal/storage"
	nodev1 "github.com/qwq-panel/qwq/sdk/gen/qwq/node/v1"
	platformv1 "github.com/qwq-panel/qwq/sdk/gen/qwq/platform/v1"
)

// ======================== 常量、模型与服务端配置 ========================

const (
	// NodeProtocolVersion 为当前控制面与边缘节点通信协议主版本号。
	NodeProtocolVersion uint32 = 1

	// DefaultHeartbeatInterval 为默认心跳周期（15 秒）。
	DefaultHeartbeatInterval = 15 * time.Second

	// DefaultEnrollTokenTTL 为一次性入网令牌默认有效期（15 分钟）。
	DefaultEnrollTokenTTL = 15 * time.Minute

	ModeFull      = "full"
	ModeProbe512M = "probe_512m"
)

// NodeRecord 描述 nodes 表中的边缘节点持久化状态视图。
type NodeRecord struct {
	ID              string   `json:"id"`
	Name            string   `json:"name"`
	Mode            string   `json:"mode"`
	EnrollmentState string   `json:"enrollment_state"`
	CertSerial      string   `json:"cert_serial"`
	CertFingerprint string   `json:"cert_fingerprint"`
	CertExpiresAt   int64    `json:"cert_expires_at"`
	AgentVersion    string   `json:"agent_version"`
	Arch            string   `json:"arch"`
	PublicAddrs     []string `json:"public_addrs"`
	LastHeartbeatAt int64    `json:"last_heartbeat_at"`
	LastAckSeq      int64    `json:"last_ack_seq"`
	Revision        string   `json:"revision"`
	CreatedAt       int64    `json:"created_at"`
	UpdatedAt       int64    `json:"updated_at"`
}

// EnrollmentToken 描述一次签发的一次性节点入网令牌（仅创建响应返回明文 Token）。
type EnrollmentToken struct {
	ID          string `json:"id"`
	Token       string `json:"token"`
	TokenSHA256 string `json:"token_sha256"`
	PresetName  string `json:"preset_name"`
	Mode        string `json:"mode"`
	ExpiresAt   int64  `json:"expires_at"`
	CreatedBy   string `json:"created_by"`
	CreatedAt   int64  `json:"created_at"`
}

// ServerOptions 配置多节点控制面集群服务端。
type ServerOptions struct {
	DB                *storage.DB
	CA                *CA
	ServerDNSNames    []string
	ServerIPs         []net.IP
	CertTTL           time.Duration
	HeartbeatInterval time.Duration
	Now               func() time.Time
	OnEvent           func(nodeID string, ev *platformv1.Event)
}

type activeSession struct {
	id          uint64
	cancel      context.CancelFunc
	connectedAt time.Time
}

// Server 同时实现 NodeEnrollmentServiceServer 与 NodeSessionServiceServer，
// 维护在线节点注册表并提供实时吊销与毫秒级踢断能力。
type Server struct {
	nodev1.UnimplementedNodeEnrollmentServiceServer
	nodev1.UnimplementedNodeSessionServiceServer

	db                *storage.DB
	ca                *CA
	serverCert        tls.Certificate
	certTTL           time.Duration
	heartbeatInterval time.Duration
	now               func() time.Time
	onEvent           func(nodeID string, ev *platformv1.Event)

	mu           sync.RWMutex
	sessions     map[string]*activeSession
	nextStreamID atomic.Uint64
}

// NewServer 构造集群控制面服务并由独立集群 Root CA 签发服务端 TLS 证书。
func NewServer(opts ServerOptions) (*Server, error) {
	if opts.DB == nil {
		return nil, errors.New("cluster: storage DB is required")
	}
	if opts.CA == nil {
		return nil, errors.New("cluster: CA is required")
	}
	serverCert, err := opts.CA.SignServerCert(opts.ServerDNSNames, opts.ServerIPs)
	if err != nil {
		return nil, err
	}
	ttl := opts.CertTTL
	if ttl <= 0 {
		ttl = DefaultCertTTL
	}
	hb := opts.HeartbeatInterval
	if hb <= 0 {
		hb = DefaultHeartbeatInterval
	}
	nowFn := opts.Now
	if nowFn == nil {
		nowFn = time.Now
	}
	return &Server{
		db:                opts.DB,
		ca:                opts.CA,
		serverCert:        serverCert,
		certTTL:           ttl,
		heartbeatInterval: hb,
		now:               nowFn,
		onEvent:           opts.OnEvent,
		sessions:          make(map[string]*activeSession),
	}, nil
}

// CA 返回本控制面持有的独立集群 Root CA。
func (s *Server) CA() *CA { return s.ca }

// RegisterEnrollment 将入网签发服务注册到仅服务端 TLS 的 gRPC Server 上。
func (s *Server) RegisterEnrollment(r grpc.ServiceRegistrar) {
	nodev1.RegisterNodeEnrollmentServiceServer(r, s)
}

// RegisterSession 将会话与换证服务注册到强制 mTLS 1.3 的 gRPC Server 上。
func (s *Server) RegisterSession(r grpc.ServiceRegistrar) {
	nodev1.RegisterNodeSessionServiceServer(r, s)
}

// ======================== TLS 1.3 配置与实时吊销握手拦截 ========================

// ServerTLSConfig 构造强制 TLS 1.3 的服务端配置。
// 当 requireClientCert 为 true 时启用 RequireAndVerifyClientCert 并挂载 VerifyConnection，
// 在握手阶段实时查库拒绝已吊销或证书序列号已过期替换的节点连接。
func (s *Server) ServerTLSConfig(requireClientCert bool) *tls.Config {
	cfg := &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{s.serverCert},
	}
	if requireClientCert {
		cfg.ClientAuth = tls.RequireAndVerifyClientCert
		cfg.ClientCAs = s.ca.CertPool()
		cfg.VerifyConnection = s.verifyClientConnection
	}
	return cfg
}

func (s *Server) verifyClientConnection(cs tls.ConnectionState) error {
	var leaf *x509.Certificate
	if len(cs.VerifiedChains) > 0 && len(cs.VerifiedChains[0]) > 0 {
		leaf = cs.VerifiedChains[0][0]
	} else if len(cs.PeerCertificates) > 0 {
		leaf = cs.PeerCertificates[0]
	}
	nodeID, err := ExtractNodeID(leaf)
	if err != nil {
		return fmt.Errorf("cluster: reject client cert: %w", err)
	}
	serialHex := formatSerialHex(leaf.SerialNumber)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	var state, dbSerial string
	err = s.db.Reader().QueryRowContext(ctx,
		`SELECT enrollment_state, cert_serial FROM nodes WHERE id = ?`, nodeID,
	).Scan(&state, &dbSerial)
	if errors.Is(err, sql.ErrNoRows) {
		return errors.New("cluster: unknown node certificate")
	}
	if err != nil {
		return fmt.Errorf("cluster: verify node state: %w", err)
	}
	if state == "revoked" || state != "active" {
		return fmt.Errorf("cluster: node %s is %s", nodeID, state)
	}
	if dbSerial == "" || !strings.EqualFold(dbSerial, serialHex) {
		return errors.New("cluster: client certificate serial is superseded or mismatched")
	}
	return nil
}

// ======================== 入网令牌管理与 NodeEnrollmentService ========================

// CreateEnrollmentToken 生成单次短寿期入网令牌，数据库仅存 SHA-256 摘要。
func (s *Server) CreateEnrollmentToken(ctx context.Context, presetName, mode, createdBy string, ttl time.Duration) (EnrollmentToken, error) {
	presetName = strings.TrimSpace(presetName)
	if presetName == "" {
		return EnrollmentToken{}, errors.New("cluster: preset_name is required")
	}
	if mode == "" {
		mode = ModeFull
	}
	if mode != ModeFull && mode != ModeProbe512M {
		return EnrollmentToken{}, fmt.Errorf("cluster: unsupported node mode %q", mode)
	}
	if strings.TrimSpace(createdBy) == "" {
		createdBy = "system"
	}
	if ttl <= 0 {
		ttl = DefaultEnrollTokenTTL
	}

	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return EnrollmentToken{}, fmt.Errorf("cluster: generate enroll token: %w", err)
	}
	plain := "qwq_enroll_" + base64.RawURLEncoding.EncodeToString(raw)
	clear(raw)
	hashHex := sha256Hex(plain)

	nowMs := s.now().UTC().UnixMilli()
	expMs := s.now().UTC().Add(ttl).UnixMilli()
	var tokID string

	if err := s.db.Update(ctx, func(tx *storage.Tx) error {
		tokID = tx.NewID("net")
		_, err := tx.ExecContext(ctx, `
			INSERT INTO node_enrollment_tokens (id, token_sha256, preset_name, mode, expires_at, redeemed_node_id, created_by, created_at)
			VALUES (?, ?, ?, ?, ?, '', ?, ?)`,
			tokID, hashHex, presetName, mode, expMs, createdBy, nowMs,
		)
		return err
	}); err != nil {
		return EnrollmentToken{}, fmt.Errorf("cluster: store enrollment token: %w", err)
	}

	return EnrollmentToken{
		ID:          tokID,
		Token:       plain,
		TokenSHA256: hashHex,
		PresetName:  presetName,
		Mode:        mode,
		ExpiresAt:   expMs,
		CreatedBy:   createdBy,
		CreatedAt:   nowMs,
	}, nil
}

// Enroll 实现 NodeEnrollmentService.Enroll：原子核销一次性令牌、签发短寿期节点证书并写入 nodes 表。
func (s *Server) Enroll(ctx context.Context, req *nodev1.EnrollRequest) (*nodev1.EnrollResponse, error) {
	token := strings.TrimSpace(req.GetToken())
	if token == "" {
		return nil, status.Error(codes.InvalidArgument, "enrollment token is required")
	}
	if len(req.GetCsrDer()) == 0 {
		return nil, status.Error(codes.InvalidArgument, "csr_der is required")
	}

	tokenHash := sha256Hex(token)
	nowMs := s.now().UTC().UnixMilli()

	var (
		nodeID string
		signed SignedCert
	)
	err := s.db.Update(ctx, func(tx *storage.Tx) error {
		var tokID, presetName, mode, redeemedBy string
		var expiresAt int64
		err := tx.QueryRowContext(ctx, `
			SELECT id, preset_name, mode, expires_at, redeemed_node_id
			FROM node_enrollment_tokens WHERE token_sha256 = ?`, tokenHash,
		).Scan(&tokID, &presetName, &mode, &expiresAt, &redeemedBy)
		if errors.Is(err, sql.ErrNoRows) {
			return status.Error(codes.Unauthenticated, "invalid enrollment token")
		}
		if err != nil {
			return status.Error(codes.Internal, "failed to read enrollment token")
		}
		if redeemedBy != "" {
			return status.Error(codes.FailedPrecondition, "enrollment token already redeemed")
		}
		if nowMs > expiresAt {
			return status.Error(codes.FailedPrecondition, "enrollment token expired")
		}

		nodeID = tx.NewID("node")
		signed, err = s.ca.SignNodeCSR(req.GetCsrDer(), nodeID, s.certTTL)
		if err != nil {
			return status.Errorf(codes.InvalidArgument, "invalid csr: %v", err)
		}

		res, err := tx.ExecContext(ctx, `
			UPDATE node_enrollment_tokens SET redeemed_node_id = ? WHERE id = ? AND redeemed_node_id = ''`,
			nodeID, tokID,
		)
		if err != nil {
			return status.Error(codes.Internal, "failed to redeem enrollment token")
		}
		if n, _ := res.RowsAffected(); n != 1 {
			return status.Error(codes.FailedPrecondition, "enrollment token already redeemed")
		}

		name := presetName
		if name == "" && req.GetFacts() != nil {
			name = strings.TrimSpace(req.GetFacts().GetHostname())
		}
		if name == "" {
			name = nodeID
		}
		arch := ""
		if req.GetFacts() != nil {
			arch = strings.TrimSpace(req.GetFacts().GetArch())
		}
		rev := tx.NewID("rev")
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO nodes (
				id, name, mode, enrollment_state, cert_serial, cert_fingerprint, cert_expires_at,
				agent_version, arch, public_addrs_json, last_heartbeat_at, last_ack_seq, revision, created_at, updated_at
			) VALUES (?, ?, ?, 'active', ?, ?, ?, ?, ?, '[]', ?, 0, ?, ?, ?)`,
			nodeID, name, mode, signed.SerialHex, signed.Fingerprint, signed.ExpiresAt.UnixMilli(),
			strings.TrimSpace(req.GetAgentVersion()), arch, nowMs, rev, nowMs, nowMs,
		); err != nil {
			return status.Error(codes.Internal, "failed to register node")
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	return &nodev1.EnrollResponse{
		NodeId:               nodeID,
		CertificateDer:       signed.CertDER,
		CaCertificatesDer:    [][]byte{s.ca.CertDER()},
		DesiredStateRevision: 0,
	}, nil
}

// ======================== mTLS 双向长连接会话与无感证书轮换 ========================

// Session 实现 NodeSessionService.Session：仅信任 mTLS 证书 URI SAN 推导的 node_id，
// 完成 Hello/Welcome 握手、心跳刷新、离线事件续传累计确认与毫秒级踢断。
func (s *Server) Session(stream grpc.BidiStreamingServer[nodev1.SessionRequest, nodev1.SessionResponse]) error {
	nodeID, serialHex, err := peerNodeIdentity(stream.Context())
	if err != nil {
		return status.Errorf(codes.Unauthenticated, "%v", err)
	}

	var (
		state      string
		dbSerial   string
		lastAckSeq int64
	)
	err = s.db.Reader().QueryRowContext(stream.Context(),
		`SELECT enrollment_state, cert_serial, last_ack_seq FROM nodes WHERE id = ?`, nodeID,
	).Scan(&state, &dbSerial, &lastAckSeq)
	if errors.Is(err, sql.ErrNoRows) {
		return status.Error(codes.Unauthenticated, "unknown node")
	}
	if err != nil {
		return status.Error(codes.Internal, "failed to load node state")
	}
	if state != "active" {
		return status.Errorf(codes.PermissionDenied, "node is %s", state)
	}
	if !strings.EqualFold(dbSerial, serialHex) {
		return status.Error(codes.Unauthenticated, "certificate serial superseded")
	}

	first, err := stream.Recv()
	if err != nil {
		return err
	}
	hello := first.GetHello()
	if hello == nil {
		return status.Error(codes.InvalidArgument, "first frame must be Hello")
	}

	nowMs := s.now().UTC().UnixMilli()
	agentVer := strings.TrimSpace(hello.GetAgentVersion())
	arch := ""
	if hello.GetFacts() != nil {
		arch = strings.TrimSpace(hello.GetFacts().GetArch())
	}
	if err := s.db.Update(stream.Context(), func(tx *storage.Tx) error {
		_, err := tx.ExecContext(stream.Context(), `
			UPDATE nodes
			SET agent_version = CASE WHEN ? != '' THEN ? ELSE agent_version END,
			    arch          = CASE WHEN ? != '' THEN ? ELSE arch END,
			    last_heartbeat_at = ?,
			    updated_at        = ?
			WHERE id = ? AND enrollment_state = 'active'`,
			agentVer, agentVer, arch, arch, nowMs, nowMs, nodeID,
		)
		return err
	}); err != nil {
		return status.Error(codes.Internal, "failed to record node hello")
	}

	sessCtx, cancel := context.WithCancel(stream.Context())
	defer cancel()
	streamID := s.registerSession(nodeID, cancel)
	defer s.unregisterSession(nodeID, streamID)

	if err := stream.Send(&nodev1.SessionResponse{
		Frame: &nodev1.SessionResponse_Welcome{
			Welcome: &nodev1.Welcome{
				ProtocolVersion:      NodeProtocolVersion,
				NodeId:               nodeID,
				LastEventSequence:    uint64(lastAckSeq),
				DesiredStateRevision: 0,
				HeartbeatIntervalMs:  uint32(s.heartbeatInterval.Milliseconds()),
			},
		},
	}); err != nil {
		return err
	}

	type recvResult struct {
		msg *nodev1.SessionRequest
		err error
	}
	recvCh := make(chan recvResult, 1)
	go func() {
		defer close(recvCh)
		for {
			msg, rerr := stream.Recv()
			select {
			case recvCh <- recvResult{msg: msg, err: rerr}:
			case <-sessCtx.Done():
				return
			}
			if rerr != nil {
				return
			}
		}
	}()

	for {
		select {
		case <-sessCtx.Done():
			if stream.Context().Err() != nil {
				return stream.Context().Err()
			}
			return status.Error(codes.PermissionDenied, "node session terminated")
		case res, ok := <-recvCh:
			if !ok {
				return nil
			}
			if res.err != nil {
				if errors.Is(res.err, io.EOF) {
					return nil
				}
				return res.err
			}
			if err := s.handleSessionFrame(sessCtx, stream, nodeID, &lastAckSeq, res.msg); err != nil {
				return err
			}
		}
	}
}

func (s *Server) handleSessionFrame(
	ctx context.Context,
	stream grpc.BidiStreamingServer[nodev1.SessionRequest, nodev1.SessionResponse],
	nodeID string,
	lastAckSeq *int64,
	req *nodev1.SessionRequest,
) error {
	nowMs := s.now().UTC().UnixMilli()
	switch f := req.GetFrame().(type) {
	case *nodev1.SessionRequest_Heartbeat:
		if err := s.touchNodeHeartbeat(ctx, nodeID, nowMs); err != nil {
			return err
		}
		return stream.Send(&nodev1.SessionResponse{
			Frame: &nodev1.SessionResponse_Heartbeat{
				Heartbeat: &nodev1.Heartbeat{SentAtUnixMs: nowMs},
			},
		})

	case *nodev1.SessionRequest_EventBatch:
		var maxSeq int64
		for _, ev := range f.EventBatch.GetEvents() {
			if ev == nil {
				continue
			}
			if s.onEvent != nil {
				s.onEvent(nodeID, ev)
			}
			if seq := int64(ev.GetSequence()); seq > maxSeq {
				maxSeq = seq
			}
		}
		if maxSeq > *lastAckSeq {
			if err := s.db.Update(ctx, func(tx *storage.Tx) error {
				_, err := tx.ExecContext(ctx, `
					UPDATE nodes
					SET last_ack_seq = CASE WHEN last_ack_seq < ? THEN ? ELSE last_ack_seq END,
					    last_heartbeat_at = ?,
					    updated_at = ?
					WHERE id = ?`, maxSeq, maxSeq, nowMs, nowMs, nodeID)
				return err
			}); err != nil {
				return status.Error(codes.Internal, "failed to persist event ack")
			}
			*lastAckSeq = maxSeq
		} else {
			if err := s.touchNodeHeartbeat(ctx, nodeID, nowMs); err != nil {
				return err
			}
		}
		return stream.Send(&nodev1.SessionResponse{
			Frame: &nodev1.SessionResponse_EventAck{
				EventAck: &nodev1.EventAck{Sequence: uint64(*lastAckSeq)},
			},
		})

	case *nodev1.SessionRequest_StateReport,
		*nodev1.SessionRequest_CommandAck,
		*nodev1.SessionRequest_CommandProgress,
		*nodev1.SessionRequest_CommandResult:
		return s.touchNodeHeartbeat(ctx, nodeID, nowMs)

	case *nodev1.SessionRequest_Hello:
		return status.Error(codes.InvalidArgument, "duplicate Hello frame")
	default:
		return nil
	}
}

func (s *Server) touchNodeHeartbeat(ctx context.Context, nodeID string, nowMs int64) error {
	return s.db.Update(ctx, func(tx *storage.Tx) error {
		_, err := tx.ExecContext(ctx,
			`UPDATE nodes SET last_heartbeat_at = ?, updated_at = ? WHERE id = ?`,
			nowMs, nowMs, nodeID,
		)
		return err
	})
}

// RotateCertificate 实现 NodeSessionService.RotateCertificate：
// 校验活跃 mTLS 节点身份与当前序列号，签发新 30 天客户端证书并更新 nodes 表使旧证书立即失效。
func (s *Server) RotateCertificate(ctx context.Context, req *nodev1.RotateCertificateRequest) (*nodev1.RotateCertificateResponse, error) {
	nodeID, serialHex, err := peerNodeIdentity(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Unauthenticated, "%v", err)
	}
	if len(req.GetCsrDer()) == 0 {
		return nil, status.Error(codes.InvalidArgument, "csr_der is required")
	}

	nowMs := s.now().UTC().UnixMilli()
	var signed SignedCert
	err = s.db.Update(ctx, func(tx *storage.Tx) error {
		var state, dbSerial string
		err := tx.QueryRowContext(ctx,
			`SELECT enrollment_state, cert_serial FROM nodes WHERE id = ?`, nodeID,
		).Scan(&state, &dbSerial)
		if errors.Is(err, sql.ErrNoRows) {
			return status.Error(codes.Unauthenticated, "unknown node")
		}
		if err != nil {
			return status.Error(codes.Internal, "failed to load node state")
		}
		if state != "active" {
			return status.Errorf(codes.PermissionDenied, "node is %s", state)
		}
		if !strings.EqualFold(dbSerial, serialHex) {
			return status.Error(codes.Unauthenticated, "certificate serial superseded")
		}

		signed, err = s.ca.SignNodeCSR(req.GetCsrDer(), nodeID, s.certTTL)
		if err != nil {
			return status.Errorf(codes.InvalidArgument, "invalid csr: %v", err)
		}
		rev := tx.NewID("rev")
		if _, err := tx.ExecContext(ctx, `
			UPDATE nodes
			SET cert_serial = ?, cert_fingerprint = ?, cert_expires_at = ?, revision = ?, updated_at = ?
			WHERE id = ?`,
			signed.SerialHex, signed.Fingerprint, signed.ExpiresAt.UnixMilli(), rev, nowMs, nodeID,
		); err != nil {
			return status.Error(codes.Internal, "failed to persist rotated certificate")
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	return &nodev1.RotateCertificateResponse{
		CertificateDer:    signed.CertDER,
		CaCertificatesDer: [][]byte{s.ca.CertDER()},
	}, nil
}

// ======================== 在线注册表、吊销与管理查询辅助 ========================

func (s *Server) registerSession(nodeID string, cancel context.CancelFunc) uint64 {
	id := s.nextStreamID.Add(1)
	s.mu.Lock()
	if prev := s.sessions[nodeID]; prev != nil {
		prev.cancel()
	}
	s.sessions[nodeID] = &activeSession{id: id, cancel: cancel, connectedAt: s.now().UTC()}
	s.mu.Unlock()
	return id
}

func (s *Server) unregisterSession(nodeID string, streamID uint64) {
	s.mu.Lock()
	if cur := s.sessions[nodeID]; cur != nil && cur.id == streamID {
		delete(s.sessions, nodeID)
	}
	s.mu.Unlock()
}

// ConnectedNodes 返回当前处于在线状态的节点 ID 排序列表。
func (s *Server) ConnectedNodes() []string {
	s.mu.RLock()
	out := make([]string, 0, len(s.sessions))
	for id := range s.sessions {
		out = append(out, id)
	}
	s.mu.RUnlock()
	slices.Sort(out)
	return out
}

// KickNode 毫秒级取消指定节点当前的在途 Session 双向流。
func (s *Server) KickNode(nodeID string) bool {
	s.mu.Lock()
	cur := s.sessions[nodeID]
	if cur != nil {
		delete(s.sessions, nodeID)
	}
	s.mu.Unlock()
	if cur != nil {
		cur.cancel()
		return true
	}
	return false
}

// RevokeNode 将指定节点标记为 revoked 并立即踢断其在线会话；后续重连将在 TLS 握手阶段被 VerifyConnection 拦截。
func (s *Server) RevokeNode(ctx context.Context, nodeID string) error {
	nodeID = strings.TrimSpace(nodeID)
	if nodeID == "" {
		return errors.New("cluster: node_id is required")
	}
	nowMs := s.now().UTC().UnixMilli()
	err := s.db.Update(ctx, func(tx *storage.Tx) error {
		rev := tx.NewID("rev")
		res, err := tx.ExecContext(ctx,
			`UPDATE nodes SET enrollment_state = 'revoked', revision = ?, updated_at = ? WHERE id = ?`,
			rev, nowMs, nodeID,
		)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return sql.ErrNoRows
		}
		return nil
	})
	if err != nil {
		return err
	}
	s.KickNode(nodeID)
	return nil
}

// GetNode 查询单个节点的持久化记录。
func (s *Server) GetNode(ctx context.Context, nodeID string) (NodeRecord, error) {
	var rec NodeRecord
	var addrsJSON string
	err := s.db.Reader().QueryRowContext(ctx, `
		SELECT id, name, mode, enrollment_state, cert_serial, cert_fingerprint, cert_expires_at,
		       agent_version, arch, public_addrs_json, last_heartbeat_at, last_ack_seq, revision, created_at, updated_at
		FROM nodes WHERE id = ?`, nodeID,
	).Scan(
		&rec.ID, &rec.Name, &rec.Mode, &rec.EnrollmentState, &rec.CertSerial, &rec.CertFingerprint, &rec.CertExpiresAt,
		&rec.AgentVersion, &rec.Arch, &addrsJSON, &rec.LastHeartbeatAt, &rec.LastAckSeq, &rec.Revision, &rec.CreatedAt, &rec.UpdatedAt,
	)
	if err != nil {
		return NodeRecord{}, err
	}
	rec.PublicAddrs = make([]string, 0)
	_ = json.Unmarshal([]byte(addrsJSON), &rec.PublicAddrs)
	return rec, nil
}

// ListNodes 按创建时间倒序返回集群内全部节点记录。
func (s *Server) ListNodes(ctx context.Context) ([]NodeRecord, error) {
	rows, err := s.db.Reader().QueryContext(ctx, `
		SELECT id, name, mode, enrollment_state, cert_serial, cert_fingerprint, cert_expires_at,
		       agent_version, arch, public_addrs_json, last_heartbeat_at, last_ack_seq, revision, created_at, updated_at
		FROM nodes ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]NodeRecord, 0)
	for rows.Next() {
		var rec NodeRecord
		var addrsJSON string
		if err := rows.Scan(
			&rec.ID, &rec.Name, &rec.Mode, &rec.EnrollmentState, &rec.CertSerial, &rec.CertFingerprint, &rec.CertExpiresAt,
			&rec.AgentVersion, &rec.Arch, &addrsJSON, &rec.LastHeartbeatAt, &rec.LastAckSeq, &rec.Revision, &rec.CreatedAt, &rec.UpdatedAt,
		); err != nil {
			return nil, err
		}
		rec.PublicAddrs = make([]string, 0)
		_ = json.Unmarshal([]byte(addrsJSON), &rec.PublicAddrs)
		out = append(out, rec)
	}
	return out, rows.Err()
}

// ======================== 内部工具函数 ========================

func peerNodeIdentity(ctx context.Context) (nodeID string, serialHex string, err error) {
	p, ok := peer.FromContext(ctx)
	if !ok || p == nil || p.AuthInfo == nil {
		return "", "", errors.New("missing mTLS peer credentials")
	}
	tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok {
		return "", "", errors.New("non-TLS peer credentials")
	}
	var leaf *x509.Certificate
	if len(tlsInfo.State.VerifiedChains) > 0 && len(tlsInfo.State.VerifiedChains[0]) > 0 {
		leaf = tlsInfo.State.VerifiedChains[0][0]
	} else if len(tlsInfo.State.PeerCertificates) > 0 {
		leaf = tlsInfo.State.PeerCertificates[0]
	}
	nodeID, err = ExtractNodeID(leaf)
	if err != nil {
		return "", "", err
	}
	return nodeID, formatSerialHex(leaf.SerialNumber), nil
}

func sha256Hex(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}
