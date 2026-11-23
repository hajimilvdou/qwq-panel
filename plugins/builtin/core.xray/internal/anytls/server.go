// SPDX-License-Identifier: AGPL-3.0-only

// Package anytls 实现纯 Go AnyTLS v1/v2 服务端与多实例生命周期管理器。
package anytls

import (
	"bufio"
	"context"
	"crypto/md5"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	corev2 "github.com/qwq-panel/qwq/sdk/coreapi/v2"
)

const (
	cmdWaste               byte = 0
	cmdSYN                 byte = 1
	cmdPSH                 byte = 2
	cmdFIN                 byte = 3
	cmdSettings            byte = 4
	cmdAlert               byte = 5
	cmdUpdatePaddingScheme byte = 6
	cmdSYNACK              byte = 7
	cmdHeartRequest        byte = 8
	cmdHeartResponse       byte = 9
	cmdServerSettings      byte = 10

	maxFramePayload          = 16384
	maxStreamsPerSession     = 256
	maxPendingBytesPerStream = 256 * 1024
	dialTimeout              = 10 * time.Second
	targetWriteTimeout       = 30 * time.Second
	idleReadTimeout          = 5 * time.Minute
)

// ProfileSpec 描述单个运行中 AnyTLS 入站的监听地址、TLS 证书、填充方案与用户凭据。
type ProfileSpec struct {
	ProfileID     string
	BindingRef    string
	ServerName    string
	Listen        string
	Port          int
	CertPEM       []byte
	KeyPEM        []byte
	PaddingScheme []string
	Users         map[string][]byte   // userID -> raw password
	UserDigests   map[string][32]byte // userID -> sha256(password)（重启恢复时避免落盘明文密码）
}

type userEntry struct {
	id     string
	digest [32]byte
	up     *atomic.Int64
	down   *atomic.Int64
}

// Server 承载单个 AnyTLS v1/v2 TLS 监听实例并统计入站/逐用户流量。
type Server struct {
	profileID   string
	bindingRef  string
	serverName  string
	listenAddr  string
	paddingText string
	paddingMD5  string
	users       []userEntry
	inboundUp   atomic.Int64
	inboundDown atomic.Int64
	cert        atomic.Pointer[tls.Certificate]
	dialTarget  func(ctx context.Context, network, addr string) (net.Conn, error)

	ln          net.Listener
	ctx         context.Context
	cancel      context.CancelFunc
	connsMu     sync.Mutex
	activeConns map[net.Conn]struct{}
	stopped     bool
	wg          sync.WaitGroup
	stopOnce    sync.Once
}

// NewServer 校验并构造 AnyTLS 服务端实例（尚未开始监听）。
func NewServer(spec ProfileSpec) (*Server, error) {
	if spec.ProfileID == "" || spec.Listen == "" || spec.Port < 1 || spec.Port > 65535 {
		return nil, errors.New("anytls: invalid profile listen specification")
	}
	if len(spec.Users) == 0 && len(spec.UserDigests) == 0 {
		return nil, errors.New("anytls: at least one user is required")
	}
	cert, err := tls.X509KeyPair(spec.CertPEM, spec.KeyPEM)
	if err != nil {
		return nil, fmt.Errorf("anytls: load x509 keypair: %w", err)
	}
	scheme := spec.PaddingScheme
	if len(scheme) == 0 {
		scheme = corev2.DefaultAnyTLSPaddingScheme()
	}
	paddingText := strings.Join(scheme, "\n")
	sum := md5.Sum([]byte(paddingText))

	entries := make([]userEntry, 0, len(spec.Users)+len(spec.UserDigests))
	seen := make(map[string]struct{}, len(spec.Users)+len(spec.UserDigests))
	for uid, pwd := range spec.Users {
		seen[uid] = struct{}{}
		entries = append(entries, userEntry{
			id:     uid,
			digest: sha256.Sum256(pwd),
			up:     &atomic.Int64{},
			down:   &atomic.Int64{},
		})
	}
	for uid, digest := range spec.UserDigests {
		if _, ok := seen[uid]; ok {
			continue
		}
		entries = append(entries, userEntry{
			id:     uid,
			digest: digest,
			up:     &atomic.Int64{},
			down:   &atomic.Int64{},
		})
	}
	s := &Server{
		profileID:   spec.ProfileID,
		bindingRef:  spec.BindingRef,
		serverName:  spec.ServerName,
		listenAddr:  net.JoinHostPort(spec.Listen, strconv.Itoa(spec.Port)),
		paddingText: paddingText,
		paddingMD5:  hex.EncodeToString(sum[:]),
		users:       entries,
		dialTarget:  (&net.Dialer{Timeout: dialTimeout}).DialContext,
		activeConns: make(map[net.Conn]struct{}),
	}
	s.cert.Store(&cert)
	return s, nil
}

// Start 绑定 TLS 监听并启动异步接收循环。
func (s *Server) Start(parent context.Context) error {
	tlsCfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			return s.cert.Load(), nil
		},
	}
	rawLn, err := net.Listen("tcp", s.listenAddr)
	if err != nil {
		return fmt.Errorf("anytls: listen %s: %w", s.listenAddr, err)
	}
	s.ln = tls.NewListener(rawLn, tlsCfg)
	s.ctx, s.cancel = context.WithCancel(parent)
	s.wg.Add(1)
	go s.acceptLoop()
	return nil
}

// Addr 返回实际监听地址（测试使用 :0 端口时尤为有用）。
func (s *Server) Addr() net.Addr {
	if s.ln == nil {
		return nil
	}
	return s.ln.Addr()
}

// UpdateCertificate 零中断热替换 TLS 证书与私钥。
func (s *Server) UpdateCertificate(certPEM, keyPEM []byte) error {
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return fmt.Errorf("anytls: reload x509 keypair: %w", err)
	}
	s.cert.Store(&cert)
	return nil
}

// Stop 关闭监听与全部活跃客户端连接，并在有界时间内等待会话退出。
func (s *Server) Stop(timeout time.Duration) {
	s.stopOnce.Do(func() {
		if s.cancel != nil {
			s.cancel()
		}
		if s.ln != nil {
			_ = s.ln.Close()
		}
		s.connsMu.Lock()
		s.stopped = true
		conns := make([]net.Conn, 0, len(s.activeConns))
		for c := range s.activeConns {
			conns = append(conns, c)
		}
		clear(s.activeConns)
		s.connsMu.Unlock()
		for _, c := range conns {
			_ = c.Close()
		}
	})
	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	select {
	case <-done:
	case <-time.After(timeout):
	}
}

// AddCounters 将本入站及各用户的上下行字节数累加到输出字典（格式对齐 Xray StatsService）。
func (s *Server) AddCounters(out map[string]int64) {
	out["inbound>>>qwq-in-"+s.profileID+">>>traffic>>>uplink"] += s.inboundUp.Load()
	out["inbound>>>qwq-in-"+s.profileID+">>>traffic>>>downlink"] += s.inboundDown.Load()
	for _, u := range s.users {
		up := u.up.Load()
		down := u.down.Load()
		if up > 0 || down > 0 {
			out["user>>>qwq-user-"+u.id+">>>traffic>>>uplink"] += up
			out["user>>>qwq-user-"+u.id+">>>traffic>>>downlink"] += down
		}
	}
}

func (s *Server) acceptLoop() {
	defer s.wg.Done()
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			return
		}
		s.wg.Add(1)
		go func(c net.Conn) {
			defer s.wg.Done()
			s.handleConn(c)
		}(conn)
	}
}

func (s *Server) matchUser(digest []byte) *userEntry {
	if len(digest) != 32 {
		return nil
	}
	var matched *userEntry
	for idx := range s.users {
		if subtle.ConstantTimeCompare(s.users[idx].digest[:], digest) == 1 {
			matched = &s.users[idx]
		}
	}
	return matched
}

func (s *Server) registerConn(conn net.Conn) bool {
	s.connsMu.Lock()
	defer s.connsMu.Unlock()
	if s.stopped {
		return false
	}
	s.activeConns[conn] = struct{}{}
	return true
}

func (s *Server) unregisterConn(conn net.Conn) {
	s.connsMu.Lock()
	delete(s.activeConns, conn)
	s.connsMu.Unlock()
}

func (s *Server) handleConn(conn net.Conn) {
	if !s.registerConn(conn) {
		_ = conn.Close()
		return
	}
	defer func() {
		s.unregisterConn(conn)
		_ = conn.Close()
	}()
	if tlsConn, ok := conn.(*tls.Conn); ok {
		_ = tlsConn.SetDeadline(time.Now().Add(15 * time.Second))
		if err := tlsConn.HandshakeContext(s.ctx); err != nil {
			return
		}
	}

	br := bufio.NewReaderSize(conn, 32*1024)
	_ = conn.SetReadDeadline(time.Now().Add(15 * time.Second))

	// AnyTLS 认证头：32 字节 sha256(password) + 2 字节 BE padLen + pad0
	var authHeader [34]byte
	if _, err := io.ReadFull(br, authHeader[:]); err != nil {
		return
	}
	user := s.matchUser(authHeader[:32])
	if user == nil {
		return
	}
	padLen := int(binary.BigEndian.Uint16(authHeader[32:34]))
	if padLen > 0 {
		if _, err := io.CopyN(io.Discard, br, int64(padLen)); err != nil {
			return
		}
	}
	_ = conn.SetDeadline(time.Time{})

	sess := &anytlsSession{
		server:        s,
		user:          user,
		conn:          conn,
		br:            br,
		clientVersion: 1,
		streams:       make(map[uint32]*anytlsStream),
	}
	sess.run()
}

type anytlsSession struct {
	server        *Server
	user          *userEntry
	conn          net.Conn
	br            *bufio.Reader
	writeMu       sync.Mutex
	mu            sync.Mutex
	wg            sync.WaitGroup
	clientVersion int
	streams       map[uint32]*anytlsStream
	closed        bool
}

type anytlsStream struct {
	id           uint32
	sess         *anytlsSession
	mu           sync.Mutex
	writeMu      sync.Mutex
	addrBuf      []byte
	dialing      bool
	ready        bool
	closed       bool
	pending      [][]byte
	pendingBytes int
	targetConn   net.Conn
}

func (sess *anytlsSession) writeFrame(cmd byte, streamID uint32, payload []byte) error {
	if len(payload) > 65535 {
		return errors.New("anytls: frame too large")
	}
	var hdr [7]byte
	hdr[0] = cmd
	binary.BigEndian.PutUint32(hdr[1:5], streamID)
	binary.BigEndian.PutUint16(hdr[5:7], uint16(len(payload)))

	sess.writeMu.Lock()
	defer sess.writeMu.Unlock()
	_ = sess.conn.SetWriteDeadline(time.Now().Add(30 * time.Second))
	if _, err := sess.conn.Write(hdr[:]); err != nil {
		return err
	}
	if len(payload) > 0 {
		if _, err := sess.conn.Write(payload); err != nil {
			return err
		}
	}
	return nil
}

func (sess *anytlsSession) closeAllStreams() {
	sess.mu.Lock()
	sess.closed = true
	streams := make([]*anytlsStream, 0, len(sess.streams))
	for _, st := range sess.streams {
		streams = append(streams, st)
	}
	clear(sess.streams)
	sess.mu.Unlock()
	for _, st := range streams {
		st.closeLocal()
	}
}

func (sess *anytlsSession) run() {
	defer func() {
		sess.closeAllStreams()
		sess.wg.Wait()
	}()
	var hdr [7]byte
	for {
		if sess.server.ctx.Err() != nil {
			return
		}
		_ = sess.conn.SetReadDeadline(time.Now().Add(idleReadTimeout))
		if _, err := io.ReadFull(sess.br, hdr[:]); err != nil {
			return
		}
		cmd := hdr[0]
		streamID := binary.BigEndian.Uint32(hdr[1:5])
		dataLen := int(binary.BigEndian.Uint16(hdr[5:7]))

		var data []byte
		if dataLen > 0 {
			if cmd == cmdWaste {
				if _, err := io.CopyN(io.Discard, sess.br, int64(dataLen)); err != nil {
					return
				}
				continue
			}
			data = make([]byte, dataLen)
			if _, err := io.ReadFull(sess.br, data); err != nil {
				return
			}
		}

		switch cmd {
		case cmdWaste:
			continue
		case cmdSettings:
			if err := sess.handleSettings(data); err != nil {
				return
			}
		case cmdSYN:
			st, ok := sess.getOrCreateStream(streamID)
			if !ok {
				sess.rejectStream(streamID, errors.New("anytls: max concurrent streams exceeded"))
				continue
			}
			if len(data) > 0 {
				st.onClientData(data)
			}
		case cmdPSH:
			sess.mu.Lock()
			st := sess.streams[streamID]
			sess.mu.Unlock()
			if st != nil {
				st.onClientData(data)
			}
		case cmdFIN:
			sess.removeStream(streamID, true)
		case cmdHeartRequest:
			if err := sess.writeFrame(cmdHeartResponse, streamID, nil); err != nil {
				return
			}
		case cmdHeartResponse:
			continue
		case cmdAlert:
			return
		default:
			continue
		}
	}
}

func (sess *anytlsSession) handleSettings(data []byte) error {
	lines := strings.Split(string(data), "\n")
	ver := 1
	clientMD5 := ""
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		switch strings.TrimSpace(k) {
		case "v":
			if parsed, err := strconv.Atoi(strings.TrimSpace(v)); err == nil && parsed > 0 {
				ver = parsed
			}
		case "padding-md5":
			clientMD5 = strings.ToLower(strings.TrimSpace(v))
		}
	}
	sess.mu.Lock()
	sess.clientVersion = ver
	sess.mu.Unlock()

	if ver >= 2 {
		if err := sess.writeFrame(cmdServerSettings, 0, []byte("v=2\n")); err != nil {
			return err
		}
	}
	if clientMD5 != sess.server.paddingMD5 {
		if err := sess.writeFrame(cmdUpdatePaddingScheme, 0, []byte(sess.server.paddingText)); err != nil {
			return err
		}
	}
	return nil
}

func (sess *anytlsSession) getOrCreateStream(streamID uint32) (*anytlsStream, bool) {
	sess.mu.Lock()
	defer sess.mu.Unlock()
	if st, ok := sess.streams[streamID]; ok {
		return st, true
	}
	if len(sess.streams) >= maxStreamsPerSession {
		return nil, false
	}
	st := &anytlsStream{id: streamID, sess: sess}
	sess.streams[streamID] = st
	return st, true
}

func (sess *anytlsSession) rejectStream(streamID uint32, err error) {
	sess.mu.Lock()
	ver := sess.clientVersion
	sess.mu.Unlock()
	if ver >= 2 {
		_ = sess.writeFrame(cmdSYNACK, streamID, []byte(err.Error()))
	} else {
		_ = sess.writeFrame(cmdFIN, streamID, nil)
	}
}

func (sess *anytlsSession) removeStream(streamID uint32, closeTarget bool) {
	sess.mu.Lock()
	st := sess.streams[streamID]
	delete(sess.streams, streamID)
	sess.mu.Unlock()
	if st != nil && closeTarget {
		st.closeLocal()
	}
}

func (st *anytlsStream) closeLocal() {
	st.mu.Lock()
	st.closed = true
	conn := st.targetConn
	st.targetConn = nil
	st.pending = nil
	st.pendingBytes = 0
	st.mu.Unlock()
	if conn != nil {
		_ = conn.Close()
	}
}

func (st *anytlsStream) writeToTarget(conn net.Conn, data []byte) bool {
	if len(data) == 0 {
		return true
	}
	st.writeMu.Lock()
	_ = conn.SetWriteDeadline(time.Now().Add(targetWriteTimeout))
	n, err := conn.Write(data)
	st.writeMu.Unlock()
	if n > 0 {
		st.sess.server.inboundUp.Add(int64(n))
		st.sess.user.up.Add(int64(n))
	}
	if err != nil {
		st.sess.removeStream(st.id, true)
		_ = st.sess.writeFrame(cmdFIN, st.id, nil)
		return false
	}
	return true
}

func (st *anytlsStream) onClientData(data []byte) {
	st.mu.Lock()
	if st.closed {
		st.mu.Unlock()
		return
	}
	if st.ready && st.targetConn != nil {
		conn := st.targetConn
		st.mu.Unlock()
		st.writeToTarget(conn, data)
		return
	}
	if st.dialing {
		if len(data) > 0 {
			if st.pendingBytes+len(data) > maxPendingBytesPerStream {
				st.closed = true
				st.pending = nil
				st.pendingBytes = 0
				st.mu.Unlock()
				st.failDial(errors.New("anytls: pending buffer overflow"))
				return
			}
			st.pending = append(st.pending, data)
			st.pendingBytes += len(data)
		}
		st.mu.Unlock()
		return
	}

	st.addrBuf = append(st.addrBuf, data...)
	targetAddr, consumed, complete, err := parseSocks5Addr(st.addrBuf)
	if err != nil {
		st.closed = true
		st.mu.Unlock()
		st.failDial(err)
		return
	}
	if !complete {
		if len(st.addrBuf) > 512 {
			st.closed = true
			st.mu.Unlock()
			st.failDial(errors.New("address buffer overflow"))
			return
		}
		st.mu.Unlock()
		return
	}
	rest := append([]byte(nil), st.addrBuf[consumed:]...)
	st.addrBuf = nil
	if len(rest) > maxPendingBytesPerStream {
		st.closed = true
		st.mu.Unlock()
		st.failDial(errors.New("anytls: pending buffer overflow"))
		return
	}
	st.dialing = true
	if len(rest) > 0 {
		st.pending = append(st.pending, rest)
		st.pendingBytes += len(rest)
	}
	st.mu.Unlock()

	st.sess.wg.Add(1)
	go func() {
		defer st.sess.wg.Done()
		st.dialAndRelay(targetAddr)
	}()
}

func (st *anytlsStream) failDial(err error) {
	st.sess.removeStream(st.id, true)
	st.sess.rejectStream(st.id, err)
}

func (st *anytlsStream) dialAndRelay(targetAddr string) {
	ctx, cancel := context.WithTimeout(st.sess.server.ctx, dialTimeout)
	conn, err := st.sess.server.dialTarget(ctx, "tcp", targetAddr)
	cancel()
	if err != nil {
		st.failDial(err)
		return
	}

	st.mu.Lock()
	if st.closed {
		st.mu.Unlock()
		_ = conn.Close()
		return
	}
	st.targetConn = conn
	st.mu.Unlock()

	st.sess.mu.Lock()
	ver := st.sess.clientVersion
	st.sess.mu.Unlock()
	if ver >= 2 {
		if err := st.sess.writeFrame(cmdSYNACK, st.id, nil); err != nil {
			st.sess.removeStream(st.id, true)
			return
		}
	}

	// 严格保序排空全部 0-RTT / 建连期间积压帧后，再在锁内将 st.ready 置为 true，
	// 确保后续 cmdPSH 永不会抢跑插队到 pending 之前。
	for {
		st.mu.Lock()
		if st.closed {
			st.mu.Unlock()
			return
		}
		if len(st.pending) == 0 {
			st.dialing = false
			st.ready = true
			st.mu.Unlock()
			break
		}
		pending := st.pending
		st.pending = nil
		st.pendingBytes = 0
		st.mu.Unlock()

		for _, chunk := range pending {
			if !st.writeToTarget(conn, chunk) {
				return
			}
		}
	}

	buf := make([]byte, maxFramePayload)
	for {
		n, rerr := conn.Read(buf)
		if n > 0 {
			if werr := st.sess.writeFrame(cmdPSH, st.id, buf[:n]); werr != nil {
				st.sess.removeStream(st.id, true)
				return
			}
			st.sess.server.inboundDown.Add(int64(n))
			st.sess.user.down.Add(int64(n))
		}
		if rerr != nil {
			st.sess.removeStream(st.id, true)
			_ = st.sess.writeFrame(cmdFIN, st.id, nil)
			return
		}
	}
}

// parseSocks5Addr 解析 SOCKS5 目标地址格式（ATYP + ADDR + PORT BE），支持分片缓冲。
func parseSocks5Addr(buf []byte) (addr string, consumed int, complete bool, err error) {
	if len(buf) < 1 {
		return "", 0, false, nil
	}
	atyp := buf[0]
	switch atyp {
	case 1: // IPv4
		need := 1 + 4 + 2
		if len(buf) < need {
			return "", 0, false, nil
		}
		ip := net.IP(buf[1:5]).String()
		port := binary.BigEndian.Uint16(buf[5:7])
		return net.JoinHostPort(ip, strconv.Itoa(int(port))), need, true, nil
	case 3: // Domain
		if len(buf) < 2 {
			return "", 0, false, nil
		}
		dlen := int(buf[1])
		if dlen == 0 {
			return "", 0, false, errors.New("anytls: empty domain")
		}
		need := 1 + 1 + dlen + 2
		if len(buf) < need {
			return "", 0, false, nil
		}
		host := string(buf[2 : 2+dlen])
		port := binary.BigEndian.Uint16(buf[2+dlen : 2+dlen+2])
		return net.JoinHostPort(host, strconv.Itoa(int(port))), need, true, nil
	case 4: // IPv6
		need := 1 + 16 + 2
		if len(buf) < need {
			return "", 0, false, nil
		}
		ip := net.IP(buf[1:17]).String()
		port := binary.BigEndian.Uint16(buf[17:19])
		return net.JoinHostPort(ip, strconv.Itoa(int(port))), need, true, nil
	default:
		return "", 0, false, fmt.Errorf("anytls: unsupported address type %d", atyp)
	}
}
