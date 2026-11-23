// SPDX-License-Identifier: AGPL-3.0-only

// Package anytls 实现加固版纯 Go AnyTLS v1/v2 服务端与热更新多实例监管器。
//
// 核心修复与顶尖优化（对应 R2-BUG-02 / R2-BUG-03 / R2-BUG-11 / R2-BUG-25）：
//  1. 默认安全出站拨号器（SafeOutboundDialer）：DNS 解析后逐 IP 拦截 Loopback、RFC1918 私网、
//     Link-Local（云元数据 169.254.169.254 / fe80::）、CGNAT（100.64.0.0/10 含阿里云元数据）、
//     IPv6 ULA（fc00::/7）、NAT64 嵌私网后缀（64:ff9b::/96 后 32 位）及未指定/多播地址，彻底阻断 SSRF 与回环逃逸；
//  2. 瞬时 Accept 错误（如 EMFILE）指数退避自愈，绝不静默退出监听协程；新增 atomic.Bool 真实存活探针；
//  3. 鉴权前并发信号量（默认 256）+ 小尺寸握手读 + sync.Pool 32KiB 会话读缓冲 & 16KiB 转发缓冲池化，
//     在 1C1G 机器上彻底杜绝未鉴权连接洪泛 OOM 与 GC 抖动；
//  4. 上游目标连接启用 TCP KeepAlive 与双向空闲读超时（streamIdleTimeout），根治半开僵尸流泄漏；
//  5. Supervisor.StartAll 支持同监听地址无感热更新（Users / PaddingScheme / TLS 证书零断连刷新），
//     并跨配置变更单调继承入站与逐用户流量计数器，防止 ResetEpoch 未变时配额回退；
//  6. 支持 SagerNet UDP-over-TCP (UoT v1/v2) 复用流，且未知 SNI 在 TLS 握手层直接拒止。
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
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
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
	maxPreAuthConns          = 256
	maxActiveConns           = 2048
	maxAuthPadBytes          = 16384
	dialTimeout              = 10 * time.Second
	handshakeTimeout         = 12 * time.Second
	targetWriteTimeout       = 30 * time.Second
	streamIdleTimeout        = 3 * time.Minute
	idleReadTimeout          = 5 * time.Minute
	tcpKeepAlivePeriod       = 45 * time.Second
)

var (
	nat64WellKnownPrefix = netip.MustParsePrefix("64:ff9b::/96")
	cgnatPrefix          = netip.MustParsePrefix("100.64.0.0/10")
	benchmarkPrefix      = netip.MustParsePrefix("198.18.0.0/15")
	docV6Prefix          = netip.MustParsePrefix("2001:db8::/32")

	sessionReaderPool = sync.Pool{
		New: func() any {
			return bufio.NewReaderSize(strings.NewReader(""), 32*1024)
		},
	}
	relayBufPool = sync.Pool{
		New: func() any {
			b := make([]byte, maxFramePayload)
			return &b
		},
	}
)

// ErrBlockedDestination 表示目标地址命中服务端安全出站黑名单（回环/私网/链路本地/元数据地址）。
var ErrBlockedDestination = errors.New("anytls: target address is blocked by outbound security policy")

// IsPublicOutboundAddr 严格校验代理出站目标 IP 是否为合法公网单播地址。
func IsPublicOutboundAddr(ip netip.Addr) bool {
	if !ip.IsValid() {
		return false
	}
	ip = ip.Unmap()
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsMulticast() || ip.IsUnspecified() {
		return false
	}
	if ip.Is4() {
		v4 := ip.As4()
		// 0.0.0.0/8、100.64.0.0/10 (CGNAT & 阿里云 IMDS 100.100.100.200)、198.18.0.0/15、240.0.0.0/4
		if v4[0] == 0 || v4[0] >= 240 || cgnatPrefix.Contains(ip) || benchmarkPrefix.Contains(ip) {
			return false
		}
		return true
	}
	if docV6Prefix.Contains(ip) {
		return false
	}
	// NAT64 (64:ff9b::/96)：允许访问内嵌公网 IPv4，但严禁通过 NAT64 绕过访问内嵌回环/私网/IMDS
	if nat64WellKnownPrefix.Contains(ip) {
		raw16 := ip.As16()
		embeddedV4 := netip.AddrFrom4([4]byte{raw16[12], raw16[13], raw16[14], raw16[15]})
		return IsPublicOutboundAddr(embeddedV4)
	}
	return ip.IsGlobalUnicast()
}

// NewSafeOutboundDialer 构造在 socket connect 系统调用前基于内核目标 IP 强校验的安全拨号函数，
// 从根源免疫 DNS Rebinding、回环探测与云元数据窃取。
func NewSafeOutboundDialer(timeout time.Duration) func(ctx context.Context, network, addr string) (net.Conn, error) {
	d := &net.Dialer{
		Timeout:   timeout,
		KeepAlive: tcpKeepAlivePeriod,
		Control: func(_, address string, _ syscall.RawConn) error {
			host, portStr, err := net.SplitHostPort(address)
			if err != nil {
				return ErrBlockedDestination
			}
			port, err := strconv.Atoi(portStr)
			if err != nil || port < 1 || port > 65535 {
				return ErrBlockedDestination
			}
			ip, err := netip.ParseAddr(host)
			if err != nil || !IsPublicOutboundAddr(ip) {
				return ErrBlockedDestination
			}
			return nil
		},
	}
	return d.DialContext
}

// ProfileSpec 描述单个运行中 AnyTLS 入站的监听地址、TLS 证书、填充方案与用户凭据。
type ProfileSpec struct {
	ProfileID          string
	BindingRef         string
	ServerName         string
	Listen             string
	Port               int
	CertPEM            []byte
	KeyPEM             []byte
	PaddingScheme      []string
	Users              map[string][]byte   // userID -> raw password
	UserDigests        map[string][32]byte // userID -> sha256(password)
	AllowPrivateTarget bool                // 仅限单测显式置 true；生产环境恒为 false
}

type userEntry struct {
	id     string
	digest [32]byte
	up     *atomic.Int64
	down   *atomic.Int64
}

type serverAuthSnapshot struct {
	bindingRef  string
	serverName  string
	paddingText string
	paddingMD5  string
	users       []userEntry
}

// Server 承载单个 AnyTLS v1/v2 TLS 监听实例并统计入站/逐用户流量。
type Server struct {
	profileID          string
	listenAddr         string
	allowPrivateTarget bool
	inboundUp          atomic.Int64
	inboundDown        atomic.Int64
	cert               atomic.Pointer[tls.Certificate]
	state              atomic.Pointer[serverAuthSnapshot]
	dialTarget         func(ctx context.Context, network, addr string) (net.Conn, error)

	preAuthSem  chan struct{}
	activeSem   chan struct{}
	acceptAlive atomic.Bool

	ln          net.Listener
	ctx         context.Context
	cancel      context.CancelFunc
	connsMu     sync.Mutex
	activeConns map[net.Conn]struct{}
	stopped     bool
	wg          sync.WaitGroup
	stopOnce    sync.Once
}

func buildAuthSnapshot(spec ProfileSpec, prev *serverAuthSnapshot) (*serverAuthSnapshot, error) {
	if len(spec.Users) == 0 && len(spec.UserDigests) == 0 {
		return nil, errors.New("anytls: at least one user is required")
	}
	scheme := spec.PaddingScheme
	if len(scheme) == 0 {
		scheme = corev2.DefaultAnyTLSPaddingScheme()
	}
	paddingText := strings.Join(scheme, "\n")
	sum := md5.Sum([]byte(paddingText))

	prevCounters := make(map[string][2]*atomic.Int64)
	if prev != nil {
		for _, u := range prev.users {
			prevCounters[u.id] = [2]*atomic.Int64{u.up, u.down}
		}
	}

	entries := make([]userEntry, 0, len(spec.Users)+len(spec.UserDigests))
	seen := make(map[string]struct{}, len(spec.Users)+len(spec.UserDigests))
	allocCounters := func(uid string) (*atomic.Int64, *atomic.Int64) {
		if pair, ok := prevCounters[uid]; ok && pair[0] != nil && pair[1] != nil {
			return pair[0], pair[1]
		}
		return &atomic.Int64{}, &atomic.Int64{}
	}
	for uid, pwd := range spec.Users {
		seen[uid] = struct{}{}
		up, down := allocCounters(uid)
		entries = append(entries, userEntry{
			id:     uid,
			digest: sha256.Sum256(pwd),
			up:     up,
			down:   down,
		})
	}
	for uid, digest := range spec.UserDigests {
		if _, ok := seen[uid]; ok {
			continue
		}
		up, down := allocCounters(uid)
		entries = append(entries, userEntry{
			id:     uid,
			digest: digest,
			up:     up,
			down:   down,
		})
	}
	return &serverAuthSnapshot{
		bindingRef:  spec.BindingRef,
		serverName:  spec.ServerName,
		paddingText: paddingText,
		paddingMD5:  hex.EncodeToString(sum[:]),
		users:       entries,
	}, nil
}

// NewServer 校验并构造 AnyTLS 服务端实例（尚未开始监听）。
func NewServer(spec ProfileSpec) (*Server, error) {
	if spec.ProfileID == "" || spec.Listen == "" || spec.Port < 1 || spec.Port > 65535 {
		return nil, errors.New("anytls: invalid profile listen specification")
	}
	cert, err := tls.X509KeyPair(spec.CertPEM, spec.KeyPEM)
	if err != nil {
		return nil, fmt.Errorf("anytls: load x509 keypair: %w", err)
	}
	snap, err := buildAuthSnapshot(spec, nil)
	if err != nil {
		return nil, err
	}
	dialFn := NewSafeOutboundDialer(dialTimeout)
	if spec.AllowPrivateTarget {
		dialFn = (&net.Dialer{Timeout: dialTimeout, KeepAlive: tcpKeepAlivePeriod}).DialContext
	}
	s := &Server{
		profileID:          spec.ProfileID,
		listenAddr:         net.JoinHostPort(spec.Listen, strconv.Itoa(spec.Port)),
		allowPrivateTarget: spec.AllowPrivateTarget,
		dialTarget:         dialFn,
		preAuthSem:         make(chan struct{}, maxPreAuthConns),
		activeSem:          make(chan struct{}, maxActiveConns),
		activeConns:        make(map[net.Conn]struct{}),
	}
	s.cert.Store(&cert)
	s.state.Store(snap)
	return s, nil
}

func (s *Server) bindingRefValue() string {
	if snap := s.state.Load(); snap != nil {
		return snap.bindingRef
	}
	return ""
}

func (s *Server) serverNameValue() string {
	if snap := s.state.Load(); snap != nil {
		return snap.serverName
	}
	return ""
}

// HotUpdate 在监听地址不变时无中断热更新 TLS 证书、用户列表与填充方案，并完整保留流量计数。
func (s *Server) HotUpdate(spec ProfileSpec) error {
	cert, err := tls.X509KeyPair(spec.CertPEM, spec.KeyPEM)
	if err != nil {
		return fmt.Errorf("anytls: reload x509 keypair: %w", err)
	}
	snap, err := buildAuthSnapshot(spec, s.state.Load())
	if err != nil {
		return err
	}
	s.cert.Store(&cert)
	s.state.Store(snap)
	return nil
}

// Start 绑定 TLS 监听并启动具备瞬时错误自愈能力的接收循环。
func (s *Server) Start(parent context.Context) error {
	tlsCfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			if sn := s.serverNameValue(); sn != "" && !strings.EqualFold(strings.TrimSuffix(hello.ServerName, "."), sn) {
				return nil, errors.New("anytls: unrecognized server name")
			}
			return s.cert.Load(), nil
		},
	}
	lc := net.ListenConfig{KeepAlive: tcpKeepAlivePeriod}
	rawLn, err := lc.Listen(parent, "tcp", s.listenAddr)
	if err != nil {
		return fmt.Errorf("anytls: listen %s: %w", s.listenAddr, err)
	}
	s.ln = tls.NewListener(rawLn, tlsCfg)
	s.ctx, s.cancel = context.WithCancel(parent)
	s.acceptAlive.Store(true)
	s.wg.Add(1)
	go s.acceptLoop()
	return nil
}

// IsAlive 返回监听协程是否真实存活运行。
func (s *Server) IsAlive() bool {
	return s != nil && s.acceptAlive.Load()
}

// Addr 返回实际监听地址。
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
		s.acceptAlive.Store(false)
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
	snap := s.state.Load()
	if snap == nil {
		return
	}
	for _, u := range snap.users {
		up := u.up.Load()
		down := u.down.Load()
		if up > 0 || down > 0 {
			out["user>>>qwq-user-"+u.id+">>>traffic>>>uplink"] += up
			out["user>>>qwq-user-"+u.id+">>>traffic>>>downlink"] += down
		}
	}
}

// InheritCountersFrom 在监听端口变更重建 Server 时平滑迁移既有流量计数器，避免配额统计回退。
func (s *Server) InheritCountersFrom(prev *Server) {
	if prev == nil || s == nil {
		return
	}
	s.inboundUp.Store(prev.inboundUp.Load())
	s.inboundDown.Store(prev.inboundDown.Load())
	prevSnap := prev.state.Load()
	curSnap := s.state.Load()
	if prevSnap == nil || curSnap == nil {
		return
	}
	byID := make(map[string][2]int64, len(prevSnap.users))
	for _, u := range prevSnap.users {
		byID[u.id] = [2]int64{u.up.Load(), u.down.Load()}
	}
	for _, u := range curSnap.users {
		if pair, ok := byID[u.id]; ok {
			u.up.Store(pair[0])
			u.down.Store(pair[1])
		}
	}
}

func (s *Server) acceptLoop() {
	defer func() {
		s.acceptAlive.Store(false)
		s.wg.Done()
	}()
	var tempDelay time.Duration
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			if s.ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return
			}
			// 对 EMFILE / ENFILE / 瞬时网络错误做指数退避恢复，绝不让端口永久假死
			if tempDelay == 0 {
				tempDelay = 5 * time.Millisecond
			} else {
				tempDelay *= 2
				if tempDelay > time.Second {
					tempDelay = time.Second
				}
			}
			select {
			case <-s.ctx.Done():
				return
			case <-time.After(tempDelay):
				continue
			}
		}
		tempDelay = 0

		// 总活跃连接与未鉴权并发双重门控：满载时立即丢弃新连接，保护 1C1G 宿主内存
		select {
		case s.activeSem <- struct{}{}:
		default:
			_ = conn.Close()
			continue
		}
		select {
		case s.preAuthSem <- struct{}{}:
		default:
			<-s.activeSem
			_ = conn.Close()
			continue
		}

		s.wg.Add(1)
		go func(c net.Conn) {
			defer func() {
				<-s.activeSem
				s.wg.Done()
			}()
			s.handleConn(c)
		}(conn)
	}
}

func (s *Server) matchUser(digest []byte) (*userEntry, *serverAuthSnapshot) {
	snap := s.state.Load()
	if snap == nil || len(digest) != 32 {
		return nil, snap
	}
	var matched *userEntry
	for idx := range snap.users {
		if subtle.ConstantTimeCompare(snap.users[idx].digest[:], digest) == 1 {
			matched = &snap.users[idx]
		}
	}
	return matched, snap
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
	preAuthReleased := false
	releasePreAuth := func() {
		if !preAuthReleased {
			preAuthReleased = true
			<-s.preAuthSem
		}
	}
	defer releasePreAuth()

	if !s.registerConn(conn) {
		_ = conn.Close()
		return
	}
	defer func() {
		s.unregisterConn(conn)
		_ = conn.Close()
	}()

	if tlsConn, ok := conn.(*tls.Conn); ok {
		_ = tlsConn.SetDeadline(time.Now().Add(handshakeTimeout))
		if err := tlsConn.HandshakeContext(s.ctx); err != nil {
			return
		}
	}

	_ = conn.SetReadDeadline(time.Now().Add(handshakeTimeout))
	// 鉴权完成前直接在 conn 上读取固定 34 字节认证头，零分配 32KiB Reader，彻底防御慢速连接内存放大
	var authHeader [34]byte
	if _, err := io.ReadFull(conn, authHeader[:]); err != nil {
		return
	}
	user, snap := s.matchUser(authHeader[:32])
	if user == nil || snap == nil {
		return
	}
	padLen := int(binary.BigEndian.Uint16(authHeader[32:34]))
	if padLen > maxAuthPadBytes {
		return
	}

	// 鉴权通过！释放预鉴权名额并从 sync.Pool 借用 32KiB 会话缓冲
	releasePreAuth()
	br := sessionReaderPool.Get().(*bufio.Reader)
	br.Reset(conn)
	defer func() {
		br.Reset(strings.NewReader(""))
		sessionReaderPool.Put(br)
	}()

	if padLen > 0 {
		if _, err := io.CopyN(io.Discard, br, int64(padLen)); err != nil {
			return
		}
	}
	_ = conn.SetDeadline(time.Time{})

	sess := &anytlsSession{
		server:        s,
		user:          user,
		paddingText:   snap.paddingText,
		paddingMD5:    snap.paddingMD5,
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
	paddingText   string
	paddingMD5    string
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
	uotWriter    *io.PipeWriter
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

	// 优先读取最新热更快照的填充策略
	padMD5 := sess.paddingMD5
	padText := sess.paddingText
	if snap := sess.server.state.Load(); snap != nil {
		padMD5 = snap.paddingMD5
		padText = snap.paddingText
	}

	if ver >= 2 {
		if err := sess.writeFrame(cmdServerSettings, 0, []byte("v=2\n")); err != nil {
			return err
		}
	}
	if clientMD5 != padMD5 {
		if err := sess.writeFrame(cmdUpdatePaddingScheme, 0, []byte(padText)); err != nil {
			return err
		}
	}
	return nil
}

func (sess *anytlsSession) getOrCreateStream(streamID uint32) (*anytlsStream, bool) {
	sess.mu.Lock()
	defer sess.mu.Unlock()
	if sess.closed {
		return nil, false
	}
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
	pw := st.uotWriter
	st.uotWriter = nil
	st.pending = nil
	st.pendingBytes = 0
	st.mu.Unlock()
	if conn != nil {
		_ = conn.Close()
	}
	if pw != nil {
		_ = pw.Close()
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
	// 双向活跃刷新上游读超时，防止单向上传大文件时误触发读空闲断开
	_ = conn.SetReadDeadline(time.Now().Add(streamIdleTimeout))
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

func (st *anytlsStream) writeToUoTPipe(pw *io.PipeWriter, data []byte) bool {
	if len(data) == 0 {
		return true
	}
	st.writeMu.Lock()
	_, err := pw.Write(data)
	st.writeMu.Unlock()
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
	if st.ready {
		if st.targetConn != nil {
			conn := st.targetConn
			st.mu.Unlock()
			st.writeToTarget(conn, data)
			return
		}
		if st.uotWriter != nil {
			pw := st.uotWriter
			st.mu.Unlock()
			st.writeToUoTPipe(pw, data)
			return
		}
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
	if uotVer, ok := IsUoTMagicTarget(targetAddr); ok {
		pr, pw := io.Pipe()
		st.mu.Lock()
		if st.closed {
			st.mu.Unlock()
			_ = pr.Close()
			_ = pw.Close()
			return
		}
		st.uotWriter = pw
		st.mu.Unlock()

		uotDone := make(chan struct{})
		go func() {
			defer close(uotDone)
			st.relayUoTStream(uotVer, pr)
		}()

		for {
			st.mu.Lock()
			if st.closed {
				st.mu.Unlock()
				_ = pw.Close()
				<-uotDone
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
				if !st.writeToUoTPipe(pw, chunk) {
					<-uotDone
					return
				}
			}
		}
		<-uotDone
		return
	}

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

	bufPtr := relayBufPool.Get().(*[]byte)
	buf := *bufPtr
	defer relayBufPool.Put(bufPtr)

	for {
		_ = conn.SetReadDeadline(time.Now().Add(streamIdleTimeout))
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

// parseSocks5Addr 解析 SOCKS5 目标地址格式（ATYP + ADDR + PORT BE），并严格拒绝端口 0。
func parseSocks5Addr(buf []byte) (addr string, consumed int, complete bool, err error) {
	if len(buf) < 1 {
		return "", 0, false, nil
	}
	atyp := buf[0]
	switch atyp {
	case 1: // IPv4
		const need = 1 + 4 + 2
		if len(buf) < need {
			return "", 0, false, nil
		}
		port := binary.BigEndian.Uint16(buf[5:7])
		if port == 0 {
			return "", 0, false, errors.New("anytls: invalid port 0")
		}
		ip := net.IP(buf[1:5]).String()
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
		port := binary.BigEndian.Uint16(buf[2+dlen : 2+dlen+2])
		if port == 0 {
			return "", 0, false, errors.New("anytls: invalid port 0")
		}
		host := strings.TrimSpace(string(buf[2 : 2+dlen]))
		if host == "" || strings.ContainsAny(host, " \t\r\n\x00/\\") {
			return "", 0, false, errors.New("anytls: malformed domain")
		}
		return net.JoinHostPort(host, strconv.Itoa(int(port))), need, true, nil
	case 4: // IPv6
		const need = 1 + 16 + 2
		if len(buf) < need {
			return "", 0, false, nil
		}
		port := binary.BigEndian.Uint16(buf[17:19])
		if port == 0 {
			return "", 0, false, errors.New("anytls: invalid port 0")
		}
		ip := net.IP(buf[1:17]).String()
		return net.JoinHostPort(ip, strconv.Itoa(int(port))), need, true, nil
	default:
		return "", 0, false, fmt.Errorf("anytls: unsupported address type %d", atyp)
	}
}
