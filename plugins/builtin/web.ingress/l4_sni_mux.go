// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"
)

// L4PassthroughTarget 描述 TCP :443 四层零解密 SNI 透传的本机上游目标（如 core.xray Reality/Trojan）。
type L4PassthroughTarget struct {
	UpstreamAddr string
}

// SNIPassthroughRule 为持久化到 SQLite 的四层 SNI 透传规则记录。
type SNIPassthroughRule struct {
	ID           string `json:"id"`
	SNIPattern   string `json:"sni_pattern"`
	UpstreamAddr string `json:"upstream_addr"`
	Enabled      bool   `json:"enabled"`
	Notes        string `json:"notes,omitempty"`
	CreatedAt    int64  `json:"created_at"`
	UpdatedAt    int64  `json:"updated_at"`
}

func validateSNIPattern(raw string) (string, error) {
	p := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(raw), "."))
	if p == "" || len(p) > 253 {
		return "", errors.New("sni_pattern 不能为空且不超过 253 字符")
	}
	if strings.HasPrefix(p, "*.") {
		rest := p[2:]
		if !domainRe.MatchString(rest) {
			return "", errors.New("泛域名 sni_pattern 格式非法（例如 *.example.com）")
		}
		return p, nil
	}
	if !domainRe.MatchString(p) {
		return "", errors.New("sni_pattern 必须为合法域名或一级泛域名（如 www.microsoft.com 或 *.node.example.com）")
	}
	return p, nil
}

// validateSNIPassthroughUpstream 仅允许本机回环地址 (127.0.0.1 / ::1) + 合法端口，
// 防止四层透传被滥用为任意外网或云元数据 TCP SSRF 跳板。
func validateSNIPassthroughUpstream(raw string) (string, error) {
	addr := strings.TrimSpace(raw)
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return "", errors.New("upstream_addr 必须为 host:port 格式（例如 127.0.0.1:24443）")
	}
	port, perr := strconv.Atoi(portStr)
	if perr != nil || port < 1 || port > 65535 {
		return "", errors.New("upstream_addr 端口必须在 1..65535 范围内")
	}
	cleanHost := strings.Trim(strings.TrimSpace(host), "[]")
	ip, ierr := netip.ParseAddr(cleanHost)
	if ierr != nil || !ip.Unmap().IsLoopback() {
		return "", errors.New("受安全边界限制，四层 SNI 透传上游仅允许本机回环地址（127.0.0.1 或 ::1）")
	}
	return net.JoinHostPort(ip.Unmap().String(), strconv.Itoa(port)), nil
}

// L4SNIMuxListener 在 TCP :443 监听器进入 Go tls.Server 解密握手之前预读 ClientHello SNI：
//   - 命中四层透传表时，无损回放首包并在 TCP 层直接透明转发至本机上游（保留 Xray Reality 验签与 uTLS 指纹）；
//   - 未命中时，无损回放首包并转交本地 HTTPS Server 提供常规建站/反代服务。
type L4SNIMuxListener struct {
	rawLn       net.Listener
	localCh     chan net.Conn
	peekSem     chan struct{}
	passSem     chan struct{}
	closeOnce   sync.Once
	closedCh    chan struct{}
	baseCtx     context.Context
	cancelBase  context.CancelFunc
	mu          sync.RWMutex
	exactSNI    map[string]L4PassthroughTarget
	wildcard    map[string]L4PassthroughTarget
	dialTimeout time.Duration
	peekTimeout time.Duration
}

func NewL4SNIMuxListener(rawLn net.Listener) *L4SNIMuxListener {
	return NewL4SNIMuxListenerWithRoutes(rawLn, nil)
}

func NewL4SNIMuxListenerWithRoutes(rawLn net.Listener, initialRoutes map[string]L4PassthroughTarget) *L4SNIMuxListener {
	ctx, cancel := context.WithCancel(context.Background())
	m := &L4SNIMuxListener{
		rawLn:       rawLn,
		localCh:     make(chan net.Conn, 128),
		peekSem:     make(chan struct{}, 256),
		passSem:     make(chan struct{}, 512),
		closedCh:    make(chan struct{}),
		baseCtx:     ctx,
		cancelBase:  cancel,
		exactSNI:    make(map[string]L4PassthroughTarget),
		wildcard:    make(map[string]L4PassthroughTarget),
		dialTimeout: 5 * time.Second,
		peekTimeout: 3 * time.Second,
	}
	if len(initialRoutes) > 0 {
		m.SetRoutes(initialRoutes)
	}
	go m.acceptLoop()
	return m
}

// SetRoutes 原子热更新四层 SNI 透传路由表（零断连、无需重启 :443 监听器）。
func (m *L4SNIMuxListener) SetRoutes(routes map[string]L4PassthroughTarget) {
	if m == nil {
		return
	}
	exact := make(map[string]L4PassthroughTarget)
	wild := make(map[string]L4PassthroughTarget)
	for pattern, target := range routes {
		p, err := validateSNIPattern(pattern)
		if err != nil {
			continue
		}
		up, uerr := validateSNIPassthroughUpstream(target.UpstreamAddr)
		if uerr != nil {
			continue
		}
		target.UpstreamAddr = up
		if strings.HasPrefix(p, "*.") && len(p) > 2 {
			wild[p[1:]] = target // ".example.com"
		} else {
			exact[p] = target
		}
	}
	m.mu.Lock()
	m.exactSNI = exact
	m.wildcard = wild
	m.mu.Unlock()
}

// SetRulesFromRecords 将持久化规则列表同步至活跃透传路由表。
func (m *L4SNIMuxListener) SetRulesFromRecords(rules []SNIPassthroughRule) {
	if m == nil {
		return
	}
	routes := make(map[string]L4PassthroughTarget, len(rules))
	for _, r := range rules {
		if r.Enabled {
			routes[r.SNIPattern] = L4PassthroughTarget{UpstreamAddr: r.UpstreamAddr}
		}
	}
	m.SetRoutes(routes)
}

func (m *L4SNIMuxListener) lookupRoute(sni string) (L4PassthroughTarget, bool) {
	norm := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(sni), "."))
	if norm == "" {
		return L4PassthroughTarget{}, false
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	if t, ok := m.exactSNI[norm]; ok {
		return t, true
	}
	if dot := strings.IndexByte(norm, '.'); dot > 0 {
		if t, ok := m.wildcard[norm[dot:]]; ok {
			return t, true
		}
	}
	return L4PassthroughTarget{}, false
}

func (m *L4SNIMuxListener) hasRoutes() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.exactSNI) > 0 || len(m.wildcard) > 0
}

// Accept 实现 net.Listener：向本地 HTTPS Server 交付未被四层分流接管的连接。
func (m *L4SNIMuxListener) Accept() (net.Conn, error) {
	select {
	case c, ok := <-m.localCh:
		if !ok {
			return nil, net.ErrClosed
		}
		return c, nil
	case <-m.closedCh:
		return nil, net.ErrClosed
	}
}

func (m *L4SNIMuxListener) Close() error {
	var err error
	m.closeOnce.Do(func() {
		m.cancelBase()
		close(m.closedCh)
		err = m.rawLn.Close()
		for {
			select {
			case c := <-m.localCh:
				if c != nil {
					_ = c.Close()
				}
			default:
				return
			}
		}
	})
	return err
}

func (m *L4SNIMuxListener) Addr() net.Addr { return m.rawLn.Addr() }

func (m *L4SNIMuxListener) acceptLoop() {
	for {
		conn, err := m.rawLn.Accept()
		if err != nil {
			select {
			case <-m.closedCh:
				return
			default:
				if ne, ok := err.(net.Error); ok && ne.Timeout() {
					continue
				}
				return
			}
		}
		if !m.hasRoutes() {
			select {
			case m.localCh <- conn:
			case <-m.closedCh:
				_ = conn.Close()
				return
			default:
				_ = conn.Close()
			}
			continue
		}
		select {
		case m.peekSem <- struct{}{}:
			go m.dispatchConn(conn)
		default:
			// 高并发握手保护：超出并发嗅探上限时直接关闭防止连接积压
			_ = conn.Close()
		}
	}
}

func (m *L4SNIMuxListener) dispatchConn(conn net.Conn) {
	_ = conn.SetReadDeadline(time.Now().Add(m.peekTimeout))
	sni, peeked, err := PeekTLSClientHelloSNI(conn)
	_ = conn.SetReadDeadline(time.Time{})
	// 嗅探完成即刻释放 peekSem，避免长连接透传或本地交接长期占满并发嗅探槽位
	<-m.peekSem

	// 远端尚未发送任何字节即断开或超时，直接关闭避免向本地 HTTPS Server 投递死连接。
	if err != nil && len(peeked) == 0 {
		_ = conn.Close()
		return
	}

	wrapped := &replayConn{
		Conn:   conn,
		reader: io.MultiReader(bytes.NewReader(peeked), conn),
	}
	if err == nil && sni != "" {
		if target, ok := m.lookupRoute(sni); ok {
			select {
			case m.passSem <- struct{}{}:
				defer func() { <-m.passSem }()
				m.splicePassthrough(wrapped, target)
			default:
				_ = wrapped.Close()
			}
			return
		}
	}
	m.handToLocal(wrapped)
}

func (m *L4SNIMuxListener) handToLocal(c net.Conn) {
	timer := time.NewTimer(2 * time.Second)
	defer timer.Stop()
	select {
	case m.localCh <- c:
	case <-m.closedCh:
		_ = c.Close()
	case <-timer.C:
		_ = c.Close()
	}
}

type closeWriter interface {
	CloseWrite() error
}

func closeWriteConn(c net.Conn) {
	if cw, ok := c.(closeWriter); ok {
		_ = cw.CloseWrite()
	}
}

func (m *L4SNIMuxListener) splicePassthrough(clientConn net.Conn, target L4PassthroughTarget) {
	defer clientConn.Close()
	dialCtx, cancel := context.WithTimeout(m.baseCtx, m.dialTimeout)
	upConn, err := (&net.Dialer{}).DialContext(dialCtx, "tcp", target.UpstreamAddr)
	cancel()
	if err != nil {
		return
	}
	defer upConn.Close()

	// 若监听器整体关闭，主动中断在途透传连接防止 goroutine 泄漏
	stopWatch := context.AfterFunc(m.baseCtx, func() {
		_ = clientConn.Close()
		_ = upConn.Close()
	})
	defer stopWatch()

	done := make(chan struct{}, 2)
	cp := func(dst, src net.Conn) {
		_, _ = io.Copy(dst, src)
		closeWriteConn(dst)
		done <- struct{}{}
	}
	go cp(upConn, clientConn)
	go cp(clientConn, upConn)
	<-done
	// 单向结束后为半关闭连接设置 15 秒尾包超时，防止对端永不发 FIN 导致 goroutine 永久滞留
	halfCloseDeadline := time.Now().Add(15 * time.Second)
	_ = clientConn.SetDeadline(halfCloseDeadline)
	_ = upConn.SetDeadline(halfCloseDeadline)
	<-done
}

type replayConn struct {
	net.Conn
	reader io.Reader
}

func (rc *replayConn) Read(p []byte) (int, error) { return rc.reader.Read(p) }

func (rc *replayConn) CloseWrite() error {
	if cw, ok := rc.Conn.(closeWriter); ok {
		return cw.CloseWrite()
	}
	return nil
}

// PeekTLSClientHelloSNI 零解密解析 TLS Handshake / ClientHello 的 server_name (0x0000) 扩展，
// 支持跨多条 TLS Record 分片的 ClientHello（总计上限 16 KiB），返回提取出的 SNI 与完整已读字节供无损回放。
func PeekTLSClientHelloSNI(r io.Reader) (sni string, consumed []byte, err error) {
	const maxClientHelloBytes = 16384
	var rawBuf bytes.Buffer
	var hsBuf bytes.Buffer
	tee := io.TeeReader(r, &rawBuf)

	hdr := make([]byte, 5)
	needTotal := 0
	for {
		if _, err := io.ReadFull(tee, hdr); err != nil {
			return "", rawBuf.Bytes(), err
		}
		// ContentType 0x16 = Handshake
		if hdr[0] != 0x16 {
			return "", rawBuf.Bytes(), errors.New("not a TLS handshake record")
		}
		recLen := int(binary.BigEndian.Uint16(hdr[3:5]))
		if recLen <= 0 || hsBuf.Len()+recLen > maxClientHelloBytes {
			return "", rawBuf.Bytes(), fmt.Errorf("invalid TLS record length %d", recLen)
		}
		chunk := make([]byte, recLen)
		if _, err := io.ReadFull(tee, chunk); err != nil {
			return "", rawBuf.Bytes(), err
		}
		hsBuf.Write(chunk)

		hb := hsBuf.Bytes()
		if len(hb) >= 4 {
			if hb[0] != 0x01 {
				// 首个 Handshake 消息不是 ClientHello，停止继续读直接交给本地 TLS 栈处理
				return "", rawBuf.Bytes(), nil
			}
			if needTotal == 0 {
				msgLen := int(hb[1])<<16 | int(hb[2])<<8 | int(hb[3])
				needTotal = 4 + msgLen
				if needTotal > maxClientHelloBytes {
					return "", rawBuf.Bytes(), fmt.Errorf("ClientHello too large: %d", needTotal)
				}
			}
			if len(hb) >= needTotal {
				return parseClientHelloPayloadSNI(hb[:needTotal]), rawBuf.Bytes(), nil
			}
		}
	}
}

func parseClientHelloPayloadSNI(b []byte) string {
	// HandshakeType(1)==0x01 + Length(3) + Version(2) + Random(32) = 38 bytes
	if len(b) < 42 || b[0] != 0x01 {
		return ""
	}
	pos := 38
	// SessionID
	sessIDLen := int(b[pos])
	pos += 1 + sessIDLen
	if pos+2 > len(b) {
		return ""
	}
	// CipherSuites
	csLen := int(binary.BigEndian.Uint16(b[pos : pos+2]))
	pos += 2 + csLen
	if pos+1 > len(b) {
		return ""
	}
	// CompressionMethods
	compLen := int(b[pos])
	pos += 1 + compLen
	if pos+2 > len(b) {
		return ""
	}
	// Extensions
	extTotal := int(binary.BigEndian.Uint16(b[pos : pos+2]))
	pos += 2
	end := pos + extTotal
	if end > len(b) {
		end = len(b)
	}
	for pos+4 <= end {
		extType := binary.BigEndian.Uint16(b[pos : pos+2])
		extLen := int(binary.BigEndian.Uint16(b[pos+2 : pos+4]))
		pos += 4
		if pos+extLen > end {
			return ""
		}
		if extType == 0x0000 && extLen >= 5 { // server_name extension
			extData := b[pos : pos+extLen]
			listLen := int(binary.BigEndian.Uint16(extData[0:2]))
			p := 2
			for p+3 <= 2+listLen && p+3 <= len(extData) {
				nameType := extData[p]
				nameLen := int(binary.BigEndian.Uint16(extData[p+1 : p+3]))
				p += 3
				if p+nameLen > len(extData) {
					return ""
				}
				if nameType == 0x00 { // host_name
					return string(extData[p : p+nameLen])
				}
				p += nameLen
			}
		}
		pos += extLen
	}
	return ""
}
