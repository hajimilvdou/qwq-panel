// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/qwq-panel/qwq/sdk/pluginsdk"
)

const (
	maxBrutalBindings         = 16
	maxBrutalConnsPerListener = 256
	defaultOversendPct        = 125
	defaultBrutalGain         = 20
	defaultBrutalRateMbs      = 100
)

// brutalBindingRecord 描述一个 TCP 入站端口的 Brutal Custom 透明接管绑定。
type brutalBindingRecord struct {
	ID            string  `json:"id"`
	InboundTag    string  `json:"inbound_tag"`
	Protocol      string  `json:"protocol"` // vless | shadowsocks | trojan | tcp
	Enabled       bool    `json:"enabled"`
	ListenPort    int     `json:"listen_port"`    // 透明接管对外监听端口（0 = 由测试动态分配或暂未启用）
	TargetPort    int     `json:"target_port"`    // 本机后端代理入站端口（如 Xray VLESS 443 / SS 8388）
	BandwidthMbps int     `json:"bandwidth_mbps"` // 基准带宽 (Mbps)
	OversendPct   int     `json:"oversend_pct"`   // 超发包倍率 (%)，原始默认 125，允许 100..250 手调
	CwndGain      int     `json:"cwnd_gain"`      // 拥塞窗口增益 (单位 0.1x，20 = 2.0x，允许 10..50)
	EffectiveMbps float64 `json:"effective_mbps"` // 折算有效发包速率 = bandwidth_mbps * oversend_pct / 100
	EnableInSub   bool    `json:"enable_in_sub"`  // 是否自动将对应 TCP 订阅节点端口切换为此接管端口
	Notes         string  `json:"notes,omitempty"`
	Revision      int64   `json:"revision"`
	CreatedAt     int64   `json:"created_at"`
	UpdatedAt     int64   `json:"updated_at"`
}

type brutalBindingUpsertRequest struct {
	ID               string `json:"id"`
	InboundTag       string `json:"inbound_tag"`
	Protocol         string `json:"protocol"`
	Enabled          *bool  `json:"enabled"`
	ListenPort       int    `json:"listen_port"`
	TargetPort       int    `json:"target_port"`
	BandwidthMbps    int    `json:"bandwidth_mbps"`
	OversendPct      *int   `json:"oversend_pct"`
	CwndGain         *int   `json:"cwnd_gain"`
	EnableInSub      *bool  `json:"enable_in_sub"`
	Notes            string `json:"notes"`
	ExpectedRevision string `json:"expected_revision"`
}

// brutalBindingMetrics 实时汇报透明接管端口的活跃连接、套用成功/回退次数与字节数。
type brutalBindingMetrics struct {
	BindingID          string `json:"binding_id"`
	InboundTag         string `json:"inbound_tag"`
	BoundAddr          string `json:"bound_addr,omitempty"`
	Running            bool   `json:"running"`
	ActiveConns        int64  `json:"active_conns"`
	TotalConns         uint64 `json:"total_conns"`
	BrutalAppliedConns uint64 `json:"brutal_applied_conns"`
	FallbackConns      uint64 `json:"fallback_conns"`
	BytesTX            uint64 `json:"bytes_tx"`
	BytesRX            uint64 `json:"bytes_rx"`
	LastSockoptError   string `json:"last_sockopt_error,omitempty"`
}

func computeBrutalRateBPS(bandwidthMbps, oversendPct int) uint64 {
	if bandwidthMbps < 1 {
		bandwidthMbps = 1
	}
	if oversendPct < 100 {
		oversendPct = 100
	}
	// 1 Mbps = 125,000 Bytes/s；乘以 oversend_pct / 100 得到超发后的内核发包速率（字节/秒）。
	return uint64(bandwidthMbps) * 125000 * uint64(oversendPct) / 100
}

func computeEffectiveMbps(bandwidthMbps, oversendPct int) float64 {
	return float64(bandwidthMbps) * float64(oversendPct) / 100.0
}

func validateBrutalBindingInput(in brutalBindingUpsertRequest) (brutalBindingRecord, error) {
	id := strings.TrimSpace(in.ID)
	if id == "" || !validEntityIDPattern.MatchString(id) {
		return brutalBindingRecord{}, pluginsdk.Errorf("INVALID_ARGUMENT", "brutal 绑定 id 必须符合小写标识规范")
	}
	tag := strings.TrimSpace(in.InboundTag)
	if tag == "" || !validEntityIDPattern.MatchString(tag) {
		return brutalBindingRecord{}, pluginsdk.Errorf("INVALID_ARGUMENT", "inbound_tag 必须符合小写标识规范（如 vless-tcp、ss2022-tcp）")
	}
	proto := strings.TrimSpace(in.Protocol)
	if proto == "" {
		proto = "vless"
	}
	switch proto {
	case "vless", "shadowsocks", "trojan", "tcp":
	default:
		return brutalBindingRecord{}, pluginsdk.Errorf("INVALID_ARGUMENT", "protocol 仅支持 vless / shadowsocks / trojan / tcp")
	}
	if in.ListenPort < 0 || in.ListenPort > 65535 {
		return brutalBindingRecord{}, pluginsdk.Errorf("INVALID_ARGUMENT", "listen_port 须在 0..65535 之间")
	}
	if in.TargetPort < 1 || in.TargetPort > 65535 {
		return brutalBindingRecord{}, pluginsdk.Errorf("INVALID_ARGUMENT", "target_port 须在 1..65535 之间")
	}
	if in.ListenPort > 0 && in.ListenPort == in.TargetPort {
		return brutalBindingRecord{}, pluginsdk.Errorf("INVALID_ARGUMENT", "透明接管 listen_port 不能与本机后端 target_port 相同，否则会产生环路")
	}
	bw := in.BandwidthMbps
	if bw == 0 {
		bw = defaultBrutalRateMbs
	}
	if bw < 1 || bw > 10000 {
		return brutalBindingRecord{}, pluginsdk.Errorf("INVALID_ARGUMENT", "bandwidth_mbps 须在 1..10000 之间")
	}
	oversend := defaultOversendPct
	if in.OversendPct != nil {
		oversend = *in.OversendPct
	}
	if oversend < 100 || oversend > 250 {
		return brutalBindingRecord{}, pluginsdk.Errorf("INVALID_ARGUMENT", "oversend_pct 超发倍率须在 100..250 之间（原始默认 125）")
	}
	gain := defaultBrutalGain
	if in.CwndGain != nil {
		gain = *in.CwndGain
	}
	if gain < 10 || gain > 50 {
		return brutalBindingRecord{}, pluginsdk.Errorf("INVALID_ARGUMENT", "cwnd_gain 须在 10..50 之间（单位 0.1x，推荐 15..25）")
	}
	enabled := true
	if in.Enabled != nil {
		enabled = *in.Enabled
	}
	enableInSub := true
	if in.EnableInSub != nil {
		enableInSub = *in.EnableInSub
	}
	return brutalBindingRecord{
		ID:            id,
		InboundTag:    tag,
		Protocol:      proto,
		Enabled:       enabled,
		ListenPort:    in.ListenPort,
		TargetPort:    in.TargetPort,
		BandwidthMbps: bw,
		OversendPct:   oversend,
		CwndGain:      gain,
		EffectiveMbps: computeEffectiveMbps(bw, oversend),
		EnableInSub:   enableInSub,
		Notes:         strings.TrimSpace(in.Notes),
	}, nil
}

func (s *proxyStore) UpsertBrutalBinding(ctx context.Context, in brutalBindingUpsertRequest) (brutalBindingRecord, bool, error) {
	rec, err := validateBrutalBindingInput(in)
	if err != nil {
		return brutalBindingRecord{}, false, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return brutalBindingRecord{}, false, err
	}
	defer func() { _ = tx.Rollback() }()

	if rec.ListenPort > 0 {
		var clashID string
		_ = tx.QueryRowContext(ctx, `SELECT id FROM brutal_bindings WHERE listen_port = ? AND id <> ?`, rec.ListenPort, rec.ID).Scan(&clashID)
		if clashID != "" {
			return brutalBindingRecord{}, false, pluginsdk.Errorf("CONFLICT", "接管端口 %d 已被绑定 %s 占用", rec.ListenPort, clashID)
		}
	}

	var existingRev, existingCreated int64
	err = tx.QueryRowContext(ctx, `SELECT revision, created_at FROM brutal_bindings WHERE id = ?`, rec.ID).Scan(&existingRev, &existingCreated)
	created := errors.Is(err, sql.ErrNoRows)
	if err != nil && !created {
		return brutalBindingRecord{}, false, err
	}
	nowMs := s.now().UTC().UnixMilli()
	if created {
		if in.ExpectedRevision != "" {
			return brutalBindingRecord{}, false, pluginsdk.PreconditionFailed("brutal/"+rec.ID, "")
		}
		var cnt int
		if tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM brutal_bindings`).Scan(&cnt) == nil && cnt >= maxBrutalBindings {
			return brutalBindingRecord{}, false, pluginsdk.Errorf("RESOURCE_EXHAUSTED", "TCP Brutal 端口绑定数已达上限 (%d)", maxBrutalBindings)
		}
		rec.Revision = 1
		rec.CreatedAt = nowMs
		rec.UpdatedAt = nowMs
		_, err = tx.ExecContext(ctx, `
			INSERT INTO brutal_bindings(id, inbound_tag, protocol, enabled, listen_port, target_port,
			                            bandwidth_mbps, oversend_pct, cwnd_gain, enable_in_sub, notes, revision, created_at, updated_at)
			VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?)`,
			rec.ID, rec.InboundTag, rec.Protocol, boolToInt(rec.Enabled), rec.ListenPort, rec.TargetPort,
			rec.BandwidthMbps, rec.OversendPct, rec.CwndGain, boolToInt(rec.EnableInSub), rec.Notes, nowMs, nowMs)
	} else {
		if in.ExpectedRevision != "" && in.ExpectedRevision != strconv.FormatInt(existingRev, 10) {
			return brutalBindingRecord{}, false, pluginsdk.PreconditionFailed("brutal/"+rec.ID, strconv.FormatInt(existingRev, 10))
		}
		rec.Revision = existingRev + 1
		rec.CreatedAt = existingCreated
		rec.UpdatedAt = nowMs
		_, err = tx.ExecContext(ctx, `
			UPDATE brutal_bindings
			SET inbound_tag = ?, protocol = ?, enabled = ?, listen_port = ?, target_port = ?,
			    bandwidth_mbps = ?, oversend_pct = ?, cwnd_gain = ?, enable_in_sub = ?, notes = ?, revision = ?, updated_at = ?
			WHERE id = ?`,
			rec.InboundTag, rec.Protocol, boolToInt(rec.Enabled), rec.ListenPort, rec.TargetPort,
			rec.BandwidthMbps, rec.OversendPct, rec.CwndGain, boolToInt(rec.EnableInSub), rec.Notes, rec.Revision, nowMs, rec.ID)
	}
	if err != nil {
		return brutalBindingRecord{}, false, err
	}
	if err := tx.Commit(); err != nil {
		return brutalBindingRecord{}, false, err
	}
	return rec, created, nil
}

func (s *proxyStore) ListBrutalBindings(ctx context.Context) ([]brutalBindingRecord, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, inbound_tag, protocol, enabled, listen_port, target_port,
		       bandwidth_mbps, oversend_pct, cwnd_gain, enable_in_sub, notes, revision, created_at, updated_at
		FROM brutal_bindings ORDER BY id ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]brutalBindingRecord, 0)
	for rows.Next() {
		var r brutalBindingRecord
		var en, sub int
		if err := rows.Scan(&r.ID, &r.InboundTag, &r.Protocol, &en, &r.ListenPort, &r.TargetPort,
			&r.BandwidthMbps, &r.OversendPct, &r.CwndGain, &sub, &r.Notes, &r.Revision, &r.CreatedAt, &r.UpdatedAt); err != nil {
			return nil, err
		}
		r.Enabled = en == 1
		r.EnableInSub = sub == 1
		r.EffectiveMbps = computeEffectiveMbps(r.BandwidthMbps, r.OversendPct)
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *proxyStore) DeleteBrutalBinding(ctx context.Context, id string) (bool, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM brutal_bindings WHERE id = ?`, id)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// ======================== Brutal Custom 端口透明接管运行时 ========================

type brutalListener struct {
	mu           sync.RWMutex
	binding      brutalBindingRecord
	ln           net.Listener
	boundAddr    string
	cancel       context.CancelFunc
	activeConns  atomic.Int64
	totalConns   atomic.Uint64
	appliedConns atomic.Uint64
	fallbackConn atomic.Uint64
	bytesTX      atomic.Uint64
	bytesRX      atomic.Uint64
	lastErr      string
}

func (l *brutalListener) updateParams(b brutalBindingRecord) {
	l.mu.Lock()
	l.binding = b
	l.mu.Unlock()
}

func (l *brutalListener) snapshot() brutalBindingMetrics {
	l.mu.RLock()
	b := l.binding
	lastErr := l.lastErr
	boundAddr := l.boundAddr
	l.mu.RUnlock()
	return brutalBindingMetrics{
		BindingID:          b.ID,
		InboundTag:         b.InboundTag,
		BoundAddr:          boundAddr,
		Running:            true,
		ActiveConns:        l.activeConns.Load(),
		TotalConns:         l.totalConns.Load(),
		BrutalAppliedConns: l.appliedConns.Load(),
		FallbackConns:      l.fallbackConn.Load(),
		BytesTX:            l.bytesTX.Load(),
		BytesRX:            l.bytesRX.Load(),
		LastSockoptError:   lastErr,
	}
}

func (l *brutalListener) stop() {
	if l.cancel != nil {
		l.cancel()
	}
	if l.ln != nil {
		_ = l.ln.Close()
	}
}

func (l *brutalListener) serve(ctx context.Context) {
	for {
		conn, err := l.ln.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		if l.activeConns.Load() >= maxBrutalConnsPerListener {
			_ = conn.Close()
			continue
		}
		go l.handleConn(ctx, conn)
	}
}

func (l *brutalListener) handleConn(ctx context.Context, client net.Conn) {
	defer func() { _ = client.Close() }()
	stopClient := context.AfterFunc(ctx, func() { _ = client.Close() })
	defer stopClient()

	l.activeConns.Add(1)
	l.totalConns.Add(1)
	defer l.activeConns.Add(-1)

	l.mu.RLock()
	b := l.binding
	l.mu.RUnlock()

	if tcpConn, ok := client.(*net.TCPConn); ok {
		_ = tcpConn.SetNoDelay(true)
		rateBPS := computeBrutalRateBPS(b.BandwidthMbps, b.OversendPct)
		if err := applyTCPBrutalSockopt(tcpConn, rateBPS, uint32(b.CwndGain)); err != nil {
			l.fallbackConn.Add(1)
			l.mu.Lock()
			l.lastErr = err.Error()
			l.mu.Unlock()
		} else {
			l.appliedConns.Add(1)
		}
	}

	targetAddr := net.JoinHostPort("127.0.0.1", strconv.Itoa(b.TargetPort))
	dialer := &net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}
	backend, err := dialer.DialContext(ctx, "tcp", targetAddr)
	if err != nil {
		return
	}
	defer func() { _ = backend.Close() }()
	stopBackend := context.AfterFunc(ctx, func() { _ = backend.Close() })
	defer stopBackend()
	if bt, ok := backend.(*net.TCPConn); ok {
		_ = bt.SetNoDelay(true)
	}

	var wg sync.WaitGroup
	wg.Add(2)
	// 客户端 -> 后端代理入站 (RX)
	go func() {
		defer wg.Done()
		n, _ := io.Copy(backend, client)
		if n > 0 {
			l.bytesRX.Add(uint64(n))
		}
		if cw, ok := backend.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
	}()
	// 后端代理入站 -> 客户端 (TX，受 Brutal 拥塞控制加速)
	go func() {
		defer wg.Done()
		n, _ := io.Copy(client, backend)
		if n > 0 {
			l.bytesTX.Add(uint64(n))
		}
		if cw, ok := client.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
	}()
	wg.Wait()
}

// brutalManager 统一管理所有启用中的 Brutal 端口透明接管监听器，支持热改超发倍率与平滑启停。
type brutalManager struct {
	mu        sync.Mutex
	bindHost  string
	listeners map[string]*brutalListener
}

func newBrutalManager(bindHost string) *brutalManager {
	return &brutalManager{
		bindHost:  bindHost,
		listeners: make(map[string]*brutalListener),
	}
}

func (m *brutalManager) Reconcile(bindings []brutalBindingRecord) ([]brutalBindingMetrics, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	want := make(map[string]brutalBindingRecord, len(bindings))
	for _, b := range bindings {
		if b.Enabled {
			want[b.ID] = b
		}
	}

	// 停止已移除、已停用或监听端口变更的监听器
	for id, l := range m.listeners {
		next, ok := want[id]
		l.mu.RLock()
		oldPort := l.binding.ListenPort
		l.mu.RUnlock()
		if !ok || (next.ListenPort > 0 && next.ListenPort != oldPort) {
			l.stop()
			delete(m.listeners, id)
		}
	}

	var firstErr error
	for id, b := range want {
		if cur, ok := m.listeners[id]; ok {
			// 同端口热更新超发倍率 / 基准带宽 / cwnd_gain，无需断开监听！
			cur.updateParams(b)
			continue
		}
		host := m.bindHost
		addr := net.JoinHostPort(host, strconv.Itoa(b.ListenPort))
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("brutal listener %s (%s): %w", b.ID, addr, err)
			}
			continue
		}
		lctx, cancel := context.WithCancel(context.Background())
		bl := &brutalListener{
			binding:   b,
			ln:        ln,
			boundAddr: ln.Addr().String(),
			cancel:    cancel,
		}
		m.listeners[id] = bl
		go bl.serve(lctx)
	}

	metrics := make([]brutalBindingMetrics, 0, len(m.listeners))
	for _, l := range m.listeners {
		metrics = append(metrics, l.snapshot())
	}
	sort.Slice(metrics, func(i, j int) bool { return metrics[i].BindingID < metrics[j].BindingID })
	return metrics, firstErr
}

func (m *brutalManager) Metrics() []brutalBindingMetrics {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]brutalBindingMetrics, 0, len(m.listeners))
	for _, l := range m.listeners {
		out = append(out, l.snapshot())
	}
	sort.Slice(out, func(i, j int) bool { return out[i].BindingID < out[j].BindingID })
	return out
}

func (m *brutalManager) CloseAll() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for id, l := range m.listeners {
		l.stop()
		delete(m.listeners, id)
	}
}
