// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"
)

const (
	MaxClockSkewSeconds = 120
)

var (
	ErrUnauthorizedAgent   = errors.New("invalid or revoked probe agent token")
	ErrReplayOrSkewedClock = errors.New("agent report timestamp outside +-120s anti-replay window or stale sequence")
	ErrSSRFTargetBlocked   = errors.New("probe target resolves to loopback, link-local, metadata, special IPv6, or private network")
)

// specialBlockedPrefixes 完整对齐原仓库 P1-PLG-09 出站安全边界（含 CGNAT、基准测试段、NAT64、Teredo、6to4 与丢弃路由段）。
var specialBlockedPrefixes = []netip.Prefix{
	netip.MustParsePrefix("100.64.0.0/10"),  // Carrier-Grade NAT & 阿里云元数据 100.100.100.200
	netip.MustParsePrefix("198.18.0.0/15"),  // RFC 2544 基准测试网段
	netip.MustParsePrefix("0000::/8"),       // IPv6 保留段
	netip.MustParsePrefix("64:ff9b::/96"),   // NAT64 Well-Known Prefix
	netip.MustParsePrefix("64:ff9b:1::/48"), // NAT64 Local-Use Prefix
	netip.MustParsePrefix("100::/64"),       // RFC 6666 Discard-Only Prefix
	netip.MustParsePrefix("2001::/32"),      // Teredo 隧道段
	netip.MustParsePrefix("2002::/16"),      // 6to4 映射段
}

var allowedCarrierKeys = map[string]struct{}{
	"ct": {}, "cu": {}, "cm": {}, "global": {}, "custom": {},
}

// sharedSafeHTTPClient 全局单例复用连接池，并在拨号瞬间锁定已核验的公网 IP（彻底根除 DNS Rebinding 二次解析漏洞，且零 Transport 泄漏！）。
var sharedSafeHTTPClient = &http.Client{
	Timeout: 5 * time.Second,
	Transport: &http.Transport{
		DialContext:         dialVerifiedPublicContext,
		MaxIdleConns:        16,
		MaxIdleConnsPerHost: 2,
		IdleConnTimeout:     45 * time.Second,
		TLSHandshakeTimeout: 4 * time.Second,
		TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12},
	},
	CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	},
}

// AgentReportPayload 是外部小鸡单向上报的只读遥测包（零指令回传、零远程执行面）。
type AgentReportPayload struct {
	NodeID        string           `json:"node_id"`
	TimestampUnix int64            `json:"timestamp_unix"`
	Sequence      uint64           `json:"seq"`
	BootEpoch     uint64           `json:"boot_epoch"`
	OSName        string           `json:"os_name"`
	KernelVersion string           `json:"kernel"`
	Arch          string           `json:"arch"`
	VirtType      string           `json:"virt"`
	CPUModel      string           `json:"cpu_model"`
	CPUCores      int              `json:"cpu_cores"`
	MemTotal      uint64           `json:"mem_total"`
	MemUsed       uint64           `json:"mem_used"`
	SwapTotal     uint64           `json:"swap_total"`
	SwapUsed      uint64           `json:"swap_used"`
	DiskTotal     uint64           `json:"disk_total"`
	DiskUsed      uint64           `json:"disk_used"`
	RawRxBytes    uint64           `json:"raw_rx_bytes"`
	RawTxBytes    uint64           `json:"raw_tx_bytes"`
	NetRxBps      uint64           `json:"net_rx_bps"`
	NetTxBps      uint64           `json:"net_tx_bps"`
	CPUPercent    float64          `json:"cpu_pct"`
	Load1         float64          `json:"load1"`
	Load5         float64          `json:"load5"`
	Load15        float64          `json:"load15"`
	TCPConns      uint32           `json:"tcp_conns"`
	UDPConns      uint32           `json:"udp_conns"`
	ProcessCount  uint32           `json:"process_count"`
	UptimeSeconds uint64           `json:"uptime_seconds"`
	HasIPv4       bool             `json:"has_ipv4"`
	HasIPv6       bool             `json:"has_ipv6"`
	CarrierPingMs map[string]int32 `json:"carrier_ping_ms"`
}

// AgentDesiredPullConfig 随 HTTP 200 上报回包顺带同步给 Agent 的纯只读采样配置。
type AgentDesiredPullConfig struct {
	Accepted          bool              `json:"accepted"`
	ServerTimeUnix    int64             `json:"server_time_unix"`
	ReportIntervalSec int               `json:"report_interval_sec"`
	CarrierTargets    map[string]string `json:"carrier_targets"`
}

// ServiceMonitor 定义 UptimeFlare 同款网站/API/TCP 存活与延迟拨测项。
type ServiceMonitor struct {
	ID                string `json:"id"`
	Name              string `json:"name"`
	Kind              string `json:"kind"` // tcp | http | https
	CarrierTag        string `json:"carrier_tag"`
	TargetAddr        string `json:"target_addr"`
	IntervalSec       int    `json:"interval_sec"`
	ExpectedStatusMin int    `json:"expected_status_min"`
	ExpectedStatusMax int    `json:"expected_status_max"`
	PublicVisible     bool   `json:"public_visible"`
	Enabled           bool   `json:"enabled"`
	LastStatus        string `json:"last_status"`
	LastLatencyMs     int32  `json:"last_latency_ms"`
	LastCheckedAt     int64  `json:"last_checked_at"`
}

// IngestAgentReport 校验单向 Agent 令牌与防重放窗口，并对映射长度做有界清洗防内存放大。
func (s *ProbeStore) IngestAgentReport(now time.Time, clientIP, bearerToken string, rep AgentReportPayload) (AgentDesiredPullConfig, error) {
	nowUnix := now.Unix()
	diff := nowUnix - rep.TimestampUnix
	if diff < -MaxClockSkewSeconds || diff > MaxClockSkewSeconds {
		return AgentDesiredPullConfig{}, ErrReplayOrSkewedClock
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	node, exists := s.nodes[rep.NodeID]
	if !exists || node.IsLocal {
		return AgentDesiredPullConfig{}, ErrUnauthorizedAgent
	}
	if !VerifyAgentToken(bearerToken, node.AgentTokenSHA256) {
		return AgentDesiredPullConfig{}, ErrUnauthorizedAgent
	}
	if rep.BootEpoch == node.LastBootEpoch && rep.Sequence <= node.LastReportSeq && node.LastReportSeq > 0 {
		return AgentDesiredPullConfig{}, ErrReplayOrSkewedClock
	}

	// 有界清洗 CarrierPingMs，防止恶意客户端塞入上万键消耗探针内存
	cleanPings := make(map[string]int32, min(5, len(rep.CarrierPingMs)))
	for k, v := range rep.CarrierPingMs {
		if _, ok := allowedCarrierKeys[k]; ok && v >= -1 && v <= 60000 {
			cleanPings[k] = v
		}
	}

	node.LastReportSeq = rep.Sequence
	node.OSName = truncateSafe(rep.OSName, 64)
	node.KernelVersion = truncateSafe(rep.KernelVersion, 64)
	node.Arch = truncateSafe(rep.Arch, 32)
	if rep.VirtType != "" {
		node.VirtType = truncateSafe(rep.VirtType, 24)
	}
	node.CPUModel = truncateSafe(rep.CPUModel, 96)
	if rep.CPUCores > 0 && rep.CPUCores <= 1024 {
		node.CPUCores = rep.CPUCores
	}
	node.MemTotal = rep.MemTotal
	node.SwapTotal = rep.SwapTotal
	node.DiskTotal = rep.DiskTotal
	if clientIP != "" {
		node.PrivateIP = truncateSafe(clientIP, 64)
	}
	node.HasIPv4 = rep.HasIPv4
	node.HasIPv6 = rep.HasIPv6
	node.LastSeenAt = nowUnix
	node.OnlineState = "online"

	AccumulateTraffic(node, now, rep.BootEpoch, rep.RawRxBytes, rep.RawTxBytes)

	s.live[node.ID] = LiveSample{
		SampledAtUnix: nowUnix,
		CPUPercent:    clampPct(rep.CPUPercent),
		MemUsedBytes:  min(rep.MemUsed, rep.MemTotal),
		SwapUsedBytes: min(rep.SwapUsed, rep.SwapTotal),
		DiskUsedBytes: min(rep.DiskUsed, rep.DiskTotal),
		NetRxBps:      rep.NetRxBps,
		NetTxBps:      rep.NetTxBps,
		Load1:         max(0, rep.Load1),
		Load5:         max(0, rep.Load5),
		Load15:        max(0, rep.Load15),
		TCPConns:      rep.TCPConns,
		UDPConns:      rep.UDPConns,
		ProcessCount:  rep.ProcessCount,
		UptimeSeconds: rep.UptimeSeconds,
		CarrierPingMs: cleanPings,
	}

	recordDailyCheckLocked(s.sla90d, node.ID, now.UTC().Format("2006-01-02"), true, pickAvgPing(cleanPings))

	return AgentDesiredPullConfig{
		Accepted:          true,
		ServerTimeUnix:    nowUnix,
		ReportIntervalSec: max(1, node.ReportInterval),
		CarrierTargets:    s.activeCarrierTargetsLocked(),
	}, nil
}

func (s *ProbeStore) activeCarrierTargetsLocked() map[string]string {
	out := make(map[string]string)
	for _, m := range s.monitors {
		if m.Enabled && (m.CarrierTag == "ct" || m.CarrierTag == "cu" || m.CarrierTag == "cm" || m.CarrierTag == "global") {
			out[m.CarrierTag] = m.TargetAddr
		}
	}
	return out
}

func recordDailyCheckLocked(store map[string][]DailySLABucket, id, dayUTC string, up bool, latencyMs int32) {
	buckets := store[id]
	if len(buckets) > 0 && buckets[len(buckets)-1].DayUTC == dayUTC {
		b := &buckets[len(buckets)-1]
		b.TotalChecks++
		if up {
			b.UpChecks++
		} else {
			b.DowntimeSeconds += 2
		}
		if latencyMs > 0 {
			if b.AvgLatencyMs == 0 {
				b.AvgLatencyMs = latencyMs
			} else {
				b.AvgLatencyMs = (b.AvgLatencyMs*7 + latencyMs) / 8
			}
		}
		b.UptimePercent = float64(uint64(b.UpChecks)*10000/uint64(b.TotalChecks)) / 100.0
		return
	}
	upCount := uint32(0)
	pct := 0.0
	if up {
		upCount = 1
		pct = 100.0
	}
	buckets = append(buckets, DailySLABucket{
		DayUTC:        dayUTC,
		TotalChecks:   1,
		UpChecks:      upCount,
		UptimePercent: pct,
		AvgLatencyMs:  max(0, latencyMs),
	})
	if len(buckets) > 90 {
		buckets = buckets[len(buckets)-90:]
	}
	store[id] = buckets
}

// ValidatePublicProbeTarget 执行配置保存期前置防 SSRF 校验；真实拨号仍经 dialVerifiedPublicContext 二次核验。
func ValidatePublicProbeTarget(ctx context.Context, kind, target string, allowPrivateLAN bool) error {
	var host string
	switch kind {
	case "http", "https":
		u, err := url.Parse(target)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil {
			return fmt.Errorf("invalid http(s) monitor target URL")
		}
		host = u.Hostname()
	case "tcp":
		h, port, err := net.SplitHostPort(target)
		if err != nil || h == "" || port == "" {
			return fmt.Errorf("tcp target must be host:port")
		}
		host = strings.Trim(h, "[]")
	default:
		return fmt.Errorf("unsupported monitor kind %q", kind)
	}

	if strings.EqualFold(host, "localhost") {
		return ErrSSRFTargetBlocked
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		if isBlockedProbeIP(ip.Unmap(), allowPrivateLAN) {
			return ErrSSRFTargetBlocked
		}
		return nil
	}

	ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil || len(ips) == 0 {
		return fmt.Errorf("unable to resolve probe target host")
	}
	for _, ip := range ips {
		if isBlockedProbeIP(ip.Unmap(), allowPrivateLAN) {
			return ErrSSRFTargetBlocked
		}
	}
	return nil
}

// dialVerifiedPublicContext 在实际建立 TCP 连接前解析并逐一校验所有候选 IP，直接向已验证的 netip.AddrPort 拨号，彻底免疫 DNS Rebinding。
func dialVerifiedPublicContext(ctx context.Context, network, address string) (net.Conn, error) {
	host, portStr, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	host = strings.Trim(host, "[]")
	if strings.EqualFold(host, "localhost") {
		return nil, ErrSSRFTargetBlocked
	}

	portNum, err := net.LookupPort(network, portStr)
	if err != nil || portNum <= 0 || portNum > 65535 {
		return nil, fmt.Errorf("invalid port %q", portStr)
	}

	var verified []netip.Addr
	if literal, err := netip.ParseAddr(host); err == nil {
		u := literal.Unmap()
		if isBlockedProbeIP(u, false) {
			return nil, ErrSSRFTargetBlocked
		}
		verified = []netip.Addr{u}
	} else {
		resolved, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		if err != nil || len(resolved) == 0 {
			return nil, fmt.Errorf("resolve failed: %w", err)
		}
		for _, ip := range resolved {
			u := ip.Unmap()
			if isBlockedProbeIP(u, false) {
				return nil, ErrSSRFTargetBlocked
			}
			verified = append(verified, u)
		}
	}

	var d net.Dialer
	var lastErr error
	for _, ip := range verified {
		target := netip.AddrPortFrom(ip, uint16(portNum)).String()
		conn, err := d.DialContext(ctx, network, target)
		if err == nil {
			return conn, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

func isBlockedProbeIP(ip netip.Addr, allowPrivateLAN bool) bool {
	if !ip.IsValid() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() {
		return true
	}
	for _, p := range specialBlockedPrefixes {
		if p.Contains(ip) {
			return true
		}
	}
	if !allowPrivateLAN && ip.IsPrivate() {
		return true
	}
	return false
}

// ExecuteServiceCheck 使用防 DNS Rebinding 的池化拨号器执行一次有界超时拨测。
func ExecuteServiceCheck(ctx context.Context, m ServiceMonitor) (status string, latencyMs int32) {
	cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	start := time.Now()
	if m.Kind == "tcp" {
		conn, err := dialVerifiedPublicContext(cctx, "tcp", m.TargetAddr)
		if err != nil {
			return "down", 0
		}
		_ = conn.Close()
		ms := int32(time.Since(start).Milliseconds())
		if ms > 800 {
			return "degraded", ms
		}
		return "up", ms
	}

	if m.Kind != "http" && m.Kind != "https" {
		return "down", 0
	}
	req, err := http.NewRequestWithContext(cctx, http.MethodGet, m.TargetAddr, nil)
	if err != nil {
		return "down", 0
	}
	req.Header.Set("User-Agent", "qwq-server-probe/0.1")
	resp, err := sharedSafeHTTPClient.Do(req)
	if err != nil {
		return "down", 0
	}
	_ = resp.Body.Close()

	ms := int32(time.Since(start).Milliseconds())
	minCode, maxCode := m.ExpectedStatusMin, m.ExpectedStatusMax
	if minCode == 0 {
		minCode = 200
	}
	if maxCode == 0 {
		maxCode = 399
	}
	if resp.StatusCode < minCode || resp.StatusCode > maxCode {
		return "down", ms
	}
	if ms > 1200 {
		return "degraded", ms
	}
	return "up", ms
}

func truncateSafe(s string, maxLen int) string {
	r := []rune(strings.TrimSpace(s))
	if len(r) <= maxLen {
		return string(r)
	}
	return string(r[:maxLen])
}

func clampPct(v float64) float64 {
	if v < 0 {
		return 0
	}
	if v > 100 {
		return 100
	}
	return v
}

func pickAvgPing(m map[string]int32) int32 {
	if len(m) == 0 {
		return 0
	}
	var sum, cnt int32
	for _, v := range m {
		if v > 0 {
			sum += v
			cnt++
		}
	}
	if cnt == 0 {
		return 0
	}
	return sum / cnt
}
