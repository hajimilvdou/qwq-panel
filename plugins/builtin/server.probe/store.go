// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"
)

// QuotaMode 定义月流量计费口径（对齐搬瓦工/DMIT/AWS 等不同 VPS 真实计费方式）。
type QuotaMode string

const (
	QuotaBoth    QuotaMode = "both"     // 双向合计：rx + tx
	QuotaMax     QuotaMode = "max"      // 单向取大：max(rx, tx)
	QuotaOutOnly QuotaMode = "out_only" // 仅计出站：tx
)

// LiveSample 保存节点在内存中的秒级实时跳动指标（零 SQLite 高频写放大）。
type LiveSample struct {
	SampledAtUnix int64            `json:"sampled_at"`
	CPUPercent    float64          `json:"cpu_pct"`
	MemUsedBytes  uint64           `json:"mem_used_bytes"`
	SwapUsedBytes uint64           `json:"swap_used_bytes"`
	DiskUsedBytes uint64           `json:"disk_used_bytes"`
	NetRxBps      uint64           `json:"net_rx_bps"`
	NetTxBps      uint64           `json:"net_tx_bps"`
	Load1         float64          `json:"load1"`
	Load5         float64          `json:"load5"`
	Load15        float64          `json:"load15"`
	TCPConns      uint32           `json:"tcp_conns"`
	UDPConns      uint32           `json:"udp_conns"`
	ProcessCount  uint32           `json:"process_count"`
	UptimeSeconds uint64           `json:"uptime_seconds"`
	CarrierPingMs map[string]int32 `json:"carrier_ping_ms"` // ct / cu / cm / global
}

// NodeRecord 是插件内部完整节点模型（含敏感字段，绝不直接序列化给外部访客！）。
type NodeRecord struct {
	ID               string
	Name             string
	RegionCode       string
	GroupName        string
	Tags             []string
	IsLocal          bool
	SortOrder        int
	PublicHidden     bool
	AgentTokenSHA256 string
	AgentTokenPrefix string
	LastReportSeq    uint64
	ReportInterval   int

	OSName        string
	KernelVersion string
	Arch          string
	VirtType      string
	CPUModel      string
	CPUCores      int
	MemTotal      uint64
	SwapTotal     uint64
	DiskTotal     uint64
	PrivateIP     string // 仅管理员后台可见，访客 DTO 物理不存在该字段
	HasIPv4       bool
	HasIPv6       bool

	QuotaBytes       uint64
	QuotaMode        QuotaMode
	ResetDay         int
	CurrentPeriodKey string
	PeriodRxBytes    uint64
	PeriodTxBytes    uint64
	CalibrationBytes int64
	LastBootEpoch    uint64
	LastRawRxBytes   uint64
	LastRawTxBytes   uint64

	ProviderName      string
	BillingPriceCents int64
	BillingCurrency   string
	BillingCycle      string
	ExpiresAt         int64
	AdminNote         string // 仅管理员后台可见

	LastSeenAt  int64
	OnlineState string
	Revision    string
}

// DailySLABucket 表示 UptimeFlare 同款 90 天在线率中的单日状态格。
type DailySLABucket struct {
	DayUTC          string  `json:"day"`
	TotalChecks     uint32  `json:"total_checks"`
	UpChecks        uint32  `json:"up_checks"`
	UptimePercent   float64 `json:"uptime_pct"`
	DowntimeSeconds uint32  `json:"downtime_sec"`
	AvgLatencyMs    int32   `json:"avg_latency_ms"`
	IncidentSummary string  `json:"incident,omitempty"`
}

// PublicNodeDTO 是面向外部访客与公开探针页的白名单结构体：
// 物理移除真实 IP、Token 哈希、管理员备注，并按隐私开关脱敏续费价格与商家名称。
type PublicNodeDTO struct {
	ID              string           `json:"id"`
	Name            string           `json:"name"`
	RegionCode      string           `json:"region_code"`
	GroupName       string           `json:"group_name"`
	Tags            []string         `json:"tags"`
	IsLocal         bool             `json:"is_local"`
	Online          bool             `json:"online"`
	OSName          string           `json:"os_name"`
	Arch            string           `json:"arch"`
	VirtType        string           `json:"virt_type"`
	CPUCores        int              `json:"cpu_cores"`
	MemTotalBytes   uint64           `json:"mem_total_bytes"`
	SwapTotalBytes  uint64           `json:"swap_total_bytes"`
	DiskTotalBytes  uint64           `json:"disk_total_bytes"`
	MaskedIPDisplay string           `json:"masked_ip,omitempty"`
	HasIPv4         bool             `json:"has_ipv4"`
	HasIPv6         bool             `json:"has_ipv6"`
	QuotaBytes      uint64           `json:"quota_bytes"`
	QuotaUsedBytes  uint64           `json:"quota_used_bytes"`
	QuotaMode       QuotaMode        `json:"quota_mode"`
	ResetDay        int              `json:"reset_day"`
	ProviderName    string           `json:"provider_name,omitempty"`
	BillingBadge    string           `json:"billing_badge,omitempty"`
	ExpiresInDays   *int             `json:"expires_in_days,omitempty"`
	Uptime90dPct    float64          `json:"uptime_90d_pct"`
	SLARibbon       []DailySLABucket `json:"sla_ribbon"`
	Live            LiveSample       `json:"live"`
}

// PortalSettings 保存公开页外观、隐私脱敏与双轨域名绑定配置。
type PortalSettings struct {
	SiteTitle               string `json:"site_title"`
	SiteSubtitle            string `json:"site_subtitle"`
	DefaultView             string `json:"default_view"` // orb-cards | compact-list | tty-terminal
	DefaultPalette          string `json:"default_palette"`
	AllowVisitorThemeSwitch bool   `json:"allow_visitor_theme_switch"`
	MaskNodeIP              bool   `json:"mask_node_ip"`
	ExposeBillingCost       bool   `json:"expose_billing_cost"`
	ExposeISPCarrier        bool   `json:"expose_isp_carrier"`
	VisitorPasswordSHA256   string `json:"-"`
	StatusBannerLevel       string `json:"status_banner_level"`
	StatusBannerText        string `json:"status_banner_text"`

	DomainEnabled          bool     `json:"domain_enabled"`
	CustomDomain           string   `json:"custom_domain"`
	BindingTrack           string   `json:"binding_track"` // auto | panel_dnc | builtin_acme | builtin_pem | reverse_proxy
	PanelDNSProviderID     string   `json:"panel_dns_provider_id"`
	PanelDNSZoneID         string   `json:"panel_dns_zone_id"`
	PanelCertBindingRef    string   `json:"panel_cert_binding_ref"`
	BuiltinListenAddr      string   `json:"builtin_listen_addr"`
	BuiltinACMEEmail       string   `json:"builtin_acme_email"`
	BuiltinCertFP          string   `json:"builtin_cert_fingerprint"`
	BuiltinCertExpiresAt   int64    `json:"builtin_cert_expires_at"`
	BuiltinSealedBundleB64 string   `json:"-"` // AES-256-GCM 密封的 PEM 载荷，JSON 序列化物理不可见
	TrustCloudflareIPs     bool     `json:"trust_cloudflare_ips"`
	TrustedProxies         []string `json:"trusted_proxies"`
	Revision               string   `json:"revision"`
}

// ProbeStore 维护节点元数据、实时采样环、reset_epoch 安全流量账本与 90 天 SLA。
type ProbeStore struct {
	mu       sync.RWMutex
	nodes    map[string]*NodeRecord
	live     map[string]LiveSample
	sla90d   map[string][]DailySLABucket
	monitors map[string]*ServiceMonitor
	settings PortalSettings
}

func NewProbeStore() *ProbeStore {
	return &ProbeStore{
		nodes:    make(map[string]*NodeRecord),
		live:     make(map[string]LiveSample),
		sla90d:   make(map[string][]DailySLABucket),
		monitors: make(map[string]*ServiceMonitor),
		settings: PortalSettings{
			SiteTitle:               "qwq Probe · 全球服务器实时探针",
			SiteSubtitle:            "单向零入站安全遥测 · 90 天 SLA 在线率与三网延迟实时大盘",
			DefaultView:             "orb-cards",
			DefaultPalette:          "oat-berry",
			AllowVisitorThemeSwitch: true,
			MaskNodeIP:              true,
			ExposeBillingCost:       true,
			ExposeISPCarrier:        true,
			StatusBannerLevel:       "ok",
			StatusBannerText:        "所有监控节点与拨测链路运行正常",
			BindingTrack:            "auto",
			BuiltinListenAddr:       "127.0.0.1:19080",
			TrustedProxies:          []string{"127.0.0.1/32", "::1/128"},
			Revision:                "r1",
		},
	}
}

// GenerateAgentToken 签发高熵单向节点上报令牌（明文仅在创建/轮换时返回一次）。
func GenerateAgentToken() (plainToken, sha256Hex, prefix string, err error) {
	buf := make([]byte, 24)
	if _, err := rand.Read(buf); err != nil {
		return "", "", "", err
	}
	plain := "prb_agt_" + base64.RawURLEncoding.EncodeToString(buf)
	sum := sha256.Sum256([]byte(plain))
	return plain, hex.EncodeToString(sum[:]), plain[:14] + "...", nil
}

// VerifyAgentToken 使用常数时间比较校验节点上报 Bearer 令牌。
func VerifyAgentToken(candidatePlain, expectedSHA256Hex string) bool {
	if !strings.HasPrefix(candidatePlain, "prb_agt_") || len(expectedSHA256Hex) != 64 {
		return false
	}
	sum := sha256.Sum256([]byte(candidatePlain))
	gotHex := hex.EncodeToString(sum[:])
	return subtle.ConstantTimeCompare([]byte(gotHex), []byte(expectedSHA256Hex)) == 1
}

// BillingPeriodKey 根据自定义账单重置日（1..31）计算当前所属计费周期键（如 "2026-11-cycle"）。
func BillingPeriodKey(now time.Time, resetDay int) string {
	u := now.UTC()
	if resetDay < 1 {
		resetDay = 1
	}
	if resetDay > 31 {
		resetDay = 31
	}
	year, month, day := u.Date()
	if day < resetDay {
		prev := time.Date(year, month, 1, 0, 0, 0, 0, time.UTC).AddDate(0, -1, 0)
		return fmt.Sprintf("%04d-%02d-r%02d", prev.Year(), int(prev.Month()), resetDay)
	}
	return fmt.Sprintf("%04d-%02d-r%02d", year, int(month), resetDay)
}

// AccumulateTraffic 执行防重启归零回退（boot_epoch 感知）与跨月自动清零的增量流量记账。
func AccumulateTraffic(n *NodeRecord, now time.Time, bootEpoch, rawRx, rawTx uint64) {
	periodKey := BillingPeriodKey(now, n.ResetDay)
	if n.CurrentPeriodKey == "" {
		n.CurrentPeriodKey = periodKey
		n.LastBootEpoch = bootEpoch
		n.LastRawRxBytes = rawRx
		n.LastRawTxBytes = rawTx
		return
	}
	if n.CurrentPeriodKey != periodKey {
		// 到达新计费账期：清零当期上下行并平滑续接网卡原始计数基准
		n.CurrentPeriodKey = periodKey
		n.PeriodRxBytes = 0
		n.PeriodTxBytes = 0
		n.CalibrationBytes = 0
		n.LastBootEpoch = bootEpoch
		n.LastRawRxBytes = rawRx
		n.LastRawTxBytes = rawTx
		return
	}

	// 检测被控服务器重启或网卡计数器回绕：只重定基准线，绝不扣减已累计当月流量！
	if bootEpoch != n.LastBootEpoch || rawRx < n.LastRawRxBytes || rawTx < n.LastRawTxBytes {
		n.LastBootEpoch = bootEpoch
		n.LastRawRxBytes = rawRx
		n.LastRawTxBytes = rawTx
		n.PeriodRxBytes += rawRx
		n.PeriodTxBytes += rawTx
		return
	}

	n.PeriodRxBytes += rawRx - n.LastRawRxBytes
	n.PeriodTxBytes += rawTx - n.LastRawTxBytes
	n.LastRawRxBytes = rawRx
	n.LastRawTxBytes = rawTx
}

// ComputeQuotaUsed 按节点计费模式（双向/取大/单出站）+ 人工校准值计算有效已用流量。
func ComputeQuotaUsed(n *NodeRecord) uint64 {
	var base uint64
	switch n.QuotaMode {
	case QuotaMax:
		base = max(n.PeriodRxBytes, n.PeriodTxBytes)
	case QuotaOutOnly:
		base = n.PeriodTxBytes
	default:
		base = n.PeriodRxBytes + n.PeriodTxBytes
	}
	if n.CalibrationBytes >= 0 {
		return base + uint64(n.CalibrationBytes)
	}
	neg := uint64(-n.CalibrationBytes)
	if neg >= base {
		return 0
	}
	return base - neg
}

// MaskIPAddress 对外脱敏服务器地址（开启完全脱敏时不返回任何真实段）。
func MaskIPAddress(ip string, strictMask bool) string {
	if ip == "" || strictMask {
		return ""
	}
	if strings.Contains(ip, ":") {
		parts := strings.Split(ip, ":")
		if len(parts) >= 2 {
			return parts[0] + ":" + parts[1] + ":*:* (IPv6)"
		}
		return "*:* (IPv6)"
	}
	octets := strings.Split(ip, ".")
	if len(octets) == 4 {
		return octets[0] + "." + octets[1] + ".*.*"
	}
	return "*.*.*.*"
}

// BuildPublicNodes 生成物理脱敏后的对外展示节点切片（按 sort_order 稳定排序）。
func (s *ProbeStore) BuildPublicNodes(now time.Time) []PublicNodeDTO {
	s.mu.RLock()
	defer s.mu.RUnlock()

	cfg := s.settings
	list := make([]*NodeRecord, 0, len(s.nodes))
	for _, n := range s.nodes {
		if !n.PublicHidden {
			list = append(list, n)
		}
	}
	slices.SortFunc(list, func(a, b *NodeRecord) int {
		if a.SortOrder != b.SortOrder {
			return a.SortOrder - b.SortOrder
		}
		return strings.Compare(a.ID, b.ID)
	})

	out := make([]PublicNodeDTO, 0, len(list))
	nowUnix := now.Unix()
	for _, n := range list {
		grace := int64(max(10, n.ReportInterval*4))
		online := n.LastSeenAt > 0 && (nowUnix-n.LastSeenAt) <= grace
		ribbon := slices.Clone(s.sla90d[n.ID])
		uptimePct := computeOverallUptime(ribbon)

		dto := PublicNodeDTO{
			ID:              n.ID,
			Name:            n.Name,
			RegionCode:      n.RegionCode,
			GroupName:       n.GroupName,
			Tags:            slices.Clone(n.Tags),
			IsLocal:         n.IsLocal,
			Online:          online,
			OSName:          n.OSName,
			Arch:            n.Arch,
			VirtType:        n.VirtType,
			CPUCores:        n.CPUCores,
			MemTotalBytes:   n.MemTotal,
			SwapTotalBytes:  n.SwapTotal,
			DiskTotalBytes:  n.DiskTotal,
			MaskedIPDisplay: MaskIPAddress(n.PrivateIP, cfg.MaskNodeIP),
			HasIPv4:         n.HasIPv4,
			HasIPv6:         n.HasIPv6,
			QuotaBytes:      n.QuotaBytes,
			QuotaUsedBytes:  ComputeQuotaUsed(n),
			QuotaMode:       n.QuotaMode,
			ResetDay:        n.ResetDay,
			Uptime90dPct:    uptimePct,
			SLARibbon:       ribbon,
			Live:            s.live[n.ID],
		}
		if cfg.ExposeISPCarrier {
			dto.ProviderName = n.ProviderName
		}
		if cfg.ExposeBillingCost && n.BillingPriceCents > 0 {
			dto.BillingBadge = formatBillingBadge(n.BillingPriceCents, n.BillingCurrency, n.BillingCycle)
		}
		if n.ExpiresAt > 0 {
			days := int((n.ExpiresAt - nowUnix) / 86400)
			dto.ExpiresInDays = &days
		}
		out = append(out, dto)
	}
	return out
}

func computeOverallUptime(buckets []DailySLABucket) float64 {
	if len(buckets) == 0 {
		return 100.0
	}
	var total, up uint64
	for _, b := range buckets {
		total += uint64(b.TotalChecks)
		up += uint64(b.UpChecks)
	}
	if total == 0 {
		return 100.0
	}
	return float64(up*10000/total) / 100.0
}

func formatBillingBadge(cents int64, currency, cycle string) string {
	sym := "$"
	switch strings.ToUpper(currency) {
	case "CNY", "RMB":
		sym = "¥"
	case "EUR":
		sym = "€"
	case "HKD":
		sym = "HK$"
	}
	unit := "/年"
	switch cycle {
	case "monthly":
		unit = "/月"
	case "quarterly":
		unit = "/季"
	case "semiannually":
		unit = "/半年"
	case "triennial":
		unit = "/三年"
	case "once":
		unit = "买断"
	}
	return fmt.Sprintf("%s%.2f%s", sym, float64(cents)/100.0, unit)
}
