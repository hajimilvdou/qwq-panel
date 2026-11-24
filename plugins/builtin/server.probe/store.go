// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/url"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	_ "modernc.org/sqlite"

	"github.com/qwq-panel/qwq/sdk/pluginsdk/sqlitedb"
)

//go:embed schema.sql
var embeddedSchemaSQL string

var ErrProbeReplay = errors.New("probe: replay or clock skew rejected")

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
	ID                string
	Name              string
	RegionCode        string
	GroupName         string
	Tags              []string
	IsLocal           bool
	SortOrder         int
	PublicHidden      bool
	AgentTokenSHA256  string
	AgentTokenPrefix  string
	LastReportSeq     uint64
	LastSessionEpoch  int64
	LastTimestampNano int64
	ReportInterval    int

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

// BackgroundConfig 保存动态透明水玻璃或自定义主题的壁纸配置、LQIP 占位与 9 宫格焦点参数。
type BackgroundConfig struct {
	Mode        string `json:"mode"`                   // none | local | url
	LocalFile   string `json:"local_file,omitempty"`   // bg.webp | bg.jpg | bg.png
	ExternalURL string `json:"external_url,omitempty"` // 仅允许 https://
	LQIPDataURL string `json:"lqip_data_url,omitempty"`
	FocalX      int    `json:"focal_x"`                // 0..100，默认 50
	FocalY      int    `json:"focal_y"`                // 0..100，默认 50
	Luminance   int    `json:"luminance"`              // 0..255，-1 表示未知
	DominantRGB string `json:"dominant_rgb,omitempty"` // 如 "56,189,248"
}

// AppearanceConfig 保存水玻璃透明度、磨砂模糊度、护眼遮罩、动效与自定义 CSS。
type AppearanceConfig struct {
	GlassOpacity  float64          `json:"glass_opacity"`          // 0.08..0.85
	GlassBlurPx   int              `json:"glass_blur_px"`          // 0..40
	GlassTint     string           `json:"glass_tint"`             // auto | light | dark
	VeilOpacity   float64          `json:"veil_opacity"`           // 0.0..0.75
	MotionEnabled bool             `json:"motion_enabled"`         // 默认 true
	AccentColor   string           `json:"accent_color,omitempty"` // 可选 #rrggbb
	CustomCSS     string           `json:"custom_css,omitempty"`   // 最大 16 KiB
	Background    BackgroundConfig `json:"background"`
}

func DefaultAppearanceConfig() AppearanceConfig {
	return AppearanceConfig{
		GlassOpacity:  0.26,
		GlassBlurPx:   20,
		GlassTint:     "auto",
		VeilOpacity:   0.22,
		MotionEnabled: true,
		Background: BackgroundConfig{
			Mode:      "none",
			FocalX:    50,
			FocalY:    50,
			Luminance: -1,
		},
	}
}

func SanitizeAppearanceConfig(in AppearanceConfig) AppearanceConfig {
	out := in
	if math.IsNaN(out.GlassOpacity) || math.IsInf(out.GlassOpacity, 0) || out.GlassOpacity == 0 {
		out.GlassOpacity = 0.26
	}
	if out.GlassOpacity < 0.08 {
		out.GlassOpacity = 0.08
	}
	if out.GlassOpacity > 0.85 {
		out.GlassOpacity = 0.85
	}
	if out.GlassBlurPx < 0 {
		out.GlassBlurPx = 0
	}
	if out.GlassBlurPx > 40 {
		out.GlassBlurPx = 40
	}
	switch out.GlassTint {
	case "auto", "light", "dark":
	default:
		out.GlassTint = "auto"
	}
	if math.IsNaN(out.VeilOpacity) || math.IsInf(out.VeilOpacity, 0) || out.VeilOpacity < 0 {
		out.VeilOpacity = 0.22
	}
	if out.VeilOpacity > 0.75 {
		out.VeilOpacity = 0.75
	}
	out.AccentColor = sanitizeHexColor(out.AccentColor)
	out.CustomCSS = sanitizeCustomCSS(out.CustomCSS)

	out.Background = SanitizeBackgroundConfig(out.Background)
	return out
}

var closingStyleTagRe = regexp.MustCompile(`(?i)</style`)

func sanitizeCustomCSS(raw string) string {
	const maxBytes = 16384
	s := raw
	if len(s) > maxBytes {
		cut := maxBytes
		for cut > 0 && !utf8.RuneStart(s[cut]) {
			cut--
		}
		s = s[:cut]
	}
	return closingStyleTagRe.ReplaceAllString(s, `<\/style`)
}

func SanitizeBackgroundConfig(in BackgroundConfig) BackgroundConfig {
	out := in
	switch out.Mode {
	case "none", "local", "url":
	default:
		out.Mode = "none"
	}
	switch out.LocalFile {
	case "", "bg.webp", "bg.jpg", "bg.png":
	default:
		out.LocalFile = ""
	}
	out.ExternalURL = strings.TrimSpace(out.ExternalURL)
	if out.ExternalURL != "" {
		if len(out.ExternalURL) > 1024 {
			out.ExternalURL = ""
		} else if u, err := url.Parse(out.ExternalURL); err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil {
			out.ExternalURL = ""
		}
	}
	out.LQIPDataURL = SanitizeRasterLQIP(out.LQIPDataURL)
	if out.FocalX < 0 {
		out.FocalX = 0
	}
	if out.FocalX > 100 {
		out.FocalX = 100
	}
	if out.FocalY < 0 {
		out.FocalY = 0
	}
	if out.FocalY > 100 {
		out.FocalY = 100
	}
	if out.Luminance < -1 || out.Luminance > 255 {
		out.Luminance = -1
	}
	out.DominantRGB = sanitizeRGBTriple(out.DominantRGB)
	if out.Mode == "local" && out.LocalFile == "" {
		out.Mode = "none"
	}
	if out.Mode == "url" && out.ExternalURL == "" {
		out.Mode = "none"
	}
	return out
}

func sanitizeHexColor(s string) string {
	s = strings.TrimSpace(s)
	if len(s) != 7 || s[0] != '#' {
		return ""
	}
	for i := 1; i < 7; i++ {
		c := s[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return ""
		}
	}
	return strings.ToLower(s)
}

func sanitizeRGBTriple(s string) string {
	s = strings.TrimSpace(s)
	if s == "" || len(s) > 20 {
		return ""
	}
	parts := strings.Split(s, ",")
	if len(parts) != 3 {
		return ""
	}
	var vals [3]int
	for i, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" || len(p) > 3 {
			return ""
		}
		v := 0
		for j := 0; j < len(p); j++ {
			if p[j] < '0' || p[j] > '9' {
				return ""
			}
			v = v*10 + int(p[j]-'0')
		}
		if v > 255 {
			return ""
		}
		vals[i] = v
	}
	return fmt.Sprintf("%d,%d,%d", vals[0], vals[1], vals[2])
}

// PortalSettings 保存公开页外观、隐私脱敏、可插拔前台主题与双轨域名绑定配置。
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
	StandaloneAdminVerifier string `json:"-"`
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

	ActiveThemeID string           `json:"active_theme_id"`
	Appearance    AppearanceConfig `json:"appearance"`
	ThemeSettings map[string]any   `json:"theme_settings,omitempty"`

	Revision string `json:"revision"`
}

// ProbeStore 维护节点元数据、实时采样环、reset_epoch 安全流量账本与 90 天 SLA。
type ProbeStore struct {
	mu        sync.RWMutex
	persistMu sync.Mutex
	dataDir   string
	db        *sqlitedb.DualPool
	nodes     map[string]*NodeRecord
	live      map[string]LiveSample
	sla90d    map[string][]DailySLABucket
	monitors  map[string]*ServiceMonitor
	settings  PortalSettings
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
			BuiltinListenAddr:       "127.0.0.1:8443",
			TrustedProxies:          []string{"127.0.0.1/32", "::1/128"},
			ActiveThemeID:           BuiltinThemeClassic,
			Appearance:              DefaultAppearanceConfig(),
			ThemeSettings:           map[string]any{},
			Revision:                "r1",
		},
	}
}

// OpenProbeStore 打开 <stateDir>/probe.db（若 stateDir 为空则回退至纯内存模式，便于单元测试）。
func OpenProbeStore(stateDir string) (*ProbeStore, error) {
	s := NewProbeStore()
	s.dataDir = strings.TrimSpace(stateDir)
	if s.dataDir == "" {
		return s, nil
	}
	pool, err := sqlitedb.OpenDualSQLite("sqlite", filepath.Join(s.dataDir, "probe.db"), 4)
	if err != nil {
		return nil, err
	}
	if _, err := pool.Writer.Exec(embeddedSchemaSQL); err != nil {
		_ = pool.Close()
		return nil, fmt.Errorf("init probe schema: %w", err)
	}
	// 向后兼容已有 probe.db 的幂等列迁移
	for _, stmt := range []string{
		`ALTER TABLE probe_portal_settings ADD COLUMN active_theme_id TEXT NOT NULL DEFAULT 'builtin:classic'`,
		`ALTER TABLE probe_portal_settings ADD COLUMN appearance_json TEXT NOT NULL DEFAULT '{}'`,
		`ALTER TABLE probe_portal_settings ADD COLUMN theme_settings_json TEXT NOT NULL DEFAULT '{}'`,
	} {
		if _, err := pool.Writer.Exec(stmt); err != nil && !strings.Contains(strings.ToLower(err.Error()), "duplicate column") {
			_ = pool.Close()
			return nil, fmt.Errorf("migrate probe schema: %w", err)
		}
	}
	s.db = pool
	if err := s.LoadFromDB(context.Background()); err != nil {
		_ = pool.Close()
		s.db = nil
		return nil, err
	}
	return s, nil
}

// Close 在进程退出前将内存周期流量与当前分钟归档刷盘，再优雅关闭 SQLite 双连接池。
func (s *ProbeStore) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	_ = s.FlushPeriodic(ctx, time.Now())
	cancel()
	return s.db.Close()
}

// LoadFromDB 启动时从 probe.db 加载节点、令牌哈希、当月流量、设置与近 90 天 SLA。
func (s *ProbeStore) LoadFromDB(ctx context.Context) error {
	if s.db == nil {
		return nil
	}
	rows, err := s.db.Reader.QueryContext(ctx, `
		SELECT id, name, region_code, group_name, tags_json, is_local, sort_order, public_hidden,
		       agent_token_sha256, agent_token_prefix, last_report_seq, report_interval_sec,
		       os_name, kernel_version, arch, virt_type, cpu_model, cpu_cores,
		       mem_total_bytes, swap_total_bytes, disk_total_bytes, ipv4_masked_source, has_ipv4, has_ipv6,
		       quota_bytes, quota_mode, reset_day, current_period_key, period_rx_bytes, period_tx_bytes,
		       calibration_bytes, last_boot_epoch, last_raw_rx_bytes, last_raw_tx_bytes,
		       provider_name, billing_price_cents, billing_currency, billing_cycle, expires_at, admin_note,
		       last_seen_at, online_state, revision
		FROM probe_nodes`)
	if err != nil {
		return fmt.Errorf("load probe_nodes: %w", err)
	}
	defer rows.Close()

	loadedNodes := make(map[string]*NodeRecord)
	for rows.Next() {
		var (
			n                              NodeRecord
			tagsJSON, qMode                string
			isLocal, pubHidden, v4, v6     int
			lastSeq, memTot, swapTot       int64
			diskTot, qBytes                int64
			perRx, perTx                   int64
			lastBoot, lastRawRx, lastRawTx int64
		)
		if err := rows.Scan(
			&n.ID, &n.Name, &n.RegionCode, &n.GroupName, &tagsJSON, &isLocal, &n.SortOrder, &pubHidden,
			&n.AgentTokenSHA256, &n.AgentTokenPrefix, &lastSeq, &n.ReportInterval,
			&n.OSName, &n.KernelVersion, &n.Arch, &n.VirtType, &n.CPUModel, &n.CPUCores,
			&memTot, &swapTot, &diskTot, &n.PrivateIP, &v4, &v6,
			&qBytes, &qMode, &n.ResetDay, &n.CurrentPeriodKey, &perRx, &perTx,
			&n.CalibrationBytes, &lastBoot, &lastRawRx, &lastRawTx,
			&n.ProviderName, &n.BillingPriceCents, &n.BillingCurrency, &n.BillingCycle, &n.ExpiresAt, &n.AdminNote,
			&n.LastSeenAt, &n.OnlineState, &n.Revision,
		); err != nil {
			return fmt.Errorf("scan probe_nodes: %w", err)
		}
		_ = json.Unmarshal([]byte(tagsJSON), &n.Tags)
		n.IsLocal = isLocal != 0
		n.PublicHidden = pubHidden != 0
		n.HasIPv4 = v4 != 0
		n.HasIPv6 = v6 != 0
		n.LastReportSeq = uint64(max(0, lastSeq))
		n.MemTotal = uint64(max(0, memTot))
		n.SwapTotal = uint64(max(0, swapTot))
		n.DiskTotal = uint64(max(0, diskTot))
		n.QuotaBytes = uint64(max(0, qBytes))
		n.QuotaMode = QuotaMode(qMode)
		n.PeriodRxBytes = uint64(max(0, perRx))
		n.PeriodTxBytes = uint64(max(0, perTx))
		n.LastBootEpoch = uint64(max(0, lastBoot))
		n.LastRawRxBytes = uint64(max(0, lastRawRx))
		n.LastRawTxBytes = uint64(max(0, lastRawTx))
		cp := n
		loadedNodes[n.ID] = &cp
	}
	if err := rows.Err(); err != nil {
		return err
	}

	// 加载公开设置（若已存在）
	var (
		cfg                                              PortalSettings
		allowTheme, maskIP, expBill, expISP, domEn, cfIP int
		trustedJSON, appJSON, themeSettingsJSON          string
		hasSettings                                      bool
	)
	err = s.db.Reader.QueryRowContext(ctx, `
		SELECT site_title, site_subtitle, default_view, default_palette,
		       allow_visitor_theme_switch, mask_node_ip, expose_billing_cost, expose_isp_carrier,
		       visitor_password_hash, standalone_admin_argon2, status_banner_level, status_banner_text,
		       domain_enabled, custom_domain, binding_track,
		       panel_dns_provider_id, panel_dns_zone_id, panel_cert_binding_ref,
		       builtin_listen_addr, builtin_acme_email, builtin_cert_fingerprint,
		       builtin_cert_expires_at, builtin_encrypted_pem_b64,
		       trust_cloudflare_ips, trusted_proxies_json,
		       active_theme_id, appearance_json, theme_settings_json, revision
		FROM probe_portal_settings WHERE id = 'default'`).Scan(
		&cfg.SiteTitle, &cfg.SiteSubtitle, &cfg.DefaultView, &cfg.DefaultPalette,
		&allowTheme, &maskIP, &expBill, &expISP,
		&cfg.VisitorPasswordSHA256, &cfg.StandaloneAdminVerifier, &cfg.StatusBannerLevel, &cfg.StatusBannerText,
		&domEn, &cfg.CustomDomain, &cfg.BindingTrack,
		&cfg.PanelDNSProviderID, &cfg.PanelDNSZoneID, &cfg.PanelCertBindingRef,
		&cfg.BuiltinListenAddr, &cfg.BuiltinACMEEmail, &cfg.BuiltinCertFP,
		&cfg.BuiltinCertExpiresAt, &cfg.BuiltinSealedBundleB64,
		&cfIP, &trustedJSON,
		&cfg.ActiveThemeID, &appJSON, &themeSettingsJSON, &cfg.Revision,
	)
	if err == nil {
		cfg.AllowVisitorThemeSwitch = allowTheme != 0
		cfg.MaskNodeIP = maskIP != 0
		cfg.ExposeBillingCost = expBill != 0
		cfg.ExposeISPCarrier = expISP != 0
		cfg.DomainEnabled = domEn != 0
		cfg.TrustCloudflareIPs = cfIP != 0
		_ = json.Unmarshal([]byte(trustedJSON), &cfg.TrustedProxies)
		if strings.TrimSpace(cfg.ActiveThemeID) == "" {
			cfg.ActiveThemeID = BuiltinThemeClassic
		}
		cfg.Appearance = DefaultAppearanceConfig()
		if strings.TrimSpace(appJSON) != "" && appJSON != "{}" {
			_ = json.Unmarshal([]byte(appJSON), &cfg.Appearance)
		}
		cfg.Appearance = SanitizeAppearanceConfig(cfg.Appearance)
		cfg.ThemeSettings = map[string]any{}
		if strings.TrimSpace(themeSettingsJSON) != "" {
			_ = json.Unmarshal([]byte(themeSettingsJSON), &cfg.ThemeSettings)
			if cfg.ThemeSettings == nil {
				cfg.ThemeSettings = map[string]any{}
			}
		}
		hasSettings = true
	}

	// 加载近 90 天 SLA 记录
	slaRows, err := s.db.Reader.QueryContext(ctx, `
		SELECT target_id, day_utc, total_checks, up_checks, downtime_seconds, avg_latency_ms, incident_summary
		FROM probe_daily_sla WHERE target_kind = 'node' ORDER BY day_utc ASC`)
	loadedSLA := make(map[string][]DailySLABucket)
	if err == nil {
		defer slaRows.Close()
		for slaRows.Next() {
			var (
				tid, day, inc        string
				tot, up, down, avgMs int64
			)
			if err := slaRows.Scan(&tid, &day, &tot, &up, &down, &avgMs, &inc); err != nil {
				continue
			}
			pct := 100.0
			if tot > 0 {
				pct = float64(up*10000/tot) / 100.0
			}
			b := append(loadedSLA[tid], DailySLABucket{
				DayUTC:          day,
				TotalChecks:     uint32(max(0, tot)),
				UpChecks:        uint32(max(0, up)),
				UptimePercent:   pct,
				DowntimeSeconds: uint32(max(0, down)),
				AvgLatencyMs:    int32(avgMs),
				IncidentSummary: inc,
			})
			if len(b) > 90 {
				b = b[len(b)-90:]
			}
			loadedSLA[tid] = b
		}
	}

	// 加载已配置的服务拨测监控项
	monRows, err := s.db.Reader.QueryContext(ctx, `
		SELECT id, name, kind, carrier_tag, target_addr, interval_sec,
		       expected_status_min, expected_status_max, public_visible, enabled,
		       last_status, last_latency_ms, last_checked_at
		FROM probe_service_monitors`)
	loadedMonitors := make(map[string]*ServiceMonitor)
	if err == nil {
		defer monRows.Close()
		for monRows.Next() {
			var m ServiceMonitor
			var pubVis, en int
			var latMs int64
			if err := monRows.Scan(
				&m.ID, &m.Name, &m.Kind, &m.CarrierTag, &m.TargetAddr, &m.IntervalSec,
				&m.ExpectedStatusMin, &m.ExpectedStatusMax, &pubVis, &en,
				&m.LastStatus, &latMs, &m.LastCheckedAt,
			); err != nil {
				continue
			}
			m.PublicVisible = pubVis != 0
			m.Enabled = en != 0
			m.LastLatencyMs = int32(max(0, latMs))
			cp := m
			loadedMonitors[m.ID] = &cp
		}
	}

	s.mu.Lock()
	for id, n := range loadedNodes {
		s.nodes[id] = n
	}
	for id, b := range loadedSLA {
		s.sla90d[id] = b
	}
	for id, m := range loadedMonitors {
		s.monitors[id] = m
	}
	if hasSettings {
		s.settings = cfg
	}
	s.mu.Unlock()
	return nil
}

// PersistServiceMonitorResult 将后台拨测结果异步/周期回写到 probe_service_monitors 与 probe_daily_sla。
func (s *ProbeStore) PersistServiceMonitorResult(ctx context.Context, m ServiceMonitor, now time.Time) error {
	if s.db == nil || m.ID == "" {
		return nil
	}
	s.persistMu.Lock()
	defer s.persistMu.Unlock()
	_, err := s.db.Writer.ExecContext(ctx, `
		UPDATE probe_service_monitors
		SET last_status = ?, last_latency_ms = ?, last_checked_at = ?
		WHERE id = ?`,
		m.LastStatus, int64(m.LastLatencyMs), m.LastCheckedAt, m.ID,
	)
	if err != nil {
		return err
	}
	dayUTC := now.UTC().Format("2006-01-02")
	upInc := int64(0)
	downSec := int64(max(10, m.IntervalSec))
	if m.LastStatus == "up" || m.LastStatus == "degraded" {
		upInc = 1
		downSec = 0
	}
	_, err = s.db.Writer.ExecContext(ctx, `
		INSERT INTO probe_daily_sla (
			target_kind, target_id, day_utc, total_checks, up_checks, downtime_seconds, avg_latency_ms, incident_summary
		) VALUES ('service', ?, ?, 1, ?, ?, ?, '')
		ON CONFLICT(target_kind, target_id, day_utc) DO UPDATE SET
			total_checks = probe_daily_sla.total_checks + 1,
			up_checks = probe_daily_sla.up_checks + excluded.up_checks,
			downtime_seconds = probe_daily_sla.downtime_seconds + excluded.downtime_seconds,
			avg_latency_ms = CASE
				WHEN excluded.avg_latency_ms > 0 AND probe_daily_sla.avg_latency_ms > 0
					THEN (probe_daily_sla.avg_latency_ms * 7 + excluded.avg_latency_ms) / 8
				WHEN excluded.avg_latency_ms > 0 THEN excluded.avg_latency_ms
				ELSE probe_daily_sla.avg_latency_ms
			END`,
		m.ID, dayUTC, upInc, downSec, int64(max(0, m.LastLatencyMs)),
	)
	return err
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func normalizeNodeForDB(n *NodeRecord) (tagsJSON, qMode, cycle, online, rev string, interval, resetDay int) {
	rawTags, _ := json.Marshal(n.Tags)
	if len(rawTags) == 0 || string(rawTags) == "null" {
		tagsJSON = "[]"
	} else {
		tagsJSON = string(rawTags)
	}
	switch n.QuotaMode {
	case QuotaBoth, QuotaMax, QuotaOutOnly:
		qMode = string(n.QuotaMode)
	default:
		qMode = string(QuotaBoth)
	}
	switch n.BillingCycle {
	case "monthly", "quarterly", "semiannually", "yearly", "triennial", "once":
		cycle = n.BillingCycle
	default:
		cycle = "yearly"
	}
	switch n.OnlineState {
	case "pending", "online", "offline":
		online = n.OnlineState
	default:
		online = "pending"
	}
	rev = n.Revision
	if rev == "" {
		rev = "r1"
	}
	interval = n.ReportInterval
	if interval < 1 || interval > 60 {
		interval = 2
	}
	resetDay = n.ResetDay
	if resetDay < 1 || resetDay > 31 {
		resetDay = 1
	}
	return
}

const upsertNodeSQL = `
INSERT INTO probe_nodes (
	id, name, region_code, group_name, tags_json, is_local, sort_order, public_hidden,
	agent_token_sha256, agent_token_prefix, last_report_seq, report_interval_sec,
	os_name, kernel_version, arch, virt_type, cpu_model, cpu_cores,
	mem_total_bytes, swap_total_bytes, disk_total_bytes, ipv4_masked_source, has_ipv4, has_ipv6,
	quota_bytes, quota_mode, reset_day, current_period_key, period_rx_bytes, period_tx_bytes,
	calibration_bytes, last_boot_epoch, last_raw_rx_bytes, last_raw_tx_bytes,
	provider_name, billing_price_cents, billing_currency, billing_cycle, expires_at, admin_note,
	last_seen_at, online_state, revision, created_at, updated_at
) VALUES (
	?, ?, ?, ?, ?, ?, ?, ?,
	?, ?, ?, ?,
	?, ?, ?, ?, ?, ?,
	?, ?, ?, ?, ?, ?,
	?, ?, ?, ?, ?, ?,
	?, ?, ?, ?,
	?, ?, ?, ?, ?, ?,
	?, ?, ?, ?, ?
) ON CONFLICT(id) DO UPDATE SET
	name=excluded.name,
	region_code=excluded.region_code,
	group_name=excluded.group_name,
	tags_json=excluded.tags_json,
	is_local=excluded.is_local,
	sort_order=excluded.sort_order,
	public_hidden=excluded.public_hidden,
	agent_token_sha256=excluded.agent_token_sha256,
	agent_token_prefix=excluded.agent_token_prefix,
	last_report_seq=excluded.last_report_seq,
	report_interval_sec=excluded.report_interval_sec,
	os_name=excluded.os_name,
	kernel_version=excluded.kernel_version,
	arch=excluded.arch,
	virt_type=excluded.virt_type,
	cpu_model=excluded.cpu_model,
	cpu_cores=excluded.cpu_cores,
	mem_total_bytes=excluded.mem_total_bytes,
	swap_total_bytes=excluded.swap_total_bytes,
	disk_total_bytes=excluded.disk_total_bytes,
	ipv4_masked_source=excluded.ipv4_masked_source,
	has_ipv4=excluded.has_ipv4,
	has_ipv6=excluded.has_ipv6,
	quota_bytes=excluded.quota_bytes,
	quota_mode=excluded.quota_mode,
	reset_day=excluded.reset_day,
	current_period_key=excluded.current_period_key,
	period_rx_bytes=excluded.period_rx_bytes,
	period_tx_bytes=excluded.period_tx_bytes,
	calibration_bytes=excluded.calibration_bytes,
	last_boot_epoch=excluded.last_boot_epoch,
	last_raw_rx_bytes=excluded.last_raw_rx_bytes,
	last_raw_tx_bytes=excluded.last_raw_tx_bytes,
	provider_name=excluded.provider_name,
	billing_price_cents=excluded.billing_price_cents,
	billing_currency=excluded.billing_currency,
	billing_cycle=excluded.billing_cycle,
	expires_at=excluded.expires_at,
	admin_note=excluded.admin_note,
	last_seen_at=excluded.last_seen_at,
	online_state=excluded.online_state,
	revision=excluded.revision,
	updated_at=excluded.updated_at`

func nodeExecArgs(n *NodeRecord, nowUnix int64) []any {
	tagsJSON, qMode, cycle, online, rev, interval, resetDay := normalizeNodeForDB(n)
	region := n.RegionCode
	if region == "" {
		region = "UN"
	}
	group := n.GroupName
	if group == "" {
		group = "默认分组"
	}
	virt := n.VirtType
	if virt == "" {
		virt = "kvm"
	}
	curr := n.BillingCurrency
	if curr == "" {
		curr = "USD"
	}
	cores := n.CPUCores
	if cores <= 0 {
		cores = 1
	}
	return []any{
		n.ID, n.Name, region, group, tagsJSON, boolToInt(n.IsLocal), n.SortOrder, boolToInt(n.PublicHidden),
		n.AgentTokenSHA256, n.AgentTokenPrefix, int64(n.LastReportSeq), interval,
		n.OSName, n.KernelVersion, n.Arch, virt, n.CPUModel, cores,
		int64(n.MemTotal), int64(n.SwapTotal), int64(n.DiskTotal), n.PrivateIP, boolToInt(n.HasIPv4), boolToInt(n.HasIPv6),
		int64(n.QuotaBytes), qMode, resetDay, n.CurrentPeriodKey, int64(n.PeriodRxBytes), int64(n.PeriodTxBytes),
		n.CalibrationBytes, int64(n.LastBootEpoch), int64(n.LastRawRxBytes), int64(n.LastRawTxBytes),
		n.ProviderName, n.BillingPriceCents, curr, cycle, n.ExpiresAt, n.AdminNote,
		n.LastSeenAt, online, rev, nowUnix, nowUnix,
	}
}

// PersistNode 立即将单个节点的增删改写盘（节点 CRUD 零延迟落盘）。
func (s *ProbeStore) PersistNode(ctx context.Context, n *NodeRecord) error {
	if s.db == nil || n == nil {
		return nil
	}
	s.persistMu.Lock()
	defer s.persistMu.Unlock()
	_, err := s.db.Writer.ExecContext(ctx, upsertNodeSQL, nodeExecArgs(n, time.Now().Unix())...)
	return err
}

// DeleteNode 立即从 SQLite 删除节点记录及关联 SLA（串行化防 FlushPeriodic 僵尸复活）。
func (s *ProbeStore) DeleteNode(ctx context.Context, id string) error {
	if s.db == nil || id == "" {
		return nil
	}
	s.persistMu.Lock()
	defer s.persistMu.Unlock()
	tx, err := s.db.Writer.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `DELETE FROM probe_nodes WHERE id = ?`, id); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM probe_daily_sla WHERE target_kind = 'node' AND target_id = ?`, id); err != nil {
		return err
	}
	return tx.Commit()
}

// PersistSettings 立即持久化探针公开页外观、隐私脱敏、独立管理口令校验串与双轨域名绑定配置。
func (s *ProbeStore) PersistSettings(ctx context.Context, cfg PortalSettings) error {
	if s.db == nil {
		return nil
	}
	s.persistMu.Lock()
	defer s.persistMu.Unlock()
	view := cfg.DefaultView
	switch view {
	case "orb-cards", "compact-list", "tty-terminal":
	default:
		view = "orb-cards"
	}
	banner := cfg.StatusBannerLevel
	switch banner {
	case "ok", "maintenance", "degraded":
	default:
		banner = "ok"
	}
	track := cfg.BindingTrack
	switch track {
	case "auto", "panel_dnc", "builtin_acme", "builtin_pem", "reverse_proxy":
	default:
		track = "auto"
	}
	trustedRaw, _ := json.Marshal(cfg.TrustedProxies)
	if len(trustedRaw) == 0 || string(trustedRaw) == "null" {
		trustedRaw = []byte(`["127.0.0.1/32","::1/128"]`)
	}
	rev := cfg.Revision
	if rev == "" {
		rev = "r1"
	}
	activeTheme := strings.TrimSpace(cfg.ActiveThemeID)
	if activeTheme == "" {
		activeTheme = BuiltinThemeClassic
	}
	cleanApp := SanitizeAppearanceConfig(cfg.Appearance)
	appRaw, _ := json.Marshal(cleanApp)
	if len(appRaw) == 0 {
		appRaw = []byte("{}")
	}
	themeSettings := cfg.ThemeSettings
	if themeSettings == nil {
		themeSettings = map[string]any{}
	}
	tsRaw, _ := json.Marshal(themeSettings)
	if len(tsRaw) == 0 || string(tsRaw) == "null" {
		tsRaw = []byte("{}")
	}
	_, err := s.db.Writer.ExecContext(ctx, `
		INSERT INTO probe_portal_settings (
			id, site_title, site_subtitle, default_view, default_palette,
			allow_visitor_theme_switch, mask_node_ip, expose_billing_cost, expose_isp_carrier,
			visitor_password_hash, standalone_admin_argon2, status_banner_level, status_banner_text,
			domain_enabled, custom_domain, binding_track,
			panel_dns_provider_id, panel_dns_zone_id, panel_cert_binding_ref,
			builtin_listen_addr, builtin_acme_email, builtin_cert_fingerprint,
			builtin_cert_expires_at, builtin_encrypted_pem_b64,
			trust_cloudflare_ips, trusted_proxies_json,
			active_theme_id, appearance_json, theme_settings_json, revision, updated_at
		) VALUES (
			'default', ?, ?, ?, ?,
			?, ?, ?, ?,
			?, ?, ?, ?,
			?, ?, ?,
			?, ?, ?,
			?, ?, ?,
			?, ?,
			?, ?,
			?, ?, ?, ?, ?
		) ON CONFLICT(id) DO UPDATE SET
			site_title=excluded.site_title,
			site_subtitle=excluded.site_subtitle,
			default_view=excluded.default_view,
			default_palette=excluded.default_palette,
			allow_visitor_theme_switch=excluded.allow_visitor_theme_switch,
			mask_node_ip=excluded.mask_node_ip,
			expose_billing_cost=excluded.expose_billing_cost,
			expose_isp_carrier=excluded.expose_isp_carrier,
			visitor_password_hash=excluded.visitor_password_hash,
			standalone_admin_argon2=excluded.standalone_admin_argon2,
			status_banner_level=excluded.status_banner_level,
			status_banner_text=excluded.status_banner_text,
			domain_enabled=excluded.domain_enabled,
			custom_domain=excluded.custom_domain,
			binding_track=excluded.binding_track,
			panel_dns_provider_id=excluded.panel_dns_provider_id,
			panel_dns_zone_id=excluded.panel_dns_zone_id,
			panel_cert_binding_ref=excluded.panel_cert_binding_ref,
			builtin_listen_addr=excluded.builtin_listen_addr,
			builtin_acme_email=excluded.builtin_acme_email,
			builtin_cert_fingerprint=excluded.builtin_cert_fingerprint,
			builtin_cert_expires_at=excluded.builtin_cert_expires_at,
			builtin_encrypted_pem_b64=excluded.builtin_encrypted_pem_b64,
			trust_cloudflare_ips=excluded.trust_cloudflare_ips,
			trusted_proxies_json=excluded.trusted_proxies_json,
			active_theme_id=excluded.active_theme_id,
			appearance_json=excluded.appearance_json,
			theme_settings_json=excluded.theme_settings_json,
			revision=excluded.revision,
			updated_at=excluded.updated_at`,
		cfg.SiteTitle, cfg.SiteSubtitle, view, cfg.DefaultPalette,
		boolToInt(cfg.AllowVisitorThemeSwitch), boolToInt(cfg.MaskNodeIP), boolToInt(cfg.ExposeBillingCost), boolToInt(cfg.ExposeISPCarrier),
		cfg.VisitorPasswordSHA256, cfg.StandaloneAdminVerifier, banner, cfg.StatusBannerText,
		boolToInt(cfg.DomainEnabled), cfg.CustomDomain, track,
		cfg.PanelDNSProviderID, cfg.PanelDNSZoneID, cfg.PanelCertBindingRef,
		cfg.BuiltinListenAddr, cfg.BuiltinACMEEmail, cfg.BuiltinCertFP,
		cfg.BuiltinCertExpiresAt, cfg.BuiltinSealedBundleB64,
		boolToInt(cfg.TrustCloudflareIPs), string(trustedRaw),
		activeTheme, string(appRaw), string(tsRaw), rev, time.Now().Unix(),
	)
	return err
}

// FlushPeriodic 每 60 秒或优雅停机时在单事务内批量归档当月流量、分钟级指标与日度 SLA，避免秒级高频写放大。
func (s *ProbeStore) FlushPeriodic(ctx context.Context, now time.Time) error {
	if s.db == nil {
		return nil
	}
	s.persistMu.Lock()
	defer s.persistMu.Unlock()
	s.mu.RLock()
	nodes := make([]NodeRecord, 0, len(s.nodes))
	for _, n := range s.nodes {
		cp := *n
		cp.Tags = slices.Clone(n.Tags)
		nodes = append(nodes, cp)
	}
	lives := make(map[string]LiveSample, len(s.live))
	for id, lv := range s.live {
		lives[id] = lv
	}
	latestSLA := make(map[string]DailySLABucket, len(s.sla90d))
	for id, buckets := range s.sla90d {
		if len(buckets) > 0 {
			latestSLA[id] = buckets[len(buckets)-1]
		}
	}
	s.mu.RUnlock()

	tx, err := s.db.Writer.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	nowUnix := now.Unix()
	bucketMin := (nowUnix / 60) * 60

	for i := range nodes {
		n := &nodes[i]
		if _, err := tx.ExecContext(ctx, upsertNodeSQL, nodeExecArgs(n, nowUnix)...); err != nil {
			return err
		}
		if lv, ok := lives[n.ID]; ok && lv.SampledAtUnix > 0 {
			var memPct, diskPct int64
			if n.MemTotal > 0 {
				memPct = int64(float64(lv.MemUsedBytes) * 10000.0 / float64(n.MemTotal))
			}
			if n.DiskTotal > 0 {
				diskPct = int64(float64(lv.DiskUsedBytes) * 10000.0 / float64(n.DiskTotal))
			}
			pingCT, pingCU, pingCM := int64(-1), int64(-1), int64(-1)
			if v, ok := lv.CarrierPingMs["ct"]; ok {
				pingCT = int64(v)
			}
			if v, ok := lv.CarrierPingMs["cu"]; ok {
				pingCU = int64(v)
			}
			if v, ok := lv.CarrierPingMs["cm"]; ok {
				pingCM = int64(v)
			}
			if _, err := tx.ExecContext(ctx, `
				INSERT INTO probe_metric_rollups (
					node_id, bucket_minute_unix, cpu_pct_x100, mem_pct_x100, disk_pct_x100,
					load1_x100, net_rx_bps, net_tx_bps, tcp_conns, ping_ct_ms, ping_cu_ms, ping_cm_ms
				) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
				ON CONFLICT(node_id, bucket_minute_unix) DO UPDATE SET
					cpu_pct_x100=excluded.cpu_pct_x100,
					mem_pct_x100=excluded.mem_pct_x100,
					disk_pct_x100=excluded.disk_pct_x100,
					load1_x100=excluded.load1_x100,
					net_rx_bps=excluded.net_rx_bps,
					net_tx_bps=excluded.net_tx_bps,
					tcp_conns=excluded.tcp_conns,
					ping_ct_ms=excluded.ping_ct_ms,
					ping_cu_ms=excluded.ping_cu_ms,
					ping_cm_ms=excluded.ping_cm_ms`,
				n.ID, bucketMin, int64(lv.CPUPercent*100), memPct, diskPct,
				int64(lv.Load1*100), int64(lv.NetRxBps), int64(lv.NetTxBps), int64(lv.TCPConns),
				pingCT, pingCU, pingCM,
			); err != nil {
				return err
			}
		}
		if b, ok := latestSLA[n.ID]; ok && b.DayUTC != "" {
			if _, err := tx.ExecContext(ctx, `
				INSERT INTO probe_daily_sla (
					target_kind, target_id, day_utc, total_checks, up_checks, downtime_seconds, avg_latency_ms, incident_summary
				) VALUES ('node', ?, ?, ?, ?, ?, ?, ?)
				ON CONFLICT(target_kind, target_id, day_utc) DO UPDATE SET
					total_checks=excluded.total_checks,
					up_checks=excluded.up_checks,
					downtime_seconds=excluded.downtime_seconds,
					avg_latency_ms=excluded.avg_latency_ms,
					incident_summary=excluded.incident_summary`,
				n.ID, b.DayUTC, int64(b.TotalChecks), int64(b.UpChecks), int64(b.DowntimeSeconds), int64(b.AvgLatencyMs), b.IncidentSummary,
			); err != nil {
				return err
			}
		}
	}

	// 裁剪超过 30 天的历史分钟级归档与超过 90 天的日度 SLA 归档
	cutoff := nowUnix - 30*86400
	_, _ = tx.ExecContext(ctx, `DELETE FROM probe_metric_rollups WHERE bucket_minute_unix < ?`, cutoff)
	cutoffDay := now.UTC().AddDate(0, 0, -90).Format("2006-01-02")
	_, _ = tx.ExecContext(ctx, `DELETE FROM probe_daily_sla WHERE day_utc < ?`, cutoffDay)

	return tx.Commit()
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

// VerifyProbeReportSequence 解耦操作系统开机纪元 BootEpoch 与探针进程会话纪元 SessionEpoch / 单调纳秒时间戳，
// 根治 systemctl restart qwq-probe-agent 后因 BootEpoch 不变、Sequence 归 1 导致节点被连续拒收数天的 Bug（BUG-S04）。
func VerifyProbeReportSequence(
	nowUnixNano int64,
	repTimestampNano int64,
	repSessionEpoch int64,
	repSeq uint64,
	lastTimestampNano int64,
	lastSessionEpoch int64,
	lastSeq uint64,
) error {
	const maxSkewNano = int64(MaxClockSkewSeconds) * int64(time.Second)
	if repSeq == 0 {
		return ErrProbeReplay
	}
	diff := nowUnixNano - repTimestampNano
	if diff < -maxSkewNano || diff > maxSkewNano {
		return ErrProbeReplay
	}
	if repSessionEpoch != 0 && repSessionEpoch == lastSessionEpoch {
		if repSeq <= lastSeq {
			return ErrProbeReplay
		}
		return nil
	}
	// Agent 进程重启生成了新 SessionEpoch（或旧版未传 SessionEpoch）：要求纳秒时间戳严格单调前进
	if repTimestampNano <= lastTimestampNano {
		return ErrProbeReplay
	}
	return nil
}

// SafeAccumulateNodeTraffic 安全累加节点周期流量：
// - 真机内核重启（bootEpoch 改变）：将开机后的新计数计入周期增量并更新基线；
// - 未重启但某方向计数回退（如容器 veth 销毁或 32 位网卡回绕）：仅重定回退侧基线，绝不把未回退侧的历史存量重复加一遍（BUG-S02）。
func SafeAccumulateNodeTraffic(
	bootEpoch int64, rawRx, rawTx uint64,
	lastBootEpoch *int64, lastRawRx, lastRawTx, periodRx, periodTx *uint64,
) {
	if *lastBootEpoch == 0 {
		*lastBootEpoch = bootEpoch
		*lastRawRx = rawRx
		*lastRawTx = rawTx
		return
	}
	if bootEpoch != *lastBootEpoch {
		*lastBootEpoch = bootEpoch
		*periodRx += rawRx
		*periodTx += rawTx
		*lastRawRx = rawRx
		*lastRawTx = rawTx
		return
	}
	if rawRx >= *lastRawRx {
		*periodRx += rawRx - *lastRawRx
	}
	if rawTx >= *lastRawTx {
		*periodTx += rawTx - *lastRawTx
	}
	*lastRawRx = rawRx
	*lastRawTx = rawTx
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

	lastBoot := int64(n.LastBootEpoch)
	SafeAccumulateNodeTraffic(
		int64(bootEpoch), rawRx, rawTx,
		&lastBoot, &n.LastRawRxBytes, &n.LastRawTxBytes,
		&n.PeriodRxBytes, &n.PeriodTxBytes,
	)
	n.LastBootEpoch = uint64(max(0, lastBoot))
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
