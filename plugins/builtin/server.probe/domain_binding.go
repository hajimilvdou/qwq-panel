// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"time"
)

// TrackMode 定义双轨域名绑定策略。
const (
	TrackAuto         = "auto"          // 自动探测：已装面板 DNC 优先借用，否则走探针内置独立闭环
	TrackPanelDNC     = "panel_dnc"     // 轨道 A：联动借用面板 domain.dns + tls.certificates (certbind_*)
	TrackBuiltinACME  = "builtin_acme"  // 轨道 B1：探针内置 ACME (Let's Encrypt HTTP-01 / TLS-ALPN-01)
	TrackBuiltinPEM   = "builtin_pem"   // 轨道 B2：探针直接导入 PEM 证书链 / Cloudflare 15 年源站证书
	TrackReverseProxy = "reverse_proxy" // 轨道 B3：反向代理 / 宝塔共存 / Caddy / Cloudflare Tunnel 免端口 Host 绑定
)

// CloudflarePublishedRanges 为 Cloudflare 官方回源 IPv4/IPv6 网段（供开启橙云 CDN 反代时精确提取真实访客 IP）。
var CloudflarePublishedRanges = []string{
	"173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
	"141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
	"197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
	"104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
	"2400:cb00::/32", "2606:4700::/32", "2803:f800::/32", "2405:b500::/32",
	"2405:8100::/32", "2a06:98c0::/29", "2c0f:f248::/32",
}

// HostDNCCapabilities 描述当前运行环境是否安装了面板域名与证书相关插件。
type HostDNCCapabilities struct {
	RunningInPanel          bool     `json:"running_in_panel"`
	DomainDNSPluginReady    bool     `json:"domain_dns_ready"`
	CertificatesPluginReady bool     `json:"tls_certificates_ready"`
	AvailableZones          []string `json:"available_zones"`
	AvailableCertBindings   []string `json:"available_cert_bindings"`
	RecommendedTrack        string   `json:"recommended_track"`
	FallbackReason          string   `json:"fallback_reason,omitempty"`
}

// ReverseProxySnippets 为「只装探针 / 宝塔共存 / 免端口反代」场景一键生成的零思考配置片段。
type ReverseProxySnippets struct {
	Domain          string `json:"domain"`
	UpstreamLoop    string `json:"upstream_loopback"`
	NginxBaotaConf  string `json:"nginx_baota_conf"`
	CaddyfileConf   string `json:"caddyfile_conf"`
	CloudflaredCmd  string `json:"cloudflared_cmd"`
	AgentReportBase string `json:"agent_report_base"`
}

// DiagnosticStep 表示四步域名与 HTTPS 自检结果。
type DiagnosticStep struct {
	Step   string `json:"step"`
	Status string `json:"status"` // ok | warn | fail
	Detail string `json:"detail"`
}

// DomainBindingCoordinator 统一编排轨道 A（借用面板 DNC）与轨道 B（探针内置独立闭环）。
type DomainBindingCoordinator struct {
	dataDir     string
	sealingKey  [32]byte
	panelHosts  map[string]struct{}
	activeCert  atomic.Pointer[tls.Certificate]
	activeMeta  atomic.Pointer[BoundCertSummary]
	tlsObs      atomic.Pointer[probeTLSBindingObservation]
	dncDetector func() HostDNCCapabilities
}

type BoundCertSummary struct {
	Track         string    `json:"track"`
	Domain        string    `json:"domain"`
	Issuer        string    `json:"issuer"`
	Fingerprint   string    `json:"fingerprint"`
	NotAfter      time.Time `json:"not_after"`
	AutoRenew     bool      `json:"auto_renew"`
	EffectiveURL  string    `json:"effective_url"`
	AgentEndpoint string    `json:"agent_endpoint"`
}

func NewDomainBindingCoordinator(dataDir string, sealingSecret []byte, panelHosts []string, detector func() HostDNCCapabilities) *DomainBindingCoordinator {
	sum := sha256.Sum256(append([]byte("qwq-probe-domain-seal-v1:"), sealingSecret...))
	ph := make(map[string]struct{}, len(panelHosts))
	for _, h := range panelHosts {
		if norm := normalizeFQDN(h); norm != "" {
			ph[norm] = struct{}{}
		}
	}
	return &DomainBindingCoordinator{
		dataDir:     dataDir,
		sealingKey:  sum,
		panelHosts:  ph,
		dncDetector: detector,
	}
}

// InspectEnvironment 探测当前是否可借用面板 DNC 插件；若未安装或单二进制运行，自动引导使用轨道 B。
func (c *DomainBindingCoordinator) InspectEnvironment() HostDNCCapabilities {
	if c.dncDetector != nil {
		caps := c.dncDetector()
		if caps.RunningInPanel && caps.CertificatesPluginReady {
			caps.RecommendedTrack = TrackPanelDNC
			return caps
		}
		caps.RecommendedTrack = TrackReverseProxy
		if !caps.RunningInPanel {
			caps.FallbackReason = "当前为单二进制独立探针模式（未挂载 qwq 面板宿主），已启用探针内置独立域名与 TLS 引擎"
		} else {
			caps.FallbackReason = "检测到面板未安装 domain.dns / tls.certificates 插件（仅安装探针），已自动切换至探针内置域名绑定闭环"
		}
		return caps
	}
	return HostDNCCapabilities{
		RunningInPanel:   false,
		RecommendedTrack: TrackBuiltinACME,
		FallbackReason:   "独立运行模式：支持内置 ACME 自动签发、导入 PEM/CF 源站证书或反向代理绑定",
	}
}

// ValidateAndApply 执行双轨域名绑定：自动拦截非法域名、主面板域名冲突、证书不匹配等问题。
func (c *DomainBindingCoordinator) ValidateAndApply(now time.Time, cfg *PortalSettings, uploadedCertPEM, uploadedKeyPEM []byte) (BoundCertSummary, error) {
	dom := normalizeFQDN(cfg.CustomDomain)
	if !validProbeFQDN(dom) {
		return BoundCertSummary{}, errors.New("INVALID_DOMAIN: 请输入合法二级或根域名（如 status.example.com），不支持纯 IP 或 localhost")
	}
	if _, conflict := c.panelHosts[dom]; conflict {
		return BoundCertSummary{}, errors.New("DOMAIN_CONFLICT_PANEL: 探针独占域名不能与 qwq 主面板管理域名相同，请使用独立子域名（如 status.*）以保护主面板隐身")
	}
	cfg.CustomDomain = dom

	caps := c.InspectEnvironment()
	effectiveTrack := cfg.BindingTrack
	if effectiveTrack == "" || effectiveTrack == TrackAuto {
		if caps.RunningInPanel && caps.CertificatesPluginReady && cfg.PanelCertBindingRef != "" {
			effectiveTrack = TrackPanelDNC
		} else if len(uploadedCertPEM) > 0 {
			effectiveTrack = TrackBuiltinPEM
		} else {
			effectiveTrack = TrackReverseProxy
		}
	}

	switch effectiveTrack {
	case TrackPanelDNC:
		if !caps.RunningInPanel || !caps.CertificatesPluginReady {
			return BoundCertSummary{}, errors.New("DNC_UNAVAILABLE: 当前未安装 tls.certificates 插件，请改用探针内置 ACME / 导入证书 / 反向代理轨道")
		}
		if !strings.HasPrefix(cfg.PanelCertBindingRef, "certbind_") {
			return BoundCertSummary{}, errors.New("BINDING_REF_REQUIRED: 请选择有效的面板证书绑定引用 (certbind_*)")
		}
		return c.loadMaterializedPanelCert(now, dom, cfg.PanelCertBindingRef)

	case TrackBuiltinPEM:
		if len(uploadedCertPEM) == 0 || len(uploadedKeyPEM) == 0 {
			return BoundCertSummary{}, errors.New("PEM_REQUIRED: 请同时提供完整证书链 PEM 与私钥 PEM")
		}
		pair, issuer, fp, notAfter, err := ValidateStrictProbePEM(now, dom, uploadedCertPEM, uploadedKeyPEM)
		if err != nil {
			return BoundCertSummary{}, err
		}
		// 将证书链与私钥以 AES-256-GCM 认证密封进配置，并立即清零调用方明文切片
		combined := append(append([]byte(nil), uploadedCertPEM...), '\n', '\x00', '\n')
		combined = append(combined, uploadedKeyPEM...)
		sealed, err := c.sealBytes(combined)
		clear(combined)
		clear(uploadedKeyPEM)
		if err != nil {
			return BoundCertSummary{}, err
		}
		cfg.BuiltinSealedBundleB64 = sealed
		cfg.BuiltinCertFP = fp
		cfg.BuiltinCertExpiresAt = notAfter.Unix()
		c.activeCert.Store(pair)
		summary := BoundCertSummary{
			Track:         TrackBuiltinPEM,
			Domain:        dom,
			Issuer:        issuer,
			Fingerprint:   fp,
			NotAfter:      notAfter,
			AutoRenew:     false,
			EffectiveURL:  "https://" + dom + "/",
			AgentEndpoint: "https://" + dom + "/api/probe/v1/report",
		}
		c.activeMeta.Store(&summary)
		return summary, nil

	case TrackBuiltinACME:
		if !strings.Contains(cfg.BuiltinACMEEmail, "@") {
			return BoundCertSummary{}, errors.New("ACME_EMAIL_REQUIRED: 内置自动 ACME 签发需要填写接收到期提醒的有效邮箱")
		}
		summary := BoundCertSummary{
			Track:         TrackBuiltinACME,
			Domain:        dom,
			Issuer:        "Let's Encrypt (Builtin Autocert)",
			Fingerprint:   cfg.BuiltinCertFP,
			NotAfter:      now.Add(90 * 24 * time.Hour),
			AutoRenew:     true,
			EffectiveURL:  "https://" + dom + "/",
			AgentEndpoint: "https://" + dom + "/api/probe/v1/report",
		}
		c.activeMeta.Store(&summary)
		return summary, nil

	case TrackReverseProxy:
		summary := BoundCertSummary{
			Track:         TrackReverseProxy,
			Domain:        dom,
			Issuer:        "External Reverse Proxy / Cloudflare Edge",
			AutoRenew:     true,
			EffectiveURL:  "https://" + dom + "/",
			AgentEndpoint: "https://" + dom + "/api/probe/v1/report",
		}
		c.activeMeta.Store(&summary)
		return summary, nil

	default:
		return BoundCertSummary{}, fmt.Errorf("UNSUPPORTED_TRACK: %q", effectiveTrack)
	}
}

// loadMaterializedPanelCert 读取宿主 ConsumerBindingDeployer 物化在探针私有目录的 0600 证书。
func (c *DomainBindingCoordinator) loadMaterializedPanelCert(now time.Time, dom, bindingRef string) (BoundCertSummary, error) {
	if c.dataDir == "" {
		return BoundCertSummary{}, errors.New("DATA_DIR_UNSET")
	}
	baseDir := filepath.Join(c.dataDir, "tls", "bindings", filepath.Base(bindingRef))
	chainBytes, err := os.ReadFile(filepath.Join(baseDir, "active_fullchain.pem"))
	if err != nil {
		return BoundCertSummary{}, fmt.Errorf("MATERIALIZED_CERT_MISSING: 尚未找到宿主物化证书 (%w)", err)
	}
	keyBytes, err := os.ReadFile(filepath.Join(baseDir, "active_privkey.pem"))
	if err != nil {
		return BoundCertSummary{}, fmt.Errorf("MATERIALIZED_KEY_MISSING: %w", err)
	}
	defer clear(keyBytes)

	pair, issuer, fp, notAfter, err := ValidateStrictProbePEM(now, dom, chainBytes, keyBytes)
	if err != nil {
		return BoundCertSummary{}, err
	}
	c.activeCert.Store(pair)
	summary := BoundCertSummary{
		Track:         TrackPanelDNC,
		Domain:        dom,
		Issuer:        issuer,
		Fingerprint:   fp,
		NotAfter:      notAfter,
		AutoRenew:     true,
		EffectiveURL:  "https://" + dom + "/",
		AgentEndpoint: "https://" + dom + "/api/probe/v1/report",
	}
	c.activeMeta.Store(&summary)
	return summary, nil
}

// ValidateStrictProbePEM 复用与宿主 tlsmgr/material.go 同等级的严格 PEM 校验（兼容泛域名与 Cloudflare Origin CA）。
func ValidateStrictProbePEM(now time.Time, expectedDomain string, chainPEM, keyPEM []byte) (*tls.Certificate, string, string, time.Time, error) {
	if len(chainPEM) == 0 || len(chainPEM) > (48<<10) || len(keyPEM) == 0 || len(keyPEM) > (16<<10) {
		return nil, "", "", time.Time{}, errors.New("CERTIFICATE_INVALID: PEM 长度为空或超过安全上限")
	}
	block, _ := pem.Decode(bytes.TrimSpace(chainPEM))
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, "", "", time.Time{}, errors.New("CERTIFICATE_INVALID: 首块不是有效 CERTIFICATE PEM")
	}
	pair, err := tls.X509KeyPair(chainPEM, keyPEM)
	if err != nil {
		return nil, "", "", time.Time{}, errors.New("PRIVATE_KEY_MISMATCH: 证书与私钥不匹配或无法解析")
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return nil, "", "", time.Time{}, errors.New("CERTIFICATE_INVALID: 叶证书损坏")
	}
	if err := leaf.VerifyHostname(expectedDomain); err != nil {
		return nil, "", "", time.Time{}, fmt.Errorf("SAN_MISMATCH: 证书未覆盖目标探针域名 %s", expectedDomain)
	}
	if !now.Before(leaf.NotAfter) {
		return nil, "", "", time.Time{}, errors.New("CERTIFICATE_EXPIRED: 证书已过期")
	}
	if now.Before(leaf.NotBefore.Add(-1 * time.Hour)) {
		return nil, "", "", time.Time{}, errors.New("CERTIFICATE_NOT_YET_VALID: 证书尚未生效")
	}
	switch pub := leaf.PublicKey.(type) {
	case *ecdsa.PublicKey:
		if pub.Curve.Params().BitSize < 256 {
			return nil, "", "", time.Time{}, errors.New("WEAK_KEY: ECDSA 曲线低于 P-256")
		}
	case ed25519.PublicKey:
	case *rsa.PublicKey:
		if pub.N.BitLen() < 2048 {
			return nil, "", "", time.Time{}, errors.New("WEAK_KEY: RSA 密钥短于 2048 位")
		}
	default:
		return nil, "", "", time.Time{}, errors.New("UNSUPPORTED_KEY: 不支持的公钥算法")
	}

	pair.Leaf = leaf
	rawSum := sha256.Sum256(leaf.Raw)
	fp := strings.ToUpper(hex.EncodeToString(rawSum[:8]))
	return &pair, leaf.Issuer.CommonName, fp, leaf.NotAfter.UTC(), nil
}

// BuildReverseProxySnippets 生成零思考 Nginx/宝塔、Caddy 与 Cloudflare Tunnel 反代片段（含 SSE 不缓冲指令）。
func BuildReverseProxySnippets(domain, loopbackListen string) ReverseProxySnippets {
	dom := normalizeFQDN(domain)
	if dom == "" {
		dom = "status.example.com"
	}
	if loopbackListen == "" || loopbackListen == "127.0.0.1:19080" {
		// 面板公共路由 /p/server.probe/ 由 qwq 主控直接承载（默认 127.0.0.1:8443，可通过 sudo qwq access show 查看当前端口）
		loopbackListen = "127.0.0.1:8443"
	}
	nginx := fmt.Sprintf(`# 宝塔面板 / Nginx 站点反向代理配置（完美支持实时 SSE 流与单向 Agent 上报）
server {
    listen 80;
    listen 443 ssl http2;
    server_name %s;

    # 证书可由宝塔自动续签或使用 Cloudflare 15 年源站证书
    # ssl_certificate     /www/server/panel/vhost/cert/%s/fullchain.pem;
    # ssl_certificate_key /www/server/panel/vhost/cert/%s/privkey.pem;

    location = /api/probe/v1/report {
        proxy_pass http://%s/p/server.probe/agent/v1/report;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-Host $host;
    }

    location / {
        proxy_pass http://%s/p/server.probe/portal/;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-Host $host;
        proxy_buffering off;
        proxy_cache off;
        proxy_read_timeout 3600s;
    }
}`, dom, dom, dom, loopbackListen, loopbackListen)

	caddy := fmt.Sprintf(`%s {
    encode zstd gzip
    handle /api/probe/v1/report {
        rewrite * /p/server.probe/agent/v1/report
        reverse_proxy %s {
            header_up X-Forwarded-Host {host}
        }
    }
    handle {
        rewrite * /p/server.probe/portal{uri}
        reverse_proxy %s {
            flush_interval -1
            header_up X-Forwarded-Host {host}
        }
    }
}`, dom, loopbackListen, loopbackListen)

	cfTunnel := fmt.Sprintf(`cloudflared tunnel route dns <tunnel-name> %s && cloudflared tunnel run --url http://%s/p/server.probe/portal/ <tunnel-name>`, dom, loopbackListen)

	return ReverseProxySnippets{
		Domain:          dom,
		UpstreamLoop:    loopbackListen,
		NginxBaotaConf:  nginx,
		CaddyfileConf:   caddy,
		CloudflaredCmd:  cfTunnel,
		AgentReportBase: "https://" + dom + "/api/probe/v1/report",
	}
}

// EffectiveTrustedProxies 合并管理员配置的受信反代 CIDR 与可选的 Cloudflare 官方回源段。
func EffectiveTrustedProxies(base []string, includeCloudflare bool) []netip.Prefix {
	merged := slices.Clone(base)
	if len(merged) == 0 {
		merged = []string{"127.0.0.1/32", "::1/128"}
	}
	if includeCloudflare {
		merged = append(merged, CloudflarePublishedRanges...)
	}
	out := make([]netip.Prefix, 0, len(merged))
	for _, raw := range merged {
		if p, err := netip.ParsePrefix(strings.TrimSpace(raw)); err == nil {
			out = append(out, p.Masked())
		} else if a, err := netip.ParseAddr(strings.TrimSpace(raw)); err == nil {
			bits := 32
			if a.Is6() {
				bits = 128
			}
			out = append(out, netip.PrefixFrom(a, bits))
		}
	}
	return out
}

func (c *DomainBindingCoordinator) sealBytes(plain []byte) (string, error) {
	block, err := aes.NewCipher(c.sealingKey[:])
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	ct := gcm.Seal(nonce, nonce, plain, []byte("server.probe:tls_private_key"))
	return base64.StdEncoding.EncodeToString(ct), nil
}

// ReloadSealedBundle 在重启恢复时解密并重新校验先前导入的自定义 PEM/Cloudflare 源站证书，解密缓冲用完立即清零。
func (c *DomainBindingCoordinator) ReloadSealedBundle(now time.Time, cfg PortalSettings) error {
	if cfg.BuiltinSealedBundleB64 == "" || cfg.CustomDomain == "" {
		return nil
	}
	raw, err := base64.StdEncoding.DecodeString(cfg.BuiltinSealedBundleB64)
	if err != nil {
		return err
	}
	block, err := aes.NewCipher(c.sealingKey[:])
	if err != nil {
		return err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil || len(raw) < gcm.NonceSize() {
		return errors.New("SEALED_PEM_CORRUPTED")
	}
	plain, err := gcm.Open(nil, raw[:gcm.NonceSize()], raw[gcm.NonceSize():], []byte("server.probe:tls_private_key"))
	if err != nil {
		return err
	}
	defer clear(plain)

	sep := []byte{'\n', '\x00', '\n'}
	idx := bytes.Index(plain, sep)
	if idx <= 0 {
		return errors.New("SEALED_PEM_FORMAT_INVALID")
	}
	pair, _, _, _, err := ValidateStrictProbePEM(now, cfg.CustomDomain, plain[:idx], plain[idx+len(sep):])
	if err != nil {
		return err
	}
	c.activeCert.Store(pair)
	return nil
}

func normalizeFQDN(raw string) string {
	s := strings.TrimSpace(strings.ToLower(raw))
	s = strings.TrimPrefix(s, "https://")
	s = strings.TrimPrefix(s, "http://")
	if idx := strings.IndexByte(s, '/'); idx >= 0 {
		s = s[:idx]
	}
	if h, _, err := net.SplitHostPort(s); err == nil {
		s = h
	}
	return strings.TrimSuffix(strings.Trim(s, "[]"), ".")
}

func validProbeFQDN(dom string) bool {
	if len(dom) < 4 || len(dom) > 253 || dom == "localhost" || !strings.Contains(dom, ".") {
		return false
	}
	if _, err := netip.ParseAddr(dom); err == nil {
		return false
	}
	for _, part := range strings.Split(dom, ".") {
		if len(part) == 0 || len(part) > 63 || part[0] == '-' || part[len(part)-1] == '-' {
			return false
		}
		for i := 0; i < len(part); i++ {
			ch := part[i]
			if !((ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '-') {
				return false
			}
		}
	}
	return true
}
