// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ======================== 1. 防 DNS Rebinding / 防云元数据穿透的反代安全拨号器（PLG-FIX-10） ========================

var blockedMetadataAndSpecialPrefixes = []netip.Prefix{
	netip.MustParsePrefix("169.254.0.0/16"),    // AWS/GCP/Azure/OpenStack IMDS & Link-Local
	netip.MustParsePrefix("100.64.0.0/10"),     // 阿里云 100.100.100.200 元数据 & CGNAT
	netip.MustParsePrefix("0.0.0.0/8"),         // 本网络保留段（防止 0.0.0.0 绕过回环检查）
	netip.MustParsePrefix("198.18.0.0/15"),     // 基准测试网段
	netip.MustParsePrefix("fe80::/10"),         // IPv6 Link-Local
	netip.MustParsePrefix("fd00:ec2::254/128"), // AWS IPv6 IMDS
	netip.MustParsePrefix("64:ff9b::/96"),      // NAT64（防止 64:ff9b::169.254.169.254 绕过）
	netip.MustParsePrefix("64:ff9b:1::/48"),
	netip.MustParsePrefix("2002::/16"), // 6to4
	netip.MustParsePrefix("2001::/32"), // Teredo
}

var (
	nat64WellKnownPrefix = netip.MustParsePrefix("64:ff9b::/96")
	nat64LocalPrefix     = netip.MustParsePrefix("64:ff9b:1::/48")
)

type netIPLookupFunc func(ctx context.Context, network, host string) ([]netip.Addr, error)

// NewSafeIngressTransport 构造防 DNS Rebinding 与云元数据 SSRF 的安全 HTTP Transport：
//   - Proxy 强制置 nil，绝不继承环境变量代理；
//   - 字面量 IP 上游始终阻断 169.254.0.0/16、100.64.0.0/10、Link-Local、NAT64 等元数据/特殊地址，
//     仅当 allowLoopbackUpstream=true 时放行显式填写的回环/私网业务地址（如 127.0.0.1:3000）；
//   - 域名上游在每次连接瞬间执行解析并拦截一切回环/私网/云元数据/NAT64 IP，随后直连已校验 IP 彻底消除 DNS 重绑定。
func NewSafeIngressTransport(allowLoopbackUpstream bool) *http.Transport {
	return newSafeIngressTransportWithResolver(allowLoopbackUpstream, net.DefaultResolver.LookupNetIP)
}

func newSafeIngressTransportWithResolver(allowLoopbackUpstream bool, lookup netIPLookupFunc) *http.Transport {
	if lookup == nil {
		lookup = net.DefaultResolver.LookupNetIP
	}
	dialer := &net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}
	return &http.Transport{
		Proxy:               nil, // 严禁继承环境变量代理
		MaxIdleConns:        64,
		MaxIdleConnsPerHost: 16,
		IdleConnTimeout:     60 * time.Second,
		TLSHandshakeTimeout: 5 * time.Second,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, portStr, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			cleanHost := strings.Trim(strings.TrimSpace(host), "[]")
			if strings.EqualFold(cleanHost, "metadata.google.internal") {
				return nil, errors.New("SSRF_BLOCKED: refusing to dial cloud metadata host")
			}

			// 情况 A：upstream_url 中显式填写了字面量 IP（无 DNS 重绑定风险）
			if literalIP, parseErr := netip.ParseAddr(cleanHost); parseErr == nil {
				u := literalIP.Unmap()
				if isAlwaysBlockedSpecialIP(u) {
					return nil, fmt.Errorf("SSRF_BLOCKED: upstream IP %s is a forbidden metadata or link-local address", u)
				}
				if (u.IsLoopback() || u.IsPrivate()) && !allowLoopbackUpstream {
					return nil, fmt.Errorf("SSRF_BLOCKED: private/loopback upstream %s disabled by policy", u)
				}
				return dialer.DialContext(ctx, network, net.JoinHostPort(u.String(), portStr))
			}

			// 情况 B：upstream_url 是域名 -> 连接瞬间解析并拦截一切回环/私网/元数据/NAT64 重绑定 IP
			ips, err := lookup(ctx, "ip", cleanHost)
			if err != nil {
				return nil, err
			}
			if len(ips) == 0 {
				return nil, fmt.Errorf("upstream %s resolved to zero addresses", cleanHost)
			}
			for _, ip := range ips {
				u := ip.Unmap()
				if !u.IsValid() || u.IsLoopback() || u.IsPrivate() || isAlwaysBlockedSpecialIP(u) {
					return nil, fmt.Errorf("SSRF_DNS_REBIND_BLOCKED: domain %s resolved to non-public address %s", cleanHost, u)
				}
			}
			return dialer.DialContext(ctx, network, net.JoinHostPort(ips[0].Unmap().String(), portStr))
		},
	}
}

func isAlwaysBlockedSpecialIP(ip netip.Addr) bool {
	if !ip.IsValid() || ip.IsUnspecified() || ip.IsMulticast() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return true
	}
	// 检查 NAT64 内嵌的末尾 32 位 IPv4（如 64:ff9b::a9fe:a9fe == 169.254.169.254）
	if ip.Is6() {
		raw16 := ip.As16()
		if nat64WellKnownPrefix.Contains(ip) || nat64LocalPrefix.Contains(ip) {
			embeddedV4 := netip.AddrFrom4([4]byte{raw16[12], raw16[13], raw16[14], raw16[15]})
			if embeddedV4.IsLoopback() || embeddedV4.IsPrivate() || isAlwaysBlockedSpecialIP(embeddedV4) {
				return true
			}
		}
	}
	for _, p := range blockedMetadataAndSpecialPrefixes {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

// ======================== 2. 内建原子 SNI TLS 热重载引擎 & 安全 ForceHTTPS 判定（PLG-FIX-10 & PLG-FIX-12） ========================

type tlsBindingObservation struct {
	Running         bool   `json:"running"`
	BindingRef      string `json:"binding_ref"`
	Generation      uint64 `json:"generation"`
	PolicyRevision  string `json:"policy_revision"`
	FullchainSHA256 string `json:"fullchain_sha256"`
	LeafFingerprint string `json:"leaf_fingerprint"`
	SNI             string `json:"sni"`
	Endpoint        string `json:"endpoint"`
}

// SNICertStore 从 `<dataDir>/tls/bindings/<bindingRef>/active_{fullchain,privkey}.pem`（宿主 tls.certificates 物化目录）
// 或直接 PEM 字节加载证书并以 atomic.Pointer 无锁热切换，支撑内建 HTTPS 监听与 ingress.tls.reload 零断连续期。
type SNICertStore struct {
	dataDir     string
	writeMu     sync.Mutex
	certTable   atomic.Pointer[map[string]*tls.Certificate] // lower(domain) -> *tls.Certificate
	bindings    map[string]tlsBindingObservation            // bindingRef -> observation
	hasListener atomic.Bool
}

func NewSNICertStore(dataDir string) *SNICertStore {
	s := &SNICertStore{
		dataDir:  dataDir,
		bindings: make(map[string]tlsBindingObservation),
	}
	empty := make(map[string]*tls.Certificate)
	s.certTable.Store(&empty)
	return s
}

func (s *SNICertStore) SetHTTPSListenerActive(active bool) {
	s.hasListener.Store(active)
}

func (s *SNICertStore) HTTPSListenerActive() bool {
	return s.hasListener.Load()
}

// UpsertCert 校验 PEM 证书链与私钥并原子更新指定域名的 SNI 证书。
func (s *SNICertStore) UpsertCert(domain string, certPEM, keyPEM []byte) error {
	norm := normalizeSNIDomain(domain)
	if norm == "" {
		return errors.New("ingress: domain is required for SNI certificate")
	}
	keyCopy := append([]byte(nil), keyPEM...)
	defer clear(keyCopy)
	pair, err := tls.X509KeyPair(certPEM, keyCopy)
	if err != nil {
		return fmt.Errorf("parse keypair for %s: %w", norm, err)
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	cur := s.certTable.Load()
	next := make(map[string]*tls.Certificate, len(*cur)+1)
	for k, v := range *cur {
		next[k] = v
	}
	next[norm] = &pair
	s.certTable.Store(&next)
	return nil
}

// RemoveDomain 从 SNI 映射表中原子移除指定域名的证书。
func (s *SNICertStore) RemoveDomain(domain string) {
	norm := normalizeSNIDomain(domain)
	if norm == "" {
		return
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	cur := s.certTable.Load()
	if _, exists := (*cur)[norm]; !exists {
		return
	}
	next := make(map[string]*tls.Certificate, len(*cur))
	for k, v := range *cur {
		if k != norm {
			next[k] = v
		}
	}
	s.certTable.Store(&next)
}

// ReloadFromBindings 遍历启用站点的 CertID（certbind_*），加载已物化证书并原子替换 SNI 表。
// 单站点证书缺失或解析失败时跳过该站点继续加载其余有效站点，且不保留已删除/停用域名的旧证书。
func (s *SNICertStore) ReloadFromBindings(domainToBindingRef map[string]string) (loaded int, err error) {
	parsed := make(map[string]*tls.Certificate, len(domainToBindingRef))
	var errs []error
	for domain, ref := range domainToBindingRef {
		cleanRef := filepath.Base(strings.TrimSpace(ref))
		if cleanRef == "" || cleanRef == "." || cleanRef == ".." {
			continue
		}
		fullPath, keyPath := MaterializedCertPaths(s.dataDir, cleanRef)
		certBytes, cerr := os.ReadFile(fullPath)
		if cerr != nil {
			errs = append(errs, fmt.Errorf("read materialized cert for %s (%s): %w", domain, cleanRef, cerr))
			continue
		}
		keyBytes, kerr := os.ReadFile(keyPath)
		if kerr != nil {
			errs = append(errs, fmt.Errorf("read materialized key for %s (%s): %w", domain, cleanRef, kerr))
			continue
		}
		pair, perr := tls.X509KeyPair(certBytes, keyBytes)
		clear(keyBytes)
		if perr != nil {
			errs = append(errs, fmt.Errorf("parse keypair for %s: %w", domain, perr))
			continue
		}
		norm := normalizeSNIDomain(domain)
		if norm == "" {
			continue
		}
		parsed[norm] = &pair
		loaded++
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	next := make(map[string]*tls.Certificate, len(parsed))
	for k, v := range parsed {
		next[k] = v
	}
	s.certTable.Store(&next)
	return loaded, errors.Join(errs...)
}

// LoadBinding 从宿主物化目录核验 SHA-256 摘要并原子热加载单个 TLS 绑定，供 ingress.tls.reload 调用。
func (s *SNICertStore) LoadBinding(
	bindingRef string,
	generation uint64,
	policyRevision string,
	expectedFullchainSHA256 string,
	expectedPrivKeySHA256 string,
	sni string,
	endpoint string,
) (tlsBindingObservation, error) {
	cleanRef := filepath.Base(strings.TrimSpace(bindingRef))
	if cleanRef == "" || cleanRef == "." || cleanRef == ".." || cleanRef != strings.TrimSpace(bindingRef) {
		return tlsBindingObservation{}, errors.New("invalid binding_ref")
	}
	normSNI := normalizeSNIDomain(sni)
	if normSNI == "" {
		return tlsBindingObservation{}, errors.New("invalid sni")
	}
	fullPath, keyPath := MaterializedCertPaths(s.dataDir, cleanRef)
	certBytes, err := os.ReadFile(fullPath)
	if err != nil {
		return tlsBindingObservation{}, fmt.Errorf("read active_fullchain.pem: %w", err)
	}
	keyBytes, err := os.ReadFile(keyPath)
	if err != nil {
		return tlsBindingObservation{}, fmt.Errorf("read active_privkey.pem: %w", err)
	}
	defer clear(keyBytes)

	fullHash := sha256Hex(certBytes)
	keyHash := sha256Hex(keyBytes)
	if exp := strings.ToLower(strings.TrimSpace(expectedFullchainSHA256)); exp != "" && fullHash != exp {
		return tlsBindingObservation{}, errors.New("fullchain_sha256 mismatch")
	}
	if exp := strings.ToLower(strings.TrimSpace(expectedPrivKeySHA256)); exp != "" && keyHash != exp {
		return tlsBindingObservation{}, errors.New("private_key_sha256 mismatch")
	}

	pair, err := tls.X509KeyPair(certBytes, keyBytes)
	if err != nil {
		return tlsBindingObservation{}, fmt.Errorf("parse keypair: %w", err)
	}
	var leafFP string
	if len(pair.Certificate) > 0 {
		if leaf, perr := x509.ParseCertificate(pair.Certificate[0]); perr == nil {
			sum := sha256.Sum256(leaf.Raw)
			leafFP = "sha256:" + hex.EncodeToString(sum[:])
		}
	}

	obs := tlsBindingObservation{
		Running:         s.HTTPSListenerActive(),
		BindingRef:      cleanRef,
		Generation:      generation,
		PolicyRevision:  policyRevision,
		FullchainSHA256: fullHash,
		LeafFingerprint: leafFP,
		SNI:             normSNI,
		Endpoint:        endpoint,
	}

	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	cur := s.certTable.Load()
	next := make(map[string]*tls.Certificate, len(*cur)+1)
	for k, v := range *cur {
		next[k] = v
	}
	next[normSNI] = &pair
	s.certTable.Store(&next)
	s.bindings[cleanRef] = obs
	return obs, nil
}

// InspectBinding 返回指定绑定在当前内存中的最新加载状态。
func (s *SNICertStore) InspectBinding(bindingRef, endpoint string) tlsBindingObservation {
	cleanRef := strings.TrimSpace(bindingRef)
	s.writeMu.Lock()
	obs, ok := s.bindings[cleanRef]
	s.writeMu.Unlock()
	if !ok {
		return tlsBindingObservation{
			Running:    s.HTTPSListenerActive(),
			BindingRef: cleanRef,
			Endpoint:   endpoint,
		}
	}
	obs.Running = s.HTTPSListenerActive()
	if endpoint != "" {
		obs.Endpoint = endpoint
	}
	return obs
}

// GetCertificate 按精确域名或一级泛域名（*.example.com）无锁匹配证书。
func (s *SNICertStore) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	tablePtr := s.certTable.Load()
	if tablePtr == nil {
		return nil, errors.New("ingress: no certificates loaded")
	}
	table := *tablePtr
	sni := normalizeSNIDomain(hello.ServerName)
	if cert, ok := table[sni]; ok {
		return cert, nil
	}
	if dot := strings.IndexByte(sni, '.'); dot > 0 {
		if wild, ok := table["*"+sni[dot:]]; ok {
			return wild, nil
		}
	}
	return nil, fmt.Errorf("ingress: no certificate configured for SNI %q", sni)
}

// HasCertForDomain 判断当前 SNI 缓存中是否存在匹配域名的可用证书。
func (s *SNICertStore) HasCertForDomain(domain string) bool {
	if s == nil {
		return false
	}
	tablePtr := s.certTable.Load()
	if tablePtr == nil {
		return false
	}
	table := *tablePtr
	sni := normalizeSNIDomain(domain)
	if _, ok := table[sni]; ok {
		return true
	}
	if dot := strings.IndexByte(sni, '.'); dot > 0 {
		if _, ok := table["*"+sni[dot:]]; ok {
			return true
		}
	}
	return false
}

// TLSConfig 生成挂接在 tls.NewListener 上的安全 TLS 1.2+ 配置。
func (s *SNICertStore) TLSConfig() *tls.Config {
	return &tls.Config{
		MinVersion:     tls.VersionTLS12,
		NextProtos:     []string{"h2", "http/1.1"},
		GetCertificate: s.GetCertificate,
	}
}

// MaterializedCertPaths 返回宿主 consumerfiles 物化在插件数据目录下的 0600 证书链与私钥路径。
func MaterializedCertPaths(pluginDataDir, certBindingRef string) (fullchainPath, privkeyPath string) {
	cleanRef := filepath.Base(strings.TrimSpace(certBindingRef))
	base := filepath.Join(pluginDataDir, "tls", "bindings", cleanRef)
	return filepath.ToSlash(filepath.Join(base, "active_fullchain.pem")),
		filepath.ToSlash(filepath.Join(base, "active_privkey.pem"))
}

// ShouldRedirectHTTPS 安全判定是否返回 308 HTTPS 跳转：
//  1. 仅当 hasActiveHTTPSListener 为 true（内建 HTTPS 监听已启动或已确认外部 HTTPS 终止）时才跳转，杜绝跳向无监听 :443 死循环；
//  2. 仅当直连对端位于 trustedProxies 时才信任 X-Forwarded-Proto: https（防外部伪造头绕过 HTTPS 跳转）。
func ShouldRedirectHTTPS(
	r *http.Request,
	siteForceHTTPS bool,
	hasActiveHTTPSListener bool,
	trustedProxies []netip.Prefix,
) bool {
	if !siteForceHTTPS || r == nil || r.TLS != nil {
		return false
	}
	if isRequestFromTrustedProxy(r.RemoteAddr, trustedProxies) &&
		strings.EqualFold(strings.TrimSpace(r.Header.Get("X-Forwarded-Proto")), "https") {
		return false
	}
	return hasActiveHTTPSListener
}

// RealClientIP 提取真实访客 IP 供单 IP 令牌桶限流使用：
// 仅当直接对端位于 trustedProxies 时才解析 X-Forwarded-For 右起首个非受信 IP，否则直接使用 r.RemoteAddr。
func RealClientIP(r *http.Request, trustedProxies []netip.Prefix) string {
	remoteHost, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		remoteHost = strings.TrimSpace(r.RemoteAddr)
	}
	if !isRequestFromTrustedProxy(r.RemoteAddr, trustedProxies) {
		return remoteHost
	}
	xff := r.Header.Get("X-Forwarded-For")
	if xff == "" {
		return remoteHost
	}
	parts := strings.Split(xff, ",")
	for i := len(parts) - 1; i >= 0; i-- {
		cand := strings.TrimSpace(parts[i])
		addr, perr := netip.ParseAddr(cand)
		if perr != nil {
			continue
		}
		if !containsAddr(trustedProxies, addr.Unmap()) {
			return addr.Unmap().String()
		}
	}
	return remoteHost
}

func parseTrustedProxies(raw []string) ([]netip.Prefix, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	if len(raw) > 32 {
		return nil, errors.New("trusted_proxies 最多配置 32 条网段")
	}
	out := make([]netip.Prefix, 0, len(raw))
	for _, entry := range raw {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		if strings.Contains(entry, "/") {
			p, err := netip.ParsePrefix(entry)
			if err != nil {
				return nil, fmt.Errorf("无效的 trusted_proxies CIDR %q", entry)
			}
			out = append(out, p.Masked())
		} else {
			addr, err := netip.ParseAddr(entry)
			if err != nil {
				return nil, fmt.Errorf("无效的 trusted_proxies IP %q", entry)
			}
			u := addr.Unmap()
			out = append(out, netip.PrefixFrom(u, u.BitLen()))
		}
	}
	return out, nil
}

func isRequestFromTrustedProxy(remoteAddr string, trusted []netip.Prefix) bool {
	if len(trusted) == 0 {
		return false
	}
	h, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		h = remoteAddr
	}
	addr, err := netip.ParseAddr(strings.Trim(strings.TrimSpace(h), "[]"))
	if err != nil {
		return false
	}
	return containsAddr(trusted, addr.Unmap())
}

func containsAddr(prefixes []netip.Prefix, ip netip.Addr) bool {
	for _, p := range prefixes {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

func normalizeSNIDomain(s string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(s), "."))
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// ======================== 3. SQLite 无损迁移：解除 domain UNIQUE 单路径死锁（PLG-FIX-10） ========================

// MigrateIngressSitesCompositeUnique 在 openIngressStore 初始化 Schema 后调用：
// 检测旧表若仍含单列 domain TEXT NOT NULL UNIQUE（无 (domain, path_prefix) 复合唯一约束），
// 在单事务中无损重建为 UNIQUE (domain, path_prefix)，使 example.com/ 与 example.com/api 可同时并存。
func MigrateIngressSitesCompositeUnique(ctx context.Context, db *sql.DB) error {
	var createSQL string
	err := db.QueryRowContext(ctx,
		`SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'ingress_sites'`,
	).Scan(&createSQL)
	if err != nil {
		return nil
	}
	upper := strings.ToUpper(createSQL)
	if strings.Contains(upper, "UNIQUE(DOMAIN, PATH_PREFIX)") ||
		strings.Contains(upper, "UNIQUE (DOMAIN, PATH_PREFIX)") {
		return nil
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	stmts := []string{
		`CREATE TABLE ingress_sites_v2 (
			id                 TEXT PRIMARY KEY,
			domain             TEXT NOT NULL,
			enabled            INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
			upstream_url       TEXT NOT NULL,
			path_prefix        TEXT NOT NULL DEFAULT '/',
			websocket          INTEGER NOT NULL DEFAULT 1 CHECK (websocket IN (0, 1)),
			tls_mode           TEXT NOT NULL DEFAULT 'managed' CHECK (tls_mode IN ('off', 'managed', 'custom')),
			cert_id            TEXT NOT NULL DEFAULT '',
			force_https        INTEGER NOT NULL DEFAULT 1 CHECK (force_https IN (0, 1)),
			rate_limit_rps     INTEGER NOT NULL DEFAULT 0 CHECK (rate_limit_rps >= 0 AND rate_limit_rps <= 10000),
			rate_limit_burst   INTEGER NOT NULL DEFAULT 0 CHECK (rate_limit_burst >= 0 AND rate_limit_burst <= 20000),
			basic_auth_user    TEXT NOT NULL DEFAULT '',
			basic_auth_hash    TEXT NOT NULL DEFAULT '',
			extra_headers_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(extra_headers_json)),
			notes              TEXT NOT NULL DEFAULT '',
			revision           INTEGER NOT NULL DEFAULT 1,
			created_at         INTEGER NOT NULL,
			updated_at         INTEGER NOT NULL,
			UNIQUE (domain, path_prefix)
		) STRICT;`,
		`INSERT INTO ingress_sites_v2 SELECT * FROM ingress_sites;`,
		`DROP TABLE ingress_sites;`,
		`ALTER TABLE ingress_sites_v2 RENAME TO ingress_sites;`,
		`CREATE INDEX IF NOT EXISTS idx_ingress_sites_domain ON ingress_sites(domain);`,
	}
	for _, q := range stmts {
		if _, err := tx.ExecContext(ctx, q); err != nil {
			return fmt.Errorf("migrate ingress_sites composite unique: %w", err)
		}
	}
	return tx.Commit()
}
