// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/bcrypt"
)

const (
	maxRateLimitIPs   = 4096
	maxBasicAuthCache = 512
	basicAuthCacheTTL = 60 * time.Second
)

type tokenBucket struct {
	tokens   float64
	lastSeen time.Time
}

type siteLimiter struct {
	mu      sync.Mutex
	rps     float64
	burst   float64
	buckets map[string]*tokenBucket
}

func newSiteLimiter(rps, burst int) *siteLimiter {
	if rps <= 0 {
		return nil
	}
	if burst < rps {
		burst = rps
	}
	return &siteLimiter{
		rps:     float64(rps),
		burst:   float64(burst),
		buckets: make(map[string]*tokenBucket),
	}
}

func (l *siteLimiter) Allow(ip string, now time.Time) bool {
	if l == nil {
		return true
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	b, ok := l.buckets[ip]
	if !ok {
		if len(l.buckets) >= maxRateLimitIPs {
			// 驱逐陈旧桶，严防 1C1G 内存无限增长。
			var oldestIP string
			var oldestAt time.Time
			for k, v := range l.buckets {
				if now.Sub(v.lastSeen) > 5*time.Minute {
					delete(l.buckets, k)
					continue
				}
				if oldestIP == "" || v.lastSeen.Before(oldestAt) {
					oldestIP, oldestAt = k, v.lastSeen
				}
			}
			if len(l.buckets) >= maxRateLimitIPs && oldestIP != "" {
				delete(l.buckets, oldestIP)
			}
		}
		b = &tokenBucket{tokens: l.burst, lastSeen: now}
		l.buckets[ip] = b
	}
	elapsed := now.Sub(b.lastSeen).Seconds()
	if elapsed > 0 {
		b.tokens += elapsed * l.rps
		if b.tokens > l.burst {
			b.tokens = l.burst
		}
		b.lastSeen = now
	}
	if b.tokens < 1.0 {
		return false
	}
	b.tokens -= 1.0
	return true
}

type compiledRoute struct {
	site    SiteRecord
	proxy   *httputil.ReverseProxy
	limiter *siteLimiter
}

type routeTable struct {
	byHost      map[string][]*compiledRoute
	totalRoutes int
	loaded      time.Time
}

type basicAuthCache struct {
	mu      sync.Mutex
	entries map[[32]byte]time.Time
}

func newBasicAuthCache() *basicAuthCache {
	return &basicAuthCache{entries: make(map[[32]byte]time.Time, 64)}
}

func basicAuthCacheKey(siteID, expectedUser, hash, suppliedUser, authHeader string) [32]byte {
	h := sha256.New()
	_, _ = h.Write([]byte(siteID))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write([]byte(expectedUser))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write([]byte(hash))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write([]byte(suppliedUser))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write([]byte(authHeader))
	var out [32]byte
	h.Sum(out[:0])
	return out
}

func matchPathPrefix(reqPath, prefix string) bool {
	if prefix == "" || prefix == "/" {
		return true
	}
	if strings.HasSuffix(prefix, "/") {
		return strings.HasPrefix(reqPath, prefix)
	}
	if !strings.HasPrefix(reqPath, prefix) {
		return false
	}
	return len(reqPath) == len(prefix) || reqPath[len(prefix)] == '/'
}

func (c *basicAuthCache) HasValid(key [32]byte, now time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	exp, ok := c.entries[key]
	if !ok {
		return false
	}
	if !now.Before(exp) {
		delete(c.entries, key)
		return false
	}
	return true
}

func (c *basicAuthCache) Put(key [32]byte, now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.entries) >= maxBasicAuthCache {
		for k, exp := range c.entries {
			if !now.Before(exp) {
				delete(c.entries, k)
			}
		}
		if len(c.entries) >= maxBasicAuthCache {
			clear(c.entries)
		}
	}
	c.entries[key] = now.Add(basicAuthCacheTTL)
}

// BuiltinProxy 实现零外部依赖、低内存占用的内置 Go 反向代理路由器（支持无锁原子热重载、WebSocket、限流、BasicAuth 与安全 SNI TLS）。
type BuiltinProxy struct {
	table             atomic.Pointer[routeTable]
	trustedProxies    atomic.Pointer[[]netip.Prefix]
	transport         *http.Transport
	insecureTransport *http.Transport
	authCache         *basicAuthCache
	sni               *SNICertStore
	now               func() time.Time
}

func newBuiltinProxy(nowFn func() time.Time, sni *SNICertStore) *BuiltinProxy {
	if nowFn == nil {
		nowFn = time.Now
	}
	tr := NewSafeIngressTransport(true)
	insecureTr := tr.Clone()
	insecureTr.TLSClientConfig = &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: true, //nolint:gosec // 仅限单站点显式开启 upstream_tls_insecure 且上游为 https:// 时使用（如 Portainer 自签证书）
	}
	p := &BuiltinProxy{
		transport:         tr,
		insecureTransport: insecureTr,
		authCache:         newBasicAuthCache(),
		sni:               sni,
		now:               nowFn,
	}
	p.table.Store(&routeTable{byHost: map[string][]*compiledRoute{}, loaded: nowFn()})
	return p
}

// SetTrustedProxies 原子更新受信上游代理 CIDR 列表。
func (p *BuiltinProxy) SetTrustedProxies(prefixes []netip.Prefix) {
	if p == nil {
		return
	}
	copied := append([]netip.Prefix(nil), prefixes...)
	p.trustedProxies.Store(&copied)
}

func (p *BuiltinProxy) getTrustedProxies() []netip.Prefix {
	if p == nil {
		return nil
	}
	if ptr := p.trustedProxies.Load(); ptr != nil {
		return *ptr
	}
	return nil
}

// Close 释放共享传输池中的空闲连接。
func (p *BuiltinProxy) Close() {
	if p == nil {
		return
	}
	if p.transport != nil {
		p.transport.CloseIdleConnections()
	}
	if p.insecureTransport != nil {
		p.insecureTransport.CloseIdleConnections()
	}
}

// Reload 无锁原子替换路由表，所有在途请求不受影响且复用有界传输池避免 FD 泄漏。
func (p *BuiltinProxy) Reload(sites []SiteRecord) int {
	next := &routeTable{
		byHost: make(map[string][]*compiledRoute, len(sites)),
		loaded: p.now(),
	}
	for _, s := range sites {
		if !s.Enabled {
			continue
		}
		target, err := url.Parse(s.UpstreamURL)
		if err != nil {
			continue
		}
		siteCopy := s
		routeTransport := p.transport
		if s.UpstreamTLSInsecure && strings.EqualFold(target.Scheme, "https") && p.insecureTransport != nil {
			routeTransport = p.insecureTransport
		}
		rp := &httputil.ReverseProxy{
			Transport: routeTransport,
			Rewrite: func(pr *httputil.ProxyRequest) {
				pr.SetURL(target)
				pr.SetXForwarded()
				pr.Out.Host = target.Host
			},
			ModifyResponse: func(resp *http.Response) error {
				resp.Header.Set("X-Content-Type-Options", "nosniff")
				resp.Header.Set("X-Frame-Options", "SAMEORIGIN")
				for k, v := range siteCopy.ExtraHeaders {
					resp.Header.Set(k, v)
				}
				return nil
			},
			ErrorHandler: func(w http.ResponseWriter, _ *http.Request, err error) {
				var maxErr *http.MaxBytesError
				if errors.As(err, &maxErr) {
					http.Error(w, "Request Entity Too Large", http.StatusRequestEntityTooLarge)
					return
				}
				http.Error(w, "Bad Gateway", http.StatusBadGateway)
			},
		}
		hostKey := strings.ToLower(s.Domain)
		next.byHost[hostKey] = append(next.byHost[hostKey], &compiledRoute{
			site:    siteCopy,
			proxy:   rp,
			limiter: newSiteLimiter(s.RateLimitRPS, s.RateLimitBurst),
		})
		next.totalRoutes++
	}
	// 同域名多路径按 PathPrefix 长度降序排列，最长前缀优先匹配。
	for _, routes := range next.byHost {
		slices.SortFunc(routes, func(a, b *compiledRoute) int {
			if len(a.site.PathPrefix) != len(b.site.PathPrefix) {
				return len(b.site.PathPrefix) - len(a.site.PathPrefix)
			}
			return strings.Compare(a.site.PathPrefix, b.site.PathPrefix)
		})
	}
	p.table.Store(next)
	return next.totalRoutes
}

func (p *BuiltinProxy) ActiveCount() int {
	t := p.table.Load()
	if t == nil {
		return 0
	}
	return t.totalRoutes
}

// ServeHTTP 实现标准 http.Handler，按 Host + 最长 PathPrefix 分发并执行强制 HTTPS、BasicAuth 快表校验、令牌桶限流与反代转发。
func (p *BuiltinProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	host := r.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.ToLower(strings.TrimSpace(host))
	t := p.table.Load()
	if t == nil {
		http.Error(w, "ingress route table unavailable", http.StatusServiceUnavailable)
		return
	}
	candidates := t.byHost[host]
	if len(candidates) == 0 {
		http.NotFound(w, r)
		return
	}
	var rt *compiledRoute
	for _, cand := range candidates {
		if matchPathPrefix(r.URL.Path, cand.site.PathPrefix) {
			rt = cand
			break
		}
	}
	if rt == nil {
		http.NotFound(w, r)
		return
	}
	trusted := p.getTrustedProxies()
	hasHTTPS := p.sni != nil && p.sni.HTTPSListenerActive()
	if rt.site.TLSMode != "off" && ShouldRedirectHTTPS(r, rt.site.ForceHTTPS, hasHTTPS, trusted) {
		target := "https://" + r.Host + r.URL.RequestURI()
		http.Redirect(w, r, target, http.StatusPermanentRedirect)
		return
	}
	now := p.now()
	// 先做 O(1) 令牌桶限流再校验 BasicAuth，防止暴力口令请求耗尽 1C1G CPU。
	if rt.limiter != nil {
		ip := RealClientIP(r, trusted)
		if !rt.limiter.Allow(ip, now) {
			http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
			return
		}
	}
	if rt.site.HasBasicAuth {
		authHdr := r.Header.Get("Authorization")
		user, pass, ok := r.BasicAuth()
		cacheKey := basicAuthCacheKey(rt.site.ID, rt.site.BasicAuthUser, rt.site.BasicAuthHash, user, authHdr)
		if !ok || authHdr == "" || !p.authCache.HasValid(cacheKey, now) {
			userMatch := subtle.ConstantTimeCompare([]byte(user), []byte(rt.site.BasicAuthUser)) == 1
			if !ok || !userMatch || bcrypt.CompareHashAndPassword([]byte(rt.site.BasicAuthHash), []byte(pass)) != nil {
				w.Header().Set("WWW-Authenticate", `Basic realm="qwq-ingress"`)
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}
			p.authCache.Put(cacheKey, now)
		}
	}
	if rt.site.MaxBodyMB > 0 {
		maxBytes := int64(rt.site.MaxBodyMB) << 20
		if r.ContentLength > maxBytes {
			http.Error(w, "Request Entity Too Large", http.StatusRequestEntityTooLarge)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
	}
	rt.proxy.ServeHTTP(w, r)
}

// UpstreamProbeResult 表示对单个反代上游的即时可达性与延迟探测结果。
type UpstreamProbeResult struct {
	SiteID      string `json:"site_id"`
	Domain      string `json:"domain"`
	UpstreamURL string `json:"upstream_url"`
	Reachable   bool   `json:"reachable"`
	StatusCode  int    `json:"status_code,omitempty"`
	LatencyMS   int64  `json:"latency_ms"`
	Error       string `json:"error,omitempty"`
}

func isBlockedUpstreamMetadataIP(ip netip.Addr) bool {
	return isAlwaysBlockedSpecialIP(ip.Unmap())
}

func dialSafeUpstreamProbe(ctx context.Context, network, address string) (net.Conn, error) {
	return dialSafeUpstreamProbeWithResolver(ctx, network, address, net.DefaultResolver.LookupNetIP)
}

func dialSafeUpstreamProbeWithResolver(ctx context.Context, network, address string, lookup netIPLookupFunc) (net.Conn, error) {
	if lookup == nil {
		lookup = net.DefaultResolver.LookupNetIP
	}
	host, portStr, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	host = strings.Trim(host, "[]")
	if strings.EqualFold(host, "metadata.google.internal") {
		return nil, errors.New("blocked cloud metadata host")
	}
	portNum, err := net.LookupPort(network, portStr)
	if err != nil || portNum <= 0 || portNum > 65535 {
		return nil, errors.New("invalid upstream port")
	}
	var addrs []netip.Addr
	if ip, err := netip.ParseAddr(host); err == nil {
		if isBlockedUpstreamMetadataIP(ip) {
			return nil, errors.New("blocked metadata or 100.64.0.0/10 upstream IP")
		}
		addrs = []netip.Addr{ip.Unmap()}
	} else {
		ips, err := lookup(ctx, "ip", host)
		if err != nil {
			return nil, err
		}
		if len(ips) == 0 {
			return nil, errors.New("upstream hostname resolved to no IP addresses")
		}
		for _, ip := range ips {
			u := ip.Unmap()
			if !u.IsValid() || u.IsLoopback() || u.IsPrivate() || isBlockedUpstreamMetadataIP(u) {
				return nil, fmt.Errorf("SSRF_DNS_REBIND_BLOCKED: upstream %s resolved to non-public address %s", host, u)
			}
			addrs = append(addrs, u)
		}
	}
	if len(addrs) == 0 {
		return nil, errors.New("upstream hostname resolved to no IP addresses")
	}
	d := net.Dialer{Timeout: 3 * time.Second}
	var lastErr error
	for _, ip := range addrs {
		conn, err := d.DialContext(ctx, network, netip.AddrPortFrom(ip, uint16(portNum)).String())
		if err == nil {
			return conn, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		return nil, errors.New("upstream dial failed")
	}
	return nil, lastErr
}

var sharedUpstreamProbeClient = &http.Client{
	Timeout: 3 * time.Second,
	Transport: &http.Transport{
		Proxy:               nil,
		DialContext:         dialSafeUpstreamProbe,
		MaxIdleConns:        16,
		MaxIdleConnsPerHost: 2,
		IdleConnTimeout:     30 * time.Second,
		TLSHandshakeTimeout: 3 * time.Second,
	},
	CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	},
}

var sharedInsecureUpstreamProbeClient = &http.Client{
	Timeout: 3 * time.Second,
	Transport: &http.Transport{
		Proxy:               nil,
		DialContext:         dialSafeUpstreamProbe,
		MaxIdleConns:        8,
		MaxIdleConnsPerHost: 2,
		IdleConnTimeout:     30 * time.Second,
		TLSHandshakeTimeout: 3 * time.Second,
		TLSClientConfig: &tls.Config{
			MinVersion:         tls.VersionTLS12,
			InsecureSkipVerify: true, //nolint:gosec // 仅在站点显式开启 upstream_tls_insecure 且目标为 https:// 时探测自签上游
		},
	},
	CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	},
}

func probeUpstream(ctx context.Context, s SiteRecord) UpstreamProbeResult {
	res := UpstreamProbeResult{SiteID: s.ID, Domain: s.Domain, UpstreamURL: s.UpstreamURL}
	pctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	start := time.Now()
	req, err := http.NewRequestWithContext(pctx, http.MethodHead, s.UpstreamURL, nil)
	if err != nil {
		res.Error = err.Error()
		return res
	}
	client := sharedUpstreamProbeClient
	if s.UpstreamTLSInsecure && strings.HasPrefix(strings.ToLower(s.UpstreamURL), "https://") {
		client = sharedInsecureUpstreamProbeClient
	}
	resp, err := client.Do(req)
	res.LatencyMS = time.Since(start).Milliseconds()
	if err != nil {
		res.Error = err.Error()
		return res
	}
	_ = resp.Body.Close()
	res.Reachable = true
	res.StatusCode = resp.StatusCode
	return res
}
