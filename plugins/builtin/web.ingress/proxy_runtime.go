// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"crypto/subtle"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/bcrypt"
)

const maxRateLimitIPs = 4096

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
	byHost map[string]*compiledRoute
	loaded time.Time
}

// BuiltinProxy 实现零外部依赖、低内存占用的内置 Go 反向代理路由器（支持无锁原子热重载、WebSocket、限流与 BasicAuth）。
type BuiltinProxy struct {
	table     atomic.Pointer[routeTable]
	transport *http.Transport
	now       func() time.Time
}

func newBuiltinProxy(nowFn func() time.Time) *BuiltinProxy {
	if nowFn == nil {
		nowFn = time.Now
	}
	tr := &http.Transport{
		Proxy:               http.ProxyFromEnvironment,
		DialContext:         (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		MaxIdleConns:        32,
		MaxIdleConnsPerHost: 8,
		IdleConnTimeout:     60 * time.Second,
		TLSHandshakeTimeout: 5 * time.Second,
	}
	p := &BuiltinProxy{transport: tr, now: nowFn}
	p.table.Store(&routeTable{byHost: map[string]*compiledRoute{}, loaded: nowFn()})
	return p
}

// Close 释放共享传输池中的空闲连接。
func (p *BuiltinProxy) Close() {
	if p != nil && p.transport != nil {
		p.transport.CloseIdleConnections()
	}
}

// Reload 无锁原子替换路由表，所有在途请求不受影响且复用有界传输池避免 FD 泄漏。
func (p *BuiltinProxy) Reload(sites []SiteRecord) int {
	next := &routeTable{
		byHost: make(map[string]*compiledRoute, len(sites)),
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
		rp := &httputil.ReverseProxy{
			Transport: p.transport,
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
		}
		next.byHost[strings.ToLower(s.Domain)] = &compiledRoute{
			site:    siteCopy,
			proxy:   rp,
			limiter: newSiteLimiter(s.RateLimitRPS, s.RateLimitBurst),
		}
	}
	p.table.Store(next)
	return len(next.byHost)
}

func (p *BuiltinProxy) ActiveCount() int {
	t := p.table.Load()
	if t == nil {
		return 0
	}
	return len(t.byHost)
}

// ServeHTTP 实现标准 http.Handler，按 Host 分发并执行强制 HTTPS、BasicAuth、令牌桶限流与反代转发。
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
	rt, ok := t.byHost[host]
	if !ok {
		http.NotFound(w, r)
		return
	}
	if rt.site.PathPrefix != "/" && !strings.HasPrefix(r.URL.Path, rt.site.PathPrefix) {
		http.NotFound(w, r)
		return
	}
	if rt.site.TLSMode != "off" && rt.site.ForceHTTPS && r.TLS == nil && !strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https") {
		target := "https://" + r.Host + r.URL.RequestURI()
		http.Redirect(w, r, target, http.StatusPermanentRedirect)
		return
	}
	// 先做 O(1) 令牌桶限流再校验 bcrypt BasicAuth，防止暴力口令请求耗尽 1C1G CPU。
	if rt.limiter != nil {
		ip, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			ip = r.RemoteAddr
		}
		if !rt.limiter.Allow(ip, p.now()) {
			http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
			return
		}
	}
	if rt.site.HasBasicAuth {
		user, pass, ok := r.BasicAuth()
		userMatch := subtle.ConstantTimeCompare([]byte(user), []byte(rt.site.BasicAuthUser)) == 1
		if !ok || !userMatch || bcrypt.CompareHashAndPassword([]byte(rt.site.BasicAuthHash), []byte(pass)) != nil {
			w.Header().Set("WWW-Authenticate", `Basic realm="qwq-ingress"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
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
	client := &http.Client{
		Timeout: 3 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
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
