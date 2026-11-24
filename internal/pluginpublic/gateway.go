// SPDX-License-Identifier: AGPL-3.0-only

// Package pluginpublic 实现 ADR-0024 宿主动态公开 HTTP 端点 /p/{plugin_id}/{route}/{subpath...}。
// 同时支撑 Track 04 proxy.advanced 订阅拉取与 Track 09 ai.relay 零缓冲流式 API 中转及独立分发门户 SPA。
package pluginpublic

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ======================== 资源与超时上限 ========================

const (
	DefaultMaxResponseBytes = 4 << 20  // 4 MiB（与 ADR-0024 / ABI 对齐）
	MaxThemeUploadBodyBytes = 3 << 20  // 3 MiB（server.probe 主题包上传上限，兼容 4 MiB gRPC 帧）
	MaxStreamingBodyBytes   = 32 << 20 // 32 MiB（多模态流式 AI 中转请求体上限）
	DefaultBufferedTimeout  = 15 * time.Second
	DefaultStreamTimeout    = 600 * time.Second

	themeSandboxHeader = "X-QWQ-Theme-Sandbox"
	probePortalCSP     = "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob: https:; connect-src 'self'; font-src 'self' data:; frame-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"
	defaultPortalCSP   = "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; font-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"
)

func (g *Gateway) buildThemeSandboxCSP(r *http.Request) string {
	scheme := g.effectiveProto(r)
	host := strings.TrimSpace(r.Host)
	if host == "" || strings.ContainsAny(host, " \t\r\n;\"'<>\\") {
		return "sandbox allow-scripts; default-src 'none'; style-src 'unsafe-inline'; img-src data: blob:; font-src data:; connect-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'self'"
	}
	origin := scheme + "://" + host
	return "sandbox allow-scripts; default-src 'none'; " +
		"script-src " + origin + "; " +
		"style-src 'unsafe-inline' " + origin + "; " +
		"img-src data: blob: " + origin + "; " +
		"font-src data: " + origin + "; " +
		"connect-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'self'"
}

func (g *Gateway) effectiveProto(r *http.Request) string {
	if r.TLS != nil {
		return "https"
	}
	remote := extractRemoteIP(r.RemoteAddr)
	if addr, err := netip.ParseAddr(remote); err == nil && g.isTrustedProxyIP(addr) {
		if strings.EqualFold(strings.TrimSpace(r.Header.Get("X-Forwarded-Proto")), "https") {
			return "https"
		}
	}
	return "http"
}

type ctxFromCustomDomainKey struct{}

func isCustomDomainRequest(r *http.Request) bool {
	v, _ := r.Context().Value(ctxFromCustomDomainKey{}).(bool)
	return v
}

func isThemeSandboxPath(subpath string) bool {
	return subpath == "theme-frame" || strings.HasPrefix(subpath, "theme-frame/")
}

func hasThemeSandboxHeader(headers map[string]string) bool {
	for k, v := range headers {
		if strings.EqualFold(k, themeSandboxHeader) && strings.TrimSpace(v) == "1" {
			return true
		}
	}
	return false
}

// PublicRequest 是剥离了面板管理会话凭据后传递给插件的受控公开请求。
type PublicRequest struct {
	Method          string
	Route           string
	Subpath         string
	Path            string // 以 "/" 开头的规范子路径，如 "/sub/token"
	RawQuery        string
	UserAgent       string
	ContentType     string
	ClientIP        string
	RelayAuthBearer string // 仅透传非面板前缀的业务令牌（sk-qwq-* / rly_sess_*），面板 qwq_* 令牌 100% 过滤
	ExtraHeaders    map[string]string
	Body            []byte
}

// PublicResponse 是缓冲模式下插件返回的公开响应。
type PublicResponse struct {
	StatusCode int
	Headers    map[string]string
	Body       []byte
}

// Dispatcher 分发缓冲型公开路由请求至目标插件。
type Dispatcher interface {
	ServePublicRoute(ctx context.Context, pluginID string, req PublicRequest) (PublicResponse, error)
}

// StreamDispatcher 为需要高并发 POST 与长连接 SSE 流式响应的公开路由（如 ai.relay /v1/*）提供零缓冲直通能力。
type StreamDispatcher interface {
	ServePublicStream(ctx context.Context, pluginID string, req PublicRequest, body io.Reader, w http.ResponseWriter) error
}

// RouteSpec 声明单个插件在 /p/{plugin_id}/{route}/ 下的公开路由策略。
type RouteSpec struct {
	PluginID        string
	Route           string
	AllowedMethods  []string
	RateLimitPerMin int
	MaxReqBytes     int64
	MaxRespBytes    int
	Streaming       bool // 开启 POST 请求体流式读取与 SSE 实时 Flush
	PortalSPA       bool // 开启独立自服务前端门户 CSP（仍剥离宿主 Cookie）
	AllowCORS       bool // 允许跨域 API 调用（供纯浏览器客户端直连 /v1/*）
}

type routeKey struct {
	pluginID string
	route    string
}

type ipBucket struct {
	tokens   float64
	lastNano int64
}

// Gateway 持有原子公开路由表与按源 IP 限流桶。
type Gateway struct {
	dispatcher     Dispatcher
	streamer       StreamDispatcher
	routes         atomic.Pointer[map[routeKey]RouteSpec]
	trustedProxies atomic.Pointer[[]netip.Prefix]

	mu      sync.Mutex
	buckets map[string]*ipBucket
	now     func() time.Time
}

// NewGateway 创建公开路由网关；若 dispatcher 同时实现 StreamDispatcher 则自动启用流式路由支持。
func NewGateway(dispatcher Dispatcher, now func() time.Time) *Gateway {
	if now == nil {
		now = time.Now
	}
	g := &Gateway{
		dispatcher: dispatcher,
		buckets:    make(map[string]*ipBucket),
		now:        now,
	}
	if sd, ok := dispatcher.(StreamDispatcher); ok {
		g.streamer = sd
	}
	empty := make(map[routeKey]RouteSpec)
	g.routes.Store(&empty)
	return g
}

// SetStreamDispatcher 显式绑定或替换流式公开路由分发器。
func (g *Gateway) SetStreamDispatcher(sd StreamDispatcher) {
	g.streamer = sd
}

// SetTrustedProxies configures trusted reverse-proxy CIDRs for client IP extraction.
func (g *Gateway) SetTrustedProxies(prefixes []netip.Prefix) {
	cp := append([]netip.Prefix(nil), prefixes...)
	g.trustedProxies.Store(&cp)
}

// ReplaceRoutes 原子替换公开路由表，插件启停/升级期间在途请求零闪断。
func (g *Gateway) ReplaceRoutes(specs []RouteSpec) {
	next := make(map[routeKey]RouteSpec, len(specs))
	for _, s := range specs {
		if s.PluginID == "" || s.Route == "" || !validSegment(s.PluginID) || !validRouteSegment(s.Route) {
			continue
		}
		if s.RateLimitPerMin <= 0 {
			s.RateLimitPerMin = 60
		}
		if s.MaxRespBytes <= 0 || s.MaxRespBytes > DefaultMaxResponseBytes {
			s.MaxRespBytes = DefaultMaxResponseBytes
		}
		if s.Streaming {
			if s.MaxReqBytes <= 0 || s.MaxReqBytes > MaxStreamingBodyBytes {
				s.MaxReqBytes = MaxStreamingBodyBytes
			}
		} else if s.MaxReqBytes <= 0 || s.MaxReqBytes > DefaultMaxResponseBytes {
			s.MaxReqBytes = DefaultMaxResponseBytes
		}
		if len(s.AllowedMethods) == 0 {
			if s.Streaming || s.PortalSPA {
				s.AllowedMethods = []string{http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodOptions}
			} else {
				s.AllowedMethods = []string{http.MethodGet, http.MethodHead}
			}
		}
		next[routeKey{pluginID: s.PluginID, route: s.Route}] = s
	}
	g.routes.Store(&next)
}

func validSegment(s string) bool {
	if len(s) == 0 || len(s) > 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '.' || c == '-') {
			return false
		}
	}
	return !strings.Contains(s, "..")
}

func validRouteSegment(s string) bool {
	if len(s) == 0 || len(s) > 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-') {
			return false
		}
	}
	return !strings.Contains(s, "..")
}

func (g *Gateway) allowClientIP(key string, perMin int) bool {
	nowNano := g.now().UnixNano()
	ratePerSec := float64(perMin) / 60.0
	burst := float64(max(10, perMin/2))

	g.mu.Lock()
	defer g.mu.Unlock()
	if b, ok := g.buckets[key]; ok {
		elapsed := float64(nowNano-b.lastNano) / 1e9
		if elapsed > 0 {
			b.tokens = min(burst, b.tokens+elapsed*ratePerSec)
			b.lastNano = nowNano
		}
		if b.tokens < 1.0 {
			return false
		}
		b.tokens -= 1.0
		return true
	}
	// 容量触顶时先清理 5 分钟未活跃的陈旧桶；若仍满则按 LRU 淘汰最老非限流桶（避免全局 Fail-Closed 429）。
	if len(g.buckets) >= 8192 {
		staleBefore := nowNano - int64(5*time.Minute)
		for k, b := range g.buckets {
			if b.lastNano < staleBefore {
				delete(g.buckets, k)
			}
		}
		if len(g.buckets) >= 8192 {
			var oldestKey string
			var oldestNano int64
			var oldestNonAbuserKey string
			var oldestNonAbuserNano int64
			for k, b := range g.buckets {
				if oldestKey == "" || b.lastNano < oldestNano {
					oldestKey = k
					oldestNano = b.lastNano
				}
				if b.tokens >= 1.0 && (oldestNonAbuserKey == "" || b.lastNano < oldestNonAbuserNano) {
					oldestNonAbuserKey = k
					oldestNonAbuserNano = b.lastNano
				}
			}
			if oldestNonAbuserKey != "" {
				delete(g.buckets, oldestNonAbuserKey)
			} else if oldestKey != "" {
				delete(g.buckets, oldestKey)
			}
		}
	}
	g.buckets[key] = &ipBucket{tokens: burst - 1, lastNano: nowNano}
	return true
}

var allowedPluginResponseHeaders = map[string]struct{}{
	"Content-Type":            {},
	"Cache-Control":           {},
	"ETag":                    {},
	"Subscription-Userinfo":   {},
	"Profile-Update-Interval": {},
	"Profile-Title":           {},
	"Content-Disposition":     {},
	"Location":                {},
	"X-Request-Id":            {},
	"X-Relay-Request-Id":      {},
	"Anthropic-Version":       {},
	"Vary":                    {},
}

func extractRemoteIP(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return strings.Trim(remoteAddr, "[]")
	}
	return strings.Trim(host, "[]")
}

func (g *Gateway) isTrustedProxyIP(ip netip.Addr) bool {
	unmapped := ip.Unmap()
	if unmapped.IsLoopback() {
		return true
	}
	ptr := g.trustedProxies.Load()
	if ptr == nil {
		return false
	}
	for _, p := range *ptr {
		if p.Contains(unmapped) {
			return true
		}
	}
	return false
}

func (g *Gateway) extractClientIP(r *http.Request) string {
	remote := extractRemoteIP(r.RemoteAddr)
	remoteAddr, err := netip.ParseAddr(remote)
	if err != nil || !g.isTrustedProxyIP(remoteAddr) {
		return remote
	}
	// Merge all X-Forwarded-For headers in order and walk right-to-left so
	// multiple reverse-proxy hops cannot be bypassed via duplicate XFF headers.
	xffValues := r.Header.Values("X-Forwarded-For")
	hasXFF := false
	for i := len(xffValues) - 1; i >= 0; i-- {
		if strings.TrimSpace(xffValues[i]) == "" {
			continue
		}
		hasXFF = true
		parts := strings.Split(xffValues[i], ",")
		for j := len(parts) - 1; j >= 0; j-- {
			cand := strings.TrimSpace(parts[j])
			if cand == "" {
				continue
			}
			addr, perr := netip.ParseAddr(cand)
			if perr != nil {
				return remote
			}
			if !g.isTrustedProxyIP(addr) {
				return addr.Unmap().String()
			}
		}
	}
	if hasXFF {
		return remote
	}
	// Only when no X-Forwarded-For header is present, accept a single valid
	// non-trusted-proxy X-Real-IP value set by a trusted reverse proxy.
	realIPs := r.Header.Values("X-Real-IP")
	if len(realIPs) == 1 {
		if cand := strings.TrimSpace(realIPs[0]); cand != "" {
			if addr, perr := netip.ParseAddr(cand); perr == nil && !g.isTrustedProxyIP(addr) {
				return addr.Unmap().String()
			}
		}
	}
	return remote
}

func rateLimitIPKey(ip string) string {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return ip
	}
	addr = addr.Unmap()
	if addr.Is4() {
		return addr.String()
	}
	p, _ := addr.Prefix(64)
	return p.String()
}

// extractSafePluginToken 仅提取明确属于公开插件业务命名空间（sk-qwq-* / rly_sess_* / prb_*）的令牌；
// 面板管理凭据（Cookie、qwq_* Token、Basic Auth）100% 过滤丢弃。
func extractSafePluginToken(r *http.Request) string {
	auth := strings.TrimSpace(r.Header.Get("Authorization"))
	if len(auth) >= 7 && strings.EqualFold(auth[:7], "bearer ") {
		auth = strings.TrimSpace(auth[7:])
	}
	candidates := []string{
		auth,
		strings.TrimSpace(r.Header.Get("x-api-key")),
		strings.TrimSpace(r.Header.Get("x-goog-api-key")),
		strings.TrimSpace(r.Header.Get("X-Relay-Session")),
		strings.TrimSpace(r.Header.Get("X-Probe-Admin-Token")),
	}
	for _, tok := range candidates {
		if strings.HasPrefix(tok, "sk-qwq-") || strings.HasPrefix(tok, "rly_sess_") ||
			strings.HasPrefix(tok, "prb_adm_") || strings.HasPrefix(tok, "prb_agt_") ||
			strings.HasPrefix(tok, "prb_dlg_") {
			return tok
		}
	}
	return ""
}

// ServeHTTP 处理 /p/{plugin_id}/{route}/{subpath...} 的全部公开请求。
func (g *Gateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h := w.Header()
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Cache-Control", "no-store")

	rawLower := strings.ToLower(r.URL.RawPath)
	trimmed := strings.TrimPrefix(r.URL.Path, "/p/")
	if trimmed == r.URL.Path || strings.Contains(trimmed, "..") || strings.Contains(trimmed, "\\") ||
		strings.Contains(rawLower, "%2e") || strings.Contains(rawLower, "%5c") {
		h.Set("Content-Security-Policy", "default-src 'none'; sandbox")
		http.NotFound(w, r)
		return
	}
	parts := strings.SplitN(trimmed, "/", 3)
	if len(parts) < 2 || !validSegment(parts[0]) || !validRouteSegment(parts[1]) {
		h.Set("Content-Security-Policy", "default-src 'none'; sandbox")
		http.NotFound(w, r)
		return
	}
	pluginID, route := parts[0], parts[1]
	subpath := ""
	if len(parts) == 3 {
		subpath = parts[2]
	}

	table := *g.routes.Load()
	spec, exists := table[routeKey{pluginID: pluginID, route: route}]
	if !exists || (g.dispatcher == nil && g.streamer == nil) {
		h.Set("Content-Security-Policy", "default-src 'none'; sandbox")
		http.NotFound(w, r)
		return
	}

	if (r.Method == http.MethodGet || r.Method == http.MethodHead) &&
		subpath == "" && !strings.HasSuffix(r.URL.Path, "/") && !isCustomDomainRequest(r) {
		target := r.URL.Path + "/"
		if r.URL.RawQuery != "" {
			target += "?" + r.URL.RawQuery
		}
		http.Redirect(w, r, target, http.StatusPermanentRedirect)
		return
	}

	sandboxedTheme := isThemeSandboxPath(subpath)
	if sandboxedTheme && strings.EqualFold(strings.TrimSpace(r.Header.Get("Sec-Fetch-Dest")), "document") {
		target := "/"
		if !isCustomDomainRequest(r) {
			target = "/p/" + pluginID + "/" + route + "/"
		}
		http.Redirect(w, r, target, http.StatusFound)
		return
	}
	if sandboxedTheme {
		h.Set("X-Frame-Options", "SAMEORIGIN")
		h.Set("Content-Security-Policy", g.buildThemeSandboxCSP(r))
	} else if spec.PortalSPA {
		if pluginID == "server.probe" {
			h.Set("Content-Security-Policy", probePortalCSP)
		} else {
			h.Set("Content-Security-Policy", defaultPortalCSP)
		}
	} else {
		h.Set("Content-Security-Policy", "default-src 'none'; sandbox")
	}

	if spec.AllowCORS {
		h.Set("Access-Control-Allow-Origin", "*")
		h.Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		h.Set("Access-Control-Allow-Headers", "Authorization, Content-Type, x-api-key, anthropic-version, anthropic-beta, x-goog-api-key, OpenAI-Beta, X-Relay-Session")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
	}

	if !slices.Contains(spec.AllowedMethods, r.Method) {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	clientIP := g.extractClientIP(r)
	bucketScope := route
	if subpath == "admin" || strings.HasPrefix(subpath, "admin/") ||
		subpath == "api/admin" || strings.HasPrefix(subpath, "api/admin/") {
		bucketScope = route + ":admin"
	}
	if !g.allowClientIP(rateLimitIPKey(clientIP)+"|"+pluginID+"|"+bucketScope, spec.RateLimitPerMin) {
		w.WriteHeader(http.StatusTooManyRequests)
		return
	}

	reqPath := "/" + route
	if subpath != "" {
		reqPath += "/" + subpath
	}
	var safeToken string
	if spec.Streaming || spec.PortalSPA || (pluginID == "server.probe" && route == "agent") {
		safeToken = extractSafePluginToken(r)
	}
	pubReq := PublicRequest{
		Method:          r.Method,
		Route:           route,
		Subpath:         subpath,
		Path:            reqPath,
		RawQuery:        r.URL.RawQuery,
		UserAgent:       r.Header.Get("User-Agent"),
		ContentType:     r.Header.Get("Content-Type"),
		ClientIP:        clientIP,
		RelayAuthBearer: safeToken,
		ExtraHeaders: map[string]string{
			"Host":                  r.Host,
			"X-Forwarded-Host":      r.Host,
			"X-Forwarded-Proto":     g.effectiveProto(r),
			"If-None-Match":         r.Header.Get("If-None-Match"),
			"anthropic-version":     r.Header.Get("anthropic-version"),
			"anthropic-beta":        r.Header.Get("anthropic-beta"),
			"X-Session-ID":          r.Header.Get("X-Session-ID"),
			"X-Probe-Admin-Token":   r.Header.Get("X-Probe-Admin-Token"),
			"X-Probe-Visitor-Token": r.Header.Get("X-Probe-Visitor-Token"),
		},
	}

	maxReqBytes := spec.MaxReqBytes
	if pluginID == "server.probe" && subpath == "api/admin/themes/upload" {
		maxReqBytes = MaxThemeUploadBodyBytes
	}

	if spec.Streaming && g.streamer != nil {
		rc := http.NewResponseController(w)
		// Keep a bounded per-write deadline on streaming responses (refreshed on
		// every Write/Flush) so slowloris peers cannot pin stream slots forever,
		// while keeping a 60s read deadline during body upload.
		_ = rc.SetWriteDeadline(time.Now().Add(streamPerWriteTimeout))
		ctx, cancel := context.WithTimeout(r.Context(), DefaultStreamTimeout)
		defer cancel()
		var streamBody io.ReadCloser = http.MaxBytesReader(w, r.Body, maxReqBytes)
		if r.Body != nil && r.Body != http.NoBody && r.ContentLength != 0 {
			_ = rc.SetReadDeadline(time.Now().Add(60 * time.Second))
			streamBody = &deadlineClearingReader{ReadCloser: streamBody, rc: rc}
		} else {
			_ = rc.SetReadDeadline(time.Time{})
		}
		defer streamBody.Close()
		boundedW := &deadlineResponseWriter{ResponseWriter: w, rc: rc, writeTimeout: streamPerWriteTimeout}
		if err := g.streamer.ServePublicStream(ctx, pluginID, pubReq, streamBody, boundedW); err != nil {
			http.Error(w, "upstream gateway error", http.StatusBadGateway)
		}
		return
	}

	if g.dispatcher == nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}

	if (r.Method == http.MethodGet || r.Method == http.MethodHead) && r.ContentLength > 0 {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	if r.Body != nil && r.Method != http.MethodGet && r.Method != http.MethodHead {
		bodyBytes, err := io.ReadAll(io.LimitReader(r.Body, maxReqBytes+1))
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if int64(len(bodyBytes)) > maxReqBytes {
			w.WriteHeader(http.StatusRequestEntityTooLarge)
			return
		}
		pubReq.Body = bodyBytes
	}

	timeout := DefaultBufferedTimeout
	if spec.Streaming {
		timeout = DefaultStreamTimeout
	}
	ctx, cancel := context.WithTimeout(r.Context(), timeout)
	defer cancel()

	resp, err := g.dispatcher.ServePublicRoute(ctx, pluginID, pubReq)
	if err != nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	if len(resp.Body) > spec.MaxRespBytes {
		w.WriteHeader(http.StatusBadGateway)
		return
	}

	if !sandboxedTheme && hasThemeSandboxHeader(resp.Headers) {
		h.Set("X-Frame-Options", "SAMEORIGIN")
		h.Set("Content-Security-Policy", g.buildThemeSandboxCSP(r))
	}
	for k, v := range resp.Headers {
		canon := http.CanonicalHeaderKey(k)
		if _, ok := allowedPluginResponseHeaders[canon]; ok {
			h.Set(canon, v)
		}
	}
	statusCode := resp.StatusCode
	if statusCode < 100 || statusCode > 599 {
		statusCode = http.StatusOK
	}
	w.WriteHeader(statusCode)
	if r.Method != http.MethodHead && len(resp.Body) > 0 {
		_, _ = w.Write(resp.Body)
	}
}

const streamPerWriteTimeout = 30 * time.Second

type deadlineResponseWriter struct {
	http.ResponseWriter
	rc           *http.ResponseController
	writeTimeout time.Duration
}

func (d *deadlineResponseWriter) Unwrap() http.ResponseWriter {
	return d.ResponseWriter
}

func (d *deadlineResponseWriter) refreshWriteDeadline() {
	if d.rc != nil && d.writeTimeout > 0 {
		_ = d.rc.SetWriteDeadline(time.Now().Add(d.writeTimeout))
	}
}

func (d *deadlineResponseWriter) WriteHeader(code int) {
	d.refreshWriteDeadline()
	d.ResponseWriter.WriteHeader(code)
}

func (d *deadlineResponseWriter) Write(p []byte) (int, error) {
	d.refreshWriteDeadline()
	return d.ResponseWriter.Write(p)
}

func (d *deadlineResponseWriter) Flush() {
	d.refreshWriteDeadline()
	if f, ok := d.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

type deadlineClearingReader struct {
	io.ReadCloser
	rc      *http.ResponseController
	cleared atomic.Bool
}

func (d *deadlineClearingReader) clearDeadline() {
	if d.cleared.CompareAndSwap(false, true) && d.rc != nil {
		_ = d.rc.SetReadDeadline(time.Time{})
	}
}

func (d *deadlineClearingReader) Read(p []byte) (int, error) {
	n, err := d.ReadCloser.Read(p)
	if err != nil {
		d.clearDeadline()
	}
	return n, err
}

func (d *deadlineClearingReader) Close() error {
	d.clearDeadline()
	return d.ReadCloser.Close()
}
