// SPDX-License-Identifier: AGPL-3.0-only

// Package pluginpublic 实现 ADR-0024 宿主动态公开 HTTP 端点 /p/{plugin_id}/{route}/{subpath...}。
// 同时支撑 Track 04 proxy.advanced 订阅拉取与 Track 09 ai.relay 零缓冲流式 API 中转及独立分发门户 SPA。
package pluginpublic

import (
	"context"
	"io"
	"net"
	"net/http"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ======================== 资源与超时上限 ========================

const (
	DefaultMaxResponseBytes = 4 << 20  // 4 MiB（与 ADR-0024 / ABI 对齐）
	MaxStreamingBodyBytes   = 32 << 20 // 32 MiB（多模态流式 AI 中转请求体上限）
	DefaultBufferedTimeout  = 15 * time.Second
	DefaultStreamTimeout    = 600 * time.Second
)

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
	dispatcher Dispatcher
	streamer   StreamDispatcher
	routes     atomic.Pointer[map[routeKey]RouteSpec]

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
	// 容量触顶时先清理 5 分钟未活跃的陈旧桶，绝不清空仍在活跃限流中的桶，防止 DDoS 重置限流配额。
	if len(g.buckets) >= 8192 {
		staleBefore := nowNano - int64(5*time.Minute)
		for k, b := range g.buckets {
			if b.lastNano < staleBefore {
				delete(g.buckets, k)
			}
		}
		if len(g.buckets) >= 8192 {
			return false
		}
	}
	g.buckets[key] = &ipBucket{tokens: burst - 1, lastNano: nowNano}
	return true
}

var allowedPluginResponseHeaders = map[string]struct{}{
	"Content-Type":            {},
	"Subscription-Userinfo":   {},
	"Profile-Update-Interval": {},
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
		return remoteAddr
	}
	return host
}

// extractSafePluginToken 仅提取明确属于公开插件业务命名空间（sk-qwq-* / rly_sess_* / prb_*）的令牌；
// 面板管理凭据（Cookie、qwq_* Token、Basic Auth）100% 过滤丢弃。
func extractSafePluginToken(r *http.Request) string {
	candidates := []string{
		strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")),
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

	if spec.PortalSPA {
		h.Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; font-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
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

	clientIP := extractRemoteIP(r.RemoteAddr)
	if !g.allowClientIP(clientIP+"|"+pluginID+"|"+route, spec.RateLimitPerMin) {
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
			"anthropic-version":     r.Header.Get("anthropic-version"),
			"anthropic-beta":        r.Header.Get("anthropic-beta"),
			"X-Session-ID":          r.Header.Get("X-Session-ID"),
			"X-Probe-Admin-Token":   r.Header.Get("X-Probe-Admin-Token"),
			"X-Probe-Visitor-Token": r.Header.Get("X-Probe-Visitor-Token"),
		},
	}

	if spec.Streaming && g.streamer != nil {
		ctx, cancel := context.WithTimeout(r.Context(), DefaultStreamTimeout)
		defer cancel()
		limitedBody := http.MaxBytesReader(w, r.Body, spec.MaxReqBytes)
		defer limitedBody.Close()
		if err := g.streamer.ServePublicStream(ctx, pluginID, pubReq, limitedBody, w); err != nil {
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
		bodyBytes, err := io.ReadAll(io.LimitReader(r.Body, spec.MaxReqBytes+1))
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if int64(len(bodyBytes)) > spec.MaxReqBytes {
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
