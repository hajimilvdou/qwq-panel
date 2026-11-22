// SPDX-License-Identifier: AGPL-3.0-only

// 落盘目标路径：internal/pluginpublic/custom_domain_router.go
// 作用：为 server.probe 等拥有「对外展示页 / 独立门户」的插件提供独立自定义域名根路径直达路由（如 https://status.example.com/），
// 同时实现与 qwq 面板管理面（/api/v1/*、WebShell、Session Cookie）的 100% 物理隔离。
//
// 核心安全铁律：
// 1. 严禁注册与宿主管理面 PublicOrigins 相同的域名（防管理面自锁）；
// 2. 先经 path.Clean 规范化路径，拒绝任何含 ".." 或 "//" 的未规范化探测请求，100% 阻断通过 /foo/../api/v1 绕过主面板屏蔽；
// 3. 通过插件独立域名进入的所有请求，强制剥离 Cookie 与面板 Authorization: Bearer qwq_* / X-QWQ-CSRF 头；
// 4. 原子指针（atomic.Pointer）无锁读取，未绑定域名时零额外分配直通原面板网关。

package pluginpublic

import (
	"errors"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"path"
	"strings"
	"sync/atomic"
)

var (
	ErrDomainConflictsPanelOrigin = errors.New("custom domain conflicts with panel management public origin")
	ErrInvalidCustomDomain        = errors.New("custom domain must be a valid ASCII/IDNA FQDN and not an IP or localhost")
)

// DomainBinding 描述一条已授权的插件独立域名绑定记录。
type DomainBinding struct {
	Domain      string // 规范化小写 FQDN，如 "status.example.com"
	PluginID    string // 如 "server.probe"
	PortalRoute string // 默认 "portal"（承载根路径 / 与 /api/public/*、/api/admin/*、/api/ai/*）
	AgentRoute  string // 默认 "agent"（承载 /api/probe/v1/report 单向上报）
}

// CustomDomainRouter 在宿主 HTTP 入口按 Host 分流插件独占域名与主面板域名。
type CustomDomainRouter struct {
	panelHosts     map[string]struct{}
	trustedProxies []netip.Prefix
	publicGW       http.Handler
	panelNext      http.Handler
	bindings       atomic.Pointer[map[string]DomainBinding]
}

// NewCustomDomainRouter 创建独立域名分流器。
func NewCustomDomainRouter(panelHosts []string, trustedProxies []netip.Prefix, publicGW, panelNext http.Handler) *CustomDomainRouter {
	ph := make(map[string]struct{}, len(panelHosts))
	for _, raw := range panelHosts {
		if h := canonicalDomain(raw); h != "" {
			ph[h] = struct{}{}
		}
	}
	r := &CustomDomainRouter{
		panelHosts:     ph,
		trustedProxies: trustedProxies,
		publicGW:       publicGW,
		panelNext:      panelNext,
	}
	empty := make(map[string]DomainBinding)
	r.bindings.Store(&empty)
	return r
}

// ValidateAndReplace 原子替换独立域名路由表，拦截任何试图抢占主面板管理域名的配置。
func (r *CustomDomainRouter) ValidateAndReplace(items []DomainBinding) error {
	next := make(map[string]DomainBinding, len(items))
	for _, item := range items {
		dom := canonicalDomain(item.Domain)
		if !isValidPublicFQDN(dom) {
			return ErrInvalidCustomDomain
		}
		if _, conflict := r.panelHosts[dom]; conflict {
			return ErrDomainConflictsPanelOrigin
		}
		if item.PortalRoute == "" {
			item.PortalRoute = "portal"
		}
		if item.AgentRoute == "" {
			item.AgentRoute = "agent"
		}
		item.Domain = dom
		next[dom] = item
	}
	r.bindings.Store(&next)
	return nil
}

// Lookup 供 tlsmgr/SNI 选择器按 ClientHello ServerName 判断是否为已登记的插件域名。
func (r *CustomDomainRouter) Lookup(serverName string) (DomainBinding, bool) {
	dom := canonicalDomain(serverName)
	if dom == "" {
		return DomainBinding{}, false
	}
	table := *r.bindings.Load()
	b, ok := table[dom]
	return b, ok
}

func (r *CustomDomainRouter) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	host := r.effectiveHost(req)
	table := *r.bindings.Load()
	binding, matched := table[host]
	if !matched {
		r.panelNext.ServeHTTP(w, req)
		return
	}

	// 命中插件独立域名（如 status.example.com）：
	// 1. 先拦截包含点段穿越或双斜杠的异常路径，并物理屏蔽一切宿主管理与静态特征路径
	rawPath := req.URL.Path
	if rawPath == "" {
		rawPath = "/"
	}
	cleanPath := path.Clean("/" + strings.TrimPrefix(rawPath, "/"))
	if strings.Contains(rawPath, "..") ||
		cleanPath == "/api/v1" || strings.HasPrefix(cleanPath, "/api/v1/") ||
		cleanPath == "/plugin-ui" || strings.HasPrefix(cleanPath, "/plugin-ui/") ||
		cleanPath == "/healthz" || cleanPath == "/readyz" {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Cache-Control", "no-store")
		http.NotFound(w, req)
		return
	}

	// 2. 彻底剥离浏览器可能携带的任何 Cookie 及宿主管理令牌，仅保留探针专属头
	cloned := req.Clone(req.Context())
	cloned.Header.Del("Cookie")
	cloned.Header.Del("Proxy-Authorization")
	cloned.Header.Del("X-QWQ-CSRF")
	if auth := strings.TrimSpace(cloned.Header.Get("Authorization")); strings.HasPrefix(auth, "Bearer qwq_") {
		cloned.Header.Del("Authorization")
	}

	// 3. 将独立域名根路径重写至宿主标准 /p/{plugin_id}/{route}/... 管线复用限流与安全头
	targetRoute := binding.PortalRoute
	sub := strings.TrimPrefix(cleanPath, "/")
	if cleanPath == "/api/probe" || strings.HasPrefix(cleanPath, "/api/probe/") {
		targetRoute = binding.AgentRoute
		sub = strings.TrimPrefix(cleanPath, "/api/probe")
		sub = strings.TrimPrefix(sub, "/")
	}
	rewritten := "/p/" + binding.PluginID + "/" + targetRoute
	if sub != "" {
		rewritten += "/" + sub
	}
	cloned.URL.Path = rewritten
	cloned.RequestURI = ""
	r.publicGW.ServeHTTP(w, cloned)
}

func (r *CustomDomainRouter) effectiveHost(req *http.Request) string {
	host := canonicalDomain(req.Host)
	remoteIP, err := netip.ParseAddr(stripPort(req.RemoteAddr))
	if err == nil && r.isTrustedProxy(remoteIP.Unmap()) {
		// 拒绝多值拼接的歧义 X-Forwarded-Host，仅在单值合法时采信可信反代透传的 Host
		xfhValues := req.Header.Values("X-Forwarded-Host")
		if len(xfhValues) == 1 && !strings.Contains(xfhValues[0], ",") {
			if fh := canonicalDomain(xfhValues[0]); fh != "" {
				host = fh
			}
		}
	}
	return host
}

func (r *CustomDomainRouter) isTrustedProxy(ip netip.Addr) bool {
	for _, p := range r.trustedProxies {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

func stripPort(hostport string) string {
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		return h
	}
	return strings.Trim(hostport, "[]")
}

func canonicalDomain(raw string) string {
	s := strings.TrimSpace(raw)
	if strings.Contains(s, "://") {
		if u, err := url.Parse(s); err == nil && u.Host != "" {
			s = u.Host
		}
	}
	h := strings.TrimSpace(strings.ToLower(stripPort(s)))
	return strings.TrimSuffix(h, ".")
}

func isValidPublicFQDN(dom string) bool {
	if len(dom) < 4 || len(dom) > 253 || dom == "localhost" || !strings.Contains(dom, ".") {
		return false
	}
	if _, err := netip.ParseAddr(dom); err == nil {
		return false
	}
	labels := strings.Split(dom, ".")
	for _, lb := range labels {
		if len(lb) == 0 || len(lb) > 63 || lb[0] == '-' || lb[len(lb)-1] == '-' {
			return false
		}
		for i := 0; i < len(lb); i++ {
			c := lb[i]
			if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-') {
				return false
			}
		}
	}
	return true
}
