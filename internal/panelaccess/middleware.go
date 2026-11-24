// SPDX-License-Identifier: AGPL-3.0-only

package panelaccess

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"path"
	"strings"

	"github.com/qwq-panel/qwq/internal/platform/config"
)

const (
	nginx404Body = "<html>\r\n<head><title>404 Not Found</title></head>\r\n<body>\r\n<center><h1>404 Not Found</h1></center>\r\n<hr><center>nginx</center>\r\n</body>\r\n</html>\r\n"
	nginx403Body = "<html>\r\n<head><title>403 Forbidden</title></head>\r\n<body>\r\n<center><h1>403 Forbidden</h1></center>\r\n<hr><center>nginx</center>\r\n</body>\r\n</html>\r\n"
)

// PluginUIPathToken generates a stateless 128-bit HMAC capability token for
// loading sandbox="allow-scripts" plugin iframe sub-resources without exposing
// the raw secret entry path. Rotating EntryPath invalidates it immediately.
func (s Snapshot) PluginUIPathToken() string {
	ep := config.NormalizeEntryPath(s.EntryPath)
	if ep == "" || s.GateSecret == "" {
		return ""
	}
	mac := hmac.New(sha256.New, []byte(s.GateSecret))
	mac.Write([]byte("plugin-ui:"))
	mac.Write([]byte(ep))
	return hex.EncodeToString(mac.Sum(nil)[:16])
}

// DecoratePluginUIEntryURL wraps /plugin-ui/... URLs with /_u/<tok>/plugin-ui/...
// whenever a secret entry path is configured so sandboxed iframes (opaque origin,
// no SameSite=Lax _g cookie) can load relative JS/CSS sub-resources cleanly.
func (s Snapshot) DecoratePluginUIEntryURL(entryURL string) string {
	if config.NormalizeEntryPath(s.EntryPath) == "" || !strings.HasPrefix(entryURL, "/plugin-ui/") {
		return entryURL
	}
	tok := s.PluginUIPathToken()
	if tok == "" {
		return entryURL
	}
	return "/_u/" + tok + entryURL
}

// WrapOptions configures trusted proxies and public/loopback exemptions for the
// stealth entry-path gate.
type WrapOptions struct {
	// TrustedProxies lists reverse-proxy CIDRs allowed to forward
	// X-Forwarded-Host and X-Forwarded-Proto.
	TrustedProxies []netip.Prefix
	// ExemptPublicPluginRoutes allows /p/{plugin_id}/... public routes
	// (subscriptions, AI relay, probe ingest) to bypass the admin secret path.
	ExemptPublicPluginRoutes bool
	// ExemptLoopbackHealth allows direct loopback (127.0.0.1/::1) /healthz
	// and /readyz probes without the secret path prefix.
	ExemptLoopbackHealth bool
}

// Wrap installs the stealth entry-path gate with default exemptions.
func (m *Manager) Wrap(next http.Handler) http.Handler {
	return m.WrapWithOptions(next, WrapOptions{
		ExemptPublicPluginRoutes: true,
		ExemptLoopbackHealth:     true,
	})
}

// WrapWithOptions installs the stealth entry-path gate and disguise handler.
// In cmd/qwq/serve.go, CustomDomainRouter must wrap this handler on the outside
// so plugin custom domains (e.g. status.example.com) are routed first while
// panel traffic falls through to this gate.
func (m *Manager) WrapWithOptions(next http.Handler, opts WrapOptions) http.Handler {
	if m == nil {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		snap := m.Snapshot()
		rawEntry := config.NormalizeEntryPath(snap.EntryPath)

		// 1. Direct loopback health probes (cannot be spoofed via XFF).
		if opts.ExemptLoopbackHealth && (r.URL.Path == "/healthz" || r.URL.Path == "/readyz") && isLoopbackRemote(r.RemoteAddr) {
			next.ServeHTTP(w, r)
			return
		}

		// 2. Public sessionless plugin routes (/p/...) bypass admin secret path.
		if opts.ExemptPublicPluginRoutes && isCleanPublicPluginSubtree(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}

		// 3. No secret entry path configured -> pass through directly.
		if rawEntry == "" {
			next.ServeHTTP(w, r)
			return
		}

		// 4. Stateless HMAC capability prefix /_u/<tok>/plugin-ui/... for sandboxed
		// plugin iframes (must run before domain bypass so decorated URLs work on
		// both authorized domains and bare-IP rescue sessions).
		if strings.HasPrefix(r.URL.Path, "/_u/") && (r.Method == http.MethodGet || r.Method == http.MethodHead) {
			restAfterU := strings.TrimPrefix(r.URL.Path, "/_u/")
			if slash := strings.IndexByte(restAfterU, '/'); slash > 0 {
				gotTok := restAfterU[:slash]
				subPath := restAfterU[slash:]
				wantTok := snap.PluginUIPathToken()
				if wantTok != "" && hmac.Equal([]byte(wantTok), []byte(gotTok)) &&
					strings.HasPrefix(subPath, "/plugin-ui/") && !strings.Contains(subPath, "..") {
					r2 := r.Clone(r.Context())
					u := *r.URL
					u.Path = subPath
					u.RawPath = ""
					r2.URL = &u
					next.ServeHTTP(w, r2)
					return
				}
			}
		}

		// 5. Auto-disable gate ONLY when the trusted request Host matches an
		// authorized panel domain (never when probing the origin's bare IP!).
		if snap.AutoDisableOnDomain && requestMatchesAuthorizedDomain(r, snap, opts.TrustedProxies) {
			next.ServeHTTP(w, r)
			return
		}

		prefix := "/" + rawEntry
		// Case 1: Request enters with the valid secret path prefix (/<rawEntry> or /<rawEntry>/...).
		if r.URL.Path == prefix || strings.HasPrefix(r.URL.Path, prefix+"/") {
			rest := strings.TrimPrefix(r.URL.Path, prefix)
			if rest == "" {
				rest = "/"
			}
			// Block protocol-relative open redirect (/<entry>//evil.com) and backslashes.
			for strings.HasPrefix(rest, "//") {
				rest = rest[1:]
			}
			if !strings.HasPrefix(rest, "/") || strings.Contains(rest, "\\") {
				serveDisguiseSafe(w, r, snap)
				return
			}
			if isDirectSubpath(rest) {
				r2 := r.Clone(r.Context())
				u := *r.URL
				u.Path = rest
				u.RawPath = ""
				r2.URL = &u
				next.ServeHTTP(w, r2)
				return
			}
			// Browser navigation to /<entryPath>: issue HMAC gate cookie and 302 redirect.
			// In tls_mode="proxy" over plain HTTP (before TLS reverse proxy is wired),
			// avoid setting Secure so the browser does not drop _g and loop.
			secureCookie := ShouldUseSecureGateCookie(snap.TLSMode, r, opts.TrustedProxies)
			snap.SetGateCookieForPath(w, rawEntry, secureCookie)
			target := rest
			if r.URL.RawQuery != "" {
				target += "?" + r.URL.RawQuery
			}
			http.Redirect(w, r, target, http.StatusFound)
			return
		}

		// Case 2: Request carries a valid gate cookie matching rawEntry.
		if c, err := r.Cookie(GateCookieName); err == nil && snap.ValidGateCookieForPath(rawEntry, c.Value) {
			next.ServeHTTP(w, r)
			return
		}

		// Case 3: Unauthorized probe -> zero-fingerprint disguise.
		serveDisguiseSafe(w, r, snap)
	})
}

func isDirectSubpath(p string) bool {
	for _, pfx := range []string{"/api", "/healthz", "/readyz", "/plugin-ui", "/p"} {
		if p == pfx || strings.HasPrefix(p, pfx+"/") {
			return true
		}
	}
	return false
}

// serveDisguiseSafe enforces CSP sandbox on custom HTML disguise pages to
// prevent same-origin stored XSS, and delegates other modes to serveDisguise.
func serveDisguiseSafe(w http.ResponseWriter, r *http.Request, snap Snapshot) {
	if snap.EffectiveDisguise() == config.DisguiseCustomHTML {
		clearHeaders(w.Header())
		body := snap.DisguiseHTML
		if body == "" {
			body = nginx404Body
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; img-src data:; sandbox")
		w.WriteHeader(http.StatusOK)
		if r.Method != http.MethodHead {
			_, _ = w.Write([]byte(body))
		}
		return
	}
	serveDisguise(w, r, snap)
}

// serveDisguise answers unauthorized wrong-path probes with zero qwq
// fingerprints in status, headers, cookies, or body.
func serveDisguise(w http.ResponseWriter, r *http.Request, snap Snapshot) {
	switch snap.EffectiveDisguise() {
	case config.DisguiseDrop:
		dropConnection(w)
	case config.DisguiseNginx404:
		clearHeaders(w.Header())
		w.Header().Set("Server", "nginx")
		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("Connection", "close")
		w.WriteHeader(http.StatusNotFound)
		if r.Method != http.MethodHead {
			_, _ = w.Write([]byte(nginx404Body))
		}
	case config.DisguiseNginx403:
		clearHeaders(w.Header())
		w.Header().Set("Server", "nginx")
		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("Connection", "close")
		w.WriteHeader(http.StatusForbidden)
		if r.Method != http.MethodHead {
			_, _ = w.Write([]byte(nginx403Body))
		}
	case config.DisguiseBlank404:
		clearHeaders(w.Header())
		w.Header().Set("Connection", "close")
		w.Header().Set("Content-Length", "0")
		w.WriteHeader(http.StatusNotFound)
	case config.DisguiseCustomHTML:
		serveDisguiseSafe(w, r, snap)
	default:
		dropConnection(w)
	}
}

func requestMatchesAuthorizedDomain(r *http.Request, snap Snapshot, trusted []netip.Prefix) bool {
	if snap.TLSMode == config.TLSProxy {
		if isLoopbackRemote(r.RemoteAddr) || isRemoteTrustedProxy(r.RemoteAddr, trusted) {
			if snap.PanelDomain == "" && len(snap.PublicOrigins) == 0 {
				return true
			}
		} else {
			return false
		}
	}

	reqHost := effectiveRequestHost(r, trusted)
	if reqHost == "" {
		return false
	}
	if _, err := netip.ParseAddr(reqHost); err == nil {
		return false
	}
	if reqHost == "localhost" {
		return false
	}

	if pd := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(snap.PanelDomain), ".")); pd != "" {
		if reqHost == pd {
			return true
		}
	}
	for _, orig := range snap.PublicOrigins {
		if u, err := url.Parse(orig); err == nil {
			oh := strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
			if oh != "" && oh != "localhost" && reqHost == oh {
				if _, ipErr := netip.ParseAddr(oh); ipErr != nil {
					return true
				}
			}
		}
	}
	return false
}

func effectiveRequestHost(r *http.Request, trusted []netip.Prefix) string {
	host := stripHostPortLower(r.Host)
	if isRemoteTrustedProxy(r.RemoteAddr, trusted) {
		xfh := r.Header.Values("X-Forwarded-Host")
		if len(xfh) == 1 && !strings.Contains(xfh[0], ",") {
			if h := stripHostPortLower(xfh[0]); h != "" {
				host = h
			}
		}
	}
	return strings.TrimSuffix(host, ".")
}

func stripHostPortLower(raw string) string {
	s := strings.TrimSpace(strings.ToLower(raw))
	if s == "" {
		return ""
	}
	if h, _, err := net.SplitHostPort(s); err == nil {
		return strings.Trim(h, "[]")
	}
	return strings.Trim(s, "[]")
}

func isLoopbackRemote(remoteAddr string) bool {
	h := stripHostPortLower(remoteAddr)
	ip, err := netip.ParseAddr(h)
	return err == nil && ip.Unmap().IsLoopback()
}

func isRemoteTrustedProxy(remoteAddr string, trusted []netip.Prefix) bool {
	if isLoopbackRemote(remoteAddr) {
		return true
	}
	h := stripHostPortLower(remoteAddr)
	ip, err := netip.ParseAddr(h)
	if err != nil {
		return false
	}
	ip = ip.Unmap()
	for _, p := range trusted {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

// ParseTrustedProxies parses raw IP/CIDR strings into netip.Prefix slices.
func ParseTrustedProxies(raws []string) []netip.Prefix {
	if len(raws) == 0 {
		return nil
	}
	out := make([]netip.Prefix, 0, len(raws))
	for _, raw := range raws {
		s := strings.TrimSpace(raw)
		if s == "" {
			continue
		}
		if p, err := netip.ParsePrefix(s); err == nil {
			out = append(out, p)
			continue
		}
		if a, err := netip.ParseAddr(s); err == nil {
			u := a.Unmap()
			out = append(out, netip.PrefixFrom(u, u.BitLen()))
		}
	}
	return out
}

// ShouldUseSecureGateCookie determines whether the stealth entry-gate cookie
// (_g) should carry the Secure attribute for this request.
func ShouldUseSecureGateCookie(tlsMode string, r *http.Request, trusted []netip.Prefix) bool {
	if r != nil && r.TLS != nil {
		return true
	}
	if tlsMode != "" && tlsMode != config.TLSProxy {
		return true
	}
	if r == nil {
		return false
	}
	return isHTTPSRequestTrusted(r, trusted)
}

func isHTTPSRequestTrusted(r *http.Request, trusted []netip.Prefix) bool {
	if r.TLS != nil {
		return true
	}
	if !isRemoteTrustedProxy(r.RemoteAddr, trusted) {
		return false
	}
	xfp := r.Header.Get("X-Forwarded-Proto")
	if i := strings.IndexByte(xfp, ','); i >= 0 {
		xfp = xfp[:i]
	}
	return strings.EqualFold(strings.TrimSpace(xfp), "https")
}

func isCleanPublicPluginSubtree(rawPath string) bool {
	if rawPath == "" || strings.Contains(rawPath, "..") {
		return false
	}
	clean := path.Clean(rawPath)
	return (rawPath == "/p" || strings.HasPrefix(rawPath, "/p/")) &&
		(clean == "/p" || strings.HasPrefix(clean, "/p/"))
}

// dropConnection immediately terminates the transport connection without
// sending any HTTP status line, response headers, or body bytes. On HTTP/1.1
// it hijacks the socket and issues an immediate TCP RST (SetLinger(0)); on
// HTTP/2 it triggers http.ErrAbortHandler so Go sends RST_STREAM silently.
func dropConnection(w http.ResponseWriter) {
	if hj, ok := w.(http.Hijacker); ok {
		if conn, _, err := hj.Hijack(); err == nil && conn != nil {
			if tcp := unwrapTCPConn(conn); tcp != nil {
				_ = tcp.SetLinger(0)
			}
			_ = conn.Close()
			return
		}
	}
	panic(http.ErrAbortHandler)
}

func unwrapTCPConn(c net.Conn) *net.TCPConn {
	for i := 0; i < 8 && c != nil; i++ {
		if tcp, ok := c.(*net.TCPConn); ok {
			return tcp
		}
		if wrapper, ok := c.(interface{ NetConn() net.Conn }); ok {
			c = wrapper.NetConn()
			continue
		}
		break
	}
	return nil
}

func clearHeaders(h http.Header) {
	for k := range h {
		delete(h, k)
	}
}
