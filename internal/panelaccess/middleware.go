// SPDX-License-Identifier: AGPL-3.0-only

package panelaccess

import (
	"crypto/tls"
	"net"
	"net/http"
	"strings"

	"github.com/qwq-panel/qwq/internal/platform/config"
)

const (
	nginx404Body = "<html>\r\n<head><title>404 Not Found</title></head>\r\n<body>\r\n<center><h1>404 Not Found</h1></center>\r\n<hr><center>nginx</center>\r\n</body>\r\n</html>\r\n"
	nginx403Body = "<html>\r\n<head><title>403 Forbidden</title></head>\r\n<body>\r\n<center><h1>403 Forbidden</h1></center>\r\n<hr><center>nginx</center>\r\n</body>\r\n</html>\r\n"
)

// Wrap installs the outermost stealth entry-path gate and disguise handler.
// It MUST wrap the entire Gateway so unauthorized callers on the wrong path
// receive zero qwq headers (no X-Request-Id, no CSP, no Set-Cookie, no problem
// JSON) — indistinguishable in browser & DevTools F12 from an unserved port.
func (m *Manager) Wrap(next http.Handler) http.Handler {
	if m == nil {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		snap := m.Snapshot()
		entryPath := snap.EffectiveEntryPath()
		if entryPath == "" {
			next.ServeHTTP(w, r)
			return
		}

		prefix := "/" + entryPath
		// Case 1: Request enters with the valid secret path prefix (/jsnsjx or /jsnsjx/...).
		if r.URL.Path == prefix || strings.HasPrefix(r.URL.Path, prefix+"/") {
			rest := strings.TrimPrefix(r.URL.Path, prefix)
			if rest == "" {
				rest = "/"
			}
			// Direct API, health check, or plugin-ui subpaths work seamlessly
			// without cookies (supports CLI tools, install.sh readyz, AI agents).
			if isDirectSubpath(rest) {
				r2 := r.Clone(r.Context())
				u := *r.URL
				u.Path = rest
				if u.RawPath != "" {
					if rawRest := strings.TrimPrefix(u.RawPath, prefix); rawRest != "" {
						u.RawPath = rawRest
					} else {
						u.RawPath = "/"
					}
				}
				r2.URL = &u
				next.ServeHTTP(w, r2)
				return
			}
			// Browser navigation to /<entryPath> or /<entryPath>/setup#token=...:
			// grant the HMAC entry-gate cookie and redirect to the SPA route
			// (browsers preserve #fragment across 302 redirects).
			snap.SetGateCookie(w, isHTTPSRequest(r))
			target := rest
			if r.URL.RawQuery != "" {
				target += "?" + r.URL.RawQuery
			}
			http.Redirect(w, r, target, http.StatusFound)
			return
		}

		// Case 2: Request carries a valid entry-gate cookie from an earlier
		// entry through /<entryPath>.
		if c, err := r.Cookie(GateCookieName); err == nil && snap.ValidGateCookie(c.Value) {
			next.ServeHTTP(w, r)
			return
		}

		// Case 3: Wrong or missing secret entry path -> serve stealth disguise.
		serveDisguise(w, r, snap)
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

func isHTTPSRequest(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	return strings.EqualFold(strings.TrimSpace(r.Header.Get("X-Forwarded-Proto")), "https")
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
		clearHeaders(w.Header())
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		if r.Method != http.MethodHead {
			_, _ = w.Write([]byte(snap.DisguiseHTML))
		}
	default:
		dropConnection(w)
	}
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
	switch v := c.(type) {
	case *net.TCPConn:
		return v
	case *tls.Conn:
		if nc := v.NetConn(); nc != nil {
			if tcp, ok := nc.(*net.TCPConn); ok {
				return tcp
			}
		}
	}
	return nil
}

func clearHeaders(h http.Header) {
	for k := range h {
		delete(h, k)
	}
}
