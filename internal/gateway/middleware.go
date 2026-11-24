// SPDX-License-Identifier: AGPL-3.0-only

package gateway

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"log/slog"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"runtime/debug"
	"strings"
	"time"

	"github.com/qwq-panel/qwq/internal/actor"
	"github.com/qwq-panel/qwq/internal/platform/ids"
	"github.com/qwq-panel/qwq/internal/platform/logging"
	"github.com/qwq-panel/qwq/internal/platform/problem"
)

type ctxKey int

const (
	ctxRequestID ctxKey = iota
	ctxTraceID
	ctxClientIP
	ctxPrincipal
)

// RequestID returns the request ID assigned by the gateway.
func RequestID(ctx context.Context) string {
	id, _ := ctx.Value(ctxRequestID).(string)
	return id
}

// TraceID returns the W3C trace ID of the request.
func TraceID(ctx context.Context) string {
	id, _ := ctx.Value(ctxTraceID).(string)
	return id
}

// ClientIP returns the caller's address after applying trusted proxies.
func ClientIP(ctx context.Context) string {
	ip, _ := ctx.Value(ctxClientIP).(string)
	return ip
}

// Scheme is a credential type of the public API (its securitySchemes).
type Scheme string

// Credential schemes.
const (
	SchemeSession    Scheme = "sessionCookie"
	SchemeService    Scheme = "serviceAccountToken"
	SchemeDelegation Scheme = "delegationToken"
)

// Valid reports whether s is a known scheme.
func (s Scheme) Valid() bool {
	switch s {
	case SchemeSession, SchemeService, SchemeDelegation:
		return true
	}
	return false
}

// Credentials are the raw credentials a request carried. The gateway extracts
// them so the cookie name and header stay part of the public contract; who they
// belong to is the Authenticator's decision.
type Credentials struct {
	// Session is the session cookie value ("" when absent).
	Session string
	// Bearer is the Authorization bearer token ("" when absent).
	Bearer string
	// NoTouch skips advancing session last_seen_at (background widget polls & SSE liveness checks).
	NoTouch bool
}

// Empty reports whether the request carried no credentials at all.
func (c Credentials) Empty() bool { return c.Session == "" && c.Bearer == "" }

// Principal is an authenticated caller.
type Principal struct {
	Actor actor.Actor
	// Scheme is the credential that authenticated the request.
	Scheme Scheme
	// CSRF is the session's synchroniser token; only session credentials
	// carry one.
	CSRF string
}

// Authenticator resolves credentials to a principal. internal/controller
// adapts identity.Service (sessions) and authz (delegation and service
// accounts) to it; the gateway never imports either package.
//
// A missing credential returns ErrNoCredentials. Any other error may be a
// *problem.Error to control the response (UNAUTHENTICATED, MFA_REQUIRED, ...);
// unrecognized errors become INTERNAL and are logged, never shown.
type Authenticator interface {
	Authenticate(ctx context.Context, c Credentials) (Principal, error)
}

// ErrNoCredentials reports that a request carried no credentials.
var ErrNoCredentials = errors.New("gateway: no credentials")

// PrincipalFrom returns the principal stored by the authentication middleware.
func PrincipalFrom(ctx context.Context) (Principal, bool) {
	p, ok := ctx.Value(ctxPrincipal).(Principal)
	return p, ok
}

// requestID middleware: assign the request ID, echo it, and log the request at
// debug level once it finishes.
func (g *Gateway) requestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := clientRequestID(r.Header.Get("X-Request-Id"))
		if id == "" {
			id = g.ids.New(ids.Request)
		}
		ctx := logging.With(r.Context(), slog.String(logging.KeyRequestID, id))
		ctx = context.WithValue(ctx, ctxRequestID, id)
		r = r.WithContext(ctx)
		w.Header().Set("X-Request-Id", id)

		start := g.clock.Now()
		next.ServeHTTP(w, r)

		if g.log.Enabled(ctx, slog.LevelDebug) {
			status := http.StatusOK
			if rw, ok := w.(*responseWriter); ok {
				status = rw.status
			}
			g.log.DebugContext(ctx, "http request",
				slog.String("method", r.Method),
				slog.String("path", r.URL.Path),
				slog.Int("status", status),
				slog.Duration("duration", g.clock.Now().Sub(start)),
				slog.String("client_ip", ClientIP(ctx)))
		}
	})
}

// clientRequestID accepts a caller-provided request ID only when it is a short
// token without spaces, so logs cannot be forged with newlines or huge values.
func clientRequestID(s string) string {
	if len(s) == 0 || len(s) > 64 {
		return ""
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' ||
			c == '.' || c == '_' || c == ':' || c == '-') {
			return ""
		}
	}
	return s
}

// trace middleware: continue a W3C trace context or start one.
func (g *Gateway) trace(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		traceID := parseTraceparent(r.Header.Get("traceparent"))
		if traceID == "" {
			traceID = ids.TraceID()
		}
		ctx := logging.With(r.Context(), slog.String(logging.KeyTraceID, traceID))
		ctx = context.WithValue(ctx, ctxTraceID, traceID)
		r = r.WithContext(ctx)
		w.Header().Set("X-Trace-Id", traceID)
		next.ServeHTTP(w, r)
	})
}

// parseTraceparent returns the trace-id of a valid W3C traceparent header.
func parseTraceparent(v string) string {
	// version "-" trace-id "-" parent-id "-" flags
	parts := strings.Split(v, "-")
	if len(parts) != 4 || len(parts[0]) != 2 || len(parts[2]) != 16 || len(parts[3]) != 2 {
		return ""
	}
	// version ff is forbidden; version 00 is the only version defined today,
	// but an unknown version is still parseable per the specification.
	if parts[0] == "ff" || parts[0] != "00" {
		return ""
	}
	if !isLowerHex(parts[1]) || !isLowerHex(parts[2]) || !isLowerHex(parts[3]) {
		return ""
	}
	if !ids.ValidTraceID(parts[1]) || parts[1] == "00000000000000000000000000000000" {
		return ""
	}
	if parts[2] == "0000000000000000" {
		return ""
	}
	return parts[1]
}

func isLowerHex(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// recoverPanics turns a handler panic into an INTERNAL problem without leaking
// the stack or the panic value to the client. The stack goes to the log with the
// request ID.
func (g *Gateway) recoverPanics(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			rec := recover()
			if rec == nil {
				return
			}
			// http.ErrAbortHandler is the server's own "abort this response"
			// signal; it must keep propagating.
			if err, ok := rec.(error); ok && errors.Is(err, http.ErrAbortHandler) {
				panic(rec)
			}
			g.log.ErrorContext(r.Context(), "panic serving request",
				slog.String("method", r.Method),
				slog.String("path", r.URL.Path),
				slog.String("panic", fmt.Sprint(rec)),
				slog.String("stack", string(debug.Stack())))

			if rw, ok := w.(*responseWriter); ok && rw.wroteHeader {
				// The status line is already on the wire; the only safe end is
				// to abort the connection.
				panic(http.ErrAbortHandler)
			}
			g.writeProblem(w, r, &problem.Error{
				Code:   problem.Internal,
				Detail: "An unexpected error occurred.",
				Cause:  fmt.Errorf("panic: %v", rec),
			})
		}()
		next.ServeHTTP(w, r)
	})
}

// securityHeaders sets the response headers that every endpoint shares.
func (g *Gateway) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Content-Security-Policy", "frame-ancestors 'none'")
		h.Set("Cache-Control", "no-store")
		if g.cfg.TLS {
			h.Set("Strict-Transport-Security", "max-age=15552000")
		}
		next.ServeHTTP(w, r)
	})
}

// clientIP middleware: resolve the caller address, trusting X-Forwarded-For
// only from configured proxies (ARCH §4.1.1).
func (g *Gateway) clientIP(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := context.WithValue(r.Context(), ctxClientIP, g.resolveClientIP(r))
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (g *Gateway) resolveClientIP(r *http.Request) string {
	remote, err := netip.ParseAddr(hostOnly(r.RemoteAddr))
	if err != nil {
		return hostOnly(r.RemoteAddr)
	}
	remote = remote.Unmap()
	if !g.isTrusted(remote) {
		return remote.String()
	}
	// Walk from the nearest hop: skip trusted proxies, the first valid untrusted
	// address is the client. Garbage left of it (client-supplied, kept by
	// nginx's proxy_add_x_forwarded_for) is never reached; garbage before it
	// means a trusted hop wrote nonsense, so the whole chain is ignored.
	var parts []string
	for _, h := range r.Header.Values("X-Forwarded-For") {
		parts = append(parts, strings.Split(h, ",")...)
	}
	if len(parts) > 0 {
		for i := len(parts) - 1; i >= 0; i-- {
			p := strings.TrimSpace(parts[i])
			if p == "" {
				continue
			}
			a, err := netip.ParseAddr(p)
			if err != nil {
				return remote.String()
			}
			if a = a.Unmap(); !g.isTrusted(a) {
				return a.String()
			}
		}
	}
	if xri := strings.TrimSpace(r.Header.Get("X-Real-IP")); xri != "" {
		if a, err := netip.ParseAddr(xri); err == nil {
			return a.Unmap().String()
		}
	}
	return remote.String()
}

func (g *Gateway) isTrusted(a netip.Addr) bool {
	u := a.Unmap()
	if u.IsLoopback() {
		return true
	}
	for _, p := range g.trusted {
		if p.Contains(u) {
			return true
		}
	}
	return false
}

// hostAndOrigin middleware: reject requests whose Host or Origin is not
// allow-listed, and cross-site requests (ARCH §4.1.1). It runs before routing so
// even unknown paths obey it.
func (g *Gateway) hostAndOrigin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := g.checkHostAndOrigin(r); err != nil {
			g.writeProblem(w, r, err)
			return
		}
		if !isCleanPath(r.URL.Path) {
			g.notFound(w, r)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (g *Gateway) checkHostAndOrigin(r *http.Request) error {
	host := normalizeHost(r.Host)
	if host == "" {
		return csrfFailed("The request has no valid Host header.")
	}
	// Behind a trusted reverse proxy the browser's Host arrives in
	// X-Forwarded-Host; only that proxy may set it.
	if a, err := netip.ParseAddr(hostOnly(r.RemoteAddr)); err == nil && g.isTrusted(a.Unmap()) {
		if xfh := r.Header.Get("X-Forwarded-Host"); xfh != "" {
			if h := normalizeHost(firstHeaderValue(xfh)); h != "" {
				host = h
			}
		}
	}
	if !g.hostAllowed(host) && !(isLoopbackHost(host) && isLoopbackRemoteAddr(r.RemoteAddr)) {
		return csrfFailed("The Host header is not one of the configured public origins.")
	}
	// The plugin static prefix serves public content to the sandboxed plugin
	// iframe, whose opaque origin sends Origin: null and Sec-Fetch-Site:
	// cross-site on every fetch (ADR-0018). Only the Host check above applies;
	// the content carries no session and no credentials. GET and HEAD only:
	// the mount answers every other method itself.
	if (r.Method == http.MethodGet || r.Method == http.MethodHead) && isPluginUIPath(r.URL.Path) {
		return nil
	}
	// ADR-0024：/p/ 公开路由无宿主管理会话（宿主已剥离面板 Cookie/Authorization），
	// 仅保留上述 Host 白名单检查，豁免 Origin 与 Sec-Fetch-Site 检查。
	if isPublicPluginPath(r.URL.Path) {
		return nil
	}
	if origin := r.Header.Get("Origin"); origin != "" {
		if !g.originAllowed(origin, host) {
			return csrfFailed("The request origin is not allowed.")
		}
	}
	switch r.Header.Get("Sec-Fetch-Site") {
	case "cross-site":
		return csrfFailed("Cross-site requests are not accepted.")
	case "same-site":
		if mutating(r.Method) {
			return csrfFailed("Cross-site requests are not accepted.")
		}
	}
	return nil
}

// isPluginUIPath reports whether the request path is the plugin static
// subtree.
func isPluginUIPath(p string) bool {
	return p == "/plugin-ui" || strings.HasPrefix(p, "/plugin-ui/")
}

func isPublicPluginPath(p string) bool {
	return p == "/p" || strings.HasPrefix(p, "/p/")
}

func isLoopbackRemoteAddr(remoteAddr string) bool {
	a, err := netip.ParseAddr(hostOnly(remoteAddr))
	return err == nil && a.Unmap().IsLoopback()
}

func (g *Gateway) hostAllowed(host string) bool {
	g.hostMu.RLock()
	defer g.hostMu.RUnlock()
	if len(g.hosts) == 0 {
		return true
	}
	lh := strings.ToLower(host)
	if _, ok := g.hosts[lh]; ok {
		return true
	}
	if g.dynamicPanelHost != "" && lh == g.dynamicPanelHost {
		return true
	}
	// When the configured origin has no explicit port (e.g. panel.example.com),
	// also accept host:port for the same hostname.
	if h, _, err := net.SplitHostPort(lh); err == nil {
		if _, ok := g.hosts[h]; ok {
			return true
		}
		if g.dynamicPanelHost != "" && h == g.dynamicPanelHost {
			return true
		}
	}
	return false
}

func (g *Gateway) originAllowed(origin, host string) bool {
	norm, scheme, originHost, originHostname, ok := normalizeOrigin(origin)
	if !ok {
		return false
	}
	g.hostMu.RLock()
	hasOrigins := len(g.origins) > 0
	_, allowed := g.origins[norm]
	dynHost := g.dynamicPanelHost
	g.hostMu.RUnlock()
	if hasOrigins {
		if allowed {
			return true
		}
		if dynHost != "" && strings.EqualFold(scheme, "https") && strings.EqualFold(originHostname, dynHost) {
			return true
		}
		return false
	}
	// Without a configured allow-list only same-origin requests are accepted,
	// plus loopback, which the setup flow uses over an SSH tunnel.
	return originHost == host || (dynHost != "" && strings.EqualFold(originHostname, dynHost)) || isLoopbackHost(originHost)
}

// normalizeOrigin returns "scheme://host[:port]" (with default ports removed),
// lower-case scheme, normalized host[:port], and lower-case hostname without port.
func normalizeOrigin(v string) (origin, scheme, host, hostname string, ok bool) {
	u, err := url.Parse(v)
	if err != nil || u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		return "", "", "", "", false
	}
	scheme = strings.ToLower(u.Scheme)
	host = strings.ToLower(u.Host)
	if strings.HasSuffix(host, ":443") && scheme == "https" {
		host = strings.TrimSuffix(host, ":443")
	}
	if strings.HasSuffix(host, ":80") && scheme == "http" {
		host = strings.TrimSuffix(host, ":80")
	}
	hostname = strings.ToLower(u.Hostname())
	if host == "" || hostname == "" {
		return "", "", "", "", false
	}
	return scheme + "://" + host, scheme, host, hostname, true
}

// normalizeHost lower-cases a Host header value and rejects anything that is
// not host[:port].
func normalizeHost(h string) string {
	h = strings.TrimSpace(strings.ToLower(h))
	if h == "" {
		return ""
	}
	for i := 0; i < len(h); i++ {
		c := h[i]
		if c <= ' ' || c == '/' || c == '\\' || c == '?' || c == '#' || c == '@' {
			return ""
		}
	}
	return h
}

// hostOnly strips the port from a host:port value (brackets kept for IPv6).
func hostOnly(hostport string) string {
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		return h
	}
	return strings.Trim(hostport, "[]")
}

// isLoopbackHost reports whether h names the local machine.
func isLoopbackHost(h string) bool {
	name := hostOnly(h)
	if name == "localhost" {
		return true
	}
	a, err := netip.ParseAddr(strings.Trim(name, "[]"))
	return err == nil && a.Unmap().IsLoopback()
}

// firstHeaderValue returns the first value of a comma-separated header.
func firstHeaderValue(v string) string {
	if i := strings.IndexByte(v, ','); i >= 0 {
		return strings.TrimSpace(v[:i])
	}
	return strings.TrimSpace(v)
}

// mutating reports whether a method changes state and therefore needs CSRF
// protection.
func mutating(method string) bool {
	switch method {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		return true
	}
	return false
}

// credentialsFrom extracts the session cookie and the bearer token.
func credentialsFrom(r *http.Request) Credentials {
	var c Credentials
	if cookie, err := r.Cookie(SessionCookieName); err == nil {
		c.Session = cookie.Value
	}
	if auth := r.Header.Get("Authorization"); auth != "" {
		if scheme, token, ok := strings.Cut(auth, " "); ok && strings.EqualFold(scheme, "Bearer") {
			c.Bearer = strings.TrimSpace(token)
		}
	}
	if r.Header.Get("X-QWQ-Background-Poll") == "1" {
		c.NoTouch = true
	}
	return c
}

// bodyLimit middleware: bound the request body before anything reads it.
func (g *Gateway) bodyLimit(rt *route, next http.Handler) http.Handler {
	maxBytes := rt.maxBody
	name := rt.bodyLimitName()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ContentLength > maxBytes {
			g.writeProblem(w, r, payloadTooLarge(name, maxBytes))
			return
		}
		if r.Body != nil {
			r.Body = http.MaxBytesReader(underlying(w), r.Body, maxBytes)
		}
		if rt.body == BodyPackage {
			// ErrNotSupported (test recorder) is fine: no deadline to replace.
			_ = http.NewResponseController(w).SetReadDeadline(time.Now().Add(g.limits.PackageReadTimeout))
		}
		next.ServeHTTP(w, r)
	})
}

// contentType middleware: JSON routes accept application/json only; the
// package upload route accepts multipart/form-data with a boundary.
func (g *Gateway) contentType(rt *route, next http.Handler) http.Handler {
	if rt.body == BodyNone {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch rt.body {
		case BodyPackage:
			if !multipartContentType(r.Header.Get("Content-Type")) {
				g.writeProblem(w, r, problem.New(problem.UnsupportedMediaType,
					"The request body must be multipart/form-data with a boundary."))
				return
			}
		default:
			if !jsonContentType(r.Header.Get("Content-Type")) {
				g.writeProblem(w, r, problem.New(problem.UnsupportedMediaType, "The request body must be application/json."))
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func jsonContentType(v string) bool {
	if v == "" {
		return false
	}
	mediaType, _, err := mime.ParseMediaType(v)
	return err == nil && mediaType == "application/json"
}

// multipartContentType reports whether v declares a multipart/form-data body
// with the boundary ParseMultipartForm needs.
func multipartContentType(v string) bool {
	if v == "" {
		return false
	}
	mediaType, params, err := mime.ParseMediaType(v)
	return err == nil && mediaType == "multipart/form-data" && params["boundary"] != ""
}

// authenticate middleware: resolve credentials and store the principal.
func (g *Gateway) authenticate(rt *route, next http.Handler) http.Handler {
	if rt.access == AccessPublic {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if g.cfg.Auth == nil {
			g.writeProblem(w, r, problem.New(problem.PermissionDenied, "Authentication is not configured."))
			return
		}
		creds := credentialsFrom(r)
		if creds.Empty() {
			g.writeProblem(w, r, problem.New(problem.Unauthenticated, "The request has no credentials."))
			return
		}
		p, err := g.cfg.Auth.Authenticate(r.Context(), creds)
		if err != nil {
			if errors.Is(err, ErrNoCredentials) {
				err = problem.New(problem.Unauthenticated, "The request has no credentials.")
			} else if isProblemInternal(err) {
				g.log.ErrorContext(r.Context(), "authenticator failed", slog.Any("error", err))
			}
			// A dead session cookie is expired so the browser stops replaying it.
			if creds.Session != "" && problem.HasCode(err, problem.Unauthenticated) {
				g.clearSessionCookieOnly(w)
			}
			g.writeProblem(w, r, err)
			return
		}
		if err := p.Actor.Valid(); err != nil {
			g.log.ErrorContext(r.Context(), "authenticator returned an invalid actor", slog.Any("error", err))
			g.writeProblem(w, r, problem.Wrap(fmt.Errorf("gateway: invalid actor: %w", err)))
			return
		}
		if !p.Scheme.Valid() {
			g.log.ErrorContext(r.Context(), "authenticator returned an unknown scheme", slog.String("scheme", string(p.Scheme)))
			g.writeProblem(w, r, problem.Wrap(errors.New("gateway: invalid credential scheme")))
			return
		}
		ctx := context.WithValue(r.Context(), ctxPrincipal, p)
		ctx = actor.With(ctx, p.Actor)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// csrf middleware: session-authenticated state changes need the constant-time
// CSRF header (ARCH §4.1.1). Origin/Host was already checked for every request.
func (g *Gateway) csrf(_ *route, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, ok := PrincipalFrom(r.Context())
		if !ok || p.Scheme != SchemeSession || !mutating(r.Method) {
			next.ServeHTTP(w, r)
			return
		}
		token := r.Header.Get("X-CSRF-Token")
		if p.CSRF == "" || !secureEqual(token, p.CSRF) {
			g.writeProblem(w, r, csrfFailed("The CSRF token is missing or wrong."))
			return
		}
		next.ServeHTTP(w, r)
	})
}

// secureEqual compares two secrets in constant time regardless of length.
func secureEqual(a, b string) bool {
	da := sha256.Sum256([]byte(a))
	db := sha256.Sum256([]byte(b))
	return subtle.ConstantTimeCompare(da[:], db[:]) == 1
}

// credentialPolicy middleware: each route declares which credential types it
// accepts (the OpenAPI `security` list).
func (g *Gateway) credentialPolicy(rt *route, next http.Handler) http.Handler {
	if rt.access == AccessPublic {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, ok := PrincipalFrom(r.Context())
		if !ok || !rt.access.allows(p.Scheme) {
			switch {
			case rt.access == AccessDenied:
				g.writeProblem(w, r, problem.New(problem.PermissionDenied,
					"This route has no credential policy and is unreachable."))
			case p.Scheme == SchemeDelegation:
				g.writeProblem(w, r, problem.New(problem.PermissionDenied,
					"Delegation tokens are accepted only on /api/v1/agent/*."))
			case rt.access == AccessDelegation:
				g.writeProblem(w, r, problem.New(problem.PermissionDenied,
					"This route accepts delegation tokens only."))
			default:
				g.writeProblem(w, r, problem.New(problem.PermissionDenied,
					"This credential type is not accepted on this route."))
			}
			return
		}
		next.ServeHTTP(w, r)
	})
}

// preAuthLimit middleware: limit every request per client IP before
// authentication runs, so a flood of invalid credentials never reaches the
// database or the password hasher. Unauthenticated writes (login, setup, MFA),
// where credentials are guessed, spend the stricter public-write budget instead.
func (g *Gateway) preAuthLimit(rt *route, next http.Handler) http.Handler {
	lim := g.cfg.PreAuthLimit
	if rt.access == AccessPublic && mutating(rt.method) && g.cfg.PublicWriteLimit != nil {
		lim = g.cfg.PublicWriteLimit
	}
	if rt.noRateLimit || lim == nil {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if ok, retry := lim.Allow(ipKey(ClientIP(r.Context()))); !ok {
			g.writeProblem(w, r, rateLimited(retry))
			return
		}
		next.ServeHTTP(w, r)
	})
}

// ipKey is the limiter key of a client address. IPv6 is aggregated to its /64,
// the smallest prefix a single host is usually given, so rotating through the
// addresses of one's own prefix does not buy fresh buckets.
func ipKey(ip string) string {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return "ip:" + ip
	}
	if a = a.Unmap(); a.Is4() {
		return "ip:" + a.String()
	}
	p, _ := a.Prefix(64) // cannot fail: 64 bits fit every IPv6 address
	return "ip6:" + p.String()
}

// rateLimit middleware: limit requests per principal once authentication has
// run (per client IP on public routes). Without a limiter no limit is applied;
// the host always configures one (internal/controller).
func (g *Gateway) rateLimit(rt *route, next http.Handler) http.Handler {
	if rt.noRateLimit || g.cfg.RateLimit == nil {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := ipKey(ClientIP(r.Context()))
		if p, ok := PrincipalFrom(r.Context()); ok {
			key = "principal:" + string(p.Scheme) + ":" + string(p.Actor.Kind) + ":" + p.Actor.ID
		}
		if ok, retry := g.cfg.RateLimit.Allow(key); !ok {
			g.writeProblem(w, r, rateLimited(retry))
			return
		}
		next.ServeHTTP(w, r)
	})
}

// requireIdempotency middleware enforces a required Idempotency-Key before the
// handler runs; handlers read the value with IdempotencyKey.
func (g *Gateway) requireIdempotency(rt *route, next http.Handler) http.Handler {
	if !rt.requireIdempotency {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key, err := IdempotencyKey(r)
		if err != nil {
			g.writeProblem(w, r, err)
			return
		}
		if key == "" {
			g.writeProblem(w, r, badRequest("header", "/Idempotency-Key", "REQUIRED",
				"Mutating requests require an Idempotency-Key header."))
			return
		}
		next.ServeHTTP(w, r)
	})
}
