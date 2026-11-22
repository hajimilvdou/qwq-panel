// SPDX-License-Identifier: AGPL-3.0-only

// Package gateway is the host's HTTP trust boundary: it authenticates callers,
// enforces the request limits and credential policies of the public API, routes
// requests to domain handlers and, for GET /api/v1/events, streams journal
// events over server-sent events.
//
// Middleware order is fixed and is the security contract (ADR-0006 D2):
//
//	request ID -> trace -> panic recovery -> security headers -> client IP
//	-> [per route] body size and JSON depth -> content type
//	-> rate limit per client IP -> authentication -> CSRF and Origin/Host
//	-> credential policy -> rate limit per principal -> handler
//
// The first group wraps the mux; the second group wraps each registered
// handler, because its parameters (accepted credentials, body limit, idempotency
// requirement) are declared by the route. Both groups are composed in
// routes.go by one function, so the order cannot be rearranged per route. The
// per-IP limit runs before authentication so that floods of invalid
// credentials are refused without touching the database.
//
// The gateway never writes SQL. It calls the events hub and the domain packages;
// interfaces it needs from them (Authenticator, Limiter, Check) are declared
// here and implemented by internal/controller when it assembles the host.
package gateway

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"net/url"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/qwq-panel/qwq/internal/events"
	"github.com/qwq-panel/qwq/internal/platform/clock"
	"github.com/qwq-panel/qwq/internal/platform/ids"
	"github.com/qwq-panel/qwq/internal/platform/problem"
)

// Limits are the request bounds of the public API. The defaults mirror
// x-qwq-limits in api/public/v1/openapi.yaml.
type Limits struct {
	MaxBodyBytes       int64
	MaxPluginBodyBytes int64
	MaxPackageBytes    int64
	MaxJSONDepth       int
	ListLimitDefault   int
	ListLimitMax       int
	FieldsMax          int
	SSETopicsMax       int
	SSEBufferEvents    int
	// PackageReadTimeout bounds reading one package upload body. It replaces
	// the server's whole-request ReadTimeout on that route, which is sized for
	// small JSON bodies and would cut a slow uplink (default 10 min).
	PackageReadTimeout time.Duration
}

// MaxPackageBytes is the largest plugin package upload the public API accepts
// (x-qwq-limits.max_package_bytes). The whole multipart request, including its
// framing, is bounded by this value.
const MaxPackageBytes int64 = 64 << 20

// DefaultLimits returns the values documented in x-qwq-limits.
func DefaultLimits() Limits {
	return Limits{
		MaxBodyBytes:       1 << 20, // 1 MiB for host routes
		MaxPluginBodyBytes: 4 << 20, // 4 MiB for routes carrying plugin payloads
		MaxPackageBytes:    MaxPackageBytes,
		MaxJSONDepth:       64,
		ListLimitDefault:   50,
		ListLimitMax:       200,
		FieldsMax:          32,
		SSETopicsMax:       16,
		SSEBufferEvents:    256,
		PackageReadTimeout: 10 * time.Minute,
	}
}

func (l Limits) withDefaults() Limits {
	d := DefaultLimits()
	if l.MaxBodyBytes <= 0 {
		l.MaxBodyBytes = d.MaxBodyBytes
	}
	if l.MaxPluginBodyBytes < l.MaxBodyBytes {
		l.MaxPluginBodyBytes = max(d.MaxPluginBodyBytes, l.MaxBodyBytes)
	}
	if l.MaxPackageBytes <= 0 {
		l.MaxPackageBytes = d.MaxPackageBytes
	}
	if l.MaxJSONDepth <= 0 {
		l.MaxJSONDepth = d.MaxJSONDepth
	}
	if l.ListLimitDefault <= 0 {
		l.ListLimitDefault = d.ListLimitDefault
	}
	if l.ListLimitMax < l.ListLimitDefault {
		l.ListLimitMax = max(d.ListLimitMax, l.ListLimitDefault)
	}
	if l.FieldsMax <= 0 {
		l.FieldsMax = d.FieldsMax
	}
	if l.SSETopicsMax <= 0 {
		l.SSETopicsMax = d.SSETopicsMax
	}
	if l.SSEBufferEvents <= 0 {
		l.SSEBufferEvents = d.SSEBufferEvents
	}
	if l.PackageReadTimeout <= 0 {
		l.PackageReadTimeout = d.PackageReadTimeout
	}
	return l
}

// StreamConfig tunes the SSE endpoint.
type StreamConfig struct {
	// Heartbeat is the interval of `event: heartbeat` frames. The public
	// contract requires it to stay under 30 seconds (default 15 s).
	Heartbeat time.Duration
	// WriteTimeout bounds one frame write; a client that stops reading is
	// disconnected instead of pinning a goroutine (default 10 s).
	WriteTimeout time.Duration
	// RetryMS is the `retry:` reconnect delay sent to clients (default 3000).
	RetryMS int
	// MaxPerActor bounds concurrent streams per principal (default 8).
	MaxPerActor int
	// MaxTotal bounds concurrent streams on the whole host (default 1024).
	MaxTotal int
}

func (s StreamConfig) withDefaults() StreamConfig {
	if s.Heartbeat <= 0 {
		s.Heartbeat = 15 * time.Second
	}
	if s.WriteTimeout <= 0 {
		s.WriteTimeout = 10 * time.Second
	}
	if s.RetryMS <= 0 {
		s.RetryMS = 3000
	}
	if s.MaxPerActor <= 0 {
		s.MaxPerActor = 8
	}
	if s.MaxTotal <= 0 {
		s.MaxTotal = 1024
	}
	return s
}

// Config configures a Gateway.
type Config struct {
	Logger *slog.Logger
	Clock  clock.Clock
	IDs    *ids.Generator

	// TrustedProxies are the addresses or CIDRs whose X-Forwarded-For and
	// X-Forwarded-Host are trusted (config http.trusted_proxies).
	TrustedProxies []string
	// PublicOrigins are the https origins users reach the panel at
	// (config http.public_origins). They form the Origin and Host allow-list.
	PublicOrigins []string
	// TLS reports that the listener terminates TLS: HSTS and Secure cookies
	// are enabled.
	TLS bool
	// InsecureCookies drops the Secure cookie attribute. It exists for tests on
	// plain HTTP; production listeners always use TLS.
	InsecureCookies bool

	// Auth resolves credentials. A nil Authenticator fails every non-public
	// route closed with PERMISSION_DENIED.
	Auth Authenticator
	// RateLimit limits requests per principal after authentication (per
	// client IP on public routes); nil disables it.
	RateLimit Limiter
	// PreAuthLimit limits every request per client IP, with IPv6 aggregated to
	// its /64, before authentication runs: a flood of invalid credentials never
	// reaches the database or the password hasher. nil disables it.
	PreAuthLimit Limiter
	// PublicWriteLimit takes the place of PreAuthLimit on every AccessPublic
	// write route (login, setup, the MFA step): the routes where credentials
	// are guessed. nil leaves them on PreAuthLimit.
	PublicWriteLimit Limiter

	// Limits bounds bodies, JSON depth, projections, pagination and streams.
	Limits Limits
	// Events is the journal fanout behind GET /api/v1/events; nil makes the
	// endpoint report UNAVAILABLE.
	Events *events.Hub
	// Visibility filters streamed events by caller permission. A nil value
	// denies every event, so an unwired host leaks nothing.
	Visibility events.Visibility
	// Stream tunes the SSE endpoint.
	Stream StreamConfig
	// Checks are the initial readiness checks.
	Checks []Check
}

// Gateway serves the public API. It implements http.Handler; register routes
// with Handle before serving.
type Gateway struct {
	shell   http.Handler
	cfg     Config
	limits  Limits
	stream  StreamConfig
	log     *slog.Logger
	clock   clock.Clock
	ids     *ids.Generator
	trusted []netip.Prefix
	origins map[string]struct{} // normalized scheme://host[:port]
	hosts   map[string]struct{} // normalized host[:port]

	mux   *http.ServeMux
	chain http.Handler

	mu       sync.Mutex
	routes   map[string]map[string]*route // pattern -> method -> route
	methods  map[string][]string          // pattern -> sorted methods
	checks   []Check
	streams  *streamLimiter
	closing  chan struct{}
	closeOne sync.Once
}

// New returns a gateway with /healthz, /readyz and GET /api/v1/events
// registered. It validates the configuration; routes are added with Handle.
func New(cfg Config) (*Gateway, error) {
	if cfg.Clock == nil {
		cfg.Clock = clock.System{}
	}
	if cfg.IDs == nil {
		cfg.IDs = ids.New(cfg.Clock.Now)
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.DiscardHandler)
	}
	cfg.Limits = cfg.Limits.withDefaults()
	cfg.Stream = cfg.Stream.withDefaults()
	if cfg.Stream.Heartbeat >= 30*time.Second {
		return nil, fmt.Errorf("gateway: SSE heartbeat must stay under 30s, got %v", cfg.Stream.Heartbeat)
	}

	g := &Gateway{
		cfg:     cfg,
		limits:  cfg.Limits,
		stream:  cfg.Stream,
		log:     cfg.Logger,
		clock:   cfg.Clock,
		ids:     cfg.IDs,
		origins: make(map[string]struct{}),
		hosts:   make(map[string]struct{}),
		mux:     http.NewServeMux(),
		routes:  make(map[string]map[string]*route),
		methods: make(map[string][]string),
		checks:  append([]Check(nil), cfg.Checks...),
		streams: newStreamLimiter(cfg.Stream.MaxTotal),
		closing: make(chan struct{}),
	}
	for i, s := range cfg.TrustedProxies {
		p, err := parseProxy(s)
		if err != nil {
			return nil, fmt.Errorf("gateway: trusted_proxies[%d]: %w", i, err)
		}
		g.trusted = append(g.trusted, p)
	}
	for i, o := range cfg.PublicOrigins {
		origin, host, err := parseOrigin(o)
		if err != nil {
			return nil, fmt.Errorf("gateway: public_origins[%d]: %w", i, err)
		}
		g.origins[origin] = struct{}{}
		g.hosts[host] = struct{}{}
	}
	for i, c := range g.checks {
		if err := c.valid(); err != nil {
			return nil, fmt.Errorf("gateway: checks[%d]: %w", i, err)
		}
	}

	g.mux.Handle("/", http.HandlerFunc(g.notFound))
	g.chain = g.buildChain()

	if err := g.Handle(Route{
		Method:      http.MethodGet,
		Pattern:     "/healthz",
		Access:      AccessPublic,
		Handler:     http.HandlerFunc(g.health),
		NoRateLimit: true,
	}); err != nil {
		return nil, err
	}
	if err := g.Handle(Route{
		Method:      http.MethodGet,
		Pattern:     "/readyz",
		Access:      AccessPublic,
		Handler:     http.HandlerFunc(g.ready),
		NoRateLimit: true,
	}); err != nil {
		return nil, err
	}
	if err := g.Handle(Route{
		Method:  http.MethodGet,
		Pattern: "/api/v1/events",
		Access:  AccessSessionOrService,
		Handler: http.HandlerFunc(g.streamEvents),
	}); err != nil {
		return nil, err
	}
	return g, nil
}

// buildChain composes the global middleware. requestID is outermost so every
// later layer, including the panic log, sees the request ID.
func (g *Gateway) buildChain() http.Handler {
	var h http.Handler = g.mux
	h = g.hostAndOrigin(h)
	h = g.clientIP(h)
	h = g.securityHeaders(h)
	h = g.recoverPanics(h)
	h = g.trace(h)
	h = g.requestID(h)
	return h
}

// ServeHTTP implements http.Handler.
func (g *Gateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	rw := &responseWriter{ResponseWriter: w, status: http.StatusOK}
	g.chain.ServeHTTP(rw, r)
}

// Close ends every open event stream. The HTTP server must still be shut down
// by its owner; this only unblocks the streams so they do not delay it.
func (g *Gateway) Close() {
	g.closeOne.Do(func() { close(g.closing) })
}

// MountPluginUI mounts the plugin static subtree GET|HEAD /plugin-ui/...
// (ADR-0018). It is deliberately not a registered Route: the content is
// public, serves no session, and is not part of the OpenAPI document. Call it
// before the gateway starts serving; a nil handler leaves the prefix on the
// NOT_FOUND fallback. The handler answers 405 for other methods.
func (g *Gateway) MountPluginUI(h http.Handler) {
	if h == nil {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	// Both the bare prefix and the subtree, so a request to /plugin-ui is
	// answered (404 by the handler) instead of ServeMux's redirect.
	g.mux.Handle("/plugin-ui", h)
	g.mux.Handle("/plugin-ui/", h)
}

// MountPublicRoutes 挂载插件声明的公开无会话路由 /p/{plugin_id}/{route}/...（ADR-0024）。
// 仅保留 Host 白名单校验，剥离全部宿主管理 Cookie 与会话凭据，不进入 OpenAPI。
func (g *Gateway) MountPublicRoutes(h http.Handler) {
	if h == nil {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	g.mux.Handle("/p", h)
	g.mux.Handle("/p/", h)
}

// AddCheck appends a readiness check. It is safe to call while serving, but
// the usual place is startup: the host registers the database, TLS and local
// agent probes before it starts listening.
func (g *Gateway) AddCheck(c Check) error {
	if err := c.valid(); err != nil {
		return err
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	for _, existing := range g.checks {
		if existing.Name == c.Name {
			return fmt.Errorf("gateway: duplicate readiness check %q", c.Name)
		}
	}
	g.checks = append(g.checks, c)
	return nil
}

func (g *Gateway) checksSnapshot() []Check {
	g.mu.Lock()
	defer g.mu.Unlock()
	return append([]Check(nil), g.checks...)
}

// notFound answers every path no route claims.
func (g *Gateway) notFound(w http.ResponseWriter, r *http.Request) {
	g.mu.Lock()
	shell := g.shell
	g.mu.Unlock()
	if shell != nil && !reservedShellPath(r.URL.Path) {
		shell.ServeHTTP(w, r)
		return
	}
	g.writeProblem(w, r, problem.New(problem.NotFound, "No route matches this path."))
}

// parseProxy parses one trusted_proxies entry: an IP address (a single host)
// or a CIDR.
func parseProxy(s string) (netip.Prefix, error) {
	if p, err := netip.ParsePrefix(s); err == nil {
		return p.Masked(), nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, errors.New("not an IP address or CIDR")
	}
	return netip.PrefixFrom(a, a.BitLen()), nil
}

// parseOrigin validates one public origin and returns its normalized origin
// and host form.
func parseOrigin(s string) (origin, host string, err error) {
	u, err := url.Parse(s)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil ||
		(u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		return "", "", errors.New("must be an https origin such as https://panel.example.com")
	}
	host = strings.ToLower(u.Host)
	return "https://" + host, host, nil
}

// isCleanPath reports whether p is a canonical absolute request path. Anything
// else (trailing slash, duplicate or dot segments, escaped separators) is
// answered with 404 instead of being redirected: an API that redirects can be
// turned into a cache or credential leak.
func isCleanPath(p string) bool {
	if p == "" || p == "/" {
		return true
	}
	if !strings.HasPrefix(p, "/") || strings.HasSuffix(p, "/") {
		return false
	}
	return path.Clean(p) == p
}

// formatTimestamp renders a timestamp the way the database and the Event
// schema do: RFC 3339 in UTC with milliseconds.
func formatTimestamp(t time.Time) string {
	return t.UTC().Format("2006-01-02T15:04:05.000Z")
}
