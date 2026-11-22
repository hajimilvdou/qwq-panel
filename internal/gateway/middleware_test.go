// SPDX-License-Identifier: AGPL-3.0-only

package gateway_test

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/qwq-panel/qwq/internal/gateway"
	"github.com/qwq-panel/qwq/internal/platform/clock"
	"github.com/qwq-panel/qwq/internal/platform/logging"
	"github.com/qwq-panel/qwq/internal/platform/problem"
)

func TestSecurityHeadersRequestIDAndTrace(t *testing.T) {
	g := testGateway(t)
	resp := do(t, g, newRequest(http.MethodGet, "/healthz", ""))
	if resp.code != http.StatusOK {
		t.Fatalf("status = %d", resp.code)
	}
	want := map[string]string{
		"X-Content-Type-Options":    "nosniff",
		"Referrer-Policy":           "no-referrer",
		"Content-Security-Policy":   "frame-ancestors 'none'",
		"Cache-Control":             "no-store",
		"Strict-Transport-Security": "max-age=15552000",
	}
	for k, v := range want {
		if got := resp.header.Get(k); got != v {
			t.Errorf("%s = %q, want %q", k, got, v)
		}
	}
	if id := resp.header.Get("X-Request-Id"); len(id) == 0 || !strings.HasPrefix(id, "req_") {
		t.Errorf("X-Request-Id = %q, want a generated req_ ID", id)
	}
	trace := resp.header.Get("X-Trace-Id")
	if len(trace) != 32 {
		t.Errorf("X-Trace-Id = %q, want 32 hex characters", trace)
	}
}

func TestRequestIDIsEchoedWhenWellFormed(t *testing.T) {
	g := testGateway(t, echoRoute("/api/v1/echo"))
	req := sessionRequest(http.MethodGet, "/api/v1/echo", "")
	req.Header.Set("X-Request-Id", "abc-123_XYZ:1")
	resp := do(t, g, req)
	var echo echoContext
	resp.decode(t, &echo)
	if echo.RequestID != "abc-123_XYZ:1" {
		t.Fatalf("request id = %q", echo.RequestID)
	}
	if resp.header.Get("X-Request-Id") != "abc-123_XYZ:1" {
		t.Fatalf("response header request id = %q", resp.header.Get("X-Request-Id"))
	}
}

func TestMalformedRequestIDIsReplaced(t *testing.T) {
	g := testGateway(t, echoRoute("/api/v1/echo"))
	req := sessionRequest(http.MethodGet, "/api/v1/echo", "")
	req.Header.Set("X-Request-Id", "has spaces")
	resp := do(t, g, req)
	var echo echoContext
	resp.decode(t, &echo)
	if echo.RequestID == "has spaces" || !strings.HasPrefix(echo.RequestID, "req_") {
		t.Fatalf("request id = %q, want a generated ID", echo.RequestID)
	}
}

func TestTraceparentIsContinued(t *testing.T) {
	g := testGateway(t, echoRoute("/api/v1/echo"))
	req := sessionRequest(http.MethodGet, "/api/v1/echo", "")
	req.Header.Set("traceparent", "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")
	resp := do(t, g, req)
	var echo echoContext
	resp.decode(t, &echo)
	if echo.TraceID != "4bf92f3577b34da6a3ce929d0e0e4736" {
		t.Fatalf("trace id = %q", echo.TraceID)
	}
	if resp.header.Get("X-Trace-Id") != echo.TraceID {
		t.Fatalf("trace header = %q", resp.header.Get("X-Trace-Id"))
	}
}

func TestInvalidTraceparentIsIgnored(t *testing.T) {
	g := testGateway(t, echoRoute("/api/v1/echo"))
	for _, tp := range []string{
		"",
		"garbage",
		"00-00000000000000000000000000000000-00f067aa0ba902b7-01",
		"00-4BF92F3577B34DA6A3CE929D0E0E4736-00f067aa0ba902b7-01",
		"ff-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
	} {
		req := sessionRequest(http.MethodGet, "/api/v1/echo", "")
		if tp != "" {
			req.Header.Set("traceparent", tp)
		}
		resp := do(t, g, req)
		var echo echoContext
		resp.decode(t, &echo)
		if len(echo.TraceID) != 32 || strings.HasPrefix(echo.TraceID, "4bf92f") {
			t.Fatalf("traceparent %q produced trace id %q", tp, echo.TraceID)
		}
	}
}

func TestHSTSOnlyOverTLS(t *testing.T) {
	cfg := testConfig(nil)
	cfg.TLS = false
	g := newGateway(t, cfg)
	resp := do(t, g, newRequest(http.MethodGet, "/healthz", ""))
	if got := resp.header.Get("Strict-Transport-Security"); got != "" {
		t.Fatalf("HSTS = %q, want none without TLS", got)
	}
}

func TestPanicBecomesProblemWithoutLeaking(t *testing.T) {
	var logs syncBuffer
	cfg := testConfig(&logs)
	g := newGateway(t, cfg, gateway.Route{
		Method:  http.MethodGet,
		Pattern: "/api/v1/boom",
		Access:  gateway.AccessPublic,
		Handler: http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			panic("database password is hunter2")
		}),
	})
	resp := do(t, g, newRequest(http.MethodGet, "/api/v1/boom", ""))
	if resp.code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", resp.code)
	}
	p := resp.problem(t)
	if p.Code != problem.Internal {
		t.Fatalf("code = %q", p.Code)
	}
	body := string(resp.body)
	for _, secret := range []string{"hunter2", "panic", "goroutine"} {
		if strings.Contains(body, secret) {
			t.Fatalf("response leaked %q: %s", secret, body)
		}
	}
	if p.RequestID == "" || resp.header.Get("X-Request-Id") != p.RequestID {
		t.Fatalf("problem request_id = %q, header = %q", p.RequestID, resp.header.Get("X-Request-Id"))
	}
	if !strings.Contains(logs.String(), "panic serving request") ||
		!strings.Contains(logs.String(), "stack") {
		t.Fatalf("panic was not logged with a stack: %s", logs.String())
	}
	if !strings.Contains(logs.String(), p.RequestID) {
		t.Fatalf("log record lacks the request id %q", p.RequestID)
	}
}

func TestBodyTooLarge(t *testing.T) {
	g := testGateway(t, gateway.Route{
		Method:  http.MethodPost,
		Pattern: "/api/v1/small",
		Access:  gateway.AccessPublic,
		Body:    gateway.BodyJSON,
		Handler: http.HandlerFunc(okHandler),
	})
	body := `{"name":"` + strings.Repeat("x", 400) + `"}`
	resp := do(t, g, newRequest(http.MethodPost, "/api/v1/small", body))
	if resp.code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413", resp.code)
	}
	p := resp.problem(t)
	if p.Code != problem.PayloadTooLarge {
		t.Fatalf("code = %q", p.Code)
	}
	if p.Limit == nil || p.Limit.Name != "max_body_bytes" || p.Limit.Max != 256 {
		t.Fatalf("limit = %+v", p.Limit)
	}
}

func TestJSONDepthLimit(t *testing.T) {
	cfg := testConfig(nil)
	cfg.Limits.MaxJSONDepth = 4
	var g *gateway.Gateway
	g = newGateway(t, cfg, gateway.Route{
		Method:  http.MethodPost,
		Pattern: "/api/v1/deep",
		Access:  gateway.AccessPublic,
		Body:    gateway.BodyJSON,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var v map[string]any
			if err := g.DecodeJSON(r, &v); err != nil {
				problem.Write(w, err, gateway.RequestID(r.Context()), r.URL.Path)
				return
			}
			_ = gateway.WriteJSON(w, http.StatusOK, v)
		}),
	})
	deep := strings.Repeat(`{"a":`, 6) + `1` + strings.Repeat(`}`, 6)
	resp := do(t, g, newRequest(http.MethodPost, "/api/v1/deep", deep))
	if resp.code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413 (body %s)", resp.code, resp.body)
	}
	p := resp.problem(t)
	if p.Limit == nil || p.Limit.Name != "max_json_depth" || p.Limit.Max != 4 {
		t.Fatalf("limit = %+v", p.Limit)
	}
}

func TestUnsupportedMediaType(t *testing.T) {
	g := testGateway(t, gateway.Route{
		Method:  http.MethodPost,
		Pattern: "/api/v1/json-only",
		Access:  gateway.AccessPublic,
		Body:    gateway.BodyJSON,
		Handler: http.HandlerFunc(okHandler),
	})
	req := newRequest(http.MethodPost, "/api/v1/json-only", `{"a":1}`)
	req.Header.Set("Content-Type", "text/plain")
	resp := do(t, g, req)
	if resp.code != http.StatusUnsupportedMediaType {
		t.Fatalf("status = %d, want 415", resp.code)
	}
	if p := resp.problem(t); p.Code != problem.UnsupportedMediaType {
		t.Fatalf("code = %q", p.Code)
	}

	// A charset parameter is fine.
	req = newRequest(http.MethodPost, "/api/v1/json-only", `{"a":1}`)
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	if resp := do(t, g, req); resp.code != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.code)
	}
}

func TestClientIPTrust(t *testing.T) {
	tests := []struct {
		name    string
		trusted []string
		remote  string
		xff     string
		want    string
	}{
		{
			name:   "untrusted proxy is ignored",
			remote: "203.0.113.5:4321",
			xff:    "1.2.3.4",
			want:   "203.0.113.5",
		},
		{
			name:    "trusted proxy forwards the client",
			trusted: []string{"10.0.0.0/8"},
			remote:  "10.1.2.3:4321",
			xff:     "203.0.113.9",
			want:    "203.0.113.9",
		},
		{
			name:    "chain skips trusted hops",
			trusted: []string{"10.0.0.0/8"},
			remote:  "10.1.2.3:4321",
			xff:     "198.51.100.7, 10.0.0.9",
			want:    "198.51.100.7",
		},
		{
			name:    "malformed chain is not half trusted",
			trusted: []string{"10.0.0.0/8"},
			remote:  "10.1.2.3:4321",
			xff:     "not-an-ip",
			want:    "10.1.2.3",
		},
		{
			name:    "single address entry is trusted too",
			trusted: []string{"127.0.0.1"},
			remote:  "127.0.0.1:4321",
			xff:     "203.0.113.4",
			want:    "203.0.113.4",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := clientIPFor(t, tc.trusted, tc.remote, tc.xff); got != tc.want {
				t.Fatalf("client ip = %q, want %q", got, tc.want)
			}
		})
	}
}

// clientIPFor 发一条带 RemoteAddr/XFF 的请求，返回网关解析出的客户端 IP。
func clientIPFor(t *testing.T, trusted []string, remote, xff string) string {
	t.Helper()
	cfg := testConfig(nil)
	cfg.TrustedProxies = trusted
	g := newGateway(t, cfg, echoRoute("/api/v1/echo"))
	req := sessionRequest(http.MethodGet, "/api/v1/echo", "")
	req.RemoteAddr = remote
	if xff != "" {
		req.Header.Set("X-Forwarded-For", xff)
	}
	var echo echoContext
	do(t, g, req).decode(t, &echo)
	return echo.ClientIP
}

// nginx 的 proxy_add_x_forwarded_for 保留客户端自带的左侧值：左侧垃圾不能让
// 客户端 IP 退化为代理 IP（AUTH-08）。
func TestClientIPIgnoresGarbageLeftOfTrustedHop(t *testing.T) {
	got := clientIPFor(t, []string{"127.0.0.1"}, "127.0.0.1:4321", "garbage, 203.0.113.9")
	if got != "203.0.113.9" {
		t.Fatalf("client ip = %q, want 203.0.113.9", got)
	}
}

// 受信代理右侧出现垃圾：整条链不可信，退回直连地址。
func TestClientIPGarbageRightOfClientFallsBack(t *testing.T) {
	got := clientIPFor(t, []string{"127.0.0.1"}, "127.0.0.1:4321", "203.0.113.9, garbage")
	if got != "127.0.0.1" {
		t.Fatalf("client ip = %q, want 127.0.0.1", got)
	}
}

func TestOriginAndHostChecks(t *testing.T) {
	g := testGateway(t, echoRoute("/api/v1/echo"))

	t.Run("foreign origin rejected", func(t *testing.T) {
		req := sessionRequest(http.MethodGet, "/api/v1/echo", "")
		req.Header.Set("Origin", "https://evil.example")
		resp := do(t, g, req)
		if resp.code != http.StatusForbidden {
			t.Fatalf("status = %d", resp.code)
		}
		if p := resp.problem(t); p.Code != problem.CSRFFailed {
			t.Fatalf("code = %q", p.Code)
		}
	})

	t.Run("foreign host rejected", func(t *testing.T) {
		req := sessionRequest(http.MethodGet, "/api/v1/echo", "")
		req.Host = "attacker.example"
		resp := do(t, g, req)
		if resp.code != http.StatusForbidden {
			t.Fatalf("status = %d", resp.code)
		}
	})

	t.Run("loopback host allowed", func(t *testing.T) {
		req := sessionRequest(http.MethodGet, "/api/v1/echo", "")
		req.Host = "127.0.0.1:8443"
		req.Header.Del("Origin")
		if resp := do(t, g, req); resp.code != http.StatusOK {
			t.Fatalf("status = %d", resp.code)
		}
	})

	t.Run("cross-site fetch rejected", func(t *testing.T) {
		req := sessionRequest(http.MethodGet, "/api/v1/echo", "")
		req.Header.Set("Sec-Fetch-Site", "cross-site")
		if resp := do(t, g, req); resp.code != http.StatusForbidden {
			t.Fatalf("status = %d", resp.code)
		}
	})

	t.Run("same-site mutation rejected", func(t *testing.T) {
		req := sessionRequest(http.MethodGet, "/api/v1/echo", "")
		req.Method = http.MethodPost
		req.Header.Set("Sec-Fetch-Site", "same-site")
		if resp := do(t, g, req); resp.code != http.StatusForbidden {
			t.Fatalf("status = %d", resp.code)
		}
	})

	t.Run("no allow-list accepts same origin", func(t *testing.T) {
		cfg := testConfig(nil)
		cfg.PublicOrigins = nil
		g := newGateway(t, cfg, echoRoute("/api/v1/echo"))
		if resp := do(t, g, sessionRequest(http.MethodGet, "/api/v1/echo", "")); resp.code != http.StatusOK {
			t.Fatalf("status = %d", resp.code)
		}
		req := sessionRequest(http.MethodGet, "/api/v1/echo", "")
		req.Header.Set("Origin", "https://evil.example")
		if resp := do(t, g, req); resp.code != http.StatusForbidden {
			t.Fatalf("foreign origin status = %d", resp.code)
		}
	})
}

func TestCSRFProtection(t *testing.T) {
	g := testGateway(t, gateway.Route{
		Method:  http.MethodPost,
		Pattern: "/api/v1/things",
		Access:  gateway.AccessSessionOrService,
		Body:    gateway.BodyJSON,
		Handler: http.HandlerFunc(okHandler),
	})

	t.Run("session mutation without token", func(t *testing.T) {
		req := sessionRequest(http.MethodPost, "/api/v1/things", `{}`)
		req.Header.Del("X-CSRF-Token")
		resp := do(t, g, req)
		if resp.code != http.StatusForbidden {
			t.Fatalf("status = %d", resp.code)
		}
		if p := resp.problem(t); p.Code != problem.CSRFFailed {
			t.Fatalf("code = %q", p.Code)
		}
	})

	t.Run("session mutation with wrong token", func(t *testing.T) {
		req := sessionRequest(http.MethodPost, "/api/v1/things", `{}`)
		req.Header.Set("X-CSRF-Token", "wrong-token")
		if resp := do(t, g, req); resp.code != http.StatusForbidden {
			t.Fatalf("status = %d", resp.code)
		}
	})

	t.Run("session mutation with correct token", func(t *testing.T) {
		if resp := do(t, g, sessionRequest(http.MethodPost, "/api/v1/things", `{}`)); resp.code != http.StatusOK {
			t.Fatalf("status = %d (body %s)", resp.code, resp.body)
		}
	})

	t.Run("bearer mutation needs no CSRF token", func(t *testing.T) {
		req := bearerRequest(http.MethodPost, "/api/v1/things", `{}`, serviceToken)
		if resp := do(t, g, req); resp.code != http.StatusOK {
			t.Fatalf("status = %d (body %s)", resp.code, resp.body)
		}
	})
}

func TestCredentialPolicy(t *testing.T) {
	tests := []struct {
		name   string
		route  gateway.Route
		req    func() *http.Request
		status int
		code   problem.Code
	}{
		{
			name:   "no credentials",
			route:  gateway.Route{Method: http.MethodGet, Pattern: "/api/v1/mixed", Access: gateway.AccessSessionOrService, Handler: http.HandlerFunc(okHandler)},
			req:    func() *http.Request { return newRequest(http.MethodGet, "/api/v1/mixed", "") },
			status: http.StatusUnauthorized,
			code:   problem.Unauthenticated,
		},
		{
			name:   "delegation on a normal route",
			route:  gateway.Route{Method: http.MethodGet, Pattern: "/api/v1/mixed", Access: gateway.AccessSessionOrService, Handler: http.HandlerFunc(okHandler)},
			req:    func() *http.Request { return bearerRequest(http.MethodGet, "/api/v1/mixed", "", dlgToken) },
			status: http.StatusForbidden,
			code:   problem.PermissionDenied,
		},
		{
			name:   "service account on a session-only route",
			route:  gateway.Route{Method: http.MethodGet, Pattern: "/api/v1/session-only", Access: gateway.AccessSession, Handler: http.HandlerFunc(okHandler)},
			req:    func() *http.Request { return bearerRequest(http.MethodGet, "/api/v1/session-only", "", serviceToken) },
			status: http.StatusForbidden,
			code:   problem.PermissionDenied,
		},
		{
			name:   "session on a delegation route",
			route:  gateway.Route{Method: http.MethodPost, Pattern: "/api/v1/agent/find_actions", Access: gateway.AccessDelegation, Body: gateway.BodyJSON, Handler: http.HandlerFunc(okHandler)},
			req:    func() *http.Request { return sessionRequest(http.MethodPost, "/api/v1/agent/find_actions", `{}`) },
			status: http.StatusForbidden,
			code:   problem.PermissionDenied,
		},
		{
			name:  "delegation on the agent route",
			route: gateway.Route{Method: http.MethodPost, Pattern: "/api/v1/agent/find_actions", Access: gateway.AccessDelegation, Body: gateway.BodyJSON, Handler: http.HandlerFunc(okHandler)},
			req: func() *http.Request {
				return bearerRequest(http.MethodPost, "/api/v1/agent/find_actions", `{}`, dlgToken)
			},
			status: http.StatusOK,
		},
		{
			name:   "route without a policy",
			route:  gateway.Route{Method: http.MethodGet, Pattern: "/api/v1/closed", Handler: http.HandlerFunc(okHandler)},
			req:    func() *http.Request { return sessionRequest(http.MethodGet, "/api/v1/closed", "") },
			status: http.StatusForbidden,
			code:   problem.PermissionDenied,
		},
		{
			name:  "unknown session token",
			route: gateway.Route{Method: http.MethodGet, Pattern: "/api/v1/mixed", Access: gateway.AccessSessionOrService, Handler: http.HandlerFunc(okHandler)},
			req: func() *http.Request {
				r := newRequest(http.MethodGet, "/api/v1/mixed", "")
				r.AddCookie(&http.Cookie{Name: gateway.SessionCookieName, Value: "revoked"})
				return r
			},
			status: http.StatusUnauthorized,
			code:   problem.Unauthenticated,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			g := testGateway(t, tc.route)
			resp := do(t, g, tc.req())
			if resp.code != tc.status {
				t.Fatalf("status = %d, want %d (body %s)", resp.code, tc.status, resp.body)
			}
			if tc.code != "" {
				if p := resp.problem(t); p.Code != tc.code {
					t.Fatalf("code = %q, want %q", p.Code, tc.code)
				}
			}
		})
	}
}

func TestAuthenticationNotConfigured(t *testing.T) {
	cfg := testConfig(nil)
	cfg.Auth = nil
	g := newGateway(t, cfg, gateway.Route{
		Method:  http.MethodGet,
		Pattern: "/api/v1/echo",
		Access:  gateway.AccessSession,
		Handler: http.HandlerFunc(okHandler),
	})
	resp := do(t, g, sessionRequest(http.MethodGet, "/api/v1/echo", ""))
	if resp.code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", resp.code)
	}
	if p := resp.problem(t); p.Code != problem.PermissionDenied {
		t.Fatalf("code = %q", p.Code)
	}
}

func TestAuthenticatorFailureIsProblem(t *testing.T) {
	auth := &fakeAuth{fail: problem.New(problem.Unauthenticated, "Session expired.")}
	cfg := testConfig(nil)
	cfg.Auth = auth
	g := newGateway(t, cfg, echoRoute("/api/v1/echo"))
	resp := do(t, g, sessionRequest(http.MethodGet, "/api/v1/echo", ""))
	if resp.code != http.StatusUnauthorized {
		t.Fatalf("status = %d", resp.code)
	}
	if p := resp.problem(t); p.Code != problem.Unauthenticated {
		t.Fatalf("code = %q", p.Code)
	}
}

func TestAuthenticatorInternalErrorIsHidden(t *testing.T) {
	auth := &fakeAuth{fail: errors.New("connection refused to 127.0.0.1:5432")}
	cfg := testConfig(nil)
	cfg.Auth = auth
	cfg.Logger = logging.New(&syncBuffer{}, logging.Options{})
	g := newGateway(t, cfg, echoRoute("/api/v1/echo"))
	resp := do(t, g, sessionRequest(http.MethodGet, "/api/v1/echo", ""))
	if resp.code != http.StatusInternalServerError {
		t.Fatalf("status = %d", resp.code)
	}
	p := resp.problem(t)
	if p.Code != problem.Internal {
		t.Fatalf("code = %q", p.Code)
	}
	if strings.Contains(string(resp.body), "5432") {
		t.Fatalf("internal cause leaked: %s", resp.body)
	}
}

// stubLimiter allows a fixed number of requests.
type stubLimiter struct {
	mu    sync.Mutex
	allow int
}

func (s *stubLimiter) Allow(string) (bool, time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.allow > 0 {
		s.allow--
		return true, 0
	}
	return false, 2 * time.Second
}

func TestRateLimited(t *testing.T) {
	cfg := testConfig(nil)
	cfg.RateLimit = &stubLimiter{allow: 1}
	g := newGateway(t, cfg, echoRoute("/api/v1/echo"))
	if resp := do(t, g, sessionRequest(http.MethodGet, "/api/v1/echo", "")); resp.code != http.StatusOK {
		t.Fatalf("first status = %d", resp.code)
	}
	resp := do(t, g, sessionRequest(http.MethodGet, "/api/v1/echo", ""))
	if resp.code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429", resp.code)
	}
	p := resp.problem(t)
	if p.Code != problem.RateLimited || !p.Retryable {
		t.Fatalf("problem = %+v", p)
	}
	if p.RetryAfter < 1 || resp.header.Get("Retry-After") == "" {
		t.Fatalf("retry after = %d, header %q", p.RetryAfter, resp.header.Get("Retry-After"))
	}

	// Probes are exempt.
	if resp := do(t, g, newRequest(http.MethodGet, "/healthz", "")); resp.code != http.StatusOK {
		t.Fatalf("healthz status = %d", resp.code)
	}
}

// TestPreAuthLimitBoundsInvalidCredentials checks that a flood of forged
// credentials is cut off per client IP before the Authenticator runs, so it
// never reaches the database or the password hasher.
func TestPreAuthLimitBoundsInvalidCredentials(t *testing.T) {
	auth := &fakeAuth{fail: problem.New(problem.Unauthenticated, "Unknown credentials.")}
	cfg := testConfig(nil)
	cfg.Auth = auth
	cfg.PreAuthLimit = gateway.NewTokenBuckets(frozenClock(), gateway.TokenBucketConfig{Rate: 1, Burst: 3})
	g := newGateway(t, cfg, echoRoute("/api/v1/echo"))

	forged := func() response {
		return do(t, g, bearerRequest(http.MethodGet, "/api/v1/echo", "", "forged-token"))
	}
	for i := 1; i <= 3; i++ {
		if resp := forged(); resp.code != http.StatusUnauthorized {
			t.Fatalf("request %d: status = %d, want 401 (body %s)", i, resp.code, resp.body)
		}
	}
	resp := forged()
	if resp.code != http.StatusTooManyRequests {
		t.Fatalf("request 4: status = %d, want 429 (body %s)", resp.code, resp.body)
	}
	if p := resp.problem(t); p.Code != problem.RateLimited || !p.Retryable || p.RetryAfter < 1 {
		t.Fatalf("problem = %+v", p)
	}
	if resp.header.Get("Retry-After") == "" {
		t.Fatal("429 without a Retry-After header")
	}
	if got := auth.callCount(); got != 3 {
		t.Fatalf("authenticator calls = %d, want 3: the refused request must not reach it", got)
	}

	// Probes stay exempt, even from an address that is being limited.
	if resp := do(t, g, newRequest(http.MethodGet, "/healthz", "")); resp.code != http.StatusOK {
		t.Fatalf("healthz status = %d", resp.code)
	}
}

// TestPreAuthLimitGroupsIPv6Slash64 checks that the addresses of one IPv6 /64
// share a bucket, so a host cannot rotate through its own prefix, while another
// /64 and every IPv4 address count separately.
func TestPreAuthLimitGroupsIPv6Slash64(t *testing.T) {
	cfg := testConfig(nil)
	cfg.PreAuthLimit = gateway.NewTokenBuckets(frozenClock(), gateway.TokenBucketConfig{Rate: 1, Burst: 1})
	g := newGateway(t, cfg, echoRoute("/api/v1/echo"))
	from := func(remote string) int {
		req := sessionRequest(http.MethodGet, "/api/v1/echo", "")
		req.RemoteAddr = remote
		return do(t, g, req).code
	}

	for _, tc := range []struct {
		remote string
		want   int
	}{
		{"[2001:db8:1:2::1]:4321", http.StatusOK},
		{"[2001:db8:1:2:ffff:ffff:ffff:ffff]:4321", http.StatusTooManyRequests}, // same /64
		{"[2001:db8:1:3::1]:4321", http.StatusOK},                               // next /64
		{"198.51.100.7:4321", http.StatusOK},
		{"198.51.100.8:4321", http.StatusOK},                       // IPv4 is per address
		{"[::ffff:198.51.100.7]:4321", http.StatusTooManyRequests}, // mapped form of .7
	} {
		if got := from(tc.remote); got != tc.want {
			t.Errorf("request from %s: status = %d, want %d", tc.remote, got, tc.want)
		}
	}
}

// TestPublicWriteLimitLogin checks that unauthenticated writes (login, setup,
// MFA) spend the strict public-write bucket of their client IP, while reads of
// public routes keep the pre-authentication bucket.
func TestPublicWriteLimitLogin(t *testing.T) {
	var logins atomic.Int32
	clk := frozenClock()
	cfg := testConfig(nil)
	cfg.PreAuthLimit = gateway.NewTokenBuckets(clk, gateway.TokenBucketConfig{Rate: 1, Burst: 100})
	cfg.PublicWriteLimit = gateway.NewTokenBuckets(clk, gateway.TokenBucketConfig{Rate: 1, Burst: 2})
	g := newGateway(t, cfg,
		gateway.Route{
			Method:  http.MethodPost,
			Pattern: "/api/v1/sessions",
			Access:  gateway.AccessPublic,
			Body:    gateway.BodyJSON,
			Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				logins.Add(1)
				okHandler(w, r)
			}),
		},
		gateway.Route{
			Method:  http.MethodGet,
			Pattern: "/api/v1/setup",
			Access:  gateway.AccessPublic,
			Handler: http.HandlerFunc(okHandler),
		},
	)
	login := func(remote string) response {
		req := newRequest(http.MethodPost, "/api/v1/sessions", `{"username":"alice","password":"guess"}`)
		req.RemoteAddr = remote
		return do(t, g, req)
	}

	for i := 1; i <= 2; i++ {
		if resp := login("203.0.113.5:4321"); resp.code != http.StatusOK {
			t.Fatalf("login %d: status = %d, want 200 (body %s)", i, resp.code, resp.body)
		}
	}
	resp := login("203.0.113.5:4321")
	if resp.code != http.StatusTooManyRequests {
		t.Fatalf("login 3: status = %d, want 429 (body %s)", resp.code, resp.body)
	}
	if p := resp.problem(t); p.Code != problem.RateLimited || resp.header.Get("Retry-After") == "" {
		t.Fatalf("problem = %+v, Retry-After %q", p, resp.header.Get("Retry-After"))
	}
	if got := logins.Load(); got != 2 {
		t.Fatalf("login handler ran %d times, want 2: the refused login must not reach it", got)
	}

	// A read is not a public write: it keeps the pre-authentication budget.
	read := newRequest(http.MethodGet, "/api/v1/setup", "")
	read.RemoteAddr = "203.0.113.5:4321"
	if resp := do(t, g, read); resp.code != http.StatusOK {
		t.Fatalf("public read: status = %d, want 200", resp.code)
	}
	// Another client has its own budget.
	if resp := login("203.0.113.6:4321"); resp.code != http.StatusOK {
		t.Fatalf("login from another client: status = %d, want 200", resp.code)
	}
}

func TestTokenBuckets(t *testing.T) {
	clk := clock.NewFake(time.Unix(1_700_000_000, 0).UTC())
	lim := gateway.NewTokenBuckets(clk, gateway.TokenBucketConfig{Rate: 2, Burst: 2, MaxKeys: 2})
	if ok, _ := lim.Allow("a"); !ok {
		t.Fatal("first request refused")
	}
	if ok, _ := lim.Allow("a"); !ok {
		t.Fatal("second request refused")
	}
	ok, wait := lim.Allow("a")
	if ok || wait <= 0 {
		t.Fatalf("third request allowed=%v wait=%v, want refused with a delay", ok, wait)
	}
	clk.Advance(500 * time.Millisecond) // refills one token at 2/s
	if ok, _ := lim.Allow("a"); !ok {
		t.Fatal("request after refill refused")
	}
	// The key set is bounded: a third key evicts instead of growing the map.
	lim.Allow("b")
	lim.Allow("c")
	if got := lim.Len(); got > 2 {
		t.Fatalf("tracked keys = %d, want at most 2", got)
	}
}

func TestDecodeJSONHelper(t *testing.T) {
	type nested struct {
		Enabled bool `json:"enabled"`
	}
	type payload struct {
		Name   string          `json:"name"`
		Count  int             `json:"count"`
		Nested nested          `json:"nested"`
		Raw    json.RawMessage `json:"raw"`
		Tags   []string        `json:"tags"`
	}
	var g *gateway.Gateway
	g = testGateway(t, gateway.Route{
		Method:  http.MethodPost,
		Pattern: "/api/v1/decode",
		Access:  gateway.AccessPublic,
		Body:    gateway.BodyJSON,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var p payload
			if err := g.DecodeJSON(r, &p); err != nil {
				problem.Write(w, err, gateway.RequestID(r.Context()), r.URL.Path)
				return
			}
			_ = gateway.WriteJSON(w, http.StatusOK, p)
		}),
	})

	t.Run("valid", func(t *testing.T) {
		resp := do(t, g, newRequest(http.MethodPost, "/api/v1/decode",
			`{"name":"x","count":2,"nested":{"enabled":true},"raw":{"a":1},"tags":["a","b"]}`))
		if resp.code != http.StatusOK {
			t.Fatalf("status = %d (body %s)", resp.code, resp.body)
		}
	})

	t.Run("unknown field", func(t *testing.T) {
		resp := do(t, g, newRequest(http.MethodPost, "/api/v1/decode", `{"name":"x","extra":1}`))
		if resp.code != http.StatusBadRequest {
			t.Fatalf("status = %d", resp.code)
		}
		p := resp.problem(t)
		if p.Code != problem.ValidationFailed || len(p.Violations) != 1 {
			t.Fatalf("problem = %+v", p)
		}
		if got := p.Violations[0]; got.Pointer != "/extra" || got.Code != "UNKNOWN_FIELD" {
			t.Fatalf("violation = %+v", got)
		}
	})

	t.Run("nested unknown field", func(t *testing.T) {
		resp := do(t, g, newRequest(http.MethodPost, "/api/v1/decode", `{"nested":{"bogus":true}}`))
		p := resp.problem(t)
		if got := p.Violations[0]; got.Pointer != "/nested/bogus" {
			t.Fatalf("violation = %+v", got)
		}
	})

	t.Run("type mismatch", func(t *testing.T) {
		resp := do(t, g, newRequest(http.MethodPost, "/api/v1/decode", `{"count":"two"}`))
		p := resp.problem(t)
		if got := p.Violations[0]; got.Pointer != "/count" || got.Code != "TYPE_MISMATCH" {
			t.Fatalf("violation = %+v", got)
		}
	})

	t.Run("malformed json", func(t *testing.T) {
		resp := do(t, g, newRequest(http.MethodPost, "/api/v1/decode", `{"name":`))
		if resp.code != http.StatusBadRequest {
			t.Fatalf("status = %d", resp.code)
		}
		if p := resp.problem(t); p.Code != problem.ValidationFailed {
			t.Fatalf("code = %q", p.Code)
		}
	})

	t.Run("trailing data", func(t *testing.T) {
		resp := do(t, g, newRequest(http.MethodPost, "/api/v1/decode", `{"name":"x"} {"name":"y"}`))
		if resp.code != http.StatusBadRequest {
			t.Fatalf("status = %d", resp.code)
		}
	})

	t.Run("empty body", func(t *testing.T) {
		req := newRequest(http.MethodPost, "/api/v1/decode", "")
		req.Header.Set("Content-Type", "application/json")
		resp := do(t, g, req)
		if resp.code != http.StatusBadRequest {
			t.Fatalf("status = %d", resp.code)
		}
		if p := resp.problem(t); p.Code != problem.ValidationFailed || p.Violations[0].Code != "REQUIRED" {
			t.Fatalf("problem = %+v", p)
		}
	})
}

func TestIdempotencyKeyEnforced(t *testing.T) {
	g := testGateway(t, gateway.Route{
		Method:             http.MethodPost,
		Pattern:            "/api/v1/things",
		Access:             gateway.AccessSessionOrService,
		Body:               gateway.BodyJSON,
		RequireIdempotency: true,
		Handler:            http.HandlerFunc(okHandler),
	})
	t.Run("missing key", func(t *testing.T) {
		resp := do(t, g, sessionRequest(http.MethodPost, "/api/v1/things", `{}`))
		if resp.code != http.StatusBadRequest {
			t.Fatalf("status = %d", resp.code)
		}
		p := resp.problem(t)
		if p.Violations[0].Pointer != "/Idempotency-Key" || p.Violations[0].In != "header" {
			t.Fatalf("violation = %+v", p.Violations[0])
		}
	})
	t.Run("valid key", func(t *testing.T) {
		req := sessionRequest(http.MethodPost, "/api/v1/things", `{}`)
		req.Header.Set("Idempotency-Key", "0123456789abcdef")
		if resp := do(t, g, req); resp.code != http.StatusOK {
			t.Fatalf("status = %d (body %s)", resp.code, resp.body)
		}
	})
	t.Run("short key", func(t *testing.T) {
		req := sessionRequest(http.MethodPost, "/api/v1/things", `{}`)
		req.Header.Set("Idempotency-Key", "short")
		if resp := do(t, g, req); resp.code != http.StatusBadRequest {
			t.Fatalf("status = %d", resp.code)
		}
	})
}

func TestXForwardedHostOnlyFromTrustedProxy(t *testing.T) {
	g := testGateway(t, echoRoute("/api/v1/echo"))

	req := sessionRequest(http.MethodGet, "/api/v1/echo", "")
	req.Header.Set("X-Forwarded-Host", "evil.example")
	// The request Host is allowed, so the spoofed X-Forwarded-Host must not
	// change the outcome.
	if resp := do(t, g, req); resp.code != http.StatusOK {
		t.Fatalf("status = %d (body %s)", resp.code, resp.body)
	}

	cfg := testConfig(nil)
	cfg.TrustedProxies = []string{"10.0.0.0/8"}
	g = newGateway(t, cfg, echoRoute("/api/v1/echo"))
	req = sessionRequest(http.MethodGet, "/api/v1/echo", "")
	req.RemoteAddr = "10.0.0.5:1234"
	req.Header.Set("X-Forwarded-Host", "evil.example")
	if resp := do(t, g, req); resp.code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 from the forwarded host", resp.code)
	}

	// A trusted proxy may present the public host explicitly.
	req = sessionRequest(http.MethodGet, "/api/v1/echo", "")
	req.RemoteAddr = "10.0.0.5:1234"
	req.Header.Set("X-Forwarded-Host", "panel.example.com")
	if resp := do(t, g, req); resp.code != http.StatusOK {
		t.Fatalf("status = %d (body %s)", resp.code, resp.body)
	}
}

func TestCookieAttributes(t *testing.T) {
	g := testGateway(t)
	rec := httptest.NewRecorder()
	g.SetSessionCookie(rec, "tok", time.Hour)
	cookie := rec.Header().Get("Set-Cookie")
	for _, want := range []string{
		gateway.SessionCookieName + "=tok",
		"Path=/api/",
		"HttpOnly",
		"Secure",
		"SameSite=Lax",
	} {
		if !strings.Contains(cookie, want) {
			t.Errorf("cookie %q lacks %q", cookie, want)
		}
	}

	rec = httptest.NewRecorder()
	g.ClearSessionCookie(rec)
	if got := rec.Header().Get("Set-Cookie"); !strings.Contains(got, "Max-Age=0") {
		t.Errorf("clear cookie = %q, want Max-Age=0", got)
	}
}

// TestInvalidSessionCookieIsCleared: a session cookie the authenticator
// rejects is expired in the 401, so the browser stops replaying it.
func TestInvalidSessionCookieIsCleared(t *testing.T) {
	cfg := testConfig(nil)
	cfg.Auth = &fakeAuth{fail: problem.New(problem.Unauthenticated, "Session expired.")}
	g := newGateway(t, cfg, echoRoute("/api/v1/echo"))
	resp := do(t, g, sessionRequest(http.MethodGet, "/api/v1/echo", ""))
	if resp.code != http.StatusUnauthorized {
		t.Fatalf("status = %d", resp.code)
	}
	got := resp.header.Get("Set-Cookie")
	if !strings.HasPrefix(got, gateway.SessionCookieName+"=;") || !strings.Contains(got, "Max-Age=0") {
		t.Fatalf("Set-Cookie = %q, want the session cookie cleared", got)
	}
	// A bearer failure must not touch the browser cookie.
	req := newRequest(http.MethodGet, "/api/v1/echo", "")
	req.Header.Set("Authorization", "Bearer nope")
	if resp := do(t, g, req); resp.header.Get("Set-Cookie") != "" {
		t.Fatalf("bearer failure set a cookie: %q", resp.header.Get("Set-Cookie"))
	}
}
