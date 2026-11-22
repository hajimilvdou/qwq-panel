// SPDX-License-Identifier: AGPL-3.0-only

package gateway_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/qwq-panel/qwq/internal/actor"
	"github.com/qwq-panel/qwq/internal/gateway"
	"github.com/qwq-panel/qwq/internal/platform/clock"
	"github.com/qwq-panel/qwq/internal/platform/logging"
	"github.com/qwq-panel/qwq/internal/platform/problem"
)

// testOrigin is the origin and Host the test configuration allows.
const testOrigin = "https://panel.example.com"

const (
	sessionToken = "session-token-value"
	csrfToken    = "csrf-token-value"
	serviceToken = "svc-token-value"
	dlgToken     = "dlg-token-value"
)

// fakeAuth is the Authenticator the controller will provide: it maps a cookie
// to a session principal and a bearer token to service or delegation
// principals.
type fakeAuth struct {
	mu    sync.Mutex
	fail  error
	calls int
}

func (f *fakeAuth) Authenticate(_ context.Context, c gateway.Credentials) (gateway.Principal, error) {
	f.mu.Lock()
	f.calls++
	fail := f.fail
	f.mu.Unlock()
	if fail != nil {
		return gateway.Principal{}, fail
	}
	switch c.Session {
	case sessionToken:
		return gateway.Principal{
			Actor:  actor.Actor{Kind: actor.Human, ID: "usr_alice", SessionID: "ses_1"},
			Scheme: gateway.SchemeSession,
			CSRF:   csrfToken,
		}, nil
	}
	switch c.Bearer {
	case serviceToken:
		return gateway.Principal{
			Actor:  actor.Actor{Kind: actor.Service, ID: "svc_1", OnBehalfOf: "usr_alice"},
			Scheme: gateway.SchemeService,
		}, nil
	case dlgToken:
		return gateway.Principal{
			Actor:  actor.Actor{Kind: actor.AIAgent, ID: "dlg_1", OnBehalfOf: "usr_alice"},
			Scheme: gateway.SchemeDelegation,
		}, nil
	}
	return gateway.Principal{}, problem.New(problem.Unauthenticated, "Unknown credentials.")
}

// callCount returns how many requests reached the authenticator.
func (f *fakeAuth) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

// frozenClock returns a fake clock that never advances, so token buckets do not
// refill while a test runs.
func frozenClock() *clock.Fake { return clock.NewFake(time.Unix(1_700_000_000, 0).UTC()) }

// syncBuffer is a goroutine-safe log sink.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// testConfig returns the configuration the test suite shares. It is small on
// purpose (body limits in bytes, depth 8, two topics, four buffered events) so
// each limit is easy to hit.
func testConfig(logOut *syncBuffer) gateway.Config {
	cfg := gateway.Config{
		Clock:         clock.System{},
		Auth:          &fakeAuth{},
		TLS:           true,
		PublicOrigins: []string{testOrigin},
		Limits: gateway.Limits{
			MaxBodyBytes:       256,
			MaxPluginBodyBytes: 2048,
			MaxJSONDepth:       8,
			ListLimitDefault:   5,
			ListLimitMax:       10,
			FieldsMax:          3,
			SSETopicsMax:       2,
			SSEBufferEvents:    8,
		},
		Stream: gateway.StreamConfig{
			Heartbeat:    40 * time.Millisecond,
			WriteTimeout: 2 * time.Second,
			RetryMS:      1500,
			MaxPerActor:  4,
		},
	}
	if logOut != nil {
		cfg.Logger = logging.New(logOut, logging.Options{Service: "gateway-test"})
	}
	return cfg
}

// newGateway builds a gateway from cfg plus routes.
func newGateway(t *testing.T, cfg gateway.Config, routes ...gateway.Route) *gateway.Gateway {
	t.Helper()
	g, err := gateway.New(cfg)
	if err != nil {
		t.Fatalf("gateway.New: %v", err)
	}
	t.Cleanup(g.Close)
	for _, rt := range routes {
		if err := g.Handle(rt); err != nil {
			t.Fatalf("Handle(%s %s): %v", rt.Method, rt.Pattern, err)
		}
	}
	return g
}

// testGateway is newGateway with testConfig.
func testGateway(t *testing.T, routes ...gateway.Route) *gateway.Gateway {
	t.Helper()
	return newGateway(t, testConfig(nil), routes...)
}

// response is a recorded response.
type response struct {
	code   int
	header http.Header
	body   []byte
}

func (r response) problem(t *testing.T) problem.Problem {
	t.Helper()
	if got := r.header.Get("Content-Type"); got != "application/problem+json" {
		t.Fatalf("content type = %q, want application/problem+json (body %q)", got, r.body)
	}
	var p problem.Problem
	if err := json.Unmarshal(r.body, &p); err != nil {
		t.Fatalf("decode problem: %v (%q)", err, r.body)
	}
	return p
}

func (r response) decode(t *testing.T, dst any) {
	t.Helper()
	if ct := r.header.Get("Content-Type"); ct != "application/json" {
		t.Fatalf("content type = %q, want application/json (body %q)", ct, r.body)
	}
	if err := json.Unmarshal(r.body, dst); err != nil {
		t.Fatalf("decode body: %v (%q)", err, r.body)
	}
}

// do sends req to g.
func do(t *testing.T, g http.Handler, req *http.Request) response {
	t.Helper()
	rec := httptest.NewRecorder()
	g.ServeHTTP(rec, req)
	return response{code: rec.Code, header: rec.Header(), body: rec.Body.Bytes()}
}

// newRequest builds a request with the allowed Host.
func newRequest(method, target string, body string) *http.Request {
	var r *http.Request
	if body == "" {
		r = httptest.NewRequest(method, target, nil)
	} else {
		r = httptest.NewRequest(method, target, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
	}
	r.Host = "panel.example.com"
	return r
}

// sessionRequest adds the session cookie, CSRF token and a same-origin Origin.
func sessionRequest(method, target, body string) *http.Request {
	r := newRequest(method, target, body)
	r.AddCookie(&http.Cookie{Name: gateway.SessionCookieName, Value: sessionToken})
	r.Header.Set("Origin", testOrigin)
	r.Header.Set("X-CSRF-Token", csrfToken)
	if body != "" {
		r.Header.Set("Content-Type", "application/json")
	}
	return r
}

// bearerRequest adds a bearer token.
func bearerRequest(method, target, body, token string) *http.Request {
	r := newRequest(method, target, body)
	r.Header.Set("Authorization", "Bearer "+token)
	r.Header.Set("Origin", testOrigin)
	if body != "" {
		r.Header.Set("Content-Type", "application/json")
	}
	return r
}

// waitFor polls cond until it holds or the test fails.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// echoContext is a handler that reports what the middleware resolved.
type echoContext struct {
	RequestID string `json:"request_id"`
	TraceID   string `json:"trace_id"`
	ClientIP  string `json:"client_ip"`
	Actor     string `json:"actor"`
	Scheme    string `json:"scheme"`
}

func echoHandler(w http.ResponseWriter, r *http.Request) {
	p, _ := gateway.PrincipalFrom(r.Context())
	_ = gateway.WriteJSON(w, http.StatusOK, echoContext{
		RequestID: gateway.RequestID(r.Context()),
		TraceID:   gateway.TraceID(r.Context()),
		ClientIP:  gateway.ClientIP(r.Context()),
		Actor:     p.Actor.ID,
		Scheme:    string(p.Scheme),
	})
}

// okHandler answers 200 with a fixed body.
func okHandler(w http.ResponseWriter, _ *http.Request) {
	_ = gateway.WriteJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// echoRoute is a GET route reporting the resolved request context.
func echoRoute(pattern string) gateway.Route {
	return gateway.Route{
		Method:  http.MethodGet,
		Pattern: pattern,
		Access:  gateway.AccessSessionOrService,
		Handler: http.HandlerFunc(echoHandler),
	}
}
