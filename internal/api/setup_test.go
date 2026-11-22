// SPDX-License-Identifier: AGPL-3.0-only

package api_test

import (
	"net/http"
	"testing"

	"github.com/qwq-panel/qwq/internal/identity"
	"github.com/qwq-panel/qwq/internal/platform/problem"
)

// ======================== 公共入口沿用身份服务的有界节流 ========================

func TestSetupTokenAttemptsAreThrottledOverHTTP(t *testing.T) {
	e := newEnv(t)
	body := `{"setup_token":"not-a-valid-setup-token","username":"alice","password":"` + adminPass + `"}`
	for range identity.DefaultThrottleOptions().Threshold {
		e.do(newRequest(http.MethodPost, "/api/v1/setup", body)).expectProblem(t, http.StatusUnauthorized, problem.Unauthenticated)
	}
	response := e.do(newRequest(http.MethodPost, "/api/v1/setup", body))
	response.expectProblem(t, http.StatusTooManyRequests, problem.RateLimited)
	if response.header.Get("Retry-After") == "" {
		t.Fatal("setup backoff did not expose its retry time")
	}
}

// TestSetupAndSessions covers the bootstrap and login contract: the fingerprint
// before setup, one-shot initialization, cookie attributes, current session,
// logout and the second POST /setup conflict.
func TestSetupAndSessions(t *testing.T) {
	e := newEnv(t)

	resp := e.do(newRequest(http.MethodGet, "/api/v1/setup", "")).expect(t, http.StatusOK)
	var status struct {
		Initialized    bool   `json:"initialized"`
		TLSFingerprint string `json:"tls_fingerprint"`
	}
	resp.decode(t, &status)
	if status.Initialized {
		t.Fatal("a fresh installation reports initialized=true")
	}
	if status.TLSFingerprint == "" {
		t.Fatal("self-signed listener has no fingerprint")
	}

	a := e.setupAdmin(adminUser)
	if a.raw.Path != "/api/" || !a.raw.HttpOnly || !a.raw.Secure {
		t.Fatalf("session cookie = %+v", a.raw)
	}

	// The installation is closed after the first administrator.
	resp = e.do(newRequest(http.MethodGet, "/api/v1/setup", "")).expect(t, http.StatusOK)
	resp.decode(t, &status)
	if !status.Initialized {
		t.Fatal("initialized=false after setup")
	}
	body := `{"setup_token":"used","username":"bob","password":"` + adminPass + `"}`
	e.do(newRequest(http.MethodPost, "/api/v1/setup", body)).expectProblem(t, http.StatusConflict, problem.StateConflict)

	// A wrong password and an unknown user are indistinguishable.
	for _, bad := range []string{
		`{"username":"alice","password":"wrong password entirely"}`,
		`{"username":"nobody","password":"wrong password entirely"}`,
	} {
		e.do(newRequest(http.MethodPost, "/api/v1/sessions", bad)).
			expectProblem(t, http.StatusUnauthorized, problem.Unauthenticated)
	}

	session := e.login(adminUser, adminPass)
	cur := e.do(session.sign(http.MethodGet, "/api/v1/sessions/current", "")).expect(t, http.StatusOK)
	var current map[string]any
	cur.decode(t, &current)
	if mustString(t, current, "status") != "authenticated" {
		t.Fatalf("status = %v", current["status"])
	}
	if mustString(t, current, "csrf_token") != session.csrf {
		t.Fatal("csrf_token does not match the login response")
	}
	user, _ := current["user"].(map[string]any)
	if mustString(t, user, "username") != adminUser {
		t.Fatalf("user = %v", user)
	}
	for _, key := range []string{"created_at", "idle_expires_at", "expires_at"} {
		if mustString(t, current, key) == "" {
			t.Fatalf("%s is empty", key)
		}
	}

	// The current session needs a session cookie, not merely a service token.
	e.do(newRequest(http.MethodGet, "/api/v1/sessions/current", "")).
		expectProblem(t, http.StatusUnauthorized, problem.Unauthenticated)

	// Logout revokes the session and clears the cookie.
	logout := e.do(session.sign(http.MethodDelete, "/api/v1/sessions/current", "")).expect(t, http.StatusNoContent)
	if c := logout.cookie(t); c.MaxAge != -1 || c.Value != "" {
		t.Fatalf("clearing cookie = %+v", c)
	}
	e.do(session.sign(http.MethodGet, "/api/v1/sessions/current", "")).
		expectProblem(t, http.StatusUnauthorized, problem.Unauthenticated)

	// A known path with the wrong method answers 405 with Allow.
	notAllowed := e.do(newRequest(http.MethodGet, "/api/v1/sessions", "")).expect(t, http.StatusMethodNotAllowed)
	if got := notAllowed.header.Get("Allow"); got != "POST" {
		t.Fatalf("Allow = %q", got)
	}
	notAllowed.expectProblem(t, http.StatusMethodNotAllowed, problem.MethodNotAllowed)

	// An unknown path is NOT_FOUND, never a redirect.
	e.do(newRequest(http.MethodGet, "/api/v1/nope", "")).
		expectProblem(t, http.StatusNotFound, problem.NotFound)
	e.do(newRequest(http.MethodGet, "/api/v1/users/", "")).
		expectProblem(t, http.StatusNotFound, problem.NotFound)
}
