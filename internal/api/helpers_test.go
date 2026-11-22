// SPDX-License-Identifier: AGPL-3.0-only

package api_test

import (
	"bytes"
	"encoding/base32"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/qwq-panel/qwq/internal/actor"
	"github.com/qwq-panel/qwq/internal/api"
	"github.com/qwq-panel/qwq/internal/authz"
	"github.com/qwq-panel/qwq/internal/controller"
	"github.com/qwq-panel/qwq/internal/gateway"
	"github.com/qwq-panel/qwq/internal/identity"
	"github.com/qwq-panel/qwq/internal/platform/clock"
	"github.com/qwq-panel/qwq/internal/platform/config"
	"github.com/qwq-panel/qwq/internal/platform/ids"
	"github.com/qwq-panel/qwq/internal/platform/problem"
	"github.com/qwq-panel/qwq/internal/storage"
)

const (
	testHost   = "panel.example.com"
	testOrigin = "https://panel.example.com"
	adminUser  = "alice"
	adminPass  = "correct horse battery staple"
)

// env is one fully assembled host: controller, gateway and the registered API.
type env struct {
	t *testing.T
	c *controller.Controller
}

// newEnv opens a real SQLite database in t.TempDir, builds the controller and
// registers the API on its gateway, so every test goes through the complete
// middleware chain.
func newEnv(t *testing.T) *env {
	t.Helper()
	return newEnvWith(t, nil)
}

// newEnvWith is newEnv with a hook that can set optional Deps members (the
// plugin manager and its upload store) before Register runs.
func newEnvWith(t *testing.T, customize func(*api.Deps)) *env {
	t.Helper()
	dir := t.TempDir()
	cfg := config.Default()
	cfg.DataDir = filepath.Join(dir, "data")
	cfg.RunDir = filepath.Join(dir, "run")
	cfg.HTTP.PublicOrigins = []string{testOrigin}
	c, err := controller.New(t.Context(), controller.Options{Config: cfg})
	if err != nil {
		t.Fatalf("controller.New: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return registerEnvAPI(t, c, customize)
}

// ======================== 复用真实宿主的 API 装配 ========================

func registerEnvAPI(t *testing.T, c *controller.Controller, customize func(*api.Deps)) *env {
	t.Helper()
	clk := clock.System{}
	deps := api.Deps{
		Config:   c.Config(),
		DB:       c.DB(),
		Clock:    clk,
		IDs:      ids.New(clk.Now),
		Logger:   slog.New(slog.DiscardHandler),
		Identity: c.Identity(),
		Authz:    c.Authorizer(),
		Ops:      c.Operations(),
		Catalog:  c.Catalog(),
		Secrets:  c.Secrets(),
		TLS:      c.TLS(),
		NodeID:   "local",
	}
	if customize != nil {
		customize(&deps)
	}
	if err := api.Register(c.Gateway(), deps); err != nil {
		t.Fatalf("api.Register: %v", err)
	}
	return &env{t: t, c: c}
}

// reopenCatalogHost 保留数据库与登录凭据，仅重建真实 Controller 和网关。
func (e *env) reopenCatalogHost() {
	e.t.Helper()
	cfg := e.c.Config()
	if err := e.c.Close(); err != nil {
		e.t.Fatal(err)
	}
	c, err := controller.New(e.t.Context(), controller.Options{Config: cfg})
	if err != nil {
		e.t.Fatal(err)
	}
	e.t.Cleanup(func() { _ = c.Close() })
	e.c = registerEnvAPI(e.t, c, nil).c
}

// auth is the state of one signed-in browser session.
type auth struct {
	cookie string
	csrf   string
	userID string
	raw    *http.Cookie
}

type response struct {
	status int
	header http.Header
	body   []byte
}

func (e *env) do(req *http.Request) response {
	e.t.Helper()
	rec := httptest.NewRecorder()
	e.c.Handler().ServeHTTP(rec, req)
	return response{status: rec.Code, header: rec.Header(), body: rec.Body.Bytes()}
}

func (r response) expect(t *testing.T, status int) response {
	t.Helper()
	if r.status != status {
		t.Fatalf("status = %d, want %d (body %s)", r.status, status, r.body)
	}
	return r
}

func (r response) decode(t *testing.T, dst any) {
	t.Helper()
	if ct := r.header.Get("Content-Type"); ct != "application/json" {
		t.Fatalf("content type = %q, want application/json (body %s)", ct, r.body)
	}
	if err := json.Unmarshal(r.body, dst); err != nil {
		t.Fatalf("decode body: %v (%s)", err, r.body)
	}
}

func (r response) decodeMap(t *testing.T) map[string]any {
	t.Helper()
	var m map[string]any
	r.decode(t, &m)
	return m
}

// problem decodes the RFC 9457 document of an error response.
func (r response) problemDoc(t *testing.T) problem.Problem {
	t.Helper()
	if ct := r.header.Get("Content-Type"); ct != "application/problem+json" {
		t.Fatalf("content type = %q, want application/problem+json (body %s)", ct, r.body)
	}
	var p problem.Problem
	if err := json.Unmarshal(r.body, &p); err != nil {
		t.Fatalf("decode problem: %v (%s)", err, r.body)
	}
	if p.RequestID == "" {
		t.Fatalf("problem has no request_id: %s", r.body)
	}
	return p
}

func (r response) expectProblem(t *testing.T, status int, code problem.Code) problem.Problem {
	t.Helper()
	r.expect(t, status)
	p := r.problemDoc(t)
	if p.Code != code {
		t.Fatalf("code = %q, want %q (body %s)", p.Code, code, r.body)
	}
	if p.Status != status {
		t.Fatalf("problem status = %d, want %d", p.Status, status)
	}
	return p
}

// cookie returns the first Set-Cookie of the response.
func (r response) cookie(t *testing.T) *http.Cookie {
	t.Helper()
	res := http.Response{Header: r.header}
	cookies := res.Cookies()
	if len(cookies) == 0 {
		t.Fatalf("no Set-Cookie (headers %v)", r.header)
	}
	return cookies[0]
}

func newRequest(method, target, body string) *http.Request {
	var r *http.Request
	if body == "" {
		r = httptest.NewRequest(method, target, nil)
	} else {
		r = httptest.NewRequest(method, target, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
	}
	r.Host = testHost
	return r
}

// sign builds a session-authenticated request with the CSRF token and a
// same-origin Origin header.
func (a auth) sign(method, target, body string) *http.Request {
	r := newRequest(method, target, body)
	r.AddCookie(&http.Cookie{Name: gateway.SessionCookieName, Value: a.cookie})
	r.Header.Set("X-CSRF-Token", a.csrf)
	r.Header.Set("Origin", testOrigin)
	return r
}

// bearer builds a request carrying a service-account token.
func bearer(method, target, body, token string) *http.Request {
	r := newRequest(method, target, body)
	r.Header.Set("Authorization", "Bearer "+token)
	r.Header.Set("Origin", testOrigin)
	return r
}

func idempotencyKey(n int) string { return fmt.Sprintf("test-idempotency-key-%04d", n) }

// setupAdmin completes the installation with one administrator and returns the
// signed-in session.
func (e *env) setupAdmin(username string) auth {
	e.t.Helper()
	token, _, err := e.c.Identity().NewSetupToken(e.t.Context())
	if err != nil {
		e.t.Fatalf("NewSetupToken: %v", err)
	}
	body := fmt.Sprintf(`{"setup_token":%q,"username":%q,"password":%q}`, token, username, adminPass)
	return e.sessionFrom(e.do(newRequest(http.MethodPost, "/api/v1/setup", body)).expect(e.t, http.StatusCreated))
}

// login signs in and returns the session.
func (e *env) login(username, password string) auth {
	e.t.Helper()
	body := fmt.Sprintf(`{"username":%q,"password":%q}`, username, password)
	return e.sessionFrom(e.do(newRequest(http.MethodPost, "/api/v1/sessions", body)).expect(e.t, http.StatusCreated))
}

// loginWithRecoveryCode signs a user with a second factor in: the password
// opens an MFA challenge, which a recovery code answers, so the session has
// just passed the second factor. A recovery code leaves the TOTP step counter
// alone for the codes a test still needs.
func (e *env) loginWithRecoveryCode(username, code string) auth {
	e.t.Helper()
	body := fmt.Sprintf(`{"username":%q,"password":%q}`, username, adminPass)
	var challenge struct {
		ChallengeID string `json:"challenge_id"`
	}
	e.do(newRequest(http.MethodPost, "/api/v1/sessions", body)).expect(e.t, http.StatusOK).decode(e.t, &challenge)
	answer := fmt.Sprintf(`{"challenge_id":%q,"method":"recovery_code","code":%q}`, challenge.ChallengeID, code)
	return e.sessionFrom(e.do(newRequest(http.MethodPost, "/api/v1/sessions/mfa", answer)).expect(e.t, http.StatusCreated))
}

// sessionFrom reads the signed-in session of a setup, login or MFA response.
func (e *env) sessionFrom(resp response) auth {
	e.t.Helper()
	var out struct {
		CSRFToken string `json:"csrf_token"`
		User      struct {
			UserID string `json:"user_id"`
		} `json:"user"`
	}
	resp.decode(e.t, &out)
	if out.CSRFToken == "" || out.User.UserID == "" {
		e.t.Fatalf("session = %s", resp.body)
	}
	cookie := resp.cookie(e.t)
	return auth{cookie: cookie.Value, csrf: out.CSRFToken, userID: out.User.UserID, raw: cookie}
}

// insertUser creates a user directly in identity and returns its ID; the HTTP
// route is an operation behind an approval, which these helpers skip. An empty
// password leaves the user waiting for an enrollment link, like every user the
// HTTP route creates.
func (e *env) insertUser(username string, role identity.Role, password string) string {
	e.t.Helper()
	ctx := e.t.Context()
	in := identity.CreateUserInput{Username: username, Role: role}
	if password != "" {
		hash, err := e.c.Identity().PreparePassword(ctx, username, password)
		if err != nil {
			e.t.Fatalf("PreparePassword: %v", err)
		}
		in.PasswordHash = hash
	}
	var id string
	if err := e.c.DB().Update(ctx, func(tx *storage.Tx) error {
		res, err := e.c.Identity().CreateUser(ctx, tx, in)
		id = res.User.ID
		return err
	}); err != nil {
		e.t.Fatalf("CreateUser: %v", err)
	}
	return id
}

// signIn creates a user with the test password and signs them in.
func (e *env) signIn(username string, role identity.Role) auth {
	e.t.Helper()
	e.insertUser(username, role, adminPass)
	return e.login(username, adminPass)
}

// enableTOTP confirms a TOTP second factor for a user directly in identity (no
// HTTP round trip) and returns the shared secret and the recovery
// codes. Confirming uses up the current time step: the next code a test sends
// is totpAt(secret, 1).
func (e *env) enableTOTP(userID string) ([]byte, []string) {
	e.t.Helper()
	ctx := e.t.Context()
	enrollment, err := e.c.Identity().BeginTOTPEnrollment(ctx, userID)
	if err != nil {
		e.t.Fatalf("BeginTOTPEnrollment: %v", err)
	}
	secret, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(enrollment.Secret)
	if err != nil {
		e.t.Fatalf("decode TOTP secret: %v", err)
	}
	var codes []string
	if err := e.c.DB().Update(ctx, func(tx *storage.Tx) error {
		var err error
		codes, _, err = e.c.Identity().EnableTOTP(ctx, tx, identity.EnableTOTPInput{
			UserID: userID, ExpectedRevision: enrollment.Revision, Code: totpAt(secret, 0),
		})
		return err
	}); err != nil {
		e.t.Fatalf("EnableTOTP: %v", err)
	}
	return secret, codes
}

// totpAt is the TOTP code of the current time step plus offset; the verifier
// accepts one step on either side of its clock.
func totpAt(secret []byte, offset int64) string {
	return identity.TOTPCode(secret, identity.TOTPStep(time.Now())+offset)
}

// wrongTOTP returns a six-digit code that no step of the verification window
// accepts.
func wrongTOTP(secret []byte) string {
	for d := '0'; d <= '9'; d++ {
		code := strings.Repeat(string(d), 6)
		if code != totpAt(secret, -1) && code != totpAt(secret, 0) && code != totpAt(secret, 1) {
			return code
		}
	}
	panic("unreachable: ten candidates cannot all be one of three codes")
}

// storedColumns are the stored columns a secret must never reach: the
// operation records, the stored idempotent responses, the event journal and the
// audit log.
var storedColumns = []string{
	"operations.args", "operations.result", "operations.error",
	"idempotency_keys.response_body",
	"event_journal.payload",
	"audit_log.subject", "audit_log.details",
}

// storedIn lists the table.column pairs of storedColumns in which some row
// contains s.
func (e *env) storedIn(s string) []string {
	e.t.Helper()
	var hits []string
	for _, tc := range storedColumns {
		table, column, _ := strings.Cut(tc, ".")
		var n int
		if err := e.c.DB().Reader().QueryRowContext(e.t.Context(),
			`SELECT COUNT(*) FROM `+table+` WHERE instr(COALESCE(`+column+`, ''), ?) > 0`, s).Scan(&n); err != nil {
			e.t.Fatalf("scan %s: %v", tc, err)
		}
		if n > 0 {
			hits = append(hits, tc)
		}
	}
	return hits
}

// syncBuffer is a log sink that goroutines may share.
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

// userByUsername finds a user in the admin's user list.
func (e *env) userByUsername(a auth, username string) map[string]any {
	e.t.Helper()
	resp := e.do(a.sign(http.MethodGet, "/api/v1/users?limit=200", "")).expect(e.t, http.StatusOK)
	var page struct {
		Items []map[string]any `json:"items"`
	}
	resp.decode(e.t, &page)
	for _, item := range page.Items {
		if item["username"] == username {
			return item
		}
	}
	e.t.Fatalf("user %q not in %v", username, page.Items)
	return nil
}

// createUser starts the host.users.create operation and returns its approval ID
// and operation ID. The action is risk high, so the expected answer is 202.
func (e *env) createUser(a auth, username, role, key string) (approvalID, operationID string) {
	e.t.Helper()
	body := fmt.Sprintf(`{"username":%q,"role":%q}`, username, role)
	req := a.sign(http.MethodPost, "/api/v1/users", body)
	req.Header.Set("Idempotency-Key", key)
	resp := e.do(req).expect(e.t, http.StatusAccepted)
	if loc := resp.header.Get("Location"); !strings.HasPrefix(loc, "/api/v1/operations/") {
		e.t.Fatalf("Location = %q", loc)
	}
	var op struct {
		OperationID string `json:"operation_id"`
		ApprovalID  string `json:"approval_id"`
	}
	resp.decode(e.t, &op)
	if op.OperationID == "" || op.ApprovalID == "" {
		e.t.Fatalf("accepted operation = %s", resp.body)
	}
	return op.ApprovalID, op.OperationID
}

// approval loads one approval.
func (e *env) approval(a auth, id string) map[string]any {
	e.t.Helper()
	resp := e.do(a.sign(http.MethodGet, "/api/v1/approvals/"+id, "")).expect(e.t, http.StatusOK)
	return resp.decodeMap(e.t)
}

// decide posts an approval decision.
func (e *env) decide(a auth, approvalID, decision, revision, key string) response {
	e.t.Helper()
	body := fmt.Sprintf(`{"decision":%q,"expected_revision":%q}`, decision, revision)
	req := a.sign(http.MethodPost, "/api/v1/approvals/"+approvalID+"/decision", body)
	req.Header.Set("Idempotency-Key", key)
	return e.do(req)
}

// createApprovedUser runs host.users.create through its approval and returns
// the ID of the finished operation.
func (e *env) createApprovedUser(a auth, username, role string) string {
	e.t.Helper()
	approvalID, operationID := e.createUser(a, username, role, "test-create-user-"+username)
	revision := mustString(e.t, e.approval(a, approvalID), "revision")
	e.decide(a, approvalID, "approve", revision, "test-approve-user-"+username).expect(e.t, http.StatusOK)
	return operationID
}

// issueEnrollment posts POST /api/v1/users/{user_id}/enrollment-token.
func (e *env) issueEnrollment(a auth, userID, body string, key int) response {
	e.t.Helper()
	req := a.sign(http.MethodPost, "/api/v1/users/"+userID+"/enrollment-token", body)
	req.Header.Set("Idempotency-Key", idempotencyKey(key))
	return e.do(req)
}

// mustString returns m[key] as a string.
func mustString(t *testing.T, m map[string]any, key string) string {
	t.Helper()
	v, ok := m[key].(string)
	if !ok {
		t.Fatalf("%q = %v, want a string (body %v)", key, m[key], m)
	}
	return v
}

// serviceToken mints a service account and returns its bearer token.
func (e *env) serviceToken(a auth) string {
	e.t.Helper()
	by := actor.Actor{Kind: actor.Human, ID: a.userID, SessionID: "test-session"}
	var created authz.CreatedServiceAccount
	err := e.c.DB().Update(e.t.Context(), func(tx *storage.Tx) error {
		tx.SetOrigin(storage.Origin{Actor: by})
		var cerr error
		created, cerr = e.c.Authorizer().CreateServiceAccount(e.t.Context(), tx, authz.CreateServiceAccountInput{
			Actor: by, Name: "ci", Role: authz.RoleAdmin,
		})
		return cerr
	})
	if err != nil {
		e.t.Fatalf("CreateServiceAccount: %v", err)
	}
	return created.Token
}
