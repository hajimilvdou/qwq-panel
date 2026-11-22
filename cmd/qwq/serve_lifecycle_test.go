// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"database/sql"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/qwq-panel/qwq/internal/agentsession"
	"github.com/qwq-panel/qwq/internal/controller"
	"github.com/qwq-panel/qwq/internal/gateway"
	"github.com/qwq-panel/qwq/internal/identity"
	"github.com/qwq-panel/qwq/internal/operations/opstest"
	"github.com/qwq-panel/qwq/internal/platform/config"
)

// ---------------------------------------------------------------------------
// runServe 端到端夹具：真实进程装配 + 自发信号关停
// ---------------------------------------------------------------------------

// syncBuffer is a bytes.Buffer safe for the serve goroutine and the test.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// servedHost is a runServe running in the background.
type servedHost struct {
	stdout, stderr *syncBuffer
	exit           chan int
}

// serveTestConfig returns a config for runServe on an free loopback port.
func serveTestConfig(t *testing.T) config.Config {
	t.Helper()
	cfg := testConfig(t)
	// The config refuses port 0, so reserve a free loopback port and release
	// it right before runServe binds it.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	cfg.HTTP.Listen = ln.Addr().String()
	_ = ln.Close()
	cfg.Log.Level = "error"
	return cfg
}

// startServe runs `serve-controller` with cfg until the listener is up. The
// plugin directory does not exist, so the plugin runtime and the updater stay
// disabled; the privileged socket does not exist either, which a root host
// treats as "in-process" and a non-root host as "helper not running yet".
func startServe(t *testing.T, cfg config.Config) *servedHost {
	t.Helper()
	dir := t.TempDir()
	raw, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "qwq.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	h := &servedHost{stdout: &syncBuffer{}, stderr: &syncBuffer{}, exit: make(chan int, 1)}
	go func() {
		h.exit <- runServe([]string{
			"--config", path,
			"--plugins-dir", filepath.Join(dir, "plugins"),
			"--trust-dir", filepath.Join(dir, "trust"),
			"--staging-dir", filepath.Join(dir, "staging"),
			"--privileged-socket", filepath.Join(dir, "privileged.sock"),
		}, h.stdout, h.stderr)
	}()
	deadline := time.After(30 * time.Second)
	for !strings.Contains(h.stdout.String(), "listening on ") {
		select {
		case code := <-h.exit:
			t.Fatalf("serve exited with %d before listening: %s", code, h.stderr.String())
		case <-deadline:
			t.Fatalf("serve did not start listening: %s", h.stderr.String())
		case <-time.After(5 * time.Millisecond):
		}
	}
	t.Cleanup(func() { h.stop(t, 30*time.Second) })
	return h
}

// stop sends SIGINT to this process (runServe's handler absorbs it) and waits
// for runServe to return. It returns how long the shutdown took.
func (h *servedHost) stop(t *testing.T, within time.Duration) time.Duration {
	t.Helper()
	if h.exit == nil {
		return 0
	}
	p, err := os.FindProcess(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	begin := time.Now()
	if err := p.Signal(os.Interrupt); err != nil {
		t.Fatal(err)
	}
	select {
	case code := <-h.exit:
		h.exit = nil
		if code != 0 {
			t.Errorf("serve exit = %d: %s", code, h.stderr.String())
		}
	case <-time.After(within):
		t.Fatalf("serve did not stop within %s", within)
	}
	return time.Since(begin)
}

// listenAddr extracts the bound address from the "listening on" line.
func (h *servedHost) listenAddr(t *testing.T) string {
	t.Helper()
	for _, line := range strings.Split(h.stdout.String(), "\n") {
		if rest, ok := strings.CutPrefix(line, "listening on "); ok {
			return strings.Fields(rest)[0]
		}
	}
	t.Fatalf("no listening line in %q", h.stdout.String())
	return ""
}

// seedAdmin completes first-time setup on cfg's database and returns the
// session token of the administrator.
func seedAdmin(t *testing.T, c *controller.Controller) identity.LoginResult {
	t.Helper()
	ctx := t.Context()
	token, _, err := c.Identity().NewSetupToken(ctx)
	if err != nil {
		t.Fatal(err)
	}
	admin, err := c.Identity().CompleteSetup(ctx, identity.CompleteSetupInput{
		SetupToken: token, Username: "admin", Password: "InitialPassword123!",
	})
	if err != nil {
		t.Fatal(err)
	}
	return admin
}

// ---------------------------------------------------------------------------
// CTL-01：恢复派发在全部宿主动作 handler 注册之后
// ---------------------------------------------------------------------------

// TestServeResumesApprovedOperationsAfterRoutes stages an approved
// host.users.create left behind by a restart. Its handler is registered by
// api.Register, so the operation must resume only after the routes are in
// place, and succeed.
func TestServeResumesApprovedOperationsAfterRoutes(t *testing.T) {
	ctx := t.Context()
	cfg := serveTestConfig(t)
	c, err := controller.New(ctx, controller.Options{Config: cfg})
	if err != nil {
		t.Fatal(err)
	}
	admin := seedAdmin(t, c)
	const id = "op_resume_after_routes"
	if err := opstest.InsertApproved(ctx, c.DB(), opstest.Seed{
		ID: id, Action: opstest.HostAction("host.users.create"), ActorID: admin.Session.User.ID,
		Args: json.RawMessage(`{"username":"bob","role":"viewer"}`),
	}); err != nil {
		t.Fatal(err)
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}

	startServe(t, cfg)
	deadline := time.Now().Add(10 * time.Second)
	for {
		status, detail := operationStatus(t, cfg, id)
		if status == "SUCCEEDED" {
			return
		}
		if status != "APPROVED" && status != "RUNNING" || time.Now().After(deadline) {
			t.Fatalf("operation = %s (%s), want SUCCEEDED", status, detail)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// operationStatus reads an operation through a read-only connection of its
// own, so the test can watch a running host without sharing its handles.
func operationStatus(t *testing.T, cfg config.Config, id string) (status, detail string) {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+filepath.Join(cfg.DataDir, "qwq.db")+"?_pragma=query_only(1)&_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.QueryRowContext(t.Context(),
		`SELECT status, COALESCE(error, '') FROM operations WHERE operation_id = ?`, id).Scan(&status, &detail); err != nil {
		t.Fatal(err)
	}
	return status, detail
}

// ---------------------------------------------------------------------------
// CTL-02：开着 SSE 的关停应当迅速完成
// ---------------------------------------------------------------------------

// TestServeShutdownWithOpenSSEIsPrompt keeps the event stream and an agent
// session stream open, as a dashboard does, and stops the host: both brokers
// close as Shutdown begins, so the drain does not wait out its budget.
func TestServeShutdownWithOpenSSEIsPrompt(t *testing.T) {
	ctx := t.Context()
	cfg := serveTestConfig(t)
	c, err := controller.New(ctx, controller.Options{Config: cfg})
	if err != nil {
		t.Fatal(err)
	}
	admin := seedAdmin(t, c)
	who, _, err := c.Identity().AuthenticateSession(ctx, admin.Token)
	if err != nil {
		t.Fatal(err)
	}
	sessions, err := c.NewAgentSessions(ctx)
	if err != nil {
		t.Fatal(err)
	}
	session, err := sessions.Create(ctx, who, agentsession.CreateRequest{Title: "shutdown"})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}

	h := startServe(t, cfg)
	client := &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // self-signed test host
	}}
	base := "https://" + h.listenAddr(t)
	for _, path := range []string{"/api/v1/events", "/api/v1/agent-sessions/" + session.ID + "/events"} {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Accept", "text/event-stream")
		req.AddCookie(&http.Cookie{Name: gateway.SessionCookieName, Value: admin.Token})
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
			resp.Body.Close()
			t.Fatalf("%s = %d: %s", path, resp.StatusCode, body)
		}
		// Drain in the background so the server never blocks on a full
		// socket; the body ends when the host closes the stream.
		go func() {
			defer resp.Body.Close()
			_, _ = io.Copy(io.Discard, resp.Body)
		}()
	}

	if took := h.stop(t, 30*time.Second); took > 3*time.Second {
		t.Fatalf("shutdown with open streams took %s, want under 3s", took)
	}
}

// ---------------------------------------------------------------------------
// CTL-03：卡死的 saga 恢复不能阻止宿主启动
// ---------------------------------------------------------------------------

// stuckRecoverer is an updater whose plugin never answers: Recover returns only
// when its context ends.
type stuckRecoverer struct{}

func (stuckRecoverer) Recover(ctx context.Context) ([]string, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

// TestServeStartsDespiteStuckRecover runs the startup recovery step against a
// plugin that hangs: it gives up at its timeout, logs an error and lets
// startup continue, even though the service lifetime has no deadline.
func TestServeStartsDespiteStuckRecover(t *testing.T) {
	var logs syncBuffer
	logger := slog.New(slog.NewTextHandler(&logs, nil))
	done := make(chan struct{})
	go func() {
		recoverSagas(context.Background(), stuckRecoverer{}, 100*time.Millisecond, logger)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("startup recovery blocked on a stuck plugin")
	}
	if out := logs.String(); !strings.Contains(out, "recovery failed") || !strings.Contains(out, "timed_out=true") {
		t.Fatalf("recovery log = %q", out)
	}
}
