// SPDX-License-Identifier: AGPL-3.0-only

package controller

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/qwq-panel/qwq/internal/actor"
	"github.com/qwq-panel/qwq/internal/authz"
	"github.com/qwq-panel/qwq/internal/gateway"
	"github.com/qwq-panel/qwq/internal/operations"
	"github.com/qwq-panel/qwq/internal/operations/opstest"
	"github.com/qwq-panel/qwq/internal/platform/clock"
	"github.com/qwq-panel/qwq/internal/platform/config"
	"github.com/qwq-panel/qwq/internal/storage"
	platformv1 "github.com/qwq-panel/qwq/sdk/gen/qwq/platform/v1"
)

func testOptions(t *testing.T) Options {
	t.Helper()
	dir := t.TempDir()
	cfg := config.Default()
	cfg.DataDir = filepath.Join(dir, "data")
	cfg.RunDir = filepath.Join(dir, "run")
	return Options{Config: cfg}
}

func TestNewOpensStorageAndHealth(t *testing.T) {
	ctx := t.Context()
	c, err := New(ctx, testOptions(t))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })

	if v, err := c.DB().SchemaVersion(ctx); err != nil || v == 0 {
		t.Fatalf("SchemaVersion = %d, %v", v, err)
	}
	if err := c.Ready(ctx); err != nil {
		t.Fatalf("Ready: %v", err)
	}
	keyInfo, err := os.Stat(filepath.Join(c.Config().DataDir, "keys", "master.key"))
	if err != nil {
		t.Fatalf("master key: %v", err)
	}
	if perm := keyInfo.Mode().Perm(); perm != 0o600 {
		t.Fatalf("master key mode = %04o, want 0600", perm)
	}
	if c.TLS() == nil || c.TLS().TLSConfig() == nil {
		t.Fatal("self-signed TLS config missing")
	}
	if fp := c.TLS().Fingerprint(); fp == "" {
		t.Fatal("self-signed fingerprint is empty")
	}

	srv := httptest.NewServer(c.Handler())
	t.Cleanup(srv.Close)

	for _, path := range []string{"/healthz", "/readyz"} {
		res, err := http.Get(srv.URL + path)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		var body map[string]string
		if err := json.NewDecoder(res.Body).Decode(&body); err != nil {
			t.Fatalf("GET %s: decode: %v", path, err)
		}
		res.Body.Close()
		if res.StatusCode != http.StatusOK || body["status"] != "ok" {
			t.Fatalf("GET %s = %d %v", path, res.StatusCode, body)
		}
	}
}

func TestDataDirMustBePrivate(t *testing.T) {
	opts := testOptions(t)
	if err := os.MkdirAll(opts.Config.DataDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(opts.Config.DataDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := New(t.Context(), opts); err == nil {
		t.Fatal("New accepted a data directory readable by group/others")
	}
}

func TestInvalidConfigRejected(t *testing.T) {
	opts := testOptions(t)
	opts.Config.HTTP.TLS.Mode = "bogus"
	if _, err := New(t.Context(), opts); err == nil {
		t.Fatal("New accepted an invalid TLS mode")
	}
}

func TestCloseIsIdempotent(t *testing.T) {
	c, err := New(t.Context(), testOptions(t))
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	if err := c.Ready(t.Context()); err == nil {
		t.Fatal("Ready succeeded after Close")
	}
}

// TestGatewayRateLimitersWired checks that New puts all three request limiters
// in front of the API with the gateway defaults: per client IP before
// authentication, a stricter budget for unauthenticated writes (login, setup,
// MFA) and per principal after authentication. The clock only moves when the
// test advances it, so both the burst and the refill rate of each limiter are
// observable.
func TestGatewayRateLimitersWired(t *testing.T) {
	clk := clock.NewFake(time.Now().UTC())
	opts := testOptions(t)
	opts.Clock = clk
	c, err := New(t.Context(), opts)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })

	noContent := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	for _, rt := range []gateway.Route{
		{Method: http.MethodPost, Pattern: "/api/v1/sessions", Access: gateway.AccessPublic, Body: gateway.BodyJSON, Handler: noContent},
		{Method: http.MethodGet, Pattern: "/api/v1/nodes", Access: gateway.AccessSessionOrService, Handler: noContent},
	} {
		if err := c.Gateway().Handle(rt); err != nil {
			t.Fatalf("Handle %s %s: %v", rt.Method, rt.Pattern, err)
		}
	}
	request := func(method, target, body, clientIP, bearer string) *http.Request {
		r := httptest.NewRequest(method, target, strings.NewReader(body))
		r.RemoteAddr = clientIP + ":4321"
		if body != "" {
			r.Header.Set("Content-Type", "application/json")
		}
		if bearer != "" {
			r.Header.Set("Authorization", "Bearer "+bearer)
		}
		return r
	}
	// limited checks one limiter through the requests built by next: burst
	// requests answer status and the next one 429 with Retry-After; after one
	// and a half token periods exactly one more request gets through.
	limited := func(name string, rate float64, burst, status int, next func(i int) *http.Request) {
		t.Helper()
		i := 0
		send := func(want int) {
			t.Helper()
			rec := httptest.NewRecorder()
			c.Handler().ServeHTTP(rec, next(i))
			i++
			if rec.Code != want {
				t.Fatalf("%s: request %d = %d, want %d (body %s)", name, i, rec.Code, want, rec.Body)
			}
			if want == http.StatusTooManyRequests && rec.Header().Get("Retry-After") == "" {
				t.Fatalf("%s: request %d is a 429 without Retry-After", name, i)
			}
		}
		for n := 0; n < burst; n++ {
			send(status)
		}
		send(http.StatusTooManyRequests)
		clk.Advance(time.Duration(1.5 / rate * float64(time.Second)))
		send(status)
		send(http.StatusTooManyRequests)
	}

	// Before authentication: anonymous requests from one address never reach
	// the per-principal limiter (authentication refuses them first).
	limited("pre-auth", gateway.DefaultPreAuthRate, gateway.DefaultPreAuthBurst, http.StatusUnauthorized, func(int) *http.Request {
		return request(http.MethodGet, "/api/v1/nodes", "", "198.51.100.1", "")
	})
	// Unauthenticated writes from one address.
	limited("public write", gateway.DefaultPublicWriteRate, gateway.DefaultPublicWriteBurst, http.StatusNoContent, func(int) *http.Request {
		return request(http.MethodPost, "/api/v1/sessions", `{}`, "198.51.100.2", "")
	})
	// After authentication: one service account spread over many addresses, so
	// only the per-principal limiter can refuse it.
	by := actor.Actor{Kind: actor.Human, ID: "usr_wiring", SessionID: "ses_wiring"}
	var sa authz.CreatedServiceAccount
	if err := c.DB().Update(t.Context(), func(tx *storage.Tx) error {
		tx.SetOrigin(storage.Origin{Actor: by})
		var err error
		sa, err = c.Authorizer().CreateServiceAccount(t.Context(), tx, authz.CreateServiceAccountInput{
			Actor: by, Name: "wiring", Role: authz.RoleViewer,
		})
		return err
	}); err != nil {
		t.Fatalf("CreateServiceAccount: %v", err)
	}
	limited("per principal", gateway.DefaultRequestRate, gateway.DefaultRequestBurst, http.StatusNoContent, func(i int) *http.Request {
		return request(http.MethodGet, "/api/v1/nodes", "", fmt.Sprintf("10.0.0.%d", i+1), sa.Token)
	})
}

// TestDeferOperationsDoesNotResume proves that a deferred controller leaves an
// approved operation alone until StartOperations: its host action handler is
// registered later, so resuming it inside New would fail it for good.
func TestDeferOperationsDoesNotResume(t *testing.T) {
	ctx := t.Context()
	opts := testOptions(t)
	c, err := New(ctx, opts)
	if err != nil {
		t.Fatal(err)
	}
	const id = "op_deferred"
	if err := opstest.InsertApproved(ctx, c.DB(), opstest.Seed{
		ID: id, Action: opstest.HostAction("host.test.deferred"), ActorID: "usr_test",
	}); err != nil {
		t.Fatal(err)
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}

	opts.DeferOperations = true
	c, err = New(ctx, opts)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	time.Sleep(100 * time.Millisecond)
	status := func() string {
		var s string
		if err := c.DB().Reader().QueryRowContext(ctx,
			`SELECT status FROM operations WHERE operation_id = ?`, id).Scan(&s); err != nil {
			t.Fatal(err)
		}
		return s
	}
	if got := status(); got != "APPROVED" {
		t.Fatalf("before StartOperations the operation is %s, want APPROVED", got)
	}
	c.Operations().RegisterHostAction("host.test.deferred",
		func(context.Context, *storage.Tx, operations.HostRequest) (json.RawMessage, error) {
			return json.RawMessage(`{"ok":true}`), nil
		}, nil)
	c.StartOperations(ctx)
	deadline := time.Now().Add(5 * time.Second)
	for status() != "SUCCEEDED" {
		if time.Now().After(deadline) {
			t.Fatalf("after StartOperations the operation is %s, want SUCCEEDED", status())
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// blockingJobClient is a plugin whose RunJob runs until the job context ends.
// It records whether the plugin runtime had already stopped by then: a stopped
// runtime cuts the stream of a live worker, which fails the job instead of
// leaving it to recovery.
type blockingJobClient struct {
	PluginClient
	rt         *PluginRuntime
	started    chan struct{}
	runtimeCut atomic.Bool
}

func (b *blockingJobClient) RunJob(ctx context.Context, _ *platformv1.RunJobRequest, _ func(*platformv1.JobProgress) error) error {
	close(b.started)
	<-ctx.Done()
	b.rt.mu.Lock()
	b.runtimeCut.Store(b.rt.stopped)
	b.rt.mu.Unlock()
	return ctx.Err()
}

// TestCloseStopsOperationsBeforePlugins runs a job when the controller closes:
// the operation manager stops first, so the job ends by its own context and
// stays RUNNING for the next recovery instead of being failed by a plugin
// stream the runtime cut underneath a live worker.
func TestCloseStopsOperationsBeforePlugins(t *testing.T) {
	ctx := t.Context()
	opts := testOptions(t)
	seed, err := New(ctx, opts)
	if err != nil {
		t.Fatal(err)
	}
	const id = "op_close_job"
	if err := opstest.InsertApproved(ctx, seed.DB(), opstest.Seed{ID: id, ActorID: "usr_test", Action: operations.Action{
		ID: "alpha.job", Effect: operations.EffectWrite, Risk: operations.RiskLow, Mode: operations.ModeJob,
		Source: operations.PluginSource, PluginID: "alpha", Operation: "job", APIVersion: "1", TimeoutMS: 60000,
	}}); err != nil {
		t.Fatal(err)
	}
	if err := seed.Close(); err != nil {
		t.Fatal(err)
	}

	rt := newTestRuntime(t)
	client := &blockingJobClient{rt: rt, started: make(chan struct{})}
	rt.dispatcher = &pluginDispatcher{clients: &fakeClients{client: client}}
	opts.PluginRuntime = rt
	c, err := New(ctx, opts)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	select {
	case <-client.started:
	case <-time.After(5 * time.Second):
		t.Fatal("the job never started")
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	db, err := storage.Open(ctx, storage.Options{Path: filepath.Join(opts.Config.DataDir, "qwq.db")})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var status string
	if err := db.Reader().QueryRowContext(ctx, `SELECT status FROM operations WHERE operation_id = ?`, id).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if client.runtimeCut.Load() {
		t.Fatal("the plugin runtime stopped before the operation manager")
	}
	if status != "RUNNING" {
		t.Fatalf("after Close the job is %s, want RUNNING", status)
	}
}

// TestReadyDuringCloseNoRace probes readiness while the controller closes; the
// race detector fails it if Close writes a field Ready reads.
func TestReadyDuringCloseNoRace(t *testing.T) {
	c, err := New(t.Context(), testOptions(t))
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 200; i++ {
			_ = c.Ready(context.Background())
			_ = c.DB()
		}
	}()
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	<-done
	if err := c.Ready(context.Background()); err == nil {
		t.Fatal("Ready succeeded after Close")
	}
}
