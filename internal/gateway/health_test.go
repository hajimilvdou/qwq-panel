// SPDX-License-Identifier: AGPL-3.0-only

package gateway_test

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/qwq-panel/qwq/internal/gateway"
	"github.com/qwq-panel/qwq/internal/platform/problem"
)

func TestHealthzAndReadyz(t *testing.T) {
	g := testGateway(t)

	resp := do(t, g, newRequest(http.MethodGet, "/healthz", ""))
	if resp.code != http.StatusOK {
		t.Fatalf("healthz status = %d", resp.code)
	}
	var health gateway.HealthStatus
	resp.decode(t, &health)
	if health.Status != "ok" {
		t.Fatalf("healthz = %+v", health)
	}

	resp = do(t, g, newRequest(http.MethodGet, "/readyz", ""))
	if resp.code != http.StatusOK {
		t.Fatalf("readyz status = %d (body %s)", resp.code, resp.body)
	}

	if err := g.AddCheck(gateway.Check{Name: "database", Check: func(context.Context) error { return nil }}); err != nil {
		t.Fatalf("AddCheck: %v", err)
	}
	if resp := do(t, g, newRequest(http.MethodGet, "/readyz", "")); resp.code != http.StatusOK {
		t.Fatalf("readyz with a passing check = %d", resp.code)
	}
	if err := g.AddCheck(gateway.Check{Name: "database", Check: func(context.Context) error { return nil }}); err == nil {
		t.Fatal("duplicate check was accepted")
	}
}

func TestReadyzReportsUnavailableWithoutLeaking(t *testing.T) {
	g := testGateway(t)
	secret := "certificate /var/lib/qwq/tls/tls.pem expires in 1h"
	if err := g.AddCheck(gateway.Check{Name: "tls", Check: func(context.Context) error {
		return errors.New(secret)
	}}); err != nil {
		t.Fatalf("AddCheck: %v", err)
	}
	resp := do(t, g, newRequest(http.MethodGet, "/readyz", ""))
	if resp.code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", resp.code)
	}
	p := resp.problem(t)
	if p.Code != problem.Unavailable || !p.Retryable {
		t.Fatalf("problem = %+v", p)
	}
	if !strings.Contains(p.Detail, "tls") {
		t.Fatalf("detail = %q, want the check name", p.Detail)
	}
	if strings.Contains(string(resp.body), "/var/lib/qwq") {
		t.Fatalf("readiness leak: %s", resp.body)
	}
}

func TestCheckValidation(t *testing.T) {
	g := testGateway(t)
	bad := []gateway.Check{
		{},
		{Name: "x"},
		{Name: repeat("n", 65), Check: func(context.Context) error { return nil }},
	}
	for _, c := range bad {
		if err := g.AddCheck(c); err == nil {
			t.Errorf("check %+v was accepted", c)
		}
	}
	cfg := testConfig(nil)
	cfg.Checks = []gateway.Check{{Name: "broken"}}
	if _, err := gateway.New(cfg); err == nil {
		t.Fatal("New accepted an invalid configured check")
	}
}

func TestReadyzHonoursCheckTimeout(t *testing.T) {
	g := testGateway(t)
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	if err := g.AddCheck(gateway.Check{Name: "slow", Check: func(ctx context.Context) error {
		select {
		case <-release:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(30 * time.Second):
			return nil
		}
	}}); err != nil {
		t.Fatalf("AddCheck: %v", err)
	}
	start := time.Now()
	resp := do(t, g, newRequest(http.MethodGet, "/readyz", ""))
	if resp.code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", resp.code)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("readyz took %v; the check timeout did not apply", elapsed)
	}
}
