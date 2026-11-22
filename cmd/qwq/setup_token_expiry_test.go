// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"testing"
	"time"

	"github.com/qwq-panel/qwq/internal/controller"
	"github.com/qwq-panel/qwq/internal/identity"
	"github.com/qwq-panel/qwq/internal/platform/clock"
	"github.com/qwq-panel/qwq/internal/platform/problem"
)

// ======================== 真 CLI 签发，重开 Controller 验证持久过期边界 ========================

func TestSetupTokenHonorsAdvertisedExpiry(t *testing.T) {
	for _, test := range []struct {
		name    string
		elapsed time.Duration
		expired bool
	}{
		{name: "before_deadline", elapsed: 30*time.Minute - time.Millisecond},
		{name: "at_deadline", elapsed: 30 * time.Minute, expired: true},
		{name: "after_deadline", elapsed: 30*time.Minute + time.Millisecond, expired: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			cfgPath, cfg := initDataDir(t)
			token := issueSetupToken(t, cfgPath)
			clk := clock.NewFake(time.Now().UTC())
			c, err := controller.New(t.Context(), controller.Options{Config: cfg, Clock: clk})
			if err != nil {
				t.Fatalf("reopen controller: %v", err)
			}
			t.Cleanup(func() {
				if err := c.Close(); err != nil {
					t.Errorf("close controller: %v", err)
				}
			})
			var createdText, expiresText string
			if err := c.DB().Reader().QueryRowContext(t.Context(),
				`SELECT created_at, expires_at FROM one_time_tokens WHERE purpose = 'setup' AND used_at = ''`,
			).Scan(&createdText, &expiresText); err != nil {
				t.Fatalf("read persisted setup deadline: %v", err)
			}
			created, err := time.Parse(time.RFC3339Nano, createdText)
			if err != nil {
				t.Fatal(err)
			}
			expires, err := time.Parse(time.RFC3339Nano, expiresText)
			if err != nil {
				t.Fatal(err)
			}
			if ttl := expires.Sub(created); ttl != 30*time.Minute {
				t.Errorf("persisted setup lifetime = %s, want advertised 30m", ttl)
			}
			clk.Advance(created.Add(test.elapsed).Sub(clk.Now()))
			_, err = c.Identity().CompleteSetup(t.Context(), identity.CompleteSetupInput{
				SetupToken: token, Username: "admin", Password: "InitialPassword123!",
			})
			if test.expired {
				if !problem.HasCode(err, problem.Unauthenticated) {
					t.Fatalf("setup link remained usable at/after 30m: %v", err)
				}
			} else if err != nil {
				t.Fatalf("setup link rejected just before 30m: %v", err)
			}
			initialized, err := c.Identity().SetupInitialized(t.Context())
			if err != nil {
				t.Fatalf("read setup state after redemption: %v", err)
			}
			wantInitialized := !test.expired
			if initialized != wantInitialized {
				t.Fatalf("setup initialized=%v after expired=%v redemption", initialized, test.expired)
			}
		})
	}
}
