// SPDX-License-Identifier: AGPL-3.0-only

package identity

import (
	"testing"
	"time"

	"github.com/qwq-panel/qwq/internal/storage"
)

// TestPruneRemovesExpiredSessionsAndTokens (OPS-05): sessions keep their row for
// the retention window after they expired or were revoked, used and expired
// one-time tokens go immediately, expired MFA challenges go, and nothing that is
// still usable is touched.
func TestPruneRemovesExpiredSessionsAndTokens(t *testing.T) {
	f := newFixture(t)
	f.createUser("prune", testPassword, RoleAdmin)
	f.login("prune", testPassword)
	revoked := f.login("prune", testPassword)
	if err := f.svc.Logout(f.ctx, revoked.Token); err != nil {
		t.Fatalf("logout: %v", err)
	}
	if _, _, err := f.svc.NewSetupToken(f.ctx); err != nil {
		t.Fatalf("setup token: %v", err)
	}
	mfaUser := f.createUser("prune-mfa", testPassword, RoleViewer)
	f.enableTOTP(mfaUser.ID)
	if res := f.login("prune-mfa", testPassword); res.MFA == nil {
		t.Fatal("login did not open an MFA challenge")
	}

	f.clk.Advance(31 * 24 * time.Hour)
	fresh := f.login("prune", testPassword)
	// A redeemed token: used_at is set, so it goes even before it expires.
	f.update(func(tx *storage.Tx) error {
		_, err := tx.ExecContext(f.ctx, `UPDATE one_time_tokens SET used_at = ? WHERE used_at = ''`,
			formatTime(f.clk.Now()))
		return err
	})
	if _, _, err := f.svc.NewSetupToken(f.ctx); err != nil {
		t.Fatalf("setup token: %v", err)
	}

	if err := f.svc.Prune(f.ctx, f.clk.Now()); err != nil {
		t.Fatalf("prune: %v", err)
	}
	for _, tc := range []struct {
		table string
		want  int
	}{
		{"sessions", 1},
		{"one_time_tokens", 1},
		{"mfa_challenges", 0},
	} {
		if n := f.countRows(tc.table); n != tc.want {
			t.Errorf("%s rows = %d, want %d", tc.table, n, tc.want)
		}
	}
	if _, _, err := f.svc.AuthenticateSession(f.ctx, fresh.Token); err != nil {
		t.Fatalf("the fresh session was pruned: %v", err)
	}
	// Pruning again changes nothing.
	if err := f.svc.Prune(f.ctx, f.clk.Now()); err != nil {
		t.Fatalf("second prune: %v", err)
	}
	if n := f.countRows("sessions"); n != 1 {
		t.Fatalf("sessions after the second prune = %d, want 1", n)
	}
}

// TestPruneKeepsSessionsInsideWindow: a session that expired yesterday is still
// inside the retention window and keeps its row.
func TestPruneKeepsSessionsInsideWindow(t *testing.T) {
	f := newFixtureWith(t, Options{SessionRetention: 30 * 24 * time.Hour})
	f.createUser("keep", testPassword, RoleAdmin)
	f.login("keep", testPassword)
	f.clk.Advance(2 * 24 * time.Hour)
	if err := f.svc.Prune(f.ctx, f.clk.Now()); err != nil {
		t.Fatalf("prune: %v", err)
	}
	if n := f.countRows("sessions"); n != 1 {
		t.Fatalf("sessions = %d, want 1", n)
	}
}

// countRows counts a whole table.
func (f *fixture) countRows(table string) int {
	f.t.Helper()
	var n int
	if err := f.db.Reader().QueryRowContext(f.ctx, `SELECT COUNT(*) FROM `+table).Scan(&n); err != nil {
		f.t.Fatalf("count %s: %v", table, err)
	}
	return n
}
