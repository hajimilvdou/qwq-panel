// SPDX-License-Identifier: AGPL-3.0-only

package identity

import (
	"context"
	"crypto/sha256"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/qwq-panel/qwq/internal/actor"
	"github.com/qwq-panel/qwq/internal/platform/problem"
	"github.com/qwq-panel/qwq/internal/storage"
)

func TestPasswordLoginAndSession(t *testing.T) {
	f := newFixture(t)
	u := f.createUser("alice", testPassword, RoleAdmin)
	res := f.login("alice", testPassword)
	if !res.Authenticated() {
		t.Fatal("login did not return a session")
	}
	if res.Session.User.ID != u.ID || res.Session.User.Role != RoleAdmin {
		t.Fatalf("session user = %+v", res.Session.User)
	}
	if res.Session.CSRF == "" {
		t.Fatal("session has no CSRF token")
	}
	if !res.Session.ExpiresAt.Equal(f.clk.Now().Add(DefaultAbsoluteTimeout)) {
		t.Fatalf("absolute expiry = %v", res.Session.ExpiresAt)
	}
	if res.Session.MFAVerifiedAt != (time.Time{}) {
		t.Fatal("session without a second factor reports MFA")
	}
	// The token is stored as a hash only.
	var hash []byte
	if err := f.db.Reader().QueryRowContext(f.ctx, `SELECT token_hash FROM sessions`).Scan(&hash); err != nil {
		t.Fatal(err)
	}
	if string(hash) == res.Token || len(hash) != sha256.Size {
		t.Fatalf("session token stored badly: %d bytes", len(hash))
	}
	a, sess, err := f.svc.AuthenticateSession(f.ctx, res.Token)
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	if a.Kind != actor.Human || a.ID != u.ID || a.SessionID != sess.ID {
		t.Fatalf("actor = %+v", a)
	}
	if a.MFA {
		t.Fatal("MFA reported without a second factor")
	}
	if !a.IsHumanSession() {
		t.Fatal("actor is not a human session")
	}
	if _, _, err := f.svc.AuthenticateSession(f.ctx, "nope"); !problem.HasCode(err, problem.Unauthenticated) {
		t.Fatalf("bad token: %v", err)
	}
	// Logout revokes the session and is idempotent.
	if err := f.svc.Logout(f.ctx, res.Token); err != nil {
		t.Fatalf("logout: %v", err)
	}
	if _, _, err := f.svc.AuthenticateSession(f.ctx, res.Token); !problem.HasCode(err, problem.Unauthenticated) {
		t.Fatalf("session survived logout: %v", err)
	}
	if err := f.svc.Logout(f.ctx, res.Token); err != nil {
		t.Fatalf("second logout: %v", err)
	}
	if f.audit.count(ActionLogout) != 1 {
		t.Fatalf("logout audits = %d", f.audit.count(ActionLogout))
	}
}

func TestLoginFailuresAreIndistinguishable(t *testing.T) {
	f := newFixture(t)
	f.createUser("alice", testPassword, RoleAdmin)
	cases := []LoginInput{
		{Username: "alice", Password: "wrong-password-here", ClientIP: "192.0.2.1"},
		{Username: "nobody", Password: "wrong-password-here", ClientIP: "192.0.2.2"},
		{Username: "bad name", Password: "x", ClientIP: "192.0.2.3"},
	}
	for _, in := range cases {
		if _, err := f.svc.Login(f.ctx, in); !problem.HasCode(err, problem.Unauthenticated) {
			t.Fatalf("Login(%q) = %v, want UNAUTHENTICATED", in.Username, err)
		}
	}
	if f.audit.count(ActionLoginFailed) != 3 {
		t.Fatalf("failed login audits = %d, want 3", f.audit.count(ActionLoginFailed))
	}
}

// TestLoginSaturatedHasherIsIndistinguishable: with every hashing slot taken,
// a known and an unknown username fail the same way, and once the slots are
// free both are back to UNAUTHENTICATED (no cached failure on either path).
func TestLoginSaturatedHasherIsIndistinguishable(t *testing.T) {
	f := newFixture(t)
	f.createUser("alice", testPassword, RoleAdmin)
	release := fillSemaphore(f.svc.hasher)
	codes := make([]problem.Code, 0, 2)
	for i, name := range []string{"alice", "nobody"} {
		ctx, cancel := context.WithTimeout(f.ctx, 50*time.Millisecond)
		_, err := f.svc.Login(ctx, LoginInput{Username: name, Password: "wrong-password-here", ClientIP: fmt.Sprintf("192.0.2.%d", i+1)})
		cancel()
		if err == nil {
			t.Fatalf("Login(%q) succeeded on a saturated hasher", name)
		}
		codes = append(codes, problem.From(err).Code)
	}
	release()
	if codes[0] != codes[1] {
		t.Fatalf("saturated hasher: known user -> %s, unknown user -> %s", codes[0], codes[1])
	}
	for i, name := range []string{"alice", "nobody"} {
		_, err := f.svc.Login(f.ctx, LoginInput{Username: name, Password: "wrong-password-here", ClientIP: fmt.Sprintf("192.0.2.%d", i+10)})
		if !problem.HasCode(err, problem.Unauthenticated) {
			t.Fatalf("Login(%q) after release = %v, want UNAUTHENTICATED", name, err)
		}
	}
}

// TestLoginConcurrentGuessesThrottled proves the budget is spent before argon2
// runs. Every guess that reaches the verifier ends in exactly one bad_password
// audit record, so the audit count is the number of hashes an attacker bought.
func TestLoginConcurrentGuessesThrottled(t *testing.T) {
	f := newFixture(t)
	f.createUser("alice", testPassword, RoleOperator)
	const guesses = 50
	var (
		wg        sync.WaitGroup
		limited   atomic.Int64
		other     atomic.Int64
		threshold = DefaultThrottleOptions().Threshold
	)
	start := make(chan struct{})
	for range guesses {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, err := f.svc.Login(f.ctx, LoginInput{Username: "alice", Password: "not-the-password", ClientIP: "198.51.100.20"})
			switch {
			case problem.HasCode(err, problem.RateLimited):
				limited.Add(1)
			case !problem.HasCode(err, problem.Unauthenticated):
				other.Add(1)
			}
		}()
	}
	close(start)
	wg.Wait()
	if n := other.Load(); n != 0 {
		t.Fatalf("%d guesses ended neither UNAUTHENTICATED nor RATE_LIMITED", n)
	}
	verified := f.audit.count(ActionLoginFailed)
	if verified == 0 || verified > threshold+1 {
		t.Fatalf("%d of %d concurrent guesses reached argon2, want 1..%d", verified, guesses, threshold+1)
	}
	if got := int(limited.Load()); got != guesses-verified {
		t.Fatalf("%d guesses were rate limited, want %d", got, guesses-verified)
	}
}

func TestDisabledUserCannotLogIn(t *testing.T) {
	f := newFixture(t)
	u := f.createUser("alice", testPassword, RoleAdmin)
	f.createUser("root", testPassword, RoleAdmin)
	rev := f.user(u.ID).Revision
	disabled := true
	f.update(func(tx *storage.Tx) error {
		_, err := f.svc.UpdateUser(f.ctx, tx, UpdateUserInput{
			UserID: u.ID, ExpectedRevision: rev, Disabled: &disabled,
		})
		return err
	})
	if _, err := f.svc.Login(f.ctx, LoginInput{Username: "alice", Password: testPassword, ClientIP: "198.51.100.1"}); !problem.HasCode(err, problem.Unauthenticated) {
		t.Fatalf("disabled user logged in: %v", err)
	}
	if got := f.user(u.ID); !got.Disabled {
		t.Fatal("user is not disabled")
	}
}

func TestSessionIdleTimeout(t *testing.T) {
	f := newFixtureWith(t, Options{IdleTimeout: 10 * time.Minute, AbsoluteTimeout: time.Hour})
	f.createUser("alice", testPassword, RoleOperator)
	res := f.login("alice", testPassword)
	f.clk.Advance(11 * time.Minute)
	if _, _, err := f.svc.AuthenticateSession(f.ctx, res.Token); !problem.HasCode(err, problem.Unauthenticated) {
		t.Fatalf("idle session accepted: %v", err)
	}
}

func TestSessionAbsoluteTimeout(t *testing.T) {
	f := newFixtureWith(t, Options{IdleTimeout: 24 * time.Hour, AbsoluteTimeout: time.Hour})
	f.createUser("alice", testPassword, RoleOperator)
	res := f.login("alice", testPassword)
	f.clk.Advance(59 * time.Minute)
	if _, _, err := f.svc.AuthenticateSession(f.ctx, res.Token); err != nil {
		t.Fatalf("session rejected before its absolute deadline: %v", err)
	}
	f.clk.Advance(2 * time.Minute)
	if _, _, err := f.svc.AuthenticateSession(f.ctx, res.Token); !problem.HasCode(err, problem.Unauthenticated) {
		t.Fatalf("session outlived its absolute deadline: %v", err)
	}
}

func TestSessionTouchIsThrottled(t *testing.T) {
	f := newFixture(t)
	f.createUser("alice", testPassword, RoleOperator)
	res := f.login("alice", testPassword)
	read := func() string {
		var v string
		if err := f.db.Reader().QueryRowContext(f.ctx, `SELECT last_seen_at FROM sessions WHERE session_id = ?`, res.Session.ID).Scan(&v); err != nil {
			t.Fatal(err)
		}
		return v
	}
	first := read()
	f.clk.Advance(30 * time.Second)
	if _, _, err := f.svc.AuthenticateSession(f.ctx, res.Token); err != nil {
		t.Fatal(err)
	}
	if got := read(); got != first {
		t.Fatalf("last_seen_at written after 30s: %s -> %s", first, got)
	}
	f.clk.Advance(40 * time.Second)
	if _, _, err := f.svc.AuthenticateSession(f.ctx, res.Token); err != nil {
		t.Fatal(err)
	}
	if got := read(); got == first {
		t.Fatal("last_seen_at was not refreshed after the touch interval")
	}
}
