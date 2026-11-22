// SPDX-License-Identifier: AGPL-3.0-only

package identity

import (
	"crypto/sha256"
	"testing"
	"time"

	"github.com/qwq-panel/qwq/internal/platform/problem"
	"github.com/qwq-panel/qwq/internal/storage"
)

func TestSetupFlow(t *testing.T) {
	f := newFixture(t)
	if init, err := f.svc.SetupInitialized(f.ctx); err != nil || init {
		t.Fatalf("fresh installation reports initialized=%v err=%v", init, err)
	}
	token, expires, err := f.svc.NewSetupToken(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(token) < 32 {
		t.Fatalf("setup token too short: %d", len(token))
	}
	if want := f.clk.Now().Add(DefaultSetupTokenTTL); !expires.Equal(want) {
		t.Fatalf("expiry = %v, want %v", expires, want)
	}
	// Only the hash is stored.
	var hash []byte
	if err := f.db.Reader().QueryRowContext(f.ctx, `SELECT token_hash FROM one_time_tokens`).Scan(&hash); err != nil {
		t.Fatal(err)
	}
	if string(hash) == token {
		t.Fatal("setup token stored in clear")
	}
	if len(hash) != sha256.Size {
		t.Fatalf("token_hash length = %d, want %d", len(hash), sha256.Size)
	}
	res, err := f.svc.CompleteSetup(f.ctx, CompleteSetupInput{
		SetupToken: token, Username: "Admin", Password: testPassword,
		DisplayName: "Owner", ClientIP: "127.0.0.1", UserAgent: "test",
	})
	if err != nil {
		t.Fatalf("complete setup: %v", err)
	}
	if !res.Authenticated() {
		t.Fatal("setup did not return a session")
	}
	if res.Session.User.Username != "admin" || res.Session.User.Role != RoleAdmin {
		t.Fatalf("first user = %+v", res.Session.User)
	}
	if init, err := f.svc.SetupInitialized(f.ctx); err != nil || !init {
		t.Fatalf("initialized=%v err=%v after setup", init, err)
	}
	if _, _, err := f.svc.AuthenticateSession(f.ctx, res.Token); err != nil {
		t.Fatalf("session from setup is not usable: %v", err)
	}
	// A second attempt is a state conflict, even with the used token.
	_, err = f.svc.CompleteSetup(f.ctx, CompleteSetupInput{
		SetupToken: token, Username: "other", Password: testPassword,
	})
	if !problem.HasCode(err, problem.StateConflict) {
		t.Fatalf("second setup: %v, want STATE_CONFLICT", err)
	}
	if f.audit.count(ActionSetupCompleted) != 1 {
		t.Fatalf("setup audits = %d", f.audit.count(ActionSetupCompleted))
	}
	// The used token is also refused on a database where setup is open again:
	// simulate by checking the token row directly.
	var used string
	if err := f.db.Reader().QueryRowContext(f.ctx, `SELECT used_at FROM one_time_tokens`).Scan(&used); err != nil {
		t.Fatal(err)
	}
	if used == "" {
		t.Fatal("setup token was not consumed")
	}
}

func TestCompleteSetupRejectsToken(t *testing.T) {
	f := newFixture(t)
	_, err := f.svc.CompleteSetup(f.ctx, CompleteSetupInput{
		SetupToken: "wrong-token-that-is-long-enough", Username: "admin", Password: testPassword,
	})
	if !problem.HasCode(err, problem.Unauthenticated) {
		t.Fatalf("wrong token: %v, want UNAUTHENTICATED", err)
	}
	if _, err := f.svc.CompleteSetup(f.ctx, CompleteSetupInput{
		Username: "admin", Password: testPassword,
	}); !problem.HasCode(err, problem.Unauthenticated) {
		t.Fatalf("missing token: %v, want UNAUTHENTICATED", err)
	}
	token, _, err := f.svc.NewSetupToken(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	f.clk.Advance(DefaultSetupTokenTTL + time.Minute)
	if _, err := f.svc.CompleteSetup(f.ctx, CompleteSetupInput{
		SetupToken: token, Username: "admin", Password: testPassword,
	}); !problem.HasCode(err, problem.Unauthenticated) {
		t.Fatalf("expired token: %v, want UNAUTHENTICATED", err)
	}
}

func TestCompleteSetupValidatesInput(t *testing.T) {
	f := newFixture(t)
	token, _, err := f.svc.NewSetupToken(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	cases := []CompleteSetupInput{
		{SetupToken: token, Username: "bad name", Password: testPassword},
		{SetupToken: token, Username: "admin", Password: "short"},
	}
	for _, in := range cases {
		if _, err := f.svc.CompleteSetup(f.ctx, in); !problem.HasCode(err, problem.ValidationFailed) {
			t.Fatalf("CompleteSetup(%q) = %v, want VALIDATION_FAILED", in.Username, err)
		}
	}
}

func TestNewSetupTokenInvalidatesOlder(t *testing.T) {
	f := newFixture(t)
	first, _, err := f.svc.NewSetupToken(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	second, _, err := f.svc.NewSetupToken(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.CompleteSetup(f.ctx, CompleteSetupInput{
		SetupToken: first, Username: "admin", Password: testPassword,
	}); !problem.HasCode(err, problem.Unauthenticated) {
		t.Fatalf("superseded token accepted: %v", err)
	}
	if _, err := f.svc.CompleteSetup(f.ctx, CompleteSetupInput{
		SetupToken: second, Username: "admin", Password: testPassword,
	}); err != nil {
		t.Fatalf("current token rejected: %v", err)
	}
}

func TestEnrollmentToken(t *testing.T) {
	f := newFixture(t)
	f.createUser("admin", testPassword, RoleAdmin)
	var res CreateUserResult
	f.update(func(tx *storage.Tx) error {
		var err error
		res, err = f.svc.CreateUser(f.ctx, tx, CreateUserInput{Username: "newbie", Role: RoleViewer})
		return err
	})
	if want := f.clk.Now().Add(DefaultEnrollmentTokenTTL); !res.EnrollmentUntil.Equal(want) {
		t.Fatalf("pending enrolment until %v, want %v", res.EnrollmentUntil, want)
	}
	// The user cannot log in before redeeming a link.
	if _, err := f.svc.Login(f.ctx, LoginInput{Username: "newbie", Password: "anything", ClientIP: "192.0.2.1"}); !problem.HasCode(err, problem.Unauthenticated) {
		t.Fatalf("user without a password logged in: %v", err)
	}
	token, expires, err := f.enrollmentToken(res.User.ID)
	if err != nil {
		t.Fatalf("mint link: %v", err)
	}
	if len(token) < 32 {
		t.Fatalf("enrolment token too short: %d", len(token))
	}
	if want := f.clk.Now().Add(DefaultEnrollmentTokenTTL); !expires.Equal(want) {
		t.Fatalf("expiry = %v, want %v", expires, want)
	}
	// Only the hash is stored, and only the newest link's: minting replaced the
	// pending enrolment of CreateUser.
	var hash []byte
	if err := f.db.Reader().QueryRowContext(f.ctx,
		`SELECT token_hash FROM one_time_tokens WHERE purpose = 'enroll' AND user_id = ? AND used_at = ''`,
		res.User.ID).Scan(&hash); err != nil {
		t.Fatal(err)
	}
	if sum := sha256.Sum256([]byte(token)); string(hash) != string(sum[:]) {
		t.Fatal("the stored token_hash is not the SHA-256 of the issued token")
	}
	u, err := f.svc.RedeemEnrollmentToken(f.ctx, token, "brand-new-passphrase")
	if err != nil {
		t.Fatalf("redeem: %v", err)
	}
	if u.ID != res.User.ID {
		t.Fatalf("redeemed user %s, want %s", u.ID, res.User.ID)
	}
	if _, err := f.svc.Login(f.ctx, LoginInput{Username: "newbie", Password: "brand-new-passphrase", ClientIP: "192.0.2.2"}); err != nil {
		t.Fatalf("login after enrolment: %v", err)
	}
	// Single use.
	if _, err := f.svc.RedeemEnrollmentToken(f.ctx, token, "another-passphrase-x"); !problem.HasCode(err, problem.Unauthenticated) {
		t.Fatalf("reused token: %v", err)
	}
}

// TestEnrollmentTokenRefusesUserWithPassword: an enrolment link sets a first
// password. For a user who already has one, a link would let whoever holds it
// replace the password and take the account over, so identity refuses to mint
// it whoever asks (changing a password is ResetPassword's job).
func TestEnrollmentTokenRefusesUserWithPassword(t *testing.T) {
	f := newFixture(t)
	admin := f.createUser("admin", testPassword, RoleAdmin)
	if _, _, err := f.enrollmentToken(admin.ID); !problem.HasCode(err, problem.StateConflict) {
		t.Fatalf("link for a user with a password: %v, want STATE_CONFLICT", err)
	}

	// Redeeming a link gives the user a password, so the next link is refused.
	newbie := f.createPendingUser("newbie")
	token, _, err := f.enrollmentToken(newbie.ID)
	if err != nil {
		t.Fatalf("link for a user without a password: %v", err)
	}
	if _, err := f.svc.RedeemEnrollmentToken(f.ctx, token, "brand-new-passphrase"); err != nil {
		t.Fatalf("redeem: %v", err)
	}
	if _, _, err := f.enrollmentToken(newbie.ID); !problem.HasCode(err, problem.StateConflict) {
		t.Fatalf("link after enrolment: %v, want STATE_CONFLICT", err)
	}

	// A disabled user gets no link; an unknown one does not exist.
	idle := f.createPendingUser("idle")
	disabled := true
	f.update(func(tx *storage.Tx) error {
		_, err := f.svc.UpdateUser(f.ctx, tx, UpdateUserInput{UserID: idle.ID, ExpectedRevision: idle.Revision, Disabled: &disabled})
		return err
	})
	if _, _, err := f.enrollmentToken(idle.ID); !problem.HasCode(err, problem.StateConflict) {
		t.Fatalf("link for a disabled user: %v, want STATE_CONFLICT", err)
	}
	if _, _, err := f.enrollmentToken("usr_does_not_exist"); !problem.HasCode(err, problem.NotFound) {
		t.Fatalf("link for an unknown user: %v, want NOT_FOUND", err)
	}
}

// TestEnrollmentTokenSupersedesUnused: minting a link retires every unused
// link of the same user, so at most one works at a time; other users' links
// are untouched.
func TestEnrollmentTokenSupersedesUnused(t *testing.T) {
	f := newFixture(t)
	newbie := f.createPendingUser("newbie")
	other := f.createPendingUser("other")
	first, _, err := f.enrollmentToken(newbie.ID)
	if err != nil {
		t.Fatal(err)
	}
	second, _, err := f.enrollmentToken(newbie.ID)
	if err != nil {
		t.Fatal(err)
	}
	otherToken, _, err := f.enrollmentToken(other.ID)
	if err != nil {
		t.Fatal(err)
	}
	var live int
	if err := f.db.Reader().QueryRowContext(f.ctx,
		`SELECT COUNT(*) FROM one_time_tokens WHERE purpose = 'enroll' AND user_id = ? AND used_at = ''`,
		newbie.ID).Scan(&live); err != nil {
		t.Fatal(err)
	}
	if live != 1 {
		t.Fatalf("unused enrolment tokens of one user = %d, want 1", live)
	}
	if _, err := f.svc.RedeemEnrollmentToken(f.ctx, first, "brand-new-passphrase"); !problem.HasCode(err, problem.Unauthenticated) {
		t.Fatalf("superseded link: %v, want UNAUTHENTICATED", err)
	}
	if _, err := f.svc.RedeemEnrollmentToken(f.ctx, otherToken, "brand-new-passphrase"); err != nil {
		t.Fatalf("another user's link: %v", err)
	}
	if _, err := f.svc.RedeemEnrollmentToken(f.ctx, second, "brand-new-passphrase"); err != nil {
		t.Fatalf("current link: %v", err)
	}
}

// createPendingUser creates a user without a password: they wait for an
// enrolment link.
func (f *fixture) createPendingUser(username string) User {
	f.t.Helper()
	var res CreateUserResult
	f.update(func(tx *storage.Tx) error {
		var err error
		res, err = f.svc.CreateUser(f.ctx, tx, CreateUserInput{Username: username, Role: RoleViewer})
		return err
	})
	return res.User
}

// enrollmentToken mints an enrolment link for a user in its own transaction.
func (f *fixture) enrollmentToken(userID string) (token string, expires time.Time, err error) {
	err = f.db.Update(f.ctx, func(tx *storage.Tx) error {
		var ierr error
		token, expires, ierr = f.svc.NewEnrollmentToken(f.ctx, tx, userID)
		return ierr
	})
	return token, expires, err
}
