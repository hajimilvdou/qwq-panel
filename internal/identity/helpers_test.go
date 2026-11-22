// SPDX-License-Identifier: AGPL-3.0-only

package identity

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/qwq-panel/qwq/internal/platform/clock"
	"github.com/qwq-panel/qwq/internal/platform/ids"
	"github.com/qwq-panel/qwq/internal/platform/problem"
	"github.com/qwq-panel/qwq/internal/secrets"
	"github.com/qwq-panel/qwq/internal/storage"
)

var testStart = time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)

// testParams keep password hashing fast; the production cost is covered by
// TestDefaultParamsSane and is not re-derived in every test.
func testParams() Params {
	return Params{Memory: 8 * 1024, Iterations: 1, Parallelism: 1, SaltLength: 16, KeyLength: 32}
}

const testPassword = "correct-horse-battery-staple"

var _ SecretSealer = (*secrets.Store)(nil)

type fakeAuditor struct {
	mu      sync.Mutex
	records []AuditRecord
}

func (f *fakeAuditor) Audit(_ context.Context, _ *storage.Tx, rec AuditRecord) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.records = append(f.records, rec)
	return nil
}

func (f *fakeAuditor) count(action string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, r := range f.records {
		if r.Action == action {
			n++
		}
	}
	return n
}

func (f *fakeAuditor) last(action string) (AuditRecord, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i := len(f.records) - 1; i >= 0; i-- {
		if f.records[i].Action == action {
			return f.records[i], true
		}
	}
	return AuditRecord{}, false
}

type fixture struct {
	t      *testing.T
	db     *storage.DB
	clk    *clock.Fake
	gen    *ids.Generator
	svc    *Service
	audit  *fakeAuditor
	sealer *secrets.Store
	ctx    context.Context
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	return newFixtureWith(t, Options{})
}

// newFixtureWith builds a Service with opts, filling DB, Clock, IDs, Hasher,
// Auditor and Sealer when the caller left them empty.
func newFixtureWith(t *testing.T, opts Options) *fixture {
	t.Helper()
	clk := clock.NewFake(testStart)
	gen := ids.New(clk.Now)
	db, err := storage.Open(context.Background(), storage.Options{
		Path:  filepath.Join(t.TempDir(), "qwq.db"),
		Clock: clk,
		IDs:   gen,
	})
	if err != nil {
		t.Fatalf("open storage: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if opts.Hasher == nil {
		opts.Hasher = NewHasher(testParams(), 2)
	}
	audit := &fakeAuditor{}
	keys, err := secrets.LoadKeyRing(t.TempDir())
	if err != nil {
		t.Fatalf("load fixture keys: %v", err)
	}
	sealer, err := secrets.New(secrets.Options{DB: db, Keys: keys})
	if err != nil {
		t.Fatalf("open fixture secrets: %v", err)
	}
	opts.DB, opts.Clock, opts.IDs = db, clk, gen
	opts.Auditor = audit
	opts.Sealer = sealer
	if opts.Throttle == nil {
		opts.Throttle = NewLoginThrottle(clk.Now, DefaultThrottleOptions())
	}
	svc, err := New(opts)
	if err != nil {
		t.Fatalf("identity.New: %v", err)
	}
	return &fixture{t: t, db: db, clk: clk, gen: gen, svc: svc, audit: audit, sealer: sealer, ctx: context.Background()}
}

// createUser inserts a user with a password and returns it.
func (f *fixture) createUser(username, password string, role Role) User {
	f.t.Helper()
	hash, err := f.svc.PreparePassword(f.ctx, username, password)
	if err != nil {
		f.t.Fatalf("prepare password: %v", err)
	}
	var res CreateUserResult
	if err := f.db.Update(f.ctx, func(tx *storage.Tx) error {
		var err error
		res, err = f.svc.CreateUser(f.ctx, tx, CreateUserInput{
			Username: username, Role: role, PasswordHash: hash, DisplayName: username,
		})
		return err
	}); err != nil {
		f.t.Fatalf("create user: %v", err)
	}
	return res.User
}

// user reloads a user by ID.
func (f *fixture) user(id string) User {
	f.t.Helper()
	u, err := f.svc.User(f.ctx, id)
	if err != nil {
		f.t.Fatalf("load user: %v", err)
	}
	return u
}

// update runs fn in a write transaction and fails the test on error.
func (f *fixture) update(fn func(*storage.Tx) error) {
	f.t.Helper()
	if err := f.db.Update(f.ctx, fn); err != nil {
		f.t.Fatalf("write transaction: %v", err)
	}
}

// try runs fn in a write transaction and asserts the problem code.
func (f *fixture) try(fn func(*storage.Tx) error, code problem.Code) {
	f.t.Helper()
	err := f.db.Update(f.ctx, fn)
	if !problem.HasCode(err, code) {
		f.t.Fatalf("got %v, want problem code %s", err, code)
	}
}

// enableTOTP enrols a second factor for a user and returns the secret and the
// recovery codes. The clock is advanced afterwards so the next login uses a
// fresh TOTP step (the enrolment step is already consumed).
func (f *fixture) enableTOTP(userID string) ([]byte, []string) {
	f.t.Helper()
	enr, err := f.svc.BeginTOTPEnrollment(f.ctx, userID)
	if err != nil {
		f.t.Fatalf("begin TOTP enrollment: %v", err)
	}
	secret, err := totpEncoding.DecodeString(enr.Secret)
	if err != nil {
		f.t.Fatalf("decode secret: %v", err)
	}
	code := TOTPCode(secret, TOTPStep(f.clk.Now()))
	var codes []string
	f.update(func(tx *storage.Tx) error {
		var err error
		codes, _, err = f.svc.EnableTOTP(f.ctx, tx, EnableTOTPInput{
			UserID: userID, ExpectedRevision: enr.Revision, Code: code,
		})
		return err
	})
	f.clk.Advance(TOTPPeriod * time.Second)
	return secret, codes
}

func (f *fixture) login(username, password string) LoginResult {
	f.t.Helper()
	res, err := f.svc.Login(f.ctx, LoginInput{Username: username, Password: password, ClientIP: "203.0.113.7"})
	if err != nil {
		f.t.Fatalf("login: %v", err)
	}
	return res
}

// asProblem reports whether err is a *problem.Error and stores it in dst.
func asProblem(err error, dst **problem.Error) bool {
	var pe *problem.Error
	if !errors.As(err, &pe) {
		return false
	}
	*dst = pe
	return true
}
