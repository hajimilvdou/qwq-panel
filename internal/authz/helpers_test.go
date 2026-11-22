// SPDX-License-Identifier: AGPL-3.0-only

package authz

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/qwq-panel/qwq/internal/actor"
	"github.com/qwq-panel/qwq/internal/platform/clock"
	"github.com/qwq-panel/qwq/internal/platform/ids"
	"github.com/qwq-panel/qwq/internal/platform/problem"
	"github.com/qwq-panel/qwq/internal/storage"
)

var testStart = time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)

// dbPrincipals reads the users table exactly like identity.Service.PrincipalRole
// does, so the test exercises the real integration query rather than a stub that
// could drift from it.
type dbPrincipals struct{ db *storage.DB }

func (p dbPrincipals) PrincipalRole(ctx context.Context, userID string) (string, bool, error) {
	var role string
	var disabled int
	err := p.db.Reader().QueryRowContext(ctx,
		`SELECT role, disabled FROM users WHERE user_id = ?`, userID).Scan(&role, &disabled)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, fmt.Errorf("no such principal: %s", userID)
	}
	if err != nil {
		return "", false, err
	}
	return role, disabled != 0, nil
}

type fixture struct {
	t   *testing.T
	db  *storage.DB
	clk *clock.Fake
	gen *ids.Generator
	z   *Authorizer
	ctx context.Context
}

func newFixture(t *testing.T) *fixture {
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
	z, err := New(Options{DB: db, Clock: clk, Principals: dbPrincipals{db}})
	if err != nil {
		t.Fatalf("authz.New: %v", err)
	}
	return &fixture{t: t, db: db, clk: clk, gen: gen, z: z, ctx: context.Background()}
}

func (f *fixture) update(fn func(*storage.Tx) error) {
	f.t.Helper()
	if err := f.db.Update(f.ctx, fn); err != nil {
		f.t.Fatalf("write transaction: %v", err)
	}
}

func (f *fixture) try(fn func(*storage.Tx) error, code problem.Code) {
	f.t.Helper()
	err := f.db.Update(f.ctx, fn)
	if !problem.HasCode(err, code) {
		f.t.Fatalf("got %v, want problem code %s", err, code)
	}
}

// user inserts a user row and returns its ID.
func (f *fixture) user(username, role string, disabled bool) string {
	f.t.Helper()
	id := f.gen.New(ids.User)
	now := storage.FormatTime(f.clk.Now())
	d := 0
	if disabled {
		d = 1
	}
	f.update(func(tx *storage.Tx) error {
		_, err := tx.ExecContext(f.ctx,
			`INSERT INTO users (user_id, username, display_name, role, disabled, created_at, updated_at, revision)
			 VALUES (?, ?, ?, ?, ?, ?, ?, 0)`, id, username, username, role, d, now, now)
		return err
	})
	return id
}

// setRole changes a user's role, as an administrator would through identity.
func (f *fixture) setRole(userID, role string) {
	f.t.Helper()
	f.update(func(tx *storage.Tx) error {
		_, err := tx.ExecContext(f.ctx,
			`UPDATE users SET role = ?, updated_at = ? WHERE user_id = ?`,
			role, storage.FormatTime(f.clk.Now()), userID)
		return err
	})
}

// disable disables a user, as identity.UpdateUser would.
func (f *fixture) disable(userID string) {
	f.t.Helper()
	f.update(func(tx *storage.Tx) error {
		_, err := tx.ExecContext(f.ctx,
			`UPDATE users SET disabled = 1, updated_at = ? WHERE user_id = ?`,
			storage.FormatTime(f.clk.Now()), userID)
		return err
	})
}

// human returns a human session actor for a user.
func (f *fixture) human(userID string) actor.Actor {
	return actor.Actor{Kind: actor.Human, ID: userID, SessionID: f.gen.New(ids.Session)}
}

// createDelegation issues a token for the owner.
func (f *fixture) createDelegation(owner actor.Actor, policy Policy, ttl time.Duration) Created {
	f.t.Helper()
	var created Created
	f.update(func(tx *storage.Tx) error {
		var err error
		created, err = f.z.CreateDelegation(f.ctx, tx, CreateDelegationInput{
			Actor: owner, Label: "Claude desktop", Policy: policy, TTL: ttl,
		})
		return err
	})
	return created
}

// agent returns the actor Bearer authentication yields for a token.
func (f *fixture) agent(token string) actor.Actor {
	f.t.Helper()
	a, err := f.z.AuthenticateBearer(f.ctx, token)
	if err != nil {
		f.t.Fatalf("AuthenticateBearer: %v", err)
	}
	return a
}
