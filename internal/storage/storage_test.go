// SPDX-License-Identifier: AGPL-3.0-only

package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"testing/fstest"
	"time"

	"github.com/qwq-panel/qwq/internal/platform/clock"
)

func open(t *testing.T, opts Options) *DB {
	t.Helper()
	if opts.Path == "" {
		opts.Path = filepath.Join(t.TempDir(), "qwq.db")
	}
	db, err := Open(context.Background(), opts)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func TestPragmas(t *testing.T) {
	db := open(t, Options{})
	ctx := context.Background()
	check := func(c *sql.DB, pragma, want string) {
		t.Helper()
		var got string
		if err := c.QueryRowContext(ctx, "PRAGMA "+pragma).Scan(&got); err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Errorf("%s = %s, want %s", pragma, got, want)
		}
	}
	check(db.w, "journal_mode", "wal")
	check(db.w, "synchronous", "2") // FULL
	check(db.w, "foreign_keys", "1")
	check(db.r, "foreign_keys", "1")
	check(db.r, "query_only", "1")
}

func TestReaderRefusesWrites(t *testing.T) {
	db := open(t, Options{})
	_, err := db.Reader().Exec(`INSERT INTO event_journal (event_id, type, schema_version, subject, occurred_at, payload) VALUES ('e','t','1','s','x','{}')`)
	if err == nil {
		t.Fatal("write through read pool succeeded")
	}
}

func TestMigrationsIdempotentAndGuarded(t *testing.T) {
	path := filepath.Join(t.TempDir(), "qwq.db")
	ctx := context.Background()
	v1 := fstest.MapFS{"0001_a.sql": {Data: []byte("CREATE TABLE event_journal (seq INTEGER PRIMARY KEY AUTOINCREMENT, event_id TEXT, type TEXT, schema_version TEXT, subject TEXT, occurred_at TEXT, actor_kind TEXT, actor_id TEXT, on_behalf_of TEXT, node_id TEXT, trace_id TEXT, operation_id TEXT, payload TEXT);")}}
	v2 := fstest.MapFS{"0001_a.sql": v1["0001_a.sql"], "0002_b.sql": {Data: []byte("CREATE TABLE b (x INTEGER);")}}

	for i := 0; i < 2; i++ { // second open applies nothing
		db, err := Open(ctx, Options{Path: path, Migrations: v1})
		if err != nil {
			t.Fatal(err)
		}
		db.Close()
	}
	db, err := Open(ctx, Options{Path: path, Migrations: v2})
	if err != nil {
		t.Fatal(err)
	}
	if v, _ := db.SchemaVersion(ctx); v != 2 {
		t.Fatalf("schema version %d", v)
	}
	db.Close()

	if _, err := Open(ctx, Options{Path: path, Migrations: v1}); err == nil || !strings.Contains(err.Error(), "newer than this binary") {
		t.Fatalf("older binary: %v", err)
	}
	edited := fstest.MapFS{"0001_a.sql": v1["0001_a.sql"], "0002_b.sql": {Data: []byte("CREATE TABLE b (y INTEGER);")}}
	if _, err := Open(ctx, Options{Path: path, Migrations: edited}); err == nil || !strings.Contains(err.Error(), "changed after it was applied") {
		t.Fatalf("edited migration: %v", err)
	}
}

func TestOpenNoMigrateRefusesPending(t *testing.T) {
	path := filepath.Join(t.TempDir(), "qwq.db")
	ctx := context.Background()
	v1 := fstest.MapFS{"0001_a.sql": {Data: []byte("CREATE TABLE event_journal (seq INTEGER PRIMARY KEY AUTOINCREMENT, event_id TEXT, type TEXT, schema_version TEXT, subject TEXT, occurred_at TEXT, actor_kind TEXT, actor_id TEXT, on_behalf_of TEXT, node_id TEXT, trace_id TEXT, operation_id TEXT, payload TEXT);")}}
	v2 := fstest.MapFS{"0001_a.sql": v1["0001_a.sql"], "0002_b.sql": {Data: []byte("CREATE TABLE b (x INTEGER);")}}

	// 空库：NoMigrate 不得建表。
	if _, err := Open(ctx, Options{Path: path, Migrations: v1, NoMigrate: true}); !errors.Is(err, ErrPendingMigrations) {
		t.Fatalf("empty database: %v", err)
	}
	db, err := Open(ctx, Options{Path: path, Migrations: v1})
	if err != nil {
		t.Fatal(err)
	}
	db.Close()

	// 二进制比库新：拒绝，且不得偷偷执行 0002。
	if _, err := Open(ctx, Options{Path: path, Migrations: v2, NoMigrate: true}); !errors.Is(err, ErrPendingMigrations) {
		t.Fatalf("pending migration: %v", err)
	}
	db, err = Open(ctx, Options{Path: path, Migrations: v1, NoMigrate: true})
	if err != nil {
		t.Fatalf("up-to-date database: %v", err)
	}
	defer db.Close()
	if v, _ := db.SchemaVersion(ctx); v != 1 {
		t.Fatalf("schema version %d, want 1", v)
	}
}

func TestMigrationFilesValidated(t *testing.T) {
	cases := map[string]fstest.MapFS{
		"gap":     {"0001_a.sql": {Data: []byte("SELECT 1;")}, "0003_c.sql": {Data: []byte("SELECT 1;")}},
		"name":    {"1_a.sql": {Data: []byte("SELECT 1;")}},
		"pragma":  {"0001_a.sql": {Data: []byte("pragma foreign_keys=off;")}},
		"bad sql": {"0001_a.sql": {Data: []byte("CREATE TABLEX;")}},
	}
	for name, fsys := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Open(context.Background(), Options{Path: filepath.Join(t.TempDir(), "x.db"), Migrations: fsys}); err == nil {
				t.Fatal("accepted")
			}
		})
	}
	// A failed migration leaves nothing behind.
	path := filepath.Join(t.TempDir(), "x.db")
	bad := fstest.MapFS{"0001_a.sql": {Data: []byte("CREATE TABLE a (x INTEGER); CREATE TABLEX;")}}
	if _, err := Open(context.Background(), Options{Path: path, Migrations: bad}); err == nil {
		t.Fatal("accepted")
	}
	c, _ := sql.Open("sqlite", path)
	defer c.Close()
	var n int
	c.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE name = 'a'`).Scan(&n)
	if n != 0 {
		t.Fatal("partial migration committed")
	}
}

// migrationsBefore returns the embedded migrations older than version: the
// schema a database written by an earlier release has.
func migrationsBefore(t *testing.T, version int) fstest.MapFS {
	t.Helper()
	all, err := loadMigrations(embedded())
	if err != nil {
		t.Fatal(err)
	}
	out := fstest.MapFS{}
	for _, m := range all {
		if m.version < version {
			out[fmt.Sprintf("%04d_%s.sql", m.version, m.name)] = &fstest.MapFile{Data: []byte(m.sql)}
		}
	}
	return out
}

// TestMigration0008ScrubsTokens upgrades a database that still holds
// enrollment tokens in clear (AUTH-06). Migration 0008 removes the token from
// host.users.create results and from stored idempotent responses and retires
// every unused enrollment token; nothing else changes.
func TestMigration0008ScrubsTokens(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "qwq.db")
	const (
		at       = "2026-11-01T08:00:00.000Z"
		until    = "2026-11-02T08:00:00.000Z"
		created  = `{"user":{"user_id":"usr_1","username":"bob"},"enrollment_token":"tok-op","enrollment_expires_at":"` + until + `"}`
		foreign  = `{"enrollment_token":"belongs-to-the-plugin"}`
		outcome  = `{"operation_id":"op_1","action":"host.users.create","status":"SUCCEEDED","result":` + created + `,"revision":"7"}`
		accepted = `{"operation_id":"op_2","action":"host.users.create","status":"AWAITING_APPROVAL","revision":"3"}`
	)
	old, err := Open(ctx, Options{Path: path, Migrations: migrationsBefore(t, 8)})
	if err != nil {
		t.Fatal(err)
	}
	err = old.Update(ctx, func(tx *Tx) error {
		for _, s := range []struct {
			query string
			args  []any
		}{
			{`INSERT INTO users (user_id, username, role, created_at, updated_at) VALUES ('usr_1', 'bob', 'operator', ?, ?)`, []any{at, at}},
			{insertOperation, []any{"op_1", "host.users.create", created, at, at}},
			{insertOperation, []any{"op_2", "host.users.create", nil, at, at}},
			{insertOperation, []any{"op_3", "com.example.monitor/scan", foreign, at, at}},
			{insertIdempotencyKey, []any{"idk_1", "test-key-0000000001", "completed", outcome, at, at, until}},
			{insertIdempotencyKey, []any{"idk_2", "test-key-0000000002", "in_progress", nil, at, at, until}},
			{insertIdempotencyKey, []any{"idk_3", "test-key-0000000003", "completed", accepted, at, at, until}},
			{insertOneTimeToken, []any{"stk_enroll_live", "enroll", "usr_1", "h1", at, until, ""}},
			{insertOneTimeToken, []any{"stk_enroll_used", "enroll", "usr_1", "h2", at, until, at}},
			{insertOneTimeToken, []any{"stk_setup_live", "setup", nil, "h3", at, until, ""}},
		} {
			if _, err := tx.ExecContext(ctx, s.query, s.args...); err != nil {
				return fmt.Errorf("%s: %w", s.query, err)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	old.Close()

	db := open(t, Options{Path: path})
	text := func(query string, args ...any) sql.NullString {
		t.Helper()
		var s sql.NullString
		if err := db.Reader().QueryRowContext(ctx, query, args...).Scan(&s); err != nil {
			t.Fatalf("%s: %v", query, err)
		}
		return s
	}
	object := func(query string, args ...any) map[string]any {
		t.Helper()
		var m map[string]any
		if err := json.Unmarshal([]byte(text(query, args...).String), &m); err != nil {
			t.Fatalf("%s: %v", query, err)
		}
		return m
	}

	// The token leaves the user-create result; the rest of the result stays.
	result := object(`SELECT result FROM operations WHERE operation_id = 'op_1'`)
	if _, ok := result["enrollment_token"]; ok {
		t.Fatalf("op_1 result still holds the token: %v", result)
	}
	if user, _ := result["user"].(map[string]any); result["enrollment_expires_at"] != until || user["username"] != "bob" {
		t.Fatalf("op_1 result lost other members: %v", result)
	}
	if got := text(`SELECT result FROM operations WHERE operation_id = 'op_2'`); got.Valid {
		t.Fatalf("op_2 result = %q, want NULL", got.String)
	}
	if got := text(`SELECT result FROM operations WHERE operation_id = 'op_3'`); got.String != foreign {
		t.Fatalf("another action's result changed: %s", got.String)
	}

	// The stored response of the create call loses the token too.
	body := object(`SELECT response_body FROM idempotency_keys WHERE key_id = 'idk_1'`)
	stored, _ := body["result"].(map[string]any)
	if _, ok := stored["enrollment_token"]; ok {
		t.Fatalf("stored response still holds the token: %v", body)
	}
	if body["operation_id"] != "op_1" || stored["enrollment_expires_at"] != until {
		t.Fatalf("stored response lost other members: %v", body)
	}
	if got := text(`SELECT response_body FROM idempotency_keys WHERE key_id = 'idk_2'`); got.Valid {
		t.Fatalf("idk_2 response = %q, want NULL", got.String)
	}
	if got := text(`SELECT response_body FROM idempotency_keys WHERE key_id = 'idk_3'`); got.String != accepted {
		t.Fatalf("an unrelated stored response changed: %s", got.String)
	}

	// Every unused enrollment token is retired; used tokens and the setup token
	// keep their state.
	retired := text(`SELECT used_at FROM one_time_tokens WHERE token_id = 'stk_enroll_live'`).String
	if _, err := ParseTime(retired); err != nil {
		t.Fatalf("retired enrollment token used_at = %q: %v", retired, err)
	}
	if got := text(`SELECT used_at FROM one_time_tokens WHERE token_id = 'stk_enroll_used'`).String; got != at {
		t.Fatalf("used enrollment token used_at = %q, want %q", got, at)
	}
	if got := text(`SELECT used_at FROM one_time_tokens WHERE token_id = 'stk_setup_live'`).String; got != "" {
		t.Fatalf("setup token used_at = %q, want empty", got)
	}
}

// Seed statements of TestMigration0008ScrubsTokens, with only the columns that
// have no default.
const (
	insertOperation = `INSERT INTO operations (operation_id, action, action_meta, status, target, actor_kind,
		actor_id, effective_risk, declared_risk, effect, mode, args, args_digest, result, timeout_ms,
		created_at, updated_at, revision)
		VALUES (?, ?, '{}', 'SUCCEEDED', '{}', 'human', 'usr_admin', 'high', 'high', 'write', 'invoke', '{}',
		'sha256:0', ?, 10000, ?, ?, 1)`
	insertIdempotencyKey = `INSERT INTO idempotency_keys (key_id, principal, method, route, key, fingerprint,
		state, response_body, created_at, updated_at, expires_at)
		VALUES (?, 'human:usr_admin', 'POST', '/api/v1/users', ?, 'f', ?, ?, ?, ?, ?)`
	insertOneTimeToken = `INSERT INTO one_time_tokens (token_id, purpose, user_id, token_hash, created_at,
		expires_at, used_at) VALUES (?, ?, ?, CAST(? AS BLOB), ?, ?, ?)`
)

func appendTest(ctx context.Context, tx *Tx, subject string) (int64, error) {
	return tx.AppendEvent(ctx, Event{Type: "resource.changed", SchemaVersion: "1", Subject: subject,
		ActorKind: "human", ActorID: "usr_1", Payload: json.RawMessage(`{"subject":"` + subject + `"}`)})
}

func TestUpdateRollbackAndEvents(t *testing.T) {
	fc := clock.NewFake(time.Date(2026, 11, 1, 8, 0, 0, 123_456_789, time.UTC))
	db := open(t, Options{Clock: fc})
	ctx := context.Background()

	boom := errors.New("boom")
	err := db.Update(ctx, func(tx *Tx) error {
		if _, err := appendTest(ctx, tx, "nodes/local"); err != nil {
			return err
		}
		return boom
	})
	if !errors.Is(err, boom) || db.HeadSeq() != 0 {
		t.Fatalf("rollback: err=%v head=%d", err, db.HeadSeq())
	}

	var seq int64
	if err := db.Update(ctx, func(tx *Tx) (err error) { seq, err = appendTest(ctx, tx, "nodes/local"); return err }); err != nil {
		t.Fatal(err)
	}
	if db.HeadSeq() != seq {
		t.Fatalf("head %d, seq %d", db.HeadSeq(), seq)
	}
	evs, err := db.EventsAfter(ctx, 0, 10)
	if err != nil || len(evs) != 1 {
		t.Fatalf("%v %v", evs, err)
	}
	e := evs[0]
	if e.Seq != seq || e.Subject != "nodes/local" || !strings.HasPrefix(e.EventID, "evt_") ||
		!e.OccurredAt.Equal(time.Date(2026, 11, 1, 8, 0, 0, 123_000_000, time.UTC)) || e.ActorID != "usr_1" {
		t.Fatalf("event %+v", e)
	}

	if err := db.Update(ctx, func(tx *Tx) error {
		_, err := tx.AppendEvent(ctx, Event{Type: "x", SchemaVersion: "1", Subject: "s", Payload: json.RawMessage(`{`)})
		return err
	}); err == nil {
		t.Fatal("invalid payload accepted")
	}
}

func TestPanicRollsBack(t *testing.T) {
	db := open(t, Options{})
	ctx := context.Background()
	func() {
		defer func() { recover() }()
		_ = db.Update(ctx, func(tx *Tx) error {
			appendTest(ctx, tx, "a")
			panic("x")
		})
	}()
	// The single write connection must be usable again.
	if err := db.Update(ctx, func(tx *Tx) error { _, err := appendTest(ctx, tx, "b"); return err }); err != nil {
		t.Fatal(err)
	}
	evs, _ := db.EventsAfter(ctx, 0, 10)
	if len(evs) != 1 || evs[0].Subject != "b" {
		t.Fatalf("%+v", evs)
	}
}

// Concurrent writers and readers: no SQLITE_BUSY, every committed event
// visible exactly once, sequences in commit order without gaps.
func TestConcurrency(t *testing.T) {
	db := open(t, Options{})
	ctx := context.Background()
	const writers, per = 6, 60
	var wg sync.WaitGroup
	errs := make(chan error, writers+4)
	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < per; i++ {
				if err := db.Update(ctx, func(tx *Tx) error {
					_, err := appendTest(ctx, tx, fmt.Sprintf("w%d/%d", w, i))
					return err
				}); err != nil {
					errs <- err
					return
				}
			}
		}(w)
	}
	stop := make(chan struct{})
	var rg sync.WaitGroup
	for r := 0; r < 4; r++ {
		rg.Add(1)
		go func() {
			defer rg.Done()
			var after int64
			for {
				select {
				case <-stop:
					return
				default:
				}
				evs, err := db.EventsAfter(ctx, after, 50)
				if err != nil {
					errs <- err
					return
				}
				for _, e := range evs {
					if e.Seq != after+1 {
						errs <- fmt.Errorf("gap: after %d got %d", after, e.Seq)
						return
					}
					after = e.Seq
				}
			}
		}()
	}
	wg.Wait()
	close(stop)
	rg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	if db.HeadSeq() != writers*per {
		t.Fatalf("head %d", db.HeadSeq())
	}
	st := db.Stats()
	if st.WriteTxs < writers*per {
		t.Fatalf("stats %+v", st)
	}
}

func TestWaitAfter(t *testing.T) {
	db := open(t, Options{})
	ctx := context.Background()
	got := make(chan int64, 1)
	go func() {
		h, _ := db.WaitAfter(ctx, 0)
		got <- h
	}()
	if err := db.Update(ctx, func(tx *Tx) error { _, err := appendTest(ctx, tx, "a"); return err }); err != nil {
		t.Fatal(err)
	}
	select {
	case h := <-got:
		if h != 1 {
			t.Fatalf("head %d", h)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("waiter not woken")
	}
	cctx, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := db.WaitAfter(cctx, 1); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled wait: %v", err)
	}
}

func TestPruneKeepsUnion(t *testing.T) {
	fc := clock.NewFake(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	db := open(t, Options{Clock: fc})
	ctx := context.Background()
	add := func(n int) {
		for i := 0; i < n; i++ {
			if err := db.Update(ctx, func(tx *Tx) error { _, err := appendTest(ctx, tx, "s"); return err }); err != nil {
				t.Fatal(err)
			}
		}
	}
	add(10)                         // old: seq 1..10
	fc.Advance(10 * 24 * time.Hour) // later events are recent
	add(5)                          // recent: seq 11..15

	// keep newest 8 (seq 8..15) OR younger than 7 days (11..15): delete 1..7.
	n, err := db.PruneEvents(ctx, 8, 7*24*time.Hour, 100)
	if err != nil || n != 7 {
		t.Fatalf("pruned %d, %v", n, err)
	}
	if o, _ := db.OldestSeq(ctx); o != 8 {
		t.Fatalf("oldest %d", o)
	}
	// Recent events survive even when keep is small.
	if n, _ := db.PruneEvents(ctx, 1, 7*24*time.Hour, 100); n != 3 {
		t.Fatalf("second prune %d", n)
	}
	// Sequences are never reused after pruning.
	add(1)
	if db.HeadSeq() != 16 {
		t.Fatalf("head %d", db.HeadSeq())
	}
}

func TestBackup(t *testing.T) {
	db := open(t, Options{})
	ctx := context.Background()
	if err := db.Update(ctx, func(tx *Tx) error { _, err := appendTest(ctx, tx, "a"); return err }); err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(t.TempDir(), "backup.db")
	if err := db.Backup(ctx, dest); err != nil {
		t.Fatal(err)
	}
	if err := db.Backup(ctx, dest); err == nil {
		t.Fatal("overwrote an existing backup")
	}
	b, err := Open(ctx, Options{Path: dest})
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	if b.HeadSeq() != 1 {
		t.Fatalf("backup head %d", b.HeadSeq())
	}
	if err := db.QuickCheck(ctx); err != nil {
		t.Fatal(err)
	}
	if err := db.Checkpoint(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestIsConstraint(t *testing.T) {
	db := open(t, Options{})
	ctx := context.Background()
	var id string
	db.Update(ctx, func(tx *Tx) error {
		appendTest(ctx, tx, "a")
		return tx.QueryRowContext(ctx, `SELECT event_id FROM event_journal`).Scan(&id)
	})
	err := db.Update(ctx, func(tx *Tx) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO event_journal (event_id, type, schema_version, subject, occurred_at, payload) VALUES (?, 't', '1', 's', 'x', '{}')`, id)
		return err
	})
	if !IsConstraint(err) {
		t.Fatalf("IsConstraint(%v) = false", err)
	}
	if IsConstraint(errors.New("x")) {
		t.Fatal("IsConstraint(plain) = true")
	}
}
