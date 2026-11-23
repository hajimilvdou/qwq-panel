// SPDX-License-Identifier: AGPL-3.0-only

// Package storage owns the Controller's SQLite database (ARCH §8.1, ADR-0008).
//
// There is exactly one write connection; every write transaction starts with
// BEGIN IMMEDIATE (DSN _txlock=immediate), so a transaction never upgrades from
// read to write and never fails with SQLITE_BUSY halfway. Reads use a separate
// small pool of query_only connections. Because writes are serialized, event
// journal sequence numbers are assigned in commit order, and the journal
// doubles as the transactional outbox: subscribers are woken after commit and
// never see gaps.
package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"github.com/qwq-panel/qwq/internal/platform/clock"
	"github.com/qwq-panel/qwq/internal/platform/ids"

	_ "modernc.org/sqlite" // database/sql driver "sqlite"
)

// Options configure Open.
type Options struct {
	// Path of the database file; its directory is created with mode 0700.
	Path string
	// ReadConns is the size of the read pool (default 4).
	ReadConns int
	// CacheKiB is the page cache of the write connection (default 8192);
	// read connections use a quarter of it. Small on purpose for 1 GiB hosts.
	CacheKiB int
	// BusyTimeout bounds waits for locks held by other processes, e.g. a
	// backup or `qwq recover` (default 5s).
	BusyTimeout time.Duration
	// SlowTx logs write transactions that hold the lock longer than this
	// (default 200ms); long write transactions are a design error (ADR-0008 §3).
	SlowTx time.Duration
	// Migrations overrides the embedded migrations (tests).
	Migrations fs.FS
	// NoMigrate opens an existing database without applying migrations; Open
	// fails with ErrPendingMigrations if the binary knows migrations the
	// database lacks. Offline tools (qwq recover, qwq setup-token) use it so a
	// newer binary never migrates a database an older controller still runs on.
	NoMigrate bool

	Clock  clock.Clock
	IDs    *ids.Generator
	Logger *slog.Logger
}

// DB is the opened database.
type DB struct {
	w, r   *sql.DB
	path   string
	clock  clock.Clock
	ids    *ids.Generator
	log    *slog.Logger
	slowTx time.Duration
	mark   watermark
	stats  struct {
		txs, waitNanos, maxWaitNanos atomic.Int64
	}
}

// Open opens or creates the database, applies pending migrations and returns
// it ready for use.
func Open(ctx context.Context, opts Options) (*DB, error) {
	if opts.Path == "" || strings.ContainsAny(opts.Path, "?#") {
		return nil, errors.New("storage: path must be non-empty and contain no '?' or '#'")
	}
	if opts.ReadConns <= 0 {
		opts.ReadConns = 4
	}
	if opts.CacheKiB <= 0 {
		opts.CacheKiB = 8192
	}
	if opts.BusyTimeout <= 0 {
		opts.BusyTimeout = 5 * time.Second
	}
	if opts.SlowTx <= 0 {
		opts.SlowTx = 200 * time.Millisecond
	}
	if opts.Migrations == nil {
		opts.Migrations = embedded()
	}
	if opts.Clock == nil {
		opts.Clock = clock.System{}
	}
	if opts.IDs == nil {
		opts.IDs = ids.New(opts.Clock.Now)
	}
	if opts.Logger == nil {
		opts.Logger = slog.New(slog.DiscardHandler)
	}
	if err := os.MkdirAll(filepath.Dir(opts.Path), 0o700); err != nil {
		return nil, fmt.Errorf("storage: %w", err)
	}

	busy := opts.BusyTimeout.Milliseconds()
	w, err := sql.Open("sqlite", dsn(opts.Path,
		"_txlock=immediate",
		fmt.Sprintf("_pragma=busy_timeout(%d)", busy),
		"_pragma=journal_mode(WAL)",
		"_pragma=synchronous(FULL)",
		"_pragma=foreign_keys(1)",
		"_pragma=journal_size_limit(67108864)",
		fmt.Sprintf("_pragma=cache_size(-%d)", opts.CacheKiB),
	))
	if err != nil {
		return nil, fmt.Errorf("storage: open writer: %w", err)
	}
	w.SetMaxOpenConns(1)
	w.SetMaxIdleConns(1)
	w.SetConnMaxLifetime(0)
	w.SetConnMaxIdleTime(0)

	// query_only instead of mode=ro: a read-only open cannot always map the
	// WAL index, while query_only refuses writes at the SQL level.
	r, err := sql.Open("sqlite", dsn(opts.Path,
		fmt.Sprintf("_pragma=busy_timeout(%d)", busy),
		"_pragma=query_only(1)",
		"_pragma=foreign_keys(1)",
		fmt.Sprintf("_pragma=cache_size(-%d)", max(opts.CacheKiB/4, 512)),
	))
	if err != nil {
		w.Close()
		return nil, fmt.Errorf("storage: open readers: %w", err)
	}
	r.SetMaxOpenConns(opts.ReadConns)
	r.SetMaxIdleConns(opts.ReadConns)
	r.SetConnMaxIdleTime(5 * time.Minute) // return memory on idle 1 GiB hosts

	db := &DB{w: w, r: r, path: opts.Path, clock: opts.Clock, ids: opts.IDs, log: opts.Logger, slowTx: opts.SlowTx}
	db.mark.init()
	if err := db.migrate(ctx, opts.Migrations, opts.NoMigrate); err != nil {
		db.Close()
		return nil, err
	}
	var seq sql.NullInt64
	if err := r.QueryRowContext(ctx, `SELECT MAX(seq) FROM event_journal`).Scan(&seq); err != nil {
		db.Close()
		return nil, fmt.Errorf("storage: read journal head: %w", err)
	}
	db.mark.advance(seq.Int64)
	return db, nil
}

// dsn builds a modernc.org/sqlite DSN: a plain file path followed by driver
// parameters. Paths containing '?' or '#' are rejected by Open.
func dsn(path string, params ...string) string {
	return path + "?" + strings.Join(params, "&")
}

// Close closes both connection pools.
func (db *DB) Close() error {
	return errors.Join(db.r.Close(), db.w.Close())
}

// Path returns the database file path.
func (db *DB) Path() string { return db.path }

// Tx is a write transaction.
type Tx struct {
	*sql.Tx
	db      *DB
	now     time.Time
	lastSeq int64
	origin  Origin
}

// Now is the transaction's timestamp: one value for every row it writes.
func (tx *Tx) Now() time.Time { return tx.now }

// NewID returns a new ID with the given prefix.
func (tx *Tx) NewID(prefix string) string { return tx.db.ids.New(prefix) }

// Update runs fn in a write transaction and commits it if fn returns nil.
// Events appended in fn become visible to subscribers only after the commit.
// fn must not perform network calls or call plugins (ADR-0008 §3).
func (db *DB) Update(ctx context.Context, fn func(*Tx) error) (err error) {
	start := time.Now()
	stx, err := db.w.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("storage: begin: %w", err)
	}
	locked := time.Now()
	wait := locked.Sub(start).Nanoseconds()
	db.stats.txs.Add(1)
	db.stats.waitNanos.Add(wait)
	for {
		m := db.stats.maxWaitNanos.Load()
		if wait <= m || db.stats.maxWaitNanos.CompareAndSwap(m, wait) {
			break
		}
	}

	tx := &Tx{Tx: stx, db: db, now: db.clock.Now().UTC().Truncate(time.Millisecond)}
	defer func() {
		if p := recover(); p != nil {
			_ = stx.Rollback()
			panic(p)
		}
		if held := time.Since(locked); held > db.slowTx {
			db.log.WarnContext(ctx, "slow write transaction", "held_ms", held.Milliseconds())
		}
	}()
	if err := fn(tx); err != nil {
		_ = stx.Rollback()
		return err
	}
	if err := stx.Commit(); err != nil {
		return fmt.Errorf("storage: commit: %w", err)
	}
	if tx.lastSeq > 0 {
		db.mark.advance(tx.lastSeq)
	}
	return nil
}

// View runs fn in a read-only transaction on the read pool, so every query in
// fn sees one snapshot.
func (db *DB) View(ctx context.Context, fn func(*sql.Tx) error) error {
	tx, err := db.r.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return fmt.Errorf("storage: begin read: %w", err)
	}
	defer tx.Rollback()
	return fn(tx)
}

// Reader returns the read pool for single queries that need no snapshot.
func (db *DB) Reader() *sql.DB { return db.r }

// Stats reports write lock contention (ARCH §13 "DB 锁等待").
type Stats struct {
	WriteTxs    int64
	WaitTotal   time.Duration
	WaitMax     time.Duration
	Write, Read sql.DBStats
}

// Stats returns counters since Open.
func (db *DB) Stats() Stats {
	return Stats{
		WriteTxs:  db.stats.txs.Load(),
		WaitTotal: time.Duration(db.stats.waitNanos.Load()),
		WaitMax:   time.Duration(db.stats.maxWaitNanos.Load()),
		Write:     db.w.Stats(),
		Read:      db.r.Stats(),
	}
}

// Checkpoint truncates the WAL; call it when the host is idle.
func (db *DB) Checkpoint(ctx context.Context) error {
	_, err := db.w.ExecContext(ctx, `PRAGMA wal_checkpoint(TRUNCATE)`)
	return err
}

// CheckpointPassive runs a non-blocking PASSIVE WAL checkpoint suitable for
// periodic background sweeps without stalling concurrent readers or writers.
func (db *DB) CheckpointPassive(ctx context.Context) error {
	_, err := db.w.ExecContext(ctx, `PRAGMA wal_checkpoint(PASSIVE)`)
	return err
}

// QuickCheck runs PRAGMA quick_check.
func (db *DB) QuickCheck(ctx context.Context) error {
	rows, err := db.r.QueryContext(ctx, `PRAGMA quick_check`)
	if err != nil {
		return err
	}
	defer rows.Close()
	var problems []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return err
		}
		if s != "ok" {
			problems = append(problems, s)
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if len(problems) > 0 {
		return fmt.Errorf("storage: quick_check: %v", problems)
	}
	return nil
}

// IsConstraint reports whether err is an SQLite constraint violation
// (UNIQUE, FOREIGN KEY, CHECK, NOT NULL).
func IsConstraint(err error) bool {
	var e interface{ Code() int }
	return errors.As(err, &e) && e.Code()&0xff == 19 // SQLITE_CONSTRAINT
}

// TimeFormat is how timestamps are stored: RFC 3339, UTC, milliseconds. It
// sorts lexicographically.
const TimeFormat = "2006-01-02T15:04:05.000Z"

// FormatTime formats t for storage.
func FormatTime(t time.Time) string { return t.UTC().Format(TimeFormat) }

// ParseTime parses a stored timestamp.
func ParseTime(s string) (time.Time, error) { return time.Parse(TimeFormat, s) }
