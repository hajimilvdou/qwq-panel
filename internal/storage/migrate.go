// SPDX-License-Identifier: AGPL-3.0-only

package storage

import (
	"context"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"regexp"
	"sort"
	"strconv"
)

//go:embed migrations/*.sql
var migrationFiles embed.FS

func embedded() fs.FS {
	sub, err := fs.Sub(migrationFiles, "migrations")
	if err != nil {
		panic(err)
	}
	return sub
}

// Migration file names are NNNN_name.sql; versions start at 1 and have no gaps.
var (
	migrationName = regexp.MustCompile(`^(\d{4})_([a-z0-9_]+)\.sql$`)
	pragmaLine    = regexp.MustCompile(`(?im)^\s*pragma\b`)
)

type migration struct {
	version  int
	name     string
	sql      string
	checksum string
}

func loadMigrations(fsys fs.FS) ([]migration, error) {
	entries, err := fs.ReadDir(fsys, ".")
	if err != nil {
		return nil, fmt.Errorf("storage: read migrations: %w", err)
	}
	var ms []migration
	for _, e := range entries {
		if e.IsDir() || path.Ext(e.Name()) != ".sql" {
			continue
		}
		m := migrationName.FindStringSubmatch(e.Name())
		if m == nil {
			return nil, fmt.Errorf("storage: bad migration file name %q", e.Name())
		}
		body, err := fs.ReadFile(fsys, e.Name())
		if err != nil {
			return nil, err
		}
		// PRAGMAs cannot run inside the migration transaction; connection
		// settings belong in the DSN.
		if pragmaLine.Match(body) {
			return nil, fmt.Errorf("storage: migration %s contains PRAGMA", e.Name())
		}
		v, _ := strconv.Atoi(m[1])
		sum := sha256.Sum256(body)
		ms = append(ms, migration{version: v, name: m[2], sql: string(body), checksum: hex.EncodeToString(sum[:])})
	}
	sort.Slice(ms, func(i, j int) bool { return ms[i].version < ms[j].version })
	for i, m := range ms {
		if m.version != i+1 {
			return nil, fmt.Errorf("storage: migration versions must be 1..n without gaps; found %04d at position %d", m.version, i+1)
		}
	}
	return ms, nil
}

// ErrPendingMigrations is returned by Open with NoMigrate when the database
// lacks migrations this binary knows.
var ErrPendingMigrations = errors.New("storage: database has pending migrations; start the new controller once to apply them")

// migrate applies pending migrations, all in one write transaction. It
// refuses a database whose recorded migrations differ from the binary's
// (edited file) or go beyond them (newer binary wrote it): the host must not
// run against a schema it does not know (ARCH §1.3, §12). With noMigrate a
// pending migration aborts the transaction instead, so nothing is written.
// Before migrating a database that already has a schema, it is snapshotted
// to BackupDir (DEP-04).
func (db *DB) migrate(ctx context.Context, fsys fs.FS, noMigrate bool) error {
	ms, err := loadMigrations(fsys)
	if err != nil {
		return err
	}
	if !noMigrate {
		from, err := appliedVersion(ctx, db.r)
		if err != nil {
			return err
		}
		if from > 0 && from < len(ms) {
			if err := db.snapshotBeforeMigrate(ctx, from, len(ms), db.clock.Now()); err != nil {
				return err
			}
		}
	}
	return db.Update(ctx, func(tx *Tx) error {
		if _, err := tx.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
			version    INTEGER PRIMARY KEY,
			name       TEXT NOT NULL,
			checksum   TEXT NOT NULL,
			applied_at TEXT NOT NULL
		) STRICT`); err != nil {
			return fmt.Errorf("storage: create schema_migrations: %w", err)
		}
		rows, err := tx.QueryContext(ctx, `SELECT version, name, checksum FROM schema_migrations ORDER BY version`)
		if err != nil {
			return err
		}
		applied := map[int][2]string{}
		maxApplied := 0
		for rows.Next() {
			var v int
			var name, sum string
			if err := rows.Scan(&v, &name, &sum); err != nil {
				rows.Close()
				return err
			}
			applied[v] = [2]string{name, sum}
			maxApplied = max(maxApplied, v)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		if maxApplied > len(ms) {
			return fmt.Errorf("storage: database schema version %d is newer than this binary (%d); refusing to start", maxApplied, len(ms))
		}
		for _, m := range ms {
			if a, ok := applied[m.version]; ok {
				if a[1] != m.checksum {
					return fmt.Errorf("storage: migration %04d_%s was changed after it was applied", m.version, m.name)
				}
				continue
			}
			if noMigrate {
				return fmt.Errorf("%w (first pending: %04d_%s)", ErrPendingMigrations, m.version, m.name)
			}
			if _, err := tx.ExecContext(ctx, m.sql); err != nil {
				return fmt.Errorf("storage: migration %04d_%s: %w", m.version, m.name, err)
			}
			if _, err := tx.ExecContext(ctx,
				`INSERT INTO schema_migrations (version, name, checksum, applied_at) VALUES (?, ?, ?, ?)`,
				m.version, m.name, m.checksum, FormatTime(tx.Now())); err != nil {
				return err
			}
			db.log.InfoContext(ctx, "applied migration", "version", m.version, "name", m.name)
		}
		return nil
	})
}

// SchemaVersion returns the highest applied migration.
func (db *DB) SchemaVersion(ctx context.Context) (int, error) {
	var v int
	err := db.r.QueryRowContext(ctx, `SELECT COALESCE(MAX(version), 0) FROM schema_migrations`).Scan(&v)
	return v, err
}
