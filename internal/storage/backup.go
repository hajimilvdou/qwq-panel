// SPDX-License-Identifier: AGPL-3.0-only

package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// Backup writes a consistent snapshot of the database to dest; see BackupFile.
func (db *DB) Backup(ctx context.Context, dest string) error {
	return BackupFile(ctx, db.path, dest)
}

// BackupFile writes a consistent snapshot of the database at src to dest with
// VACUUM INTO (ARCH §8.3): it reads one snapshot, so concurrent writes are
// neither blocked for long nor torn. The snapshot is written next to dest,
// made private (0600: it holds sealed secrets and session hashes), synced,
// checked and renamed, so dest is either absent or complete. dest must not
// exist. src is never migrated, so offline tools can snapshot a database of
// any schema version.
func BackupFile(ctx context.Context, src, dest string) error {
	if _, err := os.Lstat(dest); err == nil {
		return fmt.Errorf("storage: backup target %s exists", dest)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	tmp := dest + ".partial"
	_ = os.Remove(tmp)
	defer os.Remove(tmp)

	// A dedicated connection: read connections are query_only, which refuses
	// VACUUM INTO, and the write connection must not be tied up. VACUUM INTO
	// only takes a read snapshot of the source.
	c, err := sql.Open("sqlite", dsn(src, fmt.Sprintf("_pragma=busy_timeout(%d)", 5000)))
	if err != nil {
		return err
	}
	defer c.Close()
	if _, err := c.ExecContext(ctx, `VACUUM INTO ?`, tmp); err != nil {
		return fmt.Errorf("storage: vacuum into: %w", err)
	}
	if err := os.Chmod(tmp, 0o600); err != nil {
		return err
	}
	if err := syncFile(tmp); err != nil {
		return err
	}
	if _, err := InspectFile(ctx, tmp); err != nil {
		return err
	}
	if err := os.Rename(tmp, dest); err != nil {
		return err
	}
	return syncDir(filepath.Dir(dest))
}

// InspectFile checks a database file that no process has open (a backup) with
// PRAGMA quick_check and returns its schema version, the highest applied
// migration (0 for a database without migrations).
func InspectFile(ctx context.Context, path string) (int, error) {
	c, err := sql.Open("sqlite", dsn(path, "_pragma=query_only(1)"))
	if err != nil {
		return 0, err
	}
	defer c.Close()
	var s string
	if err := c.QueryRowContext(ctx, `PRAGMA quick_check`).Scan(&s); err != nil {
		return 0, fmt.Errorf("storage: check %s: %w", path, err)
	}
	if s != "ok" {
		return 0, fmt.Errorf("storage: %s failed quick_check: %s", path, s)
	}
	return appliedVersion(ctx, c)
}

// LatestSchemaVersion is the schema version this binary migrates databases
// to. A database (or backup) with a higher version was written by a newer
// release and must not be used.
func LatestSchemaVersion() int {
	ms, err := loadMigrations(embedded())
	if err != nil {
		panic(err) // the embedded migrations are checked by tests
	}
	return len(ms)
}

// appliedVersion returns the highest applied migration, 0 when the database
// has never been migrated.
func appliedVersion(ctx context.Context, q interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}) (int, error) {
	var n int
	if err := q.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'schema_migrations'`).Scan(&n); err != nil {
		return 0, fmt.Errorf("storage: read schema version: %w", err)
	}
	if n == 0 {
		return 0, nil
	}
	var v int
	if err := q.QueryRowContext(ctx, `SELECT COALESCE(MAX(version), 0) FROM schema_migrations`).Scan(&v); err != nil {
		return 0, fmt.Errorf("storage: read schema version: %w", err)
	}
	return v, nil
}

// ── 迁移前快照 ──────────────────────────────────────────────────────────────

// keepPreMigrate is how many pre-migration snapshots Open keeps.
const keepPreMigrate = 3

// BackupDir is where the host keeps automatic and scheduled backups of the
// database at dbPath: <data dir>/backups.
func BackupDir(dbPath string) string {
	return filepath.Join(filepath.Dir(dbPath), "backups")
}

// snapshotBeforeMigrate snapshots the database before migrations from..to
// run, so the previous release can be put back together with its data (a
// migrated database refuses the older binary). Only the latest
// keepPreMigrate snapshots are kept.
func (db *DB) snapshotBeforeMigrate(ctx context.Context, from, to int, now time.Time) error {
	dir := BackupDir(db.path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("storage: pre-migration snapshot: %w", err)
	}
	dest := filepath.Join(dir, fmt.Sprintf("pre-migrate-%04d-%04d-%s.db", from, to, now.UTC().Format("20060102T150405Z")))
	if err := db.Backup(ctx, dest); err != nil {
		return fmt.Errorf("storage: pre-migration snapshot: %w", err)
	}
	db.log.InfoContext(ctx, "pre-migration snapshot", "path", dest, "from", from, "to", to)
	if err := PruneBackups(dir, "pre-migrate-*.db", keepPreMigrate); err != nil {
		db.log.WarnContext(ctx, "prune pre-migration snapshots", "error", err)
	}
	return nil
}

// PruneBackups deletes all but the newest keep files in dir that match the
// glob pattern; newest by modification time, then by name. keep <= 0 keeps
// everything.
func PruneBackups(dir, pattern string, keep int) error {
	if keep <= 0 {
		return nil
	}
	paths, err := filepath.Glob(filepath.Join(dir, pattern))
	if err != nil {
		return err
	}
	type entry struct {
		path string
		mod  time.Time
	}
	var es []entry
	for _, p := range paths {
		fi, err := os.Lstat(p)
		if err != nil || !fi.Mode().IsRegular() {
			continue
		}
		es = append(es, entry{p, fi.ModTime()})
	}
	sort.Slice(es, func(i, j int) bool {
		if !es[i].mod.Equal(es[j].mod) {
			return es[i].mod.After(es[j].mod)
		}
		return es[i].path > es[j].path
	})
	var errs []error
	for _, e := range es[min(keep, len(es)):] {
		if err := os.Remove(e.path); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func syncFile(path string) error {
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}

func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
