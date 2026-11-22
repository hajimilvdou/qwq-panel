// SPDX-License-Identifier: AGPL-3.0-only

//go:build unix

package storage

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"testing/fstest"
	"time"

	"github.com/qwq-panel/qwq/internal/platform/clock"
)

// TestBackupFileMode0600 keeps snapshots private whatever the umask: they hold
// sealed secrets, session hashes and operation results (DEP-04).
func TestBackupFileMode0600(t *testing.T) {
	old := syscall.Umask(0o022)
	t.Cleanup(func() { syscall.Umask(old) })

	db := open(t, Options{})
	dest := filepath.Join(t.TempDir(), "backup.db")
	if err := db.Backup(context.Background(), dest); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(dest)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("backup mode %v, want 0600", fi.Mode().Perm())
	}
}

// TestOpenSnapshotsBeforeMigrate: an upgrade that migrates an existing
// database first leaves a pre-migration snapshot, so the old binary can be
// put back with its data (DEP-04). Only the latest three are kept; a fresh
// database and an up-to-date one get none.
func TestOpenSnapshotsBeforeMigrate(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	path := filepath.Join(dir, "qwq.db")
	backups := filepath.Join(dir, "backups")
	clk := clock.NewFake(time.Date(2026, 11, 10, 8, 0, 0, 0, time.UTC))

	ms := fstest.MapFS{"0001_a.sql": {Data: []byte("CREATE TABLE event_journal (seq INTEGER PRIMARY KEY AUTOINCREMENT, event_id TEXT, type TEXT, schema_version TEXT, subject TEXT, occurred_at TEXT, actor_kind TEXT, actor_id TEXT, on_behalf_of TEXT, node_id TEXT, trace_id TEXT, operation_id TEXT, payload TEXT);")}}
	openWith := func() {
		t.Helper()
		db, err := Open(ctx, Options{Path: path, Migrations: ms, Clock: clk})
		if err != nil {
			t.Fatal(err)
		}
		db.Close()
	}
	snapshots := func() []string {
		t.Helper()
		got, err := filepath.Glob(filepath.Join(backups, "pre-migrate-*.db"))
		if err != nil {
			t.Fatal(err)
		}
		return got
	}

	openWith() // fresh database
	openWith() // up to date
	if got := snapshots(); len(got) != 0 {
		t.Fatalf("snapshots without a migration: %v", got)
	}

	for v := 2; v <= 5; v++ {
		ms[fmt.Sprintf("%04d_t%d.sql", v, v)] = &fstest.MapFile{Data: []byte(fmt.Sprintf("CREATE TABLE t%d (x INTEGER);", v))}
		clk.Advance(time.Minute)
		openWith()
	}
	got := snapshots()
	if len(got) != 3 {
		t.Fatalf("snapshots %v, want the latest 3", got)
	}
	if !strings.HasPrefix(filepath.Base(got[0]), "pre-migrate-0002-0003-") ||
		!strings.HasPrefix(filepath.Base(got[2]), "pre-migrate-0004-0005-") {
		t.Fatalf("kept %v, want 0002-0003 .. 0004-0005", got)
	}
	fi, err := os.Stat(got[2])
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("snapshot mode %v, want 0600", fi.Mode().Perm())
	}
	if v, err := InspectFile(ctx, got[2]); err != nil || v != 4 {
		t.Fatalf("snapshot schema = %d, %v; want 4 (before migration 0005)", v, err)
	}
}
