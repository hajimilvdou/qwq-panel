// SPDX-License-Identifier: AGPL-3.0-only

package secrets

import (
	"context"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"github.com/qwq-panel/qwq/internal/platform/clock"
	"github.com/qwq-panel/qwq/internal/platform/problem"
	"github.com/qwq-panel/qwq/internal/storage"
)

// testTime is the fake clock start; certificates and timestamps in tests are
// relative to it.
var testTime = time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)

// newTestStore returns a store over a fresh database and key ring in a temporary
// data directory.
func newTestStore(t *testing.T) (store *Store, db *storage.DB, dataDir string) {
	t.Helper()
	return newTestStoreWith(t, nil)
}

// newTestStoreWith is newTestStore with a logger attached to the store.
func newTestStoreWith(t *testing.T, logger *slog.Logger) (store *Store, db *storage.DB, dataDir string) {
	t.Helper()
	dataDir = t.TempDir()
	db, err := storage.Open(context.Background(), storage.Options{
		Path:        filepath.Join(dataDir, "qwq.db"),
		ReadConns:   2,
		BusyTimeout: 2 * time.Second,
		Clock:       clock.NewFake(testTime),
	})
	if err != nil {
		t.Fatalf("storage.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	ring, err := LoadKeyRing(dataDir)
	if err != nil {
		t.Fatalf("LoadKeyRing: %v", err)
	}
	store, err = New(Options{DB: db, Keys: ring, Logger: logger})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return store, db, dataDir
}

// mustPut stores a value in its own transaction.
func mustPut(t *testing.T, s *Store, db *storage.DB, owner, purpose string, plaintext []byte) Ref {
	t.Helper()
	var ref Ref
	err := db.Update(context.Background(), func(tx *storage.Tx) error {
		r, err := s.Put(context.Background(), tx, owner, purpose, plaintext)
		if err != nil {
			return err
		}
		ref = r
		return nil
	})
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	return ref
}

// exec runs one statement in a write transaction.
func execSQL(t *testing.T, db *storage.DB, query string, args ...any) {
	t.Helper()
	err := db.Update(context.Background(), func(tx *storage.Tx) error {
		_, err := tx.ExecContext(context.Background(), query, args...)
		return err
	})
	if err != nil {
		t.Fatalf("exec %q: %v", query, err)
	}
}

// requireCode fails unless err carries the given problem code.
func requireCode(t *testing.T, err error, code problem.Code) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected %s, got nil", code)
	}
	if !problem.HasCode(err, code) {
		t.Fatalf("expected %s, got %v", code, err)
	}
}
