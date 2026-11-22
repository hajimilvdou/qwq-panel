// SPDX-License-Identifier: AGPL-3.0-only

package testsupport

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/qwq-panel/qwq/internal/platform/clock"
	"github.com/qwq-panel/qwq/internal/secrets"
	"github.com/qwq-panel/qwq/internal/storage"
)

// ======================== 共享真实 SQLite 与 AES-GCM fixture ========================

func EncryptedStorage(t testing.TB, source clock.Clock) (*storage.DB, *secrets.Store) {
	t.Helper()
	directory := t.TempDir()
	db, err := storage.Open(context.Background(), storage.Options{Path: filepath.Join(directory, "vault.db"), ReadConns: 2, Clock: source})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Error(err)
		}
	})
	keys, err := secrets.LoadKeyRing(directory)
	if err != nil {
		t.Fatal(err)
	}
	store, err := secrets.New(secrets.Options{DB: db, Keys: keys})
	if err != nil {
		t.Fatal(err)
	}
	return db, store
}
