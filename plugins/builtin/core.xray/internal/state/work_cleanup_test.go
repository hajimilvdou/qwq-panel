// SPDX-License-Identifier: AGPL-3.0-only

//go:build linux

package state

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// ============================================================================
// 真实私有树：空 owner 不积累，历史残留可以恢复，坏输入不导致部分清理。
// ============================================================================

func TestCleanWorkRemovesOnlyEmptyOwner(t *testing.T) {
	store := storeFixture(t)
	for _, attempt := range []uint32{1, 2} {
		if _, err := store.Stage(t.Context(), "op-one", attempt, []byte(`{"fixture":true}`)); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.CleanWork(t.Context(), "op-one", 1); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(store.directory, "work", "op-one", "2", "config.json")); err != nil {
		t.Fatalf("another attempt was removed: %v", err)
	}
	if err := store.CleanWork(t.Context(), "op-one", 2); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(store.directory, "work", "op-one")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("empty owner survived completed cleanup: %v", err)
	}
	if err := store.CleanWork(t.Context(), "op-one", 2); err != nil {
		t.Fatalf("cleanup retry: %v", err)
	}
}

func TestCleanWorkRetryRemovesLegacyEmptyOwner(t *testing.T) {
	store := storeFixture(t)
	owner := filepath.Join(store.directory, "work", "op-orphan")
	if err := os.MkdirAll(owner, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := store.CleanWork(t.Context(), "op-orphan", 1); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(owner); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("retry kept an owner whose attempt is already gone: %v", err)
	}
}

func TestCleanAbandonedWorkRecoversBeyondOldLimit(t *testing.T) {
	for _, layout := range []string{"owners", "attempts"} {
		t.Run(layout, func(t *testing.T) {
			store := storeFixture(t)
			for index := 1; index <= 1100; index++ {
				owner, attempt := "op-many", uint32(index)
				if layout == "owners" {
					owner, attempt = fmt.Sprintf("op-%04d", index), 1
				}
				seedCleanupWork(t, store, owner, attempt)
			}
			if err := store.CleanAbandonedWork(t.Context()); err != nil {
				t.Fatalf("recovering %s beyond the old 1024 limit: %v", layout, err)
			}
			entries, err := os.ReadDir(filepath.Join(store.directory, "work"))
			if err != nil || len(entries) != 0 {
				t.Fatalf("recovery left %d entries: %v", len(entries), err)
			}
			if err := store.CleanAbandonedWork(t.Context()); err != nil {
				t.Fatalf("recovery retry: %v", err)
			}
		})
	}
}

func TestCleanAbandonedWorkValidatesEveryBatchBeforeDeleting(t *testing.T) {
	store := storeFixture(t)
	for index := 1; index <= 1050; index++ {
		seedCleanupWork(t, store, fmt.Sprintf("op-%04d", index), 1)
	}
	bad := filepath.Join(store.directory, "work", "unexpected owner")
	if err := os.Mkdir(bad, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := store.CleanAbandonedWork(t.Context()); !errors.Is(err, ErrOwner) {
		t.Fatalf("invalid late batch=%v; want ErrOwner", err)
	}
	entries, err := os.ReadDir(filepath.Join(store.directory, "work"))
	if err != nil || len(entries) != 1051 {
		t.Fatalf("validation removed an earlier batch: %d entries, %v", len(entries), err)
	}
}

func TestCleanAbandonedWorkRejectsNonCanonicalAttemptBeyondOldLimit(t *testing.T) {
	store := storeFixture(t)
	for attempt := uint32(1); attempt <= 1050; attempt++ {
		seedCleanupWork(t, store, "op-many", attempt)
	}
	owner := filepath.Join(store.directory, "work", "op-many")
	if err := os.Mkdir(filepath.Join(owner, "01"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := store.CleanAbandonedWork(t.Context()); !errors.Is(err, ErrOwner) {
		t.Fatalf("non-canonical attempt=%v; want ErrOwner", err)
	}
	entries, err := os.ReadDir(owner)
	if err != nil || len(entries) != 1051 {
		t.Fatalf("invalid attempt caused partial cleanup: %d entries, %v", len(entries), err)
	}
}

func seedCleanupWork(t *testing.T, store *Store, owner string, attempt uint32) {
	t.Helper()
	directory := filepath.Join(store.directory, "work", owner, fmt.Sprint(attempt))
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "config.json"), []byte(`{"test_only":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
}
