// SPDX-License-Identifier: AGPL-3.0-only

//go:build linux

package state

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func storeFixture(t *testing.T) *Store {
	t.Helper()
	directory := filepath.Join(t.TempDir(), "data")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	return NewStore(directory)
}

func fixtureSummary() *IntentSummary {
	return &IntentSummary{PublicIntentSummary: PublicIntentSummary{InboundID: "main", Listen: "127.0.0.1", Port: 10443,
		Protocol: "vless", Transport: "raw", Flow: "xtls-rprx-vision", SecurityMode: "reality",
		Target: "example.com:443", ServerNames: []string{"example.com"}, ShortIDCount: 1,
		UserIDs: []string{"alice"}, OutboundType: "direct"},
		PrivateKeyRefDigest: "sha256:" + strings.Repeat("a", 64), UserRefsDigest: "sha256:" + strings.Repeat("b", 64), ShortIDsDigest: "sha256:" + strings.Repeat("c", 64)}
}

func installFixture(t *testing.T, store *Store, operation, revision, label string) *Generation {
	t.Helper()
	work, err := store.Stage(t.Context(), operation, 1, []byte(`{"fixture":"`+label+`"}`))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Install(t.Context(), work); err != nil {
		t.Fatal(err)
	}
	return &Generation{Digest: work.Digest, Revision: revision, Version: CoreVersion, Enabled: true, Summary: fixtureSummary()}
}

// ======================== 真实私有文件与原子指针 ========================
func TestStoreImmutableGenerationAndCurrentPreviousCommit(t *testing.T) {
	store := storeFixture(t)
	first := installFixture(t, store, "op-one", "1", "one")
	old := &Metadata{SchemaVersion: "1", State: "RUNNING", Current: first, ResetEpoch: "epoch-one"}
	if err := store.Commit(t.Context(), old); err != nil {
		t.Fatal(err)
	}
	second := installFixture(t, store, "op-two", "2", "two")
	next := &Metadata{SchemaVersion: "1", State: "RUNNING", Current: second, Previous: first, ResetEpoch: "epoch-two"}
	if err := store.Commit(t.Context(), next); err != nil {
		t.Fatal(err)
	}
	current, err := store.Committed(t.Context())
	if err != nil || current.Current.Revision != "2" || current.Previous.Revision != "1" {
		t.Fatalf("current/previous were not committed together: %v", err)
	}
	path, err := store.GenerationPath(t.Context(), first.Digest)
	if err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	work, err := store.Stage(t.Context(), "op-repeat", 2, []byte(`{"fixture":"one"}`))
	if err != nil || work.Digest != first.Digest {
		t.Fatal("identical native bytes did not keep their digest")
	}
	if err := store.Install(t.Context(), work); err != nil {
		t.Fatal(err)
	}
	after, err := os.Stat(path)
	if err != nil || !os.SameFile(before, after) || after.Mode().Perm() != 0o600 {
		t.Fatal("existing immutable generation was overwritten")
	}
}

func TestStoreInvalidOwnershipCancellationAndDamagedGeneration(t *testing.T) {
	store := storeFixture(t)
	for _, owner := range []string{"", "../outside", "op/path", ".", strings.Repeat("a", 129)} {
		if _, err := store.Stage(t.Context(), owner, 1, []byte(`{}`)); err == nil {
			t.Fatal("unsafe work owner was accepted")
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := store.Stage(ctx, "op-cancel", 1, []byte(`{}`)); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled staging wrote a candidate")
	}
	first := installFixture(t, store, "op-one", "1", "one")
	metadata := &Metadata{SchemaVersion: "1", State: "RUNNING", Current: first, ResetEpoch: "epoch-one"}
	if err := store.Commit(t.Context(), metadata); err != nil {
		t.Fatal(err)
	}
	path, err := store.GenerationPath(t.Context(), first.Digest)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(`{"fixture":"corrupt"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Committed(t.Context()); !errors.Is(err, ErrCorrupt) {
		t.Fatal("damaged generation did not fail closed")
	}
}

func TestStoreCommitFailureKeepsPairAndGarbageCollectionKeepsBoth(t *testing.T) {
	store := storeFixture(t)
	first := installFixture(t, store, "op-one", "1", "one")
	second := installFixture(t, store, "op-two", "2", "two")
	orphan := installFixture(t, store, "op-orphan", "3", "orphan")
	metadata := &Metadata{SchemaVersion: "1", State: "RUNNING", Current: second, Previous: first, ResetEpoch: "epoch-two"}
	if err := store.Commit(t.Context(), metadata); err != nil {
		t.Fatal(err)
	}
	write := store.write
	store.write = func(*os.Root, string, []byte, os.FileMode) error { return errors.New("fake disk failure") }
	if err := store.Commit(t.Context(), &Metadata{SchemaVersion: "1", State: "RUNNING", Current: orphan, Previous: second}); err == nil {
		t.Fatal("commit failure was ignored")
	}
	store.write = write
	current, err := store.Committed(t.Context())
	if err != nil || current.Current.Digest != second.Digest || current.Previous.Digest != first.Digest {
		t.Fatal("failed commit split or replaced the pointers")
	}
	if err := store.Prune(t.Context(), current); err != nil {
		t.Fatal(err)
	}
	for _, keep := range []*Generation{first, second} {
		if _, err := store.GenerationPath(t.Context(), keep.Digest); err != nil {
			t.Fatal("garbage collection removed a committed generation")
		}
	}
	if _, err := store.GenerationPath(t.Context(), orphan.Digest); err == nil {
		t.Fatal("garbage collection retained an unreferenced generation")
	}
	if err := store.CleanWork(t.Context(), "op-one", 1); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(store.directory, "work", "op-one", "1")); !os.IsNotExist(err) {
		t.Fatal("owned work remained after cleanup")
	}
	if _, err := os.Stat(filepath.Join(store.directory, "work", "op-two", "1")); err != nil {
		t.Fatal("cleanup removed another operation's work")
	}
}

func TestStorePruneRejectsStalePointersAndSymlinkParent(t *testing.T) {
	store := storeFixture(t)
	first := installFixture(t, store, "op-one", "1", "one")
	second := installFixture(t, store, "op-two", "2", "two")
	old := &Metadata{SchemaVersion: "1", State: "RUNNING", Current: first}
	next := &Metadata{SchemaVersion: "1", State: "RUNNING", Current: second, Previous: first}
	if err := store.Commit(t.Context(), next); err != nil {
		t.Fatal(err)
	}
	if err := store.Prune(t.Context(), old); !errors.Is(err, ErrConflict) {
		t.Fatal("stale collector could remove a newly committed generation")
	}
	if _, err := store.GenerationPath(t.Context(), second.Digest); err != nil {
		t.Fatal("stale collection removed the current generation")
	}
	other := t.TempDir()
	if err := os.Chmod(other, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(filepath.Join(store.directory, "runtime")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(store.directory, "runtime"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(other, filepath.Join(store.directory, "runtime", "generations")); err != nil {
		t.Fatal(err)
	}
	if err := store.Prune(t.Context(), nil); !errors.Is(err, ErrCorrupt) {
		t.Fatal("collector followed a symlink parent")
	}
}

func TestStoreQueuedReadHonorsDeadline(t *testing.T) {
	store := storeFixture(t)
	<-store.gate
	defer func() { store.gate <- struct{}{} }()
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer cancel()
	if _, err := store.Committed(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("snapshot read waited past its cancelled queue slot")
	}
}

func TestStoreRestoreFirstApplyReturnsToUnconfigured(t *testing.T) {
	store := storeFixture(t)
	first := installFixture(t, store, "op-first", "1", "one")
	if err := store.Commit(t.Context(), &Metadata{SchemaVersion: "1", State: "RUNNING", Current: first}); err != nil {
		t.Fatal(err)
	}
	if err := store.Restore(t.Context(), nil); err != nil {
		t.Fatal(err)
	}
	if metadata, err := store.Committed(t.Context()); err != nil || metadata != nil {
		t.Fatal("rollback of first Apply left a committed candidate")
	}
	if _, err := store.GenerationPath(t.Context(), first.Digest); err != nil {
		t.Fatal("restoring pointers removed configuration before process cleanup")
	}
	if err := store.Prune(t.Context(), nil); err != nil {
		t.Fatal(err)
	}
	if _, err := store.GenerationPath(t.Context(), first.Digest); err == nil {
		t.Fatal("unreferenced first candidate survived final cleanup")
	}
}

func TestStoreStartupCleanupRemovesOnlyValidatedWorkOwners(t *testing.T) {
	store := storeFixture(t)
	first, err := store.Stage(t.Context(), "op-old", 3, []byte(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	second, err := store.Stage(t.Context(), "op-other", 4, []byte(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.CleanAbandonedWork(t.Context()); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{first.Path, second.Path} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatal("abandoned work was retained")
		}
	}
	if err := store.CleanAbandonedWork(t.Context()); err != nil {
		t.Fatal("startup cleanup was not idempotent")
	}
}
