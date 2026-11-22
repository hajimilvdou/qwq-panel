// SPDX-License-Identifier: AGPL-3.0-only
//go:build linux

package local

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/qwq-panel/qwq/internal/sandbox"
)

func testFileState(t *testing.T) FileState {
	t.Helper()
	root := t.TempDir()
	return FileState{Directory: root, Name: "qwq.nft", LockDirectory: root, LockName: "capability.lock", Trust: sandbox.TrustPolicy{UID: os.Getuid(), StopAt: root}}
}

func TestPrivateFileStatePersistsAcrossInstances(t *testing.T) {
	root := t.TempDir()
	state := FileState{Directory: root, Name: "private-state.json", Trust: sandbox.TrustPolicy{UID: os.Getuid(), StopAt: root}, Mode: 0600}
	if err := state.Commit([]byte(`{"state":"pending"}`)); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(root, state.Name))
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("private state permission is not 0600")
	}
	restarted := state
	raw, exists, err := restarted.Read()
	if err != nil || !exists || string(raw) != `{"state":"pending"}` {
		t.Fatal("private state did not survive a new instance")
	}
	if err := os.Chmod(filepath.Join(root, state.Name), 0644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := restarted.Read(); err == nil {
		t.Fatal("weakened private state permission accepted")
	}
}

func TestFileStateLockAndCancellation(t *testing.T) {
	s := testFileState(t)
	unlock, err := s.Lock(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Millisecond)
	defer cancel()
	if _, err := s.Lock(ctx); !errors.Is(err, context.DeadlineExceeded) {
		unlock()
		t.Fatal("second lock did not cancel")
	}
	unlock()
	unlock, err = s.Lock(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	unlock()
}

func TestFileStateAtomicCommitAndSymlink(t *testing.T) {
	s := testFileState(t)
	if _, exists, err := s.Read(); err != nil || exists {
		t.Fatal("missing state was not distinguished")
	}
	if err := s.Commit([]byte("TEST-ONLY-original")); err != nil {
		t.Fatal(err)
	}
	if err := s.Commit([]byte("TEST-ONLY-replacement")); err != nil {
		t.Fatal(err)
	}
	raw, exists, err := s.Read()
	if err != nil || !exists || string(raw) != "TEST-ONLY-replacement" {
		t.Fatal("atomic replacement failed")
	}
	info, err := os.Stat(filepath.Join(s.Directory, s.Name))
	if err != nil || info.Mode().Perm() != 0644 {
		t.Fatal("state file permissions changed")
	}
	if err := s.Commit(nil); err != nil {
		t.Fatal(err)
	}
	victim := filepath.Join(t.TempDir(), "victim")
	if err := os.WriteFile(victim, []byte("TEST-ONLY-untouched"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victim, filepath.Join(s.Directory, s.Name)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Read(); err == nil {
		t.Fatal("symlink state was read")
	}
	if err := s.Commit([]byte("TEST-ONLY-unsafe")); err == nil {
		t.Fatal("symlink state was replaced")
	}
	raw, err = os.ReadFile(victim)
	if err != nil || string(raw) != "TEST-ONLY-untouched" {
		t.Fatal("state write escaped the trusted root")
	}
	entries, err := os.ReadDir(s.Directory)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if filepath.Ext(entry.Name()) == ".tmp" {
			t.Fatal("temporary state was not cleaned")
		}
	}
}
