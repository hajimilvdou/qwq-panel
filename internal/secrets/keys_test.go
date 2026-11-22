// SPDX-License-Identifier: AGPL-3.0-only

package secrets

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestLoadKeyRingCreatesKeyAtomically(t *testing.T) {
	dataDir := t.TempDir()
	ring, err := LoadKeyRing(dataDir)
	if err != nil {
		t.Fatalf("LoadKeyRing: %v", err)
	}
	keyPath := filepath.Join(dataDir, "keys", "master.key")
	info, err := os.Stat(keyPath)
	if err != nil {
		t.Fatalf("stat master key: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("master.key mode %04o, want 0600", got)
	}
	dirInfo, err := os.Stat(filepath.Join(dataDir, "keys"))
	if err != nil {
		t.Fatalf("stat key directory: %v", err)
	}
	if got := dirInfo.Mode().Perm(); got != 0o700 {
		t.Fatalf("keys directory mode %04o, want 0700", got)
	}
	raw, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("read master key: %v", err)
	}
	if len(raw) != MasterKeySize {
		t.Fatalf("master.key holds %d bytes, want %d", len(raw), MasterKeySize)
	}
	if !regexp.MustCompile(`^[0-9a-f]{16}$`).MatchString(ring.Primary().ID) {
		t.Fatalf("key id %q is not 16 lower-case hex characters", ring.Primary().ID)
	}

	// Reloading reads the same key: the id is stable across restarts.
	again, err := LoadKeyRing(dataDir)
	if err != nil {
		t.Fatalf("second LoadKeyRing: %v", err)
	}
	if again.Primary().ID != ring.Primary().ID {
		t.Fatalf("reload produced key id %s, want %s", again.Primary().ID, ring.Primary().ID)
	}
	if len(again.IDs()) != 1 {
		t.Fatalf("reload found keys %v, want only the primary", again.IDs())
	}
	// No temporary files are left behind.
	entries, err := os.ReadDir(filepath.Join(dataDir, "keys"))
	if err != nil {
		t.Fatalf("read key directory: %v", err)
	}
	if len(entries) != 1 {
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Fatalf("keys directory holds %v, want only master.key", names)
	}
}

func TestLoadKeyRingRefusesWidePermissions(t *testing.T) {
	t.Run("key file", func(t *testing.T) {
		dataDir := t.TempDir()
		ring, err := LoadKeyRing(dataDir)
		if err != nil {
			t.Fatalf("LoadKeyRing: %v", err)
		}
		keyPath := filepath.Join(dataDir, "keys", "master.key")
		if err := os.Chmod(keyPath, 0o640); err != nil {
			t.Fatalf("chmod: %v", err)
		}
		_, err = LoadKeyRing(dataDir)
		if err == nil {
			t.Fatal("LoadKeyRing accepted a group-readable master key")
		}
		if !strings.Contains(err.Error(), "chmod 600") {
			t.Fatalf("error does not tell the operator how to fix it: %v", err)
		}
		if !strings.Contains(err.Error(), "0640") {
			t.Fatalf("error does not name the offending mode: %v", err)
		}
		// The error must not leak the key; it only names the file.
		if strings.Contains(err.Error(), ring.Primary().ID) {
			t.Fatalf("permission error mentions the key id: %v", err)
		}
	})

	t.Run("key directory", func(t *testing.T) {
		dataDir := t.TempDir()
		if _, err := LoadKeyRing(dataDir); err != nil {
			t.Fatalf("LoadKeyRing: %v", err)
		}
		dir := filepath.Join(dataDir, "keys")
		if err := os.Chmod(dir, 0o755); err != nil {
			t.Fatalf("chmod: %v", err)
		}
		_, err := LoadKeyRing(dataDir)
		if err == nil {
			t.Fatal("LoadKeyRing accepted a world-readable key directory")
		}
		if !strings.Contains(err.Error(), "chmod 700") {
			t.Fatalf("error does not tell the operator how to fix it: %v", err)
		}
	})

	t.Run("wrong size", func(t *testing.T) {
		dataDir := t.TempDir()
		dir := filepath.Join(dataDir, "keys")
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if err := os.WriteFile(filepath.Join(dir, "master.key"), []byte("short"), 0o600); err != nil {
			t.Fatalf("write key: %v", err)
		}
		_, err := LoadKeyRing(dataDir)
		if err == nil || !strings.Contains(err.Error(), "exactly 32 bytes") {
			t.Fatalf("LoadKeyRing accepted a 5-byte key: %v", err)
		}
	})
}

func TestKeyRingRotation(t *testing.T) {
	dataDir := t.TempDir()
	ring, err := LoadKeyRing(dataDir)
	if err != nil {
		t.Fatalf("LoadKeyRing: %v", err)
	}
	old := ring.Primary()
	rotated, err := ring.Rotate()
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if rotated.ID == old.ID {
		t.Fatal("Rotate kept the old key id")
	}
	if got := ring.Primary().ID; got != rotated.ID {
		t.Fatalf("primary is %s, want %s", got, rotated.ID)
	}
	if ids := ring.Retired(); len(ids) != 1 || ids[0] != old.ID {
		t.Fatalf("retired keys %v, want [%s]", ids, old.ID)
	}
	retiredPath := filepath.Join(dataDir, "keys", "retired-"+old.ID+".key")
	info, err := os.Stat(retiredPath)
	if err != nil {
		t.Fatalf("retired key file: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("retired key mode %04o, want 0600", got)
	}

	// Both keys must survive a restart, otherwise values written before the
	// rotation become unreadable.
	reloaded, err := LoadKeyRing(dataDir)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if got := reloaded.Primary().ID; got != rotated.ID {
		t.Fatalf("reloaded primary %s, want %s", got, rotated.ID)
	}
	if got := reloaded.Retired(); len(got) != 1 || got[0] != old.ID {
		t.Fatalf("reloaded retired keys %v, want [%s]", got, old.ID)
	}
	if _, err := reloaded.aead(old.ID); err != nil {
		t.Fatalf("old key is not usable after reload: %v", err)
	}

	// Dropping the retired key removes its file, and the primary cannot be
	// dropped.
	if err := reloaded.DropRetired(rotated.ID); err == nil {
		t.Fatal("DropRetired accepted the primary key")
	}
	if err := reloaded.DropRetired(old.ID); err != nil {
		t.Fatalf("DropRetired: %v", err)
	}
	if _, err := os.Stat(retiredPath); !os.IsNotExist(err) {
		t.Fatalf("retired key file still exists: %v", err)
	}
	if _, err := reloaded.aead(old.ID); err == nil {
		t.Fatal("dropped key is still usable")
	}
	if err := reloaded.DropRetired(old.ID); err == nil {
		t.Fatal("DropRetired accepted an id that is not in the ring")
	}
}

func TestKeyRingRefusesMismatchedRetiredFile(t *testing.T) {
	dataDir := t.TempDir()
	ring, err := LoadKeyRing(dataDir)
	if err != nil {
		t.Fatalf("LoadKeyRing: %v", err)
	}
	if _, err := ring.Rotate(); err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	keysDir := filepath.Join(dataDir, "keys")
	entries, err := os.ReadDir(keysDir)
	if err != nil {
		t.Fatalf("read dir: %v", err)
	}
	var retired string
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "retired-") {
			retired = e.Name()
		}
	}
	if retired == "" {
		t.Fatal("rotation left no retired key file")
	}
	// Rename it so the id in the name no longer matches the key it holds: the
	// ring must refuse rather than guess which ciphertexts it opens.
	renamed := filepath.Join(keysDir, "retired-0000000000000000.key")
	if err := os.Rename(filepath.Join(keysDir, retired), renamed); err != nil {
		t.Fatalf("rename: %v", err)
	}
	if _, err := LoadKeyRing(dataDir); err == nil {
		t.Fatal("LoadKeyRing accepted a retired key file with the wrong name")
	}
}

func TestKeyRedaction(t *testing.T) {
	dataDir := t.TempDir()
	ring, err := LoadKeyRing(dataDir)
	if err != nil {
		t.Fatalf("LoadKeyRing: %v", err)
	}
	key := ring.Primary()
	raw := fmt.Sprintf("%x", key.raw)
	if raw == "" {
		t.Fatal("test key has no bytes")
	}
	for _, s := range []string{key.String(), key.GoString(), fmt.Sprintf("%#v", key), fmt.Sprint(key)} {
		if strings.Contains(s, raw) {
			t.Fatalf("%q leaks the key bytes", s)
		}
	}
	if !strings.Contains(key.GoString(), key.ID) {
		t.Fatalf("GoString %q does not name the key id", key.GoString())
	}
	if got := key.LogValue().String(); !strings.Contains(got, key.ID) || strings.Contains(got, raw) {
		t.Fatalf("LogValue = %q", got)
	}
}
