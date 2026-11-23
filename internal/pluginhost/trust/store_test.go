// SPDX-License-Identifier: AGPL-3.0-only

package trust

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/qwq-panel/qwq/sdk/manifest"
	"github.com/qwq-panel/qwq/sdk/pkgfile"
)

type fixedClock struct{ t time.Time }

func (c fixedClock) Now() time.Time                         { return c.t }
func (c fixedClock) After(d time.Duration) <-chan time.Time { return time.After(d) }

func mustGenerateKeyPair(t *testing.T) (ed25519.PublicKey, string, string) {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	pemBytes, err := pkgfile.MarshalPublicKeyPEM(pub)
	if err != nil {
		t.Fatalf("MarshalPublicKeyPEM: %v", err)
	}
	return pub, string(pemBytes), manifest.KeyID(pub)
}

func TestCompositeTrustStoreLifecycle(t *testing.T) {
	sysDir := filepath.Join(t.TempDir(), "system-trust")
	custDir := filepath.Join(t.TempDir(), "custom-trust")
	if err := os.MkdirAll(sysDir, 0o755); err != nil {
		t.Fatalf("mkdir sysDir: %v", err)
	}

	offPub, offPEM, offID := mustGenerateKeyPair(t)
	if err := os.WriteFile(filepath.Join(sysDir, "qwq-official.pem"), []byte(offPEM), 0o644); err != nil {
		t.Fatalf("write official pem: %v", err)
	}
	if err := os.WriteFile(filepath.Join(sysDir, "qwq-official.policy.json"),
		[]byte(`{"publisher":"qwq-builtin","plugin_ids":["core.*"]}`), 0o644); err != nil {
		t.Fatalf("write policy: %v", err)
	}

	clk := fixedClock{t: time.Date(2026, 11, 23, 8, 0, 0, 0, time.UTC)}
	store := NewCompositeTrustStore(sysDir, custDir, clk)

	// Official key is immediately visible and retains its sidecar policy.
	tk, err := store.LookupKey(offID)
	if err != nil {
		t.Fatalf("LookupKey official: %v", err)
	}
	if !tk.PublicKey.Equal(offPub) || tk.Publisher != "qwq-builtin" || len(tk.PluginIDs) != 1 || tk.PluginIDs[0] != "core.*" {
		t.Fatalf("unexpected official TrustedKey: %+v", tk)
	}

	// Unknown key returns manifest.ErrKeyNotFound.
	devPub, devPEM, devID := mustGenerateKeyPair(t)
	if _, err := store.LookupKey(devID); !errors.Is(err, manifest.ErrKeyNotFound) {
		t.Fatalf("expected ErrKeyNotFound before Add, got %v", err)
	}

	// Add custom developer key and verify immediate LookupKey visibility.
	added, err := store.Add("Acme Dev Key", devPEM, "usr_admin")
	if err != nil {
		t.Fatalf("Add: %v", err)
	}
	if added.KeyID != devID || added.Source != SourceCustom || added.Label != "Acme Dev Key" || added.AddedBy != "usr_admin" {
		t.Fatalf("unexpected added info: %+v", added)
	}
	gotDev, err := store.LookupKey(devID)
	if err != nil {
		t.Fatalf("LookupKey custom: %v", err)
	}
	if !gotDev.PublicKey.Equal(devPub) {
		t.Fatalf("custom public key mismatch")
	}

	// Duplicate add (custom or official) is rejected.
	if _, err := store.Add("Dup Dev", devPEM, "usr_admin"); !errors.Is(err, ErrDuplicateKey) {
		t.Fatalf("expected ErrDuplicateKey for custom dup, got %v", err)
	}
	if _, err := store.Add("Dup Official", offPEM, "usr_admin"); !errors.Is(err, ErrDuplicateKey) {
		t.Fatalf("expected ErrDuplicateKey for official dup, got %v", err)
	}

	// Invalid label and invalid PEM are rejected.
	if _, err := store.Add("   ", devPEM, "usr_admin"); !errors.Is(err, ErrInvalidLabel) {
		t.Fatalf("expected ErrInvalidLabel, got %v", err)
	}
	if _, err := store.Add("Bad PEM", "not a pem", "usr_admin"); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("expected ErrInvalidKey, got %v", err)
	}

	// List returns official first, then custom.
	items, err := store.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(items) != 2 {
		t.Fatalf("List len = %d, want 2", len(items))
	}
	if items[0].Source != SourceOfficial || items[0].KeyID != offID || items[0].Label != "qwq-builtin" {
		t.Fatalf("items[0] = %+v", items[0])
	}
	if items[1].Source != SourceCustom || items[1].KeyID != devID || items[1].Label != "Acme Dev Key" {
		t.Fatalf("items[1] = %+v", items[1])
	}

	// Removing official key is forbidden.
	if err := store.Remove(offID); !errors.Is(err, ErrOfficialKey) {
		t.Fatalf("expected ErrOfficialKey, got %v", err)
	}

	// Removing custom key succeeds and immediately disappears from LookupKey & List.
	if err := store.Remove(devID); err != nil {
		t.Fatalf("Remove custom: %v", err)
	}
	if _, err := store.LookupKey(devID); !errors.Is(err, manifest.ErrKeyNotFound) {
		t.Fatalf("expected ErrKeyNotFound after Remove, got %v", err)
	}
	if err := store.Remove(devID); !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("expected ErrKeyNotFound on second Remove, got %v", err)
	}
	if err := store.Remove("bad-id"); !errors.Is(err, ErrInvalidKeyID) {
		t.Fatalf("expected ErrInvalidKeyID, got %v", err)
	}
}
