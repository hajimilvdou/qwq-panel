// SPDX-License-Identifier: AGPL-3.0-only

package controller

import (
	"bytes"
	"crypto/ed25519"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/qwq-panel/qwq/internal/platform/problem"
	"github.com/qwq-panel/qwq/sdk/manifest"
	"github.com/qwq-panel/qwq/sdk/pkgfile"
)

// TestPluginInstallerInspectVerifiesWithoutPublishing: a package the install
// saga would accept comes back as a fully verified verdict, and the version
// directory is never published (GAPS gap 4).
func TestPluginInstallerInspectVerifiesWithoutPublishing(t *testing.T) {
	f := newInstallerFixture(t)

	verdict, err := f.installer.Inspect(t.Context(), f.pkg.path)
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if verdict.Staged == nil {
		t.Fatal("a valid package has no staged result")
	}
	defer func() { _ = verdict.Staged.DiscardStaged() }()
	if verdict.Manifest == nil || verdict.Manifest.ID != updaterTestID {
		t.Fatalf("manifest = %+v", verdict.Manifest)
	}
	if !verdict.Valid || !verdict.Trusted || verdict.KeyID != manifest.KeyID(f.pkg.pub) {
		t.Fatalf("signature verdict = %+v", verdict)
	}
	if verdict.UnpackedBytes <= 0 {
		t.Fatalf("unpacked bytes = %d", verdict.UnpackedBytes)
	}
	if len(verdict.Problems) != 0 {
		t.Fatalf("problems = %+v", verdict.Problems)
	}
	// Only the private staging area was written.
	if _, err := os.Stat(filepath.Join(f.pluginsRoot, updaterTestID)); !os.IsNotExist(err) {
		t.Fatalf("inspection published the version directory: %v", err)
	}
}

// TestPluginInstallerInspectUnknownKey: a package signed by a key outside the
// trust root is reported with its manifest, not failed.
func TestPluginInstallerInspectUnknownKey(t *testing.T) {
	f := newInstallerFixture(t)
	other := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x07}, ed25519.SeedSize))
	otherDir := t.TempDir()
	pemBytes, err := pkgfile.MarshalPublicKeyPEM(other.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(otherDir, "other.pem"), pemBytes, 0o644); err != nil {
		t.Fatal(err)
	}
	f.installer.TrustDir = otherDir

	verdict, err := f.installer.Inspect(t.Context(), f.pkg.path)
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if verdict.Staged != nil {
		t.Fatal("a refused package was staged")
	}
	if verdict.Valid || verdict.Trusted {
		t.Fatalf("signature verdict = %+v, want refused", verdict)
	}
	if verdict.KeyID != manifest.KeyID(f.pkg.pub) {
		t.Fatalf("key id = %q", verdict.KeyID)
	}
	if verdict.Manifest == nil || verdict.Manifest.ID != updaterTestID || verdict.UnpackedBytes <= 0 {
		t.Fatalf("refused package lost its manifest or size: %+v", verdict)
	}
}

// TestPluginInstallerInspectPublisherPolicy: a signature that verifies but is
// bound to another publisher is a field violation, not an invalid signature
// (ADR-0015).
func TestPluginInstallerInspectPublisherPolicy(t *testing.T) {
	f := newInstallerFixture(t)
	dir := f.pkg.trustDir(t)
	policy := []byte(`{"publisher":"someone-else"}`)
	if err := os.WriteFile(filepath.Join(dir, "publisher.policy.json"), policy, 0o644); err != nil {
		t.Fatal(err)
	}
	f.installer.TrustDir = dir

	verdict, err := f.installer.Inspect(t.Context(), f.pkg.path)
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if !verdict.Valid || !verdict.Trusted {
		t.Fatalf("verdict = %+v, want crypto and trust accepted", verdict)
	}
	if len(verdict.Problems) != 1 || verdict.Problems[0].Code != manifest.CodePublisherMismatch {
		t.Fatalf("problems = %+v", verdict.Problems)
	}
	if verdict.Manifest == nil {
		t.Fatal("binding refusal lost the manifest")
	}
}

// TestPluginInstallerInspectCorruptAndMisconfigured: an unparseable container
// keeps an error (the updater maps it), and a host without a trust directory
// reports UNAVAILABLE.
func TestPluginInstallerInspectCorruptAndMisconfigured(t *testing.T) {
	f := newInstallerFixture(t)
	broken := filepath.Join(t.TempDir(), "broken.ppkg")
	if err := os.WriteFile(broken, []byte("not a package"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := f.installer.Inspect(t.Context(), broken); err == nil || !strings.Contains(err.Error(), pkgfile.CodeCorrupt) {
		t.Fatalf("Inspect(corrupt) = %v, want a package rejection", err)
	}
	if _, err := f.installer.Inspect(t.Context(), ""); !problem.HasCode(err, problem.ValidationFailed) {
		t.Fatalf("Inspect(empty) = %v, want VALIDATION_FAILED", err)
	}
	f.installer.TrustDir = ""
	if _, err := f.installer.Inspect(t.Context(), f.pkg.path); !problem.HasCode(err, problem.Unavailable) {
		t.Fatalf("Inspect(no trust dir) = %v, want UNAVAILABLE", err)
	}
}
