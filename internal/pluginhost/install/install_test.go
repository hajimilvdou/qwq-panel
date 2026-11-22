// SPDX-License-Identifier: AGPL-3.0-only

package install

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/qwq-panel/qwq/sdk/manifest"
	"github.com/qwq-panel/qwq/sdk/pkgfile"
)

const (
	testID      = "test.plugin"
	testVersion = "1.2.3"
)

// testFiles is the tree every test package is packed from.
var testFiles = map[string]string{
	"bin/plugin":                  "#!/bin/sh\necho test plugin\n",
	"schemas/config.schema.json":  `{"type":"object"}`,
	"attestations/sbom.spdx.json": `{"spdxVersion":"SPDX-2.3"}`,
	"ui/index.html":               "<!doctype html><title>test</title>",
}

// testManifest is a schema-valid manifest for the given signing key.
func testManifest(keyID string) string {
	return `{
  "schema_version": "1.2",
  "id": "` + testID + `",
  "version": "` + testVersion + `",
  "name": "Test Plugin",
  "summary": "Install staging test fixture.",
  "publisher": {"id": "test", "key_id": "` + keyID + `"},
  "abi": {"major": 1, "minimum_minor": 0},
  "engine_constraint": ">=1.0.0",
  "target": "linux/amd64",
  "entrypoint": "bin/plugin",
  "files": {},
  "provenance": {"sbom": "attestations/sbom.spdx.json"},
  "placement": "node",
  "lifecycle": {"startup": "eager", "background": false, "update_strategy": "restart"},
  "operations": [],
  "capabilities": [],
  "dependencies": [],
  "state": {"schema_version": "1", "minimum_rollback_version": "1.0.0", "backup_paths": []},
  "config": {"schema": "schemas/config.schema.json", "hot_apply": false},
  "resources": {"memory_max_mb": 32, "cpu_quota_percent": 50, "pids_max": 16, "fds_max": 64, "disk_max_mb": 64}
}
`
}

// uiTestManifest is testManifest plus a sandboxed UI declaration over the
// ui/index.html of testFiles.
func uiTestManifest(keyID string) string {
	return strings.Replace(testManifest(keyID),
		`"placement": "node",`,
		`"ui": {"entry": "ui/index.html", "sandbox": true, "connect_sources": [], "routes": []},
  "placement": "node",`, 1)
}

// testKey is a deterministic Ed25519 key; no key material is ever stored.
func testKey() ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x42}, ed25519.SeedSize))
}

// testPackage is a signed package written to disk.
type testPackage struct {
	path    string
	pub     ed25519.PublicKey
	priv    ed25519.PrivateKey
	digests map[string]string
}

func newTestPackage(t *testing.T) *testPackage {
	t.Helper()
	return newTestPackageWith(t, nil)
}

// newTestPackageWith packs testFiles plus extra (which may add or override
// files) and signs it.
func newTestPackageWith(t *testing.T, extra map[string]string) *testPackage {
	t.Helper()
	return newTestPackageWithManifest(t, testManifest, extra)
}

// newTestPackageWithManifest packs testFiles plus extra and signs it with a
// manifest produced by buildManifest from the signing key id.
func newTestPackageWithManifest(t *testing.T, buildManifest func(keyID string) string, extra map[string]string) *testPackage {
	t.Helper()
	priv := testKey()
	pub := priv.Public().(ed25519.PublicKey)
	src := t.TempDir()
	tree := map[string]string{"manifest.json": buildManifest(manifest.KeyID(pub))}
	for name, content := range testFiles {
		tree[name] = content
	}
	for name, content := range extra {
		tree[name] = content
	}
	for name, content := range tree {
		p := filepath.Join(src, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		mode := fs.FileMode(0o644)
		if name == "bin/plugin" {
			mode = 0o755
		}
		if err := os.WriteFile(p, []byte(content), mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(p, mode); err != nil {
			t.Fatal(err)
		}
	}
	var buf bytes.Buffer
	pkg, err := pkgfile.Pack(src, &buf, pkgfile.PackOptions{SigningKey: priv})
	if err != nil {
		t.Fatalf("Pack: %v", err)
	}
	path := filepath.Join(src, "package.ppkg")
	if err := os.WriteFile(path, buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	digests := make(map[string]string, len(pkg.Files))
	for _, f := range pkg.Files {
		digests[f.Path] = f.Digest
	}
	return &testPackage{path: path, pub: pub, priv: priv, digests: digests}
}

// trustStore returns a trust store that accepts pkg's key.
func (p *testPackage) trustStore(t *testing.T) manifest.TrustStore {
	t.Helper()
	ts, err := manifest.NewStaticTrustStore(manifest.TrustedKey{PublicKey: p.pub})
	if err != nil {
		t.Fatal(err)
	}
	return ts
}

// layout returns the staging root, the plugins root and the expected version
// directory for a test.
func layout(t *testing.T) (staging, plugins, versionDir string) {
	t.Helper()
	base := t.TempDir()
	return filepath.Join(base, "staging"), filepath.Join(base, "plugins"), VersionDir(filepath.Join(base, "plugins"), testID, testVersion)
}

func TestExtractKeepsSignedManifestBytes(t *testing.T) {
	p := newTestPackage(t)
	staging, _, final := layout(t)
	staged, err := Extract(t.Context(), p.path, p.trustStore(t), staging)
	if err != nil {
		t.Fatal(err)
	}
	defer staged.Discard()
	raw := append([]byte(nil), staged.Package().ManifestBytes...)
	if err := staged.Commit(final); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(final, pkgfile.ManifestPath)
	installed, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(installed, raw) || !ed25519.Verify(p.pub, installed, staged.Package().Signature.Sig) {
		t.Fatal("installed manifest is not the exact verified package header")
	}
	info, err := os.Stat(file)
	if err != nil || info.Mode().Perm() != FileMode {
		t.Fatal("installed manifest is not read-only")
	}
}

// TestExtractCommit walks the whole path: verify, stage, publish, and check
// the published tree byte for byte.
func TestExtractCommit(t *testing.T) {
	p := newTestPackage(t)
	staging, plugins, finalDir := layout(t)
	staged, err := Extract(context.Background(), p.path, p.trustStore(t), staging)
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	if !strings.HasPrefix(filepath.Base(staged.Dir()), StagingPrefix) {
		t.Errorf("staging directory %q does not carry %q", staged.Dir(), StagingPrefix)
	}
	if filepath.Dir(staged.Dir()) != staging {
		t.Errorf("staging directory %q is not below %q", staged.Dir(), staging)
	}
	if got := staged.Manifest().ID; got != testID {
		t.Errorf("manifest id %q", got)
	}
	if staged.Package().Signature == nil {
		t.Error("staged package has no signature")
	}
	assertTree(t, staged.Dir())

	if err := staged.Commit(finalDir); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	if staged.Dir() != finalDir {
		t.Errorf("Dir after Commit is %q, want %q", staged.Dir(), finalDir)
	}
	if _, err := os.Stat(filepath.Dir(staged.Dir())); err != nil {
		t.Fatalf("published parent: %v", err)
	}
	assertTree(t, finalDir)
	entries, err := os.ReadDir(staging)
	if err != nil {
		t.Fatalf("read staging root: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("staging root still holds %d entries after Commit", len(entries))
	}
	for name, content := range testFiles {
		got, rerr := os.ReadFile(filepath.Join(finalDir, filepath.FromSlash(name)))
		if rerr != nil {
			t.Fatalf("read published %s: %v", name, rerr)
		}
		if string(got) != content {
			t.Errorf("published %s differs from the package", name)
		}
		// The published tree still matches the manifest, which is exactly what
		// an ExecStartPre check runs before every start.
		if verr := pkgfile.VerifyFile(finalDir, name, p.digests[name]); verr != nil {
			t.Errorf("VerifyFile(%s): %v", name, verr)
		}
	}
	if err := staged.Discard(); err != nil {
		t.Errorf("Discard after Commit: %v", err)
	}
	if _, serr := os.Stat(finalDir); serr != nil {
		t.Errorf("Discard removed the published version directory: %v", serr)
	}

	// A second install of the same version is refused.
	again, err := Extract(context.Background(), p.path, p.trustStore(t), staging)
	if err != nil {
		t.Fatalf("Extract again: %v", err)
	}
	if cerr := again.Commit(finalDir); !errors.Is(cerr, ErrTargetExists) {
		t.Errorf("second Commit = %v, want ErrTargetExists", cerr)
	}
	if err := again.Discard(); err != nil {
		t.Errorf("Discard: %v", err)
	}
	if entries, rerr := os.ReadDir(staging); rerr != nil || len(entries) != 0 {
		t.Errorf("staging root not empty after a refused install: %v %v", entries, rerr)
	}
	if _, serr := os.Stat(plugins); serr != nil {
		t.Errorf("plugins root: %v", serr)
	}
}

// assertTree checks the published modes: 0555 directories, 0444 files and
// 0555 for the executable.
func assertTree(t *testing.T, root string) {
	t.Helper()
	rootInfo, err := os.Stat(root)
	if err != nil {
		t.Fatalf("stat %s: %v", root, err)
	}
	if got := rootInfo.Mode().Perm(); got != DirMode {
		t.Errorf("%s: mode %o, want %o", root, got, DirMode)
	}
	err = filepath.WalkDir(root, func(p string, d fs.DirEntry, werr error) error {
		if werr != nil {
			return werr
		}
		info, ierr := d.Info()
		if ierr != nil {
			return ierr
		}
		rel, _ := filepath.Rel(root, p)
		switch {
		case info.IsDir():
			if got := info.Mode().Perm(); got != DirMode {
				t.Errorf("%s: directory mode %o, want %o", rel, got, DirMode)
			}
		case rel == "bin/plugin":
			if got := info.Mode().Perm(); got != ExecMode {
				t.Errorf("%s: mode %o, want %o", rel, got, ExecMode)
			}
		default:
			if got := info.Mode().Perm(); got != FileMode {
				t.Errorf("%s: mode %o, want %o", rel, got, FileMode)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", root, err)
	}
	if os.Geteuid() != 0 {
		// An unprivileged owner cannot write into the published tree. Root
		// bypasses the permission bits, so the check only runs unprivileged.
		target := filepath.Join(root, "ui", "index.html")
		if err := os.WriteFile(target, []byte("tampered"), 0o644); err == nil {
			t.Error("the published tree is writable")
		}
	}
}

// TestExtractRejectsBadPackages: a rejected package leaves no staging
// directory behind.
func TestExtractRejectsBadPackages(t *testing.T) {
	p := newTestPackage(t)
	raw, err := os.ReadFile(p.path)
	if err != nil {
		t.Fatal(err)
	}
	entries := readPackage(t, raw)

	cases := []struct {
		name string
		data []byte
		code string
	}{
		{
			name: "tampered content",
			data: writePackage(t, replaceData(entries, "bin/plugin", []byte("#!/bin/sh\necho pwned\n"))),
			code: pkgfile.CodeDigestMismatch,
		},
		{
			name: "extra file",
			data: writePackage(t, append(entries[:len(entries):len(entries)], entry{
				hdr:  tar.Header{Name: "ui/extra.js", Typeflag: tar.TypeReg, Mode: 0o644},
				body: []byte("alert(1)"),
			})),
			code: pkgfile.CodeFileUnlisted,
		},
		{
			name: "symlink entry",
			data: writePackage(t, retarget(entries, "ui/index.html", tar.TypeSymlink, "/etc/passwd")),
			code: pkgfile.CodeEntryType,
		},
		{
			name: "traversal path",
			data: writePackage(t, rename(entries, "ui/index.html", "../index.html")),
			code: pkgfile.CodePathTraversal,
		},
		{
			name: "absolute path",
			data: writePackage(t, rename(entries, "ui/index.html", "/etc/index.html")),
			code: pkgfile.CodePathAbsolute,
		},
		{
			name: "missing file",
			data: writePackage(t, dropEntry(entries, "ui/index.html")),
			code: pkgfile.CodeFileMissing,
		},
		{
			name: "unsigned package",
			data: writePackage(t, withoutSignature(entries)),
			code: pkgfile.CodeMissingSignature,
		},
		{
			name: "truncated package",
			data: raw[:len(raw)/2],
			code: pkgfile.CodeCorrupt,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			staging := filepath.Join(t.TempDir(), "staging")
			bad := filepath.Join(t.TempDir(), "bad.ppkg")
			if err := os.WriteFile(bad, c.data, 0o644); err != nil {
				t.Fatal(err)
			}
			staged, err := Extract(context.Background(), bad, p.trustStore(t), staging)
			if err == nil {
				_ = staged.Discard()
				t.Fatal("Extract accepted a broken package")
			}
			var pe *pkgfile.Error
			if !errors.As(err, &pe) || !pe.Has(c.code) {
				t.Fatalf("want pkgfile code %s, got %T: %v", c.code, err, err)
			}
			assertNoStaging(t, staging)
		})
	}
}

// TestExtractRejectsUntrustedKey covers the signature and publisher cases.
func TestExtractRejectsUntrustedKey(t *testing.T) {
	p := newTestPackage(t)
	other := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x17}, ed25519.SeedSize))
	ts, err := manifest.NewStaticTrustStore(manifest.TrustedKey{PublicKey: other.Public().(ed25519.PublicKey)})
	if err != nil {
		t.Fatal(err)
	}
	staging := filepath.Join(t.TempDir(), "staging")
	_, xerr := Extract(context.Background(), p.path, ts, staging)
	var me *manifest.Error
	if !errors.As(xerr, &me) || !me.Has(manifest.CodeKeyUnknown) {
		t.Fatalf("want KEY_UNKNOWN, got %T: %v", xerr, xerr)
	}
	assertNoStaging(t, staging)

	// A trust store that binds the key to another publisher also fails.
	bound, berr := manifest.NewStaticTrustStore(manifest.TrustedKey{PublicKey: p.pub, Publisher: "someone-else"})
	if berr != nil {
		t.Fatal(berr)
	}
	_, xerr = Extract(context.Background(), p.path, bound, staging)
	if !errors.As(xerr, &me) || !me.Has(manifest.CodePublisherMismatch) {
		t.Fatalf("want PUBLISHER_MISMATCH, got %T: %v", xerr, xerr)
	}
	assertNoStaging(t, staging)
}

// TestExtractRequiresTrustStore: installing without verification is not an
// option.
func TestExtractRequiresTrustStore(t *testing.T) {
	p := newTestPackage(t)
	staging := filepath.Join(t.TempDir(), "staging")
	if _, err := Extract(context.Background(), p.path, nil, staging); err == nil {
		t.Fatal("Extract accepted a nil trust store")
	}
}

// TestExtractRejectsCompressionBomb: a package that expands far beyond its
// compressed size is refused before it can fill the disk (ARCH §10.4).
func TestExtractRejectsCompressionBomb(t *testing.T) {
	p := newTestPackageWith(t, map[string]string{"ui/zeros.bin": strings.Repeat("\x00", 16<<20)})
	staging := filepath.Join(t.TempDir(), "staging")
	_, err := Extract(context.Background(), p.path, p.trustStore(t), staging)
	var pe *pkgfile.Error
	if !errors.As(err, &pe) || !pe.Has(pkgfile.CodeCompressionRatio) {
		t.Fatalf("want PKG_COMPRESSION_RATIO, got %T: %v", err, err)
	}
	assertNoStaging(t, staging)
}

// TestDiscard checks the cleanup path and its idempotence.
func TestDiscard(t *testing.T) {
	p := newTestPackage(t)
	staging, _, finalDir := layout(t)
	staged, err := Extract(context.Background(), p.path, p.trustStore(t), staging)
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	dir := staged.Dir()
	if err := staged.Discard(); err != nil {
		t.Fatalf("Discard: %v", err)
	}
	if _, serr := os.Stat(dir); !errors.Is(serr, fs.ErrNotExist) {
		t.Errorf("staging directory still exists: %v", serr)
	}
	if err := staged.Discard(); err != nil {
		t.Errorf("second Discard: %v", err)
	}
	if err := staged.Commit(finalDir); !errors.Is(err, ErrStagedClosed) {
		t.Errorf("Commit after Discard = %v, want ErrStagedClosed", err)
	}
}

// TestCommitTargetChecks: Commit only accepts <root>/<id>/<version>, and a
// rejected target does not consume the staged package.
func TestCommitTargetChecks(t *testing.T) {
	p := newTestPackage(t)
	staging, plugins, finalDir := layout(t)
	staged, err := Extract(context.Background(), p.path, p.trustStore(t), staging)
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	defer func() { _ = staged.Discard() }()
	bad := []string{
		"relative/path",
		filepath.Join(plugins, testID),
		filepath.Join(plugins, "other.plugin", testVersion),
		filepath.Join(plugins, testID, "9.9.9"),
		filepath.Join(plugins, testID, testVersion, "extra"),
	}
	for _, target := range bad {
		if err := staged.Commit(target); !errors.Is(err, ErrTargetMismatch) {
			t.Errorf("Commit(%q) = %v, want ErrTargetMismatch", target, err)
		}
	}
	if err := staged.Commit(finalDir); err != nil {
		t.Fatalf("Commit after rejected targets: %v", err)
	}
	if err := staged.Commit(finalDir); !errors.Is(err, ErrStagedClosed) {
		t.Errorf("second Commit = %v, want ErrStagedClosed", err)
	}
}

// TestCleanupStale removes crash leftovers and nothing else.
func TestCleanupStale(t *testing.T) {
	base := t.TempDir()
	staging := filepath.Join(base, "staging")
	if err := os.MkdirAll(staging, 0o700); err != nil {
		t.Fatal(err)
	}
	old := filepath.Join(staging, StagingPrefix+"old")
	fresh := filepath.Join(staging, StagingPrefix+"fresh")
	other := filepath.Join(staging, "keep-me")
	for _, dir := range []string{old, fresh, other} {
		if err := os.MkdirAll(filepath.Join(dir, "bin"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "bin", "x"), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	past := time.Now().Add(-2 * time.Hour)
	if err := os.Chtimes(old, past, past); err != nil {
		t.Fatal(err)
	}
	removed, err := CleanupStale(staging, time.Hour)
	if err != nil {
		t.Fatalf("CleanupStale: %v", err)
	}
	if len(removed) != 1 || removed[0] != old {
		t.Errorf("CleanupStale removed %v, want [%s]", removed, old)
	}
	if _, serr := os.Stat(fresh); serr != nil {
		t.Errorf("a fresh staging directory was removed: %v", serr)
	}
	if _, serr := os.Stat(other); serr != nil {
		t.Errorf("CleanupStale touched an unrelated entry: %v", serr)
	}
	removed, err = CleanupStale(staging, 0)
	if err != nil {
		t.Fatalf("CleanupStale(0): %v", err)
	}
	if len(removed) != 1 || removed[0] != fresh {
		t.Errorf("CleanupStale(0) removed %v, want [%s]", removed, fresh)
	}
	// A missing staging root is not an error.
	if removed, err := CleanupStale(filepath.Join(base, "absent"), time.Hour); err != nil || len(removed) != 0 {
		t.Errorf("CleanupStale on a missing root = %v, %v", removed, err)
	}
}

// TestCleanupStaleRemovesReadOnlyTrees: a crash leaves the read-only tree
// behind, and cleanup has to cope with it.
func TestCleanupStaleRemovesReadOnlyTrees(t *testing.T) {
	p := newTestPackage(t)
	staging := filepath.Join(t.TempDir(), "staging")
	staged, err := Extract(context.Background(), p.path, p.trustStore(t), staging)
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	// Simulate a crash: drop the handle without committing or discarding.
	_ = staged.closeRoot()
	removed, err := CleanupStale(staging, 0)
	if err != nil {
		t.Fatalf("CleanupStale: %v", err)
	}
	if len(removed) != 1 {
		t.Fatalf("CleanupStale removed %v", removed)
	}
	assertNoStaging(t, staging)
}

// assertNoStaging fails if the staging root holds any entry.
func assertNoStaging(t *testing.T, staging string) {
	t.Helper()
	entries, err := os.ReadDir(staging)
	if errors.Is(err, fs.ErrNotExist) {
		return
	}
	if err != nil {
		t.Fatalf("read staging root: %v", err)
	}
	if len(entries) != 0 {
		names := make([]string, len(entries))
		for i, e := range entries {
			names[i] = e.Name()
		}
		t.Fatalf("staging root is not clean: %v", names)
	}
}

// entry is one raw tar entry of a package.
type entry struct {
	hdr  tar.Header
	body []byte
}

// readPackage decodes a package into entries.
func readPackage(t *testing.T, data []byte) []entry {
	t.Helper()
	zr, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("gzip: %v", err)
	}
	tr := tar.NewReader(zr)
	var out []entry
	for {
		hdr, herr := tr.Next()
		if errors.Is(herr, io.EOF) {
			break
		}
		if herr != nil {
			t.Fatalf("tar: %v", herr)
		}
		body, rerr := io.ReadAll(tr)
		if rerr != nil {
			t.Fatalf("read entry: %v", rerr)
		}
		out = append(out, entry{hdr: *hdr, body: body})
	}
	return out
}

// writePackage re-encodes entries as tar+gzip.
func writePackage(t *testing.T, entries []entry) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(zw)
	for _, e := range entries {
		h := e.hdr
		isFile := h.Typeflag == tar.TypeReg || h.Typeflag == 0
		if isFile {
			h.Size = int64(len(e.body))
		} else {
			h.Size = 0
		}
		if err := tw.WriteHeader(&h); err != nil {
			t.Fatalf("write header %q: %v", h.Name, err)
		}
		if isFile {
			if _, err := tw.Write(e.body); err != nil {
				t.Fatalf("write body %q: %v", h.Name, err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("tar close: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
	return buf.Bytes()
}

// replaceData swaps the content of one entry.
func replaceData(entries []entry, name string, body []byte) []entry {
	return mutate(entries, func(e *entry) bool {
		if e.hdr.Name != name {
			return false
		}
		e.body = body
		return true
	})
}

// rename changes the name of one entry.
func rename(entries []entry, name, newName string) []entry {
	return mutate(entries, func(e *entry) bool {
		if e.hdr.Name != name {
			return false
		}
		e.hdr.Name = newName
		return true
	})
}

// retarget turns one entry into another type.
func retarget(entries []entry, name string, typ byte, link string) []entry {
	return mutate(entries, func(e *entry) bool {
		if e.hdr.Name != name {
			return false
		}
		e.hdr.Typeflag = typ
		e.hdr.Linkname = link
		e.body = nil
		return true
	})
}

// withoutSignature drops the signature entry.
func withoutSignature(entries []entry) []entry {
	out := make([]entry, 0, len(entries))
	for _, e := range entries {
		if e.hdr.Name == pkgfile.SignaturePath {
			continue
		}
		out = append(out, e)
	}
	return out
}

// dropEntry removes one entry, so the package is missing a listed file.
func dropEntry(entries []entry, name string) []entry {
	out := make([]entry, 0, len(entries))
	for _, e := range entries {
		if e.hdr.Name == name {
			continue
		}
		out = append(out, e)
	}
	return out
}

// mutate applies fn to every entry and keeps the result.
func mutate(entries []entry, fn func(*entry) bool) []entry {
	out := make([]entry, 0, len(entries))
	for _, e := range entries {
		fn(&e)
		out = append(out, e)
	}
	return out
}

// TestExtractRejectsRemoteUIScripts: a package whose ui/ tree references a
// remote script is authentic but violates ARCH §5.1, so Extract refuses it
// with a PolicyError and leaves nothing staged.
func TestExtractRejectsRemoteUIScripts(t *testing.T) {
	cases := map[string]string{
		"script tag":                   `<script src="https://cdn.example/app.js"></script>`,
		"protocol-relative script tag": `<script src="//cdn.example/app.js"></script>`,
		"module import":                `import x from "https://cdn.example/app.js"`,
		"dynamic import":               `import("https://cdn.example/app.js")`,
		"worker":                       `new Worker("https://cdn.example/worker.js")`,
		"importScripts":                `importScripts("http://cdn.example/worker.js")`,
	}
	for name, content := range cases {
		t.Run(name, func(t *testing.T) {
			p := newTestPackageWithManifest(t, uiTestManifest, map[string]string{"ui/app.js": content})
			staging := filepath.Join(t.TempDir(), "staging")
			_, err := Extract(context.Background(), p.path, p.trustStore(t), staging)
			var pe *PolicyError
			if !errors.As(err, &pe) {
				t.Fatalf("Extract = %v, want *PolicyError", err)
			}
			if pe.Code != "UI_REMOTE_SCRIPT" || pe.Path != "ui/app.js" {
				t.Fatalf("policy error = %+v", pe)
			}
			if entries, rerr := os.ReadDir(staging); rerr != nil || len(entries) != 0 {
				t.Fatalf("staging not cleaned: %v %v", entries, rerr)
			}
		})
	}
}

// TestExtractAcceptsLegitimateUI: same-package references and plain code pass
// the check.
func TestExtractAcceptsLegitimateUI(t *testing.T) {
	p := newTestPackageWithManifest(t, uiTestManifest, map[string]string{
		"ui/app.js": `fetch("/api/v1/plugins"); import("./chunk.js"); export const from = "x";`,
	})
	staging := filepath.Join(t.TempDir(), "staging")
	if _, err := Extract(context.Background(), p.path, p.trustStore(t), staging); err != nil {
		t.Fatalf("Extract: %v", err)
	}
}
