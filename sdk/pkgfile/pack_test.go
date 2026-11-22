// SPDX-License-Identifier: Apache-2.0

package pkgfile

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/qwq-panel/qwq/sdk/manifest"
)

// TestPackDeterministic pins the canonical form: the same source tree packs
// to the same bytes, independent of the directory it lives in and of map
// iteration order.
func TestPackDeterministic(t *testing.T) {
	f := newFixture(t)
	var again bytes.Buffer
	pkg, err := Pack(f.dir, &again, PackOptions{SigningKey: f.priv})
	if err != nil {
		t.Fatalf("Pack: %v", err)
	}
	if !bytes.Equal(f.pkg, again.Bytes()) {
		t.Fatalf("packing twice produced different bytes (%d vs %d)", len(f.pkg), again.Len())
	}

	// The same tree in another directory must produce the same package.
	other := t.TempDir()
	tree := map[string]string{ManifestPath: string(testManifest(manifest.KeyID(f.pub), "1.2.3"))}
	for k, v := range sourceFiles {
		tree[k] = v
	}
	writeTree(t, other, tree)
	var third bytes.Buffer
	if _, err := Pack(other, &third, PackOptions{SigningKey: f.priv}); err != nil {
		t.Fatalf("Pack other: %v", err)
	}
	if !bytes.Equal(f.pkg, third.Bytes()) {
		t.Fatal("the same tree in another directory packed differently")
	}
	if len(pkg.Files) != len(sourceFiles) {
		t.Fatalf("Pack reported %d files, want %d", len(pkg.Files), len(sourceFiles))
	}
}

// TestPackLayout pins the container: entry order, header fields, modes and
// the two fixed entries.
func TestPackLayout(t *testing.T) {
	f := newFixture(t)

	zr, err := gzip.NewReader(bytes.NewReader(f.pkg))
	if err != nil {
		t.Fatalf("gzip: %v", err)
	}
	if !zr.Header.ModTime.IsZero() {
		t.Errorf("gzip MTIME is %v, want the zero time", zr.Header.ModTime)
	}
	if zr.Header.Name != "" || zr.Header.Comment != "" {
		t.Errorf("gzip header carries a name or comment: %q %q", zr.Header.Name, zr.Header.Comment)
	}
	if zr.Header.OS != 255 {
		t.Errorf("gzip OS is %d, want 255 (unknown)", zr.Header.OS)
	}

	entries := rawEntries(t, f.pkg)
	if got := entries[0].hdr.Name; got != ManifestPath {
		t.Fatalf("first entry is %q, want %q", got, ManifestPath)
	}
	if got := entries[1].hdr.Name; got != SignaturePath {
		t.Fatalf("second entry is %q, want %q", got, SignaturePath)
	}
	if names := sortedNames(entries); !strictlySorted(names) {
		t.Fatalf("entries are not sorted by name: %v", names)
	}
	for _, e := range entries {
		h := e.hdr
		if h.ModTime.Unix() != 0 || h.ModTime.Nanosecond() != 0 {
			t.Errorf("%s: ModTime %v, want the epoch", h.Name, h.ModTime)
		}
		if h.Uid != 0 || h.Gid != 0 || h.Uname != "" || h.Gname != "" {
			t.Errorf("%s: owner %d:%d (%q/%q), want 0:0 with empty names", h.Name, h.Uid, h.Gid, h.Uname, h.Gname)
		}
		if h.Format != tar.FormatUSTAR {
			t.Errorf("%s: format %v, want USTAR", h.Name, h.Format)
		}
		switch h.Typeflag {
		case tar.TypeDir:
			if h.Mode != 0o755 {
				t.Errorf("%s: directory mode %o, want 0755", h.Name, h.Mode)
			}
		case tar.TypeReg:
			want := int64(0o644)
			if h.Name == "bin/plugin" {
				want = 0o755
			}
			if h.Mode != want {
				t.Errorf("%s: mode %o, want %o", h.Name, h.Mode, want)
			}
		default:
			t.Errorf("%s: type %v is not allowed in a canonical package", h.Name, h.Typeflag)
		}
	}

	// The manifest lists exactly the packed files, with their digests.
	m, err := manifest.Parse(entries[0].data)
	if err != nil {
		t.Fatalf("manifest inside the package does not parse: %v", err)
	}
	if len(m.Files) != len(sourceFiles) {
		t.Fatalf("manifest lists %d files, want %d", len(m.Files), len(sourceFiles))
	}
	for name, content := range sourceFiles {
		sum := sha256.Sum256([]byte(content))
		want := digestString(sum[:])
		got, ok := m.Files[name]
		if !ok {
			t.Errorf("manifest.files is missing %s", name)
			continue
		}
		if got != want {
			t.Errorf("manifest.files[%s] = %s, want %s", name, got, want)
		}
	}
	for _, name := range []string{ManifestPath, SignaturePath, "signatures"} {
		if _, ok := m.Files[name]; ok {
			t.Errorf("manifest.files must not list %s", name)
		}
	}

	// No signatures/ directory entry: the signature is the only member.
	for _, e := range entries {
		if e.hdr.Name == "signatures" ||
			(strings.HasPrefix(e.hdr.Name, "signatures/") && e.hdr.Name != SignaturePath) {
			t.Errorf("unexpected signatures entry %q", e.hdr.Name)
		}
	}
}

// strictlySorted reports whether names are strictly increasing.
func strictlySorted(names []string) bool {
	for i := 1; i < len(names); i++ {
		if names[i-1] >= names[i] {
			return false
		}
	}
	return true
}

// TestPackPreservesManifest checks that Pack only replaces files: every other
// value survives the rewrite, and numbers stay integers.
func TestPackPreservesManifest(t *testing.T) {
	f := newFixture(t)
	m := f.manifest
	if m.Name != "Test Plugin" || m.Summary != "Package format test fixture." {
		t.Errorf("identity changed: %+v", m)
	}
	if m.Resources.MemoryMaxMB != 32 || m.Resources.PIDsMax != 16 {
		t.Errorf("resources changed: %+v", m.Resources)
	}
	if m.ABI.Major != 1 || m.ABI.MinimumMinor != 0 {
		t.Errorf("abi changed: %+v", m.ABI)
	}
	if m.Publisher.KeyID != manifest.KeyID(f.pub) {
		t.Errorf("publisher.key_id = %s, want %s", m.Publisher.KeyID, manifest.KeyID(f.pub))
	}
	if m.Entrypoint != "bin/plugin" {
		t.Errorf("entrypoint = %q", m.Entrypoint)
	}
	raw := string(rawEntries(t, f.pkg)[0].data)
	for _, want := range []string{`"memory_max_mb": 32`, `"disk_max_mb": 64`, `"minimum_minor": 0`} {
		if !strings.Contains(raw, want) {
			t.Errorf("packed manifest lost the original number encoding %q", want)
		}
	}
	if !strings.Contains(raw, "\n  \"id\": \"test.plugin\"") {
		t.Error("packed manifest is not two-space indented")
	}
}

// TestPackUnsigned checks the optional signature.
func TestPackUnsigned(t *testing.T) {
	f := newFixture(t)
	var buf bytes.Buffer
	pkg, err := Pack(f.dir, &buf, PackOptions{})
	if err != nil {
		t.Fatalf("Pack: %v", err)
	}
	if pkg.Signature != nil {
		t.Error("unsigned pack returned a signature")
	}
	entries := rawEntries(t, buf.Bytes())
	if len(entries) < 2 || entries[1].hdr.Name == SignaturePath {
		t.Fatal("unsigned package carries a signature entry")
	}
	if _, err := Read(bytes.NewReader(buf.Bytes()), trust(t, f.pub), ReadOptions{}); err == nil {
		t.Fatal("a signed read accepted an unsigned package")
	} else {
		wantCode(t, err, CodeMissingSignature)
	}
}

// TestPackRejects covers source trees the package format cannot represent.
func TestPackRejects(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(t *testing.T, dir string, man []byte) []byte
		code   string
	}{
		{
			name: "symlink",
			mutate: func(t *testing.T, dir string, man []byte) []byte {
				if err := os.Symlink("index.html", filepath.Join(dir, "ui", "link.html")); err != nil {
					t.Skipf("symlinks unavailable: %v", err)
				}
				return man
			},
			code: CodeSourceInvalid,
		},
		{
			name: "path too deep",
			mutate: func(t *testing.T, dir string, man []byte) []byte {
				deep := "ui"
				for i := 0; i < 20; i++ {
					deep += "/d"
				}
				writeTree(t, dir, map[string]string{deep + "/x.js": "x"})
				return man
			},
			code: CodePathTooDeep,
		},
		{
			name: "path too long",
			mutate: func(t *testing.T, dir string, man []byte) []byte {
				long := "ui"
				for i := 0; i < 5; i++ {
					long += "/" + strings.Repeat("a", 60)
				}
				writeTree(t, dir, map[string]string{long + "/x.js": "x"})
				return man
			},
			code: CodePathTooLong,
		},
		{
			name: "stray signature file",
			mutate: func(t *testing.T, dir string, man []byte) []byte {
				writeTree(t, dir, map[string]string{"signatures/extra.sig": "nope"})
				return man
			},
			code: CodePathConflict,
		},
		{
			name: "reserved name case variant",
			mutate: func(t *testing.T, dir string, man []byte) []byte {
				writeTree(t, dir, map[string]string{"Manifest.json": "nope"})
				return man
			},
			code: CodePathConflict,
		},
		{
			name: "missing referenced file",
			mutate: func(t *testing.T, dir string, man []byte) []byte {
				if err := os.Remove(filepath.Join(dir, "attestations", "sbom.spdx.json")); err != nil {
					t.Fatal(err)
				}
				return man
			},
			code: "", // reported as a manifest violation
		},
		{
			name: "duplicate manifest key",
			mutate: func(t *testing.T, dir string, man []byte) []byte {
				return []byte(`{"id":"a","id":"b","schema_version":"1.0"}`)
			},
			code: CodeManifestInvalid,
		},
		{
			name: "manifest is not an object",
			mutate: func(t *testing.T, dir string, man []byte) []byte {
				return []byte(`[1,2,3]`)
			},
			code: CodeManifestInvalid,
		},
		{
			name: "manifest is not valid JSON",
			mutate: func(t *testing.T, dir string, man []byte) []byte {
				return []byte(`{"id":`)
			},
			code: CodeManifestInvalid,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			priv := testKey(1)
			pub := priv.Public().(ed25519.PublicKey)
			man := testManifest(manifest.KeyID(pub), "1.2.3")
			dir := t.TempDir()
			tree := map[string]string{ManifestPath: string(man)}
			for k, v := range sourceFiles {
				tree[k] = v
			}
			writeTree(t, dir, tree)
			if replaced := c.mutate(t, dir, man); !bytes.Equal(replaced, man) {
				if err := os.WriteFile(filepath.Join(dir, ManifestPath), replaced, 0o644); err != nil {
					t.Fatal(err)
				}
			}
			var buf bytes.Buffer
			if _, err := Pack(dir, &buf, PackOptions{SigningKey: priv}); err == nil {
				t.Fatalf("Pack accepted %s", c.name)
			} else if c.code != "" {
				wantCode(t, err, c.code)
			} else {
				wantManifestCode(t, err, manifest.CodeFileNotListed)
			}
		})
	}
}

// TestPackPublisherMismatch: the manifest must name the signing key, because
// the host checks that immediately after verification.
func TestPackPublisherMismatch(t *testing.T) {
	dir := t.TempDir()
	other := testKey(2)
	tree := map[string]string{ManifestPath: string(testManifest(manifest.KeyID(other.Public().(ed25519.PublicKey)), "1.2.3"))}
	for k, v := range sourceFiles {
		tree[k] = v
	}
	writeTree(t, dir, tree)
	var buf bytes.Buffer
	_, err := Pack(dir, &buf, PackOptions{SigningKey: testKey(1)})
	wantCode(t, err, CodePublisherMismatch)
}

// TestPackNoManifest: a tree without manifest.json is not a package.
func TestPackNoManifest(t *testing.T) {
	dir := t.TempDir()
	writeTree(t, dir, map[string]string{"bin/plugin": "x"})
	var buf bytes.Buffer
	_, err := Pack(dir, &buf, PackOptions{})
	wantCode(t, err, CodeSourceInvalid)
}

// TestPackNotADirectory covers the obvious misuse.
func TestPackNotADirectory(t *testing.T) {
	f := newFixture(t)
	var buf bytes.Buffer
	_, err := Pack(filepath.Join(f.dir, "bin", "plugin"), &buf, PackOptions{})
	if err == nil {
		t.Fatal("Pack accepted a file as a source tree")
	}
	var e *Error
	if errors.As(err, &e) {
		t.Fatalf("want a plain error for a non-directory, got %v", err)
	}
}
