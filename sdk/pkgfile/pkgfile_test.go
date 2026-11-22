// SPDX-License-Identifier: Apache-2.0

package pkgfile

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/qwq-panel/qwq/sdk/manifest"
)

// testKey returns a deterministic Ed25519 key so a failing test is
// reproducible without any key material in the repository.
func testKey(n byte) ed25519.PrivateKey {
	seed := sha256.Sum256([]byte{'p', 'k', 'g', 'f', 'i', 'l', 'e', n})
	return ed25519.NewKeyFromSeed(seed[:])
}

// testManifest returns a schema-valid manifest for keyID and version. Pack
// replaces files, so the placeholder below is only a placeholder; a test that
// feeds the manifest to Read must keep the map Pack computed.
func testManifest(keyID, version string) []byte {
	return []byte(`{
  "schema_version": "1.0",
  "id": "test.plugin",
  "version": "` + version + `",
  "name": "Test Plugin",
  "summary": "Package format test fixture.",
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
`)
}

// sourceFiles is the tree every fixture is packed from.
var sourceFiles = map[string]string{
	"bin/plugin":                  "#!/bin/sh\necho test plugin\n",
	"schemas/config.schema.json":  `{"type":"object","properties":{}}`,
	"attestations/sbom.spdx.json": `{"spdxVersion":"SPDX-2.3"}`,
	"ui/index.html":               "<!doctype html><title>test</title>",
	"ui/app.js":                   "console.log('hi');\n",
}

// writeTree writes files below dir, creating parents. Every file is 0644
// except bin/plugin, which is 0755 so the executable bit is exercised.
func writeTree(t testing.TB, dir string, files map[string]string) {
	t.Helper()
	for name, content := range files {
		p := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", p, err)
		}
		mode := fs.FileMode(0o644)
		if name == "bin/plugin" {
			mode = 0o755
		}
		if err := os.WriteFile(p, []byte(content), mode); err != nil {
			t.Fatalf("write %s: %v", p, err)
		}
		if err := os.Chmod(p, mode); err != nil { // defeat the umask
			t.Fatalf("chmod %s: %v", p, err)
		}
	}
}

// fixture is a signed package plus the source tree it came from.
type fixture struct {
	priv     ed25519.PrivateKey
	pub      ed25519.PublicKey
	dir      string
	pkg      []byte
	manifest *manifest.Manifest
}

// newFixture packs sourceFiles with testManifest and returns the package.
func newFixture(t testing.TB) *fixture {
	t.Helper()
	return newFixtureWith(t, nil)
}

// newFixtureWith packs sourceFiles plus extra (which may add or override
// files) and returns the package.
func newFixtureWith(t testing.TB, extra map[string]string) *fixture {
	t.Helper()
	priv := testKey(1)
	pub := priv.Public().(ed25519.PublicKey)
	dir := t.TempDir()
	tree := make(map[string]string, len(sourceFiles)+len(extra)+1)
	for k, v := range sourceFiles {
		tree[k] = v
	}
	for k, v := range extra {
		tree[k] = v
	}
	tree[ManifestPath] = string(testManifest(manifest.KeyID(pub), "1.2.3"))
	writeTree(t, dir, tree)
	var buf bytes.Buffer
	pkg, err := Pack(dir, &buf, PackOptions{SigningKey: priv})
	if err != nil {
		t.Fatalf("Pack: %v", err)
	}
	return &fixture{priv: priv, pub: pub, dir: dir, pkg: buf.Bytes(), manifest: pkg.Manifest}
}

// trust builds a static trust store for the given keys.
func trust(t testing.TB, keys ...ed25519.PublicKey) manifest.TrustStore {
	t.Helper()
	tk := make([]manifest.TrustedKey, len(keys))
	for i, k := range keys {
		tk[i] = manifest.TrustedKey{PublicKey: k}
	}
	s, err := manifest.NewStaticTrustStore(tk...)
	if err != nil {
		t.Fatalf("trust store: %v", err)
	}
	return s
}

// rawEntry is one tar entry of a package, kept whole so a test can change it
// and rebuild an archive that is byte-for-byte plausible.
type rawEntry struct {
	hdr  tar.Header
	data []byte
}

// rawEntries decodes a package into its entries.
func rawEntries(t testing.TB, pkg []byte) []rawEntry {
	t.Helper()
	zr, err := gzip.NewReader(bytes.NewReader(pkg))
	if err != nil {
		t.Fatalf("gzip: %v", err)
	}
	tr := tar.NewReader(zr)
	var out []rawEntry
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("tar: %v", err)
		}
		data, err := io.ReadAll(tr)
		if err != nil {
			t.Fatalf("read entry: %v", err)
		}
		out = append(out, rawEntry{hdr: *hdr, data: data})
	}
	return out
}

// buildArchive writes entries as a plain tar+gzip archive, without any of the
// canonical rules Pack applies.
func buildArchive(t testing.TB, entries []rawEntry) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(zw)
	for _, e := range entries {
		h := e.hdr
		reg := regular(&h)
		if reg {
			h.Size = int64(len(e.data))
		} else {
			h.Size = 0
		}
		if err := tw.WriteHeader(&h); err != nil {
			t.Fatalf("write header %q: %v", h.Name, err)
		}
		if reg {
			if _, err := tw.Write(e.data); err != nil {
				t.Fatalf("write data %q: %v", h.Name, err)
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

// findEntry returns the index of the entry with the given name.
func findEntry(t testing.TB, entries []rawEntry, name string) int {
	t.Helper()
	for i := range entries {
		if entries[i].hdr.Name == name {
			return i
		}
	}
	t.Fatalf("entry %q not found", name)
	return -1
}

// replaceEntryData returns entries with the data of name replaced.
func replaceEntryData(entries []rawEntry, name string, data []byte) []rawEntry {
	out := append([]rawEntry(nil), entries...)
	i := -1
	for j := range out {
		if out[j].hdr.Name == name {
			i = j
			break
		}
	}
	out[i].data = data
	out[i].hdr.Size = int64(len(data))
	return out
}

// hasCode reports whether err is a pkgfile Error with the given code.
func hasCode(err error, code string) bool {
	var e *Error
	return errors.As(err, &e) && e.Has(code)
}

// wantCode fails unless err is a pkgfile Error carrying code.
func wantCode(t testing.TB, err error, code string) {
	t.Helper()
	if err == nil {
		t.Fatalf("want %s, got no error", code)
	}
	if !hasCode(err, code) {
		t.Fatalf("want code %s, got %T: %v", code, err, err)
	}
}

// wantManifestCode fails unless err is a manifest Error carrying code.
func wantManifestCode(t testing.TB, err error, code string) {
	t.Helper()
	if err == nil {
		t.Fatalf("want manifest code %s, got no error", code)
	}
	var e *manifest.Error
	if !errors.As(err, &e) {
		t.Fatalf("want *manifest.Error with %s, got %T: %v", code, err, err)
	}
	if !e.Has(code) {
		t.Fatalf("want manifest code %s, got %v", code, err)
	}
}

// memSink collects what Read hands over.
type memSink struct {
	dirs  []string
	files map[string][]byte
	modes map[string]fs.FileMode
	order []string
	// failAt, when set, makes CreateFile fail for that path.
	failAt string
}

func newMemSink() *memSink {
	return &memSink{files: map[string][]byte{}, modes: map[string]fs.FileMode{}}
}

func (s *memSink) CreateDir(path string) error {
	s.dirs = append(s.dirs, path)
	return nil
}

func (s *memSink) CreateFile(path string, size int64, mode fs.FileMode) (io.WriteCloser, error) {
	if s.failAt != "" && path == s.failAt {
		return nil, errors.New("sink refuses " + path)
	}
	s.order = append(s.order, path)
	s.modes[path] = mode
	return &memFile{sink: s, path: path}, nil
}

type memFile struct {
	sink *memSink
	path string
	buf  bytes.Buffer
}

func (f *memFile) Write(p []byte) (int, error) { return f.buf.Write(p) }

func (f *memFile) Close() error {
	f.sink.files[f.path] = f.buf.Bytes()
	return nil
}

// sortedNames returns the names of entries sorted byte-wise.
func sortedNames(entries []rawEntry) []string {
	names := make([]string, len(entries))
	for i := range entries {
		names[i] = entries[i].hdr.Name
	}
	sort.Strings(names)
	return names
}
