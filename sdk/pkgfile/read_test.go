// SPDX-License-Identifier: Apache-2.0

package pkgfile

import (
	"archive/tar"
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"sort"
	"strings"
	"testing"

	"github.com/qwq-panel/qwq/sdk/manifest"
)

// TestReadRoundTrip reads a canonical package and checks everything it hands
// over: manifest, signature, files, digests, modes and content.
func TestReadRoundTrip(t *testing.T) {
	f := newFixture(t)
	sink := newMemSink()
	pkg, err := Read(bytes.NewReader(f.pkg), trust(t, f.pub), ReadOptions{Sink: sink})
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if pkg.Manifest.ID != "test.plugin" || pkg.Manifest.Version != "1.2.3" {
		t.Errorf("manifest identity is %s@%s", pkg.Manifest.ID, pkg.Manifest.Version)
	}
	if pkg.Signature == nil || pkg.Signature.KeyID != manifest.KeyID(f.pub) {
		t.Errorf("signature is %+v, want key %s", pkg.Signature, manifest.KeyID(f.pub))
	}
	if !ed25519.Verify(f.pub, pkg.ManifestBytes, pkg.Signature.Sig) {
		t.Error("the reported signature does not verify over the reported manifest bytes")
	}
	if len(pkg.Files) != len(sourceFiles) {
		t.Fatalf("Read reported %d files, want %d", len(pkg.Files), len(sourceFiles))
	}
	var total int64
	for _, fi := range pkg.Files {
		content, ok := sourceFiles[fi.Path]
		if !ok {
			t.Errorf("unexpected file %s", fi.Path)
			continue
		}
		sum := sha256.Sum256([]byte(content))
		if fi.Size != int64(len(content)) {
			t.Errorf("%s: size %d, want %d", fi.Path, fi.Size, len(content))
		}
		if fi.Digest != digestString(sum[:]) {
			t.Errorf("%s: digest %s", fi.Path, fi.Digest)
		}
		total += fi.Size
	}
	if pkg.Size != total {
		t.Errorf("Package.Size = %d, want %d", pkg.Size, total)
	}
	if rawCount := len(rawEntries(t, f.pkg)); pkg.Entries != rawCount {
		t.Errorf("Package.Entries = %d, want %d", pkg.Entries, rawCount)
	}
	for name, content := range sourceFiles {
		if got := string(sink.files[name]); got != content {
			t.Errorf("%s: sink received %q, want %q", name, got, content)
		}
	}
	if sink.modes["bin/plugin"] != ModeExec {
		t.Errorf("bin/plugin mode is %o, want %o", sink.modes["bin/plugin"], ModeExec)
	}
	if sink.modes["ui/app.js"] != ModeFile {
		t.Errorf("ui/app.js mode is %o, want %o", sink.modes["ui/app.js"], ModeFile)
	}
	wantDirs := []string{"attestations", "bin", "schemas", "ui"}
	if got := append([]string(nil), sink.dirs...); len(got) != len(wantDirs) {
		t.Errorf("sink dirs = %v, want %v", got, wantDirs)
	} else {
		for i := range wantDirs {
			if got[i] != wantDirs[i] {
				t.Errorf("sink dirs = %v, want %v", got, wantDirs)
				break
			}
		}
	}
	if !sort.StringsAreSorted(sink.order) {
		t.Errorf("files arrived out of order: %v", sink.order)
	}
}

// TestReadUnsigned: ReadUnverified accepts an unsigned package and reports no
// signature.
func TestReadUnsigned(t *testing.T) {
	f := newFixture(t)
	var buf bytes.Buffer
	if _, err := Pack(f.dir, &buf, PackOptions{}); err != nil {
		t.Fatalf("Pack: %v", err)
	}
	pkg, err := ReadUnverified(bytes.NewReader(buf.Bytes()), ReadOptions{})
	if err != nil {
		t.Fatalf("ReadUnverified: %v", err)
	}
	if pkg.Signature != nil {
		t.Error("unsigned package reported a signature")
	}
	if len(pkg.Files) != len(sourceFiles) {
		t.Errorf("ReadUnverified reported %d files", len(pkg.Files))
	}
}

// TestReadRequiresTrustStore: an installer must not be able to skip
// verification by passing a nil store.
func TestReadRequiresTrustStore(t *testing.T) {
	f := newFixture(t)
	if _, err := Read(bytes.NewReader(f.pkg), nil, ReadOptions{}); err == nil {
		t.Fatal("Read accepted a nil trust store")
	}
}

// TestReadRejects mutates one valid package at a time and checks the code.
func TestReadRejects(t *testing.T) {
	f := newFixture(t)
	ts := trust(t, f.pub)
	base := rawEntries(t, f.pkg)

	clone := func() []rawEntry { return append([]rawEntry(nil), base...) }

	cases := []struct {
		name    string
		entries func() []rawEntry
		code    string
	}{
		{
			name: "tampered content",
			entries: func() []rawEntry {
				return replaceEntryData(clone(), "bin/plugin", []byte("#!/bin/sh\necho pwned\n"))
			},
			code: CodeDigestMismatch,
		},
		{
			name: "extra file",
			entries: func() []rawEntry {
				e := clone()
				return append(e, rawEntry{
					hdr:  tar.Header{Name: "ui/extra.js", Typeflag: tar.TypeReg, Mode: 0o644},
					data: []byte("alert(1)"),
				})
			},
			code: CodeFileUnlisted,
		},
		{
			name: "missing file",
			entries: func() []rawEntry {
				e := clone()
				i := findEntry(t, e, "ui/app.js")
				return append(e[:i], e[i+1:]...)
			},
			code: CodeFileMissing,
		},
		{
			name: "symlink entry",
			entries: func() []rawEntry {
				e := clone()
				i := findEntry(t, e, "ui/app.js")
				e[i].hdr.Typeflag = tar.TypeSymlink
				e[i].hdr.Linkname = "/etc/passwd"
				e[i].data = nil
				return e
			},
			code: CodeEntryType,
		},
		{
			name: "hard link entry",
			entries: func() []rawEntry {
				e := clone()
				i := findEntry(t, e, "ui/app.js")
				e[i].hdr.Typeflag = tar.TypeLink
				e[i].hdr.Linkname = "bin/plugin"
				e[i].data = nil
				return e
			},
			code: CodeEntryType,
		},
		{
			name: "character device entry",
			entries: func() []rawEntry {
				e := clone()
				i := findEntry(t, e, "ui/app.js")
				e[i].hdr.Typeflag = tar.TypeChar
				e[i].data = nil
				return e
			},
			code: CodeEntryType,
		},
		{
			name: "fifo entry",
			entries: func() []rawEntry {
				e := clone()
				i := findEntry(t, e, "ui/app.js")
				e[i].hdr.Typeflag = tar.TypeFifo
				e[i].data = nil
				return e
			},
			code: CodeEntryType,
		},
		{
			name: "traversal path",
			entries: func() []rawEntry {
				e := clone()
				e[findEntry(t, e, "ui/app.js")].hdr.Name = "ui/../../etc/passwd"
				return e
			},
			code: CodePathTraversal,
		},
		{
			name: "absolute path",
			entries: func() []rawEntry {
				e := clone()
				e[findEntry(t, e, "ui/app.js")].hdr.Name = "/etc/passwd"
				return e
			},
			code: CodePathAbsolute,
		},
		{
			name: "empty path component",
			entries: func() []rawEntry {
				e := clone()
				e[findEntry(t, e, "ui/app.js")].hdr.Name = "ui//app.js"
				return e
			},
			code: CodePathInvalid,
		},
		{
			name: "backslash in path",
			entries: func() []rawEntry {
				e := clone()
				e[findEntry(t, e, "ui/app.js")].hdr.Name = `ui\app.js`
				return e
			},
			code: CodePathInvalid,
		},
		{
			name: "control character in path",
			entries: func() []rawEntry {
				e := clone()
				e[findEntry(t, e, "ui/app.js")].hdr.Name = "ui/ap\x01p.js"
				return e
			},
			code: CodePathInvalid,
		},
		{
			name: "invalid UTF-8 name",
			entries: func() []rawEntry {
				e := clone()
				i := findEntry(t, e, "ui/app.js")
				e[i].hdr.Name = "ui/a\xff.js"
				e[i].hdr.Format = tar.FormatGNU
				return e
			},
			code: CodePathInvalidUTF8,
		},
		{
			name: "case-folded duplicate",
			entries: func() []rawEntry {
				e := clone()
				i := findEntry(t, e, "ui/app.js")
				dup := e[i]
				dup.hdr.Name = "UI/app.js"
				return append(e, dup)
			},
			code: CodePathDuplicate,
		},
		{
			name: "file shadowing a directory",
			entries: func() []rawEntry {
				e := clone()
				e = append(e, rawEntry{
					hdr:  tar.Header{Name: "ui", Typeflag: tar.TypeReg, Mode: 0o644},
					data: []byte("x"),
				})
				return e
			},
			code: CodePathConflict,
		},
		{
			name: "setuid mode",
			entries: func() []rawEntry {
				e := clone()
				e[findEntry(t, e, "bin/plugin")].hdr.Mode = 0o4755
				return e
			},
			code: CodeEntryMode,
		},
		{
			name: "manifest is not first",
			entries: func() []rawEntry {
				e := clone()
				moved := append(e[1:], e[0])
				return moved
			},
			code: CodeMissingManifest,
		},
		{
			name: "signature is not second",
			entries: func() []rawEntry {
				e := clone()
				first := e[2]
				out := []rawEntry{e[0], first, e[1]}
				return append(out, e[3:]...)
			},
			code: CodeMissingSignature,
		},
		{
			name: "duplicate manifest entry",
			entries: func() []rawEntry {
				e := clone()
				return append(e, e[0])
			},
			code: CodeEntryOrder,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			data := buildArchive(t, c.entries())
			_, err := Read(bytes.NewReader(data), ts, ReadOptions{})
			wantCode(t, err, c.code)
			// ReadUnverified must reach the same structural verdict.
			if c.code != CodeMissingSignature {
				if _, uerr := ReadUnverified(bytes.NewReader(data), ReadOptions{}); uerr == nil {
					t.Fatal("ReadUnverified accepted a broken package")
				}
			}
		})
	}
}

// TestReadCorrupt covers inputs that are not packages at all.
func TestReadCorrupt(t *testing.T) {
	f := newFixture(t)
	ts := trust(t, f.pub)
	cases := map[string][]byte{
		"empty":     {},
		"not gzip":  []byte("this is not a package\n"),
		"truncated": f.pkg[:len(f.pkg)/2],
	}
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := Read(bytes.NewReader(data), ts, ReadOptions{})
			wantCode(t, err, CodeCorrupt)
		})
	}
}

// TestReadSignatureErrors checks the trust decisions, which are the manifest
// package's codes because it owns the envelope format.
func TestReadSignatureErrors(t *testing.T) {
	f := newFixture(t)
	other := testKey(2)
	entries := rawEntries(t, f.pkg)

	t.Run("untrusted key", func(t *testing.T) {
		_, err := Read(bytes.NewReader(f.pkg), trust(t, other.Public().(ed25519.PublicKey)), ReadOptions{})
		wantManifestCode(t, err, manifest.CodeKeyUnknown)
	})
	t.Run("publisher binding", func(t *testing.T) {
		ts, terr := manifest.NewStaticTrustStore(manifest.TrustedKey{
			PublicKey: f.pub,
			Publisher: "someone-else",
		})
		if terr != nil {
			t.Fatal(terr)
		}
		_, err := Read(bytes.NewReader(f.pkg), ts, ReadOptions{})
		wantManifestCode(t, err, manifest.CodePublisherMismatch)
	})
	t.Run("tampered manifest", func(t *testing.T) {
		bad := clone2(entries)
		bad[0].data = bytes.Replace(bad[0].data, []byte(`"Test Plugin"`), []byte(`"Evil Plugin"`), 1)
		bad[0].hdr.Size = int64(len(bad[0].data))
		_, err := Read(bytes.NewReader(buildArchive(t, bad)), trust(t, f.pub), ReadOptions{})
		wantManifestCode(t, err, manifest.CodeSignatureInvalid)
	})
	t.Run("malformed envelope", func(t *testing.T) {
		bad := clone2(entries)
		bad[1].data = []byte(`{"key_id":"nope","signature":"x"}`)
		bad[1].hdr.Size = int64(len(bad[1].data))
		_, err := Read(bytes.NewReader(buildArchive(t, bad)), trust(t, f.pub), ReadOptions{})
		wantManifestCode(t, err, manifest.CodeSignatureMalformed)
	})
}

// TestReadLenientSignature 仅放宽只读预检的签名信封，安装读取仍严格拒绝。
func TestReadLenientSignature(t *testing.T) {
	f := newFixture(t)
	entries := clone2(rawEntries(t, f.pkg))
	entries[1].data = []byte(`{"key_id":"nope","signature":"x"}`)
	entries[1].hdr.Size = int64(len(entries[1].data))
	data := buildArchive(t, entries)

	_, err := ReadUnverified(bytes.NewReader(data), ReadOptions{})
	wantManifestCode(t, err, manifest.CodeSignatureMalformed)

	pkg, err := ReadUnverified(bytes.NewReader(data), ReadOptions{LenientSignature: true})
	if err != nil {
		t.Fatalf("lenient inspection: %v", err)
	}
	if pkg.Signature != nil || pkg.Manifest == nil || pkg.Manifest.ID != f.manifest.ID {
		t.Fatalf("lenient inspection lost safe manifest or accepted signature: %+v", pkg)
	}
	_, err = Read(bytes.NewReader(data), trust(t, f.pub), ReadOptions{LenientSignature: true})
	wantManifestCode(t, err, manifest.CodeSignatureMalformed)
}

// clone2 copies entries deeply enough for the signature tests.
func clone2(entries []rawEntry) []rawEntry {
	out := make([]rawEntry, len(entries))
	copy(out, entries)
	return out
}

// TestReadLimits checks every budget with a deliberately small value.
func TestReadLimits(t *testing.T) {
	f := newFixture(t)
	ts := trust(t, f.pub)
	cases := []struct {
		name   string
		limits Limits
		code   string
	}{
		{"compressed size", Limits{CompressedBytes: 64}, CodeTooLarge},
		{"entry count", Limits{Entries: 2}, CodeEntryLimit},
		{"file size", Limits{FileBytes: 4}, CodeFileTooLarge},
		{"total size", Limits{TotalBytes: 64}, CodeTotalTooLarge},
		{"path length", Limits{PathBytes: 4}, CodePathTooLong},
		{"path depth", Limits{PathDepth: 1}, CodePathTooDeep},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := Read(bytes.NewReader(f.pkg), ts, ReadOptions{Limits: c.limits})
			wantCode(t, err, c.code)
		})
	}
}

// TestReadCompressionBomb: a small package that expands enormously is
// rejected once it crosses the configured ratio, and the same package is
// accepted with the default limits.
func TestReadCompressionBomb(t *testing.T) {
	f := newFixtureWith(t, map[string]string{"ui/zeros.bin": strings.Repeat("\x00", 4<<20)})
	ts := trust(t, f.pub)
	if _, err := Read(bytes.NewReader(f.pkg), ts, ReadOptions{}); err != nil {
		t.Fatalf("default limits rejected an honest package: %v", err)
	}
	limits := Limits{RatioFloorBytes: 1 << 20, CompressionRatio: 10}
	_, err := Read(bytes.NewReader(f.pkg), ts, ReadOptions{Limits: limits})
	wantCode(t, err, CodeCompressionRatio)
}

// TestReadSinkFailure: an error from the sink aborts the read instead of
// leaving a half-written tree to be committed.
func TestReadSinkFailure(t *testing.T) {
	f := newFixture(t)
	sink := newMemSink()
	sink.failAt = "bin/plugin"
	_, err := Read(bytes.NewReader(f.pkg), trust(t, f.pub), ReadOptions{Sink: sink})
	if err == nil {
		t.Fatal("Read ignored a failing sink")
	}
	if !strings.Contains(err.Error(), "sink refuses") {
		t.Errorf("error does not mention the sink: %v", err)
	}
	var pe *Error
	if errors.As(err, &pe) {
		t.Errorf("a sink error is not a package violation: %v", err)
	}
}
