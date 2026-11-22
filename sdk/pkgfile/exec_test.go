// SPDX-License-Identifier: Apache-2.0

package pkgfile

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestPackForcesEntrypointExec(t *testing.T) {
	f := newFixture(t)
	// A source tree from Windows: nothing carries the executable bit.
	if err := os.Chmod(filepath.Join(f.dir, "bin", "plugin"), 0o644); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if _, err := Pack(f.dir, &buf, PackOptions{SigningKey: f.priv}); err != nil {
		t.Fatalf("Pack: %v", err)
	}
	entries := rawEntries(t, buf.Bytes())
	if got := entries[findEntry(t, entries, "bin/plugin")].hdr.Mode; got != int64(ModeExec) {
		t.Fatalf("bin/plugin header mode = %o, want %o", got, ModeExec)
	}
}

// readWithMode rewrites one entry's header mode and reads the package.
func readWithMode(t *testing.T, name string, mode int64) *memSink {
	t.Helper()
	f := newFixture(t)
	entries := rawEntries(t, f.pkg)
	entries[findEntry(t, entries, name)].hdr.Mode = mode
	sink := newMemSink()
	if _, err := Read(bytes.NewReader(buildArchive(t, entries)), trust(t, f.pub), ReadOptions{Sink: sink}); err != nil {
		t.Fatalf("Read: %v", err)
	}
	return sink
}

func TestReadForcesEntrypointExec(t *testing.T) {
	if got := readWithMode(t, "bin/plugin", 0o644).modes["bin/plugin"]; got != ModeExec {
		t.Fatalf("entrypoint mode = %o, want %o", got, ModeExec)
	}
}

func TestReadDropsExecOutsideBin(t *testing.T) {
	if got := readWithMode(t, "ui/app.js", 0o755).modes["ui/app.js"]; got != ModeFile {
		t.Fatalf("ui/app.js mode = %o, want %o", got, ModeFile)
	}
}
