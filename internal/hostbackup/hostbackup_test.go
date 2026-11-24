// SPDX-License-Identifier: AGPL-3.0-only

package hostbackup

import (
	"archive/tar"
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/qwq-panel/qwq/internal/storage"
)

func TestRedactSupportLogLinePrefixEntryAndSubToken(t *testing.T) {
	pemMarker := "-----BEGIN " + "PRIVATE KEY-----"
	lines := strings.Join([]string{
		`2026-11-24T00:00:00Z host qwq[1]: Authorization: Bearer eyJ-PREFIX-SECRET {"level":"INFO","msg":"req","path":"/secretgate99/api/v1/system","webhook_url":"https://hooks.example/abc","master_key":"mk-123","public_key":"pk-keep","idempotency_key":"idk-keep","sub":"/p/proxy.advanced/sub/tok_999_xyz"}`,
		`2026-11-24T00:00:01Z host qwq[1]: GET /secretgate99/login X-Api-Key: sk-plain-777 sub=/p/proxy.advanced/sub/plain_tok_42 entry_path=secretgate99`,
		`2026-11-24T00:00:02Z host qwq[1]: {"private_pem":"` + pemMarker + `","user":"admin"}`,
	}, "\n") + "\n"

	got := RedactLog(lines, "secretgate99")
	for _, secret := range []string{
		"eyJ-PREFIX-SECRET",
		"/secretgate99/",
		"hooks.example/abc",
		"mk-123",
		"tok_999_xyz",
		"sk-plain-777",
		"plain_tok_42",
		"BEGIN " + "PRIVATE KEY",
	} {
		if strings.Contains(got, secret) {
			t.Fatalf("RedactLog leaked secret %q in:\n%s", secret, got)
		}
	}
	for _, keep := range []string{`"public_key":"pk-keep"`, `"idempotency_key":"idk-keep"`, `"user":"admin"`, "/[REDACTED_ENTRY]/"} {
		if !strings.Contains(got, keep) {
			t.Fatalf("RedactLog lost expected content %q in:\n%s", keep, got)
		}
	}
}

func TestCreateAndListBackupsIncludesAgentDirs(t *testing.T) {
	dataDir := t.TempDir()
	db, err := storage.Open(t.Context(), storage.Options{Path: filepath.Join(dataDir, BackupDBName)})
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	_ = db.Close()
	for _, rel := range []string{
		"keys/master.key",
		"agent-workspace/skills/demo.md",
		"agent-homes/codex/config.json",
	} {
		full := filepath.Join(dataDir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(full), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte("test-data"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	outDir := filepath.Join(dataDir, "backups")
	entry, archivePath, err := CreateBackup(t.Context(), CreateOptions{
		DataDir:   dataDir,
		RawConfig: []byte(`{"role":"standalone","data_dir":"` + filepath.ToSlash(dataDir) + `"}`),
		OutDir:    outDir,
		Now:       time.Date(2026, 11, 24, 12, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatalf("CreateBackup: %v", err)
	}
	if !IsValidBackupFilename(entry.Filename) {
		t.Fatalf("unexpected backup filename %q", entry.Filename)
	}
	listed, err := ListBackups(outDir)
	if err != nil || len(listed) != 1 || listed[0].Filename != entry.Filename {
		t.Fatalf("ListBackups = %+v, err=%v", listed, err)
	}

	f, err := os.Open(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	seen := map[string]bool{}
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		seen[hdr.Name] = true
	}
	for _, want := range []string{
		"data/qwq.db",
		"data/keys/master.key",
		"data/agent-workspace/skills/demo.md",
		"data/agent-homes/codex/config.json",
		"config/qwq.json",
		"manifest.json",
	} {
		if !seen[want] {
			t.Fatalf("archive missing %s (have %v)", want, seen)
		}
	}
}
