// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/qwq-panel/qwq/internal/doctor"
)

func TestSupportBundleRedacts(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "qwq.json")
	if err := os.WriteFile(cfgPath, []byte(`{"http":{"listen":"127.0.0.1:8443","tls":{"mode":"acme","domains":["panel.example.com"],"email":"ops@example.com"}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	unit := filepath.Join(dir, "qwq-controller.service")
	if err := os.WriteFile(unit, []byte("[Service]\nUser=qwq\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	journal := strings.Join([]string{
		`2026-11-09T10:00:00+0000 host qwq[1]: {"level":"INFO","msg":"login","session_token":"tok-SECRET-1","user":"admin"}`,
		`2026-11-09T10:00:01+0000 host qwq[1]: level=WARN msg=retry password=hunter2 api_key="key SECRET 2" peer=127.0.0.1`,
		`2026-11-09T10:00:02+0000 host qwq[1]: setup link https://127.0.0.1:8443/setup#token=SECRET-3`,
	}, "\n") + "\n"

	var buf bytes.Buffer
	err := writeSupportBundle(context.Background(), &buf, bundleSources{
		Doctor:     func(context.Context) []doctor.Result { return []doctor.Result{{ID: "config", Status: doctor.OK}} },
		Journal:    func(context.Context) (string, error) { return journal, nil },
		ConfigPath: cfgPath,
		UnitGlobs:  []string{filepath.Join(dir, "qwq-*.service")},
	})
	if err != nil {
		t.Fatal(err)
	}
	files := readBundle(t, &buf)
	for _, name := range []string{"doctor.json", "journal.txt", "qwq.json", "buildinfo.txt", "units/" + strings.TrimPrefix(unit, "/")} {
		if _, ok := files[name]; !ok {
			t.Errorf("bundle lacks %s (has %v)", name, keys(files))
		}
	}
	all := strings.Join(values(files), "\n")
	for _, secret := range []string{"tok-SECRET-1", "hunter2", "SECRET 2", "SECRET-3", "ops@example.com"} {
		if strings.Contains(all, secret) {
			t.Errorf("bundle leaks %q", secret)
		}
	}
	for _, kept := range []string{`"user":"admin"`, "peer=127.0.0.1", "panel.example.com", "User=qwq"} {
		if !strings.Contains(all, kept) {
			t.Errorf("bundle lost the non-secret %q", kept)
		}
	}
}

func readBundle(t *testing.T, r io.Reader) map[string]string {
	t.Helper()
	gz, err := gzip.NewReader(r)
	if err != nil {
		t.Fatal(err)
	}
	tr := tar.NewReader(gz)
	files := map[string]string{}
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return files
		}
		if err != nil {
			t.Fatal(err)
		}
		if h.Mode != 0o600 {
			t.Errorf("%s mode %#o, want 0600", h.Name, h.Mode)
		}
		b, err := io.ReadAll(tr)
		if err != nil {
			t.Fatal(err)
		}
		files[h.Name] = string(b)
	}
}

func keys(m map[string]string) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}

func values(m map[string]string) []string {
	var out []string
	for _, v := range m {
		out = append(out, v)
	}
	return out
}
