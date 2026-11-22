// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// cliResult is one qwqctl invocation.
type cliResult struct {
	code int
	out  string
	err  string
}

// cli runs qwqctl with the given arguments.
func cli(t *testing.T, args ...string) cliResult {
	t.Helper()
	var out, errb bytes.Buffer
	code := run(args, &out, &errb)
	return cliResult{code: code, out: out.String(), err: errb.String()}
}

// mustOK fails the test unless the command succeeded.
func mustOK(t *testing.T, args ...string) cliResult {
	t.Helper()
	res := cli(t, args...)
	if res.code != 0 {
		t.Fatalf("qwqctl %v exited %d\nstdout:\n%s\nstderr:\n%s", args, res.code, res.out, res.err)
	}
	return res
}

// keyIDFrom parses the key id keygen printed.
func keyIDFrom(t *testing.T, out string) string {
	t.Helper()
	for _, line := range strings.Split(out, "\n") {
		if rest, ok := strings.CutPrefix(line, "key_id:"); ok {
			id := strings.TrimSpace(rest)
			if !strings.HasPrefix(id, "ed25519:") {
				t.Fatalf("keygen printed a malformed key id %q", id)
			}
			return id
		}
	}
	t.Fatalf("keygen printed no key id:\n%s", out)
	return ""
}

// testManifest is a schema-valid manifest for one signing key.
func testManifest(keyID string) string {
	return `{
  "schema_version": "1.2",
  "id": "test.plugin",
  "version": "1.2.3",
  "name": "Test Plugin",
  "summary": "CLI test fixture.",
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

// writeSource writes the tree qwqctl packs.
func writeSource(t *testing.T, dir, keyID string) {
	t.Helper()
	files := map[string]string{
		"manifest.json":               testManifest(keyID),
		"bin/plugin":                  "#!/bin/sh\necho test plugin\n",
		"schemas/config.schema.json":  `{"type":"object"}`,
		"attestations/sbom.spdx.json": `{"spdxVersion":"SPDX-2.3"}`,
		"ui/index.html":               "<!doctype html><title>test</title>",
	}
	for name, content := range files {
		p := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		mode := os.FileMode(0o644)
		if name == "bin/plugin" {
			mode = 0o755
		}
		if err := os.WriteFile(p, []byte(content), mode); err != nil {
			t.Fatal(err)
		}
	}
}

// TestKeygenPackVerify is the end-to-end path: generate a key pair, pack a
// signed package, verify it.
func TestKeygenPackVerify(t *testing.T) {
	dir := t.TempDir()
	prefix := filepath.Join(dir, "signing")
	res := mustOK(t, "keygen", "-out", prefix)
	keyID := keyIDFrom(t, res.out)
	for _, name := range []string{prefix + ".key", prefix + ".pub"} {
		info, err := os.Stat(name)
		if err != nil {
			t.Fatalf("keygen did not create %s: %v", name, err)
		}
		want := os.FileMode(0o644)
		if strings.HasSuffix(name, ".key") {
			want = 0o600
		}
		if got := info.Mode().Perm(); got != want {
			t.Errorf("%s mode is %o, want %o", name, got, want)
		}
	}

	src := filepath.Join(dir, "src")
	writeSource(t, src, keyID)
	pkgPath := filepath.Join(dir, "test.plugin_1.2.3_linux-amd64.ppkg")
	packed := mustOK(t, "pack", "-src", src, "-out", pkgPath, "-key", prefix+".key")
	for _, want := range []string{"id:         test.plugin", "version:    1.2.3", "signed by:  " + keyID, "files:      4"} {
		if !strings.Contains(packed.out, want) {
			t.Errorf("pack output is missing %q:\n%s", want, packed.out)
		}
	}
	if _, err := os.Stat(pkgPath); err != nil {
		t.Fatalf("pack did not write the package: %v", err)
	}

	verified := mustOK(t, "verify", "-trust", prefix+".pub", "-files", pkgPath)
	for _, want := range []string{"result:     OK", "signed by:  " + keyID, "bin/plugin", "ui/index.html"} {
		if !strings.Contains(verified.out, want) {
			t.Errorf("verify output is missing %q:\n%s", want, verified.out)
		}
	}

	// A second key does not trust the package.
	otherPrefix := filepath.Join(dir, "other")
	mustOK(t, "keygen", "-out", otherPrefix)
	res = cli(t, "verify", "-trust", otherPrefix+".pub", pkgPath)
	if res.code != 1 {
		t.Fatalf("verify with an untrusted key exited %d, want 1", res.code)
	}
	if !strings.Contains(res.err, "KEY_UNKNOWN") {
		t.Errorf("verify stderr does not name the unknown key: %s", res.err)
	}

	// Multiple -trust flags are accepted.
	mustOK(t, "verify", "-trust", otherPrefix+".pub", "-trust", prefix+".pub", pkgPath)

	// An unsigned package cannot be verified, but can be signed.
	unsigned := filepath.Join(dir, "unsigned.ppkg")
	mustOK(t, "pack", "-src", src, "-out", unsigned)
	if res := cli(t, "verify", "-trust", prefix+".pub", unsigned); res.code != 1 {
		t.Fatalf("verify accepted an unsigned package (%d)", res.code)
	}
	mustOK(t, "sign", "-key", prefix+".key", unsigned)
	mustOK(t, "verify", "-trust", prefix+".pub", unsigned)

	// Tampering with the archive is detected.
	raw, err := os.ReadFile(pkgPath)
	if err != nil {
		t.Fatal(err)
	}
	raw[len(raw)/2] ^= 0xff
	if err := os.WriteFile(pkgPath, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	if res := cli(t, "verify", "-trust", prefix+".pub", pkgPath); res.code != 1 {
		t.Fatalf("verify accepted a corrupted package (%d)\n%s", res.code, res.out)
	}
}

// TestSignInPlace: without -out, sign rewrites the package it was given.
func TestSignInPlace(t *testing.T) {
	dir := t.TempDir()
	prefix := filepath.Join(dir, "signing")
	keyID := keyIDFrom(t, mustOK(t, "keygen", "-out", prefix).out)
	src := filepath.Join(dir, "src")
	writeSource(t, src, keyID)
	pkgPath := filepath.Join(dir, "pkg.ppkg")
	mustOK(t, "pack", "-src", src, "-out", pkgPath, "-key", prefix+".key")
	before, err := os.ReadFile(pkgPath)
	if err != nil {
		t.Fatal(err)
	}
	mustOK(t, "sign", "-key", prefix+".key", pkgPath)
	after, err := os.ReadFile(pkgPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Error("signing an already signed package changed it")
	}
}

// TestKeygenRefusesOverwrite: a signing key is never replaced silently.
func TestKeygenRefusesOverwrite(t *testing.T) {
	prefix := filepath.Join(t.TempDir(), "signing")
	mustOK(t, "keygen", "-out", prefix)
	res := cli(t, "keygen", "-out", prefix)
	if res.code != 1 {
		t.Fatalf("second keygen exited %d, want 1", res.code)
	}
	if !strings.Contains(res.err, "exist") {
		t.Errorf("second keygen does not explain the refusal: %s", res.err)
	}
}

// TestPackRejectsBadManifest: a manifest problem is reported, not packaged.
func TestPackRejectsBadManifest(t *testing.T) {
	dir := t.TempDir()
	prefix := filepath.Join(dir, "signing")
	keyID := keyIDFrom(t, mustOK(t, "keygen", "-out", prefix).out)
	src := filepath.Join(dir, "src")
	writeSource(t, src, keyID)
	if err := os.WriteFile(filepath.Join(src, "manifest.json"), []byte(`{"id":`), 0o644); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "pkg.ppkg")
	res := cli(t, "pack", "-src", src, "-out", out, "-key", prefix+".key")
	if res.code != 1 {
		t.Fatalf("pack of a broken manifest exited %d, want 1", res.code)
	}
	if !strings.Contains(res.err, "PKG_MANIFEST_INVALID") {
		t.Errorf("pack stderr does not name the code: %s", res.err)
	}
	if _, err := os.Stat(out); !os.IsNotExist(err) {
		t.Error("pack left a package behind after a failure")
	}
}

// TestUsageErrors: missing arguments and bad flags exit 2.
func TestUsageErrors(t *testing.T) {
	dir := t.TempDir()
	pkgPath := filepath.Join(dir, "pkg.ppkg")
	cases := [][]string{
		{"pack"},
		{"pack", "-src", dir},
		{"sign", pkgPath},
		{"verify", pkgPath},
		{"verify", "-trust"},
		{"keygen"},
		{"keygen", "-bogus"},
		{"pack", "-bogus"},
		{"verify", "-h"},
	}
	for _, args := range cases {
		if res := cli(t, args...); res.code != 2 {
			t.Errorf("qwqctl %v exited %d, want 2", args, res.code)
		}
	}
}
