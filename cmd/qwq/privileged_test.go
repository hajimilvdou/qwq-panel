// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/qwq-panel/qwq/internal/sandbox"
	"github.com/qwq-panel/qwq/sdk/pkgfile"
)

// asRoot makes privilegedEUID report 0 for the duration of the test.
func asRoot(t *testing.T) {
	t.Helper()
	old := privilegedEUID
	privilegedEUID = func() int { return 0 }
	t.Cleanup(func() { privilegedEUID = old })
}

// asUnprivileged makes privilegedEUID report a normal user.
func asUnprivileged(t *testing.T) {
	t.Helper()
	old := privilegedEUID
	privilegedEUID = func() int { return 1000 }
	t.Cleanup(func() { privilegedEUID = old })
}

// runPrivilegedForTest runs the command and decodes its JSON outcome. Commands
// that print usage (help, missing arguments) are reported with code 2 and no
// JSON.
func runPrivilegedForTest(t *testing.T, args []string, stdin string) (privilegedOutcome, int, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := runPrivileged(args, strings.NewReader(stdin), &stdout, &stderr)
	var out privilegedOutcome
	if strings.HasPrefix(strings.TrimSpace(stdout.String()), "{") {
		if err := json.Unmarshal(stdout.Bytes(), &out); err != nil {
			t.Fatalf("stdout is not one JSON object: %v\n%s", err, stdout.String())
		}
	}
	return out, code, stderr.String()
}

func requireLinux(t *testing.T) {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("qwq privileged is Linux only")
	}
}

func TestRunPrivilegedUsage(t *testing.T) {
	if out, code, stderr := runPrivilegedForTest(t, nil, ""); code != 2 || !strings.Contains(stderr, "usage: qwq privileged") {
		t.Errorf("no args: code %d, stderr %q, out %+v", code, stderr, out)
	}
	helpOut, code, stderr := runPrivilegedForTest(t, []string{"help"}, "")
	if code != 0 || stderr != "" {
		t.Errorf("help: code %d, stderr %q, out %+v", code, stderr, helpOut)
	}
	if _, code, stderr := runPrivilegedForTest(t, []string{"bogus"}, ""); code != 2 || !strings.Contains(stderr, `unknown command "bogus"`) {
		t.Errorf("bogus: code %d, stderr %q", code, stderr)
	}
}

func TestRunPrivilegedRefusesNonRoot(t *testing.T) {
	requireLinux(t)
	asUnprivileged(t)
	out, code, stderr := runPrivilegedForTest(t, []string{"verify-entrypoint", "-dir", "/tmp", "-entrypoint", "bin/plugin", "-digest", "sha256:" + strings.Repeat("a", 64)}, "")
	if code != 1 {
		t.Fatalf("code = %d, want 1; stderr %q", code, stderr)
	}
	if out.OK || !strings.Contains(out.Error, "root") {
		t.Errorf("outcome = %+v", out)
	}
}

func TestRunPrivilegedRender(t *testing.T) {
	requireLinux(t)
	asRoot(t)
	dir := t.TempDir()
	spec := sandbox.UnitSpec{
		ID:         "alpha",
		VersionDir: "/var/lib/qwq-plugins/alpha/1.2.3",
		Entrypoint: "bin/plugin",
		Digest:     "sha256:" + strings.Repeat("a", 64),
		Limits:     &sandbox.Limits{MemoryMaxMB: 32, CPUQuotaPercent: 20, PIDsMax: 16, FDsMax: 128},
	}
	b, err := json.Marshal(spec)
	if err != nil {
		t.Fatal(err)
	}
	specPath := filepath.Join(dir, "spec.json")
	if err := os.WriteFile(specPath, b, 0o600); err != nil {
		t.Fatal(err)
	}
	out, code, stderr := runPrivilegedForTest(t, []string{"render", "-spec", specPath, "-out", filepath.Join(dir, "out")}, "")
	if code != 0 || !out.OK {
		t.Fatalf("code = %d, stderr %q, outcome %+v", code, stderr, out)
	}
	service := filepath.Join(dir, "out", "systemd", "qwq-plugin@alpha.service")
	if _, err := os.Stat(service); err != nil {
		t.Fatalf("rendered service: %v", err)
	}
	got, err := os.ReadFile(service)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(got), "ExecStart=/var/lib/qwq-plugins/alpha/1.2.3/bin/plugin\n") {
		t.Errorf("rendered service does not pin the executable:\n%s", got)
	}
	for _, path := range append(append([]string{}, out.Files...), out.Tmpfiles) {
		if _, err := os.Stat(path); err != nil {
			t.Errorf("reported file %s: %v", path, err)
		}
	}
	if len(out.Files) != 3 || !strings.HasSuffix(out.Tmpfiles, "qwq-plugin-alpha.conf") {
		t.Errorf("outcome = %+v", out)
	}
}

func TestRunPrivilegedVerifyEntrypoint(t *testing.T) {
	requireLinux(t)
	asRoot(t)
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "bin", "plugin"), []byte("#!/bin/true\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	digest, err := pkgfile.DigestFile(dir, "bin/plugin")
	if err != nil {
		t.Fatal(err)
	}
	out, code, stderr := runPrivilegedForTest(t, []string{
		"verify-entrypoint", "-dir", dir, "-entrypoint", "bin/plugin", "-digest", digest,
	}, "")
	if code != 0 || !out.OK {
		t.Fatalf("code = %d, stderr %q, outcome %+v", code, stderr, out)
	}
	bad, code, _ := runPrivilegedForTest(t, []string{
		"verify-entrypoint", "-dir", dir, "-entrypoint", "bin/plugin", "-digest", "sha256:" + strings.Repeat("0", 64),
	}, "")
	if code != 1 || bad.OK {
		t.Errorf("wrong digest: code %d, outcome %+v", code, bad)
	}
	if _, code, _ := runPrivilegedForTest(t, []string{"verify-entrypoint", "-dir", dir}, ""); code != 2 {
		t.Errorf("missing flags: code %d, want 2", code)
	}
}

func TestRunPrivilegedInstallRejectsBadSpec(t *testing.T) {
	requireLinux(t)
	asRoot(t)
	dir := t.TempDir()
	unitDir := filepath.Join(dir, "systemd")
	tmpfilesDir := filepath.Join(dir, "tmpfiles")
	runtimeBase := filepath.Join(dir, "run")
	if err := os.MkdirAll(filepath.Join(runtimeBase, "qwq"), 0o750); err != nil {
		t.Fatal(err)
	}
	// The id can never reach a unit file, so install must fail before it
	// writes anything or calls groupadd.
	spec := map[string]any{
		"id":          "alpha\nExecStart=/bin/sh",
		"version_dir": "/var/lib/qwq-plugins/alpha/1.2.3",
		"entrypoint":  "bin/plugin",
		"digest":      "sha256:" + strings.Repeat("a", 64),
	}
	b, err := json.Marshal(spec)
	if err != nil {
		t.Fatal(err)
	}
	specPath := filepath.Join(dir, "spec.json")
	if err := os.WriteFile(specPath, b, 0o600); err != nil {
		t.Fatal(err)
	}
	out, code, stderr := runPrivilegedForTest(t, []string{
		"install", "-spec", specPath,
		"-unit-dir", unitDir, "-tmpfiles-dir", tmpfilesDir, "-runtime-base", runtimeBase,
	}, "")
	if code != 1 || out.OK {
		t.Fatalf("code = %d, stderr %q, outcome %+v", code, stderr, out)
	}
	if _, err := os.Stat(filepath.Join(unitDir, "qwq-plugin@alpha.service")); !os.IsNotExist(err) {
		t.Error("install wrote a unit file for a rejected spec")
	}
}

func TestRunPrivilegedRejectsUnknownSpecField(t *testing.T) {
	requireLinux(t)
	asRoot(t)
	dir := t.TempDir()
	specPath := filepath.Join(dir, "spec.json")
	if err := os.WriteFile(specPath, []byte(`{"id":"alpha","bogus":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, code, stderr := runPrivilegedForTest(t, []string{"render", "-spec", specPath, "-out", filepath.Join(dir, "out")}, ""); code != 1 || out.OK {
		t.Errorf("code = %d, stderr %q, outcome %+v", code, stderr, out)
	}
}

func TestRunPrivilegedReadsSpecFromStdin(t *testing.T) {
	requireLinux(t)
	asRoot(t)
	dir := t.TempDir()
	stdin := `{"id":"alpha","version_dir":"/var/lib/qwq-plugins/alpha/1.2.3",` +
		`"entrypoint":"bin/plugin","digest":"sha256:` + strings.Repeat("a", 64) + `"}`
	out, code, stderr := runPrivilegedForTest(t, []string{"render", "-spec", "-", "-out", filepath.Join(dir, "out")}, stdin)
	if code != 0 || !out.OK {
		t.Fatalf("code = %d, stderr %q, outcome %+v", code, stderr, out)
	}
	if out.ID != "alpha" {
		t.Errorf("outcome = %+v", out)
	}
}

func TestReadToken(t *testing.T) {
	token := strings.Repeat("ab", 32)
	for _, in := range []string{token, token + "\n", token + "\r\n"} {
		got, err := readToken(strings.NewReader(in))
		if err != nil || string(got) != token {
			t.Errorf("readToken(%q) = %q, %v", in, got, err)
		}
	}
	if _, err := readToken(strings.NewReader(strings.Repeat("a", maxCredentialBytes+1))); err == nil {
		t.Error("readToken accepted an oversized credential")
	}
}

func TestReadSpecRejectsTrailingData(t *testing.T) {
	dir := t.TempDir()
	good := `{"id":"alpha","version_dir":"/var/lib/qwq-plugins/alpha/1.2.3",` +
		`"entrypoint":"bin/plugin","digest":"sha256:` + strings.Repeat("a", 64) + `"}`
	for _, body := range []string{good + good, good + "}"} {
		path := filepath.Join(dir, "spec.json")
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := readSpec(path, strings.NewReader("")); err == nil {
			t.Errorf("readSpec accepted trailing data in %q", body)
		}
	}
	if _, err := readSpec("relative.json", strings.NewReader("")); err == nil {
		t.Error("readSpec accepted a relative path")
	}
}
