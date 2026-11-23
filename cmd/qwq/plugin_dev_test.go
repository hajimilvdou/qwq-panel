// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestPluginDevRoundTripKeygenInitPackVerify(t *testing.T) {
	tmp := t.TempDir()
	privPath := filepath.Join(tmp, "keys", "dev.key.pem")
	pubPath := filepath.Join(tmp, "keys", "dev.pub.pem")

	// 1. keygen
	var out, errBuf bytes.Buffer
	rc := runPlugin([]string{"keygen", "--out-priv", privPath, "--out-pub", pubPath}, &out, &errBuf)
	if rc != 0 {
		t.Fatalf("keygen failed rc=%d stderr=%s", rc, errBuf.String())
	}
	if !strings.Contains(out.String(), "key_id:      ed25519:") {
		t.Fatalf("keygen output missing key_id: %s", out.String())
	}
	if runtime.GOOS != "windows" {
		st, err := os.Stat(privPath)
		if err != nil {
			t.Fatalf("stat priv: %v", err)
		}
		if st.Mode().Perm() != 0o600 {
			t.Fatalf("priv mode = %o, want 0600", st.Mode().Perm())
		}
	}
	// Refuses overwriting existing keypair.
	out.Reset()
	errBuf.Reset()
	if rc := runPlugin([]string{"keygen", "--out-priv", privPath, "--out-pub", pubPath}, &out, &errBuf); rc == 0 {
		t.Fatalf("keygen unexpectedly overwrote existing keypair")
	}

	// 2. init (positional <dir> before flags)
	srcDir := filepath.Join(tmp, "acme-hello")
	out.Reset()
	errBuf.Reset()
	rc = runPlugin([]string{"init", srcDir, "--id", "acme.hello", "--name", "Acme Hello", "--with-ui"}, &out, &errBuf)
	if rc != 0 {
		t.Fatalf("init failed rc=%d stderr=%s", rc, errBuf.String())
	}
	for _, rel := range []string{
		"manifest.json",
		"main.go",
		"schemas/config.schema.json",
		"schemas/hello.request.json",
		"schemas/hello.response.json",
		"attestations/sbom.spdx.json",
		"ui/index.html",
		"ui/plugin.css",
		"ui/plugin.js",
		"README.md",
	} {
		if _, err := os.Stat(filepath.Join(srcDir, filepath.FromSlash(rel))); err != nil {
			t.Fatalf("expected scaffold file %s: %v", rel, err)
		}
	}
	htmlBytes, err := os.ReadFile(filepath.Join(srcDir, "ui", "index.html"))
	if err != nil {
		t.Fatalf("read ui/index.html: %v", err)
	}
	html := string(htmlBytes)
	if strings.Contains(html, "<style") || strings.Contains(html, "onclick=") {
		t.Fatalf("scaffold ui/index.html violates zero-inline CSP: %s", html)
	}

	// Add ignored .git directory and stale .qwqpkg file to verify pack skips them.
	if err := os.MkdirAll(filepath.Join(srcDir, ".git"), 0o755); err != nil {
		t.Fatalf("mkdir .git: %v", err)
	}
	if err := os.WriteFile(filepath.Join(srcDir, ".git", "HEAD"), []byte("ref: refs/heads/main\n"), 0o644); err != nil {
		t.Fatalf("write .git/HEAD: %v", err)
	}
	if err := os.WriteFile(filepath.Join(srcDir, "old.qwqpkg"), []byte("stale"), 0o644); err != nil {
		t.Fatalf("write stale pkg: %v", err)
	}

	// Create a dummy compiled binary passed via --entrypoint.
	dummyBin := filepath.Join(tmp, "hello-linux-amd64")
	if err := os.WriteFile(dummyBin, []byte("#!/bin/sh\necho hello\n"), 0o755); err != nil {
		t.Fatalf("write dummy bin: %v", err)
	}

	// 3. pack
	pkgPath := filepath.Join(tmp, "dist", "acme.hello-0.1.0.qwqpkg")
	out.Reset()
	errBuf.Reset()
	rc = runPlugin([]string{"pack", srcDir, "--out", pkgPath, "--key", privPath, "--entrypoint", dummyBin}, &out, &errBuf)
	if rc != 0 {
		t.Fatalf("pack failed rc=%d stderr=%s", rc, errBuf.String())
	}
	if !strings.Contains(out.String(), "id:           acme.hello") {
		t.Fatalf("pack summary missing id: %s", out.String())
	}

	// 4a. verify with single pub.pem file
	out.Reset()
	errBuf.Reset()
	rc = runPlugin([]string{"verify", pkgPath, "--trust", pubPath}, &out, &errBuf)
	if rc != 0 {
		t.Fatalf("verify (file) failed rc=%d stderr=%s", rc, errBuf.String())
	}
	verifyOut := out.String()
	for _, want := range []string{"id:           acme.hello", "version:      0.1.0", "key_id:       ed25519:", "verified:     OK"} {
		if !strings.Contains(verifyOut, want) {
			t.Fatalf("verify output missing %q:\n%s", want, verifyOut)
		}
	}

	// 4b. verify with trust directory
	trustDir := filepath.Join(tmp, "trust-dir")
	if err := os.MkdirAll(trustDir, 0o755); err != nil {
		t.Fatalf("mkdir trustDir: %v", err)
	}
	pubRaw, err := os.ReadFile(pubPath)
	if err != nil {
		t.Fatalf("read pub: %v", err)
	}
	if err := os.WriteFile(filepath.Join(trustDir, "dev.pem"), pubRaw, 0o644); err != nil {
		t.Fatalf("write trust dir pem: %v", err)
	}
	out.Reset()
	errBuf.Reset()
	if rc := runPlugin([]string{"verify", pkgPath, "--trust", trustDir}, &out, &errBuf); rc != 0 {
		t.Fatalf("verify (dir) failed rc=%d stderr=%s", rc, errBuf.String())
	}

	// 5. verify fails against a different untrusted key
	otherPriv := filepath.Join(tmp, "keys", "other.key.pem")
	otherPub := filepath.Join(tmp, "keys", "other.pub.pem")
	out.Reset()
	errBuf.Reset()
	if rc := runPlugin([]string{"keygen", "--out-priv", otherPriv, "--out-pub", otherPub}, &out, &errBuf); rc != 0 {
		t.Fatalf("other keygen failed: %s", errBuf.String())
	}
	out.Reset()
	errBuf.Reset()
	if rc := runPlugin([]string{"verify", pkgPath, "--trust", otherPub}, &out, &errBuf); rc == 0 {
		t.Fatalf("verify unexpectedly passed with wrong trust key")
	}

	// 6. verify fails on tampered package bytes (flip inside archive payload/signature, not trailing tar EOF padding)
	tamperedPath := filepath.Join(tmp, "tampered.qwqpkg")
	pkgBytes, err := os.ReadFile(pkgPath)
	if err != nil {
		t.Fatalf("read pkg: %v", err)
	}
	pkgBytes[len(pkgBytes)/2] ^= 0xff
	if err := os.WriteFile(tamperedPath, pkgBytes, 0o644); err != nil {
		t.Fatalf("write tampered: %v", err)
	}
	out.Reset()
	errBuf.Reset()
	if rc := runPlugin([]string{"verify", tamperedPath, "--trust", pubPath}, &out, &errBuf); rc == 0 {
		t.Fatalf("verify unexpectedly passed on tampered package")
	}
}

func TestPluginInitRejectsReservedNamespaceAndSupportsNoUI(t *testing.T) {
	var out, errBuf bytes.Buffer
	badDir := filepath.Join(t.TempDir(), "bad")
	if rc := runPlugin([]string{"init", badDir, "--id", "qwq.bad", "--name", "Bad"}, &out, &errBuf); rc != 2 {
		t.Fatalf("expected rc=2 for reserved id, got %d", rc)
	}

	noUIDir := filepath.Join(t.TempDir(), "headless")
	out.Reset()
	errBuf.Reset()
	if rc := runPlugin([]string{"init", noUIDir, "--id", "acme.headless", "--name", "Headless", "--with-ui=false"}, &out, &errBuf); rc != 0 {
		t.Fatalf("init --with-ui=false failed rc=%d stderr=%s", rc, errBuf.String())
	}
	if _, err := os.Stat(filepath.Join(noUIDir, "ui", "index.html")); !os.IsNotExist(err) {
		t.Fatalf("expected no ui/index.html when --with-ui=false")
	}
}

func TestPluginPackRefusesPrivateKeysAndTraversalEntrypoint(t *testing.T) {
	tmp := t.TempDir()
	privPath := filepath.Join(tmp, "keys", "dev.key.pem")
	pubPath := filepath.Join(tmp, "keys", "dev.pub.pem")
	var out, errBuf bytes.Buffer
	if rc := runPlugin([]string{"keygen", "--out-priv", privPath, "--out-pub", pubPath}, &out, &errBuf); rc != 0 {
		t.Fatalf("keygen failed: %s", errBuf.String())
	}
	privBytes, err := os.ReadFile(privPath)
	if err != nil {
		t.Fatalf("read priv: %v", err)
	}
	dummyBin := filepath.Join(tmp, "plugin-bin")
	if err := os.WriteFile(dummyBin, []byte("#!/bin/sh\necho hi\n"), 0o755); err != nil {
		t.Fatalf("write dummy bin: %v", err)
	}

	// 1. Private key (.pem/.key or PEM body) inside source dir must be hard-refused.
	t.Run("refuses private key in source dir", func(t *testing.T) {
		srcDir := filepath.Join(tmp, "src-privkey")
		out.Reset()
		errBuf.Reset()
		if rc := runPlugin([]string{"init", srcDir, "--id", "acme.leak", "--name", "Acme <Leak>"}, &out, &errBuf); rc != 0 {
			t.Fatalf("init failed: %s", errBuf.String())
		}
		// Also verify HTML escaping in scaffold ui/index.html.
		htmlBytes, err := os.ReadFile(filepath.Join(srcDir, "ui", "index.html"))
		if err != nil {
			t.Fatalf("read ui/index.html: %v", err)
		}
		if strings.Contains(string(htmlBytes), "<Leak>") || !strings.Contains(string(htmlBytes), "&lt;Leak&gt;") {
			t.Fatalf("expected spec.Name to be HTML-escaped in ui/index.html: %s", string(htmlBytes))
		}

		// Case 1a: .pem file inside source dir
		leakedPEM := filepath.Join(srcDir, "leaked.key.pem")
		if err := os.WriteFile(leakedPEM, privBytes, 0o600); err != nil {
			t.Fatalf("write leaked pem: %v", err)
		}
		out.Reset()
		errBuf.Reset()
		pkgPath := filepath.Join(tmp, "leak1.qwqpkg")
		if rc := runPlugin([]string{"pack", srcDir, "--out", pkgPath, "--key", privPath, "--entrypoint", dummyBin}, &out, &errBuf); rc == 0 {
			t.Fatalf("pack unexpectedly succeeded with leaked .pem key inside source dir")
		}
		_ = os.Remove(leakedPEM)

		// Case 1b: non-.pem file containing BEGIN PRIVATE KEY block inside source dir
		leakedTxt := filepath.Join(srcDir, "notes.txt")
		if err := os.WriteFile(leakedTxt, privBytes, 0o600); err != nil {
			t.Fatalf("write leaked txt: %v", err)
		}
		out.Reset()
		errBuf.Reset()
		if rc := runPlugin([]string{"pack", srcDir, "--out", pkgPath, "--key", privPath, "--entrypoint", dummyBin}, &out, &errBuf); rc == 0 {
			t.Fatalf("pack unexpectedly succeeded with PEM private key body inside source dir")
		}
	})

	// 2. Excludes --key, --out, and --entrypoint by os.SameFile if placed inside source dir.
	t.Run("excludes key out and entrypoint via SameFile", func(t *testing.T) {
		srcDir := filepath.Join(tmp, "src-samefile")
		out.Reset()
		errBuf.Reset()
		if rc := runPlugin([]string{"init", srcDir, "--id", "acme.samefile", "--name", "SameFile"}, &out, &errBuf); rc != 0 {
			t.Fatalf("init failed: %s", errBuf.String())
		}
		inKey := filepath.Join(srcDir, "signing.key.pem")
		if err := os.WriteFile(inKey, privBytes, 0o600); err != nil {
			t.Fatalf("write inKey: %v", err)
		}
		inBin := filepath.Join(srcDir, "raw-bin")
		if err := os.WriteFile(inBin, []byte("#!/bin/sh\necho ok\n"), 0o755); err != nil {
			t.Fatalf("write inBin: %v", err)
		}
		inOut := filepath.Join(srcDir, "out.qwqpkg")
		out.Reset()
		errBuf.Reset()
		if rc := runPlugin([]string{"pack", srcDir, "--out", inOut, "--key", inKey, "--entrypoint", inBin}, &out, &errBuf); rc != 0 {
			t.Fatalf("pack with in-dir --key/--entrypoint/--out failed rc=%d stderr=%s", rc, errBuf.String())
		}
		out.Reset()
		errBuf.Reset()
		if rc := runPlugin([]string{"verify", inOut, "--trust", pubPath}, &out, &errBuf); rc != 0 {
			t.Fatalf("verify failed: %s", errBuf.String())
		}
	})

	// 3. Traversal or non-bin manifest.entrypoint must be rejected before copying.
	t.Run("rejects traversal manifest.entrypoint", func(t *testing.T) {
		for _, badEntry := range []string{"../../escape", "../bin/plugin", "/bin/plugin", "bin\\plugin", "other/plugin"} {
			srcDir := filepath.Join(tmp, "src-escape-"+strings.NewReplacer("/", "_", "\\", "_", ".", "d").Replace(badEntry))
			out.Reset()
			errBuf.Reset()
			if rc := runPlugin([]string{"init", srcDir, "--id", "acme.escape", "--name", "Escape"}, &out, &errBuf); rc != 0 {
				t.Fatalf("init failed: %s", errBuf.String())
			}
			mPath := filepath.Join(srcDir, "manifest.json")
			raw, err := os.ReadFile(mPath)
			if err != nil {
				t.Fatalf("read manifest: %v", err)
			}
			mutated := strings.Replace(string(raw), `"entrypoint": "bin/plugin"`, `"entrypoint": "`+strings.ReplaceAll(badEntry, `\`, `\\`)+`"`, 1)
			if err := os.WriteFile(mPath, []byte(mutated), 0o644); err != nil {
				t.Fatalf("write manifest: %v", err)
			}
			out.Reset()
			errBuf.Reset()
			pkgPath := filepath.Join(tmp, "escape.qwqpkg")
			if rc := runPlugin([]string{"pack", srcDir, "--out", pkgPath, "--key", privPath, "--entrypoint", dummyBin}, &out, &errBuf); rc == 0 {
				t.Fatalf("pack unexpectedly accepted malicious entrypoint %q", badEntry)
			}
		}
	})
}
