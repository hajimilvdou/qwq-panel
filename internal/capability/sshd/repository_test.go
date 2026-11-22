// SPDX-License-Identifier: AGPL-3.0-only

package sshd

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/qwq-panel/qwq/internal/capability/local"
	"github.com/qwq-panel/qwq/internal/sandbox"
	"golang.org/x/crypto/ssh"
)

func nativeRepository(t *testing.T, body string) FileRepository {
	t.Helper()
	if _, err := os.Stat("/usr/sbin/sshd"); err != nil {
		t.Skip("native OpenSSH unavailable")
	}
	root := t.TempDir()
	configDir, tempDir := filepath.Join(root, "ssh"), filepath.Join(root, "run")
	for _, dir := range []string{configDir, tempDir, filepath.Join(configDir, "sshd_config.d")} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKey(key, "temporary native test")
	clear(key)
	if err != nil {
		t.Fatal(err)
	}
	private := pem.EncodeToMemory(block)
	keyPath := filepath.Join(root, "host-key")
	if err := os.WriteFile(keyPath, private, 0600); err != nil {
		t.Fatal(err)
	}
	clear(private)
	clear(block.Bytes)
	main := "HostKey " + keyPath + "\nInclude " + filepath.Join(configDir, "sshd_config.d", "*.conf") + "\n" + body
	if err := os.WriteFile(filepath.Join(configDir, "sshd_config"), []byte(main), 0600); err != nil {
		t.Fatal(err)
	}
	return FileRepository{ConfigDir: configDir, TempDir: tempDir, Executor: local.ExecTools{}, Trust: sandbox.TrustPolicy{UID: os.Getuid(), StopAt: root}}
}

func TestNativeIncludeMatchAndCandidate(t *testing.T) {
	r := nativeRepository(t, "PasswordAuthentication yes\nMatch User qwq_no_match\n PermitRootLogin yes\nMatch User root\n PermitRootLogin no\n")
	cloud := filepath.Join(r.ConfigDir, "sshd_config.d", "50-cloud-init.conf")
	if err := os.WriteFile(cloud, []byte("PasswordAuthentication no\n"), 0600); err != nil {
		t.Fatal(err)
	}
	before, err := r.Read(context.Background(), Match{User: "root", Address: "127.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	if settingValue(before.Settings, "passwordauthentication") != "no" || settingValue(before.Settings, "permitrootlogin") != "no" {
		t.Fatal("native Match/Include behavior lost")
	}
	for _, setting := range before.Settings {
		if setting.Key == "passwordauthentication" && setting.SourceFile != cloud {
			t.Fatalf("password source = %s", setting.SourceFile)
		}
		if setting.Key == "permitrootlogin" && setting.SourceFile != filepath.Join(r.ConfigDir, "sshd_config") {
			t.Fatalf("root source = %s", setting.SourceFile)
		}
	}
	global, err := r.Read(context.Background(), Match{})
	if err != nil || global.Revision != before.Revision {
		t.Fatal("resource revision depends on match query")
	}
	raw := renderDropIn(loginPolicy{Ports: []uint32{2233}})
	candidate, err := r.Candidate(context.Background(), global, raw, Match{})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(candidate.Ports, []uint32{2233}) {
		t.Fatalf("candidate ports = %v", candidate.Ports)
	}
	if _, err := os.Stat(filepath.Join(r.ConfigDir, ownedDropIn)); !os.IsNotExist(err) {
		t.Fatal("validation wrote live config")
	}
	if err := r.Commit(raw); err != nil {
		t.Fatal(err)
	}
	after, err := r.Read(context.Background(), Match{})
	if err != nil || after.Revision != candidate.Revision {
		t.Fatal("candidate revision did not match committed native config")
	}
	entries, err := os.ReadDir(r.TempDir)
	if err != nil || len(entries) != 0 {
		t.Fatal("candidate directories leaked")
	}
}

func TestNativeAdditivePortsAndUntrustedInclude(t *testing.T) {
	r := nativeRepository(t, "Port 2222\n")
	before, err := r.Read(context.Background(), Match{})
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := r.Candidate(context.Background(), before, renderDropIn(loginPolicy{Ports: []uint32{2233}}), Match{})
	if err != nil || !slices.Equal(candidate.Ports, []uint32{2222, 2233}) {
		t.Fatal("external additive Port was hidden")
	}
	if err := os.Symlink(filepath.Join(r.ConfigDir, "sshd_config"), filepath.Join(r.ConfigDir, "sshd_config.d", "50-linked.conf")); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Read(context.Background(), Match{}); err == nil {
		t.Fatal("symlink Include accepted")
	}
}

func TestConfigSyntaxAndOwnedScope(t *testing.T) {
	for _, raw := range []string{"Port 22\n", managedHeader + "ForceCommand sh\n", managedHeader + "Port 0\n", managedHeader + "PasswordAuthentication yes\nPasswordAuthentication no\n"} {
		if _, err := parseDropIn([]byte(raw)); err == nil {
			t.Fatal("unsafe owned config accepted")
		}
	}
	fields, err := configFields("Include \"sshd_config.d/*.conf\" # explanation")
	if err != nil || !slices.Equal(fields, []string{"Include", "sshd_config.d/*.conf"}) {
		t.Fatal("quoted Include not decoded")
	}
	for _, line := range []string{"Include \"unterminated", "Include a\\b", "Include x\x00"} {
		if _, err := configFields(line); err == nil {
			t.Fatal("invalid syntax accepted")
		}
	}
	if raw := string(renderDropIn(loginPolicy{Ports: []uint32{2233, 2222, 2222}})); !strings.HasSuffix(raw, "Port 2222\nPort 2233\n") {
		t.Fatal("port output is not canonical")
	}
}
