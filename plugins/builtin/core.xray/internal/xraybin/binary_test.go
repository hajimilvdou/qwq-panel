// SPDX-License-Identifier: AGPL-3.0-only

package xraybin

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/qwq-panel/qwq/internal/sandbox"
	"github.com/qwq-panel/qwq/sdk/manifest"
)

// binaryFixture 的脚本只用于固定 argv/环境与失败脱敏，不运行真实 Xray 或监听。
func binaryFixture(t *testing.T, script string) (string, string, sandbox.TrustPolicy) {
	t.Helper()
	root := t.TempDir()
	bin := filepath.Join(root, "bin")
	if err := os.Mkdir(bin, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bin, "plugin"), []byte("fixture"), 0o555); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bin, "xray"), []byte(script), 0o555); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile("../../manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	m, err := manifest.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(script))
	digest := hex.EncodeToString(sum[:])
	m.Files["bin/xray"] = "sha256:" + digest
	raw, err = json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "manifest.json"), raw, 0o444); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(bin, 0o555); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(root, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(root, 0o700); _ = os.Chmod(bin, 0o700) })
	return filepath.Join(bin, "plugin"), digest, sandbox.TrustPolicy{UID: os.Geteuid(), StopAt: root}
}

func candidateFixture(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(dir, "config.json")
	if err := os.WriteFile(file, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return file
}

func TestLocatorPinnedAndIndependentOfPath(t *testing.T) {
	executable, digest, trust := binaryFixture(t, "#!/bin/sh\nexit 0\n")
	original, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	other := t.TempDir()
	if err := os.Chdir(other); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(original) })
	t.Setenv("PATH", other)
	binary, err := locate(executable, digest, trust)
	if err != nil || binary.path != filepath.Join(filepath.Dir(executable), "xray") {
		t.Fatal("locator depends on cwd or PATH")
	}
	if _, err := locate(executable, strings.Repeat("0", 64), trust); err != ErrBinary {
		t.Fatal("wrong pinned digest accepted")
	}
	if _, err := locate(filepath.Join(other, "plugin"), digest, trust); err != ErrBinary {
		t.Fatal("unpackaged executable accepted")
	}
}

func TestLocatorRejectsWritableAndSymlinkBinary(t *testing.T) {
	for _, mutate := range []func(string){
		func(file string) { _ = os.Chmod(file, 0o755) },
		func(file string) { _ = os.Remove(file) },
		func(file string) { _ = os.Remove(file); _ = os.Symlink("plugin", file) },
	} {
		executable, digest, trust := binaryFixture(t, "#!/bin/sh\nexit 0\n")
		_ = os.Chmod(filepath.Dir(executable), 0o700)
		mutate(filepath.Join(filepath.Dir(executable), "xray"))
		_ = os.Chmod(filepath.Dir(executable), 0o555)
		if _, err := locate(executable, digest, trust); err != ErrBinary {
			t.Fatal("unsafe/missing binary accepted")
		}
	}
}

func TestFixedCommandPrivateCandidateAndRedactedFailure(t *testing.T) {
	executable, digest, trust := binaryFixture(t, "#!/bin/sh\nprintf CANARY_PRIVATE_MATERIAL >&2\nexit 1\n")
	binary, err := locate(executable, digest, trust)
	if err != nil {
		t.Fatal(err)
	}
	file := candidateFixture(t)
	t.Setenv("QWQ_HOST_TOKEN", "CANARY_HOST_TOKEN")
	command, err := binary.Command(t.Context(), file, true)
	if err != nil {
		t.Fatal(err)
	}
	if command.Path != binary.path || strings.Join(command.Args[1:], " ") != "run -test -config "+file || strings.Contains(strings.Join(command.Env, " "), "CANARY") {
		t.Fatal("command or inherited environment escaped its boundary")
	}
	if err := binary.Preflight(t.Context(), file); !errors.Is(err, ErrPreflight) || strings.Contains(err.Error(), "CANARY") {
		t.Fatal("preflight stderr leaked or failure was accepted")
	}
	if err := os.Chmod(file, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := binary.Command(t.Context(), file, true); err != ErrCandidate {
		t.Fatal("public candidate accepted")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := binary.Command(ctx, file, true); !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation ignored")
	}
}

func TestOutputBoundContinuesDraining(t *testing.T) {
	output := &boundedOutput{}
	data := bytes.Repeat([]byte("x"), 64<<10)
	count, err := output.Write(data)
	if err != nil || count != len(data) || len(output.data) != 8192 || !output.overflow {
		t.Fatal("output memory or draining bound broken")
	}
}
