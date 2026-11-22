// SPDX-License-Identifier: AGPL-3.0-only

package controller

import (
	"bytes"
	"crypto/sha256"
	"os"
	"path/filepath"
	"testing"
)

// ======================== 实际凭据文件与数据库必须一致 ========================

func TestReinstallUnitPersistsIssuedCredential(t *testing.T) {
	f := newInstallerFixture(t)
	tokens := &PluginTokens{DB: testDB(t)}
	f.installer.Tokens = tokens
	staged, err := f.installer.Stage(t.Context(), f.pkg.path)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.installer.InstallUnit(t.Context(), staged); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(f.installer.Sandbox.CredDir, staged.PluginID+".token")
	previous, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(previous)
	if err := f.installer.ReinstallUnit(t.Context(), staged.PluginID, staged.Version, staged.Manifest); err != nil {
		t.Fatal(err)
	}
	current, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(current)
	if bytes.Equal(previous, current) {
		t.Fatal("reinstall did not issue a fresh credential")
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatal("reinstall did not retain private credential file permissions")
	}
	digest, err := tokens.Digest(t.Context(), staged.PluginID)
	if err != nil {
		t.Fatal(err)
	}
	expected := sha256.Sum256(current)
	if !bytes.Equal(digest, expected[:]) {
		t.Fatal("the restored process would present a credential the host database rejects")
	}
}
