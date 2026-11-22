// SPDX-License-Identifier: AGPL-3.0-only

package sandbox

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/qwq-panel/qwq/sdk/pkgfile"
)

// cmdCall records one Runner invocation.
type cmdCall struct {
	name string
	args []string
}

// fakeRunner implements Runner for the groupadd/groupdel/getent calls the
// installer makes. Tests never depend on the build machine having shadow
// tools or root.
type fakeRunner struct {
	mu    sync.Mutex
	calls []cmdCall
	reply func(name string, args []string) (string, error)
}

func (f *fakeRunner) Run(_ context.Context, name string, args ...string) (string, error) {
	f.mu.Lock()
	f.calls = append(f.calls, cmdCall{name: name, args: append([]string(nil), args...)})
	reply := f.reply
	f.mu.Unlock()
	if reply != nil {
		return reply(name, args)
	}
	return "", nil
}

func (f *fakeRunner) has(name string, args ...string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, c := range f.calls {
		if c.name != name || len(c.args) != len(args) {
			continue
		}
		match := true
		for i := range args {
			if c.args[i] != args[i] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

func (f *fakeRunner) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

func TestWriteFileAtomic(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sub", "unit.service")
	if err := WriteFileAtomic(path, []byte("first\n"), 0o640); err != nil {
		t.Fatalf("WriteFileAtomic: %v", err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if got := fi.Mode().Perm(); got != 0o640 {
		t.Errorf("mode = %o, want 0640", got)
	}
	if got, _ := os.ReadFile(path); string(got) != "first\n" {
		t.Errorf("content = %q", got)
	}
	if err := WriteFileAtomic(path, []byte("second\n"), 0o600); err != nil {
		t.Fatalf("overwrite: %v", err)
	}
	if got, _ := os.ReadFile(path); string(got) != "second\n" {
		t.Errorf("content after overwrite = %q", got)
	}
	if fi, err := os.Stat(path); err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("mode after overwrite = %v, %v", fi.Mode().Perm(), err)
	}
	// The temporary file must not survive.
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "unit.service" {
		t.Errorf("directory contains %v, want just unit.service", entries)
	}
	// Refusals.
	if err := WriteFileAtomic("relative/path", nil, 0o600); err == nil {
		t.Error("WriteFileAtomic accepted a relative path")
	}
	unclean := filepath.Join(dir, "a") + "/../b"
	if err := WriteFileAtomic(unclean, nil, 0o600); err == nil {
		t.Error("WriteFileAtomic accepted an unclean path")
	}
	if err := WriteFileAtomic(filepath.Join(dir, "bad\nname"), nil, 0o600); err == nil {
		t.Error("WriteFileAtomic accepted a newline in the path")
	}
	if err := WriteFileAtomic(filepath.Join(dir, "empty-mode"), nil, 0); err == nil {
		t.Error("WriteFileAtomic accepted an empty mode")
	}
}

func TestInstallAndRemoveUnit(t *testing.T) {
	ctx := context.Background()
	destDir := t.TempDir()
	written, err := InstallUnit(ctx, alphaSpec(), destDir)
	if err != nil {
		t.Fatalf("InstallUnit: %v", err)
	}
	want := []string{
		filepath.Join(destDir, "qwq-plugin@alpha.service"),
		filepath.Join(destDir, "qwq-plugin@alpha.service.d", "10-resources.conf"),
		filepath.Join(destDir, "qwq-plugin@alpha.socket"),
	}
	if strings.Join(written, "\n") != strings.Join(want, "\n") {
		t.Fatalf("InstallUnit wrote %v, want %v", written, want)
	}
	rendered, err := RenderUnit(alphaSpec())
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range written {
		fi, err := os.Stat(path)
		if err != nil {
			t.Fatalf("stat %s: %v", path, err)
		}
		if fi.Mode().Perm() != UnitFileMode {
			t.Errorf("%s mode = %o, want %o", path, fi.Mode().Perm(), UnitFileMode)
		}
		name := strings.TrimPrefix(strings.TrimPrefix(path, destDir), string(filepath.Separator))
		want, ok := rendered[filepath.ToSlash(name)]
		if !ok {
			t.Fatalf("%s has no matching RenderUnit entry", name)
		}
		got, _ := os.ReadFile(path)
		if string(got) != string(want) {
			t.Errorf("%s content does not match RenderUnit", path)
		}
	}
	// A second install replaces the files without leftovers.
	if _, err := InstallUnit(ctx, alphaSpec(), destDir); err != nil {
		t.Fatalf("second InstallUnit: %v", err)
	}
	var leftovers []string
	_ = filepath.WalkDir(destDir, func(p string, d fs.DirEntry, err error) error {
		if err == nil && strings.HasPrefix(d.Name(), ".qwq-tmp-") {
			leftovers = append(leftovers, p)
		}
		return nil
	})
	if len(leftovers) != 0 {
		t.Errorf("temporary files left behind: %v", leftovers)
	}
	removed, err := RemoveUnit("alpha", destDir)
	if err != nil {
		t.Fatalf("RemoveUnit: %v", err)
	}
	if len(removed) != 3 {
		t.Fatalf("RemoveUnit removed %v, want 3 paths", removed)
	}
	for _, path := range want {
		if _, err := os.Stat(path); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("%s still exists", path)
		}
	}
	if removed, err := RemoveUnit("alpha", destDir); err != nil || len(removed) != 0 {
		t.Errorf("second RemoveUnit = %v, %v; want no paths and no error", removed, err)
	}

	// Refusals.
	if _, err := InstallUnit(ctx, alphaSpec(), "relative"); err == nil {
		t.Error("InstallUnit accepted a relative unit directory")
	}
	if _, err := RemoveUnit("bad/id", destDir); err == nil {
		t.Error("RemoveUnit accepted an invalid id")
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := InstallUnit(cancelled, alphaSpec(), destDir); err == nil {
		t.Error("InstallUnit accepted a cancelled context")
	}
}

func TestWriteCredential(t *testing.T) {
	base := t.TempDir()
	dir := filepath.Join(base, "creds")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	r, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Close() }()
	token := []byte(strings.Repeat("a1", 32))
	name, err := WriteCredential(r, "alpha", token)
	if err != nil {
		t.Fatalf("WriteCredential: %v", err)
	}
	if name != "alpha.token" {
		t.Errorf("name = %q, want alpha.token", name)
	}
	path := filepath.Join(dir, name)
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != CredentialFileMode {
		t.Errorf("mode = %o, want %o", fi.Mode().Perm(), CredentialFileMode)
	}
	di, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if di.Mode().Perm() != CredentialDirMode {
		t.Errorf("dir mode = %o, want %o", di.Mode().Perm(), CredentialDirMode)
	}
	if got, _ := os.ReadFile(path); string(got) != string(token) {
		t.Errorf("credential content = %q", got)
	}
	for _, c := range []struct {
		name  string
		token []byte
	}{
		{"short", []byte("short")},
		{"too long", []byte(strings.Repeat("a", MaxTokenLen+1))},
		{"newline", []byte(strings.Repeat("a", 63) + "\n")},
		{"space", []byte(strings.Repeat("a", 32) + " " + strings.Repeat("a", 32))},
		{"nul", append([]byte(strings.Repeat("a", 31)), 0)},
	} {
		if _, err := WriteCredential(r, "alpha", c.token); err == nil {
			t.Errorf("%s: WriteCredential accepted the token", c.name)
		}
	}
	if _, err := WriteCredential(r, "bad/id", token); err == nil {
		t.Error("WriteCredential accepted an invalid id")
	}
}

func TestVerifyEntrypoint(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	entry := filepath.Join(dir, "bin", "plugin")
	if err := os.WriteFile(entry, []byte("#!/bin/true\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	digest, err := pkgfile.DigestFile(dir, "bin/plugin")
	if err != nil {
		t.Fatalf("DigestFile: %v", err)
	}
	if err := VerifyEntrypoint(dir, "bin/plugin", digest); err != nil {
		t.Fatalf("VerifyEntrypoint: %v", err)
	}
	if err := VerifyEntrypoint(dir, "bin/plugin", "sha256:"+strings.Repeat("0", 64)); err == nil {
		t.Error("VerifyEntrypoint accepted a wrong digest")
	}
	if err := VerifyEntrypoint(dir, "bin/missing", digest); err == nil {
		t.Error("VerifyEntrypoint accepted a missing entrypoint")
	}
	for _, ep := range []string{"../etc/passwd", "/bin/plugin", "bin/sub/plugin", "plugin", ""} {
		if err := VerifyEntrypoint(dir, ep, digest); err == nil {
			t.Errorf("VerifyEntrypoint accepted entrypoint %q", ep)
		}
	}
	for _, d := range []string{"sha256:abc", strings.Repeat("a", 64), "sha256:" + strings.Repeat("A", 64)} {
		if err := VerifyEntrypoint(dir, "bin/plugin", d); err == nil {
			t.Errorf("VerifyEntrypoint accepted digest %q", d)
		}
	}
	// A directory is not an entrypoint.
	if err := os.MkdirAll(filepath.Join(dir, "bin", "dirplugin"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := VerifyEntrypoint(dir, "bin/dirplugin", digest); err == nil {
		t.Error("VerifyEntrypoint accepted a directory as entrypoint")
	}
	// A symlinked version directory is refused before the digest check.
	link := filepath.Join(t.TempDir(), "version")
	if err := os.Symlink(dir, link); err != nil {
		t.Fatal(err)
	}
	if err := VerifyEntrypoint(link, "bin/plugin", digest); err == nil {
		t.Error("VerifyEntrypoint accepted a symlinked version directory")
	}
}

func TestPluginGroups(t *testing.T) {
	ctx := context.Background()
	fr := &fakeRunner{}
	if err := CreatePluginGroup(ctx, fr, "qwq-p-alpha"); err != nil {
		t.Fatalf("CreatePluginGroup: %v", err)
	}
	if !fr.has("groupadd", "--system", "--force", "qwq-p-alpha") {
		t.Errorf("groupadd was not called with --system --force: %v", fr.calls)
	}
	if err := RemovePluginGroup(ctx, fr, "qwq-p-alpha"); err != nil {
		t.Fatalf("RemovePluginGroup: %v", err)
	}
	if !fr.has("groupdel", "qwq-p-alpha") {
		t.Errorf("groupdel was not called: %v", fr.calls)
	}

	// groupdel fails because the group is already gone: getent fails too.
	absent := &fakeRunner{reply: func(name string, _ []string) (string, error) {
		return "", errors.New("not found")
	}}
	if err := RemovePluginGroup(ctx, absent, "qwq-p-alpha"); err != nil {
		t.Errorf("RemovePluginGroup on an absent group = %v", err)
	}
	// groupdel fails and the group still exists: report the failure.
	busy := &fakeRunner{reply: func(name string, _ []string) (string, error) {
		if name == "groupdel" {
			return "group is in use", errors.New("exit status 3")
		}
		return "qwq-p-alpha:x:999:", nil
	}}
	if err := RemovePluginGroup(ctx, busy, "qwq-p-alpha"); err == nil {
		t.Error("RemovePluginGroup ignored a failed groupdel while the group still exists")
	}

	bad := &fakeRunner{}
	if err := CreatePluginGroup(ctx, bad, "bad group"); err == nil {
		t.Error("CreatePluginGroup accepted an invalid group name")
	}
	if err := RemovePluginGroup(ctx, bad, strings.Repeat("g", 33)); err == nil {
		t.Error("RemovePluginGroup accepted a 33-character group name")
	}
	if bad.count() != 0 {
		t.Errorf("invalid names reached the runner: %v", bad.calls)
	}
}

// installerFixture builds an Installer with temporary paths and an existing
// runtime base.
func installerFixture(t *testing.T) (Installer, *fakeRunner, string) {
	t.Helper()
	root := t.TempDir()
	runtimeBase := filepath.Join(root, "run")
	// tmpfiles creates /run/qwq and the qwq-owned /run/qwq/host on a real host.
	if err := os.MkdirAll(filepath.Join(runtimeBase, runtimeDirName, hostDirName), 0o750); err != nil {
		t.Fatal(err)
	}
	// tmpfiles creates the persistent credential directory as well.
	if err := os.Mkdir(filepath.Join(root, "creds"), 0o700); err != nil {
		t.Fatal(err)
	}
	fr := &fakeRunner{}
	in := Installer{
		CredDir:     filepath.Join(root, "creds"),
		UnitDir:     filepath.Join(root, "systemd"),
		TmpfilesDir: filepath.Join(root, "tmpfiles"),
		RuntimeBase: runtimeBase,
		AgentUser:   DefaultAgentUser,
		Runner:      fr,
		Trust:       testTrust(root),
		LookupIDs:   currentIDs,
	}
	return in, fr, root
}

func TestInstallerInstallAndRemove(t *testing.T) {
	ctx := context.Background()
	in, fr, root := installerFixture(t)
	token := []byte(strings.Repeat("ab", 32))
	res, err := in.Install(ctx, alphaSpec(), token)
	if err != nil {
		t.Fatalf("Install: %v", err)
	}
	if res.ID != "alpha" || res.Group != "qwq-p-alpha" {
		t.Errorf("result = %+v", res)
	}
	if len(res.UnitFiles) != 3 {
		t.Errorf("UnitFiles = %v", res.UnitFiles)
	}
	if !fr.has("groupadd", "--system", "--force", "qwq-p-alpha") {
		t.Errorf("Install did not create the group: %v", fr.calls)
	}
	for _, path := range append(append([]string{}, res.UnitFiles...), res.Tmpfiles, res.Credential) {
		if !strings.HasPrefix(path, root) {
			t.Errorf("%s escaped the temporary root", path)
		}
		if _, err := os.Stat(path); err != nil {
			t.Errorf("stat %s: %v", path, err)
		}
	}
	if fi, err := os.Stat(res.Credential); err != nil || fi.Mode().Perm() != CredentialFileMode {
		t.Errorf("credential mode = %v, %v", fi.Mode().Perm(), err)
	}
	if got, _ := os.ReadFile(res.Credential); string(got) != string(token) {
		t.Errorf("credential content = %q", got)
	}
	tmpfiles, err := os.ReadFile(res.Tmpfiles)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"d " + filepath.Join(in.RuntimeBase, "qwq", "plugin") + " 0711 root root -",
		"d " + filepath.Join(in.RuntimeBase, "qwq", "plugin", "alpha") + " 0711 root root -",
		"d " + filepath.Join(in.RuntimeBase, "qwq", "link") + " 0711 root root -",
		"d " + filepath.Join(in.RuntimeBase, "qwq", "host", "alpha") + " 2750 qwq qwq-p-alpha -",
	} {
		if !strings.Contains(string(tmpfiles), want+"\n") {
			t.Errorf("tmpfiles is missing %q:\n%s", want, tmpfiles)
		}
	}
	for _, d := range []struct {
		path string
		mode fs.FileMode
	}{
		{filepath.Join(in.RuntimeBase, "qwq", "plugin"), RuntimeDirMode},
		{filepath.Join(in.RuntimeBase, "qwq", "plugin", "alpha"), RuntimeDirMode},
		{filepath.Join(in.RuntimeBase, "qwq", "link"), RuntimeDirMode},
	} {
		fi, err := os.Stat(d.path)
		if err != nil {
			t.Errorf("stat %s: %v", d.path, err)
			continue
		}
		if fi.Mode().Perm() != d.mode {
			t.Errorf("%s mode = %o, want %o", d.path, fi.Mode().Perm(), d.mode)
		}
	}

	res2, err := in.Remove(ctx, "alpha")
	if err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if len(res2.UnitFiles) != 3 {
		t.Errorf("Remove unit files = %v", res2.UnitFiles)
	}
	if len(res2.Removed) != 4 {
		t.Errorf("Removed = %v, want tmpfiles, token, plugin dir and host dir", res2.Removed)
	}
	if !fr.has("groupdel", "qwq-p-alpha") {
		t.Errorf("Remove did not delete the group: %v", fr.calls)
	}
	for _, path := range append(append([]string{}, res2.UnitFiles...), res2.Removed...) {
		if _, err := os.Stat(path); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("%s still exists", path)
		}
	}
	res3, err := in.Remove(ctx, "alpha")
	if err != nil {
		t.Fatalf("second Remove: %v", err)
	}
	if len(res3.UnitFiles) != 0 || len(res3.Removed) != 0 {
		t.Errorf("second Remove reported %+v", res3)
	}
}

func TestInstallerAgentUserPropagates(t *testing.T) {
	in, _, _ := installerFixture(t)
	in.AgentUser = "qwq-agent"
	if _, err := in.Install(context.Background(), alphaSpec(), nil); err != nil {
		t.Fatalf("Install: %v", err)
	}
	b, err := os.ReadFile(filepath.Join(in.UnitDir, "qwq-plugin@alpha.socket"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "SocketUser=qwq-agent\n") {
		t.Errorf("socket unit did not use the installer agent user:\n%s", b)
	}
}

func TestInstallerRejectsBeforeWriting(t *testing.T) {
	ctx := context.Background()
	in, fr, _ := installerFixture(t)

	// The runtime base exists but /run/qwq was never created.
	broken := in
	broken.RuntimeBase = filepath.Join(t.TempDir(), "run")
	if _, err := broken.Install(ctx, alphaSpec(), nil); err == nil || !strings.Contains(err.Error(), "systemd-tmpfiles") {
		t.Errorf("Install without a runtime directory = %v", err)
	}

	// A bad credential is rejected before any directory or group is touched.
	if _, err := in.Install(ctx, alphaSpec(), []byte("short")); err == nil {
		t.Error("Install accepted a short credential")
	}
	if fr.count() != 0 {
		t.Errorf("a rejected credential reached the runner: %v", fr.calls)
	}

	// A newline in the id never reaches a unit file.
	spec := alphaSpec()
	spec.ID = "alpha\nExecStart=/bin/sh"
	if _, err := in.Install(ctx, spec, nil); err == nil {
		t.Error("Install accepted an id with a newline")
	}
	if fr.count() != 0 {
		t.Errorf("a rejected spec reached the runner: %v", fr.calls)
	}
	if _, err := os.Stat(filepath.Join(in.UnitDir, "qwq-plugin@alpha.service")); !errors.Is(err, fs.ErrNotExist) {
		t.Error("Install wrote a unit file for a rejected spec")
	}
}
