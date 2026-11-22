// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/qwq-panel/qwq/internal/platform/problem"
	"github.com/qwq-panel/qwq/internal/pluginhost/install"
	"github.com/qwq-panel/qwq/internal/sandbox"
)

// cmdCall records one external command the helper ran.
type cmdCall struct {
	name string
	args []string
}

// fakeRunner implements sandbox.Runner for the shadow tools and systemctl.
// Tests never need root, systemd or the shadow tools.
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
	return defaultReply(name, args)
}

// defaultReply answers as a healthy host would: no running unit, commands
// succeed.
func defaultReply(name string, args []string) (string, error) {
	if name == "systemctl" && len(args) > 0 && args[0] == "show" {
		return "MainPID=0\n", nil
	}
	return "", nil
}

func (f *fakeRunner) has(name string, args ...string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, call := range f.calls {
		if call.name != name || len(call.args) != len(args) {
			continue
		}
		match := true
		for i := range args {
			if call.args[i] != args[i] {
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

// testHost builds a helper server whose privileged paths all live in a
// temporary directory.
type testHost struct {
	cfg    helperConfig
	server *helperServer
	runner *fakeRunner
}

func newTestHost(t *testing.T) *testHost {
	t.Helper()
	root := t.TempDir()
	cfg := helperConfig{
		Socket:          filepath.Join(root, "run", "helper.sock"),
		UnitDir:         filepath.Join(root, "systemd"),
		TmpfilesDir:     filepath.Join(root, "tmpfiles"),
		RuntimeBase:     filepath.Join(root, "run"),
		CredDir:         filepath.Join(root, "creds"),
		PluginsRoot:     filepath.Join(root, "plugins"),
		DataRoot:        filepath.Join(root, "plugin-data"),
		PrivateDataRoot: filepath.Join(root, "private", "plugin-data"),
		StagingRoot:     filepath.Join(root, "staging"),
		AgentUser:       "qwq",
		SocketGroup:     "qwq",
		Version:         "test",
		Trust:           sandbox.TrustPolicy{UID: os.Getuid(), StopAt: root},
	}
	// sandbox.Installer requires <runtime base>/qwq to exist (tmpfiles creates
	// it on a real host).
	if err := os.MkdirAll(filepath.Join(cfg.RuntimeBase, "qwq", "host"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(cfg.CredDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(cfg.PluginsRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(cfg.StagingRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	runner := &fakeRunner{}
	server, err := newHelperServer(cfg, runner, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatalf("newHelperServer: %v", err)
	}
	// The agent user and the plugin group do not exist on a build host.
	server.installer.LookupIDs = func(string, string) (int, int, error) { return os.Getuid(), os.Getgid(), nil }
	server.lookupUID = func(string) (int, error) { return os.Getuid(), nil }
	// A published tree is 0555/0444; make the temporary roots writable again
	// before t.TempDir removes them, so a non-root test run can clean up.
	t.Cleanup(func() {
		relaxTree(root)
	})
	return &testHost{cfg: cfg, server: server, runner: runner}
}

// relaxTree removes the read-only modes of a published version tree without
// following symlinks (which would otherwise chmod target directories to 0600).
func relaxTree(root string) {
	_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil //nolint:nilerr // best effort cleanup
		}
		if d.Type()&fs.ModeSymlink != 0 {
			return nil
		}
		if d.IsDir() {
			_ = os.Chmod(path, 0o700)
		} else {
			_ = os.Chmod(path, 0o600)
		}
		return nil
	})
}

// stagedFile is one file of a fake staged package.
type stagedFile struct {
	content string
	mode    fs.FileMode
}

// addStaged creates one .staging-* directory below the configured staging root.
func (h *testHost) addStaged(t *testing.T, files map[string]stagedFile) string {
	t.Helper()
	dir, err := os.MkdirTemp(h.cfg.StagingRoot, install.StagingPrefix)
	if err != nil {
		t.Fatal(err)
	}
	for name, file := range files {
		path := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(file.content), file.mode); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// publishRequest is the wire form of a valid publish request.
func (h *testHost) publishRequest(stagedDir, id, version string) sandbox.HelperRequest {
	return sandbox.HelperRequest{
		Op:         sandbox.HelperOpPublish,
		StagedDir:  stagedDir,
		VersionDir: filepath.Join(h.cfg.PluginsRoot, id, version),
		PluginID:   id,
		Version:    version,
	}
}

// addVersion creates an installed version directory.
func (h *testHost) addVersion(t *testing.T, id, version string) string {
	t.Helper()
	dir := filepath.Join(h.cfg.PluginsRoot, id, version)
	if err := os.MkdirAll(filepath.Join(dir, "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "bin", "plugin"), []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	return dir
}

// specFor returns a valid unit spec for versionDir.
func specFor(id, versionDir string) sandbox.UnitSpec {
	return sandbox.UnitSpec{
		ID:         id,
		VersionDir: versionDir,
		Entrypoint: "bin/plugin",
		Digest:     "sha256:" + strings.Repeat("a", 64),
		Limits:     &sandbox.Limits{MemoryMaxMB: 32, CPUQuotaPercent: 20, PIDsMax: 16, FDsMax: 128},
	}
}

func token() []byte { return []byte(strings.Repeat("ab", 32)) }

// installRequest is the wire form of a valid install request.
func installRequest(spec sandbox.UnitSpec, credential []byte) sandbox.HelperRequest {
	req := sandbox.HelperRequest{Op: sandbox.HelperOpInstall, Spec: &spec}
	if credential != nil {
		req.CredentialBase64 = base64.StdEncoding.EncodeToString(credential)
	}
	return req
}

func TestInstallWritesArtifacts(t *testing.T) {
	h := newTestHost(t)
	versionDir := h.addVersion(t, "alpha", "1.2.3")
	resp := h.server.handle(context.Background(), installRequest(specFor("alpha", versionDir), token()))
	if !resp.OK {
		t.Fatalf("install failed: %+v", resp)
	}
	if resp.Install == nil || resp.Install.ID != "alpha" || resp.Install.Group != "qwq-p-alpha" {
		t.Fatalf("install result = %+v", resp.Install)
	}
	if len(resp.Install.UnitFiles) != 3 {
		t.Errorf("unit files = %v", resp.Install.UnitFiles)
	}
	if len(resp.Warnings) != 0 {
		t.Errorf("warnings = %v", resp.Warnings)
	}
	service := filepath.Join(h.cfg.UnitDir, "qwq-plugin@alpha.service")
	data, err := os.ReadFile(service)
	if err != nil {
		t.Fatalf("reading the rendered service: %v", err)
	}
	wantExec := "ExecStart=" + filepath.Join(versionDir, "bin/plugin") + "\n"
	if !strings.Contains(string(data), wantExec) {
		t.Errorf("service does not pin %q:\n%s", wantExec, data)
	}
	credential := filepath.Join(h.cfg.CredDir, "alpha.token")
	tokenData, err := os.ReadFile(credential)
	if err != nil {
		t.Fatalf("reading the credential: %v", err)
	}
	if string(tokenData) != string(token()) {
		t.Errorf("credential = %q", tokenData)
	}
	if fi, err := os.Stat(credential); err != nil {
		t.Fatalf("stating the credential: %v", err)
	} else if fi.Mode().Perm() != 0o600 {
		t.Errorf("credential mode = %o, want 0600", fi.Mode().Perm())
	}
	// The response reports paths, never the token itself.
	encoded, jerr := json.Marshal(resp)
	if jerr != nil {
		t.Fatalf("marshalling the response: %v", jerr)
	}
	if strings.Contains(string(encoded), string(token())) {
		t.Error("the install response contains the plugin credential")
	}
	for _, call := range []struct {
		name string
		args []string
	}{
		{"groupadd", []string{"--system", "--force", "qwq-p-alpha"}},
		{"systemctl", []string{"daemon-reload"}},
		{"systemctl", []string{"enable", "--now", "qwq-plugin@alpha.socket"}},
	} {
		if !h.runner.has(call.name, call.args...) {
			t.Errorf("the helper did not run %s %v", call.name, call.args)
		}
	}
}

// TestInstallRendersHostPolicyFields exercises the full helper path with the
// host-computed policy fields (X1 network relaxation, X2 data directory): the
// rendered unit carries exactly the reviewed relaxations and the default
// sandbox otherwise. A reinstall of the same spec must produce the same bytes.
func TestInstallRendersHostPolicyFields(t *testing.T) {
	h := newTestHost(t)
	versionDir := h.addVersion(t, "alpha", "1.2.3")
	spec := specFor("alpha", versionDir)
	spec.NetworkProxyDirect = true
	spec.DataDir = "/var/lib/qwq-plugin-data/alpha/default"
	resp := h.server.handle(context.Background(), installRequest(spec, token()))
	if !resp.OK {
		t.Fatalf("install failed: %+v", resp)
	}
	service := filepath.Join(h.cfg.UnitDir, "qwq-plugin@alpha.service")
	data, err := os.ReadFile(service)
	if err != nil {
		t.Fatalf("reading the rendered service: %v", err)
	}
	for _, want := range []string{
		"PrivateNetwork=no\n",
		"RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6\n",
		"StateDirectory=qwq-plugin-data/alpha/default\n",
		"StateDirectoryMode=0700\n",
		"DynamicUser=yes\n",
		"CapabilityBoundingSet=\n",
	} {
		if !strings.Contains(string(data), want) {
			t.Errorf("rendered service is missing %q:\n%s", want, data)
		}
	}
	// Reinstalling the identical spec re-renders byte-identical units.
	before := string(data)
	if resp2 := h.server.handle(context.Background(), installRequest(spec, token())); !resp2.OK {
		t.Fatalf("reinstall failed: %+v", resp2)
	}
	if data2, err := os.ReadFile(service); err != nil || string(data2) != before {
		t.Fatalf("reinstall changed the rendered unit (err=%v)", err)
	}
}

func TestPublishCopiesStagedTree(t *testing.T) {
	h := newTestHost(t)
	staged := h.addStaged(t, map[string]stagedFile{
		"manifest.json": {"{}", 0o644},
		"bin/plugin":    {"#!/bin/sh\n", 0o755},
	})
	// install.Extract finalizes the staging tree to 0555/0444 before publish.
	for _, dir := range []string{staged, filepath.Join(staged, "bin")} {
		if err := os.Chmod(dir, 0o555); err != nil {
			t.Fatal(err)
		}
	}
	resp := h.server.handle(context.Background(), h.publishRequest(staged, "alpha", "1.2.3"))
	if !resp.OK || resp.Publish == nil {
		t.Fatalf("publish failed: %+v", resp)
	}
	versionDir := filepath.Join(h.cfg.PluginsRoot, "alpha", "1.2.3")
	if resp.Publish.ID != "alpha" || resp.Publish.Version != "1.2.3" ||
		resp.Publish.VersionDir != versionDir || resp.Publish.Existing {
		t.Errorf("publish result = %+v", resp.Publish)
	}
	if resp.Publish.Files != 2 || resp.Publish.Dirs != 1 {
		t.Errorf("publish counted files=%d dirs=%d, want 2/1", resp.Publish.Files, resp.Publish.Dirs)
	}
	for path, want := range map[string]struct {
		mode fs.FileMode
		body string
	}{
		versionDir:                                 {0o555, ""},
		filepath.Join(versionDir, "bin"):           {0o555, ""},
		filepath.Join(versionDir, "bin/plugin"):    {0o555, "#!/bin/sh\n"},
		filepath.Join(versionDir, "manifest.json"): {0o444, "{}"},
	} {
		fi, err := os.Stat(path)
		if err != nil {
			t.Fatalf("stat %s: %v", path, err)
		}
		if fi.Mode().Perm() != want.mode {
			t.Errorf("%s mode = %o, want %o", path, fi.Mode().Perm(), want.mode)
		}
		if want.body != "" {
			if body, err := os.ReadFile(path); err != nil || string(body) != want.body {
				t.Errorf("%s content = %q, %v", path, body, err)
			}
		}
	}
	if fi, err := os.Stat(filepath.Join(h.cfg.PluginsRoot, "alpha")); err != nil {
		t.Errorf("plugin parent: %v", err)
	} else if !fi.IsDir() || fi.Mode().Perm()&0o400 == 0 {
		t.Errorf("plugin parent = %v", fi.Mode())
	}
	// The helper only reads the staging tree; the controller discards it.
	if _, err := os.Stat(staged); err != nil {
		t.Errorf("publish removed the staging tree: %v", err)
	}
}

func TestPublishIsIdempotentAndDetectsContentChange(t *testing.T) {
	h := newTestHost(t)
	staged := h.addStaged(t, map[string]stagedFile{
		"manifest.json": {"{}", 0o644},
		"bin/plugin":    {"#!/bin/sh\n", 0o755},
	})
	req := h.publishRequest(staged, "alpha", "1.2.3")
	if resp := h.server.handle(context.Background(), req); !resp.OK {
		t.Fatalf("first publish failed: %+v", resp)
	}
	second := h.server.handle(context.Background(), req)
	if !second.OK || second.Publish == nil || !second.Publish.Existing {
		t.Fatalf("second publish = %+v, want an idempotent success", second)
	}
	// A staged tree with different content must not overwrite the immutable
	// version directory.
	manifest := filepath.Join(staged, "manifest.json")
	if err := os.Chmod(manifest, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(manifest, []byte(`{"changed":true}`), 0o644); err != nil {
		t.Fatal(err)
	}
	third := h.server.handle(context.Background(), req)
	if third.OK || third.Code != string(problem.PreconditionFailed) {
		t.Fatalf("third publish = %+v, want PRECONDITION_FAILED", third)
	}
	body, err := os.ReadFile(filepath.Join(h.cfg.PluginsRoot, "alpha", "1.2.3", "manifest.json"))
	if err != nil || string(body) != "{}" {
		t.Errorf("published content changed to %q (%v)", body, err)
	}
}

func TestPublishRejectsBadPaths(t *testing.T) {
	h := newTestHost(t)
	staged := h.addStaged(t, map[string]stagedFile{"manifest.json": {"{}", 0o644}})
	outside := filepath.Join(filepath.Dir(h.cfg.StagingRoot), "outside")
	if err := os.MkdirAll(outside, 0o700); err != nil {
		t.Fatal(err)
	}
	nestedParent := filepath.Join(h.cfg.StagingRoot, ".staging-parent")
	nested := filepath.Join(nestedParent, "child")
	if err := os.MkdirAll(nested, 0o700); err != nil {
		t.Fatal(err)
	}
	valid := h.publishRequest(staged, "alpha", "1.2.3")
	cases := map[string]sandbox.HelperRequest{
		"staged outside the staging root": func() sandbox.HelperRequest {
			req := valid
			req.StagedDir = outside
			return req
		}(),
		"staged below a subdirectory": func() sandbox.HelperRequest {
			req := valid
			req.StagedDir = nested
			return req
		}(),
		"staging root itself": func() sandbox.HelperRequest {
			req := valid
			req.StagedDir = h.cfg.StagingRoot
			return req
		}(),
		"missing staging directory": func() sandbox.HelperRequest {
			req := valid
			req.StagedDir = filepath.Join(h.cfg.StagingRoot, ".staging-missing")
			return req
		}(),
		"wrong version directory": func() sandbox.HelperRequest {
			req := valid
			req.VersionDir = filepath.Join(h.cfg.PluginsRoot, "beta", "1.2.3")
			return req
		}(),
		"relative version directory": func() sandbox.HelperRequest {
			req := valid
			req.VersionDir = "plugins/alpha/1.2.3"
			return req
		}(),
		"path traversal id": func() sandbox.HelperRequest {
			req := valid
			req.PluginID = "../alpha"
			return req
		}(),
		"path traversal version": func() sandbox.HelperRequest {
			req := valid
			req.Version = "../1.2.3"
			return req
		}(),
	}
	for name, req := range cases {
		resp := h.server.handle(context.Background(), req)
		if resp.OK || resp.Code != string(problem.ValidationFailed) {
			t.Errorf("%s: response = %+v, want VALIDATION_FAILED", name, resp)
		}
	}
	if _, err := os.Stat(filepath.Join(h.cfg.PluginsRoot, "alpha")); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("a rejected publish created the version tree: %v", err)
	}
}

func TestPublishRejectsSymlinkedPluginParent(t *testing.T) {
	h := newTestHost(t)
	staged := h.addStaged(t, map[string]stagedFile{"manifest.json": {"{}", 0o644}})
	target := t.TempDir()
	if err := os.Symlink(target, filepath.Join(h.cfg.PluginsRoot, "alpha")); err != nil {
		t.Skipf("symlinks are not available: %v", err)
	}
	resp := h.server.handle(context.Background(), h.publishRequest(staged, "alpha", "1.2.3"))
	if resp.OK || resp.Code != string(problem.PreconditionFailed) {
		t.Errorf("response = %+v, want PRECONDITION_FAILED", resp)
	}
	if _, err := os.Stat(filepath.Join(target, "1.2.3")); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("publish wrote through the symlinked plugin parent: %v", err)
	}
}

func TestPublishRequiresPluginsRoot(t *testing.T) {
	h := newTestHost(t)
	staged := h.addStaged(t, map[string]stagedFile{"manifest.json": {"{}", 0o644}})
	if err := os.RemoveAll(h.cfg.PluginsRoot); err != nil {
		t.Fatal(err)
	}
	resp := h.server.handle(context.Background(), h.publishRequest(staged, "alpha", "1.2.3"))
	if resp.OK || resp.Code != string(problem.Unavailable) {
		t.Fatalf("response = %+v, want UNAVAILABLE", resp)
	}
}

func TestInstallRejectsInvalidRequests(t *testing.T) {
	h := newTestHost(t)
	versionDir := h.addVersion(t, "alpha", "1.2.3")
	otherDir := h.addVersion(t, "beta", "1.2.3")
	valid := specFor("alpha", versionDir)
	mutate := func(f func(*sandbox.UnitSpec)) sandbox.UnitSpec {
		spec := valid
		f(&spec)
		return spec
	}
	bad := map[string]sandbox.HelperRequest{
		"missing spec": {Op: sandbox.HelperOpInstall},
		"relative version dir": installRequest(mutate(func(s *sandbox.UnitSpec) {
			s.VersionDir = "plugins/alpha/1.2.3"
		}), nil),
		"unclean version dir": installRequest(mutate(func(s *sandbox.UnitSpec) {
			s.VersionDir = h.cfg.PluginsRoot + "/../plugins/alpha/1.2.3"
		}), nil),
		"version dir outside the root": installRequest(mutate(func(s *sandbox.UnitSpec) {
			s.VersionDir = "/var/lib/qwq-plugins/alpha/1.2.3"
		}), nil),
		"version dir below another plugin": installRequest(specFor("alpha", otherDir), nil),
		"agent user not allowed": installRequest(mutate(func(s *sandbox.UnitSpec) {
			s.AgentUser = "root"
		}), nil),
		"foreign runtime base": installRequest(mutate(func(s *sandbox.UnitSpec) {
			s.RuntimeBase = "/run"
		}), nil),
		"entrypoint traversal": installRequest(mutate(func(s *sandbox.UnitSpec) {
			s.Entrypoint = "../bin/plugin"
			s.Executable = filepath.Join(filepath.Dir(versionDir), "bin/plugin")
		}), nil),
		"bad digest": installRequest(mutate(func(s *sandbox.UnitSpec) {
			s.Digest = "sha256:not-hex"
		}), nil),
		"limits out of range": installRequest(mutate(func(s *sandbox.UnitSpec) {
			s.Limits = &sandbox.Limits{MemoryMaxMB: 1, CPUQuotaPercent: 20, PIDsMax: 16, FDsMax: 128}
		}), nil),
		"bad credential base64": {
			Op:               sandbox.HelperOpInstall,
			Spec:             &valid,
			CredentialBase64: "!!!not-base64!!!",
		},
		"credential too short": {
			Op:               sandbox.HelperOpInstall,
			Spec:             &valid,
			CredentialBase64: base64.StdEncoding.EncodeToString([]byte("short")),
		},
		"credential with spaces": {
			Op:               sandbox.HelperOpInstall,
			Spec:             &valid,
			CredentialBase64: base64.StdEncoding.EncodeToString([]byte(strings.Repeat(" ", 64))),
		},
	}
	for name, req := range bad {
		resp := h.server.handle(context.Background(), req)
		if resp.OK || resp.Code != string(problem.ValidationFailed) {
			t.Errorf("%s: response = %+v, want VALIDATION_FAILED", name, resp)
		}
	}
	if entries, err := os.ReadDir(h.cfg.UnitDir); err == nil && len(entries) != 0 {
		t.Errorf("a rejected install wrote %d unit files", len(entries))
	}
	if !strings.Contains(string(mustRead(t, filepath.Join(otherDir, "bin", "plugin"))), "sh") {
		t.Error("a rejected install disturbed another plugin version")
	}
}

func TestInstallEnableFailureIsWarning(t *testing.T) {
	h := newTestHost(t)
	versionDir := h.addVersion(t, "alpha", "1.2.3")
	h.runner.reply = func(name string, args []string) (string, error) {
		if name == "systemctl" && len(args) > 1 && args[0] == "enable" {
			return "Job for qwq-plugin@alpha.socket failed", errors.New("exit status 1")
		}
		return defaultReply(name, args)
	}
	resp := h.server.handle(context.Background(), installRequest(specFor("alpha", versionDir), nil))
	if !resp.OK {
		t.Fatalf("enable failure made the install fail: %+v", resp)
	}
	if len(resp.Warnings) != 1 || !strings.Contains(resp.Warnings[0], "could not be enabled") {
		t.Errorf("warnings = %v", resp.Warnings)
	}
	if _, err := os.Stat(filepath.Join(h.cfg.UnitDir, "qwq-plugin@alpha.service")); err != nil {
		t.Errorf("the unit was not written: %v", err)
	}
}

func TestInstallDaemonReloadFailureIsError(t *testing.T) {
	h := newTestHost(t)
	versionDir := h.addVersion(t, "alpha", "1.2.3")
	h.runner.reply = func(name string, args []string) (string, error) {
		if name == "systemctl" && len(args) == 1 && args[0] == "daemon-reload" {
			return "Failed to reload daemon", errors.New("exit status 1")
		}
		return defaultReply(name, args)
	}
	resp := h.server.handle(context.Background(), installRequest(specFor("alpha", versionDir), nil))
	if resp.OK || resp.Code != string(problem.Internal) {
		t.Fatalf("response = %+v, want INTERNAL", resp)
	}
	if _, err := os.Stat(filepath.Join(h.cfg.UnitDir, "qwq-plugin@alpha.service")); err != nil {
		t.Errorf("the unit should already be written before daemon-reload: %v", err)
	}
}

func TestRemoveRemovesUnitsAndVersion(t *testing.T) {
	h := newTestHost(t)
	versionDir := h.addVersion(t, "alpha", "1.2.3")
	if resp := h.server.handle(context.Background(), installRequest(specFor("alpha", versionDir), token())); !resp.OK {
		t.Fatalf("install failed: %+v", resp)
	}
	req := sandbox.HelperRequest{
		Op:      sandbox.HelperOpRemove,
		ID:      "alpha",
		Version: "1.2.3",
		Paths:   []string{versionDir},
	}
	resp := h.server.handle(context.Background(), req)
	if !resp.OK || resp.Remove == nil {
		t.Fatalf("remove failed: %+v", resp)
	}
	if resp.Remove.ID != "alpha" || resp.Remove.Group != "qwq-p-alpha" {
		t.Errorf("remove result = %+v", resp.Remove)
	}
	for _, path := range []string{
		filepath.Join(h.cfg.UnitDir, "qwq-plugin@alpha.service"),
		filepath.Join(h.cfg.UnitDir, "qwq-plugin@alpha.socket"),
		filepath.Join(h.cfg.TmpfilesDir, "qwq-plugin-alpha.conf"),
		filepath.Join(h.cfg.CredDir, "alpha.token"),
		versionDir,
		filepath.Join(h.cfg.PluginsRoot, "alpha"),
	} {
		if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%s still exists", path)
		}
	}
	if !h.runner.has("groupdel", "qwq-p-alpha") {
		t.Error("the helper did not delete the plugin group")
	}
	if !h.runner.has("systemctl", "disable", "--now", "qwq-plugin@alpha.socket") {
		t.Error("the helper did not disable the plugin socket")
	}
	// Idempotent: the second remove succeeds and reports nothing.
	again := h.server.handle(context.Background(), req)
	if !again.OK {
		t.Fatalf("second remove failed: %+v", again)
	}
	if len(again.Remove.Removed) != 0 {
		t.Errorf("second remove reported %v", again.Remove.Removed)
	}
}

func TestRemoveDisableFailureIsWarning(t *testing.T) {
	h := newTestHost(t)
	versionDir := h.addVersion(t, "alpha", "1.2.3")
	if resp := h.server.handle(context.Background(), installRequest(specFor("alpha", versionDir), nil)); !resp.OK {
		t.Fatalf("install failed: %+v", resp)
	}
	h.runner.reply = func(name string, args []string) (string, error) {
		if name == "systemctl" && len(args) > 1 && args[0] == "disable" {
			return "Failed to disable unit", errors.New("exit status 1")
		}
		return defaultReply(name, args)
	}
	resp := h.server.handle(context.Background(), sandbox.HelperRequest{
		Op: sandbox.HelperOpRemove, ID: "alpha", Version: "1.2.3", Paths: []string{versionDir},
	})
	if !resp.OK {
		t.Fatalf("a disable failure made the remove fail: %+v", resp)
	}
	if len(resp.Warnings) != 1 || !strings.Contains(resp.Warnings[0], "could not be disabled") {
		t.Errorf("warnings = %v", resp.Warnings)
	}
	if _, err := os.Stat(filepath.Join(h.cfg.UnitDir, "qwq-plugin@alpha.service")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the unit was not removed: %v", err)
	}
}

func TestRemoveKeepsUnitsForAnotherVersion(t *testing.T) {
	h := newTestHost(t)
	versionDir := h.addVersion(t, "alpha", "1.2.3")
	h.addVersion(t, "alpha", "1.2.4")
	if resp := h.server.handle(context.Background(), installRequest(specFor("alpha", versionDir), nil)); !resp.OK {
		t.Fatalf("install failed: %+v", resp)
	}
	resp := h.server.handle(context.Background(), sandbox.HelperRequest{
		Op: sandbox.HelperOpRemove, ID: "alpha", Version: "1.2.3",
		Paths: []string{versionDir}, KeepUnit: true,
	})
	if !resp.OK {
		t.Fatalf("remove failed: %+v", resp)
	}
	if _, err := os.Stat(filepath.Join(h.cfg.UnitDir, "qwq-plugin@alpha.service")); err != nil {
		t.Errorf("the unit was removed while another version remains: %v", err)
	}
	if _, err := os.Stat(versionDir); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the version directory still exists: %v", err)
	}
	if h.runner.has("systemctl", "disable", "--now", "qwq-plugin@alpha.socket") {
		t.Error("the helper disabled the socket while another version remains")
	}
}

func TestRemoveRefusesRunningPlugin(t *testing.T) {
	h := newTestHost(t)
	versionDir := h.addVersion(t, "alpha", "1.2.3")
	if resp := h.server.handle(context.Background(), installRequest(specFor("alpha", versionDir), nil)); !resp.OK {
		t.Fatalf("install failed: %+v", resp)
	}
	h.runner.reply = func(name string, args []string) (string, error) {
		if name == "systemctl" && len(args) > 0 && args[0] == "show" {
			return "MainPID=4242\n", nil
		}
		return defaultReply(name, args)
	}
	resp := h.server.handle(context.Background(), sandbox.HelperRequest{
		Op: sandbox.HelperOpRemove, ID: "alpha", Version: "1.2.3", Paths: []string{versionDir},
	})
	if resp.OK || resp.Code != string(problem.PreconditionFailed) {
		t.Fatalf("response = %+v, want PRECONDITION_FAILED", resp)
	}
	if _, err := os.Stat(filepath.Join(h.cfg.UnitDir, "qwq-plugin@alpha.service")); err != nil {
		t.Errorf("the running unit's file was removed: %v", err)
	}
	if _, err := os.Stat(versionDir); err != nil {
		t.Errorf("the running version directory was removed: %v", err)
	}
}

func TestRemoveRejectsForeignPaths(t *testing.T) {
	h := newTestHost(t)
	h.addVersion(t, "alpha", "1.2.3")
	versionDir := filepath.Join(h.cfg.PluginsRoot, "alpha", "1.2.3")
	bad := []sandbox.HelperRequest{
		{Op: sandbox.HelperOpRemove, ID: "alpha", Version: "1.2.3", Paths: []string{filepath.Join(h.cfg.PluginsRoot, "alpha", "9.9.9")}},
		{Op: sandbox.HelperOpRemove, ID: "alpha", Version: "1.2.3", Paths: []string{"/var/lib/qwq-plugins/alpha/1.2.3"}},
		{Op: sandbox.HelperOpRemove, ID: "alpha", Version: "1.2.3", Paths: []string{"plugins/alpha/1.2.3"}},
		{Op: sandbox.HelperOpRemove, ID: "alpha", Version: "1.2.3", Paths: []string{versionDir, "/etc/passwd"}},
		{Op: sandbox.HelperOpRemove, ID: "alpha", Paths: []string{versionDir}},
		{Op: sandbox.HelperOpRemove, ID: "alpha", Version: "../1.2.3", Paths: []string{versionDir}},
		{Op: sandbox.HelperOpRemove, ID: "../alpha", Version: "1.2.3", Paths: []string{versionDir}},
	}
	for _, req := range bad {
		resp := h.server.handle(context.Background(), req)
		if resp.OK || resp.Code != string(problem.ValidationFailed) {
			t.Errorf("request %+v: response = %+v, want VALIDATION_FAILED", req, resp)
		}
	}
	if _, err := os.Stat(versionDir); err != nil {
		t.Errorf("a rejected remove deleted the version directory: %v", err)
	}
}

func TestReloadPingAndUnknownOperation(t *testing.T) {
	h := newTestHost(t)
	if resp := h.server.handle(context.Background(), sandbox.HelperRequest{Op: sandbox.HelperOpReload}); !resp.OK {
		t.Fatalf("reload failed: %+v", resp)
	}
	if !h.runner.has("systemctl", "daemon-reload") {
		t.Error("reload did not run systemctl daemon-reload")
	}
	ping := h.server.handle(context.Background(), sandbox.HelperRequest{Op: sandbox.HelperOpPing})
	if !ping.OK || ping.Version != "test" || ping.UID != os.Geteuid() {
		t.Errorf("ping = %+v", ping)
	}
	unknown := h.server.handle(context.Background(), sandbox.HelperRequest{Op: "exec"})
	if unknown.OK || unknown.Code != string(problem.ValidationFailed) {
		t.Errorf("unknown operation = %+v", unknown)
	}
}

func TestHandleRecoversFromPanic(t *testing.T) {
	h := newTestHost(t)
	versionDir := h.addVersion(t, "alpha", "1.2.3")
	h.runner.reply = func(name string, args []string) (string, error) {
		if name == "groupadd" {
			panic("boom")
		}
		return defaultReply(name, args)
	}
	resp := h.server.handle(context.Background(), installRequest(specFor("alpha", versionDir), nil))
	if resp.OK || resp.Code != string(problem.Internal) {
		t.Fatalf("response = %+v, want a recovered INTERNAL error", resp)
	}
}

func TestSystemctlAllowlist(t *testing.T) {
	allowed := [][]string{
		{"daemon-reload"},
		{"show", "-p", "MainPID", "qwq-plugin@alpha.service"},
		{"enable", "--now", "qwq-plugin@alpha.socket"},
		{"disable", "--now", "qwq-plugin@alpha.socket"},
	}
	for _, args := range allowed {
		if err := checkSystemctlArgs(args); err != nil {
			t.Errorf("checkSystemctlArgs(%v) = %v, want nil", args, err)
		}
	}
	rejected := [][]string{
		{},
		{"start", "qwq-plugin@alpha.service"},
		{"restart", "qwq-plugin@alpha.service"},
		{"daemon-reload", "extra"},
		{"show", "-p", "MainPID"},
		{"show", "-p", "ActiveState", "qwq-plugin@alpha.service"},
		{"show", "-p", "MainPID", "evil.service"},
		{"show", "-p", "MainPID", "qwq-plugin@../alpha.service"},
		{"enable", "qwq-plugin@alpha.socket"},
		{"enable", "--now", "qwq-plugin@alpha.service"},
		{"enable", "--now", "other.socket"},
		{"disable", "qwq-plugin@alpha.socket"},
		{"disable", "--now", "qwq-plugin@alpha.service"},
	}
	for _, args := range rejected {
		if err := checkSystemctlArgs(args); err == nil {
			t.Errorf("checkSystemctlArgs(%v) accepted the command", args)
		}
	}
}

func TestGroupRunnerAllowlist(t *testing.T) {
	runner := groupRunner{base: &fakeRunner{}}
	ctx := context.Background()
	for _, call := range []struct {
		name string
		args []string
	}{
		{"groupadd", []string{"--system", "--force", "qwq-p-alpha"}},
		{"groupdel", []string{"qwq-p-alpha"}},
		{"getent", []string{"group", "qwq-p-alpha"}},
	} {
		if _, err := runner.Run(ctx, call.name, call.args...); err != nil {
			t.Errorf("%s %v: %v", call.name, call.args, err)
		}
	}
	for _, call := range []struct {
		name string
		args []string
	}{
		{"systemctl", []string{"start", "x.service"}},
		{"groupadd", []string{"--force", "qwq-p-alpha"}},
		{"groupdel", []string{"root"}},
		{"groupdel", []string{"qwq-p-../alpha"}},
		{"getent", []string{"passwd", "root"}},
		{"sh", []string{"-c", "id"}},
	} {
		if _, err := runner.Run(ctx, call.name, call.args...); err == nil {
			t.Errorf("%s %v was accepted", call.name, call.args)
		}
	}
}

func TestHelperProtocolOverSocket(t *testing.T) {
	h := newTestHost(t)
	versionDir := h.addVersion(t, "alpha", "1.2.3")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := os.MkdirAll(filepath.Dir(h.cfg.Socket), 0o750); err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("unix", h.cfg.Socket)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	done := make(chan error, 1)
	go func() { done <- h.server.serve(ctx, ln, false) }()

	client := sandbox.NewHelperClient(h.cfg.Socket)
	ping, err := client.Ping(context.Background())
	if err != nil || ping.Version != "test" {
		t.Fatalf("Ping = %+v, %v", ping, err)
	}
	staged := h.addStaged(t, map[string]stagedFile{"bin/plugin": {"#!/bin/sh\n", 0o755}})
	published, err := client.Publish(context.Background(), sandbox.HelperPublish{
		StagedDir:  staged,
		VersionDir: filepath.Join(h.cfg.PluginsRoot, "beta", "2.0.0"),
		PluginID:   "beta",
		Version:    "2.0.0",
	})
	if err != nil || published.ID != "beta" || published.Files != 1 {
		t.Fatalf("Publish = %+v, %v", published, err)
	}
	if _, err := os.Stat(filepath.Join(h.cfg.PluginsRoot, "beta", "2.0.0", "bin", "plugin")); err != nil {
		t.Fatalf("published file: %v", err)
	}
	res, err := client.Install(context.Background(), specFor("alpha", versionDir), token())
	if err != nil || res.ID != "alpha" {
		t.Fatalf("Install = %+v, %v", res, err)
	}
	removed, err := client.Remove(context.Background(), sandbox.HelperRemove{
		ID: "alpha", Version: "1.2.3", Paths: []string{versionDir},
	})
	if err != nil || removed.ID != "alpha" {
		t.Fatalf("Remove = %+v, %v", removed, err)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("serve returned %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("serve did not stop after cancellation")
	}
}

func TestSocketActivatedServeHandlesOneRequest(t *testing.T) {
	h := newTestHost(t)
	if err := os.MkdirAll(filepath.Dir(h.cfg.Socket), 0o750); err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("unix", h.cfg.Socket)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	done := make(chan error, 1)
	go func() { done <- h.server.serve(context.Background(), ln, true) }()
	client := sandbox.NewHelperClient(h.cfg.Socket)
	if _, err := client.Ping(context.Background()); err != nil {
		t.Fatalf("Ping: %v", err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("one-shot serve returned %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the one-shot activation did not exit after one request")
	}
}

// TestConcurrentRequestLimit checks that one activation never handles more than
// four requests at the same time.
func TestConcurrentRequestLimit(t *testing.T) {
	h := newTestHost(t)
	const clients = 6
	specs := make([]sandbox.UnitSpec, clients)
	for i := range specs {
		id := fmt.Sprintf("alpha%d", i)
		specs[i] = specFor(id, h.addVersion(t, id, "1.0.0"))
	}
	release := make(chan struct{})
	var active, peak int64
	var reachedFour sync.Once
	four := make(chan struct{})
	h.runner.reply = func(name string, args []string) (string, error) {
		if name == "groupadd" {
			cur := atomic.AddInt64(&active, 1)
			defer atomic.AddInt64(&active, -1)
			h.runner.mu.Lock()
			if cur > peak {
				peak = cur
			}
			h.runner.mu.Unlock()
			if cur >= 4 {
				reachedFour.Do(func() { close(four) })
			}
			<-release
		}
		return defaultReply(name, args)
	}
	if err := os.MkdirAll(filepath.Dir(h.cfg.Socket), 0o750); err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("unix", h.cfg.Socket)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- h.server.serve(ctx, ln, false) }()

	client := sandbox.NewHelperClient(h.cfg.Socket)
	var wg sync.WaitGroup
	errs := make(chan error, clients)
	for i := range specs {
		wg.Add(1)
		go func(spec sandbox.UnitSpec) {
			defer wg.Done()
			if _, err := client.Install(context.Background(), spec, nil); err != nil {
				errs <- err
			}
		}(specs[i])
	}
	select {
	case <-four:
	case <-time.After(3 * time.Second):
		t.Fatal("four requests never ran at the same time")
	}
	h.runner.mu.Lock()
	if peak != 4 {
		t.Errorf("peak concurrency = %d, want 4", peak)
	}
	h.runner.mu.Unlock()
	close(release)
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Errorf("install failed: %v", err)
	}
	h.runner.mu.Lock()
	if peak > 4 {
		t.Errorf("peak concurrency = %d, want at most 4", peak)
	}
	h.runner.mu.Unlock()
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("serve did not stop")
	}
}

// mustRead reads a file or fails the test.
func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	return data
}
