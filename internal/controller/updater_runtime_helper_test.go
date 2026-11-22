// SPDX-License-Identifier: AGPL-3.0-only

package controller

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/qwq-panel/qwq/internal/platform/problem"
	"github.com/qwq-panel/qwq/internal/pluginhost/install"
	"github.com/qwq-panel/qwq/internal/sandbox"
)

// tokenPattern matches the 32-byte base64url credential InstallUnit generates.
var tokenPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)

// startHelperServer runs a fake privileged helper on a real Unix socket. It
// uses the production wire helpers so the client is exercised end to end
// without root or systemd.
func startHelperServer(t *testing.T, respond func(sandbox.HelperRequest) sandbox.HelperResponse) (string, <-chan sandbox.HelperRequest) {
	t.Helper()
	// A Unix socket path is limited to 107 bytes; t.TempDir() includes the
	// (long) test name, so the listener lives in a short /tmp directory.
	dir, err := os.MkdirTemp("/tmp", "qwq-helper-")
	if err != nil {
		t.Fatalf("create the helper socket directory: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	socket := filepath.Join(dir, "h.sock")
	ln, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	requests := make(chan sandbox.HelperRequest, 8)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer func() { _ = conn.Close() }()
				var req sandbox.HelperRequest
				if err := sandbox.ReadHelperJSON(conn, &req); err != nil {
					return
				}
				requests <- req
				_ = sandbox.WriteHelperJSON(conn, respond(req))
			}()
		}
	}()
	t.Cleanup(func() {
		_ = ln.Close()
		wg.Wait()
	})
	return socket, requests
}

// helperInstaller returns a PluginInstaller wired to a fake helper.
func helperInstaller(t *testing.T, socket string) *PluginInstaller {
	t.Helper()
	return &PluginInstaller{
		PluginsRoot: t.TempDir(),
		Helper:      sandbox.NewHelperClient(socket),
		Logger:      slog.New(slog.DiscardHandler),
	}
}

func helperSpec() sandbox.UnitSpec {
	return sandbox.UnitSpec{
		ID:         "alpha",
		VersionDir: "/var/lib/qwq-plugins/alpha/1.2.3",
		Entrypoint: "bin/plugin",
		Digest:     "sha256:" + strings.Repeat("a", 64),
		Limits:     &sandbox.Limits{MemoryMaxMB: 32, CPUQuotaPercent: 20, PIDsMax: 16, FDsMax: 128},
	}
}

func TestInstallUnitUsesPrivilegedHelper(t *testing.T) {
	socket, requests := startHelperServer(t, func(req sandbox.HelperRequest) sandbox.HelperResponse {
		return sandbox.HelperResponse{
			OK: true,
			Install: &sandbox.InstallResult{
				ID:        "alpha",
				Group:     "qwq-p-alpha",
				UnitFiles: []string{"/etc/systemd/system/qwq-plugin@alpha.service"},
			},
			Warnings: []string{"the socket unit was not enabled"},
		}
	})
	installer := helperInstaller(t, socket)
	spec := helperSpec()
	credential := []byte(strings.Repeat("cd", 32))

	res, err := installer.installUnit(context.Background(), spec, credential)
	if err != nil {
		t.Fatalf("installUnit: %v", err)
	}
	got := <-requests
	if got.Op != sandbox.HelperOpInstall || got.Spec == nil {
		t.Fatalf("request = %+v", got)
	}
	if got.Spec.ID != spec.ID || got.Spec.VersionDir != spec.VersionDir || got.Spec.Digest != spec.Digest {
		t.Errorf("request spec = %+v", got.Spec)
	}
	decoded, derr := base64.StdEncoding.DecodeString(got.CredentialBase64)
	if derr != nil || string(decoded) != string(credential) {
		t.Errorf("credential = %q (decode error %v)", decoded, derr)
	}
	if res.ID != "alpha" || res.Group != "qwq-p-alpha" {
		t.Errorf("result = %+v", res)
	}
	if len(res.Warnings) != 1 {
		t.Errorf("warnings = %v", res.Warnings)
	}
}

func TestInstallUnitHelperRefusalKeepsCode(t *testing.T) {
	socket, _ := startHelperServer(t, func(req sandbox.HelperRequest) sandbox.HelperResponse {
		return sandbox.HelperResponse{Code: string(problem.Unavailable), Error: "the helper is not installed"}
	})
	installer := helperInstaller(t, socket)

	_, err := installer.installUnit(context.Background(), helperSpec(), nil)
	if !problem.HasCode(err, problem.Unavailable) {
		t.Fatalf("installUnit = %v, want UNAVAILABLE", err)
	}
	wrapped := wrapInstallerFailure("The systemd unit could not be installed.", err)
	if !problem.HasCode(wrapped, problem.Unavailable) {
		t.Errorf("wrapped error = %v, want UNAVAILABLE", wrapped)
	}
	var pe *problem.Error
	if !errors.As(wrapped, &pe) || !strings.Contains(pe.Detail, "systemd unit") {
		t.Errorf("wrapped error = %#v", wrapped)
	}
}

func TestRemoveUnitUsesPrivilegedHelper(t *testing.T) {
	for _, tc := range []struct {
		name        string
		others      []string
		wantKeep    bool
		wantVersion string
	}{
		{name: "last version removes the unit", wantKeep: false, wantVersion: "1.2.3"},
		{name: "retained version keeps the unit", others: []string{"1.2.4"}, wantKeep: true, wantVersion: "1.2.3"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			socket, requests := startHelperServer(t, func(req sandbox.HelperRequest) sandbox.HelperResponse {
				return sandbox.HelperResponse{OK: true, Remove: &sandbox.RemoveResult{ID: req.ID, Group: "qwq-p-" + req.ID}}
			})
			installer := helperInstaller(t, socket)
			versionDir := filepath.Join(installer.PluginsRoot, "alpha", "1.2.3")
			if err := os.MkdirAll(versionDir, 0o755); err != nil {
				t.Fatal(err)
			}
			for _, other := range tc.others {
				if err := os.MkdirAll(filepath.Join(installer.PluginsRoot, "alpha", other), 0o755); err != nil {
					t.Fatal(err)
				}
			}
			if err := installer.RemoveUnit(context.Background(), "alpha", "1.2.3"); err != nil {
				t.Fatalf("RemoveUnit: %v", err)
			}
			got := <-requests
			if got.Op != sandbox.HelperOpRemove || got.ID != "alpha" || got.Version != tc.wantVersion {
				t.Fatalf("request = %+v", got)
			}
			if got.KeepUnit != tc.wantKeep {
				t.Errorf("keep_unit = %v, want %v", got.KeepUnit, tc.wantKeep)
			}
			if len(got.Paths) != 1 || got.Paths[0] != versionDir {
				t.Errorf("paths = %v, want [%s]", got.Paths, versionDir)
			}
		})
	}
}

func TestRemoveUnitHelperKeepsPreconditionCode(t *testing.T) {
	socket, _ := startHelperServer(t, func(req sandbox.HelperRequest) sandbox.HelperResponse {
		return sandbox.HelperResponse{
			Code:  string(problem.PreconditionFailed),
			Error: "plugin alpha is still running (main PID 4242); its files cannot be removed.",
		}
	})
	installer := helperInstaller(t, socket)
	if err := os.MkdirAll(filepath.Join(installer.PluginsRoot, "alpha", "1.2.3"), 0o755); err != nil {
		t.Fatal(err)
	}
	err := installer.RemoveUnit(context.Background(), "alpha", "1.2.3")
	if !problem.HasCode(err, problem.PreconditionFailed) {
		t.Fatalf("RemoveUnit = %v, want PRECONDITION_FAILED", err)
	}
}

// TestInstallUnitPublishesThroughHelper drives the whole InstallUnit path
// against a fake helper: publish first, then install with a freshly generated
// credential, and the staging tree is discarded afterwards.
func TestInstallUnitPublishesThroughHelper(t *testing.T) {
	f := newInstallerFixture(t)
	var logs bytes.Buffer
	f.installer.Logger = slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	socket, requests := startHelperServer(t, func(req sandbox.HelperRequest) sandbox.HelperResponse {
		switch req.Op {
		case sandbox.HelperOpPublish:
			if err := os.MkdirAll(req.VersionDir, 0o755); err != nil {
				t.Errorf("fake publish: %v", err)
			}
			return sandbox.HelperResponse{OK: true, Publish: &sandbox.PublishResult{
				ID: req.PluginID, Version: req.Version, VersionDir: req.VersionDir,
				Files: 3, Dirs: 1,
			}}
		case sandbox.HelperOpInstall:
			return sandbox.HelperResponse{OK: true, Install: &sandbox.InstallResult{
				ID: req.Spec.ID, Group: "qwq-p-" + req.Spec.ID,
			}}
		default:
			return sandbox.HelperResponse{Code: string(problem.Internal), Error: "unexpected operation"}
		}
	})
	f.installer.Helper = sandbox.NewHelperClient(socket)

	staged, err := f.installer.Stage(t.Context(), f.pkg.path)
	if err != nil {
		t.Fatalf("Stage: %v", err)
	}
	handle, ok := staged.Handle.(*install.Staged)
	if !ok {
		t.Fatalf("staged handle = %T, want *install.Staged", staged.Handle)
	}
	stagedDir := handle.Dir()
	versionDir := install.VersionDir(f.pluginsRoot, updaterTestID, updaterTestVersion)
	if !strings.HasPrefix(stagedDir, f.stagingRoot+string(filepath.Separator)+install.StagingPrefix) {
		t.Fatalf("staged dir %q is not below %s", stagedDir, f.stagingRoot)
	}
	if err := f.installer.InstallUnit(t.Context(), staged); err != nil {
		t.Fatalf("InstallUnit: %v", err)
	}

	var publishReq, installReq sandbox.HelperRequest
	deadline := time.After(2 * time.Second)
	for i := 0; i < 2; i++ {
		select {
		case req := <-requests:
			switch req.Op {
			case sandbox.HelperOpPublish:
				publishReq = req
			case sandbox.HelperOpInstall:
				installReq = req
			default:
				t.Fatalf("unexpected helper operation %q", req.Op)
			}
		case <-deadline:
			t.Fatalf("received %d of 2 helper requests", i)
		}
	}
	if publishReq.StagedDir != stagedDir || publishReq.VersionDir != versionDir ||
		publishReq.PluginID != updaterTestID || publishReq.Version != updaterTestVersion {
		t.Errorf("publish request = %+v", publishReq)
	}
	if installReq.Spec == nil || installReq.Spec.VersionDir != versionDir {
		t.Fatalf("install request = %+v", installReq)
	}
	token, err := base64.StdEncoding.DecodeString(installReq.CredentialBase64)
	if err != nil {
		t.Fatalf("credential is not base64: %v", err)
	}
	if len(token) != 43 || !tokenPattern.Match(token) {
		t.Errorf("credential = %q, want 43 base64url characters", token)
	}
	entries, err := os.ReadDir(f.stagingRoot)
	if err == nil {
		for _, entry := range entries {
			if strings.HasPrefix(entry.Name(), install.StagingPrefix) {
				t.Errorf("staging directory %q was left behind", entry.Name())
			}
		}
	}
	if strings.Contains(logs.String(), string(token)) {
		t.Error("the plugin credential appears in the controller log")
	}

	// A retry with the same Staged value has no staging copy left: it must skip
	// publish (the version directory is immutable and already verified) and
	// only install the unit again with a fresh credential.
	if err := f.installer.InstallUnit(t.Context(), staged); err != nil {
		t.Fatalf("retry InstallUnit: %v", err)
	}
	select {
	case req := <-requests:
		if req.Op != sandbox.HelperOpInstall {
			t.Errorf("retry requested %q, want install", req.Op)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("retry did not reach the helper")
	}
}

// TestInstallUnitWritesCredentialWithoutHelper covers the in-process path: the
// generated token is materialized at the credential path with mode 0600.
func TestInstallUnitWritesCredentialWithoutHelper(t *testing.T) {
	f := newInstallerFixture(t)
	var logs bytes.Buffer
	f.installer.Logger = slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))

	staged, err := f.installer.Stage(t.Context(), f.pkg.path)
	if err != nil {
		t.Fatalf("Stage: %v", err)
	}
	if err := f.installer.InstallUnit(t.Context(), staged); err != nil {
		t.Fatalf("InstallUnit: %v", err)
	}
	credentialPath := filepath.Join(f.installer.Sandbox.CredDir, updaterTestID+".token")
	token, err := os.ReadFile(credentialPath)
	if err != nil {
		t.Fatalf("reading the credential: %v", err)
	}
	if len(token) != 43 || !tokenPattern.Match(token) {
		t.Errorf("credential = %q, want 43 base64url characters", token)
	}
	if fi, err := os.Stat(credentialPath); err != nil {
		t.Fatalf("stating the credential: %v", err)
	} else if fi.Mode().Perm() != 0o600 {
		t.Errorf("credential mode = %o, want 0600", fi.Mode().Perm())
	}
	if strings.Contains(logs.String(), string(token)) {
		t.Error("the plugin credential appears in the controller log")
	}
}
