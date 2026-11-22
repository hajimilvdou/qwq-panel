// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/qwq-panel/qwq/internal/platform/problem"
	"github.com/qwq-panel/qwq/internal/sandbox"
)

// ============================================================================
// 彻底卸载通过真实 JSON 契约显式请求；未知字段不能默默变成普通卸载。
// ============================================================================

func TestHelperAcceptsExplicitPurgeRequest(t *testing.T) {
	h := newTestHost(t)
	var req sandbox.HelperRequest
	if err := sandbox.ReadHelperJSON(strings.NewReader(`{"op":"remove","id":"alpha","purge_data":true}`+"\n"), &req); err != nil {
		t.Fatalf("explicit purge request rejected: %v", err)
	}
	if response := h.server.handle(t.Context(), req); !response.OK {
		t.Fatalf("purge without recorded versions failed: %+v", response)
	}
}

func TestHelperPurgeDeletesBothLayoutsAndRetainsOtherPlugin(t *testing.T) {
	for _, layout := range []string{"directory", "leaf-link", "plugin-link"} {
		t.Run(layout, func(t *testing.T) {
			h := newTestHost(t)
			private := filepath.Join(h.cfg.PrivateDataRoot, "alpha", "default")
			writeHelperPurgeMarker(t, filepath.Join(private, "state.json"))
			logical := filepath.Join(h.cfg.DataRoot, "alpha")
			switch layout {
			case "directory":
				writeHelperPurgeMarker(t, filepath.Join(logical, "default", "state.json"))
			case "leaf-link":
				if err := os.MkdirAll(logical, 0o711); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(private, filepath.Join(logical, "default")); err != nil {
					t.Fatal(err)
				}
			case "plugin-link":
				if err := os.MkdirAll(h.cfg.DataRoot, 0o711); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(filepath.Dir(private), logical); err != nil {
					t.Fatal(err)
				}
			}
			for _, root := range []string{h.cfg.DataRoot, h.cfg.PrivateDataRoot} {
				writeHelperPurgeMarker(t, filepath.Join(root, "beta", "state.json"))
			}
			outside := filepath.Join(filepath.Dir(h.cfg.PluginsRoot), "outside", "retain.json")
			writeHelperPurgeMarker(t, outside)
			if err := os.Symlink(filepath.Dir(outside), filepath.Join(private, "foreign")); err != nil {
				t.Fatal(err)
			}
			req := sandbox.HelperRequest{Op: sandbox.HelperOpRemove, ID: "alpha", PurgeData: true}
			if resp := h.server.handle(t.Context(), req); !resp.OK {
				t.Fatalf("purge=%+v", resp)
			}
			for _, root := range []string{h.cfg.DataRoot, h.cfg.PrivateDataRoot} {
				requireHelperPurgePath(t, filepath.Join(root, "alpha"), false)
				requireHelperPurgePath(t, filepath.Join(root, "beta", "state.json"), true)
			}
			requireHelperPurgePath(t, outside, true)
			if resp := h.server.handle(t.Context(), req); !resp.OK || len(resp.Remove.Removed) != 0 {
				t.Fatalf("retry=%+v", resp)
			}
		})
	}
}

func TestHelperDefaultRemoveRetainsData(t *testing.T) {
	h := newTestHost(t)
	for _, root := range []string{h.cfg.DataRoot, h.cfg.PrivateDataRoot} {
		writeHelperPurgeMarker(t, filepath.Join(root, "alpha", "state.json"))
	}
	if resp := h.server.handle(t.Context(), sandbox.HelperRequest{Op: sandbox.HelperOpRemove, ID: "alpha"}); !resp.OK {
		t.Fatalf("remove=%+v", resp)
	}
	for _, root := range []string{h.cfg.DataRoot, h.cfg.PrivateDataRoot} {
		requireHelperPurgePath(t, filepath.Join(root, "alpha", "state.json"), true)
	}
}

func TestHelperPurgeRefusesRunningOrUnknownUnit(t *testing.T) {
	for _, kind := range []string{"running", "unreadable"} {
		t.Run(kind, func(t *testing.T) {
			h := newTestHost(t)
			marker := filepath.Join(h.cfg.PrivateDataRoot, "alpha", "state.json")
			writeHelperPurgeMarker(t, marker)
			h.runner.reply = func(name string, args []string) (string, error) {
				if name == "systemctl" && len(args) > 0 && args[0] == "show" {
					if kind == "running" {
						return "MainPID=42\n", nil
					}
					return "", errors.New("TEST-ONLY: systemd unavailable")
				}
				return defaultReply(name, args)
			}
			resp := h.server.handle(t.Context(), sandbox.HelperRequest{Op: sandbox.HelperOpRemove, ID: "alpha", PurgeData: true})
			if resp.OK {
				t.Fatalf("purge accepted %s unit", kind)
			}
			requireHelperPurgePath(t, marker, true)
		})
	}
}

func TestHelperPurgeRejectsDataRootLink(t *testing.T) {
	h := newTestHost(t)
	outside := filepath.Join(filepath.Dir(h.cfg.PluginsRoot), "outside", "alpha", "state.json")
	writeHelperPurgeMarker(t, outside)
	if err := os.Symlink(filepath.Dir(filepath.Dir(outside)), h.cfg.DataRoot); err != nil {
		t.Fatal(err)
	}
	resp := h.server.handle(t.Context(), sandbox.HelperRequest{Op: sandbox.HelperOpRemove, ID: "alpha", PurgeData: true})
	if resp.OK {
		t.Fatal("purge accepted a linked data root")
	}
	requireHelperPurgePath(t, outside, true)
}

func TestHelperPurgeRejectsKeptUnitAndFailedSocketDisable(t *testing.T) {
	h := newTestHost(t)
	version := h.addVersion(t, "alpha", "1.2.3")
	if resp := h.server.handle(t.Context(), installRequest(specFor("alpha", version), nil)); !resp.OK {
		t.Fatalf("install=%+v", resp)
	}
	marker := filepath.Join(h.cfg.PrivateDataRoot, "alpha", "state.json")
	writeHelperPurgeMarker(t, marker)
	req := sandbox.HelperRequest{Op: sandbox.HelperOpRemove, ID: "alpha", PurgeData: true, KeepUnit: true}
	if resp := h.server.handle(t.Context(), req); resp.OK || resp.Code != string(problem.ValidationFailed) {
		t.Fatalf("retained unit purge=%+v", resp)
	}
	h.runner.reply = func(name string, args []string) (string, error) {
		if name == "systemctl" && len(args) > 0 && args[0] == "disable" {
			return "", errors.New("TEST-ONLY: disable failed")
		}
		return defaultReply(name, args)
	}
	req.KeepUnit = false
	if resp := h.server.handle(t.Context(), req); resp.OK || resp.Code != string(problem.Unavailable) {
		t.Fatalf("disable failed purge=%+v", resp)
	}
	requireHelperPurgePath(t, marker, true)
	requireHelperPurgePath(t, filepath.Join(h.cfg.UnitDir, "qwq-plugin@alpha.service"), true)
}

func writeHelperPurgeMarker(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(`{"test_only":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
}

func requireHelperPurgePath(t *testing.T, path string, present bool) {
	t.Helper()
	_, err := os.Lstat(path)
	if present && err != nil {
		t.Fatalf("retained path %s: %v", path, err)
	}
	if !present && !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("purged path %s: %v", path, err)
	}
}
