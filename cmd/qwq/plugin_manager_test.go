// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/qwq-panel/qwq/internal/api"
	"github.com/qwq-panel/qwq/internal/platform/problem"
	"github.com/qwq-panel/qwq/internal/pluginhost/updater"
	"github.com/qwq-panel/qwq/internal/sandbox"
	"github.com/qwq-panel/qwq/sdk/manifest"
)

// fakeUpdater implements pluginUpdater and records the requests the adapter
// builds.
type fakeUpdater struct {
	all      []updater.Version
	versions map[string][]updater.Version
	active   map[string]updater.Version
	configs  map[string]updater.ConfigRevision

	installReq     updater.InstallRequest
	installVersion updater.Version
	installErr     error

	rollbackID     string
	rollbackResult updater.UpdateResult
	rollbackErr    error

	applyReq    updater.ConfigRequest
	applyResult updater.ConfigRevision
	applyErr    error

	inspectPath   string
	inspectResult *updater.Inspection
	inspectErr    error

	removeReq  updater.RemoveRequest
	removeErr  error
	dependents []string

	enabledID    string
	enabledValue bool
	enabledErr   error

	logResult sandbox.LogResult
	logErr    error
}

func (f *fakeUpdater) Remove(_ context.Context, req updater.RemoveRequest) error {
	f.removeReq = req
	return f.removeErr
}

func (f *fakeUpdater) Dependents(string) ([]string, error) { return f.dependents, nil }

func (f *fakeUpdater) Logs(context.Context, string, string, string, int) (sandbox.LogResult, error) {
	return f.logResult, f.logErr
}

func (f *fakeUpdater) SetEnabled(_ context.Context, pluginID string, enabled bool) error {
	f.enabledID, f.enabledValue = pluginID, enabled
	return f.enabledErr
}

func (f *fakeUpdater) Install(_ context.Context, req updater.InstallRequest) (*updater.Version, error) {
	f.installReq = req
	if f.installErr != nil {
		return nil, f.installErr
	}
	return &f.installVersion, nil
}

func (f *fakeUpdater) Rollback(_ context.Context, pluginID string) (*updater.UpdateResult, error) {
	f.rollbackID = pluginID
	if f.rollbackErr != nil {
		return nil, f.rollbackErr
	}
	return &f.rollbackResult, nil
}

func (f *fakeUpdater) ApplyConfig(_ context.Context, req updater.ConfigRequest) (updater.ConfigRevision, error) {
	f.applyReq = req
	return f.applyResult, f.applyErr
}

func (f *fakeUpdater) Inspect(_ context.Context, pkgPath string) (*updater.Inspection, error) {
	f.inspectPath = pkgPath
	if f.inspectErr != nil {
		return nil, f.inspectErr
	}
	return f.inspectResult, nil
}

func (f *fakeUpdater) Active(pluginID string) (updater.Version, bool) {
	v, ok := f.active[pluginID]
	return v, ok
}

func (f *fakeUpdater) ActiveConfig(pluginID string) (updater.ConfigRevision, bool) {
	c, ok := f.configs[pluginID]
	return c, ok
}

func (f *fakeUpdater) Versions(pluginID string) ([]updater.Version, error) {
	v, ok := f.versions[pluginID]
	if !ok {
		return nil, nil
	}
	return v, nil
}

func (f *fakeUpdater) AllVersions() ([]updater.Version, error) { return f.all, nil }

func testManifest(id, version, name, schema string) *manifest.Manifest {
	return &manifest.Manifest{
		ID: id, Version: version, Name: name, Summary: "summary of " + id,
		Publisher: manifest.Publisher{ID: "acme"}, Placement: "node",
		Config: manifest.Config{Schema: schema},
	}
}

func testVersion(id, version, name string, active bool, revision int64) updater.Version {
	return updater.Version{
		PluginID: id, Version: version, Digest: "sha256:" + strings.Repeat("a", 64),
		Manifest: testManifest(id, version, name, "schemas/config.schema.json"),
		Status:   updater.VersionActive, InstallStatus: updater.InstallInstalled,
		Active: active, Revision: revision,
	}
}

func newTestManager(u *fakeUpdater, root string, update pluginUpdateFunc) *pluginManager {
	return &pluginManager{
		updater: u, update: update, pluginsRoot: root,
		logger: slog.New(slog.DiscardHandler),
		// 此 helper 只测试请求映射；真实身份/绑定校验由 Controller 集成覆盖。
		validateConfig: func(ctx context.Context, _ api.ApplyPluginConfigRequest) error { return ctx.Err() },
	}
}

func TestPluginManagerConfigWriteRequiresCurrentGuard(t *testing.T) {
	u := &fakeUpdater{}
	m := newTestManager(u, t.TempDir(), nil)
	sentinel := problem.New(problem.PermissionDenied, "fixture configuration scope denied")
	m.validateConfig = func(context.Context, api.ApplyPluginConfigRequest) error { return sentinel }
	if _, err := m.ApplyConfig(t.Context(), api.ApplyPluginConfigRequest{PluginID: "alpha", Config: json.RawMessage(`{}`)}); !errors.Is(err, sentinel) || u.applyReq.PluginID != "" {
		t.Fatal("直接适配器写入跳过了配置权限守卫")
	}
	m.validateConfig = nil
	if err := m.ValidateConfig(t.Context(), api.ApplyPluginConfigRequest{}); !problem.HasCode(err, problem.PluginUnavailable) {
		t.Fatalf("缺守卫仍接受配置: %v", err)
	}
	called := false
	m.validateConfig = func(context.Context, api.ApplyPluginConfigRequest) error { called = true; return nil }
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := m.ApplyConfig(ctx, api.ApplyPluginConfigRequest{PluginID: "alpha"}); err == nil || called || u.applyReq.PluginID != "" {
		t.Fatal("取消后的调用进入配置守卫或Updater写入")
	}
}

func TestPluginManagerListAndGet(t *testing.T) {
	alpha2 := testVersion("alpha", "2.0.0", "Alpha", true, 20)
	alpha1 := testVersion("alpha", "1.0.0", "Alpha", false, 10)
	alpha1.Status = updater.VersionStopped
	beta := testVersion("beta", "0.1.0", "Beta", false, 5)
	beta.Status = updater.VersionRejected

	u := &fakeUpdater{
		all: []updater.Version{alpha2, alpha1, beta},
		versions: map[string][]updater.Version{
			"alpha": {alpha2, alpha1},
			"beta":  {beta},
		},
		active: map[string]updater.Version{
			"alpha": alpha2,
		},
		configs: map[string]updater.ConfigRevision{
			"alpha": {PluginID: "alpha", Revision: 3, Config: json.RawMessage(`{"url":"x"}`), Active: true},
		},
	}
	m := newTestManager(u, t.TempDir(), nil)

	plugins, err := m.List(context.Background())
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(plugins) != 2 || plugins[0].PluginID != "alpha" || plugins[1].PluginID != "beta" {
		t.Fatalf("plugins = %+v", plugins)
	}
	a := plugins[0]
	if a.Name != "Alpha" || a.Summary != "summary of alpha" || a.Publisher != "acme" || a.Placement != "node" {
		t.Fatalf("alpha summary = %+v", a)
	}
	if a.ActiveVersion != "2.0.0" || a.ActiveStatus != "ACTIVE" || a.InstallStatus != "INSTALLED" {
		t.Fatalf("alpha active = %+v", a)
	}
	if a.ConfigRevision != 3 || a.Revision != 20 {
		t.Fatalf("alpha revisions = %d/%d", a.ConfigRevision, a.Revision)
	}
	if len(a.Versions) != 2 || a.Versions[0].Version != "2.0.0" || a.Versions[1].Version != "1.0.0" {
		t.Fatalf("alpha versions = %+v", a.Versions)
	}
	b := plugins[1]
	if b.ActiveVersion != "" || b.ActiveStatus != "" || b.Revision != 5 {
		t.Fatalf("beta = %+v", b)
	}

	got, err := m.Get(context.Background(), "alpha")
	if err != nil || got.PluginID != "alpha" || got.Name != "Alpha" {
		t.Fatalf("Get(alpha) = %+v, %v", got, err)
	}
	_, err = m.Get(context.Background(), "missing")
	if !problem.HasCode(err, problem.NotFound) {
		t.Fatalf("Get(missing) = %v", err)
	}
}

func TestPluginManagerInstallUpdateRollbackAndConfig(t *testing.T) {
	active := testVersion("alpha", "1.0.0", "Alpha", true, 20)
	u := &fakeUpdater{
		active:         map[string]updater.Version{"alpha": active},
		installVersion: testVersion("alpha", "1.1.0", "Alpha", true, 21),
		rollbackResult: updater.UpdateResult{
			SagaID: "sag_1", PluginID: "alpha", FromVersion: "1.1.0", ToVersion: "1.0.0",
			Strategy: updater.StrategyRestart, State: updater.SagaCommitted, Restarted: true,
			Version: active,
		},
		applyResult: updater.ConfigRevision{PluginID: "alpha", Revision: 2, Config: json.RawMessage(`{}`), Active: true},
	}
	var updateReq updater.UpdateRequest
	m := newTestManager(u, t.TempDir(), func(_ context.Context, req updater.UpdateRequest) (*updater.UpdateResult, error) {
		updateReq = req
		return &updater.UpdateResult{
			SagaID: "sag_u", PluginID: "alpha", FromVersion: "1.0.0", ToVersion: "1.1.0",
			Strategy: updater.StrategyRestart, State: updater.SagaCommitted, Restarted: true,
			Version: testVersion("alpha", "1.1.0", "Alpha", true, 21),
		}, nil
	})

	version, err := m.Install(context.Background(), api.InstallPackageRequest{
		PackagePath: "/staging/upload.pkg", AcceptedCapabilities: []string{"net.connect"}, ExpectedRevision: 4,
	})
	if err != nil || version.Version != "1.1.0" {
		t.Fatalf("Install = %+v, %v", version, err)
	}
	if u.installReq.PackagePath != "/staging/upload.pkg" ||
		u.installReq.AcceptedCapabilities[0] != "net.connect" ||
		u.installReq.ExpectedRevision != 4 {
		t.Fatalf("install request = %+v", u.installReq)
	}

	updated, err := m.Update(context.Background(), api.UpdatePackageRequest{
		PluginID: "alpha", PackagePath: "/staging/u.pkg",
		AcceptedCapabilities: []string{"net.connect"}, ExpectedRevision: 20,
	})
	if err != nil || updated.SagaID != "sag_u" {
		t.Fatalf("Update = %+v, %v", updated, err)
	}
	if updateReq.Strategy != updater.StrategyRestart || updateReq.PluginID != "alpha" ||
		updateReq.PackagePath != "/staging/u.pkg" || updateReq.ExpectedRevision != 20 {
		t.Fatalf("update request = %+v", updateReq)
	}

	if _, err := m.Rollback(context.Background(), "alpha", 19); !problem.HasCode(err, problem.RevisionConflict) {
		t.Fatalf("Rollback(wrong revision) = %v", err)
	}
	if u.rollbackID != "" {
		t.Fatal("the rollback reached the updater despite the revision mismatch")
	}
	if _, err := m.Rollback(context.Background(), "alpha", 20); err != nil || u.rollbackID != "alpha" {
		t.Fatalf("Rollback = %v, %q", err, u.rollbackID)
	}

	applied, err := m.ApplyConfig(context.Background(), api.ApplyPluginConfigRequest{
		PluginID: "alpha", Config: json.RawMessage(`{"url":"x"}`), ExpectedRevision: 1,
	})
	if err != nil || applied.Revision != 2 {
		t.Fatalf("ApplyConfig = %+v, %v", applied, err)
	}
	if u.applyReq.PluginID != "alpha" || u.applyReq.ExpectedRevision != 1 {
		t.Fatalf("apply request = %+v", u.applyReq)
	}

	cfg, err := m.GetConfig(context.Background(), "alpha")
	if err != nil || cfg.Revision != 0 || string(cfg.Config) != "{}" {
		t.Fatalf("GetConfig(no config) = %+v, %v", cfg, err)
	}
	u.configs = map[string]updater.ConfigRevision{
		"alpha": {PluginID: "alpha", Revision: 7, Config: json.RawMessage(`{"url":"y"}`), Active: true},
	}
	cfg, err = m.GetConfig(context.Background(), "alpha")
	if err != nil || cfg.Revision != 7 || string(cfg.Config) != `{"url":"y"}` {
		t.Fatalf("GetConfig = %+v, %v", cfg, err)
	}
	if _, err := m.GetConfig(context.Background(), "missing"); !problem.HasCode(err, problem.NotFound) {
		t.Fatalf("GetConfig(missing) = %v", err)
	}
}

func TestPluginManagerConfigSchema(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "alpha", "1.0.0", "schemas")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	schema := []byte(`{"type":"object","properties":{"password":{"type":"string","writeOnly":true}}}`)
	if err := os.WriteFile(filepath.Join(dir, "config.schema.json"), schema, 0o644); err != nil {
		t.Fatal(err)
	}
	active := testVersion("alpha", "1.0.0", "Alpha", true, 20)
	u := &fakeUpdater{active: map[string]updater.Version{"alpha": active}}
	m := newTestManager(u, root, nil)

	got, err := m.ConfigSchema(context.Background(), "alpha")
	if err != nil || string(got) != string(schema) {
		t.Fatalf("ConfigSchema = %s, %v", got, err)
	}

	// A schema path that escapes the version directory is refused before any
	// file is opened.
	escaped := active
	escaped.Manifest = testManifest("alpha", "1.0.0", "Alpha", "../../etc/passwd")
	u.active["alpha"] = escaped
	if _, err := m.ConfigSchema(context.Background(), "alpha"); !problem.HasCode(err, problem.PluginUnavailable) {
		t.Fatalf("traversal schema = %v", err)
	}

	// A missing schema file hides its path from the problem detail.
	active.Manifest = testManifest("alpha", "1.0.0", "Alpha", "schemas/missing.json")
	u.active["alpha"] = active
	_, err = m.ConfigSchema(context.Background(), "alpha")
	if !problem.HasCode(err, problem.PluginUnavailable) {
		t.Fatalf("missing schema = %v", err)
	}
	var pe *problem.Error
	if errors.As(err, &pe) && strings.Contains(pe.Detail, root) {
		t.Fatalf("the problem detail leaks a path: %q", pe.Detail)
	}

	delete(u.active, "alpha")
	if _, err := m.ConfigSchema(context.Background(), "alpha"); !problem.HasCode(err, problem.NotFound) {
		t.Fatalf("unknown plugin schema = %v", err)
	}
}

// TestPluginManagerInspectPackage: the adapter merges the updater's verdict
// with the plugins filesystem capacity and applies the catalog's risk and
// approval clamps to the manifest preview (GAPS gap 4).
func TestPluginManagerInspectPackage(t *testing.T) {
	routes := []manifest.UIRoute{{Path: "/x", Title: "X", Permission: "host.plugins:read"}}
	widgets := []manifest.UIWidget{{ID: "load", Title: "Load", Kind: "stat", Operation: "status", RefreshSeconds: 5, Size: "s"}}
	u := &fakeUpdater{inspectResult: &updater.Inspection{
		PluginID: "alpha", Version: "1.0.0",
		Manifest: &manifest.Manifest{
			ID: "alpha", Version: "1.0.0", Name: "Alpha", Summary: "s",
			Publisher: manifest.Publisher{ID: "acme", KeyID: "ed25519:" + strings.Repeat("a", 64)},
			Placement: "node", Target: "linux/amd64", ABI: manifest.ABI{Major: 1, MinimumMinor: 0},
			Resources: manifest.Resources{MemoryMaxMB: 64, CPUQuotaPercent: 100, PIDsMax: 32, FDsMax: 256, DiskMaxMB: 8},
			Capabilities: []manifest.Capability{
				{Name: "system.firewall", Scope: "nftables", Reason: "rules"},
				{Name: "net.connect", Scope: "outbound", Reason: "api"},
			},
			Operations: []manifest.Operation{
				// An explicit empty capability list: no capabilities, so no floor.
				{Name: "status", Effect: "read", Risk: "low", Capabilities: []manifest.CapabilityRef{}},
				{Name: "fw.apply", Effect: "write", Risk: "medium", Approval: "auto"},
			},
			UI: &manifest.UI{Entry: "ui/index.html", ConnectSources: []string{"https://api.example"}, Routes: routes, Widgets: widgets},
		},
		Signature:     updater.InspectionSignature{Valid: true, Trusted: true, KeyID: "ed25519:" + strings.Repeat("a", 64)},
		UnpackedBytes: 2 << 20,
		Memory:        updater.InspectionMemory{RequiredBytes: 64 << 20, AvailableBytes: 2 << 30, OK: true},
		Installed:     &updater.InspectionInstalled{Version: "0.9.0", Revision: 7},
	}}
	m := newTestManager(u, t.TempDir(), nil)

	got, err := m.InspectPackage(context.Background(), api.InspectPackageRequest{PackagePath: "/staging/x.pkg"})
	if err != nil {
		t.Fatalf("InspectPackage: %v", err)
	}
	if u.inspectPath != "/staging/x.pkg" {
		t.Fatalf("inspect path = %q", u.inspectPath)
	}
	if got.PluginID != "alpha" || got.Version != "1.0.0" ||
		!got.SignatureValid || !got.SignatureTrusted || got.SignatureKeyID == "" {
		t.Fatalf("identity/signature = %+v", got)
	}
	if got.UnpackedBytes != 2<<20 {
		t.Fatalf("unpacked = %d", got.UnpackedBytes)
	}
	if got.Installed == nil || got.Installed.Version != "0.9.0" || got.Installed.Revision != 7 {
		t.Fatalf("installed = %+v", got.Installed)
	}
	if got.Memory.RequiredBytes != 64<<20 || got.Memory.AvailableBytes != 2<<30 || !got.Memory.OK {
		t.Fatalf("memory = %+v", got.Memory)
	}
	// Disk: a small package fits on the test filesystem, and the byte-level
	// reserve rule refuses an impossible size.
	if got.Disk.RequiredBytes != 2<<20 || !got.Disk.OK || got.Disk.AvailableBytes <= 0 {
		t.Fatalf("disk = %+v", got.Disk)
	}
	if huge := m.diskCapacity(1 << 62); huge.OK {
		t.Fatalf("a huge package passed the disk check: %+v", huge)
	}
	preview := got.Manifest
	if preview == nil || preview.ABI != "1.0" || preview.Target != "linux/amd64" || preview.PublisherID != "acme" {
		t.Fatalf("manifest preview = %+v", preview)
	}
	if len(preview.Capabilities) != 2 || !preview.Capabilities[0].Sensitive || preview.Capabilities[1].Sensitive {
		t.Fatalf("capabilities = %+v", preview.Capabilities)
	}
	if preview.UIRoutes != 1 || preview.Widgets != 1 ||
		len(preview.ConnectSources) != 1 || preview.ConnectSources[0] != "https://api.example" {
		t.Fatalf("ui preview = %+v", preview)
	}
	if len(preview.Operations) != 2 {
		t.Fatalf("operations = %+v", preview.Operations)
	}
	status := preview.Operations[0]
	if status.Risk != "low" || status.Approval != "auto" || status.Reachability {
		t.Fatalf("status operation = %+v", status)
	}
	// fw.apply writes and may use system.firewall: the host forces
	// reachability and clamps risk high / approval ai_confirm (ADR-0016).
	apply := preview.Operations[1]
	if !apply.Reachability || apply.Risk != "high" || apply.Approval != "ai_confirm" {
		t.Fatalf("fw.apply = %+v", apply)
	}

	// Errors pass through unchanged.
	u.inspectErr = problem.New(problem.ValidationFailed, "broken")
	if _, err := m.InspectPackage(context.Background(), api.InspectPackageRequest{PackagePath: "/x"}); !problem.HasCode(err, problem.ValidationFailed) {
		t.Fatalf("InspectPackage error = %v", err)
	}
}
