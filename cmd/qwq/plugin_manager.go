// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/qwq-panel/qwq/internal/api"
	"github.com/qwq-panel/qwq/internal/catalog"
	"github.com/qwq-panel/qwq/internal/controller"
	"github.com/qwq-panel/qwq/internal/operations"
	"github.com/qwq-panel/qwq/internal/platform/diskfree"
	"github.com/qwq-panel/qwq/internal/platform/problem"
	"github.com/qwq-panel/qwq/internal/pluginhost/install"
	"github.com/qwq-panel/qwq/internal/pluginhost/supervisor"
	"github.com/qwq-panel/qwq/internal/pluginhost/updater"
	"github.com/qwq-panel/qwq/internal/pluginui"
	"github.com/qwq-panel/qwq/internal/sandbox"
	"github.com/qwq-panel/qwq/sdk/manifest"
)

// maxConfigSchemaBytes bounds the configuration schema read from a published
// version. Manifest schemas are small; anything larger is treated as a broken
// package rather than read into memory.
const maxConfigSchemaBytes = 1 << 20

// pluginVersionPattern is the version grammar the installer enforces when the
// version becomes a path component. The updater already validated it; the
// adapter repeats the check because ConfigSchema joins it into a path.
var pluginVersionPattern = regexp.MustCompile(`^[0-9]+(\.[0-9]+)*([-+][0-9A-Za-z.+-]+)?$`)

// pluginUpdater is the read/write surface the adapter needs from
// internal/pluginhost/updater. It is an interface so the adapter tests can
// assert the exact request the HTTP layer produces.
type pluginUpdater interface {
	Install(ctx context.Context, req updater.InstallRequest) (*updater.Version, error)
	Rollback(ctx context.Context, pluginID string) (*updater.UpdateResult, error)
	ApplyConfig(ctx context.Context, req updater.ConfigRequest) (updater.ConfigRevision, error)
	Inspect(ctx context.Context, pkgPath string) (*updater.Inspection, error)
	Active(pluginID string) (updater.Version, bool)
	ActiveConfig(pluginID string) (updater.ConfigRevision, bool)
	Versions(pluginID string) ([]updater.Version, error)
	AllVersions() ([]updater.Version, error)
	Remove(ctx context.Context, req updater.RemoveRequest) error
	Dependents(pluginID string) ([]string, error)
	Enabled(ctx context.Context, pluginID string) (bool, error)
	UnitRunning(pluginID string) bool
	SetEnabled(ctx context.Context, pluginID string, enabled bool) error
	EnsureActive(ctx context.Context, pluginID string) error
	Logs(ctx context.Context, pluginID, cursor, stream string, limit int) (sandbox.LogResult, error)
}

// pluginUpdateFunc is the restart-forcing update entry point. The production
// value is Controller.UpdatePlugin; the adapter tests replace it.
type pluginUpdateFunc func(context.Context, updater.UpdateRequest) (*updater.UpdateResult, error)

// mandatoryBuiltinPluginID is the sole mandatory base plugin bundled with the
// host that cannot be uninstalled from the Web UI. All 10 optional official
// plugins installed via the Official Store remain uninstallable.
const mandatoryBuiltinPluginID = "security.basic"

// installDiskReserve is the free space the plugins filesystem must keep
// beyond a package's unpacked size before an install is accepted. It matches
// the GW-07 staging reserve so upload and install agree on what "enough room"
// means.
const installDiskReserve = 256 << 20

// pluginManager adapts the updater to api.PluginManager. It owns no policy:
// every install/update/rollback/config call is the updater's, and the
// configuration schema is read from the immutable published version directory.
type pluginManager struct {
	updater     pluginUpdater
	update      pluginUpdateFunc
	pluginsRoot string
	logger      *slog.Logger
	// catalog holds the plugin half of the action catalog. It is reconciled
	// with the active versions after every lifecycle change (syncCatalog).
	catalog *catalog.Catalog
	// instances reads the in-memory instance snapshot of the plugin runtime;
	// nil on a host without one.
	instances func() []supervisor.Status
	// control stops and starts one instance (restart); nil without a runtime.
	control pluginControl
	// memory reads the cgroup use of one instance; nil without a runtime.
	memory func(pluginID string) (uint64, error)
	// syncPublicRoutes refreshes /p/{plugin_id}/... public routes after plugin
	// lifecycle or enablement changes.
	syncPublicRoutes func()
	// 配置写入前的真实主体/绑定守卫，由 Controller 构造。
	validateConfig func(context.Context, api.ApplyPluginConfigRequest) error
}

// pluginControl is the part of the supervisor the restart route needs.
type pluginControl interface {
	Stop(ctx context.Context, pluginID string) error
	Ensure(ctx context.Context, pluginID string) (*supervisor.Instance, error)
}

// newPluginManager builds the API adapter when the host runs an updater.
func newPluginManager(c *controller.Controller, pluginsRoot string, logger *slog.Logger) *pluginManager {
	if c == nil {
		return nil
	}
	up := c.Updater()
	if up == nil {
		return nil
	}
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	m := &pluginManager{
		updater:     up,
		update:      c.UpdatePlugin,
		pluginsRoot: pluginsRoot,
		logger:      logger,
		catalog:     c.Catalog(),
	}
	m.validateConfig = func(ctx context.Context, req api.ApplyPluginConfigRequest) error {
		schema, err := m.ConfigSchema(ctx, req.PluginID)
		if err != nil {
			return err
		}
		return c.ValidatePluginConfiguration(ctx, controller.PluginConfigurationInput{Actor: req.Actor, PluginID: req.PluginID,
			ExpectedRevision: req.ExpectedRevision, Schema: schema, Config: req.Config})
	}
	if rt := c.PluginRuntime(); rt != nil {
		if sup := rt.Supervisor(); sup != nil {
			m.instances = sup.Instances
			m.control = sup
		}
		m.syncPublicRoutes = rt.SyncPublicRoutes
	}
	m.memory = up.MemoryCurrent
	// The updater recovered its sagas before the adapter is built, so the
	// active set is final: register the actions of every active version now.
	m.syncCatalog(context.Background())
	return m
}

// List returns every plugin that has a version row, sorted by plugin id.
func (m *pluginManager) List(ctx context.Context) ([]api.Plugin, error) {
	versions, err := m.updater.AllVersions()
	if err != nil {
		return nil, problem.Wrap(err)
	}
	byPlugin := make(map[string][]updater.Version)
	ids := make([]string, 0, len(versions))
	for _, v := range versions {
		if _, seen := byPlugin[v.PluginID]; !seen {
			ids = append(ids, v.PluginID)
		}
		byPlugin[v.PluginID] = append(byPlugin[v.PluginID], v)
	}
	sort.Strings(ids)
	out := make([]api.Plugin, 0, len(ids))
	for _, id := range ids {
		out = append(out, m.buildPlugin(id, byPlugin[id]))
	}
	return out, nil
}

// Get returns one plugin, or NOT_FOUND when it has no version row.
func (m *pluginManager) Get(_ context.Context, pluginID string) (api.Plugin, error) {
	versions, err := m.updater.Versions(pluginID)
	if err != nil {
		return api.Plugin{}, err
	}
	if len(versions) == 0 {
		return api.Plugin{}, problem.New(problem.NotFound, "The plugin is not installed.")
	}
	return m.buildPlugin(pluginID, versions), nil
}

// buildPlugin assembles the public view from one plugin's version rows. The
// updater returns them newest first.
func (m *pluginManager) buildPlugin(pluginID string, versions []updater.Version) api.Plugin {
	p := api.Plugin{PluginID: pluginID, Versions: make([]api.PluginVersion, 0, len(versions))}
	var (
		active    *updater.Version
		newest    *updater.Version
		createdAt time.Time
		revision  int64
	)
	for i := range versions {
		v := versions[i]
		if newest == nil {
			newest = &versions[i]
		}
		if v.Active {
			active = &versions[i]
		}
		if createdAt.IsZero() || v.InstalledAt.Before(createdAt) {
			createdAt = v.InstalledAt
		}
		if v.Revision > revision {
			revision = v.Revision
		}
		p.Versions = append(p.Versions, pluginVersionDTO(v))
	}
	summary := newest
	if active != nil {
		summary = active
		p.ActiveVersion = active.Version
		p.ActiveStatus = string(active.Status)
		p.InstallStatus = string(active.InstallStatus)
		p.Revision = active.Revision
	} else {
		p.Revision = revision
	}
	if summary != nil && summary.Manifest != nil {
		p.Name = summary.Manifest.Name
		p.Summary = summary.Manifest.Summary
		p.Publisher = summary.Manifest.Publisher.ID
		p.Placement = summary.Manifest.Placement
	}
	// The optional UI metadata comes from the ACTIVE version only: a rejected
	// candidate must not change what the shell shows (GAPS gap 3).
	if active != nil && active.Manifest != nil {
		m.fillMetadata(&p, active.Manifest)
	}
	p.CreatedAt = createdAt
	if cfg, ok := m.updater.ActiveConfig(pluginID); ok {
		p.ConfigRevision = cfg.Revision
	}
	enabled := true
	if en, err := m.updater.Enabled(context.Background(), pluginID); err == nil {
		enabled = en
	}
	p.Enabled = &enabled
	p.Runtime = m.runtimeState(pluginID, enabled, p.Startup)
	return p
}

// fillMetadata copies the manifest metadata of the active version into the
// public view. Every text here is written by the plugin author: untrusted.
func (m *pluginManager) fillMetadata(p *api.Plugin, manifest *manifest.Manifest) {
	p.Description = manifest.Description
	p.Icon = manifest.Icon
	p.Homepage = manifest.Homepage
	p.License = manifest.License
	p.HasConfig = manifest.Config.Schema != ""
	p.Builtin = p.PluginID == mandatoryBuiltinPluginID
	p.Startup = manifest.Lifecycle.Startup
	for _, c := range manifest.Capabilities {
		p.Capabilities = append(p.Capabilities, api.PluginCapability{
			Name: c.Name, Scope: c.Scope, Reason: c.Reason,
			Sensitive: operations.CapabilitySensitive(c.Name),
		})
	}
	for _, d := range manifest.Dependencies {
		p.Dependencies = append(p.Dependencies, d.ID)
	}
	r := manifest.Resources
	p.Resources = &api.PluginResources{
		MemoryMaxMB: r.MemoryMaxMB, CPUQuotaPercent: r.CPUQuotaPercent,
		PIDsMax: r.PIDsMax, FDsMax: r.FDsMax, DiskMaxMB: r.DiskMaxMB,
	}
	if manifest.UI != nil {
		ui := &api.PluginUI{
			Entry:          manifest.UI.Entry,
			ConnectSources: append([]string{}, manifest.UI.ConnectSources...),
		}
		for _, rt := range manifest.UI.Routes {
			ui.Routes = append(ui.Routes, api.PluginRoute{
				Path: rt.Path, Title: rt.Title, Nav: rt.EffectiveNav(), Permission: rt.Permission,
			})
		}
		for _, w := range manifest.UI.Widgets {
			ui.Widgets = append(ui.Widgets, api.PluginWidget{
				ID: w.ID, Title: w.Title, Kind: w.Kind, Operation: w.Operation,
				RefreshSeconds: w.RefreshSeconds, Size: w.Size, Icon: w.Icon, Color: w.Color,
			})
		}
		p.UI = ui
	}
}

// runtimeState unifies the supervisor snapshot, updater runtime handles,
// enablement flag, and on-demand startup semantics so newly installed or
// socket-activated plugins are never falsely reported as stopped.
func (m *pluginManager) runtimeState(pluginID string, enabled bool, startup string) *api.PluginRuntime {
	if m.instances == nil {
		return nil
	}
	if !enabled {
		return &api.PluginRuntime{State: "stopped"}
	}
	active, hasActive := m.updater.Active(pluginID)
	for _, st := range m.instances() {
		if st.PluginID != pluginID {
			continue
		}
		out := &api.PluginRuntime{Since: st.Since}
		switch st.State {
		case supervisor.StateRunning:
			out.State = "running"
			out.Detail = st.LastError
		case supervisor.StateDegraded:
			// The supervisor exhausted its restart attempts: the unit is in a
			// crash loop until something intervenes.
			out.State = "crashed"
			out.Restarts = st.Attempts
			out.Detail = st.LastError
		default:
			out.State = "unknown"
			out.Detail = st.LastError
		}
		m.fillMemory(out, pluginID, active, hasActive)
		return out
	}
	if hasActive {
		switch active.Status {
		case updater.VersionStaged, updater.VersionStarting, updater.VersionCandidate:
			return &api.PluginRuntime{State: "starting"}
		case updater.VersionQuarantined, updater.VersionRejected:
			return &api.PluginRuntime{State: "quarantined", Detail: active.RejectedReason}
		case updater.VersionActive:
			out := &api.PluginRuntime{State: "stopped"}
			if m.updater.UnitRunning(pluginID) {
				out.State = "running"
			} else if startup == "on_demand" {
				out.State = "standby"
			}
			m.fillMemory(out, pluginID, active, hasActive)
			return out
		}
	}
	return &api.PluginRuntime{State: "stopped"}
}

// fillMemory reports the cgroup use and the limit the manifest declares. An
// unreadable source leaves memory_bytes out instead of reporting a zero
// measurement; a manifest without a limit leaves memory_max_bytes out.
func (m *pluginManager) fillMemory(out *api.PluginRuntime, pluginID string, active updater.Version, hasActive bool) {
	if m.memory != nil {
		if cur, err := m.memory(pluginID); err == nil {
			out.MemoryBytes = int64(cur)
		}
	}
	if hasActive && active.Manifest != nil && active.Manifest.Resources.MemoryMaxMB > 0 {
		out.MemoryMaxBytes = int64(active.Manifest.Resources.MemoryMaxMB) << 20
	}
}

// Uninstall runs the updater's idempotent removal and reconciles the action
// catalog afterwards (GAPS gap 7).
func (m *pluginManager) Uninstall(ctx context.Context, pluginID string, purgeData bool) error {
	if err := m.updater.Remove(ctx, updater.RemoveRequest{PluginID: pluginID, PurgeData: purgeData}); err != nil {
		return err
	}
	m.syncCatalog(ctx)
	return nil
}

// Logs reads one page of the plugin's journal through the updater's privileged
// log source and maps it to the public DTO (GAPS gap 7).
func (m *pluginManager) Logs(ctx context.Context, pluginID, cursor, stream string, limit int) (api.PluginLogPage, error) {
	res, err := m.updater.Logs(ctx, pluginID, cursor, stream, limit)
	if err != nil {
		return api.PluginLogPage{}, err
	}
	page := api.PluginLogPage{Items: make([]api.PluginLogLine, 0, len(res.Lines)), NextCursor: res.NextCursor, Truncated: res.Truncated}
	for _, l := range res.Lines {
		page.Items = append(page.Items, api.PluginLogLine{At: l.At, Stream: l.Stream, Line: l.Line})
	}
	return page, nil
}

// SetEnabled persists the enablement flag and reconciles the runtime with it.
func (m *pluginManager) SetEnabled(ctx context.Context, pluginID string, enabled bool) error {
	if err := m.updater.SetEnabled(ctx, pluginID, enabled); err != nil {
		return err
	}
	if m.syncPublicRoutes != nil {
		m.syncPublicRoutes()
	}
	return nil
}

// Dependents lists the plugins that still require pluginID.
func (m *pluginManager) Dependents(_ context.Context, pluginID string) ([]string, error) {
	return m.updater.Dependents(pluginID)
}

// Restart stops the running instance and starts the active version again with
// the active configuration, then returns the refreshed plugin (GAPS gap 7).
func (m *pluginManager) Restart(ctx context.Context, pluginID, reason string) (api.Plugin, error) {
	if m.control == nil {
		return api.Plugin{}, problem.New(problem.Unavailable, "The plugin runtime is not available on this host.")
	}
	if _, ok := m.updater.Active(pluginID); !ok {
		return api.Plugin{}, problem.New(problem.NotFound, "The plugin is not installed.")
	}
	if err := m.control.Stop(ctx, pluginID); err != nil {
		return api.Plugin{}, err
	}
	if err := m.updater.EnsureActive(ctx, pluginID); err != nil {
		return api.Plugin{}, err
	}
	if _, err := m.control.Ensure(ctx, pluginID); err != nil {
		return api.Plugin{}, err
	}
	m.logger.InfoContext(ctx, "plugin restarted", "plugin_id", pluginID, "reason", reason)
	return m.Get(ctx, pluginID)
}

// syncCatalog reconciles the plugin half of the action catalog with the
// updater's active versions: every ACTIVE version registers its manifest
// actions, and plugins without one are dropped. It is idempotent and runs at
// startup and after every install, update or rollback; a failure keeps the
// previous entries and the version rows intact.
func (m *pluginManager) syncCatalog(ctx context.Context) {
	if m.catalog == nil {
		return
	}
	versions, err := m.updater.AllVersions()
	if err != nil {
		m.logger.WarnContext(ctx, "plugin actions not registered", "error", err)
		return
	}
	active := make(map[string]updater.Version)
	for _, v := range versions {
		if v.Active {
			active[v.PluginID] = v
		}
	}
	for id, v := range active {
		if v.Manifest == nil {
			continue
		}
		load, err := pluginPackageLoader(m.pluginsRoot, id, v.Version)
		if err != nil {
			m.logger.WarnContext(ctx, "plugin actions not registered", "plugin_id", id, "version", v.Version, "error", err)
			continue
		}
		if err := m.catalog.SetPlugin(v.Manifest, load); err != nil {
			m.logger.WarnContext(ctx, "plugin actions not registered", "plugin_id", id, "version", v.Version, "error", err)
		}
	}
	// A plugin whose active version disappeared (rollback to none, failed
	// uninstall) must not stay callable.
	for _, e := range m.catalog.Entries() {
		if e.Source == catalog.Plugin {
			if _, ok := active[e.PluginID]; !ok {
				m.catalog.RemovePlugin(e.PluginID)
			}
		}
	}
	if m.syncPublicRoutes != nil {
		m.syncPublicRoutes()
	}
}

// pluginUIResolver resolves the static prefix /plugin-ui/{id}/{version}/...
// to the published version directory an installed, retained version occupies
// (ADR-0018). It answers from the updater's version rows, never from a request
// path.
type pluginUIResolver struct {
	updater     *updater.Updater
	pluginsRoot string
}

// newPluginUIResolver builds the resolver for the plugin static handler.
func newPluginUIResolver(up *updater.Updater, pluginsRoot string) pluginUIResolver {
	return pluginUIResolver{updater: up, pluginsRoot: filepath.Clean(pluginsRoot)}
}

// Version implements pluginui.Resolver.
func (r pluginUIResolver) Version(pluginID, version string) (pluginui.Version, bool) {
	versions, err := r.updater.Versions(pluginID)
	if err != nil {
		return pluginui.Version{}, false
	}
	for _, v := range versions {
		if v.Version != version || v.Manifest == nil {
			continue
		}
		// 已隔离或拒绝的版本停止发布 UI；安全保留的旧版本仍可读取静态资源。
		if v.Status == updater.VersionQuarantined || v.Status == updater.VersionRejected {
			return pluginui.Version{}, false
		}
		dir := install.VersionDir(r.pluginsRoot, pluginID, version)
		if st, err := os.Stat(dir); err != nil || !st.IsDir() {
			return pluginui.Version{}, false
		}
		out := pluginui.Version{Dir: dir, Icon: v.Manifest.Icon}
		if v.Manifest.UI != nil {
			out.ConnectSources = append([]string(nil), v.Manifest.UI.ConnectSources...)
		}
		return out, true
	}
	return pluginui.Version{}, false
}

// pluginPackageLoader confines catalog schema reads to the immutable version
// directory of one published version. The paths come from the signed manifest,
// never from a request.
func pluginPackageLoader(pluginsRoot, pluginID, version string) (catalog.LoadFile, error) {
	if pluginsRoot == "" || !filepath.IsAbs(pluginsRoot) {
		return nil, errors.New("the plugin package directory is not configured")
	}
	if err := sandbox.ValidateID(pluginID); err != nil {
		return nil, err
	}
	if !pluginVersionPattern.MatchString(version) {
		return nil, errors.New("the installed plugin version is not a safe path component")
	}
	versionDir := install.VersionDir(filepath.Clean(pluginsRoot), pluginID, version)
	return func(path string) ([]byte, error) {
		full, err := versionFilePath(versionDir, path)
		if err != nil {
			return nil, err
		}
		return readSmallFile(full, maxConfigSchemaBytes)
	}, nil
}

// Install installs a staged package.
func (m *pluginManager) Install(ctx context.Context, req api.InstallPackageRequest) (api.PluginVersion, error) {
	ctx = context.WithoutCancel(ctx) // a lifecycle outlives its caller; see lifecycleContext
	version, err := m.updater.Install(ctx, updater.InstallRequest{
		PackagePath:          req.PackagePath,
		AcceptedCapabilities: req.AcceptedCapabilities,
		ExpectedRevision:     req.ExpectedRevision,
	})
	if err != nil {
		return api.PluginVersion{}, err
	}
	if version == nil {
		return api.PluginVersion{}, problem.New(problem.Internal,
			"The updater reported a successful install without a version.")
	}
	m.syncCatalog(ctx)
	return pluginVersionDTO(*version), nil
}

// Update replaces the active version. The systemd unit name is per plugin, so
// the adapter forces the restart strategy through Controller.UpdatePlugin.
func (m *pluginManager) Update(ctx context.Context, req api.UpdatePackageRequest) (api.PluginUpdate, error) {
	ctx = context.WithoutCancel(ctx)
	result, err := m.update(ctx, updater.UpdateRequest{
		PluginID:             req.PluginID,
		PackagePath:          req.PackagePath,
		Strategy:             updater.StrategyRestart,
		AcceptedCapabilities: req.AcceptedCapabilities,
		ExpectedRevision:     req.ExpectedRevision,

		AcceptPublisherChange: req.AcceptPublisherChange,
	})
	if err != nil {
		return api.PluginUpdate{}, err
	}
	m.syncCatalog(ctx)
	return pluginUpdateDTO(result), nil
}

// Rollback switches to the retained previous version. The updater has no
// expected-revision argument, so a non-zero expectation is checked here before
// the call; the per-plugin updater lock still serializes the actual rollback.
func (m *pluginManager) Rollback(ctx context.Context, pluginID string, expectedRevision int64) (api.PluginUpdate, error) {
	ctx = context.WithoutCancel(ctx)
	if expectedRevision != 0 {
		active, ok := m.updater.Active(pluginID)
		if !ok {
			return api.PluginUpdate{}, problem.New(problem.NotFound,
				"Plugin %s has no active version.", pluginID)
		}
		if active.Revision != expectedRevision {
			return api.PluginUpdate{}, problem.Conflict(strconv.FormatInt(active.Revision, 10))
		}
	}
	result, err := m.updater.Rollback(ctx, pluginID)
	if err != nil {
		return api.PluginUpdate{}, err
	}
	m.syncCatalog(ctx)
	return pluginUpdateDTO(result), nil
}

// InspectPackage verifies and parses a staged package for the pre-install
// inspection (GAPS gap 4). The updater owns verification and the memory
// preflight; the adapter adds the disk capacity of the plugins filesystem,
// which only the host knows.
func (m *pluginManager) InspectPackage(ctx context.Context, req api.InspectPackageRequest) (api.PackageInspection, error) {
	insp, err := m.updater.Inspect(ctx, req.PackagePath)
	if err != nil {
		return api.PackageInspection{}, err
	}
	out := api.PackageInspection{
		PluginID:         insp.PluginID,
		Version:          insp.Version,
		SignatureValid:   insp.Signature.Valid,
		SignatureTrusted: insp.Signature.Trusted,
		SignatureKeyID:   insp.Signature.KeyID,
		UnpackedBytes:    insp.UnpackedBytes,
		Memory: api.InspectionCapacity{
			RequiredBytes:  int64(insp.Memory.RequiredBytes),
			AvailableBytes: int64(insp.Memory.AvailableBytes),
			OK:             insp.Memory.OK,
		},
	}
	for _, v := range insp.Problems {
		out.Problems = append(out.Problems, api.PackageProblem{
			Pointer: v.Pointer, Code: v.Code, Message: v.Message,
		})
	}
	if insp.Manifest != nil {
		out.Manifest = packageManifestPreview(insp.Manifest)
	}
	if insp.Installed != nil {
		out.Installed = &api.InstalledPluginVersion{
			Version: insp.Installed.Version, Revision: insp.Installed.Revision,
		}
	}
	out.Disk = m.diskCapacity(insp.UnpackedBytes)
	return out, nil
}

// diskCapacity reports whether the plugins filesystem has room for the
// package's unpacked content plus the installer reserve. A host whose free
// space cannot be read (an unsupported platform, an unset root) skips the
// check instead of blocking installs.
func (m *pluginManager) diskCapacity(required int64) api.InspectionCapacity {
	cap := api.InspectionCapacity{RequiredBytes: required, OK: true}
	if m.pluginsRoot == "" {
		return cap
	}
	avail, err := diskfree.Bytes(m.pluginsRoot)
	if err != nil {
		return cap
	}
	cap.AvailableBytes = int64(avail)
	cap.OK = uint64(required)+installDiskReserve <= avail
	return cap
}

// packageManifestPreview renders the manifest of a staged package for the
// pre-install inspection. Risk and approval are the values the catalog would
// publish: the capability risk floor and the ADR-0016 reachability clamp are
// applied with the same operations helpers the catalog uses, so the grant
// step shows what the install would actually run.
func packageManifestPreview(m *manifest.Manifest) *api.PackageManifest {
	out := &api.PackageManifest{
		ID: m.ID, Version: m.Version, Name: m.Name, Summary: m.Summary,
		Description: m.Description, Placement: m.Placement, Target: m.Target,
		ABI:         fmt.Sprintf("%d.%d", m.ABI.Major, m.ABI.MinimumMinor),
		PublisherID: m.Publisher.ID,
	}
	for _, c := range m.Capabilities {
		out.Capabilities = append(out.Capabilities, api.PluginCapability{
			Name: c.Name, Scope: c.Scope, Reason: c.Reason,
			Sensitive: operations.CapabilitySensitive(c.Name),
		})
	}
	r := m.Resources
	out.Resources = &api.PluginResources{
		MemoryMaxMB: r.MemoryMaxMB, CPUQuotaPercent: r.CPUQuotaPercent,
		PIDsMax: r.PIDsMax, FDsMax: r.FDsMax, DiskMaxMB: r.DiskMaxMB,
	}
	if m.UI != nil {
		out.UIRoutes = len(m.UI.Routes)
		out.Widgets = len(m.UI.Widgets)
		out.ConnectSources = append([]string{}, m.UI.ConnectSources...)
	}
	for _, op := range m.Operations {
		caps := operationCapabilities(m, op)
		reach := op.EffectiveReachability() || operations.ForcedReachability(op.Effect, caps)
		risk := operations.RiskFloor(op.Risk, op.Effect, caps)
		approval := op.EffectiveApproval()
		if reach {
			risk = operations.RiskHigh
			if approval == operations.ApprovalAuto {
				approval = operations.ApprovalAIConfirm
			}
		}
		out.Operations = append(out.Operations, api.PackageOperation{
			Name: op.Name, Summary: op.Summary, Effect: op.Effect,
			Risk: risk, Approval: approval, Reachability: reach,
		})
	}
	return out
}

// operationCapabilities resolves the capabilities one operation may use: its
// own list, or every capability of the plugin when the operation omits it
// (ADR-0007), exactly as the catalog resolves it.
func operationCapabilities(m *manifest.Manifest, op manifest.Operation) []operations.Capability {
	if op.Capabilities == nil {
		out := make([]operations.Capability, 0, len(m.Capabilities))
		for _, c := range m.Capabilities {
			out = append(out, operations.Capability{Name: c.Name, Scope: c.Scope})
		}
		return out
	}
	out := make([]operations.Capability, 0, len(op.Capabilities))
	for _, c := range op.Capabilities {
		out = append(out, operations.Capability{Name: c.Name, Scope: c.Scope})
	}
	return out
}

// GetConfig returns the active configuration revision; a plugin without one
// returns revision 0 and an empty object.
func (m *pluginManager) GetConfig(_ context.Context, pluginID string) (api.PluginConfig, error) {
	if _, ok := m.updater.Active(pluginID); !ok {
		return api.PluginConfig{}, problem.New(problem.NotFound,
			"Plugin %s is not installed.", pluginID)
	}
	cfg, ok := m.updater.ActiveConfig(pluginID)
	if !ok {
		return api.PluginConfig{PluginID: pluginID, Config: json.RawMessage("{}")}, nil
	}
	return pluginConfigDTO(cfg), nil
}

// ApplyConfig applies one configuration revision.
func (m *pluginManager) ApplyConfig(ctx context.Context, req api.ApplyPluginConfigRequest) (api.PluginConfig, error) {
	if err := m.ValidateConfig(ctx, req); err != nil {
		return api.PluginConfig{}, err
	}
	ctx = context.WithoutCancel(ctx)
	cfg, err := m.updater.ApplyConfig(ctx, updater.ConfigRequest{
		PluginID:         req.PluginID,
		Config:           req.Config,
		ExpectedRevision: req.ExpectedRevision,
	})
	if err != nil {
		return api.PluginConfig{}, err
	}
	return pluginConfigDTO(cfg), nil
}

// ======================== 配置入口共用真实授权守卫 ========================
// ValidateConfig 同时保护直接适配器调用，HTTP 预检不成为唯一授权边界。
func (m *pluginManager) ValidateConfig(ctx context.Context, req api.ApplyPluginConfigRequest) error {
	if ctx == nil || m == nil || m.validateConfig == nil {
		return problem.New(problem.PluginUnavailable, "配置授权后端尚未装配。")
	}
	if err := ctx.Err(); err != nil {
		return problem.From(err)
	}
	return m.validateConfig(ctx, req)
}

// ConfigSchema reads the JSON Schema of the active version's configuration.
// The path comes from the signed manifest, not from the request, and is
// confined to the immutable version directory.
func (m *pluginManager) ConfigSchema(_ context.Context, pluginID string) (json.RawMessage, error) {
	active, ok := m.updater.Active(pluginID)
	if !ok {
		return nil, problem.New(problem.NotFound, "Plugin %s is not installed.", pluginID)
	}
	if active.Manifest == nil || active.Manifest.Config.Schema == "" {
		return nil, &problem.Error{
			Code:   problem.PluginUnavailable,
			Detail: "The plugin does not declare a configuration schema.",
		}
	}
	path, err := configSchemaPath(m.pluginsRoot, pluginID, active.Version, active.Manifest.Config.Schema)
	if err != nil {
		return nil, err
	}
	raw, err := readConfigSchema(path)
	if err != nil {
		m.logger.Warn("the plugin configuration schema could not be read",
			"plugin_id", pluginID, "version", active.Version, "error", err)
		return nil, &problem.Error{
			Code:   problem.PluginUnavailable,
			Detail: "The plugin configuration schema is not available.",
			Cause:  err,
		}
	}
	return raw, nil
}

// pluginVersionDTO maps one updater version to the API type.
func pluginVersionDTO(v updater.Version) api.PluginVersion {
	return api.PluginVersion{
		PluginID:       v.PluginID,
		Version:        v.Version,
		Digest:         v.Digest,
		Status:         string(v.Status),
		InstallStatus:  string(v.InstallStatus),
		Active:         v.Active,
		InstalledAt:    v.InstalledAt,
		ActivatedAt:    v.ActivatedAt,
		RejectedReason: v.RejectedReason,
		Revision:       v.Revision,
	}
}

// pluginUpdateDTO maps one updater result to the API type.
func pluginUpdateDTO(u *updater.UpdateResult) api.PluginUpdate {
	if u == nil {
		return api.PluginUpdate{}
	}
	return api.PluginUpdate{
		SagaID:      u.SagaID,
		PluginID:    u.PluginID,
		FromVersion: u.FromVersion,
		ToVersion:   u.ToVersion,
		Strategy:    string(u.Strategy),
		State:       string(u.State),
		Restarted:   u.Restarted,
		Version:     pluginVersionDTO(u.Version),
	}
}

// pluginConfigDTO maps one updater configuration revision to the API type.
func pluginConfigDTO(c updater.ConfigRevision) api.PluginConfig {
	return api.PluginConfig{
		PluginID:  c.PluginID,
		Revision:  c.Revision,
		Config:    append(json.RawMessage(nil), c.Config...),
		Active:    c.Active,
		CreatedAt: c.CreatedAt,
		AppliedAt: c.AppliedAt,
	}
}

// configSchemaPath resolves the schema path inside the immutable version
// directory and rejects anything that escapes it.
func configSchemaPath(pluginsRoot, pluginID, version, schema string) (string, error) {
	if pluginsRoot == "" || !filepath.IsAbs(pluginsRoot) {
		return "", &problem.Error{
			Code:   problem.PluginUnavailable,
			Detail: "The plugin package directory is not configured.",
		}
	}
	if err := sandbox.ValidateID(pluginID); err != nil {
		return "", &problem.Error{
			Code:   problem.PluginUnavailable,
			Detail: "The installed plugin id is not a safe path component.",
		}
	}
	if !pluginVersionPattern.MatchString(version) {
		return "", &problem.Error{
			Code:   problem.PluginUnavailable,
			Detail: "The installed plugin version is not a safe path component.",
		}
	}
	versionDir := install.VersionDir(filepath.Clean(pluginsRoot), pluginID, version)
	path, err := versionFilePath(versionDir, schema)
	if err != nil {
		return "", &problem.Error{
			Code:   problem.PluginUnavailable,
			Detail: "The plugin configuration schema path is invalid.",
		}
	}
	return path, nil
}

// versionFilePath joins a package-relative path onto an immutable version
// directory and rejects anything that escapes it.
func versionFilePath(versionDir, rel string) (string, error) {
	clean := filepath.Clean(filepath.FromSlash(rel))
	if clean == "." || filepath.IsAbs(clean) || clean == ".." ||
		strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return "", errors.New("the path escapes the version directory")
	}
	path := filepath.Join(versionDir, clean)
	back, err := filepath.Rel(versionDir, path)
	if err != nil || back == ".." || strings.HasPrefix(back, ".."+string(filepath.Separator)) ||
		filepath.IsAbs(back) {
		return "", errors.New("the path escapes the version directory")
	}
	return path, nil
}

// readSmallFile reads at most max bytes and validates the JSON.
func readSmallFile(path string, max int) (json.RawMessage, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, int64(max)+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > max {
		return nil, errors.New("the file exceeds the size limit")
	}
	if !json.Valid(raw) {
		return nil, errors.New("the file is not valid JSON")
	}
	return json.RawMessage(raw), nil
}

// readConfigSchema reads at most maxConfigSchemaBytes and validates the JSON.
func readConfigSchema(path string) (json.RawMessage, error) {
	return readSmallFile(path, maxConfigSchemaBytes)
}
