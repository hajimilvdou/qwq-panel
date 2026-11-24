// SPDX-License-Identifier: AGPL-3.0-only

package api

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/qwq-panel/qwq/internal/actor"
	"github.com/qwq-panel/qwq/internal/catalog"
	"github.com/qwq-panel/qwq/internal/gateway"
	"github.com/qwq-panel/qwq/internal/operations"
	"github.com/qwq-panel/qwq/internal/platform/problem"
	"github.com/qwq-panel/qwq/internal/secrets"
	"github.com/qwq-panel/qwq/internal/storage"
)

// Plugin routes. The package lifecycle is served by the updater adapter the
// host passes as Deps.Plugins; a host without an updater answers the mutating
// routes with 503 PLUGIN_UNAVAILABLE, keeps GET /plugins empty and reports
// every single plugin as NOT_FOUND. Uploads are staged by Deps.PluginUploads:
// a request never names a filesystem path.

// pluginInstallRequest is the PluginInstallRequest schema.
type pluginInstallRequest struct {
	UploadID             string                  `json:"upload_id"`
	AcceptedCapabilities []acceptedCapabilityDTO `json:"accepted_capabilities"`
	ExpectedRevision     string                  `json:"expected_revision,omitempty"`
}

// pluginUpdateRequest is the PluginUpdateRequest schema.
type pluginUpdateRequest struct {
	UploadID              string                  `json:"upload_id"`
	AcceptedCapabilities  []acceptedCapabilityDTO `json:"accepted_capabilities"`
	ExpectedRevision      string                  `json:"expected_revision,omitempty"`
	AcceptPublisherChange bool                    `json:"accept_publisher_change,omitempty"`
}

// pluginRollbackRequest is the PluginRollbackRequest schema; the body is
// optional.
type pluginRollbackRequest struct {
	ExpectedRevision string `json:"expected_revision,omitempty"`
}

// pluginRestartRequest is the PluginRestartRequest schema; the body is optional.
type pluginRestartRequest struct {
	Reason string `json:"reason,omitempty"`
}

// pluginConfigRequest is the PluginConfigRequest schema.
type pluginConfigRequest struct {
	Config           json.RawMessage `json:"config"`
	ExpectedRevision string          `json:"expected_revision,omitempty"`
}

// acceptedCapabilityDTO is one accepted capability. The updater identifies a
// capability by (name, scope); an empty scope accepts the name only when the
// signed manifest declares it under a single scope.
type acceptedCapabilityDTO struct {
	Name  string `json:"name"`
	Scope string `json:"scope,omitempty"`
}

// pluginInvokeRequest is the PluginInvokeRequest schema.
type pluginInvokeRequest struct {
	Payload          json.RawMessage `json:"payload"`
	Subject          string          `json:"subject,omitempty"`
	ExpectedRevision string          `json:"expected_revision,omitempty"`
	PlanID           string          `json:"plan_id,omitempty"`
}

// --- wire DTOs --------------------------------------------------------------

// pluginVersionDTO is the PluginVersion schema.
type pluginVersionDTO struct {
	PluginID       string `json:"plugin_id"`
	Version        string `json:"version"`
	Digest         string `json:"digest"`
	Status         string `json:"status"`
	InstallStatus  string `json:"install_status"`
	Active         bool   `json:"active"`
	InstalledAt    string `json:"installed_at"`
	ActivatedAt    string `json:"activated_at,omitempty"`
	RejectedReason string `json:"rejected_reason,omitempty"`
	Revision       string `json:"revision"`
}

// pluginDTO is the Plugin schema.
type pluginDTO struct {
	PluginID       string             `json:"plugin_id"`
	Name           string             `json:"name"`
	Summary        string             `json:"summary"`
	PublisherID    string             `json:"publisher_id"`
	Placement      string             `json:"placement"`
	ActiveVersion  string             `json:"active_version,omitempty"`
	ActiveStatus   string             `json:"active_status,omitempty"`
	InstallStatus  string             `json:"install_status,omitempty"`
	ConfigRevision string             `json:"config_revision"`
	Versions       []pluginVersionDTO `json:"versions"`
	CreatedAt      string             `json:"created_at"`
	Revision       string             `json:"revision"`

	// Manifest metadata of the active version (GAPS gap 3). All texts are
	// written by the plugin author: untrusted.
	Description  string                `json:"description,omitempty"`
	IconURL      string                `json:"icon_url,omitempty"`
	Homepage     string                `json:"homepage,omitempty"`
	License      string                `json:"license,omitempty"`
	Builtin      bool                  `json:"builtin,omitempty"`
	Enabled      bool                  `json:"enabled"`
	Startup      string                `json:"startup,omitempty"`
	HasConfig    bool                  `json:"has_config"`
	Capabilities []pluginCapabilityDTO `json:"capabilities,omitempty"`
	Operations   []pluginActionDTO     `json:"operations,omitempty"`
	Dependencies []string              `json:"dependencies,omitempty"`
	Resources    *pluginResourcesDTO   `json:"resources,omitempty"`
	UI           *pluginUIDTO          `json:"ui,omitempty"`
	Runtime      *pluginRuntimeDTO     `json:"runtime,omitempty"`
}

// pluginCapabilityDTO is the PluginCapability schema. Sensitive is the host's
// verdict (ARCH §10.3 高敏); the reason is the author's text.
type pluginCapabilityDTO struct {
	Name      string `json:"name"`
	Scope     string `json:"scope"`
	Reason    string `json:"reason"`
	Sensitive bool   `json:"sensitive"`
}

// pluginResourcesDTO is the PluginResources schema.
type pluginResourcesDTO struct {
	MemoryMaxMB     int64 `json:"memory_max_mb"`
	CPUQuotaPercent int64 `json:"cpu_quota_percent"`
	PIDsMax         int64 `json:"pids_max"`
	FDsMax          int64 `json:"fds_max"`
	DiskMaxMB       int64 `json:"disk_max_mb"`
}

// pluginRouteDTO is the PluginRoute schema.
type pluginRouteDTO struct {
	Path       string `json:"path"`
	Title      string `json:"title"`
	Nav        bool   `json:"nav"`
	Permission string `json:"permission"`
}

// pluginWidgetDTO is the PluginWidget schema (manifest 1.3, ADR-0018).
type pluginWidgetDTO struct {
	ID             string `json:"id"`
	Title          string `json:"title"`
	Kind           string `json:"kind"`
	Operation      string `json:"operation"`
	RefreshSeconds int64  `json:"refresh_seconds"`
	Size           string `json:"size"`
	Icon           string `json:"icon,omitempty"`
	Color          string `json:"color,omitempty"`
}

// pluginUIDTO is the PluginUi schema: the plugin's UI contribution with
// versioned URLs the Web Shell can load directly.
type pluginUIDTO struct {
	EntryURL       string            `json:"entry_url"`
	Routes         []pluginRouteDTO  `json:"routes"`
	Widgets        []pluginWidgetDTO `json:"widgets"`
	ConnectSources []string          `json:"connect_sources"`
}

// pluginRuntimeDTO is the PluginRuntime schema: the in-memory process state.
type pluginRuntimeDTO struct {
	State          string `json:"state"`
	Since          string `json:"since,omitempty"`
	Restarts       int    `json:"restarts,omitempty"`
	MemoryBytes    int64  `json:"memory_bytes,omitempty"`
	MemoryMaxBytes int64  `json:"memory_max_bytes,omitempty"`
	Detail         string `json:"detail,omitempty"`
}

// pluginActionDTO is the ActionMeta schema of one operation of the active
// version, as the catalog holds it (risk and approval already clamped).
type pluginActionDTO struct {
	ID                  string `json:"id"`
	Summary             string `json:"summary"`
	Effect              string `json:"effect"`
	Risk                string `json:"risk"`
	DeclaredRisk        string `json:"declared_risk"`
	Mode                string `json:"mode"`
	Idempotent          bool   `json:"idempotent"`
	Plannable           bool   `json:"plannable"`
	Undo                string `json:"undo,omitempty"`
	UIRoute             string `json:"ui_route,omitempty"`
	Permission          string `json:"permission,omitempty"`
	TimeoutMS           int    `json:"timeout_ms,omitempty"`
	Source              string `json:"source"`
	PluginID            string `json:"plugin_id,omitempty"`
	Placement           string `json:"placement,omitempty"`
	Approval            string `json:"approval,omitempty"`
	ApprovalSummary     string `json:"approval_summary,omitempty"`
	ApprovalDescription string `json:"approval_description,omitempty"`
	Reachability        bool   `json:"reachability,omitempty"`
}

// pluginUpdateDTO is the PluginUpdateResult schema.
type pluginUpdateDTO struct {
	SagaID      string           `json:"saga_id"`
	PluginID    string           `json:"plugin_id"`
	FromVersion string           `json:"from_version,omitempty"`
	ToVersion   string           `json:"to_version"`
	Strategy    string           `json:"strategy"`
	State       string           `json:"state"`
	Restarted   bool             `json:"restarted"`
	Version     pluginVersionDTO `json:"version"`
}

// pluginConfigDTO is the PluginConfig schema.
type pluginConfigDTO struct {
	PluginID  string          `json:"plugin_id"`
	Revision  string          `json:"revision"`
	Config    json.RawMessage `json:"config"`
	Active    bool            `json:"active"`
	CreatedAt string          `json:"created_at,omitempty"`
	AppliedAt string          `json:"applied_at,omitempty"`
}

// pluginPackageUploadDTO is the PluginPackageUpload schema.
type pluginPackageUploadDTO struct {
	UploadID  string `json:"upload_id"`
	Size      int64  `json:"size"`
	SHA256    string `json:"sha256"`
	ExpiresAt string `json:"expires_at"`
}

func newPluginVersionDTO(v PluginVersion) pluginVersionDTO {
	return pluginVersionDTO{
		PluginID:       v.PluginID,
		Version:        v.Version,
		Digest:         v.Digest,
		Status:         v.Status,
		InstallStatus:  v.InstallStatus,
		Active:         v.Active,
		InstalledAt:    ts(v.InstalledAt),
		ActivatedAt:    ts(v.ActivatedAt),
		RejectedReason: v.RejectedReason,
		Revision:       storage.Revision(v.Revision),
	}
}

// newPluginDTO renders p. actions are the catalog entries of the plugin,
// already filtered by plugin id (nil when the catalog holds none).
func newPluginDTO(p Plugin, actions []pluginActionDTO) pluginDTO {
	versions := make([]pluginVersionDTO, 0, len(p.Versions))
	for _, v := range p.Versions {
		versions = append(versions, newPluginVersionDTO(v))
	}
	enabled := true
	if p.Enabled != nil {
		enabled = *p.Enabled
	}
	d := pluginDTO{
		PluginID:       p.PluginID,
		Name:           p.Name,
		Summary:        p.Summary,
		PublisherID:    p.Publisher,
		Placement:      p.Placement,
		ActiveVersion:  p.ActiveVersion,
		ActiveStatus:   p.ActiveStatus,
		InstallStatus:  p.InstallStatus,
		ConfigRevision: storage.Revision(p.ConfigRevision),
		Versions:       versions,
		CreatedAt:      ts(p.CreatedAt),
		Revision:       storage.Revision(p.Revision),
		Description:    p.Description,
		Homepage:       p.Homepage,
		License:        p.License,
		Builtin:        p.Builtin,
		Enabled:        enabled,
		Startup:        p.Startup,
		HasConfig:      p.HasConfig,
		Operations:     actions,
	}
	// The versioned static prefix is the only place plugin files are served
	// from (ADR-0018); URLs exist only for an ACTIVE version.
	if p.ActiveVersion != "" {
		if p.Icon != "" {
			d.IconURL = pluginUIURL(p.PluginID, p.ActiveVersion, p.Icon)
		}
	}
	for _, c := range p.Capabilities {
		d.Capabilities = append(d.Capabilities, pluginCapabilityDTO(c))
	}
	d.Dependencies = append(d.Dependencies, p.Dependencies...)
	if p.Resources != nil {
		d.Resources = &pluginResourcesDTO{
			MemoryMaxMB:     p.Resources.MemoryMaxMB,
			CPUQuotaPercent: p.Resources.CPUQuotaPercent,
			PIDsMax:         p.Resources.PIDsMax,
			FDsMax:          p.Resources.FDsMax,
			DiskMaxMB:       p.Resources.DiskMaxMB,
		}
	}
	if p.UI != nil && p.ActiveVersion != "" {
		ui := &pluginUIDTO{
			EntryURL:       pluginUIURL(p.PluginID, p.ActiveVersion, p.UI.Entry),
			ConnectSources: append([]string{}, p.UI.ConnectSources...),
		}
		for _, r := range p.UI.Routes {
			ui.Routes = append(ui.Routes, pluginRouteDTO(r))
		}
		for _, w := range p.UI.Widgets {
			ui.Widgets = append(ui.Widgets, pluginWidgetDTO(w))
		}
		d.UI = ui
	}
	if p.Runtime != nil {
		d.Runtime = &pluginRuntimeDTO{
			State:          p.Runtime.State,
			Since:          ts(p.Runtime.Since),
			Restarts:       p.Runtime.Restarts,
			MemoryBytes:    p.Runtime.MemoryBytes,
			MemoryMaxBytes: p.Runtime.MemoryMaxBytes,
			Detail:         clipUntrusted(p.Runtime.Detail, maxRuntimeDetail),
		}
	}
	return d
}

// pluginDTO decorates plugin UI entry URLs with the stateless HMAC capability
// prefix when a panel secret entry path is active (preventing sandboxed iframe
// sub-resource 404/timeout when SameSite=Lax _g cookies are stripped).
func (a *api) pluginDTO(p Plugin) pluginDTO {
	d := newPluginDTO(p, pluginActionsOf(a.d.Catalog, p.PluginID))
	if a.d.Access != nil && d.UI != nil && d.UI.EntryURL != "" {
		d.UI.EntryURL = a.d.Access.Snapshot().DecoratePluginUIEntryURL(d.UI.EntryURL)
	}
	return d
}

// pluginUIURL composes a URL under the versioned plugin static prefix
// (ADR-0018). path comes from the signed manifest, never from a request.
func pluginUIURL(pluginID, version, path string) string {
	return "/plugin-ui/" + pluginID + "/" + version + "/" + path
}

// maxRuntimeDetail bounds the runtime detail text the supervisor may attach.
const maxRuntimeDetail = 500

// clipUntrusted cuts untrusted text to a rune budget without splitting UTF-8.
func clipUntrusted(s string, max int) string {
	if len(s) <= max {
		return s
	}
	cut := max
	for cut > 0 && s[cut]&0xC0 == 0x80 {
		cut--
	}
	return s[:cut]
}

// newPluginActionDTO maps one catalog entry to the ActionMeta schema.
func newPluginActionDTO(e *catalog.Entry) pluginActionDTO {
	return pluginActionDTO{
		ID: e.ID, Summary: e.Summary, Effect: e.Effect, Risk: e.Risk, DeclaredRisk: e.DeclaredRisk,
		Mode: e.Mode, Idempotent: e.Idempotent, Plannable: e.Plannable, Undo: e.Undo,
		UIRoute: e.UIRoute, Permission: e.Permission, TimeoutMS: e.TimeoutMS,
		Source: string(e.Source), PluginID: e.PluginID, Placement: e.Placement,
		Approval: e.Approval, ApprovalSummary: e.ApprovalSummary, ApprovalDescription: e.ApprovalDescription,
		Reachability: e.Reachability,
	}
}

// pluginActionsOf returns the catalog actions of one plugin, sorted by ID.
func pluginActionsOf(c *catalog.Catalog, pluginID string) []pluginActionDTO {
	if c == nil {
		return nil
	}
	var out []pluginActionDTO
	for _, e := range c.Entries() {
		if e.Source == catalog.Plugin && e.PluginID == pluginID {
			out = append(out, newPluginActionDTO(e))
		}
	}
	return out
}

func newPluginUpdateDTO(u PluginUpdate) pluginUpdateDTO {
	return pluginUpdateDTO{
		SagaID:      u.SagaID,
		PluginID:    u.PluginID,
		FromVersion: u.FromVersion,
		ToVersion:   u.ToVersion,
		Strategy:    u.Strategy,
		State:       u.State,
		Restarted:   u.Restarted,
		Version:     newPluginVersionDTO(u.Version),
	}
}

func newPluginConfigDTO(c PluginConfig) pluginConfigDTO {
	cfg := c.Config
	if len(bytes.TrimSpace(cfg)) == 0 {
		cfg = json.RawMessage("{}")
	}
	return pluginConfigDTO{
		PluginID:  c.PluginID,
		Revision:  storage.Revision(c.Revision),
		Config:    cfg,
		Active:    c.Active,
		CreatedAt: ts(c.CreatedAt),
		AppliedAt: ts(c.AppliedAt),
	}
}

func newPluginPackageUploadDTO(u PluginUpload) pluginPackageUploadDTO {
	return pluginPackageUploadDTO{
		UploadID:  u.ID,
		Size:      u.Size,
		SHA256:    u.SHA256,
		ExpiresAt: ts(u.ExpiresAt),
	}
}

// --- handlers ---------------------------------------------------------------

// uploadPluginPackage stages a package for a later install/update. It executes
// nothing: the signed manifest is only read when the upload is installed.
func (a *api) uploadPluginPackage(w http.ResponseWriter, r *http.Request) {
	act, err := a.caller(r)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	if err := a.authorize(r.Context(), act, "host.plugins:install", ""); err != nil {
		a.fail(w, r, err)
		return
	}
	if a.d.Plugins == nil || a.d.PluginUploads == nil {
		a.fail(w, r, pluginUnavailable())
		return
	}
	upload, err := a.d.PluginUploads.Receive(r.Context(), r, principalScope(act))
	if err != nil {
		a.fail(w, r, err)
		return
	}
	a.writeResource(w, r, http.StatusCreated, newPluginPackageUploadDTO(upload), nil)
}

// deletePluginPackage discards a staged package upload owned by the caller so
// failed preflights or aborted installs do not exhaust the per-account quota.
func (a *api) deletePluginPackage(w http.ResponseWriter, r *http.Request) {
	act, err := a.caller(r)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	if err := a.authorize(r.Context(), act, "host.plugins:install", ""); err != nil {
		a.fail(w, r, err)
		return
	}
	if a.d.Plugins == nil || a.d.PluginUploads == nil {
		a.fail(w, r, pluginUnavailable())
		return
	}
	uploadID := r.PathValue("upload_id")
	if !a.d.PluginUploads.RemoveForPrincipal(uploadID, principalScope(act)) {
		a.fail(w, r, problem.New(problem.NotFound, "The staged plugin package was not found."))
		return
	}
	a.inspections.drop(uploadID)
	w.WriteHeader(http.StatusNoContent)
}

// listPlugins returns one page of the plugins the updater recorded.
func (a *api) listPlugins(w http.ResponseWriter, r *http.Request) {
	act, err := a.caller(r)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	if err := a.authorize(r.Context(), act, "host.plugins:read", ""); err != nil {
		a.fail(w, r, err)
		return
	}
	q, err := a.g.ListQuery(r)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	items := []any{}
	next := ""
	if a.d.Plugins != nil {
		plugins, err := a.d.Plugins.List(r.Context())
		if err != nil {
			a.fail(w, r, err)
			return
		}
		sort.Slice(plugins, func(i, j int) bool { return plugins[i].PluginID < plugins[j].PluginID })
		var page []Plugin
		page, next = pagePlugins(plugins, q.Cursor, q.Limit)
		for _, p := range page {
			items = append(items, a.pluginDTO(p))
		}
	}
	a.writeList(w, r, listResponse{Items: items, NextCursor: next, Revision: a.watermark()}, q.Fields)
}

// getPlugin returns one installed plugin.
func (a *api) getPlugin(w http.ResponseWriter, r *http.Request) {
	act, err := a.caller(r)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	if err := a.authorize(r.Context(), act, "host.plugins:read", r.PathValue("plugin_id")); err != nil {
		a.fail(w, r, err)
		return
	}
	if a.d.Plugins == nil {
		a.fail(w, r, problem.New(problem.NotFound, "The plugin is not installed."))
		return
	}
	p, err := a.d.Plugins.Get(r.Context(), r.PathValue("plugin_id"))
	if err != nil {
		a.fail(w, r, err)
		return
	}
	fields, err := a.fields(r)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	a.writeResource(w, r, http.StatusOK, a.pluginDTO(p), fields)
}

// installPlugin installs a staged package. The version comes from the signed
// manifest; the request cannot name one.
func (a *api) installPlugin(w http.ResponseWriter, r *http.Request) {
	act, err := a.caller(r)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	if err := a.authorize(r.Context(), act, "host.plugins:install", ""); err != nil {
		a.fail(w, r, err)
		return
	}
	if a.d.Plugins == nil || a.d.PluginUploads == nil {
		a.fail(w, r, pluginUnavailable())
		return
	}
	var req pluginInstallRequest
	if err := a.decodeJSON(r, &req); err != nil {
		a.fail(w, r, err)
		return
	}
	uploadID, capabilities, revision, err := validatePackageRequest(req.UploadID, req.AcceptedCapabilities, req.ExpectedRevision)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	slot, err := a.pluginReplaySlot(r, act, req)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	if done, err := a.replayedPluginResult(w, r, slot); err != nil {
		a.fail(w, r, err)
		return
	} else if done {
		return
	}
	path, ok := a.d.PluginUploads.filePathForPrincipal(uploadID, principalScope(act))
	if !ok {
		a.fail(w, r, uploadNotFound())
		return
	}
	version, err := a.d.Plugins.Install(lifecycleContext(r), InstallPackageRequest{
		PackagePath:          path,
		AcceptedCapabilities: capabilities,
		ExpectedRevision:     revision,
	})
	if err != nil {
		a.fail(w, r, err)
		return
	}
	a.discardUpload(r, uploadID)
	w.Header().Set("Location", "/api/v1/plugins/"+version.PluginID)
	a.writePluginResult(w, r, slot, http.StatusCreated, newPluginVersionDTO(version))
}

// updatePlugin replaces the active version of a plugin with a staged package.
func (a *api) updatePlugin(w http.ResponseWriter, r *http.Request) {
	act, err := a.caller(r)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	pluginID := r.PathValue("plugin_id")
	if err := a.authorize(r.Context(), act, "host.plugins:update", pluginID); err != nil {
		a.fail(w, r, err)
		return
	}
	if a.d.Plugins == nil || a.d.PluginUploads == nil {
		a.fail(w, r, pluginUnavailable())
		return
	}
	var req pluginUpdateRequest
	if err := a.decodeJSON(r, &req); err != nil {
		a.fail(w, r, err)
		return
	}
	// Handing a plugin to another publisher is a human decision (ADR-0015).
	if req.AcceptPublisherChange && act.Kind != actor.Human {
		a.fail(w, r, problem.New(problem.PermissionDenied, "Only a human session can accept a publisher change."))
		return
	}
	uploadID, capabilities, revision, err := validatePackageRequest(req.UploadID, req.AcceptedCapabilities, req.ExpectedRevision)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	slot, err := a.pluginReplaySlot(r, act, req)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	if done, err := a.replayedPluginResult(w, r, slot); err != nil {
		a.fail(w, r, err)
		return
	} else if done {
		return
	}
	path, ok := a.d.PluginUploads.filePathForPrincipal(uploadID, principalScope(act))
	if !ok {
		a.fail(w, r, uploadNotFound())
		return
	}
	result, err := a.d.Plugins.Update(lifecycleContext(r), UpdatePackageRequest{
		PluginID:             pluginID,
		PackagePath:          path,
		AcceptedCapabilities: capabilities,
		ExpectedRevision:     revision,

		AcceptPublisherChange: req.AcceptPublisherChange,
	})
	if err != nil {
		a.fail(w, r, err)
		return
	}
	a.discardUpload(r, uploadID)
	a.writePluginResult(w, r, slot, http.StatusOK, newPluginUpdateDTO(result))
}

// rollbackPlugin switches a plugin back to its retained previous version.
func (a *api) rollbackPlugin(w http.ResponseWriter, r *http.Request) {
	act, err := a.caller(r)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	pluginID := r.PathValue("plugin_id")
	if err := a.authorize(r.Context(), act, "host.plugins:rollback", pluginID); err != nil {
		a.fail(w, r, err)
		return
	}
	if a.d.Plugins == nil {
		a.fail(w, r, pluginUnavailable())
		return
	}
	var req pluginRollbackRequest
	if err := a.decodeOptionalJSON(r, &req); err != nil {
		a.fail(w, r, err)
		return
	}
	revision, err := parseOptionalRevision(req.ExpectedRevision)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	slot, err := a.pluginReplaySlot(r, act, req)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	if done, err := a.replayedPluginResult(w, r, slot); err != nil {
		a.fail(w, r, err)
		return
	} else if done {
		return
	}
	result, err := a.d.Plugins.Rollback(lifecycleContext(r), pluginID, revision)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	a.writePluginResult(w, r, slot, http.StatusOK, newPluginUpdateDTO(result))
}

// restartPlugin stops the running instance of a plugin and starts it again with
// the active version and configuration. Like install, update and rollback it
// runs in the updater's own transactions, so it is catalog-exempt and answers
// with the refreshed plugin (GAPS gap 7).
func (a *api) restartPlugin(w http.ResponseWriter, r *http.Request) {
	act, err := a.caller(r)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	pluginID := r.PathValue("plugin_id")
	if err := a.authorize(r.Context(), act, "host.plugins:update", pluginID); err != nil {
		a.fail(w, r, err)
		return
	}
	if a.d.Plugins == nil {
		a.fail(w, r, pluginUnavailable())
		return
	}
	var req pluginRestartRequest
	if err := a.decodeOptionalJSON(r, &req); err != nil {
		a.fail(w, r, err)
		return
	}
	if len([]rune(req.Reason)) > maxPluginReason {
		a.fail(w, r, problem.Validation(problem.Violation{
			Pointer: "/reason", Code: "INVALID", Message: "The reason is longer than 500 characters.",
		}))
		return
	}
	slot, err := a.pluginReplaySlot(r, act, req)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	if done, err := a.replayedPluginResult(w, r, slot); err != nil {
		a.fail(w, r, err)
		return
	} else if done {
		return
	}
	p, err := a.d.Plugins.Restart(lifecycleContext(r), pluginID, req.Reason)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	// The restart runs outside the operation surface, so its audit row is
	// written here; the updater audits its own sagas.
	rec := operations.AuditRecord{
		Actor: act, Action: "plugin.restart", Subject: "plugins/" + pluginID,
		Outcome: operations.AuditSuccess, NodeID: a.d.NodeID, RequestID: requestID(r),
	}
	if req.Reason != "" {
		if b, err := json.Marshal(map[string]string{"reason": req.Reason}); err == nil {
			rec.Details = b
		}
	}
	if err := a.d.DB.Update(r.Context(), func(tx *storage.Tx) error {
		return operations.Audit(r.Context(), tx, rec)
	}); err != nil {
		a.d.Logger.WarnContext(r.Context(), "api: audit plugin restart", "error", err)
	}
	a.writePluginResult(w, r, slot, http.StatusOK, a.pluginDTO(p))
}

// getPluginLogs reads one page of a plugin's journal (GAPS gap 7). The text is
// untrusted plugin output: the privileged helper truncates each line at 4 KiB
// and only ever reads this plugin's unit.
func (a *api) getPluginLogs(w http.ResponseWriter, r *http.Request) {
	act, err := a.caller(r)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	pluginID := r.PathValue("plugin_id")
	if err := a.authorize(r.Context(), act, "host.plugins:logs", pluginID); err != nil {
		a.fail(w, r, err)
		return
	}
	if a.d.Plugins == nil {
		a.fail(w, r, pluginUnavailable())
		return
	}
	if _, err := a.d.Plugins.Get(r.Context(), pluginID); err != nil {
		a.fail(w, r, err)
		return
	}
	list, err := a.g.ListQuery(r)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	if list.SinceRevision != "" {
		a.fail(w, r, queryViolation("/since_revision", "INVALID",
			"Plugin logs are not a revisioned collection; page with cursor."))
		return
	}
	stream := r.URL.Query().Get("stream")
	switch stream {
	case "", "stdout", "stderr":
	default:
		a.fail(w, r, queryViolation("/stream", "INVALID", "The stream must be stdout or stderr."))
		return
	}
	page, err := a.d.Plugins.Logs(r.Context(), pluginID, list.Cursor, stream, list.Limit)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	items := make([]any, 0, len(page.Items))
	for _, line := range page.Items {
		out, err := project(list.Fields, line)
		if err != nil {
			a.fail(w, r, err)
			return
		}
		items = append(items, out)
	}
	a.writeResource(w, r, http.StatusOK, pluginLogPageDTO{
		Items: items, NextCursor: page.NextCursor, Truncated: page.Truncated,
	}, nil)
}

// pluginLogPageDTO is the PluginLogPage schema; items are any so the fields
// projection can replace a line with its projected form.
type pluginLogPageDTO struct {
	Items      []any  `json:"items"`
	NextCursor string `json:"next_cursor,omitempty"`
	Truncated  bool   `json:"truncated"`
}

// maxPluginReason bounds the free text a lifecycle request carries into the
// audit log (the reason maxLength of the public schemas).
const maxPluginReason = 500

// getPluginConfig returns the active configuration with sensitive values
// redacted.
func (a *api) getPluginConfig(w http.ResponseWriter, r *http.Request) {
	act, err := a.caller(r)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	pluginID := r.PathValue("plugin_id")
	if err := a.authorize(r.Context(), act, "host.plugins:read", pluginID); err != nil {
		a.fail(w, r, err)
		return
	}
	if a.d.Plugins == nil {
		a.fail(w, r, pluginUnavailable())
		return
	}
	cfg, err := a.d.Plugins.GetConfig(r.Context(), pluginID)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	if cfg.Revision > 0 {
		schema, err := a.pluginConfigSchema(r.Context(), pluginID)
		if err != nil {
			a.fail(w, r, err)
			return
		}
		cfg.Config, err = redactPluginConfig(schema, cfg.Config)
		if err != nil {
			a.fail(w, r, err)
			return
		}
	}
	fields, err := a.fields(r)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	a.writeResource(w, r, http.StatusOK, newPluginConfigDTO(cfg), fields)
}

// putPluginConfig applies one configuration revision. Sensitive values declared
// by the plugin's schema are moved into the secret store before the snapshot is
// stored, so the updater only ever persists references.
func (a *api) putPluginConfig(w http.ResponseWriter, r *http.Request) {
	act, err := a.caller(r)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	pluginID := r.PathValue("plugin_id")
	if err := a.authorize(r.Context(), act, "host.plugins:config", pluginID); err != nil {
		a.fail(w, r, err)
		return
	}
	if a.d.Plugins == nil {
		a.fail(w, r, pluginUnavailable())
		return
	}
	var req pluginConfigRequest
	if err := a.decodeJSON(r, &req); err != nil {
		a.fail(w, r, err)
		return
	}
	if !isJSONObject(req.Config) {
		a.fail(w, r, problem.Validation(problem.Violation{
			Pointer: "/config", Code: "INVALID",
			Message: "config must be a JSON object.",
		}))
		return
	}
	revision, err := parseOptionalRevision(req.ExpectedRevision)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	slot, err := a.pluginReplaySlot(r, act, req)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	if done, err := a.replayedPluginResult(w, r, slot); err != nil {
		a.fail(w, r, err)
		return
	} else if done {
		return
	}
	if err := a.d.Plugins.ValidateConfig(r.Context(), ApplyPluginConfigRequest{Actor: act, PluginID: pluginID, Config: req.Config, ExpectedRevision: revision}); err != nil {
		a.fail(w, r, err)
		return
	}
	schema, err := a.pluginConfigSchema(r.Context(), pluginID)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	stored, extracted, err := a.extractPluginSecrets(lifecycleContext(r), pluginID, schema, req.Config)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	applied, err := a.d.Plugins.ApplyConfig(lifecycleContext(r), ApplyPluginConfigRequest{
		Actor:            act,
		PluginID:         pluginID,
		Config:           stored,
		ExpectedRevision: revision,
	})
	if err != nil {
		cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 5*time.Second)
		cleanupErr := a.d.Secrets.DiscardExtracted(cleanupCtx, extracted)
		cancel()
		if cleanupErr != nil {
			a.fail(w, r, &problem.Error{Code: problem.Unavailable,
				Detail: "Temporary plugin secrets could not be cleaned up after the failed configuration write.", Cause: cleanupErr})
			return
		}
		a.fail(w, r, err)
		return
	}
	applied.Config, err = redactPluginConfig(schema, applied.Config)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	a.writePluginResult(w, r, slot, http.StatusOK, newPluginConfigDTO(applied))
}

// getPluginConfigSchema returns the configuration JSON Schema of the active
// version. The schema is written by the plugin author: untrusted, and the
// caller renders the form from it without executing anything.
func (a *api) getPluginConfigSchema(w http.ResponseWriter, r *http.Request) {
	act, err := a.caller(r)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	pluginID := r.PathValue("plugin_id")
	if err := a.authorize(r.Context(), act, "host.plugins:read", pluginID); err != nil {
		a.fail(w, r, err)
		return
	}
	if a.d.Plugins == nil {
		a.fail(w, r, pluginUnavailable())
		return
	}
	schema, err := a.pluginConfigSchema(r.Context(), pluginID)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	if err := gateway.WriteJSON(w, http.StatusOK, schema); err != nil {
		a.d.Logger.WarnContext(r.Context(), "api: write response", "error", err)
	}
}

// uninstallPlugin queues the uninstall job (GAPS gap 7). The removal itself is
// the updater's idempotent step sequence, which owns its own transactions and
// talks to the privileged helper, so it runs as a mode=job host action rather
// than inside the operation executor's write transaction.
func (a *api) uninstallPlugin(w http.ResponseWriter, r *http.Request) {
	act, err := a.caller(r)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	pluginID := r.PathValue("plugin_id")
	if err := a.authorize(r.Context(), act, "host.plugins:uninstall", pluginID); err != nil {
		a.fail(w, r, err)
		return
	}
	if strings.TrimSpace(pluginID) == "security.basic" {
		a.fail(w, r, problem.New(problem.StateConflict, "基础安全防护插件为系统必装底座，不支持卸载。"))
		return
	}
	if a.d.Plugins == nil {
		a.fail(w, r, pluginUnavailable())
		return
	}
	revision, err := gateway.ExpectedRevisionQuery(r)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	purge, err := parsePurgeData(r)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	// Purging data is destructive: it needs a recent second factor. The session
	// stays valid, so this is 403 MFA_REQUIRED, never 401.
	if purge && !act.MFA {
		a.fail(w, r, problem.New(problem.MFARequired, "Deleting a plugin's data requires a fresh second factor."))
		return
	}
	p, err := a.d.Plugins.Get(r.Context(), pluginID)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	// The guard is checked here, against the plugin revision the caller saw:
	// the operation target of a host action is a subject, and the plugin's
	// public revision is its active version's.
	if want, err := parseOptionalRevision(revision); err != nil {
		a.fail(w, r, err)
		return
	} else if want != 0 && want != p.Revision {
		a.fail(w, r, problem.Conflict(storage.Revision(p.Revision)))
		return
	}
	dependents, err := a.d.Plugins.Dependents(r.Context(), pluginID)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	if len(dependents) > 0 {
		conflict := problem.New(problem.StateConflict, "Plugin %s is still required by other plugins.", pluginID)
		conflict.Dependents = dependents
		a.fail(w, r, conflict)
		return
	}
	args, err := json.Marshal(map[string]any{"plugin_id": pluginID, "purge_data": purge})
	if err != nil {
		a.fail(w, r, problem.Wrap(err))
		return
	}
	key, err := gateway.IdempotencyKey(r)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	resp, err := a.d.Ops.Run(r.Context(), operations.RunRequest{
		Actor:       act,
		TraceID:     traceID(r),
		RequestID:   requestID(r),
		NodeID:      a.d.NodeID,
		Action:      actionPluginUninstall,
		Target:      operations.Target{Subject: "plugins/" + pluginID},
		Args:        args,
		Idempotency: operations.Idempotency{Key: key, Method: r.Method, Route: r.URL.Path},
	})
	if err != nil {
		a.fail(w, r, err)
		return
	}
	a.writeOperationResponse(w, resp)
}

// actionPluginUninstall is the catalog id of the uninstall job.
const actionPluginUninstall = "host.plugins.uninstall"

// parsePurgeData reads the optional purge_data query flag.
func parsePurgeData(r *http.Request) (bool, error) {
	switch v := r.URL.Query().Get("purge_data"); v {
	case "", "false":
		return false, nil
	case "true":
		return true, nil
	default:
		return false, queryViolation("/purge_data", "INVALID", "purge_data must be true or false.")
	}
}

// executePluginUninstall runs the removal on a job worker, outside any
// transaction. Every step is idempotent, so a retry after a crash continues.
func (a *api) executePluginUninstall(ctx context.Context, req operations.HostRequest) (json.RawMessage, error) {
	var args struct {
		PluginID  string `json:"plugin_id"`
		PurgeData bool   `json:"purge_data"`
	}
	if err := decodeArgs(req.Args, &args); err != nil {
		return nil, err
	}
	if a.d.Plugins == nil {
		return nil, pluginUnavailable()
	}
	pluginID := strings.TrimSpace(args.PluginID)
	if pluginID == "security.basic" {
		return nil, problem.New(problem.StateConflict, "基础安全防护插件为系统必装底座，不支持卸载。")
	}
	dependents, err := a.d.Plugins.Dependents(ctx, pluginID)
	if err != nil {
		return nil, err
	}
	if len(dependents) > 0 {
		conflict := problem.New(problem.StateConflict, "Plugin %s is still required by other plugins.", pluginID)
		conflict.Dependents = dependents
		return nil, conflict
	}
	if err := a.d.Plugins.Uninstall(ctx, pluginID, args.PurgeData); err != nil {
		return nil, err
	}
	return json.Marshal(map[string]any{
		"plugin_id": pluginID, "purge_data": args.PurgeData, "uninstalled": true,
	})
}

// Catalog ids of the enablement jobs (GAPS gap 7).
const (
	actionPluginEnable  = "host.plugins.enable"
	actionPluginDisable = "host.plugins.disable"
)

// enablePlugin and disablePlugin queue the enablement job. The flag is
// persistent, so a disabled plugin stays disabled across a host restart.
func (a *api) enablePlugin(w http.ResponseWriter, r *http.Request)  { a.setPluginEnabled(w, r, true) }
func (a *api) disablePlugin(w http.ResponseWriter, r *http.Request) { a.setPluginEnabled(w, r, false) }

func (a *api) setPluginEnabled(w http.ResponseWriter, r *http.Request, enabled bool) {
	act, err := a.caller(r)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	pluginID := r.PathValue("plugin_id")
	if err := a.authorize(r.Context(), act, "host.plugins:update", pluginID); err != nil {
		a.fail(w, r, err)
		return
	}
	if a.d.Plugins == nil {
		a.fail(w, r, pluginUnavailable())
		return
	}
	if _, err := a.d.Plugins.Get(r.Context(), pluginID); err != nil {
		a.fail(w, r, err)
		return
	}
	key, err := gateway.IdempotencyKey(r)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	args, err := json.Marshal(map[string]any{"plugin_id": pluginID})
	if err != nil {
		a.fail(w, r, problem.Wrap(err))
		return
	}
	action := actionPluginEnable
	if !enabled {
		action = actionPluginDisable
	}
	resp, err := a.d.Ops.Run(r.Context(), operations.RunRequest{
		Actor:       act,
		TraceID:     traceID(r),
		RequestID:   requestID(r),
		NodeID:      a.d.NodeID,
		Action:      action,
		Target:      operations.Target{Subject: "plugins/" + pluginID},
		Args:        args,
		Idempotency: operations.Idempotency{Key: key, Method: r.Method, Route: r.URL.Path},
	})
	if err != nil {
		a.fail(w, r, err)
		return
	}
	a.writeOperationResponse(w, resp)
}

// executePluginEnable and executePluginDisable run on a job worker: the flag is
// written in the updater's own transaction and the runtime is reconciled
// outside it, so no write transaction is held across a systemd call.
func (a *api) executePluginEnable(ctx context.Context, req operations.HostRequest) (json.RawMessage, error) {
	return a.executeSetEnabled(ctx, req, true)
}

func (a *api) executePluginDisable(ctx context.Context, req operations.HostRequest) (json.RawMessage, error) {
	return a.executeSetEnabled(ctx, req, false)
}

func (a *api) executeSetEnabled(ctx context.Context, req operations.HostRequest, enabled bool) (json.RawMessage, error) {
	var args struct {
		PluginID string `json:"plugin_id"`
	}
	if err := decodeArgs(req.Args, &args); err != nil {
		return nil, err
	}
	if a.d.Plugins == nil {
		return nil, pluginUnavailable()
	}
	if err := a.d.Plugins.SetEnabled(ctx, args.PluginID, enabled); err != nil {
		return nil, err
	}
	return json.Marshal(map[string]any{"plugin_id": args.PluginID, "enabled": enabled})
}

// invokeControllerPlugin calls an operation of a controller-placed plugin.
func (a *api) invokeControllerPlugin(w http.ResponseWriter, r *http.Request) {
	pluginID := r.PathValue("plugin_id")
	operation := r.PathValue("operation")
	a.invokePlugin(w, r, operations.Target{PluginID: pluginID, Subject: ""}, pluginID, operation)
}

// invokeNodePlugin calls an operation of a plugin instance on a node.
func (a *api) invokeNodePlugin(w http.ResponseWriter, r *http.Request) {
	nodeID := strings.TrimSpace(r.PathValue("node_id"))
	if nodeID == "" {
		a.fail(w, r, problem.New(problem.NotFound, "The node does not exist."))
		return
	}
	if nodeID != a.d.NodeID {
		var state string
		err := a.d.DB.Reader().QueryRowContext(r.Context(),
			`SELECT enrollment_state FROM nodes WHERE id = ?`, nodeID,
		).Scan(&state)
		if errors.Is(err, sql.ErrNoRows) {
			a.fail(w, r, problem.New(problem.NotFound, "The node does not exist."))
			return
		}
		if err != nil {
			a.fail(w, r, problem.Wrap(err))
			return
		}
		if state != "active" {
			a.fail(w, r, problem.New(problem.PreconditionFailed, "The target node is not active."))
			return
		}
	}
	pluginID := r.PathValue("plugin_id")
	operation := r.PathValue("operation")
	target := operations.Target{
		NodeID:     nodeID,
		PluginID:   pluginID,
		InstanceID: r.PathValue("instance_id"),
	}
	a.invokePlugin(w, r, target, pluginID, operation)
}

// invokePlugin turns a plugin invocation into a Run request. The action ID is
// `<plugin_id>/<operation>` (ActionId schema); while no plugin provides it the
// catalog answers NOT_FOUND, and once one does the operation manager owns the
// dispatch, the risk and the approval.
func (a *api) invokePlugin(w http.ResponseWriter, r *http.Request, target operations.Target, pluginID, operation string) {
	act, err := a.caller(r)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	var req pluginInvokeRequest
	if err := a.decodeJSON(r, &req); err != nil {
		a.fail(w, r, err)
		return
	}
	if !isJSONObject(req.Payload) {
		a.fail(w, r, problem.Validation(problem.Violation{
			Pointer: "/payload", Code: "INVALID", Message: "payload must be a JSON object.",
		}))
		return
	}
	if req.PlanID != "" {
		// Binding a call to an earlier plan requires the plan's args digest and
		// preconditions; the operation manager applies that only through
		// executePlan. Refusing is safer than silently dropping the guard.
		a.fail(w, r, problem.Validation(problem.Violation{
			Pointer: "/plan_id", Code: "UNSUPPORTED",
			Message: "Execute the plan with POST /api/v1/plans/{plan_id}/execute instead.",
		}))
		return
	}
	actionID := pluginID + "/" + operation
	entry, _ := a.d.Catalog.Get(actionID)
	key, err := gateway.IdempotencyKey(r)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	if key == "" && entry != nil && (entry.Effect != operations.EffectRead || entry.Mode == operations.ModeJob) {
		a.fail(w, r, problem.Validation(problem.Violation{
			In: "header", Pointer: "/Idempotency-Key", Code: "REQUIRED",
			Message: "Mutating plugin operations and persistent jobs require an Idempotency-Key header.",
		}))
		return
	}
	runNodeID := target.NodeID
	if runNodeID == "" {
		runNodeID = a.d.NodeID
	}
	// 同步 read+invoke widget 才进入轮询限额，不为轮询创建 operation。
	// 显式 read+job 使用持久任务和幂等预算，不借 widget 通道重复派发。
	if entry != nil && entry.Effect == operations.EffectRead && entry.Mode == operations.ModeInvoke && entry.WidgetRefreshSeconds > 0 {
		floor := time.Duration(entry.WidgetRefreshSeconds) * time.Second
		scope := principalScope(act) + "\x00" + actionID
		wait, ok := a.widgets.begin(scope, a.d.Clock.Now(), floor)
		if !ok {
			limited := problem.New(problem.RateLimited, "The widget refresh interval has not elapsed.")
			limited.RetryAfterSec = max(1, int((wait+time.Second-1)/time.Second))
			a.fail(w, r, limited)
			return
		}
		defer a.widgets.end(scope)

		// 对于处于休眠（stopped）状态的 on_demand 插件，直接读取其宿主持久 KV 中的
		// summary/* 快照返回，绝不因打开首页概览而唤醒全部闲置插件。
		if a.tryServeStoppedOnDemandWidgetSnapshot(w, r, act, entry, runNodeID, pluginID, operation) {
			return
		}
	}
	target.Subject = req.Subject
	resp, err := a.d.Ops.Run(r.Context(), operations.RunRequest{
		Actor:            act,
		TraceID:          gateway.TraceID(r.Context()),
		RequestID:        gateway.RequestID(r.Context()),
		NodeID:           runNodeID,
		Action:           actionID,
		Target:           target,
		Args:             req.Payload,
		ExpectedRevision: req.ExpectedRevision,
		Idempotency: operations.Idempotency{
			Key: key, Method: r.Method, Route: r.URL.Path, Fingerprint: fingerprint(req),
		},
	})
	if err != nil {
		a.fail(w, r, err)
		return
	}
	a.writeOperationResponse(w, resp)
}

// tryServeStoppedOnDemandWidgetSnapshot checks whether pluginID is a stopped
// on_demand plugin with a cached summary/* snapshot in host plugin-state KV.
// Returning true means the HTTP response has already been written without
// waking the hibernated plugin process.
func (a *api) tryServeStoppedOnDemandWidgetSnapshot(
	w http.ResponseWriter,
	r *http.Request,
	act actor.Actor,
	entry *catalog.Entry,
	nodeID, pluginID, operation string,
) bool {
	if nodeID != a.d.NodeID {
		return false
	}
	if a.d.Plugins == nil || a.d.DB == nil || a.d.Config.DataDir == "" {
		return false
	}
	if pluginID == "" || filepath.Base(pluginID) != pluginID || strings.Contains(pluginID, "..") {
		return false
	}
	p, err := a.d.Plugins.Get(r.Context(), pluginID)
	if err != nil || !strings.EqualFold(p.ActiveStatus, "active") || p.ActiveVersion == "" || p.Runtime == nil {
		return false
	}
	if p.Enabled != nil && !*p.Enabled {
		return false
	}
	if p.Runtime.State != "standby" && p.Runtime.State != "stopped" {
		return false
	}
	var manifestRaw string
	if err := a.d.DB.Reader().QueryRowContext(r.Context(),
		`SELECT manifest_json FROM plugin_versions WHERE plugin_id = ? AND active = 1`, pluginID,
	).Scan(&manifestRaw); err != nil {
		return false
	}
	var mf struct {
		Lifecycle struct {
			Startup string `json:"startup"`
		} `json:"lifecycle"`
	}
	if json.Unmarshal([]byte(manifestRaw), &mf) != nil || mf.Lifecycle.Startup != "on_demand" {
		return false
	}
	if entry.Permission != "" {
		if err := a.authorize(r.Context(), act, entry.Permission, nodeID); err != nil {
			a.fail(w, r, err)
			return true
		}
	}
	statePath := filepath.Join(a.d.Config.DataDir, "plugin-state", pluginID, "state.json")
	raw, err := os.ReadFile(statePath)
	if err != nil || len(bytes.TrimSpace(raw)) == 0 {
		return false
	}
	var doc struct {
		Entries map[string]struct {
			Value json.RawMessage `json:"value"`
		} `json:"entries"`
	}
	if json.Unmarshal(raw, &doc) != nil || len(doc.Entries) == 0 {
		return false
	}
	keys := []string{
		"summary/" + operation,
		"summary/" + strings.TrimPrefix(operation, pluginID+"."),
	}
	for _, k := range keys {
		rec, ok := doc.Entries[k]
		if ok && len(rec.Value) > 0 && json.Valid(rec.Value) {
			out := operations.Outcome{
				Action:        entry.ID,
				Status:        operations.Succeeded,
				EffectiveRisk: entry.Risk,
				Result:        rec.Value,
			}
			if err := gateway.WriteJSON(w, http.StatusOK, out); err != nil {
				a.d.Logger.Warn("api: write cached widget snapshot", "plugin", pluginID, "operation", operation, "error", err)
			}
			return true
		}
	}
	return false
}

// --- helpers ----------------------------------------------------------------

// lifecycleContext detaches a plugin lifecycle from the request context: a
// client disconnect or a reverse-proxy timeout must not cut a saga in half.
// The updater's Options.Timeout still bounds the operation.
func lifecycleContext(r *http.Request) context.Context {
	return context.WithoutCancel(r.Context())
}

// pluginUnavailable is the PLUGIN_UNAVAILABLE of a host without a plugin
// updater.
func pluginUnavailable() *problem.Error {
	return problem.New(problem.PluginUnavailable,
		"The plugin updater is not available on this host.")
}

// uploadNotFound is the same NOT_FOUND for expired, unknown and malformed
// upload ids once the grammar has already been checked.
func uploadNotFound() *problem.Error {
	return problem.New(problem.NotFound, "The package upload is unknown or expired.")
}

// validatePackageRequest checks the members shared by install and update.
func validatePackageRequest(uploadID string, accepted []acceptedCapabilityDTO, revision string) (string, []string, int64, error) {
	if uploadID == "" {
		return "", nil, 0, problem.Validation(problem.Violation{
			Pointer: "/upload_id", Code: "REQUIRED",
			Message: "upload_id is required.",
		})
	}
	if !pluginUploadIDPattern.MatchString(uploadID) {
		return "", nil, 0, problem.Validation(problem.Violation{
			Pointer: "/upload_id", Code: "INVALID",
			Message: "upload_id is not an upload this host issued.",
		})
	}
	if accepted == nil {
		return "", nil, 0, problem.Validation(problem.Violation{
			Pointer: "/accepted_capabilities", Code: "REQUIRED",
			Message: "accepted_capabilities is required; it records the consent shown to the user.",
		})
	}
	names := make([]string, 0, len(accepted))
	seen := make(map[string]struct{}, len(accepted))
	for i, c := range accepted {
		if c.Name == "" {
			return "", nil, 0, problem.Validation(problem.Violation{
				Pointer: "/accepted_capabilities/" + strconv.Itoa(i) + "/name", Code: "REQUIRED",
				Message: "A capability name is required.",
			})
		}
		entry := c.Name
		if c.Scope != "" {
			entry += ":" + c.Scope
		}
		if _, dup := seen[entry]; dup {
			continue
		}
		seen[entry] = struct{}{}
		names = append(names, entry)
	}
	rev, err := parseOptionalRevision(revision)
	if err != nil {
		return "", nil, 0, err
	}
	return uploadID, names, rev, nil
}

// parseOptionalRevision parses an optional opaque revision. The empty string
// and "0" mean "no expectation" (the updater's zero value).
func parseOptionalRevision(raw string) (int64, error) {
	if raw == "" {
		return 0, nil
	}
	n, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || n < 0 {
		return 0, problem.Validation(problem.Violation{
			Pointer: "/expected_revision", Code: "INVALID",
			Message: "expected_revision is not a revision this host issued.",
		})
	}
	return n, nil
}

// pagePlugins slices the sorted plugin list. The plugin id is the opaque cursor.
func pagePlugins(all []Plugin, cursor string, limit int) ([]Plugin, string) {
	if limit <= 0 {
		limit = 1
	}
	start := 0
	if cursor != "" {
		start = sort.Search(len(all), func(i int) bool { return all[i].PluginID > cursor })
	}
	if start >= len(all) {
		return nil, ""
	}
	end := start + limit
	if end > len(all) {
		end = len(all)
	}
	next := ""
	if end < len(all) {
		next = all[end-1].PluginID
	}
	return all[start:end], next
}

// pluginReplaySlot is the idempotency scope of one mutating plugin request.
type pluginReplaySlot struct {
	scope       string
	key         string
	fingerprint string
}

// pluginReplaySlot derives the replay identity from the actor, route and body.
func (a *api) pluginReplaySlot(r *http.Request, act actor.Actor, req any) (pluginReplaySlot, error) {
	key, err := a.idempotency(r, req)
	if err != nil {
		return pluginReplaySlot{}, err
	}
	return pluginReplaySlot{
		scope:       principalScope(act) + "\x00" + r.Method + "\x00" + r.URL.Path,
		key:         key.Key,
		fingerprint: key.Fingerprint,
	}, nil
}

// replayedPluginResult writes a cached response. A key reused with a different
// body is IDEMPOTENCY_KEY_REUSED.
func (a *api) replayedPluginResult(w http.ResponseWriter, r *http.Request, slot pluginReplaySlot) (bool, error) {
	entry, err := a.id.lookup(slot.scope, slot.key, slot.fingerprint)
	if err != nil || entry == nil {
		return false, err
	}
	w.Header().Set("Idempotency-Replayed", "true")
	if err := gateway.WriteJSON(w, entry.status, json.RawMessage(entry.body)); err != nil {
		a.d.Logger.WarnContext(r.Context(), "api: write response", "error", err)
	}
	return true, nil
}

// writePluginResult stores the response for an idempotent replay and writes it.
func (a *api) writePluginResult(w http.ResponseWriter, r *http.Request, slot pluginReplaySlot, status int, body any) {
	raw, err := json.Marshal(body)
	if err != nil {
		a.fail(w, r, problem.Wrap(err))
		return
	}
	a.id.store(slot.scope, slot.key, slot.fingerprint, status, raw)
	if err := gateway.WriteJSON(w, status, json.RawMessage(raw)); err != nil {
		a.d.Logger.WarnContext(r.Context(), "api: write response", "error", err)
	}
}

// discardUpload removes the staged package after a successful install.
func (a *api) discardUpload(r *http.Request, uploadID string) {
	if err := a.d.PluginUploads.Remove(uploadID); err != nil {
		a.d.Logger.WarnContext(r.Context(), "the uploaded plugin package could not be removed",
			"upload_id", uploadID, "error", err)
	}
}

// pluginConfigSchema returns the schema of the active version's configuration.
func (a *api) pluginConfigSchema(ctx context.Context, pluginID string) (json.RawMessage, error) {
	schema, err := a.d.Plugins.ConfigSchema(ctx, pluginID)
	if err != nil {
		return nil, err
	}
	if len(bytes.TrimSpace(schema)) == 0 {
		return nil, &problem.Error{
			Code:   problem.PluginUnavailable,
			Detail: "The plugin has no configuration schema.",
		}
	}
	return schema, nil
}

// extractPluginSecrets replaces sensitive configuration values with references
// before the snapshot reaches the updater.
func (a *api) extractPluginSecrets(ctx context.Context, pluginID string, schema, cfg json.RawMessage) (json.RawMessage, []secrets.Extracted, error) {
	if a.d.Secrets == nil {
		return nil, nil, &problem.Error{
			Code:   problem.PluginUnavailable,
			Detail: "No secret store is configured; the plugin configuration cannot be stored safely.",
		}
	}
	stored, extracted, err := a.d.Secrets.ExtractSecrets(ctx, schema, cfg, secrets.ExtractOptions{
		Owner:                   "plugins/" + pluginID,
		Purpose:                 "plugin.config",
		AllowExistingReferences: true,
	})
	if err != nil {
		return nil, nil, err
	}
	return stored, extracted, nil
}

// redactPluginConfig replaces sensitive values and secret references with the
// host's redaction marker.
func redactPluginConfig(schema, cfg json.RawMessage) (json.RawMessage, error) {
	if len(bytes.TrimSpace(cfg)) == 0 {
		return json.RawMessage("{}"), nil
	}
	redacted, err := secrets.RedactForExport(schema, cfg)
	if err != nil {
		return nil, &problem.Error{
			Code:   problem.PluginUnavailable,
			Detail: "The plugin configuration cannot be redacted for export.",
			Cause:  err,
		}
	}
	return redacted, nil
}

// isJSONObject reports whether raw is a JSON object.
func isJSONObject(raw json.RawMessage) bool {
	trimmed := bytes.TrimSpace(raw)
	return len(trimmed) >= 2 && trimmed[0] == '{' && trimmed[len(trimmed)-1] == '}' && json.Valid(trimmed)
}
