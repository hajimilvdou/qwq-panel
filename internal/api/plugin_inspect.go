// SPDX-License-Identifier: AGPL-3.0-only

// Plugin package inspection (GAPS gap 4): GET /api/v1/plugin-packages/{upload_id}
// verifies and parses a staged package without installing it. The result is
// cached per upload id until the upload expires, so a package is never
// unpacked twice for repeated lookups.

package api

import (
	"net/http"
	"sync"
	"time"

	"github.com/qwq-panel/qwq/internal/platform/clock"
	"github.com/qwq-panel/qwq/internal/storage"
)

// pluginPackageInspectionDTO is the PluginPackageInspection schema. All
// manifest texts are written by the plugin author: untrusted.
type pluginPackageInspectionDTO struct {
	UploadID      string                     `json:"upload_id"`
	Size          int64                      `json:"size"`
	SHA256        string                     `json:"sha256"`
	ExpiresAt     string                     `json:"expires_at"`
	Signature     inspectionSignatureDTO     `json:"signature"`
	Manifest      *inspectionManifestDTO     `json:"manifest,omitempty"`
	Compatibility inspectionCompatibilityDTO `json:"compatibility"`
	Memory        inspectionCapacityDTO      `json:"memory"`
	Disk          inspectionCapacityDTO      `json:"disk"`
	Installed     *inspectionInstalledDTO    `json:"installed,omitempty"`
}

// inspectionSignatureDTO is the SignatureCheck schema.
type inspectionSignatureDTO struct {
	Valid       bool   `json:"valid"`
	KeyID       string `json:"key_id"`
	Trusted     bool   `json:"trusted"`
	PublisherID string `json:"publisher_id"`
}

// inspectionManifestDTO is the PackageManifest schema: a preview of the
// strictly parsed, not yet trusted manifest.
type inspectionManifestDTO struct {
	ID             string                   `json:"id"`
	Version        string                   `json:"version"`
	Name           string                   `json:"name"`
	Summary        string                   `json:"summary"`
	Description    string                   `json:"description,omitempty"`
	Placement      string                   `json:"placement"`
	Target         string                   `json:"target"`
	ABI            string                   `json:"abi"`
	Capabilities   []pluginCapabilityDTO    `json:"capabilities"`
	ConnectSources []string                 `json:"connect_sources"`
	Resources      *inspectionResourcesDTO  `json:"resources"`
	Operations     []inspectionOperationDTO `json:"operations"`
	UIRoutes       int                      `json:"ui_routes"`
	Widgets        int                      `json:"widgets"`
}

// inspectionResourcesDTO is the resource budget of the inspected manifest.
type inspectionResourcesDTO struct {
	MemoryMaxMB     int64 `json:"memory_max_mb"`
	CPUQuotaPercent int64 `json:"cpu_quota_percent"`
	PIDsMax         int64 `json:"pids_max"`
	FDsMax          int64 `json:"fds_max"`
	DiskMaxMB       int64 `json:"disk_max_mb"`
}

// inspectionOperationDTO is one operation of the preview with the host's
// effective risk and approval applied (ADR-0016 floors included).
type inspectionOperationDTO struct {
	Name         string `json:"name"`
	Summary      string `json:"summary"`
	Effect       string `json:"effect"`
	Risk         string `json:"risk"`
	Approval     string `json:"approval,omitempty"`
	Reachability bool   `json:"reachability,omitempty"`
}

// inspectionCompatibilityDTO is the CompatibilityCheck schema; ok is false
// exactly when a problem is present.
type inspectionCompatibilityDTO struct {
	OK       bool                     `json:"ok"`
	Problems []inspectionViolationDTO `json:"problems"`
}

// inspectionViolationDTO is the FieldViolation schema of an inspection
// problem.
type inspectionViolationDTO struct {
	Pointer string `json:"pointer"`
	Code    string `json:"code"`
	Message string `json:"message"`
}

// inspectionCapacityDTO is the CapacityCheck schema: integer megabytes.
type inspectionCapacityDTO struct {
	RequiredMB  int64 `json:"required_mb"`
	AvailableMB int64 `json:"available_mb"`
	OK          bool  `json:"ok"`
}

// inspectionInstalledDTO names the active version of an installed plugin.
type inspectionInstalledDTO struct {
	Version  string `json:"version"`
	Revision string `json:"revision"`
}

// newPluginPackageInspectionDTO merges the upload metadata with the host's
// inspection into the public schema.
func newPluginPackageInspectionDTO(u PluginUpload, insp PackageInspection) pluginPackageInspectionDTO {
	dto := pluginPackageInspectionDTO{
		UploadID:  u.ID,
		Size:      u.Size,
		SHA256:    u.SHA256,
		ExpiresAt: ts(u.ExpiresAt),
		Signature: inspectionSignatureDTO{
			Valid: insp.SignatureValid, Trusted: insp.SignatureTrusted, KeyID: insp.SignatureKeyID,
		},
		Memory:        newInspectionCapacityDTO(insp.Memory),
		Disk:          newInspectionCapacityDTO(insp.Disk),
		Compatibility: inspectionCompatibilityDTO{Problems: []inspectionViolationDTO{}},
	}
	for _, v := range insp.Problems {
		dto.Compatibility.Problems = append(dto.Compatibility.Problems, inspectionViolationDTO(v))
	}
	dto.Compatibility.OK = len(dto.Compatibility.Problems) == 0
	if m := insp.Manifest; m != nil {
		dto.Signature.PublisherID = m.PublisherID
		dto.Manifest = newInspectionManifestDTO(m)
	}
	if insp.Installed != nil {
		dto.Installed = &inspectionInstalledDTO{
			Version:  insp.Installed.Version,
			Revision: storage.Revision(insp.Installed.Revision),
		}
	}
	return dto
}

// newInspectionManifestDTO renders one manifest preview.
func newInspectionManifestDTO(m *PackageManifest) *inspectionManifestDTO {
	out := &inspectionManifestDTO{
		ID: m.ID, Version: m.Version, Name: m.Name, Summary: m.Summary,
		Description: m.Description, Placement: m.Placement, Target: m.Target, ABI: m.ABI,
		Capabilities:   []pluginCapabilityDTO{},
		Operations:     []inspectionOperationDTO{},
		ConnectSources: append([]string{}, m.ConnectSources...),
		UIRoutes:       m.UIRoutes,
		Widgets:        m.Widgets,
	}
	for _, c := range m.Capabilities {
		out.Capabilities = append(out.Capabilities, pluginCapabilityDTO(c))
	}
	if m.Resources != nil {
		out.Resources = &inspectionResourcesDTO{
			MemoryMaxMB:     m.Resources.MemoryMaxMB,
			CPUQuotaPercent: m.Resources.CPUQuotaPercent,
			PIDsMax:         m.Resources.PIDsMax,
			FDsMax:          m.Resources.FDsMax,
			DiskMaxMB:       m.Resources.DiskMaxMB,
		}
	}
	for _, op := range m.Operations {
		out.Operations = append(out.Operations, inspectionOperationDTO(op))
	}
	return out
}

// newInspectionCapacityDTO converts byte counts to the megabyte schema.
// Required bytes round up and available bytes round down, so the displayed
// verdict never looks roomier than the byte-level check found it.
func newInspectionCapacityDTO(c InspectionCapacity) inspectionCapacityDTO {
	const mib = 1 << 20
	return inspectionCapacityDTO{
		RequiredMB:  (c.RequiredBytes + mib - 1) / mib,
		AvailableMB: c.AvailableBytes / mib,
		OK:          c.OK,
	}
}

// inspectionCache memoizes the inspection of a staged upload until the upload
// expires (GAPS gap 4: repeated lookups must not unpack the package again).
// Entries are keyed by the random upload id and stay few (bounded by the
// upload caps); a failed computation is dropped so the next call retries.
type inspectionCache struct {
	clock   clock.Clock
	mu      sync.Mutex
	entries map[string]*inspectionEntry
}

// inspectionEntry is one in-flight or finished inspection.
type inspectionEntry struct {
	mu      sync.Mutex
	done    bool
	expires time.Time
	dto     pluginPackageInspectionDTO
}

// newInspectionCache returns an empty cache over the given clock.
func newInspectionCache(c clock.Clock) *inspectionCache {
	return &inspectionCache{clock: c, entries: make(map[string]*inspectionEntry)}
}

// clear drops every cached inspection so a trust-store mutation takes effect on
// the very next GET /api/v1/plugin-packages/{upload_id}.
func (c *inspectionCache) clear() {
	if c == nil {
		return
	}
	c.mu.Lock()
	clear(c.entries)
	c.mu.Unlock()
}

// load returns the cached inspection of uploadID or computes it once. The
// computation runs outside the cache lock; concurrent callers for the same
// upload wait for the first result instead of unpacking twice.
func (c *inspectionCache) load(uploadID string, expires time.Time, compute func() (pluginPackageInspectionDTO, error)) (pluginPackageInspectionDTO, error) {
	now := c.clock.Now().UTC()
	c.mu.Lock()
	for id, ent := range c.entries {
		if !ent.expires.After(now) {
			delete(c.entries, id)
		}
	}
	ent, ok := c.entries[uploadID]
	if !ok {
		ent = &inspectionEntry{expires: expires}
		c.entries[uploadID] = ent
	}
	c.mu.Unlock()

	ent.mu.Lock()
	defer ent.mu.Unlock()
	if ent.done {
		return ent.dto, nil
	}
	dto, err := compute()
	if err != nil {
		// Do not cache a failure: a retry must be able to succeed.
		c.mu.Lock()
		if c.entries[uploadID] == ent {
			delete(c.entries, uploadID)
		}
		c.mu.Unlock()
		return pluginPackageInspectionDTO{}, err
	}
	ent.dto, ent.done = dto, true
	return dto, nil
}

// inspectPluginPackage answers GET /api/v1/plugin-packages/{upload_id}: it
// verifies and parses the staged package for the uploader and installs
// nothing. Only the uploader may look: another principal gets the same 404 as
// for an unknown id (GAPS gap 4, matching the GW-07 per-principal quota).
func (a *api) inspectPluginPackage(w http.ResponseWriter, r *http.Request) {
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
	upload, ok := a.d.PluginUploads.Resolve(r.PathValue("upload_id"))
	if !ok || upload.principal != principalScope(act) {
		a.fail(w, r, uploadNotFound())
		return
	}
	dto, err := a.inspections.load(upload.ID, upload.ExpiresAt, func() (pluginPackageInspectionDTO, error) {
		insp, ierr := a.d.Plugins.InspectPackage(lifecycleContext(r), InspectPackageRequest{PackagePath: upload.path})
		if ierr != nil {
			return pluginPackageInspectionDTO{}, ierr
		}
		return newPluginPackageInspectionDTO(upload, insp), nil
	})
	if err != nil {
		a.fail(w, r, err)
		return
	}
	a.writeResource(w, r, http.StatusOK, dto, nil)
}
