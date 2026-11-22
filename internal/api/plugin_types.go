// SPDX-License-Identifier: AGPL-3.0-only

package api

import (
	"context"
	"encoding/json"
	"time"

	"github.com/qwq-panel/qwq/internal/actor"
)

// PluginManager is the host's plugin package lifecycle, implemented by the
// cmd/qwq adapter over internal/pluginhost/updater. The API never handles a
// plugin package path from a request: Install and Update receive the private
// staging file the upload endpoint created and consumed.
//
// Every method must report failures as *problem.Error so the documented
// Problem codes survive to the HTTP response. Implementations must not leak
// local paths, package bytes or secret material in an error.
//
// A nil PluginManager is a host without an updater: the mutating plugin routes
// answer 503 PLUGIN_UNAVAILABLE, the list stays empty and a single plugin is
// NOT_FOUND.
type PluginManager interface {
	// List returns every plugin the node has a version row for.
	List(ctx context.Context) ([]Plugin, error)
	// Get returns one plugin, or NOT_FOUND.
	Get(ctx context.Context, pluginID string) (Plugin, error)
	// Install installs a package that has no active version yet.
	Install(ctx context.Context, req InstallPackageRequest) (PluginVersion, error)
	// Update replaces the active version. The adapter forces the restart
	// strategy because the production unit is per plugin.
	Update(ctx context.Context, req UpdatePackageRequest) (PluginUpdate, error)
	// Rollback switches back to the retained previous version. A non-zero
	// expectedRevision is checked against the active version revision.
	Rollback(ctx context.Context, pluginID string, expectedRevision int64) (PluginUpdate, error)
	// Restart stops the running instance and starts it again with the active
	// version and configuration, then returns the refreshed plugin (GAPS gap 7).
	Restart(ctx context.Context, pluginID, reason string) (Plugin, error)
	// Uninstall removes every version of a plugin, its unit and its rows. It is
	// idempotent: a retry after a crash continues where it stopped. purgeData
	// also deletes the retained configuration and the plugin token digest.
	Uninstall(ctx context.Context, pluginID string, purgeData bool) error
	// Dependents lists the plugins whose active manifest requires pluginID.
	Dependents(ctx context.Context, pluginID string) ([]string, error)
	// SetEnabled persists the enablement flag and makes the runtime agree with
	// it: disabling stops the plugin, enabling starts it again (GAPS gap 7).
	SetEnabled(ctx context.Context, pluginID string, enabled bool) error
	// Logs reads one page of the plugin's journal through the privileged
	// boundary. Lines are untrusted plugin text (GAPS gap 7).
	Logs(ctx context.Context, pluginID, cursor, stream string, limit int) (PluginLogPage, error)
	// InspectPackage verifies and parses a staged package for the pre-install
	// inspection (GAPS gap 4). It installs nothing and consumes nothing; a
	// signature refusal is part of the returned PackageInspection, not an
	// error.
	InspectPackage(ctx context.Context, req InspectPackageRequest) (PackageInspection, error)
	// GetConfig returns the active configuration revision of a plugin. A
	// plugin without an active configuration returns revision 0 and an empty
	// object.
	GetConfig(ctx context.Context, pluginID string) (PluginConfig, error)
	// ApplyConfig applies one immutable configuration revision.
	ApplyConfig(ctx context.Context, req ApplyPluginConfigRequest) (PluginConfig, error)
	// ValidateConfig 在秘密提取前核验真实主体和完整候选；
	// ApplyConfig 在自身写入口再次调用同一守卫。
	ValidateConfig(ctx context.Context, req ApplyPluginConfigRequest) error
	// ConfigSchema returns the JSON Schema of the plugin's active version
	// configuration. The API uses it to replace sensitive values with secret
	// references before storing them and to redact them on the way out.
	ConfigSchema(ctx context.Context, pluginID string) (json.RawMessage, error)
}

// Plugin is one plugin of the node, assembled from its version rows.
type Plugin struct {
	// PluginID is the manifest id.
	PluginID string
	// Name and Summary are written by the plugin author: untrusted.
	Name      string
	Summary   string
	Publisher string
	Placement string
	// ActiveVersion is empty when no version is ACTIVE.
	ActiveVersion string
	// ActiveStatus is the lifecycle state of ActiveVersion (ARCH §6.1).
	ActiveStatus string
	// InstallStatus is the installation state of ActiveVersion (ARCH §6.6).
	InstallStatus string
	// ConfigRevision is the active configuration revision; 0 means none.
	ConfigRevision int64
	// Versions is ordered newest first.
	Versions []PluginVersion
	// CreatedAt is the installation time of the oldest version.
	CreatedAt time.Time
	// Revision is the optimistic-concurrency revision of the active version.
	Revision int64

	// Manifest metadata of the ACTIVE version (GAPS gap 3, ARCH §5.3). All
	// texts are written by the plugin author: untrusted. Zero values when no
	// version is active.
	Description string
	// Icon is the package-relative icon path from the manifest; the API turns
	// it into icon_url.
	Icon     string
	Homepage string
	License  string
	// Builtin marks a plugin signed by the host's own publisher (ADR-0005);
	// the Shell hides the uninstall action for it.
	Builtin      bool
	HasConfig    bool
	Capabilities []PluginCapability
	Dependencies []string
	Resources    *PluginResources
	UI           *PluginUI
	// Runtime is the in-memory process state of the plugin; nil on a host
	// without a plugin runtime.
	Runtime *PluginRuntime
}

// PluginCapability is one capability of the active manifest (OpenAPI
// PluginCapability). Sensitive is the host's verdict (ARCH §10.3 高敏), not
// the author's.
type PluginCapability struct {
	Name      string
	Scope     string
	Reason    string
	Sensitive bool
}

// PluginResources is the resource budget of the active manifest.
type PluginResources struct {
	MemoryMaxMB     int64
	CPUQuotaPercent int64
	PIDsMax         int64
	FDsMax          int64
	DiskMaxMB       int64
}

// PluginRoute is one route the active version contributes to the Web Shell.
type PluginRoute struct {
	Path       string
	Title      string
	Nav        bool
	Permission string
}

// PluginWidget is one declarative overview card of the active version
// (manifest schema 1.3, ADR-0018).
type PluginWidget struct {
	ID             string
	Title          string
	Kind           string
	Operation      string
	RefreshSeconds int64
	Size           string
	Icon           string
	Color          string
}

// PluginUI is the UI metadata of the active version. Entry is the
// package-relative entry path; the API turns it into entry_url.
type PluginUI struct {
	Entry          string
	Routes         []PluginRoute
	Widgets        []PluginWidget
	ConnectSources []string
}

// PluginRuntime is the in-memory process state of one plugin (OpenAPI
// PluginRuntime). It is a snapshot: state running/stopped/crashed/unknown,
// with details when the supervisor has them.
type PluginRuntime struct {
	State          string
	Since          time.Time
	Restarts       int
	MemoryBytes    int64
	MemoryMaxBytes int64
	Detail         string
}

// PluginVersion is one plugin_versions row as the updater recorded it.
type PluginVersion struct {
	PluginID       string
	Version        string
	Digest         string
	Status         string
	InstallStatus  string
	Active         bool
	InstalledAt    time.Time
	ActivatedAt    time.Time
	RejectedReason string
	Revision       int64
}

// PluginUpdate is the committed saga of an install, update or rollback.
type PluginUpdate struct {
	SagaID      string
	PluginID    string
	FromVersion string
	ToVersion   string
	Strategy    string
	State       string
	Restarted   bool
	Version     PluginVersion
}

// PluginConfig is one immutable configuration revision. Config is the stored
// form: sensitive values are secret references, never plaintext.
type PluginConfig struct {
	PluginID  string
	Revision  int64
	Config    json.RawMessage
	Active    bool
	CreatedAt time.Time
	AppliedAt time.Time
}

// InstallPackageRequest carries the private package path the API resolved from
// an upload id. The plugin id and version are read from the signed manifest by
// the updater; the request cannot override them.
type InstallPackageRequest struct {
	PackagePath          string
	AcceptedCapabilities []string
	ExpectedRevision     int64
}

// UpdatePackageRequest replaces the active version of PluginID.
type UpdatePackageRequest struct {
	PluginID             string
	PackagePath          string
	AcceptedCapabilities []string
	ExpectedRevision     int64
	// AcceptPublisherChange is only ever true for a human caller.
	AcceptPublisherChange bool
}

// ApplyPluginConfigRequest 携带真实边界主体，Actor 不来自公共请求文档。
type ApplyPluginConfigRequest struct {
	Actor            actor.Actor
	PluginID         string
	Config           json.RawMessage
	ExpectedRevision int64
}

func (ApplyPluginConfigRequest) String() string   { return "api.ApplyPluginConfigRequest{[REDACTED]}" }
func (ApplyPluginConfigRequest) GoString() string { return "api.ApplyPluginConfigRequest{[REDACTED]}" }

// InspectPackageRequest carries the private package path the API resolved
// from an upload id.
type InspectPackageRequest struct {
	PackagePath string
}

// PackageInspection is the pre-install view of one staged package (GAPS gap
// 4). Byte counts are exact; the API renders megabytes.
type PackageInspection struct {
	// PluginID and Version are empty only when the manifest could not be
	// parsed (the signature-class refusal without a readable manifest).
	PluginID string
	Version  string
	// Manifest is the strictly parsed manifest; nil when the package was not
	// parseable.
	Manifest *PackageManifest
	// Signature is the install-time verdict. Valid=false with Trusted=true is
	// a tampered package, Valid=false with Trusted=false an unknown or absent
	// signing key; neither installs.
	SignatureValid   bool
	SignatureTrusted bool
	SignatureKeyID   string
	// Problems are field violations an install would refuse with (schema
	// version, publisher binding, extraction policy).
	Problems []PackageProblem
	// UnpackedBytes is the verified content size; 0 when unknown.
	UnpackedBytes int64
	// Memory and Disk are the install capacity preflights. Disk is filled by
	// the host adapter, which knows the plugins filesystem.
	Memory InspectionCapacity
	Disk   InspectionCapacity
	// Installed names the active version when the plugin is installed: the
	// package is an update, not a fresh install.
	Installed *InstalledPluginVersion
}

// PackageProblem is one field violation of the pre-install inspection; the
// FieldViolation schema. It is transport-local, so it does not depend on the
// platform problem package.
type PackageProblem struct {
	Pointer string
	Code    string
	Message string
}

// InspectionCapacity is one capacity preflight: required, available and the
// verdict. All values are bytes.
type InspectionCapacity struct {
	RequiredBytes  int64
	AvailableBytes int64
	OK             bool
}

// InstalledPluginVersion is the active version of an installed plugin.
type InstalledPluginVersion struct {
	Version  string
	Revision int64
}

// PackageManifest is the public preview of one parsed package manifest. All
// texts are written by the plugin author: untrusted.
type PackageManifest struct {
	ID          string
	Version     string
	Name        string
	Summary     string
	Description string
	Placement   string
	Target      string
	ABI         string
	// PublisherID is the publisher the package claims.
	PublisherID    string
	Capabilities   []PluginCapability
	ConnectSources []string
	Resources      *PluginResources
	Operations     []PackageOperation
	UIRoutes       int
	Widgets        int
}

// PackageOperation is one operation of a package preview, with the host's
// effective risk and approval already applied: what the install would run is
// what the inspection shows.
type PackageOperation struct {
	Name         string
	Summary      string
	Effect       string
	Risk         string
	Approval     string
	Reachability bool
}

// PluginLogLine is one journal line of a plugin. Line is untrusted text,
// truncated at 4 KiB by the privileged helper.
type PluginLogLine struct {
	At     string `json:"at"`
	Stream string `json:"stream"`
	Line   string `json:"line"`
}

// PluginLogPage is one page of plugin logs, oldest first within the page.
// NextCursor reads what came after the last line, so a viewer follows forward.
type PluginLogPage struct {
	Items      []PluginLogLine `json:"items"`
	NextCursor string          `json:"next_cursor,omitempty"`
	Truncated  bool            `json:"truncated"`
}
