// SPDX-License-Identifier: AGPL-3.0-only

package updater

import (
	"context"
	"encoding/json"
	"time"

	"github.com/qwq-panel/qwq/internal/platform/problem"
	"github.com/qwq-panel/qwq/internal/storage"
	"github.com/qwq-panel/qwq/sdk/manifest"
)

// Handle is one plugin instance as the runtime knows it. It is opaque to the
// updater: only the Runtime that produced it may interpret it. A nil Handle
// always means "no instance", and the updater never stores one in the
// database.
type Handle any

// InstanceSpec describes the instance the updater wants to run.
//
// VersionDir is not part of the spec: the version directory is the
// installer's convention (install.VersionDir), and the runtime adapter knows
// the plugins root. The adapter derives the unit, entrypoint and directory
// from PluginID, Version and Manifest.
type InstanceSpec struct {
	PluginID string `json:"plugin_id"`
	Version  string `json:"version"`
	// Digest is the verified package digest recorded at install time.
	Digest string `json:"digest"`
	// Manifest is the verified manifest of this version.
	Manifest *manifest.Manifest `json:"manifest"`
	// Config is the active configuration JSON the instance must start with;
	// empty means "no configuration yet" and the runtime sends {}.
	Config json.RawMessage `json:"config,omitempty"`
	// ConfigRevision is the active configuration revision the instance must
	// start with; 0 means the plugin has no configuration yet.
	ConfigRevision int64 `json:"config_revision"`
	// InstanceHandle is the opaque plugin-side instance identity to use at
	// Initialize. Empty lets the runtime derive one from the process identity,
	// which is what the production adapter does (a plugin instance lives
	// exactly as long as its process).
	InstanceHandle string `json:"instance_handle,omitempty"`
	// DataDir is the host-derived absolute per-instance data directory passed
	// at Initialize (InitializeRequest.data_dir). The runtime adapter fills it
	// from its configured data root for a plugin that declares backup paths;
	// empty means the plugin needs no persistent directory. It is host state,
	// never plugin input, and carries no version or generation.
	DataDir string `json:"data_dir,omitempty"`
}

// Runtime is the narrow seam between the updater's state machine and the
// process supervisor. The production implementation is left to the host,
// which adapts internal/pluginhost/supervisor and internal/sandbox.
//
// Contract:
//   - Start creates a candidate that must not run background work (timers,
//     subscriptions, workers) until Activate. It fails if the version already
//     has a live instance; the caller uses Attach in that case.
//   - Attach connects to an already-running instance without restarting or
//     stopping it (crash recovery after a host restart). It fails when no
//     instance is running, and it must prove the process runs spec.Version:
//     with one unit per plugin another version may own the process, and a
//     mismatch is an error, never a handle.
//   - Ready waits until the transport and the plugin's self-check are ready.
//   - Activate enables background work and succeeds at most once per
//     instance: later calls are no-ops returning nil. Deactivate is the
//     inverse and is safe to call on a non-active instance.
//   - Stop asks the instance to drain and stop within grace; Release frees
//     the host-side resources of an instance that is already stopped.
//     Stop and Release are idempotent and return nil for an instance that is
//     already gone, so recovery can clean up after a crash.
//   - Health is a cheap check; it is called once after Activate and may be
//     called by the host at any time.
//   - ValidateConfig and ApplyConfig are called with the candidate revision
//     number outside any database transaction. ValidateConfig must not change
//     anything; ApplyConfig reports success only when the instance runs with
//     that revision.
//   - SwapRoutes publishes an immutable snapshot for request routing. The
//     implementation must replace an atomic pointer: concurrent readers see
//     either the complete old table or the complete new one, never a mixture
//     (ARCH §5.7).
type Runtime interface {
	Start(ctx context.Context, spec InstanceSpec) (Handle, error)
	Attach(ctx context.Context, spec InstanceSpec) (Handle, error)
	Ready(ctx context.Context, h Handle) error
	Activate(ctx context.Context, h Handle) error
	Deactivate(ctx context.Context, h Handle) error
	Stop(ctx context.Context, h Handle, grace time.Duration) error
	Release(ctx context.Context, h Handle) error
	Health(ctx context.Context, h Handle) error
	ValidateConfig(ctx context.Context, h Handle, revision int64, cfg json.RawMessage) error
	ApplyConfig(ctx context.Context, h Handle, revision int64, cfg json.RawMessage) error
	SwapRoutes(routes *RouteTable)
}

// MemorySource reports node memory in bytes. The updater uses it for the
// preflight of ARCH §6.3: Available is MemAvailable, Current is the cgroup
// usage of the plugin instance that is about to be replaced.
type MemorySource interface {
	Available() (uint64, error)
	Current(pluginID string) (uint64, error)
}

// Installer publishes plugin packages and their systemd units. The host
// adapts internal/pluginhost/install (Extract/Commit) and internal/sandbox
// (Limits/UnitSpec/Installer).
type Installer interface {
	// Stage verifies and unpacks pkgPath into a private staging directory.
	// It performs no database or systemd write.
	Stage(ctx context.Context, pkgPath string) (Staged, error)
	// Inspect reports what Stage would decide about pkgPath without installing
	// anything (GAPS gap 4). A package the trust root or a host policy refuses
	// is not an error: the verdict reports the signature outcome and the
	// strictly parsed manifest. Errors are reserved for packages whose
	// container or manifest cannot be parsed at all.
	Inspect(ctx context.Context, pkgPath string) (InspectionVerdict, error)
	// InstallUnit publishes the staged package at its immutable version
	// directory and installs the rendered unit and drop-in. For an update it
	// must not disturb the running old instance. Calling it twice for the same
	// version must succeed or fail deterministically, so recovery can retry.
	InstallUnit(ctx context.Context, staged Staged) error
	// ReinstallUnit re-renders the systemd unit for an already published
	// version. The unit name is per plugin, so a rollback (or a failed update
	// that restores the previous version) must point the unit back at the old
	// version directory before starting it. It must be idempotent.
	ReinstallUnit(ctx context.Context, pluginID, version string, m *manifest.Manifest) error
	// RemoveUnit removes the unit artifacts and version directory of a
	// version that is being discarded. The updater only calls it when no other
	// version of the plugin is running or active, because the systemd unit
	// name is per plugin rather than per version.
	RemoveUnit(ctx context.Context, pluginID, version string) error
	// PurgeData 只在明确要求彻底卸载时清理本插件的持久数据与宿主状态。
	// 必须幂等；失败阻止删行事务，缺少版本时的重试也必须执行。
	PurgeData(ctx context.Context, pluginID string) error
}

// CredentialLifecycle 是 Installer 的可选内部扩展；无凭据存储的实现保持
// 原行为。开始与健康终态收口必须复用调用方事务，不另开写事务或扩大 peer 身份。
type CredentialLifecycle interface {
	CredentialRotationEnabled() bool
	BeginCredentialRotationTx(ctx context.Context, tx *storage.Tx, pluginID string) error
	FinishCredentialRotationTx(ctx context.Context, tx *storage.Tx, pluginID string) error
}

// InspectionVerdict is the install-time verdict of one package, reported for
// the pre-install inspection. A signature- or trust-class refusal comes back
// as a verdict with Valid=false, never as an error, so the caller can explain
// it; UnpackedBytes is then still the verified content size when the package
// itself could be read.
type InspectionVerdict struct {
	// Staged is the fully verified package when every check passed; the caller
	// must DiscardStaged it. nil when the package was refused.
	Staged *Staged
	// Manifest is the strictly parsed manifest whenever the package parses
	// safely, even when the signature check refused it.
	Manifest *manifest.Manifest
	// Valid reports whether signing key verification accepts the package
	// (crypto, publisher binding and key policy); Trusted reports whether the
	// signing key is in the trust root. An unsigned package is neither.
	Valid   bool
	Trusted bool
	// KeyID is the signing key id from the signature envelope, "" when absent.
	KeyID string
	// UnpackedBytes is the verified content size; 0 when unknown.
	UnpackedBytes int64
	// Problems are field violations of the host's own checks that an install
	// would refuse with (e.g. runtime remote scripts in ui/).
	Problems []problem.Violation
}

// Staged is one verified package. The Installer returns it from Stage and
// receives it back in InstallUnit; the updater treats Handle as opaque and
// never stores it.
type Staged struct {
	// PluginID and Version are the manifest identity. Empty fields are taken
	// from Manifest.
	PluginID string
	Version  string
	// Digest is the verified package digest, "sha256:<hex>". Empty means
	// "derive from ManifestJSON".
	Digest string
	// Manifest is the parsed manifest the installer verified.
	Manifest *manifest.Manifest
	// ManifestJSON is the raw manifest bytes the signature covers. Empty
	// means "re-encode Manifest", which loses the original byte form but keeps
	// the meaning.
	ManifestJSON json.RawMessage
	// Handle is installer-private state, e.g. *install.Staged.
	Handle any
	// Discard releases a staging directory that was never published. It is
	// optional and must be safe after a successful InstallUnit (a no-op).
	Discard func() error
}

// DiscardStaged calls Discard if the installer provided one.
func (s Staged) DiscardStaged() error {
	if s.Discard == nil {
		return nil
	}
	return s.Discard()
}
