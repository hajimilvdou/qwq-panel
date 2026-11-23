// SPDX-License-Identifier: AGPL-3.0-only

// This file adapts the host's privileged installer and systemd client to the
// seams of internal/pluginhost/updater (P3). It adds no policy of its own:
//
//   - PluginInstaller verifies and publishes packages with
//     internal/pluginhost/install and renders the systemd unit with
//     internal/sandbox.
//   - UpdaterRuntime starts and stops units, attaches to the plugin's native
//     gRPC socket and forwards the ABI v1 lifecycle RPCs.
//   - HostMemory feeds the updater's memory preflight from procfs and cgroup v2.
//
// The adapter is restart-only. The systemd unit name is per plugin rather than
// per version, so two versions cannot own a unit at the same time; the updater's
// overlap strategy would need a second unit and is therefore not supported here.
// The controller method that drives an update forces updater.StrategyRestart,
// and UpdaterRuntime.Start fails with FAILED_PRECONDITION while any instance of
// the plugin is still live.
//
// Naming note: this package already has PluginRuntime (the P2 supervisor
// integration). The adapter type below is therefore UpdaterRuntime.

package controller

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/qwq-panel/qwq/internal/platform/clock"
	"github.com/qwq-panel/qwq/internal/platform/problem"
	"github.com/qwq-panel/qwq/internal/pluginhost/install"
	"github.com/qwq-panel/qwq/internal/pluginhost/supervisor"
	"github.com/qwq-panel/qwq/internal/pluginhost/updater"
	"github.com/qwq-panel/qwq/internal/sandbox"
	"github.com/qwq-panel/qwq/internal/storage"
	"github.com/qwq-panel/qwq/sdk/abi"
	platformv1 "github.com/qwq-panel/qwq/sdk/gen/qwq/platform/v1"
	"github.com/qwq-panel/qwq/sdk/manifest"
	"github.com/qwq-panel/qwq/sdk/pkgfile"
)

const (
	// DefaultStagingDirName is the staging directory below PluginsRoot. It is
	// the fallback when no StagingRoot is configured; serve-controller passes
	// DefaultStagingRoot instead, because /var/lib/qwq-plugins belongs to root.
	DefaultStagingDirName = ".staging"

	// DefaultStagingRoot is where serve-controller unpacks a verified package
	// before the privileged helper publishes it. It is outside
	// DefaultPluginsDir: the controller runs as qwq and must not be able to
	// write a published version directory. It must be on the same filesystem as
	// the plugins root so the helper can rename the finished tree.
	DefaultStagingRoot = "/var/lib/qwq/staging"

	// pluginTokenBytes is the entropy of a plugin credential. Base64url without
	// padding turns it into 43 printable bytes, inside sandbox.MinTokenLen..
	// sandbox.MaxTokenLen.
	pluginTokenBytes = 32

	// updaterConnectTimeout bounds the go-plugin handshake after the unit was
	// started.
	updaterConnectTimeout = 10 * time.Second
	// updaterRPCTimeout bounds a lifecycle RPC whose caller set no deadline:
	// a plugin that never answers must not hold startup recovery forever.
	updaterRPCTimeout = 30 * time.Second

	// drainGraceMargin is added to the updater's stop grace for the drain RPC,
	// so the plugin can answer before the host gives up.
	drainGraceMargin = time.Second

	// forceKillTimeout bounds `systemctl kill` after a failed stop. It uses a
	// context detached from the caller, whose deadline may have caused the
	// failed stop in the first place.
	forceKillTimeout = 10 * time.Second
)

// versionNamePattern is the manifest version grammar. The updater validates it
// too; the installer repeats the check because the version becomes a path
// component.
var versionNamePattern = regexp.MustCompile(`^[0-9]+(\.[0-9]+)*([-+][0-9A-Za-z.+-]+)?$`)

// Compile-time seam checks.
var (
	_ updater.Installer    = (*PluginInstaller)(nil)
	_ updater.Runtime      = (*UpdaterRuntime)(nil)
	_ updater.MemorySource = (*HostMemory)(nil)
)

// --- installer --------------------------------------------------------------

// PluginInstaller publishes verified plugin packages and their systemd units.
//
// It never unpacks into the plugins root directly: install.Extract verifies the
// signature, the manifest and every content digest into a private staging
// directory. Without a privileged helper install.Staged.Commit publishes it
// with one rename; with a helper the root process copies the staged tree into
// place, because the controller cannot write the root-owned plugins root.
// The unit is rendered from the same verified manifest by internal/sandbox.
type PluginInstaller struct {
	// PluginsRoot is the immutable version root, <root>/<id>/<version>.
	PluginsRoot string
	// DataRoot is the host root for per-instance plugin data directories,
	// sandbox.DefaultPluginDataRoot. A plugin that declares state.backup_paths gets
	// <DataRoot>/<id>/default provisioned via StateDirectory=; others keep none.
	// Empty disables data-dir provisioning (tests without a data root).
	DataRoot string
	// StateDir 是宿主持久 KV 根，由 <DataDir>/plugin-state 装配。
	// 只有明确的 PurgeData 删除根下当前插件的状态。
	StateDir string
	// StagingRoot is the private staging directory. It must be writable by the
	// unprivileged controller and on the same filesystem as PluginsRoot.
	// serve-controller passes DefaultStagingRoot. Empty keeps the historical
	// <PluginsRoot>/.staging fallback, which only works when the controller can
	// write below the plugins root.
	StagingRoot string
	// TrustDir holds the trusted publisher public keys (*.pem).
	TrustDir string
	// TrustStore, when non-nil, overrides TrustDir so the installer consults a
	// dynamic composite trust root (official system keys + custom developer keys).
	TrustStore manifest.TrustStore
	// HostBinary is the installed host binary the unit's ExecStartPre calls.
	// The sandbox renderer currently pins sandbox.DefaultHostBinary; a
	// different value is rejected instead of being silently ignored.
	HostBinary string
	// Sandbox renders the unit and drop-in. The zero value uses the production
	// paths; cmd/qwq/serve.go passes sandbox.DefaultInstaller.
	Sandbox sandbox.Installer
	// Helper is the root helper that performs the privileged half of an
	// install. serve-controller runs as the unprivileged qwq user, so it cannot
	// write /etc/systemd/system itself; when Helper is set, InstallUnit and
	// RemoveUnit send it the spec instead of calling Sandbox. When Helper is
	// nil the in-process Installer is used, which is the root/tests path.
	Helper *sandbox.HelperClient
	// Systemctl is consulted before a version is removed. It is optional so a
	// test can exercise the file layout, but the production wiring always sets
	// it: the unit name is per plugin, so removing it while the plugin runs
	// would break the running instance.
	Systemctl sandbox.Systemctl
	// Tokens records the digest of every plugin token this installer issues,
	// so the host channel can verify it (ADR-0013). Nil skips the record,
	// which only tests without a database do.
	Tokens *PluginTokens
	// HostChannels is told when a plugin's last version is removed, so its
	// resident host channel closes. Nil skips it.
	HostChannels HostChannels
	// Preflight gates every package before it is staged: serve-controller
	// passes the doctor sandbox checks, so a host whose isolation
	// prerequisites fail refuses third-party plugins (ARCH §10.2). Nil skips it.
	Preflight func(ctx context.Context) error
	// Logger receives diagnostics; the zero value discards them.
	Logger *slog.Logger
}

// Stage verifies pkgPath and unpacks it into a private staging directory. It
// writes no unit, database row or other host state.
func (i *PluginInstaller) Stage(ctx context.Context, pkgPath string) (updater.Staged, error) {
	var zero updater.Staged
	if pkgPath == "" {
		return zero, problem.Validation(problem.Violation{
			Pointer: "/package_path", Code: "REQUIRED", Message: "A plugin package path is required.",
		})
	}
	if i.Preflight != nil {
		if err := i.Preflight(ctx); err != nil {
			return zero, err
		}
	}
	staging, err := i.stagingRoot()
	if err != nil {
		return zero, err
	}
	trust, err := i.trustStore()
	if err != nil {
		return zero, err
	}
	staged, err := install.Extract(ctx, pkgPath, trust, staging)
	if err != nil {
		return zero, err
	}
	out, err := newStagedPackage(staged)
	if err != nil {
		_ = staged.Discard()
		return zero, err
	}
	return out, nil
}

// newStagedPackage converts a verified install.Staged into the updater view.
func newStagedPackage(staged *install.Staged) (updater.Staged, error) {
	var zero updater.Staged
	m := staged.Manifest()
	if m == nil {
		return zero, errors.New("install: the staged package has no manifest")
	}
	pkg := staged.Package()
	var raw []byte
	if pkg != nil {
		raw = pkg.ManifestBytes
	}
	if len(raw) == 0 {
		return zero, errors.New("install: the staged package has no manifest bytes")
	}
	sum := sha256.Sum256(raw)
	return updater.Staged{
		PluginID:     m.ID,
		Version:      m.Version,
		Digest:       "sha256:" + hex.EncodeToString(sum[:]),
		Manifest:     m,
		ManifestJSON: json.RawMessage(raw),
		Handle:       staged,
		Discard:      staged.Discard,
	}, nil
}

// Inspect verifies and parses pkgPath for the pre-install inspection (GAPS
// gap 4). It reuses the install-time checks: the full Extract (signature,
// trust root, strict manifest, digests, ui/ policy), and — for a package
// those checks refuse — an unverified re-read of the same file so the refusal
// can be explained instead of returned as an error.
func (i *PluginInstaller) Inspect(ctx context.Context, pkgPath string) (updater.InspectionVerdict, error) {
	var out updater.InspectionVerdict
	if pkgPath == "" {
		return out, problem.Validation(problem.Violation{
			Pointer: "/package_path", Code: "REQUIRED", Message: "A plugin package path is required.",
		})
	}
	if i.Preflight != nil {
		if err := i.Preflight(ctx); err != nil {
			return out, err
		}
	}
	staging, err := i.stagingRoot()
	if err != nil {
		return out, err
	}
	trust, err := i.trustStore()
	if err != nil {
		return out, err
	}

	staged, xerr := install.Extract(ctx, pkgPath, trust, staging)
	if xerr == nil {
		s, cerr := newStagedPackage(staged)
		if cerr != nil {
			_ = staged.Discard()
			return out, cerr
		}
		out.Staged = &s
		out.Manifest = s.Manifest
		out.Valid, out.Trusted = true, true
		if pkg := staged.Package(); pkg != nil {
			out.UnpackedBytes = pkg.Size
			if pkg.Signature != nil {
				out.KeyID = pkg.Signature.KeyID
			}
		}
		return out, nil
	}

	// The refusal is explainable only for the signature/trust class and the
	// host policy class; anything else (a corrupt container, an unparseable
	// manifest) keeps the install-time error.
	var perr *install.PolicyError
	switch {
	case errors.As(xerr, &perr):
		out.Problems = append(out.Problems, problem.Violation{
			Pointer: "/" + perr.Path, Code: perr.Code, Message: perr.Message,
		})
	case signatureRefusal(xerr):
		// The signature verdict below explains it.
	default:
		return out, xerr
	}

	// Re-read without trust: the strict manifest parse and every content
	// digest are still checked; only the signature is not required. This is
	// what lets the inspection show the manifest of a refused package.
	f, oerr := os.Open(pkgPath)
	if oerr != nil {
		return out, xerr
	}
	defer f.Close() //nolint:errcheck // read only
	pkg, rerr := pkgfile.ReadUnverified(f, pkgfile.ReadOptions{LenientSignature: true})
	if rerr != nil {
		return out, xerr
	}
	out.Manifest = pkg.Manifest
	out.UnpackedBytes = pkg.Size
	if sig := pkg.Signature; sig != nil {
		out.KeyID = sig.KeyID
		_, verr := manifest.VerifyAndParse(pkg.ManifestBytes, sig.Encode(), trust)
		valid, extra := signatureVerdict(verr)
		out.Valid = valid
		out.Problems = append(out.Problems, extra...)
		if _, kerr := trust.LookupKey(sig.KeyID); kerr == nil {
			out.Trusted = true
		}
	}
	// A malformed envelope is dropped by the lenient read, so its violation
	// only survives in the original error.
	var me *manifest.Error
	if errors.As(xerr, &me) {
		for _, v := range me.Violations {
			if v.Code == manifest.CodeSignatureMalformed {
				out.Problems = append(out.Problems, problem.Violation{
					Pointer: v.Pointer, Code: v.Code, Message: v.Message,
				})
			}
		}
	}
	return out, nil
}

// signatureRefusal reports whether err is the package verification refusing
// the signature or the key rather than the container: those refusals are
// reported by Inspect instead of failing.
func signatureRefusal(err error) bool {
	var me *manifest.Error
	if errors.As(err, &me) {
		for _, v := range me.Violations {
			switch v.Code {
			case manifest.CodeSignatureMalformed, manifest.CodeKeyUnknown, manifest.CodeSignatureInvalid,
				manifest.CodeKeyIDMismatch, manifest.CodePublisherMismatch, manifest.CodePluginNamespaceMismatch:
				return true
			}
		}
		return false
	}
	var pe *pkgfile.Error
	if errors.As(err, &pe) {
		return pe.Has(pkgfile.CodeMissingSignature)
	}
	return false
}

// signatureVerdict interprets one VerifyAndParse failure (nil means the
// verification accepted the package). VerifyAndParse checks the Ed25519
// signature before the publisher binding, so a binding violation still means
// the signature itself verifies; it is reported as a field violation rather
// than as an invalid signature.
func signatureVerdict(err error) (bool, []problem.Violation) {
	if err == nil {
		return true, nil
	}
	var me *manifest.Error
	if !errors.As(err, &me) || len(me.Violations) == 0 {
		return false, nil
	}
	valid := true
	var vs []problem.Violation
	for _, v := range me.Violations {
		switch v.Code {
		case manifest.CodeKeyIDMismatch, manifest.CodePublisherMismatch, manifest.CodePluginNamespaceMismatch:
			vs = append(vs, problem.Violation{Pointer: v.Pointer, Code: v.Code, Message: v.Message})
		default:
			// Signature, key or envelope class: the signature is not accepted.
			valid = false
		}
	}
	return valid, vs
}

// InstallUnit publishes the staged package at its immutable version directory
// and installs the rendered unit and drop-in. It is idempotent: an existing
// version directory is treated as already published (version directories are
// never replaced), and the unit is rewritten from the verified manifest. A
// running old version is not disturbed, because rewriting a unit file does not
// affect a running process; the saga stops the old unit before the new one
// starts.
func (i *PluginInstaller) InstallUnit(ctx context.Context, staged updater.Staged) error {
	if i.HostBinary != "" && i.HostBinary != sandbox.DefaultHostBinary {
		return problem.New(problem.Internal,
			"The configured host binary %q cannot be used: the sandbox unit template pins %s.",
			i.HostBinary, sandbox.DefaultHostBinary)
	}
	src, err := stagedPackage(staged)
	if err != nil {
		return err
	}
	m := src.Manifest()
	if m == nil {
		return errors.New("controller: the staged package has no manifest")
	}
	versionDir, err := i.versionDir(m.ID, m.Version)
	if err != nil {
		return err
	}
	if err := i.publishVersion(ctx, staged, src, m, versionDir); err != nil {
		return err
	}

	spec, err := unitSpecFor(m, versionDir, i.DataRoot)
	if err != nil {
		return err
	}
	if err := i.installUnitWithCredential(ctx, spec); err != nil {
		return wrapInstallerFailure(
			fmt.Sprintf("The systemd unit of plugin %s version %s could not be installed.", m.ID, m.Version), err)
	}
	return nil
}

// ReinstallUnit re-renders the per-plugin systemd unit for an already published
// version. It is idempotent and used by the updater before a rollback (or a
// failed-update restore) starts the retained version, because the unit name is
// per plugin rather than per version.
func (i *PluginInstaller) ReinstallUnit(ctx context.Context, pluginID, version string, m *manifest.Manifest) error {
	if m == nil {
		return problem.New(problem.Internal, "The retained version has no manifest.")
	}
	if m.ID != pluginID || m.Version != version {
		return problem.New(problem.Internal,
			"The retained manifest of plugin %s version %s declares %s %s.", pluginID, version, m.ID, m.Version)
	}
	versionDir, err := i.versionDir(pluginID, version)
	if err != nil {
		return err
	}
	spec, err := unitSpecFor(m, versionDir, i.DataRoot)
	if err != nil {
		return err
	}
	if err := i.installUnitWithCredential(ctx, spec); err != nil {
		return wrapInstallerFailure(
			fmt.Sprintf("The systemd unit of plugin %s version %s could not be reinstalled.", m.ID, m.Version), err)
	}
	return nil
}

// ======================== 安装、重装与凭据生命周期 ========================

// installUnitWithCredential 保持先受控写盘、再记当前摘要；任一步失败都不能
// 推进 saga。新 saga 已固定上一槽，发行重试只替换当前槽，不复制更多明文。
func (i *PluginInstaller) installUnitWithCredential(ctx context.Context, spec sandbox.UnitSpec) error {
	token, err := newPluginToken()
	if err != nil {
		return &problem.Error{Code: problem.Internal, Detail: "A plugin credential could not be generated.", Cause: err}
	}
	defer clear(token)
	if _, err := i.installUnit(ctx, spec, token); err != nil {
		return err
	}
	if i.Tokens != nil {
		if err := i.Tokens.Put(ctx, spec.ID, token); err != nil {
			return &problem.Error{Code: problem.Internal, Detail: "The plugin credential could not be recorded.", Cause: err}
		}
	}
	return nil
}

// CredentialRotationEnabled 只为有真实宿主数据库的 installer 启用双槽流程。
func (i *PluginInstaller) CredentialRotationEnabled() bool {
	return i != nil && i.Tokens != nil && i.Tokens.DB != nil
}

// BeginCredentialRotationTx 与新 saga 同事务固定原槽；恢复不重复调用。
func (i *PluginInstaller) BeginCredentialRotationTx(ctx context.Context, tx *storage.Tx, pluginID string) error {
	if !i.CredentialRotationEnabled() {
		return nil
	}
	return i.Tokens.BeginRotationTx(ctx, tx, pluginID)
}

// FinishCredentialRotationTx 由实际进程已对齐的健康终态事务调用。
func (i *PluginInstaller) FinishCredentialRotationTx(ctx context.Context, tx *storage.Tx, pluginID string) error {
	if !i.CredentialRotationEnabled() {
		return nil
	}
	return i.Tokens.FinishRotationTx(ctx, tx, pluginID)
}

// unitSpecFor renders the sandbox spec from a verified manifest and the
// immutable version directory. InstallUnit and ReinstallUnit share it so both
// paths produce byte-identical units. dataRoot is the installer's DataRoot; the
// data directory is derived only for a manifest that declares backup paths.
func unitSpecFor(m *manifest.Manifest, versionDir, dataRoot string) (sandbox.UnitSpec, error) {
	entryDigest, ok := m.Files[m.Entrypoint]
	if !ok {
		return sandbox.UnitSpec{}, problem.New(problem.Internal,
			"The manifest of plugin %s does not record the digest of its entrypoint %s.", m.ID, m.Entrypoint)
	}
	// Derive host-controlled sandbox relaxations strictly from the verified
	// manifest capabilities. NetworkProxyDirect stays pinned to the exact
	// (network.proxy, direct) capability for backwards compatibility, while
	// Relaxations maps network.egress / network.listen / network.proxy:direct
	// to PrivateNetwork=no + AF_INET/AF_INET6 and low-port capabilities to
	// CAP_NET_BIND_SERVICE.
	networkProxyDirect := false
	caps := make([]sandbox.CapabilityRef, len(m.Capabilities))
	for idx, c := range m.Capabilities {
		caps[idx] = sandbox.CapabilityRef{Name: c.Name, Scope: c.Scope}
		if c.Name == "network.proxy" && c.Scope == "direct" {
			networkProxyDirect = true
		}
	}
	relaxations := sandbox.DeriveSandboxRelaxations(caps)
	if networkProxyDirect && m.ID == "core.xray" {
		relaxations.BindPrivilegedPorts = true
	}
	dataDir, err := derivePluginDataDir(dataRoot, m.ID, m.State.BackupPaths)
	if err != nil {
		return sandbox.UnitSpec{}, err
	}
	return sandbox.UnitSpec{
		ID:         m.ID,
		VersionDir: versionDir,
		Entrypoint: m.Entrypoint,
		Digest:     entryDigest,
		Executable: filepath.Join(versionDir, m.Entrypoint),
		Limits: &sandbox.Limits{
			MemoryMaxMB:     m.Resources.MemoryMaxMB,
			CPUQuotaPercent: m.Resources.CPUQuotaPercent,
			PIDsMax:         m.Resources.PIDsMax,
			FDsMax:          m.Resources.FDsMax,
		},
		NetworkProxyDirect: networkProxyDirect,
		Relaxations:        relaxations,
		DataDir:            dataDir,
		Startup:            m.Lifecycle.Startup,
		Background:         m.Lifecycle.Background,
	}, nil
}

// derivePluginDataDir computes the stable per-instance data directory the host
// provisions for a plugin. It is the single derivation shared by the unit
// renderer (unitSpecFor) and the runtime (Start/Attach), so the StateDirectory=
// in the unit and the data_dir passed at Initialize are always the same path.
//
// A plugin signals its need with a non-empty state.backup_paths; without it (or
// without a configured data root) the result is empty and the plugin keeps the
// original DataDir="" behaviour. The first version only supports the default
// instance; the path carries no plugin version or process generation.
func derivePluginDataDir(dataRoot, pluginID string, backupPaths []string) (string, error) {
	if dataRoot == "" || len(backupPaths) == 0 {
		return "", nil
	}
	if err := sandbox.ValidateID(pluginID); err != nil {
		return "", problem.New(problem.ValidationFailed, "%q is not a valid plugin id.", pluginID)
	}
	dir := filepath.Join(dataRoot, pluginID, DefaultInstanceID)
	if filepath.Clean(dir) != dir || !filepath.IsAbs(dir) {
		return "", problem.New(problem.Internal, "The plugin data root %q is not a clean absolute path.", dataRoot)
	}
	return dir, nil
}

// fillDataDir provisions the spec's data directory from the runtime's DataRoot
// using the same derivation as the unit renderer. Start and Attach both call it
// so a fresh start and a host-restart recovery pass the same directory at
// Initialize. A spec that already carries a DataDir is left untouched.
func (rt *UpdaterRuntime) fillDataDir(spec *updater.InstanceSpec) error {
	if spec.DataDir != "" || spec.Manifest == nil {
		return nil
	}
	dir, err := derivePluginDataDir(rt.DataRoot, spec.PluginID, spec.Manifest.State.BackupPaths)
	if err != nil {
		return err
	}
	spec.DataDir = dir
	return nil
}

// publishVersion makes versionDir available. When a helper is configured, the
// helper copies the verified staging tree because the controller runs as qwq
// and cannot write the root-owned plugins tree; without a helper the
// in-process installer commits with one rename, as before.
//
// An existing version directory is immutable: it is accepted only when the
// helper can compare it with the staged tree and the content digest matches. A
// retry after a successful publish has no staging copy left, so the immutable
// directory is trusted then (the same rule the in-process path always used).
func (i *PluginInstaller) publishVersion(ctx context.Context, staged updater.Staged, src *install.Staged, m *manifest.Manifest, versionDir string) error {
	if i.Helper == nil {
		switch info, statErr := os.Stat(versionDir); {
		case statErr == nil:
			if !info.IsDir() {
				return fmt.Errorf("controller: plugin version path %s is not a directory", versionDir)
			}
			// Already published. Release the staging copy, if this Staged still
			// owns one; a committed Staged ignores Discard.
			i.logger().Debug("using the already published plugin version",
				"plugin_id", m.ID, "version", m.Version, "version_dir", versionDir)
			_ = staged.DiscardStaged()
		case errors.Is(statErr, fs.ErrNotExist):
			if cerr := src.Commit(versionDir); cerr != nil && !errors.Is(cerr, install.ErrTargetExists) {
				return &problem.Error{
					Code:   problem.Internal,
					Detail: fmt.Sprintf("The package of plugin %s version %s could not be published.", m.ID, m.Version),
					Cause:  cerr,
				}
			}
			_ = staged.DiscardStaged()
		default:
			return &problem.Error{
				Code:   problem.Internal,
				Detail: fmt.Sprintf("The version directory of plugin %s could not be inspected.", m.ID),
				Cause:  statErr,
			}
		}
		return nil
	}

	req := sandbox.HelperPublish{
		StagedDir:  src.Dir(),
		VersionDir: versionDir,
		PluginID:   m.ID,
		Version:    m.Version,
	}
	if info, statErr := os.Stat(versionDir); statErr == nil {
		if !info.IsDir() {
			return fmt.Errorf("controller: plugin version path %s is not a directory", versionDir)
		}
		// Let the helper verify the immutable directory when the staging copy
		// still exists; a publish retry has already discarded it.
		if _, derr := os.Stat(src.Dir()); derr == nil {
			if _, perr := i.Helper.Publish(ctx, req); perr != nil {
				return wrapInstallerFailure(
					fmt.Sprintf("The installed files of plugin %s version %s do not match the package.", m.ID, m.Version), perr)
			}
		}
		i.logger().Debug("using the already published plugin version",
			"plugin_id", m.ID, "version", m.Version, "version_dir", versionDir)
		_ = staged.DiscardStaged()
		return nil
	} else if !errors.Is(statErr, fs.ErrNotExist) {
		return &problem.Error{
			Code:   problem.Internal,
			Detail: fmt.Sprintf("The version directory of plugin %s could not be inspected.", m.ID),
			Cause:  statErr,
		}
	}
	res, err := i.Helper.Publish(ctx, req)
	if err != nil {
		return wrapInstallerFailure(
			fmt.Sprintf("The package of plugin %s version %s could not be published.", m.ID, m.Version), err)
	}
	if derr := staged.DiscardStaged(); derr != nil {
		i.logger().WarnContext(ctx, "the plugin staging directory could not be removed",
			"plugin_id", m.ID, "version", m.Version, "error", derr)
	}
	i.logger().DebugContext(ctx, "published plugin version by the privileged helper",
		"plugin_id", m.ID, "version", m.Version,
		"files", res.Files, "dirs", res.Dirs, "existing", res.Existing)
	return nil
}

// newPluginToken returns a 32-byte random credential in base64url form. It is
// printable ASCII without spaces, which is what sandbox.checkToken requires,
// and it never appears in a log line: only the credential path is reported.
func newPluginToken() ([]byte, error) {
	raw := make([]byte, pluginTokenBytes)
	if _, err := rand.Read(raw); err != nil {
		return nil, err
	}
	return []byte(base64.RawURLEncoding.EncodeToString(raw)), nil
}

// installUnit hands the rendered spec and its credential to the root helper
// when one is configured. The helper writes the unit, the drop-in, the
// tmpfiles snippet and the credential and reloads systemd; without it the
// in-process Installer does the same work, which only succeeds when the
// controller runs as root.
func (i *PluginInstaller) installUnit(ctx context.Context, spec sandbox.UnitSpec, credential []byte) (sandbox.InstallResult, error) {
	if i.Helper != nil {
		res, err := i.Helper.Install(ctx, spec, credential)
		if err != nil {
			return res, err
		}
		if len(res.Warnings) > 0 {
			i.logger().WarnContext(ctx, "plugin unit installed with warnings",
				"plugin_id", spec.ID, "warnings", res.Warnings)
		}
		i.logger().DebugContext(ctx, "plugin unit installed by the privileged helper",
			"plugin_id", spec.ID, "unit_files", res.UnitFiles)
		return res, nil
	}
	return i.Sandbox.Install(ctx, spec, credential)
}

// Logs reads one page of the plugin unit's journal through the privileged
// helper (GAPS gap 7). Without a helper the host cannot read another unit's
// journal, so it reports UNAVAILABLE instead of shelling out as qwq.
func (i *PluginInstaller) Logs(ctx context.Context, pluginID, cursor, stream string, limit int) (sandbox.LogResult, error) {
	if i.Helper == nil {
		return sandbox.LogResult{}, problem.New(problem.Unavailable,
			"The privileged helper is not configured; plugin logs are unavailable.")
	}
	return i.Helper.Logs(ctx, sandbox.HelperLogs{ID: pluginID, Cursor: cursor, Stream: stream, Limit: limit})
}

// RemoveUnit removes the unit artifacts and the version directory of a version
// that is being discarded. The updater only calls it when no other version of
// the plugin is running or active, and this method re-checks that the unit has
// no main process before it removes anything.
func (i *PluginInstaller) RemoveUnit(ctx context.Context, pluginID, version string) error {
	versionDir, err := i.versionDir(pluginID, version)
	if err != nil {
		return err
	}
	if err := i.requireStoppedPlugin(ctx, pluginID); err != nil {
		return err
	}
	// Remove the unit first so nothing can start the version between the two
	// deletions. The unit name is per plugin, so it is only removed when this
	// was the last installed version; a retained version still needs the unit
	// for a later start or rollback.
	others, err := otherVersions(filepath.Join(filepath.Clean(i.PluginsRoot), pluginID), version)
	if err != nil {
		return &problem.Error{
			Code:   problem.Internal,
			Detail: fmt.Sprintf("The installed versions of plugin %s could not be listed.", pluginID),
			Cause:  err,
		}
	}
	if i.Helper != nil {
		// The helper owns the privileged half, including the version tree:
		// /var/lib/qwq-plugins is root owned, so the qwq process cannot delete
		// it. KeepUnit keeps the unit files when another version still needs
		// them for a later start or rollback.
		remove := sandbox.HelperRemove{
			ID:       pluginID,
			Version:  version,
			Paths:    []string{versionDir},
			KeepUnit: len(others) > 0,
		}
		res, err := i.removeWithHelper(ctx, remove)
		if err != nil {
			return wrapInstallerFailure(
				fmt.Sprintf("The files of plugin %s version %s could not be removed.", pluginID, version), err)
		}
		if len(res.Warnings) > 0 {
			i.logger().WarnContext(ctx, "plugin unit removed with warnings",
				"plugin_id", pluginID, "version", version, "warnings", res.Warnings)
		}
		i.releaseHostChannel(pluginID, others)
		return nil
	}
	if len(others) == 0 {
		if _, err := i.Sandbox.Remove(ctx, pluginID); err != nil {
			return &problem.Error{
				Code:   problem.Internal,
				Detail: fmt.Sprintf("The unit artifacts of plugin %s could not be removed.", pluginID),
				Cause:  err,
			}
		}
	}
	if err := removeVersionTree(versionDir); err != nil {
		return &problem.Error{
			Code:   problem.Internal,
			Detail: fmt.Sprintf("The files of plugin %s version %s could not be removed.", pluginID, version),
			Cause:  err,
		}
	}
	i.releaseHostChannel(pluginID, others)
	return nil
}

// releaseHostChannel closes the plugin's host channel once no version is left.
func (i *PluginInstaller) releaseHostChannel(pluginID string, others []string) {
	if len(others) == 0 && i.HostChannels != nil {
		i.HostChannels.ReleaseHostChannel(pluginID)
	}
}

// stagingRoot returns the staging directory. It keeps the historical
// <PluginsRoot>/.staging fallback for in-process installs; serve-controller
// passes DefaultStagingRoot, which the unprivileged controller can write.
func (i *PluginInstaller) stagingRoot() (string, error) {
	root := i.StagingRoot
	if root == "" && i.PluginsRoot != "" {
		root = filepath.Join(i.PluginsRoot, DefaultStagingDirName)
	}
	if root == "" {
		return "", problem.New(problem.Unavailable, "The plugin staging directory is not configured.")
	}
	if !filepath.IsAbs(root) {
		return "", problem.New(problem.Unavailable, "The plugin staging directory is not an absolute path.")
	}
	return filepath.Clean(root), nil
}

// versionDir returns the only directory a version may be published at.
func (i *PluginInstaller) versionDir(pluginID, version string) (string, error) {
	if err := sandbox.ValidateID(pluginID); err != nil {
		return "", problem.New(problem.ValidationFailed, "%q is not a valid plugin id.", pluginID)
	}
	if !versionNamePattern.MatchString(version) {
		return "", problem.New(problem.ValidationFailed, "%q is not a valid plugin version.", version)
	}
	if i.PluginsRoot == "" || !filepath.IsAbs(i.PluginsRoot) {
		return "", problem.New(problem.Unavailable, "The plugin package directory is not configured.")
	}
	return install.VersionDir(filepath.Clean(i.PluginsRoot), pluginID, version), nil
}

// loadTrustPolicy applies the optional sidecar of a trusted key (ADR-0015). A
// missing file leaves the key unrestricted; a malformed one fails closed.
func loadTrustPolicy(path string, key *manifest.TrustedKey) error {
	raw, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var policy struct {
		Publisher string   `json:"publisher"`
		PluginIDs []string `json:"plugin_ids"`
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&policy); err != nil {
		return err
	}
	key.Publisher, key.PluginIDs = policy.Publisher, policy.PluginIDs
	return nil
}

// trustStore loads the publisher public keys from TrustDir. A host without a
// trusted key refuses to install anything instead of accepting an unknown
// signature; the error is UNAVAILABLE because the operator has to provision the
// trust root, not fix the request.
func (i *PluginInstaller) trustStore() (manifest.TrustStore, error) {
	if i.TrustStore != nil {
		return i.TrustStore, nil
	}
	dir := i.TrustDir
	if dir == "" {
		return nil, problem.New(problem.Unavailable,
			"No plugin trust directory is configured; plugin installation is disabled.")
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, &problem.Error{
			Code:   problem.Unavailable,
			Detail: fmt.Sprintf("The plugin trust directory %s could not be read.", dir),
			Cause:  err,
		}
	}
	keys := make([]manifest.TrustedKey, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".pem") {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		raw, rerr := os.ReadFile(path)
		if rerr != nil {
			return nil, &problem.Error{
				Code:   problem.Unavailable,
				Detail: fmt.Sprintf("The trusted publisher key %s could not be read.", entry.Name()),
				Cause:  rerr,
			}
		}
		pub, perr := pkgfile.ParsePublicKeyPEM(raw)
		if perr != nil {
			return nil, &problem.Error{
				Code:   problem.Unavailable,
				Detail: fmt.Sprintf("The trusted publisher key %s is not a valid public key.", entry.Name()),
				Cause:  perr,
			}
		}
		key := manifest.TrustedKey{PublicKey: pub}
		if err := loadTrustPolicy(strings.TrimSuffix(path, ".pem")+".policy.json", &key); err != nil {
			return nil, &problem.Error{
				Code:   problem.Unavailable,
				Detail: fmt.Sprintf("The policy of trusted publisher key %s is not valid.", entry.Name()),
				Cause:  err,
			}
		}
		keys = append(keys, key)
	}
	if len(keys) == 0 {
		return nil, problem.New(problem.Unavailable,
			"No trusted publisher key is installed in %s; plugin installation is disabled.", dir)
	}
	store, err := manifest.NewStaticTrustStore(keys...)
	if err != nil {
		return nil, &problem.Error{
			Code:   problem.Unavailable,
			Detail: "The plugin trust root is inconsistent.",
			Cause:  err,
		}
	}
	return store, nil
}

// logger returns the configured logger or a discard logger.
func (i *PluginInstaller) logger() *slog.Logger {
	if i.Logger == nil {
		return slog.New(slog.DiscardHandler)
	}
	return i.Logger
}

// wrapInstallerFailure wraps an install/remove failure in a host error while
// keeping the problem code a helper refusal already carries (UNAVAILABLE when
// the helper is not running, PRECONDITION_FAILED when the unit is still up).
// Plain errors from the in-process installer stay INTERNAL, as before.
func wrapInstallerFailure(detail string, err error) error {
	var pe *problem.Error
	if errors.As(err, &pe) {
		return &problem.Error{Code: pe.Code, Detail: detail, Cause: err}
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return ctxError(err, "writing plugin files")
	}
	return &problem.Error{Code: problem.Internal, Detail: detail, Cause: err}
}

// stagedPackage returns the install.Staged a Stage call produced.
func stagedPackage(s updater.Staged) (*install.Staged, error) {
	src, ok := s.Handle.(*install.Staged)
	if !ok || src == nil {
		return nil, problem.New(problem.Internal,
			"The staged package was not produced by the plugin installer.")
	}
	return src, nil
}

// otherVersions lists the installed versions of a plugin other than version.
// "current" is a layout pointer rather than a version and is ignored.
func otherVersions(pluginRoot, version string) ([]string, error) {
	entries, err := os.ReadDir(pluginRoot)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var others []string
	for _, entry := range entries {
		if !entry.IsDir() || entry.Name() == version || entry.Name() == "current" {
			continue
		}
		others = append(others, entry.Name())
	}
	return others, nil
}

// removeVersionTree deletes a published version directory and the plugin
// directory when it becomes empty. The published tree is read-only (0555/0444),
// so the directories are made writable first.
func removeVersionTree(dir string) error {
	_ = filepath.WalkDir(dir, func(path string, d fs.DirEntry, werr error) error {
		if werr != nil {
			return nil //nolint:nilerr // best effort; RemoveAll reports the failure
		}
		if d.IsDir() {
			_ = os.Chmod(path, 0o700)
		} else {
			_ = os.Chmod(path, 0o600)
		}
		return nil
	})
	if err := os.RemoveAll(dir); err != nil {
		return err
	}
	// A plugin with another installed version keeps its directory.
	parent := filepath.Dir(dir)
	if entries, err := os.ReadDir(parent); err == nil && len(entries) == 0 {
		_ = os.Remove(parent)
	}
	return nil
}

// UpdatePlugin drives one plugin update through the restart-only runtime.
//
// The systemd unit name is per plugin, so two versions cannot own a unit at the
// same time. This method therefore forces updater.StrategyRestart regardless of
// what the caller asked for; the memory preflight may still refuse the update
// when the node cannot hold the candidate after the old process is stopped.
// The P3 HTTP endpoint must call this method rather than updater.Update.
func (c *Controller) UpdatePlugin(ctx context.Context, req updater.UpdateRequest) (*updater.UpdateResult, error) {
	u := c.Updater()
	if u == nil {
		return nil, problem.New(problem.Unavailable, "The plugin updater is not enabled on this host.")
	}
	req.Strategy = updater.StrategyRestart
	// Detached on purpose (defense in depth with the API and the updater): a
	// caller that goes away must not cut the saga in half.
	return u.Update(context.WithoutCancel(ctx), req)
}

// --- runtime ----------------------------------------------------------------

// HostChannels owns the resident per-plugin host channels (*PluginRuntime).
type HostChannels interface {
	EnsureHostChannel(pluginID string) error
	ReleaseHostChannel(pluginID string)
}

// ensureHostChannel serves the plugin's host channel when one is wired.
func ensureHostChannel(hosts HostChannels, pluginID string) error {
	if hosts == nil {
		return nil
	}
	if err := hosts.EnsureHostChannel(pluginID); err != nil {
		return &problem.Error{
			Code:   problem.PluginUnavailable,
			Detail: fmt.Sprintf("The host channel of plugin %s could not be served.", pluginID),
			Cause:  err,
		}
	}
	return nil
}

// UpdaterRuntime is the updater's view of a running plugin. It starts and stops
// systemd units through internal/sandbox and speaks the plugin's ABI over the
// go-plugin gRPC socket that systemd exposes.
//
// It never calls plugin.Serve, AutoMTLS, SecureConfig or Client.Kill: the
// process belongs to systemd, and go-plugin is used only as a gRPC transport to
// an already running process.
type UpdaterRuntime struct {
	// Systemctl starts and stops the units; required.
	Systemctl sandbox.Systemctl
	// PluginsRoot is the immutable version root; it is only used to check that
	// the version directory exists before the unit is started.
	PluginsRoot string
	// DataRoot is the host root for per-instance plugin data directories
	// (sandbox.DefaultPluginDataRoot). Start/Attach derive <DataRoot>/<id>/default for
	// a plugin that declares state.backup_paths and pass it at Initialize. It
	// must match the installer's DataRoot so the unit's StateDirectory= and the
	// directory the plugin receives are the same path. Empty disables it.
	DataRoot string
	// RunDir holds the plugin sockets (default supervisor.DefaultRunDir).
	RunDir string
	// Clock is the time source (default clock.System).
	Clock clock.Clock
	// Logger receives diagnostics (default discard).
	Logger *slog.Logger
	// NodeID labels the lifecycle requests (default "local").
	NodeID string
	// ConnectTimeout bounds the go-plugin handshake (default 10s).
	ConnectTimeout time.Duration
	// RPCTimeout bounds each lifecycle RPC that has no deadline (default 30s).
	RPCTimeout time.Duration
	// HostChannels serves the plugin's host channel before its unit starts:
	// pluginsdk connects to host.sock before it serves gRPC. Nil skips it
	// (tests that need no host channel).
	HostChannels HostChannels

	routes atomic.Pointer[updater.RouteTable]

	mu        sync.Mutex
	instances map[string]map[string]*pluginHandle
}

// pluginHandle is the opaque updater.Handle of one attached instance.
type pluginHandle struct {
	rt         *UpdaterRuntime
	pluginID   string
	version    string
	unit       string
	mainPID    int
	startTime  time.Time
	generation string
	owner      string
	since      time.Time

	mu             sync.Mutex
	client         platformv1.PluginServiceClient
	grpc           *grpc.ClientConn
	stopped        bool
	released       bool
	configRevision int64
	// instanceHandle is the opaque identity sent at Initialize; empty until
	// the instance is bootstrapped.
	instanceHandle string
	// stateSchemaVersion is what Initialize reported; it is recorded for
	// diagnostics and a later restart could pass it back.
	stateSchemaVersion string
}

// Start starts the plugin unit, attaches to its socket and returns the instance
// handle. The candidate serves requests but runs no background work until
// Activate. Start never reuses a live instance: an update that reaches this
// point has already stopped the old version, so a live instance means the
// caller skipped that step and the restart order is not what the updater
// believes.
func (rt *UpdaterRuntime) Start(ctx context.Context, spec updater.InstanceSpec) (updater.Handle, error) {
	if err := validateInstanceSpec(spec); err != nil {
		return nil, err
	}
	if err := rt.fillDataDir(&spec); err != nil {
		return nil, err
	}
	systemctl, err := rt.requireSystemctl()
	if err != nil {
		return nil, err
	}
	if err := rt.requireVersionDir(spec); err != nil {
		return nil, err
	}
	if current := rt.liveFor(spec.PluginID); current != nil {
		return nil, problem.New(problem.PreconditionFailed,
			"Plugin %s already has a live instance of version %s; stop it before starting version %s.",
			spec.PluginID, current.version, spec.Version)
	}
	unit := supervisor.UnitName(spec.PluginID)
	state, err := systemctl.Show(ctx, unit)
	if err != nil {
		return nil, unitFailure(spec.PluginID, "inspected", err)
	}
	if state.MainPID > 0 {
		return nil, problem.New(problem.PreconditionFailed,
			"Plugin %s already has a running instance (main PID %d); stop it before starting version %s.",
			spec.PluginID, state.MainPID, spec.Version)
	}
	if err := ensureHostChannelForSpec(rt.HostChannels, spec); err != nil {
		return nil, err
	}
	if err := systemctl.Start(ctx, unit); err != nil {
		return nil, unitFailure(spec.PluginID, "started", err)
	}
	state, err = systemctl.Show(ctx, unit)
	if err != nil {
		rt.stopFailedStart(ctx, systemctl, unit)
		return nil, unitFailure(spec.PluginID, "inspected", err)
	}
	if state.MainPID == 0 {
		rt.stopFailedStart(ctx, systemctl, unit)
		return nil, problem.New(problem.PluginUnavailable,
			"The unit of plugin %s has no main process after start.", spec.PluginID)
	}
	handle, err := rt.attach(ctx, spec, state)
	if err != nil {
		rt.stopFailedStart(ctx, systemctl, unit)
		return nil, err
	}
	if err := rt.verifyRunningVersion(ctx, spec, handle, state); err != nil {
		// The unit is version-pinned, and systemd keeps the definition it
		// loaded until daemon-reload. A stale ExecStart must not be recorded as
		// the new version.
		handle.closeConnection()
		rt.stopFailedStart(ctx, systemctl, unit)
		return nil, err
	}
	if err := rt.bootstrapInstance(ctx, spec, handle, true); err != nil {
		// A process that cannot be initialized or started is not a candidate;
		// stop it so a rollback can start the old version (Start refuses while
		// any instance of the plugin is live).
		handle.closeConnection()
		rt.stopFailedStart(ctx, systemctl, unit)
		return nil, err
	}
	current, err := rt.register(handle, true)
	if err != nil {
		// Another live instance owns the unit: do not stop it, only drop the
		// connection this attempt opened.
		handle.closeConnection()
		return nil, err
	}
	if current != handle {
		// A concurrent Attach won the slot; use its connection and drop ours.
		handle.closeConnection()
		return current, nil
	}
	rt.logger().InfoContext(ctx, "plugin instance started",
		"plugin_id", spec.PluginID, "version", spec.Version, "unit", handle.unit,
		"main_pid", handle.mainPID, "start_time", handle.startTime, "since", handle.since,
		"generation", handle.generation, "owner", handle.owner, "node_id", rt.nodeID())
	return handle, nil
}

// Attach connects to an already running instance without starting or stopping
// anything. It is the recovery path after a host restart.
func (rt *UpdaterRuntime) Attach(ctx context.Context, spec updater.InstanceSpec) (updater.Handle, error) {
	if err := validateInstanceSpec(spec); err != nil {
		return nil, err
	}
	if err := rt.fillDataDir(&spec); err != nil {
		return nil, err
	}
	systemctl, err := rt.requireSystemctl()
	if err != nil {
		return nil, err
	}
	unit := supervisor.UnitName(spec.PluginID)
	state, err := systemctl.Show(ctx, unit)
	if err != nil {
		return nil, unitFailure(spec.PluginID, "inspected", err)
	}
	if existing := rt.lookup(spec.PluginID, spec.Version); existing != nil {
		// gRPC reconnects transparently to a process systemd restarted; that
		// process has no instance, so a handle of another generation is stale.
		if state.MainPID > 0 && instanceGeneration(unit, state.MainPID, state.StartTime) == existing.generation {
			return existing, nil
		}
		existing.closeConnection()
		rt.unregister(existing)
	}
	if state.MainPID == 0 {
		return nil, problem.New(problem.PluginUnavailable,
			"Plugin %s version %s has no running instance to attach to.", spec.PluginID, spec.Version)
	}
	// A process that outlived the host reconnects to host.sock on its own.
	if err := ensureHostChannel(rt.HostChannels, spec.PluginID); err != nil {
		return nil, err
	}
	handle, err := rt.attach(ctx, spec, state)
	if err != nil {
		return nil, err
	}
	// The unit is per plugin, so the process may run another version (a
	// rollback just restored it). That process is not ours to bootstrap or
	// stop: drop the connection only (PLG-05).
	if err := rt.verifyRunningVersion(ctx, spec, handle, state); err != nil {
		handle.closeConnection()
		return nil, err
	}
	// A recovered process may still be initialized from before the host
	// restart; bootstrapInstance checks the lifecycle state and only repeats
	// the calls the instance still needs. A process that cannot be
	// bootstrapped is stopped, otherwise it would block a later Start.
	if err := configureHostChannelForSpec(rt.HostChannels, spec); err != nil {
		handle.closeConnection()
		return nil, err
	}
	if err := rt.bootstrapInstance(ctx, spec, handle, false); err != nil {
		handle.closeConnection()
		rt.stopFailedStart(ctx, systemctl, unit)
		return nil, err
	}
	current, err := rt.register(handle, false)
	if err != nil {
		handle.closeConnection()
		return nil, err
	}
	if current != handle {
		handle.closeConnection()
		return current, nil
	}
	rt.logger().InfoContext(ctx, "plugin instance attached",
		"plugin_id", spec.PluginID, "version", spec.Version, "unit", handle.unit,
		"main_pid", handle.mainPID, "start_time", handle.startTime, "since", handle.since,
		"generation", handle.generation, "owner", handle.owner, "node_id", rt.nodeID())
	return handle, nil
}

// Ready waits for the plugin's self-check. A transport failure or a status
// other than SERVING is PLUGIN_UNAVAILABLE: the candidate must not receive
// traffic or background work.
func (rt *UpdaterRuntime) Ready(ctx context.Context, h updater.Handle) error {
	handle, err := rt.instance(h)
	if err != nil {
		return err
	}
	resp, err := handle.checkHealth(ctx)
	if err != nil {
		return unavailable(handle, "become ready", err)
	}
	if resp.GetStatus() != platformv1.CheckHealthResponse_STATUS_SERVING {
		return unavailable(handle, "become ready",
			fmt.Errorf("health status is %s: %s", resp.GetStatus(), resp.GetMessage()))
	}
	return nil
}

// Activate starts the plugin's background work. The ABI makes Activate
// idempotent, so a repeated call is forwarded and succeeds.
func (rt *UpdaterRuntime) Activate(ctx context.Context, h updater.Handle) error {
	handle, err := rt.instance(h)
	if err != nil {
		return err
	}
	svc, err := handle.service()
	if err != nil {
		return rpcFailure(handle, "activate", err)
	}
	rctx, cancel := rt.rpcCtx(ctx)
	defer cancel()
	if _, err := svc.Activate(rctx, &platformv1.ActivateRequest{Context: handle.rpcContext()}); err != nil {
		return rpcFailure(handle, "activate", err)
	}
	return nil
}

// Deactivate stops the plugin's background work. An instance that is already
// stopped or released is non-active by definition, so Deactivate returns nil
// for it.
func (rt *UpdaterRuntime) Deactivate(ctx context.Context, h updater.Handle) error {
	handle, err := rt.handle(h)
	if err != nil {
		return err
	}
	if handle == nil {
		return nil
	}
	svc, serr := handle.service()
	if serr != nil {
		if errors.Is(serr, errInstanceGone) {
			return nil
		}
		return serr
	}
	rctx, cancel := rt.rpcCtx(ctx)
	defer cancel()
	if _, err := svc.Deactivate(rctx, &platformv1.DeactivateRequest{Context: handle.rpcContext()}); err != nil {
		return rpcFailure(handle, "deactivate", err)
	}
	return nil
}

// Stop asks the plugin to drain, then stops the unit through systemd. A failed
// graceful stop is followed by `systemctl kill --kill-whom=main`; go-plugin's
// Client.Kill is never called, because it would signal the process directly and
// bypass the cgroup cleanup. Stop is idempotent and never closes the gRPC
// connection (Release does that).
func (rt *UpdaterRuntime) Stop(ctx context.Context, h updater.Handle, grace time.Duration) error {
	handle, err := rt.handle(h)
	if err != nil {
		return err
	}
	if handle == nil {
		return nil
	}
	handle.mu.Lock()
	if handle.stopped || handle.released {
		handle.mu.Unlock()
		return nil
	}
	handle.mu.Unlock()

	// The drain is best effort: a plugin that is already dead or wedged must
	// not prevent the authoritative systemd stop below.
	if svc, serr := handle.service(); serr == nil {
		drainCtx, cancel := drainContext(ctx, grace)
		_, derr := svc.Stop(drainCtx, &platformv1.StopRequest{
			Context:       handle.rpcContext(),
			Drain:         true,
			GracePeriodMs: graceMillis(grace),
		})
		if derr == nil {
			// ABI order: Stop(drain) then ReleaseInstance. The plugin may free
			// the instance state now; the process itself is stopped by systemd
			// below. A failure here must not block the unit stop.
			if _, rerr := svc.ReleaseInstance(drainCtx, &platformv1.ReleaseInstanceRequest{
				Context: handle.rpcContext(),
			}); rerr != nil {
				rt.logger().WarnContext(ctx, "the plugin did not release the drained instance",
					"plugin_id", handle.pluginID, "version", handle.version, "err", rerr)
			}
		}
		cancel()
		if derr != nil {
			rt.logger().WarnContext(ctx, "plugin drain did not complete; stopping the unit anyway",
				"plugin_id", handle.pluginID, "version", handle.version, "err", derr)
		}
	}

	systemctl, serr := rt.requireSystemctl()
	if serr != nil {
		return serr
	}
	if serr := rt.stopUnit(ctx, systemctl, handle.unit); serr != nil {
		return &problem.Error{
			Code:   problem.PluginUnavailable,
			Detail: fmt.Sprintf("The unit of plugin %s could not be stopped.", handle.pluginID),
			Cause:  serr,
		}
	}
	// The socket unit stays active after the service stops and would start it
	// again on the next connection (systemd socket activation). A stopped
	// instance must stay stopped, so close the listener too; a later Start
	// pulls the socket in through Requires=.
	if _, socket, nerr := sandbox.UnitNames(handle.pluginID); nerr == nil {
		if serr := rt.stopUnit(ctx, systemctl, socket); serr != nil {
			rt.logger().WarnContext(ctx, "the plugin socket unit could not be stopped",
				"plugin_id", handle.pluginID, "unit", socket, "err", serr)
		}
	}
	handle.mu.Lock()
	handle.stopped = true
	handle.mu.Unlock()
	return nil
}

// stopUnit stops one unit and force-kills it when the graceful stop fails. The
// forced step uses a context detached from the caller, because the caller's
// deadline is often what made the graceful stop fail in the first place. It
// never touches the go-plugin client, so the plugin process is only ever
// signalled by systemd.
func (rt *UpdaterRuntime) stopUnit(ctx context.Context, systemctl sandbox.Systemctl, unit string) error {
	serr := systemctl.Stop(ctx, unit)
	if serr == nil {
		return nil
	}
	killCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), forceKillTimeout)
	kerr := systemctl.Kill(killCtx, unit)
	cancel()
	if kerr != nil {
		return errors.Join(serr, kerr)
	}
	rt.logger().WarnContext(ctx, "plugin unit was force-killed after a failed stop",
		"unit", unit, "err", serr)
	return nil
}

// stopFailedStart cleans up a unit that was started by a Start call that could
// not attach to it. Without it the unit would keep the process alive, and the
// saga's rollback could not start the old version (Start refuses while any
// instance runs).
func (rt *UpdaterRuntime) stopFailedStart(ctx context.Context, systemctl sandbox.Systemctl, unit string) {
	stopCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), forceKillTimeout)
	defer cancel()
	if err := rt.stopUnit(stopCtx, systemctl, unit); err != nil {
		rt.logger().ErrorContext(ctx, "the unit of a failed plugin start could not be stopped",
			"unit", unit, "err", err)
	}
}

// Release frees the host-side connection of a stopped instance and removes it
// from the runtime registry. It never signals the process and is idempotent.
func (rt *UpdaterRuntime) Release(_ context.Context, h updater.Handle) error {
	handle, err := rt.handle(h)
	if err != nil {
		return err
	}
	if handle == nil {
		return nil
	}
	handle.mu.Lock()
	if handle.released {
		handle.mu.Unlock()
		return nil
	}
	handle.released = true
	handle.stopped = true
	grpcClient := handle.grpc
	handle.grpc, handle.client = nil, nil
	handle.mu.Unlock()

	if grpcClient != nil {
		if cerr := grpcClient.Close(); cerr != nil {
			rt.logger().Warn("closing the plugin connection failed",
				"plugin_id", handle.pluginID, "version", handle.version, "err", cerr)
		}
	}
	rt.unregister(handle)
	rt.logger().Info("plugin instance released",
		"plugin_id", handle.pluginID, "version", handle.version,
		"main_pid", handle.mainPID, "generation", handle.generation,
		"owner", handle.owner, "node_id", rt.nodeID())
	return nil
}

// Health is the cheap runtime check the host may call at any time.
func (rt *UpdaterRuntime) Health(ctx context.Context, h updater.Handle) error {
	handle, err := rt.instance(h)
	if err != nil {
		return err
	}
	resp, err := handle.checkHealth(ctx)
	if err != nil {
		return unavailable(handle, "pass its health check", err)
	}
	if resp.GetStatus() != platformv1.CheckHealthResponse_STATUS_SERVING {
		return unavailable(handle, "pass its health check",
			fmt.Errorf("health status is %s: %s", resp.GetStatus(), resp.GetMessage()))
	}
	return nil
}

// ValidateConfig asks the plugin to validate a configuration revision without
// applying it. Violations or a plugin-reported error become a validation
// problem carrying the plugin's field pointers.
func (rt *UpdaterRuntime) ValidateConfig(ctx context.Context, h updater.Handle, revision int64, cfg json.RawMessage) error {
	handle, err := rt.instance(h)
	if err != nil {
		return err
	}
	svc, err := handle.service()
	if err != nil {
		return rpcFailure(handle, "validate the configuration", err)
	}
	handle.mu.Lock()
	current := handle.configRevision
	handle.mu.Unlock()
	rctx, cancel := rt.rpcCtx(ctx)
	defer cancel()
	resp, err := svc.ValidateConfig(rctx, &platformv1.ValidateConfigRequest{
		Context:          handle.rpcContext(),
		ConfigJson:       cfg,
		ProposedRevision: strconv.FormatInt(revision, 10),
		CurrentRevision:  strconv.FormatInt(current, 10),
	})
	if err != nil {
		return rpcFailure(handle, "validate the configuration", err)
	}
	if e := resp.GetError(); e != nil {
		return pluginErrorFromProto(e)
	}
	if violations := resp.GetViolations(); len(violations) > 0 {
		mapped := make([]problem.Violation, 0, len(violations))
		for _, v := range violations {
			mapped = append(mapped, violationFromProto(v))
		}
		return &problem.Error{
			Code: problem.ValidationFailed,
			Detail: fmt.Sprintf("The plugin %s rejected configuration revision %d.",
				handle.pluginID, revision),
			Violations: mapped,
		}
	}
	return nil
}

// ApplyConfig applies a configuration revision and reports success only when
// the plugin confirms that exact revision is live.
func (rt *UpdaterRuntime) ApplyConfig(ctx context.Context, h updater.Handle, revision int64, cfg json.RawMessage) error {
	handle, err := rt.instance(h)
	if err != nil {
		return err
	}
	svc, err := handle.service()
	if err != nil {
		return rpcFailure(handle, "apply the configuration", err)
	}
	handle.mu.Lock()
	current := handle.configRevision
	handle.mu.Unlock()
	proposed := strconv.FormatInt(revision, 10)
	rctx, cancel := rt.rpcCtx(ctx)
	defer cancel()
	resp, err := svc.ApplyConfig(rctx, &platformv1.ApplyConfigRequest{
		Context:          handle.rpcContext(),
		ConfigJson:       cfg,
		ProposedRevision: proposed,
		CurrentRevision:  strconv.FormatInt(current, 10),
	})
	if err != nil {
		return rpcFailure(handle, "apply the configuration", err)
	}
	if e := resp.GetError(); e != nil {
		return pluginErrorFromProto(e)
	}
	if applied := resp.GetAppliedRevision(); applied != proposed {
		return &problem.Error{
			Code: problem.PluginError,
			Detail: fmt.Sprintf("The plugin %s reported configuration revision %q after applying %q.",
				handle.pluginID, applied, proposed),
		}
	}
	handle.mu.Lock()
	handle.configRevision = revision
	handle.mu.Unlock()
	return nil
}

// SwapRoutes stores an immutable routing snapshot. Readers see either the
// complete old table or the complete new one (ARCH 搂5.7). Publishing the
// snapshot to the operation dispatcher is the host's remaining integration
// point; this runtime only owns the snapshot.
func (rt *UpdaterRuntime) SwapRoutes(routes *updater.RouteTable) {
	if routes == nil {
		routes = updater.NewRouteTable(nil)
	}
	rt.routes.Store(routes)
}

// Routes returns the last published route snapshot.
func (rt *UpdaterRuntime) Routes() *updater.RouteTable { return rt.routes.Load() }

// attach 复用原生连接，代次和版本仍来自上层的当前 systemd 事实。
func (rt *UpdaterRuntime) attach(ctx context.Context, spec updater.InstanceSpec, state sandbox.UnitStatus) (*pluginHandle, error) {
	unit := supervisor.UnitName(spec.PluginID)
	socket := supervisor.SocketPath(rt.runDir(), spec.PluginID)
	connection, err := supervisor.OpenPluginConnection(ctx, socket, rt.connectTimeout())
	if err != nil {
		return nil, &problem.Error{
			Code:   problem.PluginUnavailable,
			Detail: fmt.Sprintf("The socket of plugin %s could not be attached.", spec.PluginID),
			Cause:  err,
		}
	}
	now := rt.clock().Now()
	return &pluginHandle{
		rt:             rt,
		pluginID:       spec.PluginID,
		version:        spec.Version,
		unit:           unit,
		mainPID:        state.MainPID,
		startTime:      state.StartTime,
		generation:     instanceGeneration(unit, state.MainPID, state.StartTime),
		owner:          supervisor.Owner(spec.PluginID, instanceGeneration(unit, state.MainPID, state.StartTime)),
		since:          now,
		client:         platformv1.NewPluginServiceClient(connection),
		grpc:           connection,
		configRevision: spec.ConfigRevision,
	}, nil
}

// ======================== 接管前核对进程的实际版本事实 ========================
// verifyRunningVersion 至少需要 descriptor 版本或已加载 ExecStart 路径证明。
// 两项都可读时必须同时匹配；缺失全部证明或相互矛盾，均不能初始化或接管。
// systemd 保留已加载的单元定义，故新文件存在不能证明旧进程已切换版本。
func (rt *UpdaterRuntime) verifyRunningVersion(ctx context.Context, spec updater.InstanceSpec, handle *pluginHandle, state sandbox.UnitStatus) error {
	svc, err := handle.service()
	if err != nil {
		return rpcFailure(handle, "report its descriptor", err)
	}
	rctx, cancel := rt.rpcCtx(ctx)
	defer cancel()
	resp, err := svc.GetDescriptor(rctx, &platformv1.GetDescriptorRequest{})
	descriptorVerified := false
	switch {
	case err == nil && resp.GetDescriptor_().GetPluginVersion() != "":
		if running := resp.GetDescriptor_().GetPluginVersion(); running != spec.Version {
			return problem.New(problem.PluginUnavailable,
				"The unit of plugin %s runs version %s, not version %s; the systemd unit definition is stale (run systemctl daemon-reload) or another version owns the unit.",
				spec.PluginID, running, spec.Version)
		}
		descriptorVerified = true
	case err != nil && status.Code(err) != codes.Unimplemented:
		rt.logger().WarnContext(ctx, "plugin descriptor unavailable; checking the unit ExecStart",
			"plugin_id", spec.PluginID, "version", spec.Version, "err", err)
	}
	if state.ExecStart == "" || spec.Manifest == nil || spec.Manifest.Entrypoint == "" {
		if descriptorVerified {
			return nil
		}
		return problem.New(problem.PluginUnavailable, "The running version of plugin %s could not be verified.", spec.PluginID)
	}
	want := filepath.Join(install.VersionDir(filepath.Clean(rt.PluginsRoot), spec.PluginID, spec.Version), spec.Manifest.Entrypoint)
	if filepath.Clean(state.ExecStart) != want {
		return problem.New(problem.PluginUnavailable,
			"The unit of plugin %s runs %s, not version %s (%s).", spec.PluginID, state.ExecStart, spec.Version, want)
	}
	return nil
}

// bootstrapInstance performs the instance half of the ABI lifecycle that
// follows the process handshake: Initialize then Start, before Ready and
// Activate. The systemd unit only starts the process; without these calls the
// plugin serves GetDescriptor and gRPC health but has no instance, so every
// instance-level RPC (including CheckHealth) would be NOT_FOUND.
//
// fresh is true when this runtime started the unit, so the process cannot have
// an instance yet. Attach sets it to false: the process may have survived a
// host restart with its instance already initialized, and re-initializing it
// is refused by the ABI. CheckHealth reports the instance lifecycle state
// (NOT_FOUND when Initialize never ran), which is what distinguishes the two
// cases without guessing from error codes.
//
// Both calls happen once per attach; a failure is a plugin fault, and the
// caller stops the unit so the saga can roll back.
func (rt *UpdaterRuntime) bootstrapInstance(ctx context.Context, spec updater.InstanceSpec, handle *pluginHandle, fresh bool) error {
	svc, err := handle.service()
	if err != nil {
		return rpcFailure(handle, "initialize", err)
	}
	if !fresh {
		hctx, cancel := rt.rpcCtx(ctx)
		resp, herr := svc.CheckHealth(hctx, &platformv1.CheckHealthRequest{Context: handle.rpcContext()})
		cancel()
		switch {
		case herr == nil:
			switch resp.GetLifecycleState() {
			case platformv1.LifecycleState_LIFECYCLE_STATE_INITIALIZED:
				// The process was initialized before the host restarted and
				// never started; the remaining step is Start.
				return rt.startInstance(ctx, handle, svc)
			case platformv1.LifecycleState_LIFECYCLE_STATE_READY,
				platformv1.LifecycleState_LIFECYCLE_STATE_ACTIVE:
				// The instance is live; Ready validates it. Releasing or
				// re-initializing it here would disturb a healthy process.
				return nil
			case platformv1.LifecycleState_LIFECYCLE_STATE_STOPPED,
				platformv1.LifecycleState_LIFECYCLE_STATE_FAILED:
				return unavailable(handle, "attach",
					fmt.Errorf("the instance is %s", resp.GetLifecycleState()))
			}
			// LIFECYCLE_STATE_UNSPECIFIED and DRAINING are not recoverable
			// states for a fresh attach; fall through and let Initialize report
			// the plugin's own reason.
		case status.Code(herr) == codes.NotFound:
			// Initialize never ran on this process.
		default:
			return rpcFailure(handle, "inspect its lifecycle state", herr)
		}
	}

	cfg := spec.Config
	if len(cfg) == 0 {
		cfg = []byte("{}")
	}
	instanceHandle := spec.InstanceHandle
	if instanceHandle == "" {
		// The handle only has to be opaque and stable for this process. A
		// plugin instance lives exactly as long as its process, so the
		// generation derived from systemd facts is the right identity.
		instanceHandle = "inst-" + handle.generation
	}
	dataDir, err := sandbox.RuntimePluginDataDir(spec.DataDir, spec.PluginID)
	if err != nil {
		return bootstrapFailure(handle, "initialize", err)
	}
	ictx, cancel := rt.rpcCtx(ctx)
	defer cancel()
	initResp, ierr := svc.Initialize(ictx, &platformv1.InitializeRequest{
		Context:        handle.rpcContext(),
		InstanceHandle: instanceHandle,
		// systemd 的逻辑 StateDirectory 叶节点是受控链接；插件收到固定真实私有路径。
		// 未声明私有状态的插件仍收到空路径。
		DataDir:        dataDir,
		ConfigJson:     cfg,
		ConfigRevision: strconv.FormatInt(spec.ConfigRevision, 10),
		HostAbiMinor:   uint32(abi.Minor),
	})
	if ierr != nil {
		return bootstrapFailure(handle, "initialize", ierr)
	}
	stateSchema := initResp.GetStateSchemaVersion()
	handle.mu.Lock()
	handle.instanceHandle = instanceHandle
	handle.configRevision = spec.ConfigRevision
	handle.stateSchemaVersion = stateSchema
	handle.mu.Unlock()
	if err := rt.startInstance(ctx, handle, svc); err != nil {
		return err
	}
	rt.logger().DebugContext(ctx, "plugin instance bootstrapped",
		"plugin_id", handle.pluginID, "version", handle.version,
		"instance_handle", instanceHandle, "config_revision", spec.ConfigRevision,
		"state_schema_version", stateSchema)
	return nil
}

// startInstance moves an initialized instance to READY.
func (rt *UpdaterRuntime) startInstance(ctx context.Context, handle *pluginHandle, svc platformv1.PluginServiceClient) error {
	rctx, cancel := rt.rpcCtx(ctx)
	defer cancel()
	if _, err := svc.Start(rctx, &platformv1.StartRequest{Context: handle.rpcContext()}); err != nil {
		return bootstrapFailure(handle, "start", err)
	}
	return nil
}

// bootstrapFailure maps an Initialize/Start failure to PLUGIN_UNAVAILABLE: the
// candidate must not serve traffic or background work. A deadline keeps its
// own code so a slow plugin is reported as a timeout, not as a crash.
func bootstrapFailure(handle *pluginHandle, action string, err error) error {
	if errors.Is(err, context.DeadlineExceeded) || status.Code(err) == codes.DeadlineExceeded {
		return rpcFailure(handle, action, err)
	}
	return unavailable(handle, action, err)
}

// register adds handle to the registry. With exclusive set it refuses while any
// instance of the plugin is live (Start); otherwise it returns the instance
// that already owns the slot (Attach).
func (rt *UpdaterRuntime) register(handle *pluginHandle, exclusive bool) (*pluginHandle, error) {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	if rt.instances == nil {
		rt.instances = make(map[string]map[string]*pluginHandle)
	}
	byVersion := rt.instances[handle.pluginID]
	if byVersion == nil {
		byVersion = make(map[string]*pluginHandle)
		rt.instances[handle.pluginID] = byVersion
	}
	for version, current := range byVersion {
		if current.released {
			delete(byVersion, version)
		}
	}
	if exclusive {
		for _, current := range byVersion {
			if current.live() {
				return nil, problem.New(problem.PreconditionFailed,
					"Plugin %s already has a live instance of version %s; stop it before starting version %s.",
					handle.pluginID, current.version, handle.version)
			}
		}
	} else if current := byVersion[handle.version]; current != nil && current.live() {
		return current, nil
	}
	byVersion[handle.version] = handle
	return handle, nil
}

// unregister removes handle if it is still the registered instance.
func (rt *UpdaterRuntime) unregister(handle *pluginHandle) {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	byVersion := rt.instances[handle.pluginID]
	if byVersion == nil || byVersion[handle.version] != handle {
		return
	}
	delete(byVersion, handle.version)
	if len(byVersion) == 0 {
		delete(rt.instances, handle.pluginID)
	}
}

// lookup returns the live handle of one version.
func (rt *UpdaterRuntime) lookup(pluginID, version string) *pluginHandle {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	if byVersion := rt.instances[pluginID]; byVersion != nil {
		if handle := byVersion[version]; handle != nil && handle.live() {
			return handle
		}
	}
	return nil
}

// liveFor returns any live handle of a plugin, whichever version it runs.
func (rt *UpdaterRuntime) liveFor(pluginID string) *pluginHandle {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	for _, handle := range rt.instances[pluginID] {
		if handle.live() {
			return handle
		}
	}
	return nil
}

// handle returns the typed handle, nil for a nil updater.Handle.
func (rt *UpdaterRuntime) handle(h updater.Handle) (*pluginHandle, error) {
	if h == nil {
		return nil, nil
	}
	handle, ok := h.(*pluginHandle)
	if !ok {
		return nil, problem.New(problem.Internal, "The plugin handle belongs to another runtime.")
	}
	return handle, nil
}

// instance returns a handle that must be usable.
func (rt *UpdaterRuntime) instance(h updater.Handle) (*pluginHandle, error) {
	handle, err := rt.handle(h)
	if err != nil {
		return nil, err
	}
	if handle == nil {
		return nil, problem.New(problem.PluginUnavailable, "No plugin instance is attached.")
	}
	return handle, nil
}

// requireSystemctl returns the systemd client or a host error.
func (rt *UpdaterRuntime) requireSystemctl() (sandbox.Systemctl, error) {
	if rt.Systemctl == nil {
		return nil, problem.New(problem.Unavailable, "The plugin runtime has no systemd client.")
	}
	return rt.Systemctl, nil
}

// requireVersionDir checks that the version was installed before its unit is
// started, so a missing package fails with PLUGIN_UNAVAILABLE instead of an
// ExecStartPre failure in the journal.
func (rt *UpdaterRuntime) requireVersionDir(spec updater.InstanceSpec) error {
	if rt.PluginsRoot == "" {
		return nil
	}
	if !filepath.IsAbs(rt.PluginsRoot) {
		return problem.New(problem.Unavailable, "The plugin package directory is not an absolute path.")
	}
	dir := install.VersionDir(filepath.Clean(rt.PluginsRoot), spec.PluginID, spec.Version)
	info, err := os.Stat(dir)
	if err != nil || !info.IsDir() {
		return &problem.Error{
			Code:   problem.PluginUnavailable,
			Detail: fmt.Sprintf("The installed files of plugin %s version %s are missing.", spec.PluginID, spec.Version),
			Cause:  err,
		}
	}
	return nil
}

// runDir returns the plugin socket root.
func (rt *UpdaterRuntime) runDir() string {
	if rt.RunDir == "" {
		return supervisor.DefaultRunDir
	}
	return rt.RunDir
}

// connectTimeout bounds the go-plugin handshake.
func (rt *UpdaterRuntime) connectTimeout() time.Duration {
	if rt.ConnectTimeout > 0 {
		return rt.ConnectTimeout
	}
	return updaterConnectTimeout
}

// rpcTimeout returns the default deadline of a lifecycle RPC.
func (rt *UpdaterRuntime) rpcTimeout() time.Duration {
	if rt.RPCTimeout > 0 {
		return rt.RPCTimeout
	}
	return updaterRPCTimeout
}

// rpcCtx 为没有截止时间的生命周期 RPC 套上默认超时，防止卡死的插件拖住宿主。
func (rt *UpdaterRuntime) rpcCtx(ctx context.Context) (context.Context, context.CancelFunc) {
	if _, ok := ctx.Deadline(); ok {
		return ctx, func() {}
	}
	return context.WithTimeout(ctx, rt.rpcTimeout())
}

// clock returns the configured clock.
func (rt *UpdaterRuntime) clock() clock.Clock {
	if rt.Clock == nil {
		return clock.System{}
	}
	return rt.Clock
}

// logger returns the configured logger.
func (rt *UpdaterRuntime) logger() *slog.Logger {
	if rt.Logger == nil {
		return slog.New(slog.DiscardHandler)
	}
	return rt.Logger
}

// nodeID returns the node label used in lifecycle requests.
func (rt *UpdaterRuntime) nodeID() string {
	if rt.NodeID == "" {
		return "local"
	}
	return rt.NodeID
}

// --- handle helpers ---------------------------------------------------------

// errInstanceGone marks a handle that was stopped or released.
var errInstanceGone = errors.New("controller: the plugin instance is gone")

// service returns the RPC client while the instance is usable.
func (h *pluginHandle) service() (platformv1.PluginServiceClient, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	switch {
	case h.released:
		return nil, fmt.Errorf("%w: instance released", errInstanceGone)
	case h.stopped:
		return nil, fmt.Errorf("%w: instance stopped", errInstanceGone)
	case h.client == nil:
		return nil, fmt.Errorf("%w: no connection", errInstanceGone)
	}
	return h.client, nil
}

// live reports whether the handle still owns a usable process connection.
func (h *pluginHandle) live() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return !h.released && !h.stopped && h.client != nil
}

// closeConnection closes our side of a connection that never became current.
func (h *pluginHandle) closeConnection() {
	h.mu.Lock()
	grpcClient := h.grpc
	h.grpc, h.client = nil, nil
	h.mu.Unlock()
	if grpcClient != nil {
		_ = grpcClient.Close()
	}
}

// checkHealth calls the plugin's self-check.
func (h *pluginHandle) checkHealth(ctx context.Context) (*platformv1.CheckHealthResponse, error) {
	svc, err := h.service()
	if err != nil {
		return nil, err
	}
	rctx, cancel := h.rt.rpcCtx(ctx)
	defer cancel()
	return svc.CheckHealth(rctx, &platformv1.CheckHealthRequest{Context: h.rpcContext()})
}

// rpcContext builds the ABI request context of a lifecycle call.
func (h *pluginHandle) rpcContext() *platformv1.RequestContext {
	return &platformv1.RequestContext{
		NodeId:     h.rt.nodeID(),
		InstanceId: DefaultInstanceID,
	}
}

// --- helpers ----------------------------------------------------------------

// validateInstanceSpec rejects a spec that cannot become a unit or a socket.
func validateInstanceSpec(spec updater.InstanceSpec) error {
	if err := sandbox.ValidateID(spec.PluginID); err != nil {
		return problem.New(problem.ValidationFailed, "%q is not a valid plugin id.", spec.PluginID)
	}
	if !versionNamePattern.MatchString(spec.Version) {
		return problem.New(problem.ValidationFailed, "%q is not a valid plugin version.", spec.Version)
	}
	if spec.Manifest == nil {
		return problem.New(problem.ValidationFailed,
			"The plugin spec of %s version %s has no manifest.", spec.PluginID, spec.Version)
	}
	return nil
}

// unitFailure maps a systemd failure to a host error.
func unitFailure(pluginID, verb string, err error) *problem.Error {
	return &problem.Error{
		Code:   problem.PluginUnavailable,
		Detail: fmt.Sprintf("The unit of plugin %s could not be %s.", pluginID, verb),
		Cause:  err,
	}
}

// unavailable wraps a readiness failure as PLUGIN_UNAVAILABLE.
func unavailable(handle *pluginHandle, action string, err error) *problem.Error {
	return &problem.Error{
		Code:   problem.PluginUnavailable,
		Detail: fmt.Sprintf("The plugin %s version %s could not %s.", handle.pluginID, handle.version, action),
		Cause:  err,
	}
}

// rpcFailure maps a lifecycle RPC failure to a host error. Transport failures
// and cancellations are PLUGIN_UNAVAILABLE; everything else keeps the ABI
// meaning.
func rpcFailure(handle *pluginHandle, action string, err error) error {
	if errors.Is(err, context.DeadlineExceeded) {
		return &problem.Error{
			Code:   problem.Timeout,
			Detail: fmt.Sprintf("The plugin %s did not %s before its deadline.", handle.pluginID, action),
			Cause:  err,
		}
	}
	if errors.Is(err, errInstanceGone) {
		return &problem.Error{
			Code:   problem.PluginUnavailable,
			Detail: fmt.Sprintf("The plugin %s version %s is not running.", handle.pluginID, handle.version),
			Cause:  err,
		}
	}
	detail := fmt.Sprintf("The plugin %s failed to %s.", handle.pluginID, action)
	switch status.Code(err) {
	case codes.Unavailable, codes.Canceled:
		return &problem.Error{Code: problem.PluginUnavailable, Detail: detail, Cause: err}
	case codes.DeadlineExceeded:
		return &problem.Error{Code: problem.Timeout, Detail: detail, Cause: err}
	case codes.Unimplemented:
		return &problem.Error{Code: problem.PluginError, Detail: detail, Cause: err}
	case codes.PermissionDenied:
		return &problem.Error{Code: problem.PermissionDenied, Detail: detail, Cause: err}
	case codes.InvalidArgument, codes.FailedPrecondition:
		return &problem.Error{Code: problem.ValidationFailed, Detail: detail, Cause: err}
	case codes.NotFound:
		return &problem.Error{Code: problem.NotFound, Detail: detail, Cause: err}
	}
	return &problem.Error{Code: problem.PluginError, Detail: detail, Cause: err}
}

// instanceGeneration is sha256(unit|MainPID|starttime)[:16], the same identity
// the supervisor derives from systemd facts (ARCH 搂5.7). The plugin never
// contributes to it.
func instanceGeneration(unit string, mainPID int, start time.Time) string {
	sum := sha256.New()
	_, _ = sum.Write([]byte(unit))
	_, _ = sum.Write([]byte{'|'})
	_, _ = sum.Write([]byte(strconv.Itoa(mainPID)))
	_, _ = sum.Write([]byte{'|'})
	_, _ = sum.Write([]byte(strconv.FormatInt(start.UnixNano(), 10)))
	return hex.EncodeToString(sum.Sum(nil))[:16]
}

// drainContext bounds the drain RPC with the grace window plus a small margin.
func drainContext(ctx context.Context, grace time.Duration) (context.Context, context.CancelFunc) {
	if grace <= 0 {
		return context.WithCancel(ctx)
	}
	return context.WithTimeout(ctx, grace+drainGraceMargin)
}

// graceMillis converts a grace window to the ABI's int32 milliseconds.
func graceMillis(grace time.Duration) int32 {
	ms := grace.Milliseconds()
	if ms <= 0 {
		return 0
	}
	if ms > math.MaxInt32 {
		return math.MaxInt32
	}
	return int32(ms)
}

// --- memory -----------------------------------------------------------------

// HostMemory implements updater.MemorySource from procfs and cgroup v2.
//
// Available is MemAvailable, which accounts for reclaimable page cache; Current
// is the memory.current of the plugin's unit cgroup. A cgroup that does not
// exist (the unit is not running) is an error, which makes the updater choose
// the restart strategy instead of guessing.
type HostMemory struct {
	// ProcRoot defaults to /proc.
	ProcRoot string
	// CgroupRoot is the cgroup v2 mount; default /sys/fs/cgroup.
	CgroupRoot string
}

// Available returns MemAvailable in bytes.
func (m *HostMemory) Available() (uint64, error) {
	path := filepath.Join(m.procRoot(), "meminfo")
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	for _, line := range strings.Split(string(data), "\n") {
		key, value, ok := strings.Cut(line, ":")
		if !ok || key != "MemAvailable" {
			continue
		}
		fields := strings.Fields(value)
		if len(fields) == 0 {
			return 0, fmt.Errorf("controller: %s has no value for MemAvailable", path)
		}
		kib, perr := strconv.ParseUint(fields[0], 10, 64)
		if perr != nil || kib > math.MaxUint64/1024 {
			return 0, fmt.Errorf("controller: %s has an unusable MemAvailable value %q", path, fields[0])
		}
		return kib * 1024, nil
	}
	return 0, fmt.Errorf("controller: %s has no MemAvailable line", path)
}

// Current 返回插件单元的 cgroup 用量，旧平铺布局只在模板路径缺失时回退。
func (m *HostMemory) Current(pluginID string) (uint64, error) {
	if err := sandbox.ValidateID(pluginID); err != nil {
		return 0, err
	}
	// --- 模板 cgroup：优先官方 slice，保留旧布局兼容 -----------------------------
	systemSlice := filepath.Join(m.cgroupRoot(), "system.slice")
	unit := supervisor.UnitName(pluginID)
	path := filepath.Join(systemSlice, `system-qwq\x2dplugin.slice`, unit, "memory.current")
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		path = filepath.Join(systemSlice, unit, "memory.current")
		data, err = os.ReadFile(path)
	}
	if err != nil {
		return 0, err
	}
	value, err := strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("controller: %s is not a byte count: %w", path, err)
	}
	return value, nil
}

func (m *HostMemory) procRoot() string {
	if m.ProcRoot == "" {
		return "/proc"
	}
	return m.ProcRoot
}

func (m *HostMemory) cgroupRoot() string {
	if m.CgroupRoot == "" {
		return "/sys/fs/cgroup"
	}
	return m.CgroupRoot
}
