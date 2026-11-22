// SPDX-License-Identifier: AGPL-3.0-only

package updater

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/qwq-panel/qwq/internal/platform/problem"
	"github.com/qwq-panel/qwq/internal/pluginhost/install"
	"github.com/qwq-panel/qwq/internal/storage"
	"github.com/qwq-panel/qwq/sdk/manifest"
)

// Install stages, verifies, installs and starts a plugin that has no active
// version yet. The installation is a saga as well, so a crash between staging
// and activation is recovered instead of leaving an orphaned unit.
func (u *Updater) Install(ctx context.Context, req InstallRequest) (*Version, error) {
	if req.PackagePath == "" {
		return nil, problem.Validation(problem.Violation{
			Pointer: "/package_path", Code: "REQUIRED", Message: "A package path is required.",
		})
	}
	ctx, cancel := u.withTimeout(ctx, req.Timeout)
	defer cancel()

	staged, err := u.stage(ctx, req.PackagePath)
	if err != nil {
		return nil, err
	}
	if err := checkSchemaVersion(staged.Manifest); err != nil {
		_ = staged.DiscardStaged()
		return nil, err
	}
	if req.PluginID != "" && req.PluginID != staged.PluginID {
		_ = staged.DiscardStaged()
		return nil, problem.Validation(problem.Violation{
			Pointer: "/plugin_id", Code: "MANIFEST_MISMATCH",
			Message: "The requested plugin id does not match the package manifest.",
		})
	}

	unlock := u.locks.lock(staged.PluginID)
	defer unlock()
	defer staged.DiscardStaged() //nolint:errcheck // best effort cleanup

	if active, ok := u.Active(staged.PluginID); ok {
		return nil, problem.New(problem.StateConflict,
			"Plugin %s already has active version %s; use Update.", staged.PluginID, active.Version)
	}
	if req.ExpectedRevision != 0 {
		return nil, problem.Conflict("0")
	}
	if err := u.requireNoRunningSaga(ctx, staged.PluginID); err != nil {
		return nil, err
	}
	if err := checkCapabilities(staged.Manifest, nil, req.AcceptedCapabilities); err != nil {
		return nil, err
	}
	// A failed install of another package under this version may have left
	// its version directory behind; nothing runs, so remove it before the
	// new package is published there.
	slot, digest, err := u.versionSlot(ctx, staged.PluginID, staged.Version)
	if err != nil {
		return nil, problem.Wrap(err)
	}
	if slot == slotRetry && digest != staged.Digest {
		if err := u.install.RemoveUnit(ctx, staged.PluginID, staged.Version); err != nil {
			return nil, problem.Wrap(err)
		}
	}
	if _, err := u.planMemory(ctx, staged.PluginID, staged.Manifest, StrategyInstall, false); err != nil {
		return nil, err
	}
	p, err := u.beginSaga(ctx, modeInstall, StrategyInstall, "", &staged)
	if err != nil {
		return nil, err
	}
	if err := u.runSaga(ctx, p); err != nil {
		return nil, err
	}
	v, err := u.loadVersion(ctx, p.saga.PluginID, p.saga.ToVersion)
	if err != nil {
		return nil, problem.Wrap(err)
	}
	return &v, nil
}

// Update replaces the active version of a plugin with a freshly staged one.
// It holds that plugin's lock for the whole saga, never a global lock.
func (u *Updater) Update(ctx context.Context, req UpdateRequest) (*UpdateResult, error) {
	if err := checkPluginID(req.PluginID); err != nil {
		return nil, err
	}
	if req.PackagePath == "" {
		return nil, problem.Validation(problem.Violation{
			Pointer: "/package_path", Code: "REQUIRED", Message: "A package path is required.",
		})
	}
	switch req.Strategy {
	case "", StrategyOverlap, StrategyRestart:
	default:
		return nil, problem.Validation(problem.Violation{
			Pointer: "/strategy", Code: "INVALID_VALUE",
			Message: "The update strategy must be overlap or restart.",
		})
	}
	ctx, cancel := u.withTimeout(ctx, req.Timeout)
	defer cancel()

	unlock := u.locks.lock(req.PluginID)
	defer unlock()

	active, ok := u.Active(req.PluginID)
	if !ok {
		return nil, problem.New(problem.StateConflict,
			"Plugin %s has no active version; use Install.", req.PluginID)
	}
	if req.ExpectedRevision != 0 && req.ExpectedRevision != active.Revision {
		return nil, problem.Conflict(fmt.Sprint(active.Revision))
	}
	if err := u.requireNoRunningSaga(ctx, req.PluginID); err != nil {
		return nil, err
	}

	staged, err := u.stage(ctx, req.PackagePath)
	if err != nil {
		return nil, err
	}
	defer staged.DiscardStaged() //nolint:errcheck // best effort cleanup
	if staged.PluginID != req.PluginID {
		return nil, problem.Validation(problem.Violation{
			Pointer: "/plugin_id", Code: "MANIFEST_MISMATCH",
			Message: "The package belongs to another plugin.",
		})
	}
	if err := checkSchemaVersion(staged.Manifest); err != nil {
		return nil, err
	}
	if err := checkPublisher(staged.Manifest, active.Manifest, req.AcceptPublisherChange); err != nil {
		return nil, err
	}
	if staged.Version == active.Version {
		return nil, problem.New(problem.StateConflict,
			"Version %s of plugin %s is already active.", staged.Version, req.PluginID)
	}
	slot, digest, err := u.versionSlot(ctx, req.PluginID, staged.Version)
	if err != nil {
		return nil, problem.Wrap(err)
	}
	switch {
	case slot == slotTaken:
		return nil, problem.New(problem.StateConflict,
			"Version %s of plugin %s is already installed.", staged.Version, req.PluginID)
	case slot == slotRetry && digest != staged.Digest:
		// The failed candidate's directory holds another package, and the
		// per-plugin unit cannot be removed while the active version runs.
		return nil, problem.New(problem.StateConflict,
			"A failed attempt of version %s of plugin %s left files of a different package; publish the retry under a new version.",
			staged.Version, req.PluginID)
	}
	if err := checkCapabilities(staged.Manifest, active.Manifest, req.AcceptedCapabilities); err != nil {
		return nil, err
	}
	mem, err := u.planMemory(ctx, req.PluginID, staged.Manifest, req.Strategy, true)
	if err != nil {
		return nil, err
	}
	p, err := u.beginSaga(ctx, modeUpdate, mem.Strategy, active.Version, &staged)
	if err != nil {
		return nil, err
	}
	p.old = &active
	if err := u.runSaga(ctx, p); err != nil {
		return nil, err
	}
	return u.result(ctx, p)
}

// minInstallSchemaMinor is the oldest manifest schema minor accepted for a
// new install or update: 1.2 is the first that enforces the permission rules
// of ADR-0014. Installed versions keep running (loadState warns).
const minInstallSchemaMinor = 2

// schemaMinor returns N of schema_version "1.N", or -1 when unreadable.
func schemaMinor(m *manifest.Manifest) int {
	if m == nil {
		return -1
	}
	_, minor, _ := strings.Cut(m.SchemaVersion, ".")
	n, err := strconv.Atoi(minor)
	if err != nil {
		return -1
	}
	return n
}

// checkSchemaVersion refuses packages older than minInstallSchemaMinor. A
// staged package without a parsed manifest is left to the other checks.
func checkSchemaVersion(m *manifest.Manifest) error {
	if m == nil || schemaMinor(m) >= minInstallSchemaMinor {
		return nil
	}
	return problem.Validation(problem.Violation{
		Pointer: "/schema_version", Code: "SCHEMA_VERSION_TOO_OLD",
		Message: fmt.Sprintf("Manifest schema_version %q is no longer accepted; 1.%d or later is required.", m.SchemaVersion, minInstallSchemaMinor),
	})
}

// checkPublisher refuses an update signed by another publisher unless the
// caller accepted the change: the new publisher takes over the plugin's data,
// KV and granted capabilities (ADR-0015).
func checkPublisher(next, current *manifest.Manifest, accepted bool) error {
	if next == nil || current == nil || accepted || next.Publisher.ID == current.Publisher.ID {
		return nil
	}
	return problem.Validation(problem.Violation{
		Pointer: "/accept_publisher_change", Code: "PUBLISHER_CHANGED",
		Message: fmt.Sprintf("The package is published by %q, the active version by %q.", next.Publisher.ID, current.Publisher.ID),
	})
}

// Rollback switches the plugin back to its most recently activated retained
// version. The current version keeps its files, so a later Update can move
// forward again.
func (u *Updater) Rollback(ctx context.Context, pluginID string) (*UpdateResult, error) {
	if err := checkPluginID(pluginID); err != nil {
		return nil, err
	}
	ctx, cancel := u.withTimeout(ctx, 0)
	defer cancel()

	unlock := u.locks.lock(pluginID)
	defer unlock()

	active, ok := u.Active(pluginID)
	if !ok {
		return nil, problem.New(problem.NotFound, "Plugin %s has no active version.", pluginID)
	}
	if err := u.requireNoRunningSaga(ctx, pluginID); err != nil {
		return nil, err
	}
	target, err := u.previousVersion(ctx, pluginID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, problem.New(problem.NotFound, "Plugin %s has no retained previous version to roll back to.", pluginID)
	}
	if err != nil {
		return nil, problem.Wrap(err)
	}
	mem, err := u.planMemory(ctx, pluginID, target.Manifest, "", true)
	if err != nil {
		return nil, err
	}
	p, err := u.beginRollbackSaga(ctx, active, target, mem.Strategy)
	if err != nil {
		return nil, err
	}
	if err := u.runSaga(ctx, p); err != nil {
		return nil, err
	}
	return u.result(ctx, p)
}

// stage verifies and unpacks a package and normalizes the installer result.
func (u *Updater) stage(ctx context.Context, pkgPath string) (Staged, error) {
	staged, err := u.install.Stage(ctx, pkgPath)
	if err != nil {
		return Staged{}, stageProblem(err)
	}
	staged, err = normalizeStaged(staged)
	if err != nil {
		_ = staged.DiscardStaged()
		return Staged{}, problem.Wrap(err)
	}
	return staged, nil
}

// stageProblem maps an installer failure: an authentic package that violates
// a host policy is VALIDATION_FAILED (the caller can fix it), anything else is
// INTERNAL.
func stageProblem(err error) error {
	var pe *install.PolicyError
	if errors.As(err, &pe) {
		return problem.Validation(problem.Violation{
			Pointer: "/" + pe.Path, Code: pe.Code, Message: pe.Message,
		})
	}
	return &problem.Error{
		Code:   problem.Internal,
		Detail: "The plugin package could not be verified and staged.",
		Cause:  err,
	}
}

// beginSaga creates the version row (except for rollback, whose target already
// exists) and the saga row in one transaction, then loads the candidate.
func (u *Updater) beginSaga(ctx context.Context, mode sagaMode, strategy Strategy, fromVersion string, staged *Staged) (*plan, error) {
	steps := stepsFor(mode, strategy)
	var (
		pluginID  string
		toVersion string
	)
	if staged != nil {
		pluginID, toVersion = staged.PluginID, staged.Version
	} else {
		// Rollback: the caller fills old and candidate; the saga row still
		// needs the plugin and target identity. It is supplied below.
		return nil, errors.New("updater: beginSaga without a staged package")
	}
	var sg *saga
	err := u.db.Update(ctx, func(tx *storage.Tx) error {
		slot, _, err := versionSlotOf(ctx, tx, pluginID, toVersion)
		if err != nil {
			return err
		}
		switch slot {
		case slotTaken:
			return problem.New(problem.StateConflict, "Version %s of plugin %s is already installed.", toVersion, pluginID)
		case slotRetry:
			if err := deleteVersionTx(ctx, tx, pluginID, toVersion); err != nil {
				return err
			}
		}
		if err := u.insertVersionTx(ctx, tx, *staged, VersionStaged, InstallStaged); err != nil {
			return err
		}
		var serr error
		sg, serr = u.insertSagaTx(ctx, tx, pluginID, fromVersion, toVersion, mode, strategy, steps[0])
		return serr
	})
	if err != nil {
		return nil, err
	}
	candidate, err := u.loadVersion(ctx, pluginID, toVersion)
	if err != nil {
		return nil, problem.Wrap(err)
	}
	return &plan{
		saga:      sg,
		steps:     steps,
		strategy:  strategy,
		candidate: &candidate,
		staged:    staged,
	}, nil
}

// beginRollbackSaga creates the saga row of a rollback. The target version
// already has a row, so only the saga is inserted.
func (u *Updater) beginRollbackSaga(ctx context.Context, old Version, target Version, strategy Strategy) (*plan, error) {
	steps := stepsFor(modeRollback, strategy)
	var sg *saga
	err := u.db.Update(ctx, func(tx *storage.Tx) error {
		var serr error
		sg, serr = u.insertSagaTx(ctx, tx, old.PluginID, old.Version, target.Version, modeRollback, strategy, steps[0])
		return serr
	})
	if err != nil {
		return nil, err
	}
	return &plan{
		saga:      sg,
		steps:     steps,
		strategy:  strategy,
		old:       &old,
		candidate: &target,
	}, nil
}

// insertSagaTx inserts one RUNNING saga row and its started audit event.
func (u *Updater) insertSagaTx(ctx context.Context, tx *storage.Tx, pluginID, fromVersion, toVersion string,
	mode sagaMode, strategy Strategy, first step) (*saga, error) {
	now := tx.Now()
	id := tx.NewID(sagaIDPrefix)
	if _, err := tx.ExecContext(ctx, `INSERT INTO plugin_update_sagas
		(saga_id, plugin_id, from_version, to_version, mode, strategy, state, step, error, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, '', ?, ?)`,
		id, pluginID, fromVersion, toVersion, mode, strategy, SagaRunning, string(first),
		storage.FormatTime(now), storage.FormatTime(now)); err != nil {
		return nil, mapConstraint(err)
	}
	if err := u.beginCredentialRotationTx(ctx, tx, pluginID); err != nil {
		return nil, err
	}
	s := &saga{
		ID:          id,
		PluginID:    pluginID,
		FromVersion: fromVersion,
		ToVersion:   toVersion,
		Mode:        mode,
		Strategy:    strategy,
		State:       SagaRunning,
		Step:        string(first),
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	if err := u.appendEventTx(ctx, tx, sagaEventName(mode, "started"), "plugins/"+pluginID, id, stepEvent{
		SagaID:      id,
		PluginID:    pluginID,
		Mode:        string(mode),
		Strategy:    string(strategy),
		Step:        string(first),
		FromVersion: fromVersion,
		ToVersion:   toVersion,
	}); err != nil {
		return nil, err
	}
	return s, nil
}

// result builds the public result of a committed saga.
func (u *Updater) result(ctx context.Context, p *plan) (*UpdateResult, error) {
	v, err := u.loadVersion(ctx, p.saga.PluginID, p.saga.ToVersion)
	if err != nil {
		return nil, problem.Wrap(err)
	}
	return &UpdateResult{
		SagaID:      p.saga.ID,
		PluginID:    p.saga.PluginID,
		FromVersion: p.saga.FromVersion,
		ToVersion:   p.saga.ToVersion,
		Strategy:    p.strategy,
		State:       p.saga.State,
		Restarted:   p.strategy == StrategyRestart,
		Version:     v,
	}, nil
}

// versionSlot classifies pluginID@version outside a write transaction.
func (u *Updater) versionSlot(ctx context.Context, pluginID, version string) (versionSlot, string, error) {
	var (
		slot   versionSlot
		digest string
	)
	err := u.db.View(ctx, func(tx *sql.Tx) error {
		var err error
		slot, digest, err = versionSlotOf(ctx, tx, pluginID, version)
		return err
	})
	return slot, digest, err
}

// checkCapabilities verifies that the caller approved every capability that
// the new version adds. A capability is identified by (name, scope) as in the
// manifest, so widening the scope of a granted capability needs fresh consent
// (PLG-09). For a fresh install oldManifest is nil, so every capability is new.
//
// An accepted entry is "name:scope" or a bare "name"; a bare name matches only
// when the package declares that name under exactly one scope. Entries that
// match nothing are rejected to catch typos early.
func checkCapabilities(next, old *manifest.Manifest, accepted []string) error {
	declared := make(map[manifest.CapabilityRef]struct{})
	scopes := make(map[string][]string)
	for _, c := range next.Capabilities {
		ref := manifest.CapabilityRef{Name: c.Name, Scope: c.Scope}
		if _, dup := declared[ref]; dup {
			continue
		}
		declared[ref] = struct{}{}
		scopes[c.Name] = append(scopes[c.Name], c.Scope)
	}
	granted := make(map[manifest.CapabilityRef]struct{}, len(accepted))
	for _, entry := range accepted {
		ref, err := resolveAccepted(entry, declared, scopes)
		if err != nil {
			return err
		}
		granted[ref] = struct{}{}
	}
	previous := make(map[manifest.CapabilityRef]struct{})
	if old != nil {
		for _, c := range old.Capabilities {
			previous[manifest.CapabilityRef{Name: c.Name, Scope: c.Scope}] = struct{}{}
		}
	}
	var missing []string
	for ref := range declared {
		if _, had := previous[ref]; had {
			continue
		}
		if _, ok := granted[ref]; !ok {
			missing = append(missing, ref.Name+":"+ref.Scope)
		}
	}
	if len(missing) == 0 {
		return nil
	}
	sort.Strings(missing)
	violations := make([]problem.Violation, 0, len(missing))
	for _, name := range missing {
		violations = append(violations, problem.Violation{
			Pointer: "/accepted_capabilities",
			Code:    "CAPABILITY_NOT_ACCEPTED",
			Message: fmt.Sprintf("The capability %q was not accepted.", name),
		})
	}
	return &problem.Error{
		Code:       problem.ValidationFailed,
		Detail:     "The new plugin version requests capabilities that were not accepted.",
		Violations: violations,
	}
}

// resolveAccepted maps one accepted entry onto a declared capability.
func resolveAccepted(entry string, declared map[manifest.CapabilityRef]struct{}, scopes map[string][]string) (manifest.CapabilityRef, error) {
	name, scope, scoped := strings.Cut(entry, ":")
	if !scoped {
		switch len(scopes[name]) {
		case 1:
			return manifest.CapabilityRef{Name: name, Scope: scopes[name][0]}, nil
		case 0:
		default:
			return manifest.CapabilityRef{}, problem.Validation(problem.Violation{
				Pointer: "/accepted_capabilities",
				Code:    "AMBIGUOUS_CAPABILITY",
				Message: fmt.Sprintf("The plugin declares %q under several scopes; accept each as \"name:scope\".", name),
			})
		}
	} else if ref := (manifest.CapabilityRef{Name: name, Scope: scope}); hasRef(declared, ref) {
		return ref, nil
	}
	return manifest.CapabilityRef{}, problem.Validation(problem.Violation{
		Pointer: "/accepted_capabilities",
		Code:    "UNKNOWN_CAPABILITY",
		Message: fmt.Sprintf("The plugin does not declare the capability %q.", entry),
	})
}

func hasRef(set map[manifest.CapabilityRef]struct{}, ref manifest.CapabilityRef) bool {
	_, ok := set[ref]
	return ok
}
