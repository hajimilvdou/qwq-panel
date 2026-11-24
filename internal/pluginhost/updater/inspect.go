// SPDX-License-Identifier: AGPL-3.0-only

package updater

import (
	"context"
	"errors"
	"fmt"

	"github.com/qwq-panel/qwq/internal/platform/problem"
	"github.com/qwq-panel/qwq/sdk/manifest"
)

// Inspection is the pre-install view of one staged package (GAPS gap 4). It
// runs the same checks the install saga runs before it writes anything, but
// reports their outcome instead of refusing: the API renders it to the user
// before a grant is asked for.
type Inspection struct {
	// PluginID and Version come from the strictly parsed manifest; empty when
	// the package was not parseable (only a signature-class refusal can come
	// back without a manifest).
	PluginID string
	Version  string
	// Manifest is the strictly parsed manifest, nil when the package was not
	// parseable.
	Manifest *manifest.Manifest
	// Signature is the verdict of the install-time key verification.
	Signature InspectionSignature
	// Problems are the field violations an install would refuse with, beyond
	// the signature verdict (schema version, extraction policy).
	Problems []problem.Violation
	// UnpackedBytes is the verified content size of the package; 0 when
	// unknown. It drives the disk capacity check.
	UnpackedBytes int64
	// Memory is the memory capacity check of the install preflight.
	Memory InspectionMemory
	// Installed names the active version when the same plugin is installed:
	// the package is an update, not a fresh install.
	Installed *InspectionInstalled
}

// InspectionSignature is the signature verdict of an Inspection.
type InspectionSignature struct {
	// Valid accepts the package: the key verifies the envelope over the
	// manifest bytes and the publisher binding holds.
	Valid bool
	// Trusted reports whether the signing key is in the host's trust root. A
	// package can be trusted but invalid (tampered after signing) and valid
	// but untrusted (signed by an unknown key) — neither installs.
	Trusted bool
	// KeyID is the signing key id from the signature envelope, "" when the
	// package carries no signature.
	KeyID string
}

// InspectionMemory is the memory preflight of one package.
type InspectionMemory struct {
	// RequiredBytes is the plugin's MemoryMax, or the host default.
	RequiredBytes uint64
	// AvailableBytes is the node's available memory; 0 when unreadable.
	AvailableBytes uint64
	// OK reports that the node can start the candidate, including the
	// host's memory reserve. When the memory source is unreadable it is true:
	// the install preflight conservatively proceeds and lets the start fail.
	OK bool
}

// InspectionInstalled is the active version of an already installed plugin.
type InspectionInstalled struct {
	Version  string
	Revision int64
}

// Inspect verifies and parses a staged package without installing it (GAPS
// gap 4). Parsing reuses the install saga's own checks: the installer's
// verification and extraction, the schema version gate and the memory
// preflight. A signature- or policy-class refusal is reported in the
// returned Inspection, not as an error; an unparseable container is an error.
func (u *Updater) Inspect(ctx context.Context, pkgPath string) (*Inspection, error) {
	if pkgPath == "" {
		return nil, problem.Validation(problem.Violation{
			Pointer: "/package_path", Code: "REQUIRED", Message: "A package path is required.",
		})
	}
	ctx, cancel := u.withTimeout(ctx, 0)
	defer cancel()

	verdict, err := u.install.Inspect(ctx, pkgPath)
	if err != nil {
		return nil, stageProblem(err)
	}
	if verdict.Staged != nil {
		defer func() { _ = verdict.Staged.DiscardStaged() }()
	}
	insp := &Inspection{
		Manifest:  verdict.Manifest,
		Signature: InspectionSignature{Valid: verdict.Valid, Trusted: verdict.Trusted, KeyID: verdict.KeyID},
		Problems:  verdict.Problems,
	}
	insp.UnpackedBytes = verdict.UnpackedBytes
	if m := verdict.Manifest; m != nil {
		insp.PluginID, insp.Version = m.ID, m.Version
		if err := checkSchemaVersion(m); err != nil {
			insp.Problems = append(insp.Problems, violationsOf(err)...)
		}
		if active, ok := u.Active(m.ID); ok {
			insp.Installed = &InspectionInstalled{Version: active.Version, Revision: active.Revision}
		}
		// The same memory preflight as Install, in its restart form (the
		// production unit is per plugin): memory.ok is false exactly when an
		// install would be refused for memory.
		plan, perr := u.planMemory(ctx, m.ID, m, StrategyRestart, insp.Installed != nil)
		required, ok := addBytes(plan.NewMax, plan.Reserve)
		if !ok {
			required = plan.NewMax
		}
		insp.Memory = InspectionMemory{
			RequiredBytes:  required,
			AvailableBytes: plan.Available,
			OK:             perr == nil,
		}
	}
	return insp, nil
}

// violationsOf extracts the field violations of a problem error. A problem
// without violations keeps a single synthetic one so nothing is lost.
func violationsOf(err error) []problem.Violation {
	var pe *problem.Error
	if errors.As(err, &pe) && len(pe.Violations) > 0 {
		return pe.Violations
	}
	return []problem.Violation{{Pointer: "", Code: "REFUSED", Message: fmt.Sprint(err)}}
}
