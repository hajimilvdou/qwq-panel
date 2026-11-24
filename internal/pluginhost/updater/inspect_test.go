// SPDX-License-Identifier: AGPL-3.0-only

package updater

import (
	"errors"
	"testing"

	"github.com/qwq-panel/qwq/internal/platform/problem"
	"github.com/qwq-panel/qwq/sdk/manifest"
)

// TestInspectPackageFacts: a verified package comes back with its identity,
// signature verdict, unpacked size and memory preflight; nothing is installed
// and the staging directory of the verification is released (GAPS gap 4).
func TestInspectPackageFacts(t *testing.T) {
	e := newEnv(t)
	spec := defaultPkg("acme.demo", "1.0.0")
	spec.UnpackedBytes = 3 << 20
	spec.Caps = []manifest.Capability{{Name: "net.connect", Scope: "outbound", Reason: "needed"}}
	e.ins.add("pkg/demo.pkg", spec)

	insp, err := e.u.Inspect(e.ctx(), "pkg/demo.pkg")
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if insp.PluginID != "acme.demo" || insp.Version != "1.0.0" || insp.Manifest == nil {
		t.Fatalf("identity = %+v", insp)
	}
	if !insp.Signature.Valid || !insp.Signature.Trusted || insp.Signature.KeyID == "" {
		t.Fatalf("signature = %+v", insp.Signature)
	}
	if insp.UnpackedBytes != 3<<20 {
		t.Fatalf("unpacked = %d", insp.UnpackedBytes)
	}
	if insp.Installed != nil {
		t.Fatalf("installed = %+v, want nil for a fresh package", insp.Installed)
	}
	if len(insp.Problems) != 0 {
		t.Fatalf("problems = %+v", insp.Problems)
	}
	if !insp.Memory.OK || insp.Memory.RequiredBytes != (48<<20)+defaultMemoryReserve || insp.Memory.AvailableBytes != 4<<30 {
		t.Fatalf("memory = %+v", insp.Memory)
	}
	// The verification staged and released its private directory.
	e.ins.mu.Lock()
	discarded := e.ins.discarded
	e.ins.mu.Unlock()
	if discarded != 1 {
		t.Fatalf("discarded = %d, want 1", discarded)
	}
	if versions, verr := e.u.Versions("acme.demo"); verr != nil || len(versions) != 0 {
		t.Fatalf("inspection changed version rows: %+v, %v", versions, verr)
	}
}

// TestInspectReportsSignatureRefusal: a package the installer refuses on
// signature-class grounds is reported, not returned as an error; the manifest
// and memory preflight are still there.
func TestInspectReportsSignatureRefusal(t *testing.T) {
	e := newEnv(t)
	m := &manifest.Manifest{
		SchemaVersion: "1.2", ID: "acme.demo", Version: "1.0.0",
		Name: "Demo", Summary: "demo", Publisher: manifest.Publisher{ID: "acme", KeyID: "ed25519:" + hex64()},
		Resources: manifest.Resources{MemoryMaxMB: 48},
	}
	e.ins.inspectVerdict = &InspectionVerdict{
		Manifest: m, Valid: false, Trusted: false,
		KeyID: "ed25519:" + hex64(), UnpackedBytes: 1 << 20,
	}

	insp, err := e.u.Inspect(e.ctx(), "pkg/untrusted.pkg")
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if insp.Signature.Valid || insp.Signature.Trusted {
		t.Fatalf("signature = %+v, want refused", insp.Signature)
	}
	if insp.Manifest == nil || insp.PluginID != "acme.demo" {
		t.Fatalf("manifest = %+v", insp.Manifest)
	}
	if insp.UnpackedBytes != 1<<20 {
		t.Fatalf("unpacked = %d", insp.UnpackedBytes)
	}
	if !insp.Memory.OK {
		t.Fatalf("memory = %+v, want the preflight to run regardless", insp.Memory)
	}
}

// TestInspectSchemaVersionProblem: a package older than the install minimum
// carries the install's own field violation (SCHEMA_VERSION_TOO_OLD).
func TestInspectSchemaVersionProblem(t *testing.T) {
	e := newEnv(t)
	spec := defaultPkg("old.demo", "1.0.0")
	spec.SchemaVersion = "1.1"
	e.ins.add("pkg/old.pkg", spec)

	insp, err := e.u.Inspect(e.ctx(), "pkg/old.pkg")
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if len(insp.Problems) != 1 || insp.Problems[0].Code != "SCHEMA_VERSION_TOO_OLD" {
		t.Fatalf("problems = %+v", insp.Problems)
	}
}

// TestInspectInstalledUpdate: inspecting a package of an installed plugin
// names the active version, so the caller knows it is an update.
func TestInspectInstalledUpdate(t *testing.T) {
	e := newEnv(t)
	v := e.mustInstallV1("acme.demo")
	spec := defaultPkg("acme.demo", "1.1.0")
	e.ins.add("pkg/up.pkg", spec)

	insp, err := e.u.Inspect(e.ctx(), "pkg/up.pkg")
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if insp.Installed == nil || insp.Installed.Version != "1.0.0" || insp.Installed.Revision != v.Revision {
		t.Fatalf("installed = %+v, want 1.0.0@%d", insp.Installed, v.Revision)
	}
}

// TestInspectMemoryInsufficient: memory.ok is false exactly when the install
// preflight would refuse to start the candidate.
func TestInspectMemoryInsufficient(t *testing.T) {
	e := newEnv(t)
	e.mem.set(32<<20, "", 0)
	spec := defaultPkg("big.demo", "1.0.0")
	spec.MemoryMB = 512
	e.ins.add("pkg/big.pkg", spec)

	insp, err := e.u.Inspect(e.ctx(), "pkg/big.pkg")
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if insp.Memory.OK || insp.Memory.RequiredBytes != (512<<20)+defaultMemoryReserve || insp.Memory.AvailableBytes != 32<<20 {
		t.Fatalf("memory = %+v", insp.Memory)
	}
}

// TestInspectErrors: an empty path is a validation problem and an unparseable
// container keeps the installer's error mapping.
func TestInspectErrors(t *testing.T) {
	e := newEnv(t)
	if _, err := e.u.Inspect(e.ctx(), ""); !problem.HasCode(err, problem.ValidationFailed) {
		t.Fatalf("Inspect(empty) = %v, want VALIDATION_FAILED", err)
	}
	e.ins.inspectErr = errors.New("container is not a package")
	if _, err := e.u.Inspect(e.ctx(), "pkg/broken.pkg"); !problem.HasCode(err, problem.Internal) {
		t.Fatalf("Inspect(broken) = %v, want INTERNAL", err)
	}
}

// hex64 returns a 64-character hex string for fake key ids.
func hex64() string {
	return "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
}
