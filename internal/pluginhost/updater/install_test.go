// SPDX-License-Identifier: AGPL-3.0-only

package updater

import (
	"encoding/json"
	"testing"

	"github.com/qwq-panel/qwq/internal/platform/problem"
	"github.com/qwq-panel/qwq/sdk/manifest"
)

func TestInstallHappyPath(t *testing.T) {
	e := newEnv(t)
	v := e.mustInstallV1("acme.demo")
	if v.Version != "1.0.0" || v.Status != VersionActive || !v.Active {
		t.Fatalf("unexpected installed version: %+v", v)
	}
	if v.InstallStatus != InstallInstalled || v.Digest == "" || v.Manifest == nil {
		t.Fatalf("install metadata incomplete: %+v", v)
	}
	if v.InstalledAt.IsZero() || v.ActivatedAt.IsZero() || v.Revision == 0 {
		t.Fatalf("install timestamps or revision missing: %+v", v)
	}
	active, ok := e.u.Active("acme.demo")
	if !ok || active.Version != "1.0.0" || !active.Active {
		t.Fatalf("Active() = %+v, %v", active, ok)
	}
	route, ok := e.u.Routes().Lookup("acme.demo")
	if !ok || route.Version != "1.0.0" {
		t.Fatalf("Routes() = %+v, %v", route, ok)
	}
	if got := e.rt.activations("acme.demo", "1.0.0"); got != 1 {
		t.Fatalf("Activate calls = %d, want 1", got)
	}
	if got := e.rt.deactivations("acme.demo", "1.0.0"); got != 0 {
		t.Fatalf("Deactivate calls = %d, want 0", got)
	}
	calls := e.rt.callList()
	start := findCall(t, calls, "Start|acme.demo@1.0.0")
	activate := findCall(t, calls, "Activate|acme.demo@1.0.0")
	swap := lastCall(t, calls, "SwapRoutes|")
	if !(start < swap && swap < activate) {
		t.Fatalf("order should be start, swap, activate: %v", calls)
	}
	sagas := e.sagasFor("acme.demo")
	if len(sagas) != 1 || sagas[0].State != SagaCommitted || sagas[0].Mode != modeInstall {
		t.Fatalf("saga = %+v", sagas)
	}
	if got := e.runningSagaCount(); got != 0 {
		t.Fatalf("running sagas = %d", got)
	}
}

func TestInstallCapabilityRejected(t *testing.T) {
	e := newEnv(t)
	spec := defaultPkg("cap.plugin", "1.0.0")
	spec.Caps = []manifest.Capability{{Name: "fs.write", Scope: "/data", Reason: "needed"}}
	e.ins.add("pkg/cap.pkg", spec)
	_, err := e.u.Install(e.ctx(), InstallRequest{PackagePath: "pkg/cap.pkg"})
	requireProblem(t, err, problem.ValidationFailed)
	pe := problem.From(err)
	if len(pe.Violations) != 1 || pe.Violations[0].Pointer != "/accepted_capabilities" {
		t.Fatalf("violations = %+v", pe.Violations)
	}
	versions, verr := e.u.Versions("cap.plugin")
	if verr != nil {
		t.Fatal(verr)
	}
	if len(versions) != 0 {
		t.Fatalf("rejected install left versions: %+v", versions)
	}
	if _, _, installs := e.ins.counts(); len(installs) != 0 {
		t.Fatalf("InstallUnit ran for a rejected install: %v", installs)
	}
	e.ins.mu.Lock()
	discarded := e.ins.discarded
	e.ins.mu.Unlock()
	if discarded != 1 {
		t.Fatalf("discarded = %d, want 1", discarded)
	}
	if e.rt.count("Start") != 0 {
		t.Fatalf("runtime started a rejected install: %v", e.rt.callList())
	}
}

func TestInstallRejectsManifestMismatch(t *testing.T) {
	e := newEnv(t)
	e.ins.add("pkg/x.pkg", defaultPkg("acme.demo", "1.0.0"))
	_, err := e.u.Install(e.ctx(), InstallRequest{PackagePath: "pkg/x.pkg", PluginID: "other.plugin"})
	requireProblem(t, err, problem.ValidationFailed)
	if e.rt.count("Start") != 0 {
		t.Fatal("runtime started a mismatched manifest")
	}
}

func TestInstallMemoryUnavailable(t *testing.T) {
	e := newEnv(t)
	e.mem.set(10<<20, "", 0) // less than 48 MiB + reserve
	spec := defaultPkg("acme.demo", "1.0.0")
	e.ins.add("pkg/mem.pkg", spec)
	_, err := e.u.Install(e.ctx(), InstallRequest{PackagePath: "pkg/mem.pkg"})
	requireProblem(t, err, problem.Unavailable)
	if versions, _ := e.u.Versions("acme.demo"); len(versions) != 0 {
		t.Fatalf("versions after refused install: %+v", versions)
	}
}

func TestInstallNilRuntimeDeps(t *testing.T) {
	e := newEnv(t)
	if _, err := New(Options{DB: e.db}); err == nil {
		t.Fatal("New accepted missing runtime dependencies")
	}
}

// TestVersionJsonRoundTrip makes sure a Version stays encodable for the API.
func TestVersionJSON(t *testing.T) {
	e := newEnv(t)
	v := e.mustInstallV1("acme.demo")
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) == 0 {
		t.Fatal("empty JSON")
	}
}
