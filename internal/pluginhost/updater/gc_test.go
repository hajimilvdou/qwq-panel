// SPDX-License-Identifier: AGPL-3.0-only

package updater

import (
	"testing"
	"time"
)

func TestSelectObsoletePluginVersionsToPrune(t *testing.T) {
	base := time.Date(2026, 11, 24, 0, 0, 0, 0, time.UTC)
	pruned := SelectObsoletePluginVersionsToPrune([]RetainedPluginVersion{
		{Version: "1.0.0", Active: false, InstalledAt: base},
		{Version: "1.1.0", Active: false, InstalledAt: base.Add(time.Hour)},
		{Version: "1.2.0", Active: false, InstalledAt: base.Add(2 * time.Hour)},
		{Version: "1.3.0", Active: true, InstalledAt: base.Add(3 * time.Hour)},
	}, 1)
	if len(pruned) != 2 || pruned[0] != "1.1.0" || pruned[1] != "1.0.0" {
		t.Fatalf("pruned = %v, want [1.1.0 1.0.0]", pruned)
	}
}

func TestUpdatePrunesObsoleteThirdVersionAfterCommit(t *testing.T) {
	e := newEnv(t)
	e.mustInstallV1("acme.demo")
	e.clk.Advance(time.Minute)
	e.ins.add("pkg/v2.pkg", defaultPkg("acme.demo", "2.0.0"))
	if _, err := e.u.Update(e.ctx(), UpdateRequest{PluginID: "acme.demo", PackagePath: "pkg/v2.pkg"}); err != nil {
		t.Fatalf("Update v2: %v", err)
	}
	e.clk.Advance(time.Minute)
	e.ins.add("pkg/v3.pkg", defaultPkg("acme.demo", "3.0.0"))
	if _, err := e.u.Update(e.ctx(), UpdateRequest{PluginID: "acme.demo", PackagePath: "pkg/v3.pkg"}); err != nil {
		t.Fatalf("Update v3: %v", err)
	}
	e.requireActive("acme.demo", "3.0.0")
	vers, err := e.u.Versions("acme.demo")
	if err != nil {
		t.Fatalf("Versions: %v", err)
	}
	if len(vers) != 2 {
		t.Fatalf("expected active + 1 rollback version retained (2 total), got %d: %+v", len(vers), vers)
	}
	removed := e.ins.removedCopy()
	foundPrune := false
	for _, r := range removed {
		if r == "prune|acme.demo@1.0.0" {
			foundPrune = true
		}
	}
	if !foundPrune {
		t.Fatalf("expected 1.0.0 pruned, got removed=%v", removed)
	}
}
