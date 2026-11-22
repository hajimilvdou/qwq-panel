// SPDX-License-Identifier: AGPL-3.0-only

package updater

import (
	"testing"

	"github.com/qwq-panel/qwq/internal/platform/problem"
)

// ======================== Current 未知也必须经过硬预算 ========================

func TestMemoryReadFailureStillChecksBudget(t *testing.T) {
	for _, test := range []struct {
		name      string
		available uint64
		refused   bool
	}{
		{name: "low", available: 10 << 20, refused: true},
		{name: "enough", available: 256 << 20},
	} {
		t.Run(test.name, func(t *testing.T) {
			e := newEnv(t)
			e.mustInstallV1("acme.demo")
			e.ins.add("pkg/v2.pkg", defaultPkg("acme.demo", "2.0.0"))
			e.mem.mu.Lock()
			e.mem.avail, e.mem.curErr = test.available, errBoom
			e.mem.mu.Unlock()
			_, _, before := e.ins.counts()
			result, err := e.u.Update(t.Context(), UpdateRequest{PluginID: "acme.demo", PackagePath: "pkg/v2.pkg", Strategy: StrategyOverlap})
			if test.refused {
				if !problem.HasCode(err, problem.Unavailable) {
					t.Errorf("Current failure bypassed the low memory budget: %v", err)
				}
				versions, verr := e.u.Versions("acme.demo")
				_, _, after := e.ins.counts()
				if verr != nil || len(versions) != 1 || len(before) != len(after) || e.runningSagaCount() != 0 || e.rt.count("Start") != 1 {
					t.Fatal("refused memory preflight changed unit, saga, version or runtime state")
				}
				e.requireActive("acme.demo", "1.0.0")
				return
			}
			if err != nil || result == nil || result.Strategy != StrategyRestart || !result.Restarted {
				t.Fatalf("unknown Current must use a budgeted restart: result=%v error=%v", result, err)
			}
			e.requireActive("acme.demo", "2.0.0")
		})
	}
}
