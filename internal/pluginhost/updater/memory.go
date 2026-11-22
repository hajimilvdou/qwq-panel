// SPDX-License-Identifier: AGPL-3.0-only

package updater

import (
	"context"
	"fmt"

	"github.com/qwq-panel/qwq/internal/platform/problem"
	"github.com/qwq-panel/qwq/sdk/manifest"
)

// memoryPlan is the preflight decision of ARCH §6.3 "小内存更新". The updater
// never chooses blue-green when the node cannot hold both processes: an OOM
// kill of the host or of the active plugin is worse than a short restart.
type memoryPlan struct {
	Strategy  Strategy
	Available uint64
	Current   uint64
	NewMax    uint64
	Reserve   uint64
	Reason    string
}

// planMemory decides the strategy. requested may be "" (auto), overlap or
// restart. The result is never overlap when the manifest declares
// lifecycle.overlap_safe=false, when memory cannot hold old and new together,
// or when the memory source cannot be read (conservative restart).
func (u *Updater) planMemory(ctx context.Context, pluginID string, m *manifest.Manifest, requested Strategy, hasOld bool) (memoryPlan, error) {
	if m == nil {
		return memoryPlan{}, problem.New(problem.Internal, "The plugin manifest of %s is missing.", pluginID)
	}
	maxMB := m.Resources.MemoryMaxMB
	if maxMB <= 0 {
		maxMB = defaultMemoryMaxMB
	}
	p := memoryPlan{
		NewMax:  uint64(maxMB) << 20,
		Reserve: u.opts.MemoryReserveBytes,
	}
	if hasOld {
		cur, err := u.mem.Current(pluginID)
		if err != nil {
			u.log.WarnContext(ctx, "plugin memory use unavailable; using restart", "plugin", pluginID, "err", err)
			p.Strategy, p.Reason = StrategyRestart, "memory use unavailable"
		} else {
			p.Current = cur
		}
	}
	avail, err := u.mem.Available()
	if err != nil {
		u.log.WarnContext(ctx, "node available memory unavailable; using restart", "plugin", pluginID, "err", err)
		p.Strategy, p.Reason = StrategyRestart, "available memory unavailable"
		return p, nil
	}
	p.Available = avail

	// --- 重启硬预算：Current 未知时按零计，不借用无法确认的内存 -------------------
	// 候选与宿主预留必须仍能容纳；溢出或预算不足都在外部副作用前拒绝。
	restartBudget, ok := addBytes(p.Available, p.Current)
	restartNeed, ok2 := addBytes(p.NewMax, p.Reserve)
	if !ok || !ok2 || restartBudget < restartNeed {
		return p, problem.New(problem.Unavailable,
			"The node does not have enough memory to start plugin %s version %s (needs %d bytes plus %d reserve).",
			pluginID, m.Version, p.NewMax, p.Reserve)
	}
	if p.Strategy == StrategyRestart {
		return p, nil
	}
	if !hasOld {
		p.Strategy = StrategyInstall
		return p, nil
	}
	if requested == StrategyRestart {
		p.Strategy, p.Reason = StrategyRestart, "requested"
		return p, nil
	}
	if u.opts.RestartOnly {
		p.Strategy, p.Reason = StrategyRestart, "the runtime is restart-only"
		return p, nil
	}
	if !m.Lifecycle.EffectiveOverlapSafe() {
		p.Strategy, p.Reason = StrategyRestart, "manifest overlap_safe=false"
		return p, nil
	}
	overlapNeed, ok := addBytes(p.Current, p.NewMax, p.Reserve)
	if !ok || p.Available < overlapNeed {
		p.Strategy, p.Reason = StrategyRestart, "not enough memory for blue-green"
		return p, nil
	}
	p.Strategy = StrategyOverlap
	return p, nil
}

// MemoryCurrent reports the cgroup memory use of a plugin instance, for the
// runtime block of the plugin DTO (GAPS gap 7). An unreadable source is an error
// the caller turns into "no memory reported" rather than a zero measurement.
func (u *Updater) MemoryCurrent(pluginID string) (uint64, error) {
	return u.mem.Current(pluginID)
}

// addBytes sums memory sizes and reports overflow. Manifests are bounded, but
// a bad MemorySource must not wrap the comparison into "enough".
func addBytes(values ...uint64) (uint64, bool) {
	var total uint64
	for _, v := range values {
		next := total + v
		if next < total {
			return 0, false
		}
		total = next
	}
	return total, true
}

// memoryReason is used by the report and logs; fmt keeps the reason visible in
// the error path without another exported type.
func (p memoryPlan) String() string {
	return fmt.Sprintf("strategy=%s available=%d current=%d new_max=%d reserve=%d reason=%s",
		p.Strategy, p.Available, p.Current, p.NewMax, p.Reserve, p.Reason)
}
