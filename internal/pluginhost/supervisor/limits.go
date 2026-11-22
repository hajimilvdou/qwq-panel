// SPDX-License-Identifier: AGPL-3.0-only

package supervisor

import "fmt"

const (
	// Memory and resource bounds mirror resources in
	// sdk/manifest/manifest.schema.json, so a manifest value the installer
	// accepted can never reach systemd as something else.
	minMemoryMaxMB     = 16
	maxMemoryMaxMB     = 65536
	maxCPUQuotaPercent = 100000
	maxTasksMax        = 4096
	minLimitNOFILE     = 16
	maxLimitNOFILE     = 65536

	// DefaultOOMScoreAdjust is the positive score of plugin units; the host runs
	// with a negative score so the kernel kills a plugin first (ARCH 6.3).
	DefaultOOMScoreAdjust = 500
)

// Limits are the resource expectations of one plugin unit (ARCH 6.3, ADR-0003
// section 7). internal/sandbox renders them into the unit drop-in (MemoryMax,
// MemoryHigh, CPUQuota, TasksMax, LimitNOFILE, OOMScoreAdjust) and into
// Environment=GOMEMLIMIT. The supervisor only derives and validates them: it
// never writes unit contents itself, and a value that fails Validate aborts the
// attach instead of reaching systemd.
type Limits struct {
	// MemoryMaxBytes is MemoryMax, from resources.memory_max_mb.
	MemoryMaxBytes int64
	// MemoryHighBytes is MemoryHigh, about 0.9 x MemoryMax.
	MemoryHighBytes int64
	// GOMEMLIMITBytes is the Go runtime soft limit for Environment=GOMEMLIMIT,
	// about 0.85 x MemoryMax (Go does not read the cgroup limit).
	GOMEMLIMITBytes int64
	// OOMScoreAdjust is the unit's positive OOM score.
	OOMScoreAdjust int
	// CPUQuotaPercent is CPUQuota in percent of one CPU, 0 when unconstrained.
	CPUQuotaPercent int
	// TasksMax is the cgroup pids limit, 0 when unconstrained.
	TasksMax int
	// LimitNOFILE is the open file limit, 0 when unconstrained.
	LimitNOFILE uint64
}

// UnitResources are the manifest resource values the supervisor validates. They
// mirror sdk/manifest.Resources without importing the SDK types into the
// supervisor: the host passes the numbers, the supervisor derives the rest.
type UnitResources struct {
	MemoryMaxMB     int64
	CPUQuotaPercent int64
	PIDsMax         int64
	FDsMax          int64
}

// LimitsFor derives the systemd limits from a manifest resources block:
// MemoryHigh = 0.9 x MemoryMax, GOMEMLIMIT = 0.85 x MemoryMax (ARCH 6.3).
func LimitsFor(r UnitResources) (Limits, error) {
	if r.MemoryMaxMB < minMemoryMaxMB || r.MemoryMaxMB > maxMemoryMaxMB {
		return Limits{}, fmt.Errorf("supervisor: memory_max_mb %d is outside %d..%d",
			r.MemoryMaxMB, minMemoryMaxMB, maxMemoryMaxMB)
	}
	maxBytes := r.MemoryMaxMB << 20
	limits := Limits{
		MemoryMaxBytes:  maxBytes,
		MemoryHighBytes: maxBytes / 10 * 9,
		GOMEMLIMITBytes: maxBytes / 20 * 17,
		OOMScoreAdjust:  DefaultOOMScoreAdjust,
		CPUQuotaPercent: int(r.CPUQuotaPercent),
		TasksMax:        int(r.PIDsMax),
	}
	if r.FDsMax > 0 {
		limits.LimitNOFILE = uint64(r.FDsMax)
	}
	if err := limits.Validate(); err != nil {
		return Limits{}, err
	}
	return limits, nil
}

// Validate checks that the limits are internally consistent and inside the
// bounds of the manifest schema. CPU, pids and file limits may be zero, which
// means "not constrained by this layer".
func (l Limits) Validate() error {
	if l.MemoryMaxBytes < minMemoryMaxMB<<20 || l.MemoryMaxBytes > maxMemoryMaxMB<<20 {
		return fmt.Errorf("supervisor: MemoryMax %d bytes is outside %d..%d MiB",
			l.MemoryMaxBytes, minMemoryMaxMB, maxMemoryMaxMB)
	}
	if l.MemoryHighBytes <= 0 || l.MemoryHighBytes > l.MemoryMaxBytes {
		return fmt.Errorf("supervisor: MemoryHigh %d bytes must be positive and not above MemoryMax %d",
			l.MemoryHighBytes, l.MemoryMaxBytes)
	}
	if l.GOMEMLIMITBytes <= 0 || l.GOMEMLIMITBytes > l.MemoryMaxBytes {
		return fmt.Errorf("supervisor: GOMEMLIMIT %d bytes must be positive and not above MemoryMax %d",
			l.GOMEMLIMITBytes, l.MemoryMaxBytes)
	}
	if l.OOMScoreAdjust < 0 || l.OOMScoreAdjust > 1000 {
		return fmt.Errorf("supervisor: OOMScoreAdjust %d is outside 0..1000", l.OOMScoreAdjust)
	}
	if l.CPUQuotaPercent < 0 || l.CPUQuotaPercent > maxCPUQuotaPercent {
		return fmt.Errorf("supervisor: CPUQuota %d%% is outside 0..%d", l.CPUQuotaPercent, maxCPUQuotaPercent)
	}
	if l.TasksMax < 0 || l.TasksMax > maxTasksMax {
		return fmt.Errorf("supervisor: TasksMax %d is outside 0..%d", l.TasksMax, maxTasksMax)
	}
	if l.LimitNOFILE != 0 && (l.LimitNOFILE < minLimitNOFILE || l.LimitNOFILE > maxLimitNOFILE) {
		return fmt.Errorf("supervisor: LimitNOFILE %d is outside %d..%d", l.LimitNOFILE, minLimitNOFILE, maxLimitNOFILE)
	}
	return nil
}
