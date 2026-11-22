// SPDX-License-Identifier: AGPL-3.0-only

package supervisor

import (
	"testing"
)

func TestLimitsFor(t *testing.T) {
	limits, err := LimitsFor(UnitResources{MemoryMaxMB: 64, CPUQuotaPercent: 150, PIDsMax: 64, FDsMax: 1024})
	if err != nil {
		t.Fatalf("LimitsFor: %v", err)
	}
	if limits.MemoryMaxBytes != 64<<20 {
		t.Fatalf("MemoryMax = %d, want %d", limits.MemoryMaxBytes, int64(64)<<20)
	}
	// ARCH 6.3: MemoryHigh is about 0.9x MemoryMax and GOMEMLIMIT about 0.85x.
	if limits.MemoryHighBytes < limits.MemoryMaxBytes/100*89 || limits.MemoryHighBytes > limits.MemoryMaxBytes/100*91 {
		t.Fatalf("MemoryHigh = %d, want about 90%% of %d", limits.MemoryHighBytes, limits.MemoryMaxBytes)
	}
	if limits.GOMEMLIMITBytes < limits.MemoryMaxBytes/100*84 || limits.GOMEMLIMITBytes > limits.MemoryMaxBytes/100*86 {
		t.Fatalf("GOMEMLIMIT = %d, want about 85%% of %d", limits.GOMEMLIMITBytes, limits.MemoryMaxBytes)
	}
	if limits.OOMScoreAdjust != DefaultOOMScoreAdjust {
		t.Fatalf("OOMScoreAdjust = %d, want %d", limits.OOMScoreAdjust, DefaultOOMScoreAdjust)
	}
	if limits.CPUQuotaPercent != 150 || limits.TasksMax != 64 || limits.LimitNOFILE != 1024 {
		t.Fatalf("limits = %+v", limits)
	}
	if err := limits.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

func TestLimitsForRejectsOutOfRangeResources(t *testing.T) {
	cases := []UnitResources{
		{MemoryMaxMB: 8},
		{MemoryMaxMB: 70000},
		{MemoryMaxMB: 64, CPUQuotaPercent: maxCPUQuotaPercent + 1},
		{MemoryMaxMB: 64, PIDsMax: maxTasksMax + 1},
		{MemoryMaxMB: 64, FDsMax: 8},
	}
	for _, r := range cases {
		if _, err := LimitsFor(r); err == nil {
			t.Errorf("LimitsFor(%+v) accepted an out-of-range resource", r)
		}
	}
}

func TestLimitsValidate(t *testing.T) {
	base := func() Limits {
		l, err := LimitsFor(UnitResources{MemoryMaxMB: 64, CPUQuotaPercent: 100, PIDsMax: 32, FDsMax: 256})
		if err != nil {
			t.Fatalf("LimitsFor: %v", err)
		}
		return l
	}
	cases := map[string]func(*Limits){
		"zero MemoryMax":     func(l *Limits) { l.MemoryMaxBytes = 0 },
		"MemoryHigh too big": func(l *Limits) { l.MemoryHighBytes = l.MemoryMaxBytes + 1 },
		"zero MemoryHigh":    func(l *Limits) { l.MemoryHighBytes = 0 },
		"zero GOMEMLIMIT":    func(l *Limits) { l.GOMEMLIMITBytes = 0 },
		"negative OOM":       func(l *Limits) { l.OOMScoreAdjust = -1 },
		"OOM too big":        func(l *Limits) { l.OOMScoreAdjust = 1001 },
		"CPU too big":        func(l *Limits) { l.CPUQuotaPercent = maxCPUQuotaPercent + 1 },
		"Tasks too big":      func(l *Limits) { l.TasksMax = maxTasksMax + 1 },
		"NOFILE too small":   func(l *Limits) { l.LimitNOFILE = 1 },
	}
	for name, mutate := range cases {
		limits := base()
		mutate(&limits)
		if err := limits.Validate(); err == nil {
			t.Errorf("%s: Validate accepted %+v", name, limits)
		}
	}
}

func TestLimitsAllowUnconstrainedCPUAndPIDs(t *testing.T) {
	limits, err := LimitsFor(UnitResources{MemoryMaxMB: 32})
	if err != nil {
		t.Fatalf("LimitsFor: %v", err)
	}
	if limits.CPUQuotaPercent != 0 || limits.TasksMax != 0 || limits.LimitNOFILE != 0 {
		t.Fatalf("limits = %+v, want unconstrained CPU/pids/fds", limits)
	}
	if err := limits.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}
