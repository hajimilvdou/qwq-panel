// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"strings"
	"testing"

	"github.com/qwq-panel/qwq/internal/doctor"
)

// polkit only decides for an unprivileged controller. A root one (development,
// tests) manages units directly, so an unusable polkit must not refuse its
// installs, while every other failed check still does (PRIV-06).
func TestPreflightFailures(t *testing.T) {
	rs := []doctor.Result{
		{ID: "sandbox-systemd", Status: doctor.OK, Detail: "systemd 249"},
		{ID: doctor.SandboxPolkitID, Status: doctor.Fail, Detail: "polkit 0.105 reads no JavaScript rules"},
		{ID: "sandbox-cgroup", Status: doctor.Fail, Detail: "cgroup v2 unified hierarchy not mounted"},
		{ID: "sandbox-exposure", Status: doctor.Warn, Detail: "1.4 (limit 1.0)"},
	}

	got := preflightFailures(rs, false)
	if len(got) != 2 || !strings.HasPrefix(got[0], doctor.SandboxPolkitID+": polkit 0.105") ||
		!strings.HasPrefix(got[1], "sandbox-cgroup: ") {
		t.Errorf("unprivileged controller: %q", got)
	}

	got = preflightFailures(rs, true)
	if len(got) != 1 || !strings.HasPrefix(got[0], "sandbox-cgroup: ") {
		t.Errorf("root controller: %q", got)
	}

	if got := preflightFailures(rs[:1], false); got != nil {
		t.Errorf("healthy host: %q", got)
	}
}
