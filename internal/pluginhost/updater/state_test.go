// SPDX-License-Identifier: AGPL-3.0-only

package updater

import (
	"testing"

	"github.com/qwq-panel/qwq/internal/platform/problem"
)

// TestSetEnabledGatesEveryStart (GAPS gap 7): the flag is persistent and
// EnsureActive — the only place a unit is started — refuses a disabled plugin,
// so a dispatch, a recovery or a rollback cannot bring it back.
func TestSetEnabledGatesEveryStart(t *testing.T) {
	e := newEnv(t)
	e.mustInstallV1("acme.demo")
	ctx := e.t.Context()
	if on, err := e.u.Enabled(ctx, "acme.demo"); err != nil || !on {
		t.Fatalf("a plugin without a state row must be enabled: %v, %v", on, err)
	}
	if err := e.u.SetEnabled(ctx, "acme.demo", false); err != nil {
		t.Fatalf("disable: %v", err)
	}
	if on, err := e.u.Enabled(ctx, "acme.demo"); err != nil || on {
		t.Fatalf("enabled = %v, %v; want false", on, err)
	}
	if err := e.u.EnsureActive(ctx, "acme.demo"); !problem.HasCode(err, problem.PluginUnavailable) {
		t.Fatalf("EnsureActive on a disabled plugin = %v, want PLUGIN_UNAVAILABLE", err)
	}
	// The flag is a row, not memory: a second reader sees it too.
	if on, err := e.u.Enabled(ctx, "acme.demo"); err != nil || on {
		t.Fatalf("enabled after re-read = %v, %v", on, err)
	}
	if err := e.u.SetEnabled(ctx, "acme.demo", true); err != nil {
		t.Fatalf("enable: %v", err)
	}
	if err := e.u.EnsureActive(ctx, "acme.demo"); err != nil {
		t.Fatalf("EnsureActive after enable: %v", err)
	}
}

// TestSetEnabledUnknownPlugin: enablement of a plugin with no active version is
// NOT_FOUND, not a silent row.
func TestSetEnabledUnknownPlugin(t *testing.T) {
	e := newEnv(t)
	if err := e.u.SetEnabled(e.t.Context(), "acme.absent", false); !problem.HasCode(err, problem.NotFound) {
		t.Fatalf("SetEnabled = %v, want NOT_FOUND", err)
	}
}
