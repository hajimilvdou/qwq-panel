// SPDX-License-Identifier: AGPL-3.0-only

package updater

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/qwq-panel/qwq/internal/platform/problem"
)

func TestApplyConfigSuccess(t *testing.T) {
	e := newEnv(t)
	e.mustInstallV1("acme.demo")

	first, err := e.u.ApplyConfig(e.ctx(), ConfigRequest{
		PluginID: "acme.demo",
		Config:   json.RawMessage(`{"interval":60}`),
	})
	if err != nil {
		t.Fatalf("ApplyConfig: %v", err)
	}
	if first.Revision != 1 || !first.Active || first.AppliedAt.IsZero() || first.Seq == 0 {
		t.Fatalf("first revision = %+v", first)
	}
	active, ok := e.u.ActiveConfig("acme.demo")
	if !ok || active.Revision != 1 || string(active.Config) != `{"interval":60}` {
		t.Fatalf("ActiveConfig = %+v, %v", active, ok)
	}
	if got := e.rt.appliedConfig("acme.demo", "1.0.0"); got != 1 {
		t.Fatalf("plugin applied revision = %d, want 1", got)
	}

	second, err := e.u.ApplyConfig(e.ctx(), ConfigRequest{
		PluginID:         "acme.demo",
		Config:           json.RawMessage(`{"interval":30}`),
		ExpectedRevision: 1,
	})
	if err != nil {
		t.Fatalf("second ApplyConfig: %v", err)
	}
	if second.Revision != 2 || !second.Active {
		t.Fatalf("second revision = %+v", second)
	}
	if got := e.rt.appliedConfig("acme.demo", "1.0.0"); got != 2 {
		t.Fatalf("plugin applied revision = %d, want 2", got)
	}
	old, err := e.u.loadConfig(e.ctx(), "acme.demo", 1)
	if err != nil {
		t.Fatal(err)
	}
	if old.Active {
		t.Fatalf("old revision is still active: %+v", old)
	}
	e.reopen()
	reloaded, ok := e.u.ActiveConfig("acme.demo")
	if !ok || reloaded.Revision != 2 || !reloaded.Active {
		t.Fatalf("ActiveConfig after reopen = %+v, %v", reloaded, ok)
	}
}

func TestApplyConfigValidationFailureKeepsOld(t *testing.T) {
	e := newEnv(t)
	e.mustInstallV1("acme.demo")
	if _, err := e.u.ApplyConfig(e.ctx(), ConfigRequest{
		PluginID: "acme.demo", Config: json.RawMessage(`{"interval":60}`),
	}); err != nil {
		t.Fatalf("ApplyConfig: %v", err)
	}

	fieldErr := &problem.Error{
		Code:   problem.ValidationFailed,
		Detail: "interval is too small",
		Violations: []problem.Violation{
			{Pointer: "/interval", Code: "MINIMUM", Message: "must be at least 30"},
		},
	}
	e.rt.setFail("ValidateConfig", "acme.demo", "1.0.0", fieldErr)
	applyCallsBefore := e.rt.count("ApplyConfig")

	_, err := e.u.ApplyConfig(e.ctx(), ConfigRequest{
		PluginID: "acme.demo", Config: json.RawMessage(`{"interval":1}`), ExpectedRevision: 1,
	})
	requireProblem(t, err, problem.ValidationFailed)
	pe := problem.From(err)
	if len(pe.Violations) != 1 || pe.Violations[0].Pointer != "/interval" {
		t.Fatalf("field-level violations lost: %+v", pe.Violations)
	}
	if got := e.activeConfigRevision("acme.demo"); got != 1 {
		t.Fatalf("active revision = %d, want 1", got)
	}
	if got := e.rt.count("ApplyConfig"); got != applyCallsBefore {
		t.Fatal("ApplyConfig was called after ValidateConfig failed")
	}
	candidate, err := e.u.loadConfig(e.ctx(), "acme.demo", 2)
	if err != nil {
		t.Fatal(err)
	}
	if candidate.Active {
		t.Fatalf("rejected candidate is active: %+v", candidate)
	}
	if got := e.rt.appliedConfig("acme.demo", "1.0.0"); got != 1 {
		t.Fatalf("plugin applied revision = %d, want 1", got)
	}
}

func TestApplyConfigApplyFailureKeepsOld(t *testing.T) {
	e := newEnv(t)
	e.mustInstallV1("acme.demo")
	e.rt.setFail("ApplyConfig", "acme.demo", "1.0.0", errBoom)

	_, err := e.u.ApplyConfig(e.ctx(), ConfigRequest{
		PluginID: "acme.demo", Config: json.RawMessage(`{"interval":60}`),
	})
	requireProblem(t, err, problem.PluginError)
	if _, ok := e.u.ActiveConfig("acme.demo"); ok {
		t.Fatal("a failed first apply activated a revision")
	}
	if got := e.activeConfigRevision("acme.demo"); got != 0 {
		t.Fatalf("active revision = %d, want 0", got)
	}
	candidate, err := e.u.loadConfig(e.ctx(), "acme.demo", 1)
	if err != nil {
		t.Fatal(err)
	}
	if candidate.Active || candidate.AppliedAt != (time.Time{}) {
		t.Fatalf("candidate = %+v", candidate)
	}
}

func TestApplyConfigExpectedRevision(t *testing.T) {
	e := newEnv(t)
	e.mustInstallV1("acme.demo")

	_, err := e.u.ApplyConfig(e.ctx(), ConfigRequest{
		PluginID: "acme.demo", Config: json.RawMessage(`{}`), ExpectedRevision: 7,
	})
	requireProblem(t, err, problem.RevisionConflict)
	if got := problem.From(err).CurrentRevision; got != "0" {
		t.Fatalf("CurrentRevision = %q, want 0", got)
	}
	if _, err := e.u.ApplyConfig(e.ctx(), ConfigRequest{
		PluginID: "acme.demo", Config: json.RawMessage(`{}`),
	}); err != nil {
		t.Fatal(err)
	}
	_, err = e.u.ApplyConfig(e.ctx(), ConfigRequest{
		PluginID: "acme.demo", Config: json.RawMessage(`{}`), ExpectedRevision: 0,
	})
	requireProblem(t, err, problem.RevisionConflict)
	if got := problem.From(err).CurrentRevision; got != "1" {
		t.Fatalf("CurrentRevision = %q, want 1", got)
	}
}

func TestApplyConfigInvalidJSON(t *testing.T) {
	e := newEnv(t)
	e.mustInstallV1("acme.demo")
	_, err := e.u.ApplyConfig(e.ctx(), ConfigRequest{PluginID: "acme.demo", Config: json.RawMessage(`{`)})
	requireProblem(t, err, problem.ValidationFailed)
	if _, err := e.u.ApplyConfig(e.ctx(), ConfigRequest{PluginID: "nobody.here", Config: json.RawMessage(`{}`)}); err == nil {
		t.Fatal("configuring a missing plugin succeeded")
	}
}

func TestConfigRetention(t *testing.T) {
	e := newEnv(t)
	e.mustInstallV1("acme.demo")
	e.opts.KeepConfigs = 2
	e.opts.KeepConfigAge = 30 * 24 * time.Hour
	e.u = e.newUpdater()

	steps := []time.Duration{0, 40 * 24 * time.Hour, 40 * 24 * time.Hour, 10 * 24 * time.Hour, 5 * 24 * time.Hour}
	for i, gap := range steps {
		if gap > 0 {
			e.advance(gap)
		}
		c, err := e.u.ApplyConfig(e.ctx(), ConfigRequest{
			PluginID: "acme.demo", Config: json.RawMessage(fmt.Sprintf(`{"n":%d}`, i+1)), ExpectedRevision: int64(i),
		})
		if err != nil {
			t.Fatalf("ApplyConfig %d: %v", i+1, err)
		}
		if c.Revision != int64(i+1) {
			t.Fatalf("revision = %d, want %d", c.Revision, i+1)
		}
	}
	// now = T0 + 95d, cutoff = T0 + 65d, newest two = 4 and 5.
	// Union: revisions 3, 4 and 5 survive; 1 and 2 are pruned.
	kept := make(map[int64]bool)
	var revisions []int64
	if err := e.db.View(e.ctx(), func(tx *sql.Tx) error {
		rows, qerr := tx.QueryContext(e.ctx(), `SELECT revision FROM plugin_configs WHERE plugin_id = ? ORDER BY revision`, "acme.demo")
		if qerr != nil {
			return qerr
		}
		defer rows.Close()
		for rows.Next() {
			var rev int64
			if serr := rows.Scan(&rev); serr != nil {
				return serr
			}
			revisions = append(revisions, rev)
		}
		return rows.Err()
	}); err != nil {
		t.Fatal(err)
	}
	for _, rev := range revisions {
		kept[rev] = true
	}
	for _, want := range []int64{3, 4, 5} {
		if !kept[want] {
			t.Fatalf("revision %d was pruned; kept %v", want, revisions)
		}
	}
	for _, gone := range []int64{1, 2} {
		if kept[gone] {
			t.Fatalf("revision %d should have been pruned; kept %v", gone, revisions)
		}
	}
	if e.activeConfigRevision("acme.demo") != 5 {
		t.Fatalf("active config = %d", e.activeConfigRevision("acme.demo"))
	}
}

func TestConfigNonHotApplyRestarts(t *testing.T) {
	e := newEnv(t)
	spec := defaultPkg("acme.demo", "1.0.0")
	spec.HotApply = false
	e.installPackage("pkg/acme.demo-1.0.0.pkg", spec)
	starts := e.rt.count("Start")

	applied, err := e.u.ApplyConfig(e.ctx(), ConfigRequest{
		PluginID: "acme.demo", Config: json.RawMessage(`{"interval":60}`),
	})
	if err != nil {
		t.Fatalf("ApplyConfig: %v", err)
	}
	if !applied.Active || applied.Revision != 1 {
		t.Fatalf("applied = %+v", applied)
	}
	if got := e.rt.count("ApplyConfig"); got != 0 {
		t.Fatalf("ApplyConfig called %d times for hot_apply=false", got)
	}
	if got := e.rt.count("Start"); got != starts+1 {
		t.Fatalf("Start count = %d, want %d", got, starts+1)
	}
	if e.rt.count("Stop") == 0 {
		t.Fatal("the old instance was not stopped")
	}
}
