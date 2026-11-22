// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/qwq-panel/qwq/plugins/builtin/core.xray/internal/apply"
	"github.com/qwq-panel/qwq/sdk/pluginsdk"
)

func TestFakePlanHasNoSecretFileOrProcessSideEffects(t *testing.T) {
	f := newApplyFixture(t)
	starts, stops, reports := f.process.starts, f.process.stops, f.host.reports
	plan, err := f.engine.Plan(t.Context(), f.request())
	if err != nil || len(plan.Changes) == 0 || len(plan.Preconditions) != 1 || plan.Preconditions[0].Subject != apply.RunningKey || plan.Preconditions[0].Revision != "" || len(plan.Warnings) == 0 {
		t.Fatalf("plan failed: %v", err)
	}
	if f.process.starts != starts || f.process.stops != stops || f.host.reports != reports || len(f.host.revealed) != 0 || f.binary.calls != 0 || f.host.found {
		t.Fatal("plan caused external work")
	}
	for _, directory := range []string{"runtime", "work"} {
		if _, err := os.Stat(filepath.Join(f.directory, directory)); !os.IsNotExist(err) {
			t.Fatal("plan created runtime files")
		}
	}
	assertPublicPlan(t, plan.Changes)
}

func TestFakePlanDescribesPortAndReferenceChangeAndGuardsRunningVersion(t *testing.T) {
	f := newApplyFixture(t)
	if _, err := f.engine.Execute(t.Context(), f.request()); err != nil {
		t.Fatal(err)
	}
	f.changeDesired()
	f.host.config = bytes.Replace(f.host.config, []byte("sec_00000000000000000000000001"), []byte("sec_00000000000000000000000002"), 1)
	reveals, starts := len(f.host.revealed), f.process.starts
	plan, err := f.engine.Plan(t.Context(), f.request())
	if err != nil || len(plan.Preconditions) != 1 || plan.Preconditions[0].Revision != "1" {
		t.Fatal("plan omitted current running guard")
	}
	encoded := planBytes(plan.Changes)
	if !bytes.Contains(encoded, []byte("11443")) || !bytes.Contains(encoded, []byte("changed")) {
		t.Fatal("plan omitted actual port or reference impact")
	}
	if len(f.host.revealed) != reveals || f.process.starts != starts {
		t.Fatal("plan revealed or restarted")
	}
	assertPublicPlan(t, plan.Changes)
}

func planBytes(changes []pluginsdk.PlannedChange) []byte {
	var data []byte
	for _, change := range changes {
		data = append(data, change.Before...)
		data = append(data, change.After...)
		data = append(data, []byte(change.Description)...)
	}
	return data
}

func assertPublicPlan(t *testing.T, changes []pluginsdk.PlannedChange) {
	t.Helper()
	data := planBytes(changes)
	for _, forbidden := range []string{"sec_", "private_key", "uuid", "refs_digest", "api.sock", "config.json", "QWQ_"} {
		if bytes.Contains(data, []byte(forbidden)) {
			t.Fatal("plan exposed secret identity, material or path")
		}
	}
}

func TestFakePlanRejectsStaleDesiredAndRunning(t *testing.T) {
	f := newApplyFixture(t)
	request := f.request()
	request.ConfigRevision = "7"
	if _, err := f.engine.Plan(t.Context(), request); apply.ErrorCode(err) != "CONFIG_REVISION_CONFLICT" {
		t.Fatal("plan accepted missing desired version")
	}
	request = f.request()
	expected := "2"
	request.ExpectedRunningRevision = &expected
	if _, err := f.engine.Plan(t.Context(), request); apply.ErrorCode(err) != "PRECONDITION_FAILED" {
		t.Fatal("plan accepted stale running precondition")
	}
}
