// SPDX-License-Identifier: AGPL-3.0-only

//go:build linux

package coreproc

import (
	"errors"
	"testing"
)

func TestFakeCounterReadCannotMixOldValuesWithNewEpoch(t *testing.T) {
	fixture := fakeProcessFixture(t, "wait", nil)
	spec := fakeStartSpec(t)
	if err := fixture.manager.Start(t.Context(), spec); err != nil {
		t.Fatal(err)
	}
	if err := fixture.manager.MarkCommitted(); err != nil {
		t.Fatal(err)
	}
	first, err := fixture.manager.ReadCounters(t.Context())
	if err != nil || first.Epoch == "" || len(first.Values) != 1 {
		t.Fatal("current counter read failed")
	}
	fixture.stats.onCounters = func() {
		fixture.stats.onCounters = nil
		if err := fixture.manager.Stop(t.Context()); err != nil {
			t.Fatal(err)
		}
		if err := fixture.manager.Start(t.Context(), spec); err != nil {
			t.Fatal(err)
		}
		if err := fixture.manager.MarkCommitted(); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := fixture.manager.ReadCounters(t.Context()); !errors.Is(err, ErrUnhealthy) {
		t.Fatal("old values were relabeled with a new process epoch")
	}
	second, err := fixture.manager.ReadCounters(t.Context())
	if err != nil || second.Epoch == first.Epoch {
		t.Fatal("new process did not produce its own epoch")
	}
}
