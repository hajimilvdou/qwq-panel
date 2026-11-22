// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/qwq-panel/qwq/internal/pluginhost/updater"
)

type fakeRestorer struct {
	routes   *updater.RouteTable
	restored []string
}

func (f *fakeRestorer) Routes() *updater.RouteTable { return f.routes }

func (f *fakeRestorer) EnsureActive(ctx context.Context, id string) error {
	if _, ok := ctx.Deadline(); !ok {
		return errors.New("no per-plugin deadline")
	}
	f.restored = append(f.restored, id)
	if id == "broken" {
		return errors.New("boom")
	}
	return nil
}

func TestRestoreActiveIsSerialAndBestEffort(t *testing.T) {
	f := &fakeRestorer{routes: updater.NewRouteTable([]updater.Route{
		{PluginID: "broken", Version: "1.0.0"},
		{PluginID: "alpha", Version: "1.0.0"},
	})}
	restoreActive(t.Context(), f, time.Second, slog.New(slog.DiscardHandler))
	if len(f.restored) != 2 {
		t.Fatalf("restored = %v, want both plugins despite a failure", f.restored)
	}
}
