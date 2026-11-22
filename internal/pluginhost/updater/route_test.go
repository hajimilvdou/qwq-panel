// SPDX-License-Identifier: AGPL-3.0-only

package updater

import (
	"sync"
	"testing"
)

// TestRoutesConcurrentSnapshots hammers route publication while readers take
// snapshots. Every snapshot must be complete: plugin B always routes to its
// only version, plugin A to exactly one of the two versions, and revisions
// never go backwards. Run with -race.
func TestRoutesConcurrentSnapshots(t *testing.T) {
	e := newEnv(t)
	e.mustInstallV1("a.plugin")
	e.mustInstallV1("b.plugin")

	base := e.u.Routes()
	if base.Len() != 2 {
		t.Fatalf("initial route table has %d entries", base.Len())
	}

	stop := make(chan struct{})
	var wg sync.WaitGroup
	for range 6 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			var lastRevision uint64
			for {
				select {
				case <-stop:
					return
				default:
				}
				table := e.u.Routes()
				if table == nil {
					t.Error("Routes() returned nil")
					return
				}
				if table.Len() != 2 {
					t.Errorf("snapshot has %d routes, want 2", table.Len())
					return
				}
				if table.Revision() < lastRevision {
					t.Errorf("revision went backwards: %d -> %d", lastRevision, table.Revision())
					return
				}
				lastRevision = table.Revision()
				b, ok := table.Lookup("b.plugin")
				if !ok || b.Version != "1.0.0" {
					t.Errorf("plugin b route = %+v, %v", b, ok)
					return
				}
				a, ok := table.Lookup("a.plugin")
				if !ok || (a.Version != "1.0.0" && a.Version != "2.0.0") {
					t.Errorf("plugin a route = %+v, %v", a, ok)
					return
				}
			}
		}()
	}

	for i := range 500 {
		version := "1.0.0"
		if i%2 == 1 {
			version = "2.0.0"
		}
		e.u.swapRoute("a.plugin", version)
	}
	close(stop)
	wg.Wait()

	if route, ok := base.Lookup("a.plugin"); !ok || route.Version != "1.0.0" {
		t.Fatal("a published snapshot was mutated in place")
	}
	if e.u.Routes().Revision() <= base.Revision() {
		t.Fatalf("route revision did not advance: %d -> %d", base.Revision(), e.u.Routes().Revision())
	}
}

func TestRouteTableIsImmutable(t *testing.T) {
	table := NewRouteTable([]Route{
		{PluginID: "a", Version: "1"},
		{PluginID: "b", Version: "2"},
	})
	if table.Len() != 2 || table.Revision() != 0 {
		t.Fatalf("table = %+v", table)
	}
	route, ok := table.Lookup("a")
	if !ok || route.Version != "1" {
		t.Fatalf("lookup = %+v, %v", route, ok)
	}
	if _, ok := table.Lookup("missing"); ok {
		t.Fatal("unknown plugin found")
	}
	list := table.List()
	if len(list) != 2 || list[0].PluginID != "a" || list[1].PluginID != "b" {
		t.Fatalf("list = %+v", list)
	}
	var nilTable *RouteTable
	if nilTable.Len() != 0 || nilTable.Revision() != 0 || nilTable.List() != nil {
		t.Fatal("nil table accessors are not safe")
	}
	if _, ok := nilTable.Lookup("a"); ok {
		t.Fatal("nil table returned a route")
	}
}
