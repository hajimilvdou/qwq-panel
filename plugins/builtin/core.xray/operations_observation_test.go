// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"strconv"
	"sync"
	"testing"

	"github.com/qwq-panel/qwq/plugins/builtin/core.xray/internal/state"
)

func TestFakeConcurrentRuntimeReadsDoNotMixGenerationAndProcess(t *testing.T) {
	f := newApplyFixture(t)
	if _, err := f.engine.Execute(t.Context(), f.request()); err != nil {
		t.Fatal(err)
	}
	driver := &driverRuntime{store: f.store, process: f.process, controller: f.engine, trusted: true, coreVersion: state.CoreVersion}
	var readers sync.WaitGroup
	done := make(chan struct{})
	readerErrors := make(chan string, 1)
	readers.Add(1)
	go func() {
		defer readers.Done()
		for {
			select {
			case <-done:
				return
			default:
			}
			snapshot, err := driver.Snapshot(context.Background())
			if err == nil && !snapshot.applying && snapshot.metadata != nil && snapshot.metadata.State == "FAILED" {
				select {
				case readerErrors <- "stable observation fabricated a generation mismatch":
				default:
				}
				return
			}
		}
	}()
	for revision := 2; revision <= 20; revision++ {
		f.host.revision = strconv.Itoa(revision)
		if _, err := f.engine.Execute(t.Context(), f.request()); err != nil {
			close(done)
			readers.Wait()
			t.Fatal(err)
		}
	}
	close(done)
	readers.Wait()
	select {
	case message := <-readerErrors:
		t.Fatal(message)
	default:
	}
}
