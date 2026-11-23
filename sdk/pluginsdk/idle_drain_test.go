// SPDX-License-Identifier: Apache-2.0

package pluginsdk

import (
	"sync/atomic"
	"testing"
	"time"
)

func TestIdleDrainerTriggersOnlyWhenIdle(t *testing.T) {
	var fired atomic.Int32
	done := make(chan struct{})
	d := NewIdleDrainer(60*time.Millisecond, func() {
		fired.Add(1)
		close(done)
	})
	defer d.Close()

	// Hold an active request longer than idleTTL.
	release := d.BeginRequest()
	time.Sleep(110 * time.Millisecond)
	if fired.Load() != 0 {
		t.Fatalf("drainer fired while request was in flight")
	}
	release()

	select {
	case <-done:
		if fired.Load() != 1 {
			t.Fatalf("expected 1 drain callback, got %d", fired.Load())
		}
	case <-time.After(1 * time.Second):
		t.Fatalf("drainer did not fire after becoming idle")
	}
}

func TestIdleTTLFromEnv(t *testing.T) {
	t.Setenv(EnvIdleTTL, "180s")
	if got := IdleTTLFromEnv(); got != 180*time.Second {
		t.Fatalf("IdleTTLFromEnv() = %v, want 180s", got)
	}
	t.Setenv(EnvIdleTTL, "-5s")
	if got := IdleTTLFromEnv(); got != 0 {
		t.Fatalf("IdleTTLFromEnv() = %v, want 0", got)
	}
	t.Setenv(EnvIdleTTL, "not-a-duration")
	if got := IdleTTLFromEnv(); got != 0 {
		t.Fatalf("IdleTTLFromEnv() = %v, want 0", got)
	}
}
