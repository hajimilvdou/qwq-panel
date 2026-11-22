// SPDX-License-Identifier: AGPL-3.0-only

package updater

import (
	"testing"
	"time"

	"github.com/qwq-panel/qwq/internal/platform/problem"
)

func TestEnsureActiveRestoresCrashedInstance(t *testing.T) {
	e := newEnv(t)
	e.mustInstallV1("acme.demo")
	// systemd restarted the process: the cached handle points at a process
	// that is gone, and the new one has no instance yet.
	crashed := e.rt.instanceFor("acme.demo", "1.0.0")
	e.rt.mu.Lock()
	crashed.stopped, crashed.active = true, false
	e.rt.mu.Unlock()

	if err := e.u.EnsureActive(e.ctx(), "acme.demo"); err != nil {
		t.Fatalf("EnsureActive: %v", err)
	}
	inst := e.rt.instanceFor("acme.demo", "1.0.0")
	if inst == nil || inst == crashed || inst.stopped || !inst.active {
		t.Fatalf("instance after EnsureActive = %+v, want a fresh active instance", inst)
	}
	// A healthy instance is left alone: no second start.
	if err := e.u.EnsureActive(e.ctx(), "acme.demo"); err != nil {
		t.Fatalf("EnsureActive(healthy): %v", err)
	}
	if e.rt.instanceFor("acme.demo", "1.0.0") != inst {
		t.Fatal("EnsureActive replaced a healthy instance")
	}
}

func TestEnsureActiveNoActiveIsNotFound(t *testing.T) {
	e := newEnv(t)
	requireProblem(t, e.u.EnsureActive(e.ctx(), "acme.demo"), problem.NotFound)
}

func TestEnsureActiveSerializesWithSaga(t *testing.T) {
	e := newEnv(t)
	e.mustInstallV1("acme.demo")
	unlock := e.u.locks.lock("acme.demo") // a saga holds the plugin
	done := make(chan error, 1)
	go func() { done <- e.u.EnsureActive(e.ctx(), "acme.demo") }()
	select {
	case err := <-done:
		t.Fatalf("EnsureActive ran during a saga: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	unlock()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("EnsureActive after the saga: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("EnsureActive did not finish after the saga")
	}
}
