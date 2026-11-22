// SPDX-License-Identifier: AGPL-3.0-only

package supervisor

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/qwq-panel/qwq/internal/platform/problem"
	platformv1 "github.com/qwq-panel/qwq/sdk/gen/qwq/platform/v1"
)

func TestEnsureStartsUnitAndReattaches(t *testing.T) {
	env := newEnv(t)
	env.pluginFor(t, "alpha").setPlan(func(context.Context, *platformv1.PlanOperationRequest) (*platformv1.PlanOperationResponse, error) {
		return &platformv1.PlanOperationResponse{Changes: []*platformv1.PlannedChange{{Subject: "x"}}}, nil
	})

	inst := env.ensure(t, "alpha")

	if starts, stops, kills := env.units.counts(); starts != 1 || stops != 0 || kills != 0 {
		t.Fatalf("unit calls = start %d stop %d kill %d, want 1/0/0", starts, stops, kills)
	}
	if serves, _ := env.host.counts(); serves != 1 {
		t.Fatalf("host Serve calls = %d, want 1", serves)
	}
	if inst.PluginID() != "alpha" {
		t.Fatalf("plugin id = %q", inst.PluginID())
	}
	if want := "qwq-plugin@alpha.service"; inst.Unit() != want {
		t.Fatalf("unit = %q, want %q", inst.Unit(), want)
	}
	if inst.MainPID() != os.Getpid() {
		t.Fatalf("main pid = %d, want %d", inst.MainPID(), os.Getpid())
	}
	if len(inst.Generation()) != 16 {
		t.Fatalf("generation = %q, want 16 hex digits", inst.Generation())
	}
	if want := Owner("alpha", inst.Generation()); inst.Owner() != want {
		t.Fatalf("owner = %q, want %q", inst.Owner(), want)
	}
	if !strings.HasSuffix(inst.VersionDir(), "alpha/1.0.0") {
		t.Fatalf("version dir = %q", inst.VersionDir())
	}
	if !inst.HostServing() {
		t.Fatal("host channel is not serving")
	}

	client := inst.Client()
	if client == nil {
		t.Fatal("instance has no client")
	}
	if got, err := env.sup.Client("alpha"); err != nil || got != client {
		t.Fatalf("Supervisor.Client = %v, %v", got, err)
	}
	if client.Generation() != inst.Generation() || client.Owner() != inst.Owner() {
		t.Fatalf("client identity = %q/%q", client.Generation(), client.Owner())
	}
	resp, err := client.Plan(context.Background(), &platformv1.PlanOperationRequest{})
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	if len(resp.GetChanges()) != 1 {
		t.Fatalf("plan changes = %d, want 1", len(resp.GetChanges()))
	}

	statuses := env.sup.Instances()
	if len(statuses) != 1 {
		t.Fatalf("instances = %d, want 1", len(statuses))
	}
	st := statuses[0]
	if st.PluginID != "alpha" || st.State != StateRunning || !st.HostServing {
		t.Fatalf("status = %+v", st)
	}
	if st.Generation != inst.Generation() || st.MainPID != os.Getpid() {
		t.Fatalf("status identity = %+v", st)
	}
	if st.ActiveState != "active" || st.SubState != "running" {
		t.Fatalf("status unit state = %q/%q", st.ActiveState, st.SubState)
	}
}

func TestEnsureReusesCurrentInstance(t *testing.T) {
	env := newEnv(t)
	first := env.ensure(t, "alpha")
	second := env.ensure(t, "alpha")

	if first != second {
		t.Fatal("Ensure reattached although the generation did not change")
	}
	if serves, _ := env.host.counts(); serves != 1 {
		t.Fatalf("host Serve calls = %d, want 1", serves)
	}
	if starts, _, _ := env.units.counts(); starts != 1 {
		t.Fatalf("unit starts = %d, want 1", starts)
	}
}

func TestEnsureOutOfBandRestartInvalidatesInstance(t *testing.T) {
	env := newEnv(t)
	first := env.ensure(t, "alpha")
	firstClient := first.Client()
	cleanup, cleanupCalls := countingCleanup()
	env.sup.RegisterCleanup(first.Owner(), cleanup)

	env.restartOutOfBand("alpha", os.Getpid()+1, time.Unix(1700000100, 0).UTC())
	second := env.ensure(t, "alpha")

	if second == first {
		t.Fatal("Ensure kept the instance of the old generation")
	}
	if second.Generation() == first.Generation() {
		t.Fatalf("generation %q did not change after an out-of-band restart", first.Generation())
	}
	if first.Client() != nil {
		t.Fatal("the old instance still hands out a client")
	}
	if _, err := firstClient.Plan(context.Background(), &platformv1.PlanOperationRequest{}); !problem.HasCode(err, problem.PluginUnavailable) {
		t.Fatalf("stale client error = %v, want PLUGIN_UNAVAILABLE", err)
	}
	if cleanupCalls.Load() != 1 {
		t.Fatalf("owner cleanups = %d, want 1", cleanupCalls.Load())
	}
	if serves, stops := env.host.counts(); serves != 2 || stops != 1 {
		t.Fatalf("host calls = serve %d stop %d, want 2/1", serves, stops)
	}
	statuses := env.sup.Instances()
	if len(statuses) != 1 || statuses[0].Generation != second.Generation() {
		t.Fatalf("instances = %+v", statuses)
	}
}

func TestEnsureRetriesThenDegraded(t *testing.T) {
	env := newEnv(t)
	env.host.setServeErr(errors.New("no host channel"))
	_, err := ensureWithClock(t, env.sup, env.clock, "alpha")
	if err == nil {
		t.Fatal("Ensure succeeded although the host channel failed")
	}
	if !problem.HasCode(err, problem.PluginUnavailable) {
		t.Fatalf("error = %v, want PLUGIN_UNAVAILABLE", err)
	}
	if got := env.host.attempts(); got != 2 {
		t.Fatalf("host Serve attempts = %d, want 2 (MaxRestarts)", got)
	}
	if starts, _, _ := env.units.counts(); starts != 1 {
		t.Fatalf("unit starts = %d, want 1", starts)
	}
	if inst := instOf(env.sup, "alpha"); inst != nil {
		t.Fatal("a degraded plugin still has an instance")
	}

	statuses := env.sup.Instances()
	if len(statuses) != 1 {
		t.Fatalf("instances = %d, want 1 degraded entry", len(statuses))
	}
	degraded := statuses[0]
	if degraded.State != StateDegraded || degraded.Attempts != 2 {
		t.Fatalf("degraded status = %+v", degraded)
	}
	if degraded.RetryAt.IsZero() || degraded.LastError == "" {
		t.Fatalf("degraded status misses retry_at or last_error: %+v", degraded)
	}

	// Before the cooldown ends Ensure must not touch the unit again.
	if _, err := ensureWithClock(t, env.sup, env.clock, "alpha"); err == nil {
		t.Fatal("Ensure retried while the plugin was in its cooldown")
	}
	if got := env.host.attempts(); got != 2 {
		t.Fatalf("host Serve attempts after a cooldown hit = %d, want 2", got)
	}

	// After the cooldown a healthy host channel attaches again.
	env.host.setServeErr(nil)
	env.clock.Advance(2 * time.Minute)
	inst := env.ensure(t, "alpha")
	if inst == nil {
		t.Fatal("Ensure did not recover")
	}
	if inst := instOf(env.sup, "alpha"); inst == nil {
		t.Fatal("recovered instance is not registered")
	}
	if statuses := env.sup.Instances(); len(statuses) != 1 || statuses[0].State != StateRunning {
		t.Fatalf("instances after recovery = %+v", statuses)
	}
}

func TestEnsureReattachesAfterTransportFailure(t *testing.T) {
	env := newEnv(t)
	first := env.ensure(t, "alpha")
	first.markTransportFailure(errors.New("connection reset by peer"))

	client := first.Client()
	if client == nil {
		t.Fatal("instance lost its client")
	}
	if _, err := client.Plan(context.Background(), &platformv1.PlanOperationRequest{}); !problem.HasCode(err, problem.PluginUnavailable) {
		t.Fatalf("broken client error = %v, want PLUGIN_UNAVAILABLE", err)
	}

	second := env.ensure(t, "alpha")
	if second == first {
		t.Fatal("Ensure reused a broken connection")
	}
	if serves, _ := env.host.counts(); serves != 2 {
		t.Fatalf("host Serve calls = %d, want 2", serves)
	}
}

func TestStopAndKillUseTheUnitManagerOnly(t *testing.T) {
	env := newEnv(t)
	inst := env.ensure(t, "alpha")
	client := inst.Client()

	if err := env.sup.Stop(context.Background(), "alpha"); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if starts, stops, kills := env.units.counts(); starts != 1 || stops != 1 || kills != 0 {
		t.Fatalf("unit calls = start %d stop %d kill %d, want 1/1/0", starts, stops, kills)
	}
	if serves, stops := env.host.counts(); serves != 1 || stops != 1 {
		t.Fatalf("host calls = serve %d stop %d, want 1/1", serves, stops)
	}
	if inst.Client() != nil {
		t.Fatal("stopped instance still hands out a client")
	}
	if _, err := client.Plan(context.Background(), &platformv1.PlanOperationRequest{}); !problem.HasCode(err, problem.PluginUnavailable) {
		t.Fatalf("stopped client error = %v, want PLUGIN_UNAVAILABLE", err)
	}
	if got := env.sup.Instances(); len(got) != 0 {
		t.Fatalf("instances after Stop = %+v, want none", got)
	}

	env.ensure(t, "alpha")
	if err := env.sup.Kill(context.Background(), "alpha"); err != nil {
		t.Fatalf("Kill: %v", err)
	}
	if starts, stops, kills := env.units.counts(); starts != 2 || stops != 1 || kills != 1 {
		t.Fatalf("unit calls = start %d stop %d kill %d, want 2/1/1", starts, stops, kills)
	}
	if serves, stops := env.host.counts(); serves != 2 || stops != 2 {
		t.Fatalf("host calls = serve %d stop %d, want 2/2", serves, stops)
	}
	// Reaching this point proves no go-plugin Client.Kill ran: the reattach Pid is
	// this test process, and Client.Kill would have SIGKILLed it.
}

func TestCleanupIsIdempotent(t *testing.T) {
	env := newEnv(t)
	inst := env.ensure(t, "alpha")
	owner := inst.Owner()
	cleanup, calls := countingCleanup()
	env.sup.RegisterCleanup(owner, cleanup)

	env.sup.Cleanup(owner)
	env.sup.Cleanup(owner)

	if calls.Load() != 1 {
		t.Fatalf("owner cleanups = %d, want 1", calls.Load())
	}
	if serves, stops := env.host.counts(); serves != 1 || stops != 1 {
		t.Fatalf("host calls = serve %d stop %d, want 1/1", serves, stops)
	}
	if got := env.sup.Instances(); len(got) != 0 {
		t.Fatalf("instances after Cleanup = %+v, want none", got)
	}
	if _, stops, kills := env.units.counts(); stops != 0 || kills != 0 {
		t.Fatalf("Cleanup touched the unit: stop %d kill %d", stops, kills)
	}

	env.ensure(t, "alpha")
	if serves, _ := env.host.counts(); serves != 2 {
		t.Fatalf("host Serve calls after re-ensure = %d, want 2", serves)
	}
}

func TestCleanupOfStaleOwnerKeepsCurrentInstance(t *testing.T) {
	env := newEnv(t)
	first := env.ensure(t, "alpha")
	staleOwner := first.Owner()

	env.restartOutOfBand("alpha", os.Getpid()+1, time.Unix(1700000200, 0).UTC())
	second := env.ensure(t, "alpha")

	env.sup.Cleanup(staleOwner)

	if second.Client() == nil || !second.HostServing() {
		t.Fatal("Cleanup of a stale owner tore down the current instance")
	}
	if serves, stops := env.host.counts(); serves != 2 || stops != 1 {
		t.Fatalf("host calls = serve %d stop %d, want 2/1", serves, stops)
	}
	if got := env.sup.Instances(); len(got) != 1 || got[0].Generation != second.Generation() {
		t.Fatalf("instances = %+v", got)
	}
}

func TestEnsureValidatesPluginID(t *testing.T) {
	env := newEnv(t)
	badIDs := []string{"", "Alpha", "al/pha", "alpha..beta", "alpha@beta", "1alpha", strings.Repeat("a", 129)}
	for _, id := range badIDs {
		if _, err := env.sup.Ensure(context.Background(), id); !problem.HasCode(err, problem.ValidationFailed) {
			t.Errorf("Ensure(%q) error = %v, want VALIDATION_FAILED", id, err)
		}
		if err := env.sup.Stop(context.Background(), id); !problem.HasCode(err, problem.ValidationFailed) {
			t.Errorf("Stop(%q) error = %v, want VALIDATION_FAILED", id, err)
		}
		if _, err := env.sup.Client(id); !problem.HasCode(err, problem.ValidationFailed) {
			t.Errorf("Client(%q) error = %v, want VALIDATION_FAILED", id, err)
		}
		if calls := env.host.attempts(); calls != 0 {
			t.Fatalf("host Serve attempts = %d, want 0", calls)
		}
	}
}

func TestEnsureReportsAttachFailures(t *testing.T) {
	t.Run("package directory unavailable", func(t *testing.T) {
		env := newEnv(t, func(o *Options) {
			o.MaxRestarts = 1
			o.PluginDir = func(string) (string, error) { return "", errors.New("not installed") }
		})
		_, err := ensureWithClock(t, env.sup, env.clock, "alpha")
		if !problem.HasCode(err, problem.PluginUnavailable) {
			t.Fatalf("error = %v, want PLUGIN_UNAVAILABLE", err)
		}
		if starts, _, _ := env.units.counts(); starts != 0 {
			t.Fatalf("unit starts = %d, want 0", starts)
		}
		if calls := env.host.attempts(); calls != 0 {
			t.Fatalf("host Serve attempts = %d, want 0", calls)
		}
	})

	t.Run("unit state unavailable", func(t *testing.T) {
		env := newEnv(t, func(o *Options) { o.MaxRestarts = 1 })
		env.units.setErrors(errors.New("dbus is down"), nil, nil, nil)
		_, err := ensureWithClock(t, env.sup, env.clock, "alpha")
		if !problem.HasCode(err, problem.PluginUnavailable) {
			t.Fatalf("error = %v, want PLUGIN_UNAVAILABLE", err)
		}
	})

	t.Run("unit start fails", func(t *testing.T) {
		env := newEnv(t, func(o *Options) { o.MaxRestarts = 1 })
		env.units.setErrors(nil, errors.New("start refused"), nil, nil)
		_, err := ensureWithClock(t, env.sup, env.clock, "alpha")
		if !problem.HasCode(err, problem.PluginUnavailable) {
			t.Fatalf("error = %v, want PLUGIN_UNAVAILABLE", err)
		}
	})

	t.Run("invalid resource limits", func(t *testing.T) {
		env := newEnv(t, func(o *Options) {
			o.MaxRestarts = 1
			o.Limits = func(string) (Limits, error) { return Limits{MemoryMaxBytes: -1}, nil }
		})
		_, err := ensureWithClock(t, env.sup, env.clock, "alpha")
		if !problem.HasCode(err, problem.ValidationFailed) {
			t.Fatalf("error = %v, want VALIDATION_FAILED", err)
		}
		if starts, _, _ := env.units.counts(); starts != 0 {
			t.Fatalf("unit starts = %d, want 0: limits are validated before the unit starts", starts)
		}
	})
}

func TestCloseClosesHostChannelsWithoutStoppingUnits(t *testing.T) {
	env := newEnv(t)
	env.addPlugin(t, "beta")
	alpha := env.ensure(t, "alpha")
	beta := env.ensure(t, "beta")
	cleanup, calls := countingCleanup()
	env.sup.RegisterCleanup(alpha.Owner(), cleanup)

	env.sup.Close()

	if calls.Load() != 1 {
		t.Fatalf("owner cleanups = %d, want 1", calls.Load())
	}
	if serves, stops := env.host.counts(); serves != 2 || stops != 2 {
		t.Fatalf("host calls = serve %d stop %d, want 2/2", serves, stops)
	}
	if alpha.Client() != nil || beta.Client() != nil {
		t.Fatal("a closed supervisor still hands out clients")
	}
	if _, stops, kills := env.units.counts(); stops != 0 || kills != 0 {
		t.Fatalf("Close touched the units: stop %d kill %d", stops, kills)
	}
	if got := env.sup.Instances(); len(got) != 0 {
		t.Fatalf("instances after Close = %+v, want none", got)
	}
	env.sup.Close() // idempotent
	if _, err := env.sup.Ensure(context.Background(), "alpha"); !problem.HasCode(err, problem.Unavailable) {
		t.Fatalf("Ensure after Close error = %v, want UNAVAILABLE", err)
	}
}

func TestBackoffBounds(t *testing.T) {
	sup, err := New(Options{
		Units:      &fakeUnits{},
		Host:       &fakeHost{},
		PluginDir:  func(string) (string, error) { return "/tmp/plugin", nil },
		BackoffMin: time.Second,
		BackoffMax: 5 * time.Minute,
		RunDir:     shortTempDir(t),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	sup.jitter = func() float64 { return 0 }

	cases := map[int]time.Duration{
		1:   500 * time.Millisecond,
		2:   1 * time.Second,
		3:   2 * time.Second,
		4:   4 * time.Second,
		100: 150 * time.Second,
	}
	for attempt, want := range cases {
		if got := sup.backoff(attempt); got != want {
			t.Errorf("backoff(%d) = %v, want %v", attempt, got, want)
		}
	}
	sup.jitter = func() float64 { return 0.999 }
	if got := sup.backoff(3); got < 2*time.Second || got > 4*time.Second {
		t.Errorf("jittered backoff(3) = %v, want within [2s, 4s]", got)
	}
}

// instOf returns the current instance of pluginID without failing the test.
func instOf(s *Supervisor, pluginID string) *Instance {
	return s.current(pluginID)
}

func TestEnsureRestoresNewGeneration(t *testing.T) {
	var restored []string
	env := newEnv(t, func(o *Options) {
		o.OnNewGeneration = func(_ context.Context, id string) error {
			restored = append(restored, id)
			return nil
		}
	})
	env.ensure(t, "alpha")
	env.ensure(t, "alpha")
	if len(restored) != 0 {
		t.Fatalf("restored %v for the first and the same generation", restored)
	}
	env.restartOutOfBand("alpha", os.Getpid()+1, time.Unix(1700000100, 0).UTC())
	env.ensure(t, "alpha")
	if len(restored) != 1 || restored[0] != "alpha" {
		t.Fatalf("restored = %v, want [alpha] after a new generation", restored)
	}
}
