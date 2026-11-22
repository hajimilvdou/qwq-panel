// SPDX-License-Identifier: Apache-2.0

package pluginsdk

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc/codes"

	platformv1 "github.com/qwq-panel/qwq/sdk/gen/qwq/platform/v1"
)

// lifePlugin scripts the Activate hook and its tracked work.
type lifePlugin struct {
	entered     chan struct{} // the Activate hook is running
	proceed     chan struct{} // lets the Activate hook continue; nil = do not block
	hold        chan struct{} // tracked work ignores cancellation until closed; nil = obey it
	live        atomic.Int32  // tracked goroutines currently running
	gens        atomic.Int32  // generations that overlapped another one
	activations atomic.Int32  // 实际执行的激活 hook 数量
}

type lifeInstance struct {
	*InstanceBase
	p *lifePlugin
}

func (p *lifePlugin) NewInstance(_ context.Context, info InstanceInfo) (Instance, error) {
	return &lifeInstance{InstanceBase: NewInstanceBase(info), p: p}, nil
}

func (i *lifeInstance) Activate(context.Context) error {
	i.p.activations.Add(1)
	if i.p.proceed != nil {
		i.p.entered <- struct{}{}
		<-i.p.proceed
	}
	return i.Go(func(ctx context.Context) {
		if i.p.live.Add(1) > 1 {
			i.p.gens.Add(1)
		}
		defer i.p.live.Add(-1)
		<-ctx.Done()
		if i.p.hold != nil {
			<-i.p.hold
		}
	})
}

func deactivate(env *testEnv, id string, graceMS int32) error {
	_, err := env.client.Deactivate(testContext(env.t), &platformv1.DeactivateRequest{
		Context: lifecycleContext(id), GracePeriodMs: graceMS})
	return err
}

func waitLive(t *testing.T, p *lifePlugin, want int32) {
	t.Helper()
	deadline := time.Now().Add(testTimeout)
	for p.live.Load() != want {
		if time.Now().After(deadline) {
			t.Fatalf("live tracked goroutines = %d, want %d", p.live.Load(), want)
		}
		time.Sleep(time.Millisecond)
	}
}

// TestRepeatedActivateKeepsBackground 覆盖恢复重复调用及并发重复投递。
func TestRepeatedActivateKeepsBackground(t *testing.T) {
	p := &lifePlugin{}
	env := newEnv(t, p, fixtureManifest(0, nil, nil))
	env.ready("a", nil)
	ctx := testContext(t)
	const callers = 8
	results := make(chan error, callers)
	for range callers {
		go func() {
			_, err := env.client.Activate(ctx, &platformv1.ActivateRequest{Context: lifecycleContext("a")})
			results <- err
		}()
	}
	for range callers {
		if err := recv(t, results, "concurrent Activate"); err != nil {
			t.Fatalf("concurrent Activate: %v", err)
		}
	}
	waitLive(t, p, 1)
	for range callers {
		if _, err := env.client.Activate(ctx, &platformv1.ActivateRequest{Context: lifecycleContext("a")}); err != nil {
			t.Fatalf("repeated Activate: %v", err)
		}
	}
	if got := p.activations.Load(); got != 1 {
		t.Fatalf("activation hooks = %d, want one background generation", got)
	}
	if got := p.gens.Load(); got != 0 {
		t.Fatalf("overlapping background generations = %d", got)
	}
	if err := deactivate(env, "a", 4000); err != nil {
		t.Fatal(err)
	}
	waitLive(t, p, 0)
}

func TestActivateDeactivateInterleaving(t *testing.T) {
	p := &lifePlugin{entered: make(chan struct{}, 1), proceed: make(chan struct{})}
	env := newEnv(t, p, fixtureManifest(0, nil, nil))
	env.ready("a", nil)

	activated := make(chan error, 1)
	go func() {
		_, err := env.client.Activate(testContext(t), &platformv1.ActivateRequest{Context: lifecycleContext("a")})
		activated <- err
	}()
	recv(t, p.entered, "activate hook")

	deactivated := make(chan error, 1)
	go func() { deactivated <- deactivate(env, "a", 4000) }()
	select {
	case err := <-deactivated:
		t.Fatalf("Deactivate overtook the running Activate hook: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	close(p.proceed)
	if err := recv(t, activated, "Activate"); err != nil {
		t.Fatalf("Activate: %v", err)
	}
	if err := recv(t, deactivated, "Deactivate"); err != nil {
		t.Fatalf("Deactivate: %v", err)
	}
	waitLive(t, p, 0)
	h, err := env.client.CheckHealth(testContext(t), &platformv1.CheckHealthRequest{Context: lifecycleContext("a")})
	if err != nil {
		t.Fatal(err)
	}
	if h.GetLifecycleState() != platformv1.LifecycleState_LIFECYCLE_STATE_READY {
		t.Fatalf("state = %v, want READY", h.GetLifecycleState())
	}
}

func TestReactivateCancelsPreviousGeneration(t *testing.T) {
	p := &lifePlugin{hold: make(chan struct{})}
	env := newEnv(t, p, fixtureManifest(0, nil, nil))
	env.active("a", nil)
	waitLive(t, p, 1)
	// Generation one ignores cancellation past the grace period.
	if err := deactivate(env, "a", 20); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(testContext(t), 30*time.Millisecond)
	defer cancel()
	_, err := env.client.Activate(ctx, &platformv1.ActivateRequest{Context: lifecycleContext("a")})
	wantCode(t, err, codes.DeadlineExceeded)

	// The server sees the deadline slightly after the client; let it give up too.
	time.Sleep(50 * time.Millisecond)
	close(p.hold)
	waitLive(t, p, 0)
	env.activate("a")
	waitLive(t, p, 1)
	if n := p.gens.Load(); n != 0 {
		t.Fatalf("%d generations overlapped", n)
	}
}

func TestConcurrentStopReleaseDrained(t *testing.T) {
	p := newTestPlugin()
	env := newTestEnv(t, p)
	env.ready("a", nil)
	invoked := make(chan error, 1)
	go func() {
		_, err := env.client.Invoke(testContext(t), &platformv1.InvokeRequest{
			Context: operationContext("a", "op-hold", "en"), Operation: "test.echo",
			PayloadJson: mustJSON(map[string]string{"message": "hold"}), Attempt: 1})
		invoked <- err
	}()
	recv(t, p.holdEcho, "held request")

	stopped := make(chan *platformv1.StopResponse, 1)
	go func() {
		resp, err := env.client.Stop(testContext(t), &platformv1.StopRequest{
			Context: lifecycleContext("a"), Drain: true, GracePeriodMs: 4000})
		if err != nil {
			t.Errorf("Stop: %v", err)
		}
		stopped <- resp
	}()
	time.Sleep(10 * time.Millisecond)
	released := make(chan error, 1)
	go func() {
		_, err := env.client.ReleaseInstance(testContext(t), &platformv1.ReleaseInstanceRequest{Context: lifecycleContext("a")})
		released <- err
	}()
	time.Sleep(10 * time.Millisecond)
	close(p.releaseEcho)
	if err := recv(t, invoked, "Invoke"); err != nil {
		t.Fatal(err)
	}
	if resp := recv(t, stopped, "Stop"); !resp.GetDrained() {
		t.Fatalf("Stop reported drained=false: %v", resp)
	}
	if err := recv(t, released, "Release"); err != nil {
		t.Fatal(err)
	}
}
