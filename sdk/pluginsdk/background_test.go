// SPDX-License-Identifier: Apache-2.0

package pluginsdk

import (
	"testing"
	"time"

	"google.golang.org/grpc/codes"

	platformv1 "github.com/qwq-panel/qwq/sdk/gen/qwq/platform/v1"
)

func TestBackgroundWorkStopsOnDeactivate(t *testing.T) {
	p := newTestPlugin()
	p.background = true
	env := newTestEnv(t, p)
	env.active("a", nil)
	if got := recv(t, p.bgStarted, "background work started"); got != "a" {
		t.Fatalf("started %q", got)
	}
	if _, err := env.client.Deactivate(testContext(t), &platformv1.DeactivateRequest{
		Context: lifecycleContext("a"), GracePeriodMs: 1000}); err != nil {
		t.Fatal(err)
	}
	if got := recv(t, p.bgStopped, "background work stopped"); got != "a" {
		t.Fatalf("stopped %q", got)
	}
	if got := recv(t, p.deactivated, "deactivate hook"); got != "a" {
		t.Fatalf("deactivated %q", got)
	}
	// READY still serves requests.
	resp, err := env.client.Invoke(testContext(t), &platformv1.InvokeRequest{
		Context: operationContext("a", "op-after", "en"), Operation: "test.echo",
		PayloadJson: mustJSON(map[string]string{"message": "still here"}), Attempt: 1})
	if err != nil || resp.GetError() != nil {
		t.Fatalf("Invoke after Deactivate: %v %v", err, resp.GetError())
	}
	// A second Deactivate is an illegal transition.
	_, err = env.client.Deactivate(testContext(t), &platformv1.DeactivateRequest{Context: lifecycleContext("a")})
	wantCode(t, err, codes.FailedPrecondition)
}

func TestGoRefusedBeforeActivate(t *testing.T) {
	p := newTestPlugin()
	p.tryGo = true
	env := newTestEnv(t, p)
	env.ready("a", nil)
	err := p.goErrNow()
	if err == nil {
		t.Fatal("InstanceBase.Go succeeded outside ACTIVE")
	}
}

func TestReleaseStopsBackgroundWork(t *testing.T) {
	p := newTestPlugin()
	p.background = true
	env := newTestEnv(t, p)
	env.active("a", nil)
	recv(t, p.bgStarted, "background work started")
	if _, err := env.client.ReleaseInstance(testContext(t), &platformv1.ReleaseInstanceRequest{
		Context: lifecycleContext("a")}); err != nil {
		t.Fatal(err)
	}
	recv(t, p.bgStopped, "background work stopped")
	var released bool
	for _, entry := range p.lifecycleSnapshot() {
		if entry == "a:release" {
			released = true
		}
	}
	if !released {
		t.Fatalf("lifecycle = %v", p.lifecycleSnapshot())
	}
}

func TestDeactivateHookFailure(t *testing.T) {
	p := newTestPlugin()
	p.deactivate = errTest
	env := newTestEnv(t, p)
	env.active("a", nil)
	_, err := env.client.Deactivate(testContext(t), &platformv1.DeactivateRequest{
		Context: lifecycleContext("a"), GracePeriodMs: 1000})
	wantCode(t, err, codes.Internal)
	// The background context is canceled and the state is READY even though the
	// hook failed, so the instance can be stopped instead of stuck in ACTIVE.
	health, herr := env.client.CheckHealth(testContext(t), &platformv1.CheckHealthRequest{Context: lifecycleContext("a")})
	if herr != nil || health.GetLifecycleState() != platformv1.LifecycleState_LIFECYCLE_STATE_READY {
		t.Fatalf("health = %v, %v", health, herr)
	}
}

func TestActivateFailureMarksFailed(t *testing.T) {
	p := newTestPlugin()
	p.activateErr = errTest
	env := newTestEnv(t, p)
	env.ready("a", nil)
	_, err := env.client.Activate(testContext(t), &platformv1.ActivateRequest{Context: lifecycleContext("a")})
	wantCode(t, err, codes.Internal)
	health, herr := env.client.CheckHealth(testContext(t), &platformv1.CheckHealthRequest{Context: lifecycleContext("a")})
	if herr != nil || health.GetLifecycleState() != platformv1.LifecycleState_LIFECYCLE_STATE_FAILED ||
		health.GetStatus() != platformv1.CheckHealthResponse_STATUS_NOT_SERVING {
		t.Fatalf("health = %v, %v", health, herr)
	}
}

func TestStopFromActiveRunsDeactivate(t *testing.T) {
	p := newTestPlugin()
	p.background = true
	env := newTestEnv(t, p)
	env.active("a", nil)
	recv(t, p.bgStarted, "background work started")

	stop, err := env.client.Stop(testContext(t), &platformv1.StopRequest{
		Context: lifecycleContext("a"), Drain: true, GracePeriodMs: 1000})
	if err != nil || !stop.GetDrained() {
		t.Fatalf("Stop = %v, %v", stop, err)
	}
	if got := recv(t, p.deactivated, "the deactivate hook of a direct Stop"); got != "a" {
		t.Fatalf("deactivated %q", got)
	}
	recv(t, p.bgStopped, "background work stopped")
}

func TestStartFailureMarksFailed(t *testing.T) {
	p := newTestPlugin()
	p.startErr = errTest
	env := newTestEnv(t, p)
	env.initialize("a", nil)
	_, err := env.client.Start(testContext(t), &platformv1.StartRequest{Context: lifecycleContext("a")})
	wantCode(t, err, codes.Internal)
	health, herr := env.client.CheckHealth(testContext(t), &platformv1.CheckHealthRequest{Context: lifecycleContext("a")})
	if herr != nil || health.GetLifecycleState() != platformv1.LifecycleState_LIFECYCLE_STATE_FAILED {
		t.Fatalf("health = %v, %v", health, herr)
	}
}

// waitState polls CheckHealth until the instance reaches want. It is used
// instead of sleeping, so the test never depends on a fixed delay.
func waitState(t *testing.T, env *testEnv, id string, want platformv1.LifecycleState) {
	t.Helper()
	ctx := testContext(t)
	deadline := time.Now().Add(testTimeout)
	for {
		health, err := env.client.CheckHealth(ctx, &platformv1.CheckHealthRequest{Context: lifecycleContext(id)})
		if err == nil && health.GetLifecycleState() == want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("instance %s did not reach %v (last health %v, err %v)", id, want, health, err)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

type echoResult struct {
	resp *platformv1.InvokeResponse
	err  error
}

func holdEcho(t *testing.T, env *testEnv, id string) (chan echoResult, *testPlugin) {
	t.Helper()
	p := env.plugin
	held := make(chan echoResult, 1)
	go func() {
		resp, err := env.client.Invoke(t.Context(), &platformv1.InvokeRequest{
			Context: operationContext(id, "op-hold", "en"), Operation: "test.echo",
			PayloadJson: mustJSON(map[string]string{"message": "hold"}), Attempt: 1,
		})
		held <- echoResult{resp: resp, err: err}
	}()
	recv(t, p.holdEcho, "the echo to be held")
	return held, p
}

func TestStopDrainWaitsForInflight(t *testing.T) {
	env := newTestEnv(t, newTestPlugin())
	env.active("a", nil)
	held, p := holdEcho(t, env, "a")

	stopped := make(chan *platformv1.StopResponse, 1)
	go func() {
		resp, _ := env.client.Stop(testContext(t), &platformv1.StopRequest{
			Context: lifecycleContext("a"), Drain: true, GracePeriodMs: 3000})
		stopped <- resp
	}()
	waitState(t, env, "a", platformv1.LifecycleState_LIFECYCLE_STATE_DRAINING)

	// While draining, new requests are refused and the in-flight one finishes.
	_, err := env.client.Invoke(testContext(t), &platformv1.InvokeRequest{
		Context: operationContext("a", "op-late", "en"), Operation: "test.echo",
		PayloadJson: mustJSON(map[string]string{"message": "late"}), Attempt: 1})
	wantCode(t, err, codes.FailedPrecondition)

	close(p.releaseEcho)
	if got := recv(t, held, "the in-flight echo"); got.err != nil || got.resp.GetError() != nil {
		t.Fatalf("in-flight echo = %v %v", got.err, got.resp.GetError())
	}
	if stop := recv(t, stopped, "Stop"); !stop.GetDrained() {
		t.Fatalf("Stop = %v, want drained", stop)
	}
}

func TestStopWithoutDrainDoesNotWait(t *testing.T) {
	env := newTestEnv(t, newTestPlugin())
	env.active("a", nil)
	held, p := holdEcho(t, env, "a")

	// The held request is still running, so a Stop that waits would never
	// return before releaseEcho is closed.
	stop, err := env.client.Stop(testContext(t), &platformv1.StopRequest{
		Context: lifecycleContext("a"), Drain: false, GracePeriodMs: 3000})
	if err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if stop.GetDrained() {
		t.Fatal("Stop reported drained while a request was in flight")
	}
	close(p.releaseEcho)
	if got := recv(t, held, "the in-flight echo"); got.err != nil || got.resp.GetError() != nil {
		t.Fatalf("in-flight echo = %v %v", got.err, got.resp.GetError())
	}
}
