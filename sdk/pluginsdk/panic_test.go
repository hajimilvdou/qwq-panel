// SPDX-License-Identifier: Apache-2.0

package pluginsdk

import (
	"context"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"

	platformv1 "github.com/qwq-panel/qwq/sdk/gen/qwq/platform/v1"
)

// panicPlugin panics from each kind of plugin code on request.
type panicPlugin struct {
	badRegistration bool
	bgPanic         bool
}

type panicInstance struct {
	*InstanceBase
	p *panicPlugin
}

var panicOps = []opSpec{
	{Name: "test.boom", Mode: "invoke", Effect: "read"},
	{Name: "test.boomjob", Mode: "job", Effect: "read"},
	{Name: "test.boomplan", Mode: "invoke", Effect: "write", Plannable: true},
}

func (p *panicPlugin) NewInstance(_ context.Context, info InstanceInfo) (Instance, error) {
	inst := &panicInstance{InstanceBase: NewInstanceBase(info), p: p}
	if p.badRegistration {
		inst.HandleInvoke("test.boom", nil)
	}
	boom := func(_ context.Context, req Request) (Response, error) {
		if string(req.Payload) == `"ok"` {
			return Response{Payload: req.Payload}, nil
		}
		panic("nil map write")
	}
	inst.HandleInvoke("test.boom", boom)
	inst.HandleInvoke("test.boomplan", boom)
	inst.HandleJob("test.boomjob", func(context.Context, Request, Progress) (Result, error) { panic("job secret") })
	inst.HandlePlan("test.boomplan", func(context.Context, Request) (Plan, error) { panic("plan secret") })
	return inst, nil
}

func (i *panicInstance) Activate(context.Context) error {
	if i.p.bgPanic {
		return i.Go(func(context.Context) { panic("background secret") })
	}
	return nil
}

func newPanicEnv(t *testing.T, p *panicPlugin) *testEnv {
	t.Helper()
	return newEnv(t, p, fixtureManifest(0, panicOps, defaultCaps))
}

func TestInvokePanicReturnsInternal(t *testing.T) {
	env := newPanicEnv(t, &panicPlugin{})
	env.ready("a", nil)
	env.ready("b", nil)
	resp, err := env.client.Invoke(testContext(t), &platformv1.InvokeRequest{
		Context: operationContext("a", "op-1", "en"), Operation: "test.boom", PayloadJson: []byte(`"x"`)})
	if err != nil {
		t.Fatalf("Invoke: %v", err)
	}
	if resp.GetError().GetCode() != "INTERNAL" || strings.Contains(resp.GetError().GetMessage(), "nil map") {
		t.Fatalf("error = %v", resp.GetError())
	}
	// The process survived: both instances keep serving.
	for _, id := range []string{"a", "b"} {
		resp, err := env.client.Invoke(testContext(t), &platformv1.InvokeRequest{
			Context: operationContext(id, "op-2", "en"), Operation: "test.boom", PayloadJson: []byte(`"ok"`)})
		if err != nil || resp.GetError() != nil {
			t.Fatalf("Invoke on %s after panic: %v %v", id, err, resp.GetError())
		}
	}
}

func TestJobAndPlanPanicReturnInternal(t *testing.T) {
	env := newPanicEnv(t, &panicPlugin{})
	env.ready("a", nil)
	stream, err := env.client.RunJob(testContext(t), &platformv1.RunJobRequest{
		Context: operationContext("a", "op-1", "en"), Operation: "test.boomjob"})
	if err != nil {
		t.Fatal(err)
	}
	msg, err := stream.Recv()
	if err != nil {
		t.Fatalf("Recv: %v", err)
	}
	if e := msg.GetProgress().GetError(); e.GetCode() != "INTERNAL" || strings.Contains(e.GetMessage(), "secret") {
		t.Fatalf("job error = %v", e)
	}
	plan, err := env.client.PlanOperation(testContext(t), &platformv1.PlanOperationRequest{
		Context: operationContext("a", "op-2", "en"), Operation: "test.boomplan"})
	if err != nil {
		t.Fatal(err)
	}
	if e := plan.GetError(); e.GetCode() != "INTERNAL" || strings.Contains(e.GetMessage(), "secret") {
		t.Fatalf("plan error = %v", e)
	}
}

func TestTrackedGoroutinePanicFailsInstance(t *testing.T) {
	env := newPanicEnv(t, &panicPlugin{bgPanic: true})
	env.active("a", nil)
	deadline := time.Now().Add(testTimeout)
	for {
		h, err := env.client.CheckHealth(testContext(t), &platformv1.CheckHealthRequest{Context: lifecycleContext("a")})
		if err != nil {
			t.Fatal(err)
		}
		if h.GetLifecycleState() == platformv1.LifecycleState_LIFECYCLE_STATE_FAILED {
			if h.GetStatus() != platformv1.CheckHealthResponse_STATUS_NOT_SERVING {
				t.Fatalf("status = %v", h.GetStatus())
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("state = %v, want FAILED", h.GetLifecycleState())
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestInitializeRegistrationPanicIsError(t *testing.T) {
	env := newPanicEnv(t, &panicPlugin{badRegistration: true})
	_, err := env.initializeWith("a", nil, 0)
	wantCode(t, err, codes.FailedPrecondition)
	if !strings.Contains(err.Error(), "nil invoke handler") {
		t.Fatalf("err = %v", err)
	}
}
