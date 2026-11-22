// SPDX-License-Identifier: Apache-2.0

package pluginsdk

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"sync"
	"time"

	platformv1 "github.com/qwq-panel/qwq/sdk/gen/qwq/platform/v1"
)

// testPlugin is the author implementation used by the SDK tests. Its knobs are
// set before Serve and read concurrently afterwards; each knob has a setter that
// takes the mutex.
type testPlugin struct {
	mu        sync.Mutex
	instances []*testInstance
	lifecycle []string

	newErr      error
	startErr    error
	activateErr error
	deactivate  error

	skip  map[string]bool // operations not registered
	extra []string        // handlers registered for undeclared operations

	background bool
	holdStep   int
	tryGo      bool
	goErr      error
	applyErr   error
	badPercent uint32
	planWrites bool
	planErr    error

	holding     chan string
	exited      chan string
	bgStarted   chan string
	bgStopped   chan string
	deactivated chan string
	holdEcho    chan string
	releaseEcho chan struct{}
}

func newTestPlugin() *testPlugin {
	return &testPlugin{
		skip:        map[string]bool{},
		holding:     make(chan string, 8),
		exited:      make(chan string, 8),
		bgStarted:   make(chan string, 8),
		bgStopped:   make(chan string, 8),
		deactivated: make(chan string, 8),
		holdEcho:    make(chan string, 8),
		releaseEcho: make(chan struct{}),
	}
}

func (p *testPlugin) instancesSnapshot() []*testInstance {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]*testInstance(nil), p.instances...)
}

func (p *testPlugin) lifecycleSnapshot() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.lifecycle...)
}

func (p *testPlugin) record(what string) {
	p.mu.Lock()
	p.lifecycle = append(p.lifecycle, what)
	p.mu.Unlock()
}

func (p *testPlugin) holdStepNow() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.holdStep
}

func (p *testPlugin) goErrNow() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.goErr
}

func (p *testPlugin) planWriteErrNow() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.planErr
}

func (p *testPlugin) badPercentNow() uint32 {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.badPercent
}

func (p *testPlugin) notify(ch chan string, v string) {
	select {
	case ch <- v:
	default:
	}
}

func (p *testPlugin) NewInstance(_ context.Context, info InstanceInfo) (Instance, error) {
	p.mu.Lock()
	if p.newErr != nil {
		err := p.newErr
		p.mu.Unlock()
		return nil, err
	}
	p.mu.Unlock()

	inst := &testInstance{InstanceBase: NewInstanceBase(info), p: p}
	p.mu.Lock()
	p.instances = append(p.instances, inst)
	skip := map[string]bool{}
	for k, v := range p.skip {
		skip[k] = v
	}
	extra := append([]string(nil), p.extra...)
	p.mu.Unlock()

	register := func(name string) bool { return !skip[name] }
	if register("test.echo") {
		HandleInvoke(inst, "test.echo", inst.echo)
	}
	if register("test.raw") {
		inst.HandleInvoke("test.raw", inst.raw)
	}
	if register("test.fail") {
		HandleInvoke(inst, "test.fail", inst.fail)
	}
	if register("test.wait") {
		HandleJob(inst, "test.wait", inst.wait)
	}
	if register("test.apply") {
		HandleJob(inst, "test.apply", inst.apply)
	}
	if register("test.set") {
		HandleInvoke(inst, "test.set", inst.set)
		HandlePlan(inst, "test.set", inst.planSet)
	}
	if register("test.setjob") {
		HandleJob(inst, "test.setjob", inst.setJob)
		HandlePlan(inst, "test.setjob", inst.planSet)
	}
	if register("test.sync") {
		HandleInvoke(inst, "test.sync", inst.sync)
	}
	if register("test.list") {
		HandleInvoke(inst, "test.list", inst.list)
	}
	if register("test.subscribe") {
		HandleInvoke(inst, "test.subscribe", inst.subscribe)
	}
	if register("test.secret") {
		HandleInvoke(inst, "test.secret", inst.secret)
	}
	for _, name := range extra {
		HandleInvoke(inst, name, inst.echo)
	}
	return inst, nil
}

// testInstance embeds *InstanceBase and implements every optional hook.
type testInstance struct {
	*InstanceBase
	p *testPlugin
}

func (i *testInstance) Start(ctx context.Context) error {
	i.p.record(i.ID() + ":start")
	i.p.mu.Lock()
	startErr, tryGo := i.p.startErr, i.p.tryGo
	i.p.mu.Unlock()
	if startErr != nil {
		return startErr
	}
	if tryGo {
		err := i.Go(func(context.Context) {})
		i.p.mu.Lock()
		i.p.goErr = err
		i.p.mu.Unlock()
	}
	return nil
}

func (i *testInstance) Activate(ctx context.Context) error {
	i.p.record(i.ID() + ":activate")
	i.p.mu.Lock()
	actErr, background := i.p.activateErr, i.p.background
	i.p.mu.Unlock()
	if actErr != nil {
		return actErr
	}
	if background {
		if err := i.Go(func(ctx context.Context) {
			i.p.notify(i.p.bgStarted, i.ID())
			<-ctx.Done()
			i.p.notify(i.p.bgStopped, i.ID())
		}); err != nil {
			return err
		}
	}
	return nil
}

func (i *testInstance) Deactivate(ctx context.Context) error {
	i.p.record(i.ID() + ":deactivate")
	i.p.notify(i.p.deactivated, i.ID())
	i.p.mu.Lock()
	err := i.p.deactivate
	i.p.mu.Unlock()
	return err
}

func (i *testInstance) Stop(context.Context) error {
	i.p.record(i.ID() + ":stop")
	return nil
}

func (i *testInstance) Release(context.Context) error {
	i.p.record(i.ID() + ":release")
	return nil
}

func (i *testInstance) Health(context.Context) Health {
	return Health{Message: "test healthy", Details: json.RawMessage(`{"custom":true}`)}
}

func (i *testInstance) ServePublicRoute(_ context.Context, req PublicRouteRequest) (PublicRouteResponse, error) {
	if req.Path == "/error" {
		return PublicRouteResponse{}, Errorf("VALIDATION_FAILED", "bad path")
	}
	return PublicRouteResponse{
		Status:  201,
		Headers: []HTTPHeader{{Name: "x-test", Value: "1"}},
		Body:    []byte("route:" + req.Path),
	}, nil
}

// ---------------- operations ----------------

type echoRequest struct {
	Message string `json:"message"`
}

type echoResponse struct {
	Message    string `json:"message"`
	InstanceID string `json:"instance_id"`
	Attempt    uint32 `json:"attempt"`
	Locale     string `json:"locale"`
}

func (i *testInstance) echo(ctx context.Context, in echoRequest) (echoResponse, error) {
	call, _ := CallFromContext(ctx)
	if in.Message == "" {
		e := Validation(FieldViolation{Pointer: "/message", Code: "REQUIRED",
			Message: Localize(call.Locale, "必须填写", "is required")})
		e.Message = Localize(call.Locale, "请求参数不合法", "invalid request")
		return echoResponse{}, e
	}
	if in.Message == "hold" {
		// Test hook: let the Stop drain tests hold one request in flight.
		i.p.notify(i.p.holdEcho, i.ID())
		select {
		case <-i.p.releaseEcho:
		case <-ctx.Done():
			return echoResponse{}, ctx.Err()
		}
	}
	return echoResponse{Message: in.Message, InstanceID: i.ID(), Attempt: call.Attempt, Locale: call.Locale}, nil
}

func (i *testInstance) raw(_ context.Context, req Request) (Response, error) {
	var in struct {
		Subject string `json:"subject"`
	}
	if err := req.Decode(&in); err != nil {
		return Response{}, err
	}
	return Response{
		Payload: mustJSON(map[string]string{"echo": "raw"}),
		Changes: []ResourceChange{{Subject: in.Subject, Revision: "1"}},
	}, nil
}

func (i *testInstance) fail(context.Context, struct{}) (struct{}, error) {
	return struct{}{}, fmt.Errorf("secret detail: hunter2")
}

type waitRequest struct {
	Steps   int `json:"steps"`
	DelayMS int `json:"delay_ms"`
}

type waitResult struct {
	Steps int `json:"steps"`
}

func (i *testInstance) wait(ctx context.Context, in waitRequest, progress Progress) (waitResult, error) {
	defer i.p.notify(i.p.exited, i.ID())
	steps := in.Steps
	if steps <= 0 {
		steps = 3
	}
	for idx := 1; idx <= steps; idx++ {
		if err := ctx.Err(); err != nil {
			return waitResult{}, err
		}
		percent := uint32(100 * idx / (steps + 1))
		if p := i.p.badPercentNow(); p != 0 && idx == 1 {
			percent = p
		}
		if err := progress(ProgressUpdate{
			Percent: percent, Step: fmt.Sprintf("s%d", idx),
			StepIndex: uint32(idx), StepCount: uint32(steps), Message: fmt.Sprintf("step %d", idx),
		}); err != nil {
			return waitResult{}, err
		}
		if in.DelayMS > 0 {
			select {
			case <-time.After(time.Duration(in.DelayMS) * time.Millisecond):
			case <-ctx.Done():
				return waitResult{}, ctx.Err()
			}
		}
		if i.p.holdStepNow() == idx {
			i.p.notify(i.p.holding, i.ID())
			<-ctx.Done()
			return waitResult{}, ctx.Err()
		}
	}
	return waitResult{Steps: steps}, nil
}

type applyRequest struct {
	Users []string `json:"users"`
}

type applyResult struct {
	AppliedRevision string `json:"applied_revision"`
	Users           int    `json:"users"`
}

func (i *testInstance) apply(ctx context.Context, in applyRequest, progress Progress) (applyResult, error) {
	defer i.p.notify(i.p.exited, i.ID())
	steps := []struct{ id, subject, pointer string }{
		{"render", "config", "/inbounds"},
		{"reload", "runtime", "/status"},
	}
	for idx, step := range steps {
		if err := ctx.Err(); err != nil {
			return applyResult{}, err
		}
		i.p.mu.Lock()
		applyErr := i.p.applyErr
		i.p.mu.Unlock()
		if applyErr != nil && idx == 1 {
			return applyResult{}, applyErr
		}
		change := ResourceChange{Subject: step.subject, Revision: strconv.Itoa(idx + 1), ChangedPointers: []string{step.pointer}}
		if err := progress(ProgressUpdate{
			Percent: uint32(50 * (idx + 1)), Step: step.id, StepIndex: uint32(idx + 1), StepCount: uint32(len(steps)),
			Changes: []ResourceChange{change},
		}); err != nil {
			return applyResult{}, err
		}
		if i.p.holdStepNow() == idx+1 {
			i.p.notify(i.p.holding, i.ID())
			<-ctx.Done()
			return applyResult{}, ctx.Err()
		}
	}
	return applyResult{AppliedRevision: "2", Users: len(in.Users)}, nil
}

type setRequest struct {
	Value string `json:"value"`
}

type setResponse struct {
	Value    string `json:"value"`
	Revision string `json:"revision"`
}

func (i *testInstance) set(ctx context.Context, in setRequest) (WithChanges[setResponse], error) {
	call, _ := CallFromContext(ctx)
	if in.Value == "" {
		e := Validation(FieldViolation{Pointer: "/value", Code: "REQUIRED",
			Message: Localize(call.Locale, "必须填写", "is required")})
		e.Message = Localize(call.Locale, "请求参数不合法", "invalid request")
		return WithChanges[setResponse]{}, e
	}
	var opt PutOption
	if pc, ok := call.Precondition("value"); ok {
		if pc.Revision == "" {
			opt.MustNotExist = true
		} else {
			opt.ExpectedRevision = pc.Revision
		}
	}
	rev, err := i.Host().KV().PutJSON(ctx, "value", in.Value, opt)
	if err != nil {
		if IsConflict(err) {
			e := PreconditionFailed("value", "")
			e.Message = Localize(call.Locale, "资源已被修改", "the resource has changed")
			return WithChanges[setResponse]{}, e
		}
		return WithChanges[setResponse]{}, err
	}
	return WithChanges[setResponse]{
		Value:   setResponse{Value: in.Value, Revision: rev},
		Changes: []ResourceChange{{Subject: "value", Revision: rev, ChangedPointers: []string{"/value"}}},
	}, nil
}

func (i *testInstance) planSet(ctx context.Context, in setRequest) (Plan, error) {
	call, _ := CallFromContext(ctx)
	if in.Value == "" {
		e := Validation(FieldViolation{Pointer: "/value", Code: "REQUIRED",
			Message: Localize(call.Locale, "必须填写", "is required")})
		e.Message = Localize(call.Locale, "请求参数不合法", "invalid request")
		return Plan{}, e
	}
	i.p.mu.Lock()
	planWrites := i.p.planWrites
	i.p.mu.Unlock()
	if planWrites {
		_, err := i.Host().KV().PutJSON(ctx, "plan-probe", "x", PutOption{})
		i.p.mu.Lock()
		i.p.planErr = err
		i.p.mu.Unlock()
	}
	var current string
	rev, found, err := i.Host().KV().GetJSON(ctx, "value", &current)
	if err != nil {
		return Plan{}, err
	}
	change := PlannedChange{Kind: ChangeCreate, Subject: "value", Pointer: "/value",
		After: mustJSON(in.Value), Reversible: true, Description: "set the value"}
	if found {
		change.Kind = ChangeUpdate
		change.Before = mustJSON(current)
	}
	return Plan{
		Changes:       []PlannedChange{change},
		Preconditions: []Precondition{{Subject: "value", Revision: rev}},
	}, nil
}

// setJob is the job-mode variant of set, mirroring scenario three's
// baseline.enable: it checks the plan's precondition atomically, reports the
// change in a progress message and then returns the terminal result.
func (i *testInstance) setJob(ctx context.Context, in setRequest, progress Progress) (setResponse, error) {
	call, _ := CallFromContext(ctx)
	if in.Value == "" {
		e := Validation(FieldViolation{Pointer: "/value", Code: "REQUIRED",
			Message: Localize(call.Locale, "必须填写", "is required")})
		e.Message = Localize(call.Locale, "请求参数不合法", "invalid request")
		return setResponse{}, e
	}
	var opt PutOption
	if pc, ok := call.Precondition("value"); ok {
		if pc.Revision == "" {
			opt.MustNotExist = true
		} else {
			opt.ExpectedRevision = pc.Revision
		}
	}
	rev, err := i.Host().KV().PutJSON(ctx, "value", in.Value, opt)
	if err != nil {
		if IsConflict(err) {
			e := PreconditionFailed("value", "")
			e.Message = Localize(call.Locale, "资源已被修改", "the resource has changed")
			return setResponse{}, e
		}
		return setResponse{}, err
	}
	if err := progress(ProgressUpdate{
		Percent: 60, Step: "write", StepIndex: 1, StepCount: 2,
		Changes: []ResourceChange{{Subject: "value", Revision: rev, ChangedPointers: []string{"/value"}}},
	}); err != nil {
		return setResponse{}, err
	}
	if err := progress(ProgressUpdate{Percent: 90, Step: "verify", StepIndex: 2, StepCount: 2}); err != nil {
		return setResponse{}, err
	}
	return setResponse{Value: in.Value, Revision: rev}, nil
}

type syncRequest struct {
	NodeID string   `json:"node_id"`
	Users  []string `json:"users"`
}

type syncResponse struct {
	CoreOperationID string `json:"core_operation_id"`
	Users           int    `json:"users"`
}

// sync is the controller-side plugin of scenario two: it calls core.apply
// through HostInvokeService, waits for the child job and reports its own change.
func (i *testInstance) sync(ctx context.Context, in syncRequest) (WithChanges[syncResponse], error) {
	defer i.p.notify(i.p.exited, i.ID())
	call, _ := CallFromContext(ctx)
	if len(in.Users) == 0 {
		e := Validation(FieldViolation{Pointer: "/users", Code: "REQUIRED",
			Message: Localize(call.Locale, "至少需要一个用户", "at least one user is required")})
		e.Message = Localize(call.Locale, "请求参数不合法", "invalid request")
		return WithChanges[syncResponse]{}, e
	}
	host := i.Host()
	started, err := host.InvokePlugin(ctx, InvokeRequest{
		TargetPluginID: "core.xray", TargetInstanceID: "default", TargetNodeID: in.NodeID,
		Operation: "core.apply", APIVersion: "v1",
		Payload:        mustJSON(map[string]any{"inbounds": []map[string]any{{"tag": "vless-in", "users": in.Users}}}),
		IdempotencyKey: call.OperationID,
	})
	if err != nil {
		return WithChanges[syncResponse]{}, err
	}
	final, err := host.AwaitOperation(ctx, started.GetOperationId())
	if err != nil {
		if ctx.Err() != nil {
			detached, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
			defer cancel()
			_, _ = host.CancelOperation(detached, started.GetOperationId())
			return WithChanges[syncResponse]{}, ctx.Err()
		}
		return WithChanges[syncResponse]{}, err
	}
	switch final.GetState() {
	case platformv1.OperationState_OPERATION_STATE_SUCCEEDED:
	case platformv1.OperationState_OPERATION_STATE_AWAITING_APPROVAL:
		return WithChanges[syncResponse]{}, Errorf("APPROVAL_REQUIRED", "the core change needs its own approval")
	default:
		if e := final.GetError(); e != nil {
			return WithChanges[syncResponse]{}, &Error{Code: e.GetCode(), Message: e.GetMessage(), Retryable: e.GetRetryable()}
		}
		return WithChanges[syncResponse]{}, Errorf("CORE_FAILED", "the core operation failed")
	}
	var core struct {
		AppliedRevision string `json:"applied_revision"`
	}
	_ = json.Unmarshal(final.GetResultJson(), &core)
	return WithChanges[syncResponse]{
		Value:   syncResponse{CoreOperationID: started.GetOperationId(), Users: len(in.Users)},
		Changes: []ResourceChange{{Subject: "sync-state", Revision: "1", ChangedPointers: []string{"/users"}}},
	}, nil
}

type listResponse struct {
	Count int      `json:"count"`
	Keys  []string `json:"keys"`
}

func (i *testInstance) list(ctx context.Context, _ struct{}) (listResponse, error) {
	entries, err := i.Host().KV().List(ctx, "item/", 7)
	if err != nil {
		return listResponse{}, err
	}
	keys := make([]string, len(entries))
	for idx, e := range entries {
		keys[idx] = e.Key
	}
	return listResponse{Count: len(entries), Keys: keys}, nil
}

type subscribeRequest struct {
	Subscription string `json:"subscription"`
}

type subscribeResponse struct {
	Types []string `json:"types"`
}

func (i *testInstance) subscribe(ctx context.Context, in subscribeRequest) (subscribeResponse, error) {
	var types []string
	err := i.Host().ConsumeEvents(ctx, in.Subscription, []string{"test.*"}, 0, func(e *platformv1.Event) error {
		types = append(types, e.GetType())
		return nil
	})
	return subscribeResponse{Types: types}, err
}

func (i *testInstance) secret(ctx context.Context, _ struct{}) (map[string]string, error) {
	value, err := i.Host().RevealSecret(ctx, "db-password", "test")
	if err != nil {
		return nil, err
	}
	return map[string]string{"value": string(value)}, nil
}

func (i *testInstance) ValidateConfig(_ context.Context, cfg Config) (ConfigValidation, error) {
	if string(cfg.JSON) == `{"bad":true}` {
		return ConfigValidation{
			Violations: []FieldViolation{{Pointer: "/bad", Code: "INVALID", Message: "bad is not allowed"}},
			Warnings:   []FieldViolation{{Pointer: "/bad", Code: "DEPRECATED", Message: "bad is deprecated"}},
		}, nil
	}
	return ConfigValidation{}, nil
}

func (i *testInstance) ApplyConfig(_ context.Context, cfg Config) error {
	if string(cfg.JSON) == `{"fail":true}` {
		return Errorf("VALIDATION_FAILED", "the config cannot be applied")
	}
	return nil
}

// minimalPlugin is the smallest valid author plugin: no optional hooks, no
// operations. It is used for RPCs the test plugin implements but a real
// minimal plugin does not.
type minimalPlugin struct{}

func (minimalPlugin) NewInstance(_ context.Context, info InstanceInfo) (Instance, error) {
	return NewInstanceBase(info), nil
}
