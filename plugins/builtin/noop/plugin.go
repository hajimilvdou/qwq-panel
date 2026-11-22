// SPDX-License-Identifier: AGPL-3.0-only

// The empty plugin (P2-T4) is also the reference implementation of
// sdk/pluginsdk: every lifecycle hook is empty, and the three operations show
// the typed handler API, the job progress API and a plannable write with an
// optimistic concurrency guard. The process entry point is main.go.
package main

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/qwq-panel/qwq/sdk/pluginsdk"
)

//go:embed manifest.json
var manifestJSON []byte

// buildVersion is injected at link time (-X main.buildVersion=...) for release
// packages. The embedded manifest.json keeps the development version 0.1.0, so
// the descriptor reported by GetDescriptor matches the package a release build
// produced. Empty keeps the checked-in version for tests and development.
var buildVersion string

// failInitialize is injected at link time only by tests/e2e/build.sh. A
// non-empty value builds a package whose every instance fails Initialize, so
// the end-to-end test can prove a failed update keeps the old version running.
var failInitialize string

// Manifest returns the embedded manifest.json. The SDK parses it and derives
// PluginDescriptor from it, so the plugin cannot advertise an operation it does
// not implement.
func Manifest() []byte {
	raw := append([]byte(nil), manifestJSON...)
	if buildVersion != "" {
		raw = bytes.Replace(raw, []byte(`"version": "0.1.0"`),
			[]byte(`"version": "`+buildVersion+`"`), 1)
	}
	return raw
}

// Plugin is the empty plugin.
type Plugin struct{}

// New returns the plugin implementation.
func New() *Plugin { return &Plugin{} }

// NewInstance registers the operations of one instance. The instance embeds
// *pluginsdk.InstanceBase, which is what makes it a pluginsdk.Instance; all
// lifecycle hooks below are empty on purpose and are shown as the template for
// plugins that need them.
func (p *Plugin) NewInstance(_ context.Context, info pluginsdk.InstanceInfo) (pluginsdk.Instance, error) {
	if failInitialize != "" {
		return nil, errors.New("noop: built to fail Initialize (e2e fixture)")
	}
	inst := &instance{InstanceBase: pluginsdk.NewInstanceBase(info)}
	pluginsdk.HandleInvoke(inst, "noop.echo", inst.echo)
	pluginsdk.HandleJob(inst, "noop.wait", inst.wait)
	pluginsdk.HandleInvoke(inst, "noop.set", inst.set)
	pluginsdk.HandlePlan(inst, "noop.set", inst.planSet)
	return inst, nil
}

// instance is the author state of one instance. The only state of the empty
// plugin is the last applied config, kept to show the hot-apply template.
type instance struct {
	*pluginsdk.InstanceBase

	config atomic.Pointer[config]
}

// config is the (empty) configuration object of schemas/config.schema.json.
type config struct{}

// ApplyConfig is the template of a hot config apply: validate the candidate
// first, then replace the internal snapshot atomically so running handlers see
// either the old or the new config. The SDK records the revision after it
// returns nil.
func (i *instance) ApplyConfig(ctx context.Context, cfg pluginsdk.Config) error {
	call, _ := pluginsdk.CallFromContext(ctx)
	var next config
	dec := json.NewDecoder(bytes.NewReader(cfg.JSON))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&next); err != nil {
		e := pluginsdk.Validation(pluginsdk.FieldViolation{
			Pointer: "", Code: "INVALID",
			Message: pluginsdk.Localize(call.Locale, "配置必须是空对象", "the config must be an empty object"),
		})
		e.Message = pluginsdk.Localize(call.Locale, "配置不合法", "invalid config")
		return e
	}
	i.config.Store(&next)
	return nil
}

// Start is called after Initialize; the instance serves requests afterwards.
func (i *instance) Start(context.Context) error { return nil }

// Activate is called after Start; background work may begin here.
func (i *instance) Activate(context.Context) error { return nil }

// Deactivate stops background work; the instance keeps serving requests.
func (i *instance) Deactivate(context.Context) error { return nil }

// Stop is the final teardown after the instance stopped accepting requests.
func (i *instance) Stop(context.Context) error { return nil }

// Release frees the instance; host-side cleanup never depends on it.
func (i *instance) Release(context.Context) error { return nil }

// Health reports domain readiness. The lifecycle state already decides
// SERVING/NOT_SERVING; the message is shown to users.
func (i *instance) Health(context.Context) pluginsdk.Health {
	return pluginsdk.Health{Message: "noop is empty"}
}

// ---------- noop.echo (invoke, read) ----------

type echoRequest struct {
	Message string `json:"message"`
}

type echoResponse struct {
	Message    string `json:"message"`
	InstanceID string `json:"instance_id"`
	Attempt    uint32 `json:"attempt"`
}

func (i *instance) echo(ctx context.Context, in echoRequest) (echoResponse, error) {
	call, _ := pluginsdk.CallFromContext(ctx)
	if n := utf8.RuneCountInString(in.Message); n == 0 || n > 64 {
		e := pluginsdk.Validation(pluginsdk.FieldViolation{
			Pointer: "/message", Code: "LENGTH",
			Message: pluginsdk.Localize(call.Locale, "长度必须为 1 到 64 个字符", "must be 1 to 64 characters"),
		})
		e.Message = pluginsdk.Localize(call.Locale, "请求参数不合法", "invalid request")
		return echoResponse{}, e
	}
	return echoResponse{Message: in.Message, InstanceID: i.ID(), Attempt: call.Attempt}, nil
}

// ---------- noop.wait (job, read) ----------

type waitRequest struct {
	// StepDelayMS delays each step so a test can cancel the job mid-flight.
	StepDelayMS int `json:"step_delay_ms"`
}

type waitResult struct {
	Steps int `json:"steps"`
}

var waitSteps = []struct{ id, zh, en string }{
	{"prepare", "准备", "prepare"},
	{"work", "执行", "work"},
	{"finish", "收尾", "finish"},
}

// wait reports three progress messages and then the terminal result. It stops
// immediately when the stream context is canceled (cancel, timeout or a broken
// stream), leaving no work behind.
func (i *instance) wait(ctx context.Context, in waitRequest, progress pluginsdk.Progress) (waitResult, error) {
	call, _ := pluginsdk.CallFromContext(ctx)
	if in.StepDelayMS < 0 || in.StepDelayMS > 60000 {
		e := pluginsdk.Validation(pluginsdk.FieldViolation{
			Pointer: "/step_delay_ms", Code: "RANGE",
			Message: pluginsdk.Localize(call.Locale, "必须在 0 到 60000 之间", "must be between 0 and 60000"),
		})
		e.Message = pluginsdk.Localize(call.Locale, "请求参数不合法", "invalid request")
		return waitResult{}, e
	}
	for idx, step := range waitSteps {
		if err := ctx.Err(); err != nil {
			return waitResult{}, err
		}
		if in.StepDelayMS > 0 {
			timer := time.NewTimer(time.Duration(in.StepDelayMS) * time.Millisecond)
			select {
			case <-timer.C:
			case <-ctx.Done():
				timer.Stop()
				return waitResult{}, ctx.Err()
			}
			timer.Stop()
		}
		if err := progress(pluginsdk.ProgressUpdate{
			Percent:   uint32(100 * (idx + 1) / (len(waitSteps) + 1)),
			Message:   pluginsdk.Localize(call.Locale, step.zh, step.en),
			Step:      step.id,
			StepIndex: uint32(idx + 1),
			StepCount: uint32(len(waitSteps)),
		}); err != nil {
			return waitResult{}, err
		}
	}
	return waitResult{Steps: len(waitSteps)}, nil
}

// ---------- noop.set (invoke, write, plannable) ----------

type setRequest struct {
	Value string `json:"value"`
}

type setResponse struct {
	Value    string `json:"value"`
	Revision string `json:"revision"`
}

const (
	maxValueRunes = 256
	valueKey      = "value"
)

func validateValue(call pluginsdk.Call, value string) error {
	if n := utf8.RuneCountInString(value); n == 0 || n > maxValueRunes {
		e := pluginsdk.Validation(pluginsdk.FieldViolation{
			Pointer: "/value", Code: "LENGTH",
			Message: pluginsdk.Localize(call.Locale, "长度必须为 1 到 256 个字符", "must be 1 to 256 characters"),
		})
		e.Message = pluginsdk.Localize(call.Locale, "请求参数不合法", "invalid request")
		return e
	}
	return nil
}

// set stores one value in the instance KV. The host-supplied precondition is
// checked atomically by the PutState compare-and-swap, so a plan that was
// approved earlier cannot overwrite a value changed in the meantime.
func (i *instance) set(ctx context.Context, in setRequest) (pluginsdk.WithChanges[setResponse], error) {
	call, _ := pluginsdk.CallFromContext(ctx)
	if err := validateValue(call, in.Value); err != nil {
		return pluginsdk.WithChanges[setResponse]{}, err
	}
	var opt pluginsdk.PutOption
	if pc, ok := call.Precondition(valueKey); ok {
		// Revision "" means "must not exist" (platform.proto, Precondition).
		if pc.Revision == "" {
			opt.MustNotExist = true
		} else {
			opt.ExpectedRevision = pc.Revision
		}
	}
	rev, err := i.Host().KV().PutJSON(ctx, valueKey, in.Value, opt)
	if err != nil {
		if pluginsdk.IsConflict(err) {
			e := pluginsdk.PreconditionFailed(valueKey, "")
			e.Message = pluginsdk.Localize(call.Locale, "值已被修改", "the value has changed")
			return pluginsdk.WithChanges[setResponse]{}, e
		}
		return pluginsdk.WithChanges[setResponse]{}, err
	}
	return pluginsdk.WithChanges[setResponse]{
		Value:   setResponse{Value: in.Value, Revision: rev},
		Changes: []pluginsdk.ResourceChange{{Subject: valueKey, Revision: rev, ChangedPointers: []string{"/value"}}},
	}, nil
}

// planSet previews set without writing. The planning call context makes the
// SDK's Host client refuse state writes, so a plan cannot have side effects.
func (i *instance) planSet(ctx context.Context, in setRequest) (pluginsdk.Plan, error) {
	call, _ := pluginsdk.CallFromContext(ctx)
	if err := validateValue(call, in.Value); err != nil {
		return pluginsdk.Plan{}, err
	}
	var current string
	rev, found, err := i.Host().KV().GetJSON(ctx, valueKey, &current)
	if err != nil {
		return pluginsdk.Plan{}, err
	}
	change := pluginsdk.PlannedChange{
		Kind: pluginsdk.ChangeCreate, Subject: valueKey, Pointer: "/value",
		After:      mustJSON(in.Value),
		Reversible: true,
		Description: pluginsdk.Localize(call.Locale,
			"把实例的值设为新内容", "set the instance value"),
	}
	if found {
		change.Kind = pluginsdk.ChangeUpdate
		change.Before = mustJSON(current)
	}
	return pluginsdk.Plan{
		Changes: []pluginsdk.PlannedChange{change},
		// Revision "" means "must not exist".
		Preconditions: []pluginsdk.Precondition{{Subject: valueKey, Revision: rev}},
	}, nil
}

// mustJSON encodes a value that is known to be JSON-encodable.
func mustJSON(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic(fmt.Sprintf("noop: encoding a plan value: %v", err))
	}
	return b
}
