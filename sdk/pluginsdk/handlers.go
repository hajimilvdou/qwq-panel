// SPDX-License-Identifier: Apache-2.0

package pluginsdk

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
)

// InvokeHandler serves one invoke-mode operation. Most plugins use the typed
// [HandleInvoke] helper instead of writing this signature directly.
type InvokeHandler func(ctx context.Context, req Request) (Response, error)

// JobHandler serves one job-mode operation. progress reports zero or more
// progress messages before the handler returns; the SDK sends exactly one
// terminal message after it.
type JobHandler func(ctx context.Context, req Request, progress Progress) (Result, error)

// PlanHandler previews one plannable operation without side effects.
type PlanHandler func(ctx context.Context, req Request) (Plan, error)

// HandleInvoke registers a typed invoke handler: the JSON payload is decoded
// into In before fn runs and the returned value becomes the response payload.
// Return a [WithChanges] value to attach ResourceChange entries.
//
// Registration must happen inside [Plugin.NewInstance]; late registration
// panics.
func HandleInvoke[In, Out any](inst Instance, name string, fn func(ctx context.Context, in In) (Out, error)) {
	inst.base().HandleInvoke(name, func(ctx context.Context, req Request) (Response, error) {
		var in In
		if err := req.Decode(&in); err != nil {
			return Response{}, err
		}
		out, err := fn(ctx, in)
		if err != nil {
			return Response{}, err
		}
		payload, changes, err := encodeResult(any(out))
		if err != nil {
			return Response{}, fmt.Errorf("encode invoke result: %w", err)
		}
		return Response{Payload: payload, Changes: changes}, nil
	})
}

// HandleJob registers a typed job handler. The handler reports progress with
// the given Progress; its return value becomes the terminal result JSON.
// Return a [WithChanges] value to attach changes to the terminal message.
func HandleJob[In, Out any](inst Instance, name string, fn func(ctx context.Context, in In, progress Progress) (Out, error)) {
	inst.base().HandleJob(name, func(ctx context.Context, req Request, progress Progress) (Result, error) {
		var in In
		if err := req.Decode(&in); err != nil {
			return Result{}, err
		}
		out, err := fn(ctx, in, progress)
		if err != nil {
			return Result{}, err
		}
		payload, changes, err := encodeResult(any(out))
		if err != nil {
			return Result{}, fmt.Errorf("encode job result: %w", err)
		}
		return Result{Payload: payload, Changes: changes}, nil
	})
}

// HandlePlan registers a typed plan handler. A declared operation with
// plannable=true must have exactly one plan handler; the SDK checks this at
// Initialize time.
func HandlePlan[In any](inst Instance, name string, fn func(ctx context.Context, in In) (Plan, error)) {
	inst.base().HandlePlan(name, func(ctx context.Context, req Request) (Plan, error) {
		var in In
		if err := req.Decode(&in); err != nil {
			return Plan{}, err
		}
		return fn(ctx, in)
	})
}

// encodeResult marshals a typed handler's result. A [WithChanges] result also
// yields the resource changes it carries; json.RawMessage passes through
// unchanged.
func encodeResult(v any) ([]byte, []ResourceChange, error) {
	if v == nil {
		return nil, nil, nil
	}
	if w, ok := v.(withChanges); ok {
		return w.encodeTyped()
	}
	payload, err := encodeJSON(v)
	return payload, nil, err
}

// encodeJSON marshals v. nil is encoded as no payload; json.RawMessage must
// already be valid JSON.
func encodeJSON(v any) ([]byte, error) {
	if v == nil {
		return nil, nil
	}
	if raw, ok := v.(json.RawMessage); ok {
		if !json.Valid(raw) {
			return nil, fmt.Errorf("json.RawMessage is not valid JSON")
		}
		return append([]byte(nil), raw...), nil
	}
	return json.Marshal(v)
}

// decodePayload decodes an operation payload into v. An empty payload is the
// zero value, which keeps operations without a request body simple.
func decodePayload(payload []byte, locale string, v any) error {
	if len(bytes.TrimSpace(payload)) == 0 {
		return nil
	}
	if err := json.Unmarshal(payload, v); err != nil {
		return Validation(FieldViolation{
			Pointer: "",
			Code:    "INVALID_JSON",
			Message: Localize(locale, "请求不是 JSON 对象或字段类型不匹配", "the request is not a JSON object or has the wrong field types"),
		})
	}
	return nil
}
