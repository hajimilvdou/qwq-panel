// SPDX-License-Identifier: AGPL-3.0-only

package operations

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/qwq-panel/qwq/internal/actor"
	"github.com/qwq-panel/qwq/internal/platform/problem"
)

func (e *testEnv) runWithKey(a actor.Actor, key, value string) (*Response, error) {
	return e.svc.Run(e.ctx, RunRequest{
		Actor: a, Action: actionWrite, Target: Target{Subject: resourceSubject},
		Args:        mustJSON(e.t, map[string]any{"value": value}),
		Idempotency: Idempotency{Key: key, Method: "POST", Route: "/api/v1/test/write"},
	})
}

func TestIdempotentReplay(t *testing.T) {
	e := newTestEnv(t)
	key := e.newKey()
	first, err := e.runWithKey(humanActor(), key, "one")
	if err != nil {
		t.Fatal(err)
	}
	second, err := e.runWithKey(humanActor(), key, "one")
	if err != nil {
		t.Fatalf("replay: %v", err)
	}
	if !second.Replayed {
		t.Fatal("second request was not marked as a replay")
	}
	if second.Status != first.Status || !bytes.Equal(second.Body, first.Body) {
		t.Fatalf("replay body differs:\n%s\n%s", first.Body, second.Body)
	}
	if second.OperationID != first.OperationID {
		t.Fatalf("replay operation = %q, want %q", second.OperationID, first.OperationID)
	}
	if second.Operation == nil || second.Operation.ID != first.Operation.ID {
		t.Fatal("replay did not hydrate the operation")
	}
	if e.countOperations() != 1 {
		t.Fatalf("operations = %d, want 1", e.countOperations())
	}
}

func TestIdempotencyKeyReused(t *testing.T) {
	e := newTestEnv(t)
	key := e.newKey()
	if _, err := e.runWithKey(humanActor(), key, "one"); err != nil {
		t.Fatal(err)
	}
	_, err := e.runWithKey(humanActor(), key, "two")
	if !problem.HasCode(err, problem.IdempotencyKeyReused) {
		t.Fatalf("got %v, want IDEMPOTENCY_KEY_REUSED", err)
	}
	if e.countOperations() != 1 {
		t.Fatalf("operations = %d", e.countOperations())
	}
}

func TestIdempotencyInProgress(t *testing.T) {
	e := newTestEnv(t)
	release := make(chan struct{})
	started := make(chan struct{}, 1)
	e.dispatcher.invokeFn = func(context.Context, PluginInvokeRequest) (PluginInvokeResponse, error) {
		started <- struct{}{}
		<-release
		return PluginInvokeResponse{Result: json.RawMessage(`{"ok":true}`)}, nil
	}
	key := e.newKey()
	req := RunRequest{
		Actor: humanActor(), Action: actionPlugin, Target: nodeTarget(),
		Args:        mustJSON(t, map[string]any{"mode": "full"}),
		Idempotency: Idempotency{Key: key, Method: "POST", Route: "/api/v1/test/plugin"},
	}
	done := make(chan error, 1)
	go func() {
		_, err := e.svc.Run(e.ctx, req)
		done <- err
	}()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("the first request never reached the dispatcher")
	}
	_, err := e.svc.Run(e.ctx, req)
	if !problem.HasCode(err, problem.IdempotencyInProgress) {
		t.Fatalf("concurrent duplicate = %v, want IDEMPOTENCY_IN_PROGRESS", err)
	}
	var pe *problem.Error
	if !asProblemError(err, &pe) || pe.RetryAfterSec <= 0 {
		t.Fatalf("problem = %+v", pe)
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatalf("first request: %v", err)
	}
	third, err := e.svc.Run(e.ctx, req)
	if err != nil {
		t.Fatalf("replay after completion: %v", err)
	}
	if !third.Replayed {
		t.Fatal("the completed request was not replayed")
	}
}

func TestIdempotencyStoresBusinessErrors(t *testing.T) {
	e := newTestEnv(t)
	if _, err := e.run(humanActor(), actionWrite, Target{Subject: resourceSubject}, map[string]any{"value": "one"}); err != nil {
		t.Fatal(err)
	}
	key := e.newKey()
	req := RunRequest{
		Actor: humanActor(), Action: actionWrite, Target: Target{Subject: resourceSubject},
		Args:             mustJSON(t, map[string]any{"value": "two"}),
		ExpectedRevision: "1", // stale on purpose
		Idempotency:      Idempotency{Key: key, Method: "POST", Route: "/api/v1/test/write"},
	}
	if _, err := e.svc.Run(e.ctx, req); !problem.HasCode(err, problem.RevisionConflict) {
		t.Fatalf("got %v, want REVISION_CONFLICT", err)
	}
	replay, err := e.svc.Run(e.ctx, req)
	if err != nil {
		t.Fatalf("replay of a stored 4xx: %v", err)
	}
	if !replay.Replayed || replay.Status != 409 {
		t.Fatalf("replay = %+v", replay)
	}
	if !strings.Contains(string(replay.Body), string(problem.RevisionConflict)) {
		t.Fatalf("stored body = %s", replay.Body)
	}
}

func TestIdempotencyExpiry(t *testing.T) {
	e := newTestEnv(t)
	key := e.newKey()
	if _, err := e.runWithKey(humanActor(), key, "one"); err != nil {
		t.Fatal(err)
	}
	e.clock.Advance(25 * time.Hour)
	swept, err := e.svc.Sweep(e.ctx)
	if err != nil {
		t.Fatal(err)
	}
	if swept.IdempotencyKeys < 1 {
		t.Fatalf("sweep = %+v", swept)
	}
	// The key is gone, so the same key starts a fresh request.
	if _, err := e.runWithKey(humanActor(), key, "one"); err != nil {
		t.Fatalf("reuse after expiry: %v", err)
	}
	if e.countOperations() != 2 {
		t.Fatalf("operations = %d, want 2", e.countOperations())
	}
}

func TestIdempotencyQuota(t *testing.T) {
	e := newTestEnv(t)
	e.svc.cfg.IdempotencyKeysPerPrincipal = 2
	if _, err := e.runWithKey(humanActor(), e.newKey(), "one"); err != nil {
		t.Fatal(err)
	}
	if _, err := e.runWithKey(humanActor(), e.newKey(), "two"); err != nil {
		t.Fatal(err)
	}
	_, err := e.runWithKey(humanActor(), e.newKey(), "three")
	if !problem.HasCode(err, problem.RateLimited) {
		t.Fatalf("third key = %v, want RATE_LIMITED", err)
	}
	var pe *problem.Error
	if !asProblemError(err, &pe) || pe.Limit == nil || pe.Limit.Name != "idempotency_keys_per_principal" {
		t.Fatalf("problem = %+v", pe)
	}
}

func TestStaleInProgressKeyIsReclaimed(t *testing.T) {
	e := newTestEnv(t)
	key := e.newKey()
	req := RunRequest{
		Actor: humanActor(), Action: actionWrite, Target: Target{Subject: resourceSubject},
		Args:        mustJSON(t, map[string]any{"value": "one"}),
		Idempotency: Idempotency{Key: key, Method: "POST", Route: "/api/v1/test/write"},
	}
	// Simulate a crash: the key was bound but the request never completed.
	act, ok := e.catalog.Action(actionWrite)
	if !ok {
		t.Fatal("missing action")
	}
	args, err := canonicalObject(req.Args)
	if err != nil {
		t.Fatal(err)
	}
	claim, replay, err := e.svc.claimIdempotency(e.ctx, req.Actor, req.Idempotency, runFingerprint(req, act, args))
	if err != nil || claim == nil || replay != nil {
		t.Fatalf("claim = %+v, %+v, %v", claim, replay, err)
	}
	e.clock.Advance(11 * time.Minute)
	resp, err := e.svc.Run(e.ctx, req)
	if err != nil {
		t.Fatalf("reclaim: %v", err)
	}
	if resp.Replayed {
		t.Fatal("a stale claim must be taken over, not replayed")
	}
	if e.countOperations() != 1 {
		t.Fatalf("operations = %d", e.countOperations())
	}
}

// ---------------------------------------------------------------------------
// OPS-02：operation 创建后幂等键不再释放或被接管（at-most-once）
// ---------------------------------------------------------------------------

func pluginRunRequest(t *testing.T, key string) RunRequest {
	return RunRequest{
		Actor: humanActor(), Action: actionPlugin, Target: nodeTarget(),
		Args:        mustJSON(t, map[string]any{"mode": "full"}),
		Idempotency: Idempotency{Key: key, Method: "POST", Route: "/api/v1/test/plugin"},
	}
}

func TestIdempotencyTimeoutDoesNotReexecute(t *testing.T) {
	e := newTestEnv(t)
	e.dispatcher.invokeFn = func(context.Context, PluginInvokeRequest) (PluginInvokeResponse, error) {
		return PluginInvokeResponse{}, context.DeadlineExceeded
	}
	req := pluginRunRequest(t, e.newKey())
	_, err := e.svc.Run(e.ctx, req)
	var first *problem.Error
	if !asProblemError(err, &first) || first.OperationID == "" {
		t.Fatalf("first = %v, want a problem with operation_id", err)
	}
	resp, err := e.svc.Run(e.ctx, req)
	if err != nil {
		t.Fatalf("retry: %v", err)
	}
	if !resp.Replayed || resp.OperationID != first.OperationID {
		t.Fatalf("retry = %+v, want a replay of %s", resp, first.OperationID)
	}
	if n := e.dispatcher.invokeCount(); n != 1 {
		t.Fatalf("invokes = %d, want 1", n)
	}
	if n := e.countOperations(); n != 1 {
		t.Fatalf("operations = %d, want 1", n)
	}
}

func TestIdempotencyStaleInProgressBoundReplays(t *testing.T) {
	e := newTestEnv(t)
	release := make(chan struct{})
	started := make(chan struct{}, 1)
	e.dispatcher.invokeFn = func(context.Context, PluginInvokeRequest) (PluginInvokeResponse, error) {
		started <- struct{}{}
		<-release
		return PluginInvokeResponse{Result: json.RawMessage(`{"ok":true}`)}, nil
	}
	req := pluginRunRequest(t, e.newKey())
	done := make(chan error, 1)
	go func() {
		_, err := e.svc.Run(e.ctx, req)
		done <- err
	}()
	<-started
	e.clock.Advance(e.svc.Config().IdempotencyInProgressTTL + time.Minute)
	resp, err := e.svc.Run(e.ctx, req)
	close(release)
	if err != nil {
		t.Fatalf("retry: %v", err)
	}
	if !resp.Replayed || resp.Status != 202 || resp.Operation == nil {
		t.Fatalf("retry = %+v, want a 202 replay of the bound operation", resp)
	}
	if err := <-done; err != nil {
		t.Fatalf("first: %v", err)
	}
	if n := e.countOperations(); n != 1 {
		t.Fatalf("operations = %d, want 1", n)
	}
	if n := e.dispatcher.invokeCount(); n != 1 {
		t.Fatalf("invokes = %d, want 1", n)
	}
}

func TestIdempotencyCanceledCtxStillCompletes(t *testing.T) {
	e := newTestEnv(t)
	ctx, cancel := context.WithCancel(e.ctx)
	defer cancel()
	e.dispatcher.invokeFn = func(context.Context, PluginInvokeRequest) (PluginInvokeResponse, error) {
		cancel()
		return PluginInvokeResponse{Result: json.RawMessage(`{"ok":true}`)}, nil
	}
	req := pluginRunRequest(t, e.newKey())
	_, _ = e.svc.Run(ctx, req)
	resp, err := e.svc.Run(e.ctx, req)
	if err != nil {
		t.Fatalf("retry: %v", err)
	}
	if !resp.Replayed || resp.Status != 200 {
		t.Fatalf("retry = %d replayed=%v, want the stored 200", resp.Status, resp.Replayed)
	}
	if n := e.dispatcher.invokeCount(); n != 1 {
		t.Fatalf("invokes = %d, want 1", n)
	}
}
