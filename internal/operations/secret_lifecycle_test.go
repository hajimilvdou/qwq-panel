// SPDX-License-Identifier: AGPL-3.0-only

package operations

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/qwq-panel/qwq/internal/platform/problem"
	"github.com/qwq-panel/qwq/internal/secrets"
)

func installRealArgumentProtector(t *testing.T, e *testEnv) *secrets.Store {
	t.Helper()
	keys, err := secrets.LoadKeyRing(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	store, err := secrets.New(secrets.Options{DB: e.db, Keys: keys})
	if err != nil {
		t.Fatal(err)
	}
	e.svc.argumentProtector, err = secrets.NewOperationProtector(e.ctx, store)
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func assertPublicReferencesHidden(t *testing.T, value any) {
	t.Helper()
	out, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(out, []byte("$secret")) || bytes.Contains(out, []byte("sec_")) || bytes.Contains(out, []byte(operationSecretSentinel)) {
		t.Fatal("public JSON contains a secret value or internal reference")
	}
}

func TestSecretPlanApprovalExecutionAndRetention(t *testing.T) {
	e := newTestEnv(t)
	store := installRealArgumentProtector(t, e)
	target := secretAction(e, actionPluginH)
	e.dispatcher.planFn = func(_ context.Context, req PluginPlanRequest) (Preview, error) {
		return Preview{Changes: []PlannedChange{{Kind: "update", Subject: "config", Before: req.Payload, After: req.Payload}}}, nil
	}
	plan, err := e.svc.CreatePlan(e.ctx, PlanRequest{
		Actor: humanActor(), Action: actionPluginH, Target: target,
		Args: mustJSON(t, map[string]any{"password": operationSecretSentinel, "user": "alice"}),
	})
	if err != nil {
		t.Fatal(err)
	}
	var args map[string]any
	if err := json.Unmarshal(plan.Args, &args); err != nil {
		t.Fatal(err)
	}
	ref, ok := secrets.RefFromObject(args["password"])
	if !ok {
		t.Fatal("private plan did not retain its execution reference")
	}
	assertPublicReferencesHidden(t, plan)
	loaded, err := e.svc.GetPlan(e.ctx, humanActor(), plan.ID)
	if err != nil || !bytes.Equal(loaded.Args, plan.Args) {
		t.Fatal("reading a public plan changed private execution arguments")
	}
	assertPublicReferencesHidden(t, loaded)
	response, err := e.svc.ExecutePlan(e.ctx, ExecutePlanRequest{
		Actor: humanActor(), PlanID: plan.ID, Idempotency: Idempotency{Key: e.newKey()},
	})
	if err != nil || response.Operation == nil || response.Operation.Status != AwaitingApproval {
		t.Fatal("secret plan could not create its approval operation")
	}
	approval, err := e.svc.GetApproval(e.ctx, humanActor(), response.Operation.ApprovalID)
	if err != nil {
		t.Fatal(err)
	}
	assertPublicReferencesHidden(t, approval)
	page, err := e.svc.ListApprovals(e.ctx, humanActor(), ApprovalFilter{})
	if err != nil || len(page.Items) != 1 {
		t.Fatal("secret approval listing failed")
	}
	assertPublicReferencesHidden(t, page)
	response, err = e.svc.Decide(e.ctx, DecisionRequest{
		Actor: humanActor(), ApprovalID: approval.ID, Decision: DecisionApprove,
		ExpectedRevision: approval.Revision, Idempotency: Idempotency{Key: e.newKey()},
	})
	if err != nil || response.Operation == nil || response.Operation.Status != Succeeded {
		t.Fatal("approved plan lost its execution arguments")
	}
	assertPublicReferencesHidden(t, response.Approval)
	e.clock.Advance(2*e.svc.cfg.PlanTTL + time.Millisecond)
	swept, err := e.svc.Sweep(e.ctx)
	if err != nil || swept.ExpiredPlans != 1 {
		t.Fatal("expired plan was not swept")
	}
	value, err := store.RevealOwned(e.ctx, ref, "plugins/"+pluginID, "plugin.operation")
	value.Clear()
	if err != nil {
		t.Fatal("plan expiry deleted a secret still held by its operation")
	}
	e.clock.Advance(e.svc.cfg.RetentionOperations + time.Millisecond)
	swept, err = e.svc.Sweep(e.ctx)
	if err != nil || swept.PrunedOperations != 1 {
		t.Fatal("finished secret operation was not pruned")
	}
	_, err = store.RevealOwned(e.ctx, ref, "plugins/"+pluginID, "plugin.operation")
	if !problem.HasCode(err, problem.NotFound) {
		t.Fatal("the last operation reference left orphan ciphertext")
	}
}

func TestFailedSecretPreviewLeavesNoCiphertext(t *testing.T) {
	for _, invalidJSON := range []bool{false, true} {
		e := newTestEnv(t)
		installRealArgumentProtector(t, e)
		target := secretAction(e, actionPluginH)
		e.dispatcher.planFn = func(context.Context, PluginPlanRequest) (Preview, error) {
			if invalidJSON {
				return Preview{Changes: []PlannedChange{{Kind: "update", Subject: "config", Before: json.RawMessage(`{`)}}}, nil
			}
			return Preview{}, errors.New("TEST-ONLY-preview-failure")
		}
		_, err := e.svc.CreatePlan(e.ctx, PlanRequest{
			Actor: humanActor(), Action: actionPluginH, Target: target,
			Args: mustJSON(t, map[string]any{"password": operationSecretSentinel}),
		})
		if err == nil {
			t.Fatal("the fixture did not reject the preview")
		}
		var count int
		if err := e.db.Reader().QueryRowContext(e.ctx, `SELECT COUNT(*) FROM secrets WHERE purpose='plugin.operation'`).Scan(&count); err != nil || count != 0 {
			t.Fatal("failed preview retained orphan operation ciphertext")
		}
	}
}

func TestLegacyReplaySecretBodyIsRedactedBeforeHydrationGuards(t *testing.T) {
	service := &Service{}
	for _, response := range []*Response{
		{Body: json.RawMessage(`{"facts":{"args":{"password":{"$secret":"private-reference"}}}}`)},
		{Operation: &Operation{}, Body: json.RawMessage(`{"facts":{"args":{"password":{"$secret":"private-reference"}}}}`)},
	} {
		service.hydrateReplay(t.Context(), response)
		if bytes.Contains(response.Body, []byte("$secret")) || bytes.Contains(response.Body, []byte("private-reference")) {
			t.Fatal("a legacy replay bypassed the public body boundary")
		}
	}
	ordinary := &Response{Body: json.RawMessage(`{"z":1,"a":2}`)}
	before := bytes.Clone(ordinary.Body)
	service.hydrateReplay(t.Context(), ordinary)
	if !bytes.Equal(before, ordinary.Body) {
		t.Fatal("an ordinary replay lost its exact response bytes")
	}
}
