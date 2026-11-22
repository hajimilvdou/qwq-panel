// SPDX-License-Identifier: Apache-2.0

package pluginsdk

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"google.golang.org/grpc"

	platformv1 "github.com/qwq-panel/qwq/sdk/gen/qwq/platform/v1"
)

func TestHostCallContextIsFilled(t *testing.T) {
	env := newTestEnv(t, newTestPlugin())
	env.initialize("a", nil)
	env.start("a")

	resp := invokeOp(t, env, "a", "op-context", "en", "test.secret", []byte(`{}`))
	if resp.GetError() != nil {
		t.Fatalf("response = %v", resp.GetError())
	}
	calls := env.host.callsOf("RevealSecret")
	if len(calls) != 1 {
		t.Fatalf("%d RevealSecret calls", len(calls))
	}
	c := calls[0]
	if c.Handle != handleFor("a") || c.OperationID != "op-context" || c.TraceID != "trace-op-context" {
		t.Fatalf("HostCallContext = %+v", c)
	}
}

func TestKVCompareAndSwapConflict(t *testing.T) {
	env := newTestEnv(t, newTestPlugin())
	env.initialize("a", nil)
	env.start("a")
	inst := env.instance("a")

	rev, err := inst.Host().PutState(context.Background(), "key", []byte(`"v1"`), PutOption{})
	if err != nil || rev == "" {
		t.Fatalf("PutState = %q, %v", rev, err)
	}
	_, err = inst.Host().PutState(context.Background(), "key", []byte(`"v2"`), PutOption{ExpectedRevision: "stale"})
	if !IsConflict(err) {
		t.Fatalf("stale PutState error = %v, want REVISION_CONFLICT", err)
	}
	if CodeOf(err) != "REVISION_CONFLICT" {
		t.Fatalf("CodeOf = %q", CodeOf(err))
	}
	if _, err := inst.Host().PutState(context.Background(), "key", []byte(`"v3"`), PutOption{MustNotExist: true}); !IsConflict(err) {
		t.Fatalf("must_not_exist on an existing key = %v", err)
	}
}

func TestKVListPaging(t *testing.T) {
	env := newTestEnv(t, newTestPlugin())
	env.initialize("a", nil)
	env.start("a")
	for idx := 0; idx < 250; idx++ {
		env.host.seedKV(handleFor("a"), fmt.Sprintf("item/%03d", idx), "1")
	}
	resp := invokeOp(t, env, "a", "op-list", "en", "test.list", []byte(`{}`))
	if resp.GetError() != nil {
		t.Fatalf("response = %v", resp.GetError())
	}
	var out listResponse
	if err := unmarshalJSON(resp.GetPayloadJson(), &out); err != nil {
		t.Fatal(err)
	}
	if out.Count != 250 || len(out.Keys) != 250 {
		t.Fatalf("count = %d, keys = %d", out.Count, len(out.Keys))
	}
	for idx, key := range out.Keys {
		if want := fmt.Sprintf("item/%03d", idx); key != want {
			t.Fatalf("key %d = %q, want %q", idx, key, want)
		}
	}
}

func TestConsumeEventsAcknowledges(t *testing.T) {
	env := newTestEnv(t, newTestPlugin())
	env.initialize("a", nil)
	env.start("a")
	env.host.setSubscribeEvents(func(_ *platformv1.SubscribeEventsRequest, stream grpc.ServerStreamingServer[platformv1.SubscribeEventsResponse]) error {
		for idx := 1; idx <= 2; idx++ {
			if err := stream.Send(&platformv1.SubscribeEventsResponse{Event: &platformv1.Event{
				EventId: fmt.Sprintf("e%d", idx), Sequence: uint64(idx), Type: fmt.Sprintf("test.e%d", idx),
			}}); err != nil {
				return err
			}
		}
		return nil
	})
	resp := invokeOp(t, env, "a", "op-sub", "en", "test.subscribe", mustJSON(subscribeRequest{Subscription: "sub-1"}))
	if resp.GetError() != nil {
		t.Fatalf("response = %v", resp.GetError())
	}
	var out subscribeResponse
	if err := unmarshalJSON(resp.GetPayloadJson(), &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Types) != 2 || out.Types[0] != "test.e1" || out.Types[1] != "test.e2" {
		t.Fatalf("types = %v", out.Types)
	}
	env.host.mu.Lock()
	defer env.host.mu.Unlock()
	if len(env.host.acks) != 2 || env.host.acks[0] != 1 || env.host.acks[1] != 2 {
		t.Fatalf("acks = %v", env.host.acks)
	}
	if len(env.host.subs) != 1 || env.host.subs[0] != "sub-1" {
		t.Fatalf("subscriptions = %v", env.host.subs)
	}
}

func TestRevealSecretNeedsADispatchedOperation(t *testing.T) {
	env := newTestEnv(t, newTestPlugin())
	env.initialize("a", nil)
	env.start("a")
	_, err := env.instance("a").Host().RevealSecret(t.Context(), "db-password", "test")
	if CodeOf(err) != "MISSING_OPERATION_ID" {
		t.Fatalf("error = %v", err)
	}
	if n := env.host.count("RevealSecret"); n != 0 {
		t.Fatalf("the host received %d RevealSecret calls", n)
	}

	// A plugin without a Host connection gets ErrNoHost instead of a panic.
	var noHost Host
	_, _, _, err = noHost.GetState(t.Context(), "k")
	if !errors.Is(err, ErrNoHost) {
		t.Fatalf("no-host error = %v", err)
	}
}

func TestHostServiceWrappers(t *testing.T) {
	env := newTestEnv(t, newTestPlugin())
	env.initialize("a", nil)
	env.start("a")
	host := env.instance("a").Host()

	config, rev, err := host.GetConfig(t.Context(), "")
	if err != nil || rev != "1" || !strings.Contains(string(config), "greeting") {
		t.Fatalf("GetConfig = %s @%s, %v", config, rev, err)
	}
	if err := host.WriteAudit(t.Context(), AuditRecord{
		Action: "test.action", Subject: "value", Outcome: platformv1.AuditOutcome_AUDIT_OUTCOME_SUCCESS,
	}); err != nil {
		t.Fatalf("WriteAudit: %v", err)
	}
	env.host.mu.Lock()
	audits := len(env.host.audits)
	env.host.mu.Unlock()
	if audits != 1 {
		t.Fatalf("%d audit records", audits)
	}

	published, err := host.PublishEvent(t.Context(), EventDraft{
		Type: "test.alert", SchemaVersion: "1", Subject: "value", Payload: []byte(`{"level":"low"}`),
	})
	if err != nil || published.GetEventId() == "" {
		t.Fatalf("PublishEvent = %v, %v", published, err)
	}
	if _, err := host.PublishEvent(t.Context(), EventDraft{Type: "resource.changed", Subject: "value"}); CodeOf(err) != "PROTOCOL_ERROR" {
		t.Fatalf("reserved event type error = %v", err)
	}
	if err := host.ReportChanges(t.Context(), ResourceChange{Subject: "a/b", Revision: "9"}); err != nil {
		t.Fatalf("ReportChanges: %v", err)
	}
	calls := env.host.callsOf("ReportChanges")
	if len(calls) != 1 || calls[0].Subject != "a/b" {
		t.Fatalf("ReportChanges calls = %+v", calls)
	}
	if err := host.ReportChanges(t.Context(), ResourceChange{Subject: "../escape"}); CodeOf(err) != "PROTOCOL_ERROR" {
		t.Fatalf("invalid ReportChanges subject = %v", err)
	}
	if n := len(env.host.callsOf("ReportChanges")); n != 1 {
		t.Fatalf("the host received %d ReportChanges calls", n)
	}
}

func TestPlanCannotWriteHostState(t *testing.T) {
	p := newTestPlugin()
	p.planWrites = true
	env := newTestEnv(t, p)
	env.active("a", nil)

	resp, err := env.client.PlanOperation(testContext(t), &platformv1.PlanOperationRequest{
		Context: operationContext("a", "op-plan-write", "en"), Operation: "test.set", ApiVersion: "v1",
		PayloadJson: mustJSON(map[string]string{"value": "x"}),
	})
	if err != nil || resp.GetError() != nil {
		t.Fatalf("PlanOperation: %v %v", err, resp.GetError())
	}
	planErr := p.planWriteErrNow()
	if CodeOf(planErr) != "PLAN_SIDE_EFFECT" {
		t.Fatalf("plan-time PutState error = %v", planErr)
	}
	if n := env.host.count("PutState"); n != 0 {
		t.Fatalf("the host saw %d PutState calls during planning", n)
	}
}

func TestKVListLargeValues(t *testing.T) {
	env := newTestEnv(t, newTestPlugin())
	env.ready("a", nil)
	value := `"` + strings.Repeat("v", 1<<20-2) + `"`
	for idx := 0; idx < 5; idx++ {
		env.host.seedKV(handleFor("a"), fmt.Sprintf("big/%d", idx), value)
	}
	kv := env.instance("a").Host().KV()
	// A host that cannot fit the page answers RESOURCE_EXHAUSTED; repeating the
	// call cannot help, so it must not be retryable.
	_, err := kv.List(testContext(t), "big/", 100)
	var domain *Error
	if !errors.As(err, &domain) || domain.Code != "RESOURCE_EXHAUSTED" || domain.Retryable {
		t.Fatalf("oversized page = %#v", err)
	}
	entries, err := kv.List(testContext(t), "big/", 2)
	if err != nil {
		t.Fatalf("List with a small page: %v", err)
	}
	if len(entries) != 5 {
		t.Fatalf("%d entries", len(entries))
	}
}
