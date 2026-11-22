// SPDX-License-Identifier: AGPL-3.0-only

package operations

import (
	"context"
	"testing"

	"github.com/qwq-panel/qwq/internal/actor"
	"github.com/qwq-panel/qwq/internal/platform/problem"
)

// ======================== 取消不得扩大主体或权限 ========================

func TestCancelRechecksCallerAndOriginalAction(t *testing.T) {
	otherHuman := actor.Actor{Kind: actor.Human, ID: "usr_other", SessionID: "ses_other"}
	otherAI := actor.Actor{Kind: actor.AIAgent, ID: "dlg_other", OnBehalfOf: "usr_human"}
	cases := []struct {
		name                 string
		owner, caller        actor.Actor
		denyCancel, denyWork bool
		want                 problem.Code
	}{
		{"human_owner", humanActor(), humanActor(), false, false, ""},
		{"owner_loses_cancel", humanActor(), humanActor(), true, false, problem.PermissionDenied},
		{"cross_owner_lacks_original", humanActor(), otherHuman, false, true, problem.PermissionDenied},
		{"authorized_cross_owner", humanActor(), otherHuman, false, false, ""},
		{"ai_only_owns_its_operation", humanActor(), otherAI, false, false, problem.NotFound},
		{"ai_other_delegation", aiActor(), otherAI, false, false, problem.NotFound},
		{"ai_own_cancellation", aiActor(), aiActor(), true, false, ""},
		{"service_owner", serviceActor(), serviceActor(), false, false, ""},
		{"service_loses_cancel", serviceActor(), serviceActor(), true, false, problem.PermissionDenied},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newTestEnv(t)
			accepted, err := e.run(tc.owner, actionJob, nodeTarget(), nil)
			if err != nil {
				t.Fatalf("create pending operation: %v", err)
			}
			before := e.operation(accepted.OperationID)
			keys := e.countRows("idempotency_keys")
			if tc.denyCancel {
				e.authorizer.denyFor(tc.caller, "host.operations.cancel", "cancel permission revoked")
			}
			if tc.denyWork {
				e.authorizer.denyFor(tc.caller, actionJob, "original action denied")
			}
			_, err = e.svc.Cancel(e.ctx, CancelRequest{
				Actor: tc.caller, OperationID: accepted.OperationID,
				Idempotency: Idempotency{Key: e.newKey(), Method: "POST", Route: "/fixture/cancel"},
			})
			if tc.want == "" {
				if err != nil {
					t.Fatalf("cancel: %v", err)
				}
				if e.operation(accepted.OperationID).Status != Canceled {
					t.Fatal("authorized cancellation did not finish the pending operation")
				}
				return
			}
			if !problem.HasCode(err, tc.want) {
				t.Fatalf("cancel error = %v, want %s", err, tc.want)
			}
			after := e.operation(accepted.OperationID)
			if after.Status != before.Status || after.CancelRequested || e.countRows("idempotency_keys") != keys {
				t.Fatal("denied cancellation changed the operation or claimed an idempotency key")
			}
		})
	}
}

func TestCancelReplayDoesNotBypassRevocation(t *testing.T) {
	e := newTestEnv(t)
	accepted, err := e.run(humanActor(), actionHigh, Target{Subject: resourceSubject}, map[string]any{"value": "pending"})
	if err != nil {
		t.Fatal(err)
	}
	request := CancelRequest{Actor: humanActor(), OperationID: accepted.OperationID,
		Idempotency: Idempotency{Key: e.newKey(), Method: "POST", Route: "/fixture/cancel"}}
	if _, err := e.svc.Cancel(e.ctx, request); err != nil {
		t.Fatal(err)
	}
	e.authorizer.denyFor(request.Actor, "host.operations.cancel", "cancel permission revoked")
	if _, err := e.svc.Cancel(e.ctx, request); !problem.HasCode(err, problem.PermissionDenied) {
		t.Fatalf("replay after revocation = %v, want PERMISSION_DENIED", err)
	}
}

// ======================== 公共出口脱敏不更改持久化结果 ========================

func TestOperationResultBoundaryIsSharedByGetListWait(t *testing.T) {
	e := newTestEnv(t)
	accepted, err := e.run(humanActor(), actionWrite, Target{Subject: resourceSubject}, map[string]any{"value": "private"})
	if err != nil {
		t.Fatal(err)
	}
	reader := actor.Actor{Kind: actor.Human, ID: "usr_reader", SessionID: "ses_reader"}
	e.authorizer.denyFor(reader, actionWrite, "original action denied")
	got, err := e.svc.Get(e.ctx, reader, accepted.OperationID)
	if err != nil || len(got.Result) != 0 || got.Status != Succeeded {
		t.Fatalf("redacted Get = %+v, %v", got, err)
	}
	page, err := e.svc.List(e.ctx, reader, ListFilter{Limit: 10})
	if err != nil || len(page.Items) != 1 || len(page.Items[0].Result) != 0 {
		t.Fatalf("redacted List = %+v, %v", page, err)
	}
	waited, err := e.svc.Wait(e.ctx, reader, accepted.OperationID, 0)
	if err != nil || len(waited.Result) != 0 {
		t.Fatalf("redacted Wait = %+v, %v", waited, err)
	}
	if len(e.operation(accepted.OperationID).Result) == 0 {
		t.Fatal("public redaction erased the stored result")
	}
	owner := humanActor()
	owner.SessionID = "ses_refreshed"
	owned, err := e.svc.Get(e.ctx, owner, accepted.OperationID)
	if err != nil || len(owned.Result) == 0 {
		t.Fatalf("owner lost its result after session refresh: %v", err)
	}
	e.authorizer.allow(reader, actionWrite)
	allowed, err := e.svc.Get(e.ctx, reader, accepted.OperationID)
	if err != nil || len(allowed.Result) == 0 {
		t.Fatalf("authorized reader did not receive the result: %v", err)
	}
	e.svc.authorizer = nil
	closed, err := e.svc.Get(e.ctx, reader, accepted.OperationID)
	if err != nil || len(closed.Result) != 0 {
		t.Fatalf("missing authorizer exposed a cross-principal result: %v", err)
	}
}

type subjectResultAuthorizer struct{ calls int }

func (a *subjectResultAuthorizer) Authorize(_ context.Context, _ actor.Actor, action Action, target Target) error {
	a.calls++
	if action.ID != actionWrite || target.Subject != "test_resources/allowed" {
		return problem.New(problem.PermissionDenied, "exact subject denied")
	}
	return nil
}

func TestResultAuthorizationCacheKeepsExactSubjectScope(t *testing.T) {
	e := newTestEnv(t)
	accepted, err := e.run(humanActor(), actionWrite, Target{Subject: resourceSubject}, map[string]any{"value": "private"})
	if err != nil {
		t.Fatal(err)
	}
	base := e.operation(accepted.OperationID)
	checker := &subjectResultAuthorizer{}
	e.svc.authorizer = checker
	reader := actor.Actor{Kind: actor.Human, ID: "usr_reader"}
	redact := e.svc.ResultRedactor(e.ctx, reader)
	for _, subject := range []string{"test_resources/allowed", "test_resources/denied", "test_resources/allowed"} {
		current := *base
		current.Target.Subject = subject
		redact(&current)
		if (len(current.Result) > 0) != (subject == "test_resources/allowed") {
			t.Fatalf("result authorization crossed the exact scope %q", subject)
		}
	}
	if checker.calls != 2 {
		t.Fatalf("authorization calls = %d, want two exact scopes", checker.calls)
	}
}
