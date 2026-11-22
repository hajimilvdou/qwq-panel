// SPDX-License-Identifier: AGPL-3.0-only

package certificates

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/qwq-panel/qwq/internal/prerequisites/fault"
)

func TestRenewalRunWorksWithoutHTTPSHandshakeAndStops(t *testing.T) {
	r := newRenewalFixture(t, consumer())
	r.due(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	failures := make(chan error, 1)
	go func() {
		defer close(done)
		r.service.Run(ctx, func(err error) {
			select {
			case failures <- err:
			default:
			}
		})
	}()
	defer func() {
		cancel()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("renewal worker did not stop")
		}
	}()
	deadline := time.After(time.Second)
	for r.clock.Waiters() == 0 {
		select {
		case err := <-failures:
			t.Fatal(err)
		case <-deadline:
			t.Fatal("renewal worker did not arm its bounded timer")
		case <-time.After(time.Millisecond):
		}
	}
	view, err := r.manager.Get(context.Background(), r.caller, "certificate-1")
	if err != nil || view.CurrentGeneration != 2 || len(view.Bindings) != 1 || view.Bindings[0].RunningGeneration != 2 || view.Bindings[0].PreviousGeneration != 1 || !view.ConsumersReady {
		t.Fatalf("renewed view: %v, error: %v", view, err)
	}
	if r.operations.begins != 1 || r.operations.finishes != 1 {
		t.Fatal("service operation was not audited exactly once")
	}
}

func TestRenewalNextCycleNeverReusesAnOldAttempt(t *testing.T) {
	r := newRenewalFixture(t)
	for range 2 {
		r.due(t)
		if err := r.service.Tick(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	view, err := r.manager.Get(context.Background(), r.caller, "certificate-1")
	if err != nil || view.CurrentGeneration != 3 || r.authority.issues != 3 {
		t.Fatalf("generation: %d, issues: %d, error: %v", view.CurrentGeneration, r.authority.issues, err)
	}
	if len(r.operations.attempts) != 2 || r.operations.attempts[0] == r.operations.attempts[1] || r.policy(t).RunNumber != 2 {
		t.Fatal("different renewal cycles reused the same attempt")
	}
}

func TestRenewalHonorsCARetryAfterAndExhaustsBoundedAttempts(t *testing.T) {
	r := newRenewalFixture(t, consumer())
	for attempt := 1; attempt <= 3; attempt++ {
		r.due(t)
		retryAt := r.clock.Now().Add(3 * time.Hour)
		r.authority.refused = &fault.Error{Code: "RATE_LIMITED", Detail: "CA limit", NotApplied: true, RetryAt: retryAt}
		requireCode(t, r.service.Tick(context.Background()), "RATE_LIMITED")
		view, err := r.service.Get(context.Background(), r.caller, "policy-1")
		if err != nil || view.Attempts != attempt {
			t.Fatalf("attempt: %d, error: %v", view.Attempts, err)
		}
		if attempt < 3 && view.NextAt.Before(retryAt) {
			t.Fatal("renewal ignored CA Retry-After")
		}
		if attempt == 3 && (!view.Exhausted || !view.NextAt.IsZero() || view.Status != "exhausted") {
			t.Fatal("renewal retries did not stop at their budget")
		}
	}
	if r.authority.issues != 4 || r.operations.begins != 3 {
		t.Fatal("retry budget sent extra CA orders")
	}
	r.clock.Advance(365 * 24 * time.Hour)
	view, err := r.service.Get(context.Background(), r.caller, "policy-1")
	if err != nil || view.Status != "expired" || view.Alert != "certificate_expired" {
		t.Fatalf("expired status: %s, error: %v", view.Status, err)
	}
	certificate, err := r.manager.Get(context.Background(), r.caller, "certificate-1")
	if err != nil || certificate.Ready || certificate.ConsumersReady {
		t.Fatal("expired certificate claimed readiness")
	}
}

func TestRenewalDeploymentFailureKeepsOldRunningGeneration(t *testing.T) {
	r := newRenewalFixture(t, consumer())
	r.due(t)
	r.bindings.failDeploy = true
	requireCode(t, r.service.Tick(context.Background()), "DEPLOYMENT_FAILED")
	view, err := r.manager.Get(context.Background(), r.caller, "certificate-1")
	if err != nil || view.CurrentGeneration != 2 || view.Bindings[0].RunningGeneration != 1 || !view.Bindings[0].Verified {
		t.Fatal("failed deployment did not keep the confirmed old generation")
	}
	policy, err := r.service.Get(context.Background(), r.caller, "policy-1")
	if err != nil || policy.Status != "issued_deployment_failed" || policy.DeployGeneration != 2 {
		t.Fatal("issued/deployment-failed state was not explicit")
	}
	r.due(t)
	r.bindings.failDeploy = false
	if err := r.service.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	view, err = r.manager.Get(context.Background(), r.caller, "certificate-1")
	if err != nil || view.Bindings[0].RunningGeneration != 2 || view.Bindings[0].PreviousGeneration != 1 || r.authority.issues != 2 {
		t.Fatal("deployment retry reissued a certificate or lost the old generation")
	}
}

func TestRenewalPartialDeploymentRetriesOnlyUnreadyConsumers(t *testing.T) {
	second := consumer()
	second.ProfileID = "profile-2"
	r := newRenewalFixture(t, consumer(), second)
	failing := r.scope.Consumers[1]
	r.bindings.failConsumers = map[string]bool{consumerKey(failing): true}
	r.due(t)
	requireCode(t, r.service.Tick(context.Background()), "DEPLOYMENT_FAILED")
	deploys := r.bindings.deploys
	r.bindings.failConsumers = nil
	r.due(t)
	if err := r.service.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	if r.bindings.deploys != deploys+1 || r.authority.issues != 2 {
		t.Fatal("partial retry redeployed healthy consumers or sent another CA order")
	}
	view, err := r.manager.Get(context.Background(), r.caller, "certificate-1")
	if err != nil || !view.ConsumersReady {
		t.Fatalf("partial retry failed: %v", err)
	}
}

func TestRenewalAuditFailureRetriesWithoutAnotherIssuance(t *testing.T) {
	r := newRenewalFixture(t)
	r.operations.finishFailure = true
	r.due(t)
	requireCode(t, r.service.Tick(context.Background()), "RENEWAL_AUDIT_FAILED")
	if r.policy(t).DeployGeneration != 2 {
		t.Fatal("audit failure discarded the issued generation")
	}
	r.operations.finishFailure = false
	r.due(t)
	if err := r.service.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	if r.authority.issues != 2 || r.operations.finishes != 2 {
		t.Fatal("audit retry sent another CA order")
	}
}

func TestRenewalUntrustedOperationErrorsNeverExposePrivateDetails(t *testing.T) {
	r := newRenewalFixture(t)
	r.operations.beginFailure = true
	r.due(t)
	err := r.service.Tick(context.Background())
	requireCode(t, err, "RENEWAL_OPERATION_FAILED")
	if strings.Contains(err.Error(), "DO-NOT-EXPOSE") || r.policy(t).LastError != "RENEWAL_OPERATION_FAILED" || r.authority.issues != 1 {
		t.Fatal("untrusted operation error leaked details or started a CA order")
	}
}
