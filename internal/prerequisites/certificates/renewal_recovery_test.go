// SPDX-License-Identifier: AGPL-3.0-only

package certificates

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/qwq-panel/qwq/internal/prerequisites/fault"
)

// unfinished 模拟宿主在完成审计与阶段提交前终止，保留真实持久状态。
func (r *renewalFixture) unfinished(t *testing.T) (context.Context, context.CancelFunc, renewalPolicy, Caller) {
	t.Helper()
	r.due(t)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	policy, err := r.service.claim(ctx, "policy-1", cancel)
	if err != nil {
		t.Fatal(err)
	}
	caller, err := r.operations.Begin(ctx, policy.ID, "1", policy.Job.AttemptID, policy.Scope)
	if err != nil {
		t.Fatal(err)
	}
	policy, err = r.service.attachOperation(ctx, policy, caller)
	if err != nil {
		t.Fatal(err)
	}
	view, err := r.manager.Get(ctx, caller, policy.Scope.CertificateID)
	if err != nil {
		t.Fatal(err)
	}
	id, err := renewalAttemptID("renewcert", policy)
	if err != nil {
		t.Fatal(err)
	}
	intent := &renewalIssue{AttemptID: id, ExpectedRevision: view.Revision}
	policy.Issue = intent
	hash, err := fingerprint(r.service.issueRequest(caller, policy))
	if err != nil {
		t.Fatal(err)
	}
	intent.Hash = hash
	policy, err = r.service.checkpoint(ctx, policy, func(current *renewalPolicy) { current.Issue = intent })
	if err != nil {
		t.Fatal(err)
	}
	return ctx, cancel, policy, caller
}

func TestRenewalCrashAfterGenerationCommitRecoversOriginalIssuance(t *testing.T) {
	r := newRenewalFixture(t, consumer())
	ctx, cancel, policy, caller := r.unfinished(t)
	issued, err := r.manager.Issue(ctx, r.service.issueRequest(caller, policy), nil)
	if err != nil || issued.View.CurrentGeneration != 2 {
		t.Fatalf("issue before crash: %v", err)
	}
	if r.policy(t).DeployGeneration != 0 {
		t.Fatal("test did not preserve the generation/policy commit window")
	}
	cancel()
	r.clock.Advance(r.service.jobTimeout + time.Second)
	r.restart(t)
	if err := r.service.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	view, err := r.manager.Get(context.Background(), r.caller, "certificate-1")
	if err != nil || view.CurrentGeneration != 2 || view.Bindings[0].RunningGeneration != 2 || r.authority.issues != 2 {
		t.Fatal("crash recovery followed latest generation or sent another CA order")
	}
	if r.policy(t).RunNumber != 2 {
		t.Fatal("recovery reused the crashed service operation")
	}
}

func TestRenewalExpiredLeaseReconcilesUncertainOriginalAttempt(t *testing.T) {
	r := newRenewalFixture(t, consumer())
	ctx, cancel, policy, caller := r.unfinished(t)
	r.authority.lostReply = true
	result, err := r.manager.Issue(ctx, r.service.issueRequest(caller, policy), nil)
	requireCode(t, err, "OUTCOME_UNKNOWN")
	if result.View.Pending != "issue" {
		t.Fatal("test did not preserve an uncertain CA write")
	}
	cancel()
	r.clock.Advance(r.service.jobTimeout + time.Second)
	r.restart(t)
	if err := r.service.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	if r.authority.issues != 2 || r.authority.reconciles != 1 {
		t.Fatal("expired lease replaced the original uncertain CA attempt")
	}
	view, err := r.manager.Get(context.Background(), r.caller, "certificate-1")
	if err != nil || view.CurrentGeneration != 2 || !view.ConsumersReady {
		t.Fatalf("recovered view: %v, error: %v", view, err)
	}
}

func TestRenewalFailedTargetCheckpointRecoversWithoutReissuing(t *testing.T) {
	r := newRenewalFixture(t, consumer())
	r.private.FailPut = func(count int) error {
		if count == 5 {
			return errors.New("disk full")
		}
		return nil
	}
	r.due(t)
	if err := r.service.Tick(context.Background()); err == nil {
		t.Fatal("target checkpoint failure was ignored")
	}
	if r.policy(t).Issue == nil || r.policy(t).DeployGeneration != 0 {
		t.Fatal("failed target checkpoint discarded the original issue intent")
	}
	r.private.FailPut = nil
	r.due(t)
	if err := r.service.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	if r.authority.issues != 2 {
		t.Fatal("checkpoint recovery sent another CA order")
	}
}

func TestRenewalRevocationCancelsInFlightWorkAndBlocksNextStep(t *testing.T) {
	r := newRenewalFixture(t, consumer())
	r.due(t)
	r.authority.started, r.authority.release = make(chan struct{}, 1), make(chan struct{})
	workCtx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	done := make(chan error, 1)
	go func() { done <- r.service.Tick(workCtx) }()
	select {
	case <-r.authority.started:
	case <-time.After(time.Second):
		t.Fatal("renewal did not enter the controlled CA call")
	}
	view, err := r.service.Revoke(context.Background(), r.caller, "policy-1", "1")
	if err != nil || view.Enabled {
		t.Fatalf("revoke: %v", err)
	}
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("revoked worker reported success")
		}
	case <-time.After(time.Second):
		t.Fatal("revoked worker did not stop")
	}
	before := r.authority.issues
	if err := r.service.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	if r.authority.issues != before || r.policy(t).Enabled || !r.policy(t).NextAt.IsZero() {
		t.Fatal("revoked policy dispatched another automatic task")
	}
	certificate, err := r.manager.Get(context.Background(), r.caller, "certificate-1")
	if err != nil || certificate.CurrentGeneration != 1 || certificate.Bindings[0].RunningGeneration != 1 {
		t.Fatal("revocation changed the running generation")
	}
}

func TestRenewalCleanupFailureIsRetriedBeforeDeployment(t *testing.T) {
	r := newRenewalFixture(t, consumer())
	r.due(t)
	r.authority.cleanupFailure = fault.New("DNS_CLEANUP_FAILED", "cleanup unavailable")
	requireCode(t, r.service.Tick(context.Background()), "DNS_CLEANUP_FAILED")
	policy, err := r.service.Get(context.Background(), r.caller, "policy-1")
	if err != nil || policy.Status != "issued_cleanup_failed" || policy.DeployGeneration != 2 {
		t.Fatal("cleanup failure was confused with deployment failure")
	}
	if r.bindings.deploys != 1 {
		t.Fatal("consumer deployment started before challenge cleanup was confirmed")
	}
	r.authority.cleanupFailure = nil
	r.due(t)
	if err := r.service.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	if r.authority.issues != 2 || r.bindings.deploys != 2 {
		t.Fatal("cleanup retry reissued a certificate or failed to deploy")
	}
}

func TestRenewalDoesNotAdoptAnotherOperationsGeneration(t *testing.T) {
	r := newRenewalFixture(t)
	ctx, cancel, _, _ := r.unfinished(t)
	view, err := r.manager.Get(ctx, r.caller, "certificate-1")
	if err != nil {
		t.Fatal(err)
	}
	_, err = r.manager.Issue(ctx, IssueRequest{Caller: r.caller, CertificateID: view.ID, AttemptID: "human-issue", ExpectedRevision: view.Revision, Scope: r.fixture.scope}, nil)
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	r.clock.Advance(r.service.jobTimeout + time.Second)
	r.restart(t)
	requireCode(t, r.service.Tick(context.Background()), "REVISION_CONFLICT")
	if r.policy(t).DeployGeneration != 0 || r.authority.issues != 2 {
		t.Fatal("renewal adopted a foreign generation or issued again")
	}
}
