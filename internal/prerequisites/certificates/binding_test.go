// SPDX-License-Identifier: AGPL-3.0-only

package certificates

import (
	"context"
	"errors"
	"testing"

	"github.com/qwq-panel/qwq/internal/prerequisites/fault"
	"github.com/qwq-panel/qwq/internal/tlsmgr"
)

func (f fixture) bind(t *testing.T, attemptID string, number uint64) Result {
	t.Helper()
	view, err := f.manager.Get(context.Background(), f.caller, "certificate-1")
	if err != nil {
		t.Fatal(err)
	}
	result, err := f.manager.BindCertificate(context.Background(), BindRequest{Caller: f.caller, CertificateID: "certificate-1", AttemptID: attemptID, ExpectedRevision: view.Revision, Generation: number, Consumer: consumer()})
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func TestBindingGenerationChangeKeepsStableReference(t *testing.T) {
	f := newFixture(t)
	f.issue(t, "stable-issue-1")
	bound := f.bind(t, "stable-bind-1", 1)
	f.issue(t, "stable-issue-2")
	f.bindings.unstableID = true
	view, err := f.manager.Get(context.Background(), f.caller, "certificate-1")
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.manager.BindCertificate(context.Background(), BindRequest{Caller: f.caller, CertificateID: view.ID, AttemptID: "unstable-bind-2", ExpectedRevision: view.Revision, Generation: 2, Consumer: consumer()})
	requireCode(t, err, "BINDING_DENIED")
	view, err = f.manager.Get(context.Background(), f.caller, view.ID)
	if err != nil || view.Bindings[0].Host.ID != bound.View.Bindings[0].Host.ID || view.Bindings[0].RunningGeneration != 1 || f.bindings.deploys != 1 {
		t.Fatal("unstable host proof changed a saved consumer or deployed")
	}
}

func TestBindingRequiresHostIdentityAndProductionTrust(t *testing.T) {
	f := newFixture(t)
	issued := f.issue(t, "bind-issue-1")
	f.bindings.wrongNode = true
	_, err := f.manager.BindCertificate(context.Background(), BindRequest{Caller: f.caller, CertificateID: "certificate-1", AttemptID: "bad-host-1", ExpectedRevision: issued.View.Revision, Generation: 1, Consumer: consumer()})
	requireCode(t, err, "BINDING_DENIED")
	if f.bindings.deploys != 0 {
		t.Fatal("wrong host proof reached deployment")
	}
	f.bindings.wrongNode = false
	bound := f.bind(t, "bind-1", 1)
	if bound.Stage != "bound" || !bound.View.ConsumersReady || bound.View.Bindings[0].RunningGeneration != 1 {
		t.Fatal("confirmed runtime binding not saved")
	}
	other := newFixture(t)
	result, err := other.manager.GenerateTestCertificate(context.Background(), TestRequest{Caller: other.caller, CertificateID: "certificate-1", AttemptID: "test-1", ExpectedRevision: MissingRevision,
		Spec: Spec{SANs: []string{"proxy.example.com"}, Purpose: tlsmgr.TestServerTLS}})
	if err != nil {
		t.Fatal(err)
	}
	_, err = other.manager.BindCertificate(context.Background(), BindRequest{Caller: other.caller, CertificateID: "certificate-1", AttemptID: "test-bind-1", ExpectedRevision: result.View.Revision, Generation: 1, Consumer: consumer()})
	requireCode(t, err, "TEST_CERTIFICATE_DENIED")
	if other.bindings.confirms != 0 {
		t.Fatal("test certificate reached production binding confirmation")
	}
}

func TestIssuanceSuccessDeploymentFailureKeepsOldRunningGeneration(t *testing.T) {
	f := newFixture(t)
	f.issue(t, "issue-1")
	f.bind(t, "bind-1", 1)
	newer := f.issue(t, "issue-2")
	f.bindings.failDeploy = true
	result, err := f.manager.BindCertificate(context.Background(), BindRequest{Caller: f.caller, CertificateID: "certificate-1", AttemptID: "deploy-fail-1", ExpectedRevision: newer.View.Revision, Generation: 2, Consumer: consumer()})
	requireCode(t, err, "DEPLOYMENT_FAILED")
	if result.Stage != "issued_deployment_failed" || result.View.CurrentGeneration != 2 || result.View.Bindings[0].RunningGeneration != 1 || !result.View.Bindings[0].Verified {
		t.Fatalf("failed deploy = %v", result)
	}
}

func TestRollbackIsPinnedAndPreviousGenerationIsProtected(t *testing.T) {
	f := newFixture(t)
	f.issue(t, "issue-1")
	f.bind(t, "bind-1", 1)
	f.issue(t, "issue-2")
	bound := f.bind(t, "bind-2", 2)
	if bound.View.Bindings[0].PreviousGeneration != 1 {
		t.Fatal("previous generation was not retained")
	}
	_, err := f.manager.RemoveGeneration(context.Background(), f.caller, "certificate-1", "remove-protected-1", bound.View.Revision, 1)
	requireCode(t, err, "GENERATION_IN_USE")
	result, err := f.manager.RollbackBinding(context.Background(), f.caller, "certificate-1", bound.View.Bindings[0].Host.ID, "rollback-1", bound.View.Revision)
	if err != nil || result.View.CurrentGeneration != 2 || result.View.Bindings[0].RunningGeneration != 1 || result.View.Bindings[0].PreviousGeneration != 2 {
		t.Fatalf("rollback = %v, %v", result, err)
	}
}

func TestLostDeploymentAndFailedStateCommitReconcileWithoutRedeploy(t *testing.T) {
	f := newFixture(t)
	issued := f.issue(t, "issue-1")
	f.bindings.lostReply = true
	puts := 0
	f.repository.FailPut = func(_ int) error {
		puts++
		if puts == 2 {
			return errors.New("final binding commit failed")
		}
		return nil
	}
	result, err := f.manager.BindCertificate(context.Background(), BindRequest{Caller: f.caller, CertificateID: "certificate-1", AttemptID: "lost-deploy-1", ExpectedRevision: issued.View.Revision, Generation: 1, Consumer: consumer()})
	requireCode(t, err, "OUTCOME_UNKNOWN")
	if result.View.Pending != "bind" || len(result.View.Bindings) != 0 {
		t.Fatal("uncommitted runtime generation was presented as bound")
	}
	view, err := f.manager.Get(context.Background(), f.caller, "certificate-1")
	if err != nil {
		t.Fatal(err)
	}
	result, err = f.manager.Recover(context.Background(), f.caller, "certificate-1", view.Revision, nil)
	if err != nil || !result.View.ConsumersReady || result.View.Bindings[0].RunningGeneration != 1 {
		t.Fatalf("recover = %v, %v", result, err)
	}
	if f.bindings.deploys != 1 {
		t.Fatal("deployment was blindly repeated")
	}
}

func TestUnconfirmedDeploymentNeverReportsConsumersReady(t *testing.T) {
	f := newFixture(t)
	f.issue(t, "issue-1")
	f.bind(t, "bind-1", 1)
	newer := f.issue(t, "issue-2")
	f.bindings.lostReply, f.bindings.failReconcile = true, true
	result, err := f.manager.BindCertificate(context.Background(), BindRequest{Caller: f.caller, CertificateID: "certificate-1", AttemptID: "unknown-deploy-1", ExpectedRevision: newer.View.Revision, Generation: 2, Consumer: consumer()})
	requireCode(t, err, "OUTCOME_UNKNOWN")
	if result.View.ConsumersReady || result.View.Bindings[0].Verified {
		t.Fatal("unconfirmed running generation reported ready")
	}
}

func TestHostSnapshotReferencesAndRemovalRecovery(t *testing.T) {
	f := newFixture(t)
	f.issue(t, "issue-1")
	newer := f.issue(t, "issue-2")
	f.bindings.external = []Reference{{Generation: 1, Consumer: consumer(), Kind: "previous"}}
	_, err := f.manager.RemoveGeneration(context.Background(), f.caller, "certificate-1", "host-ref-1", newer.View.Revision, 1)
	requireCode(t, err, "RESOURCE_IN_USE")
	if f.materials.removes != 0 {
		t.Fatal("host previous reference lost its material")
	}
	f.bindings.external = nil
	puts := 0
	f.repository.FailPut = func(_ int) error {
		puts++
		if puts == 2 {
			return errors.New("history commit failed")
		}
		return nil
	}
	view, err := f.manager.RemoveGeneration(context.Background(), f.caller, "certificate-1", "remove-1", newer.View.Revision, 1)
	requireCode(t, err, "OUTCOME_UNKNOWN")
	if view.Pending != "remove" {
		t.Fatal("partial deletion lost recovery state")
	}
	view, err = f.manager.Get(context.Background(), f.caller, "certificate-1")
	if err != nil {
		t.Fatal(err)
	}
	view, err = f.manager.RecoverGenerationRemoval(context.Background(), f.caller, "certificate-1", view.Revision)
	if err != nil || len(view.Generations) != 1 || view.Generations[0].Number != 2 || view.Pending != "" {
		t.Fatalf("remove recovery = %v, %v", view, err)
	}
}

func TestUnbindRejectsRunningConsumerAndRetainsReferences(t *testing.T) {
	f := newFixture(t)
	f.issue(t, "issue-1")
	bound := f.bind(t, "bind-1", 1)
	f.bindings.inUse = true
	view, err := f.manager.UnbindCertificate(context.Background(), f.caller, "certificate-1", bound.View.Bindings[0].Host.ID, "unbind-1", bound.View.Revision)
	requireCode(t, err, "RESOURCE_IN_USE")
	if len(view.Bindings) != 1 || f.bindings.removes != 0 {
		t.Fatal("running consumer was detached")
	}
	f.bindings.inUse = false
	view, err = f.manager.UnbindCertificate(context.Background(), f.caller, "certificate-1", view.Bindings[0].Host.ID, "unbind-2", view.Revision)
	if err != nil || len(view.Bindings) != 0 || f.bindings.removes != 1 {
		t.Fatalf("unbind = %v, %v", view, err)
	}
}

func TestRevocationPreventsBindingAndExpandedAutomaticIssue(t *testing.T) {
	f := newFixture(t)
	issued := f.issue(t, "issue-1")
	f.authorization.revoke()
	_, err := f.manager.BindCertificate(context.Background(), BindRequest{Caller: f.caller, CertificateID: "certificate-1", AttemptID: "revoked-1", ExpectedRevision: issued.View.Revision, Generation: 1, Consumer: consumer()})
	requireCode(t, err, "PERMISSION_DENIED")
	if f.bindings.confirms != 0 {
		t.Fatal("revoked caller obtained host binding")
	}
	other := newFixture(t)
	service := other.caller
	service.PolicyID, service.PolicyRevision = "renewal-1", "policy-1"
	_, err = other.manager.Issue(context.Background(), IssueRequest{Caller: service, CertificateID: "new-certificate", AttemptID: "service-1", ExpectedRevision: MissingRevision, Scope: other.scope}, nil)
	requireCode(t, err, "POLICY_SCOPE_DENIED")
	if other.authority.issues != 0 {
		t.Fatal("automatic actor created a new resource")
	}
	_, err = other.manager.GenerateTestCertificate(context.Background(), TestRequest{Caller: service, CertificateID: "new-certificate", AttemptID: "service-2", ExpectedRevision: MissingRevision,
		Spec: Spec{SANs: other.scope.Spec.SANs, Purpose: tlsmgr.TestServerTLS}})
	if fault.Code(err) != "POLICY_SCOPE_DENIED" {
		t.Fatalf("automatic test issue = %v", err)
	}
}

func TestCertificateDeletionRequiresConsumerAndHostReferenceRelease(t *testing.T) {
	f := newFixture(t)
	f.issue(t, "delete-issue-1")
	bound := f.bind(t, "delete-bind-1", 1)
	err := f.manager.RemoveCertificate(context.Background(), f.caller, "certificate-1", "delete-1", bound.View.Revision)
	requireCode(t, err, "RESOURCE_IN_USE")
	if f.materials.removes != 0 {
		t.Fatal("bound certificate material was deleted")
	}
	unbound, err := f.manager.UnbindCertificate(context.Background(), f.caller, "certificate-1", bound.View.Bindings[0].Host.ID, "delete-unbind-1", bound.View.Revision)
	if err != nil {
		t.Fatal(err)
	}
	f.bindings.external = []Reference{{Generation: 1, Consumer: consumer(), Kind: "pending"}}
	err = f.manager.RemoveCertificate(context.Background(), f.caller, "certificate-1", "delete-2", unbound.Revision)
	requireCode(t, err, "RESOURCE_IN_USE")
	f.bindings.external = nil
	if err := f.manager.RemoveCertificate(context.Background(), f.caller, "certificate-1", "delete-3", unbound.Revision); err != nil {
		t.Fatal(err)
	}
	_, err = f.manager.Get(context.Background(), f.caller, "certificate-1")
	requireCode(t, err, "NOT_FOUND")
}

func TestUnbindFinalCommitFailureKeepsRecoverableBinding(t *testing.T) {
	f := newFixture(t)
	f.issue(t, "unbind-issue-1")
	bound := f.bind(t, "unbind-bind-1", 1)
	puts := 0
	f.repository.FailPut = func(_ int) error {
		puts++
		if puts == 2 {
			return errors.New("unbind final commit failure")
		}
		return nil
	}
	view, err := f.manager.UnbindCertificate(context.Background(), f.caller, "certificate-1", bound.View.Bindings[0].Host.ID, "unbind-loss-1", bound.View.Revision)
	requireCode(t, err, "OUTCOME_UNKNOWN")
	if view.Pending != "unbind" || len(view.Bindings) != 1 {
		t.Fatal("failed unbind lost recovery state")
	}
	view, err = f.manager.Get(context.Background(), f.caller, "certificate-1")
	if err != nil {
		t.Fatal(err)
	}
	view, err = f.manager.RecoverUnbind(context.Background(), f.caller, "certificate-1", view.Revision)
	if err != nil || view.Pending != "" || len(view.Bindings) != 0 {
		t.Fatalf("unbind recovery = %v, %v", view, err)
	}
}
