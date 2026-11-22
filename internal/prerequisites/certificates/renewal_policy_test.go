// SPDX-License-Identifier: AGPL-3.0-only

package certificates

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/qwq-panel/qwq/internal/prerequisites/fault"
	"github.com/qwq-panel/qwq/internal/prerequisites/store"
)

func TestRenewalServiceActorCannotExpandConfirmedScope(t *testing.T) {
	r := newRenewalFixture(t, consumer())
	ctx, _, policy, caller := r.unfinished(t)
	result, err := r.manager.Issue(ctx, r.service.issueRequest(caller, policy), nil)
	if err != nil {
		t.Fatal(err)
	}
	policy, err = r.service.checkpoint(ctx, policy, func(current *renewalPolicy) { current.DeployGeneration = result.View.CurrentGeneration })
	if err != nil {
		t.Fatal(err)
	}
	allowed := Authorization{Caller: caller, CertificateID: policy.Scope.CertificateID, Spec: policy.Scope.Issuance.Spec, Issuance: &policy.Scope.Issuance, Access: RenewExisting}
	if err := r.service.Authorize(ctx, allowed); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"SAN", "provider", "zone", "credential revision", "CA"} {
		t.Run(field, func(t *testing.T) {
			request := allowed
			scope := policy.Scope.Issuance
			switch field {
			case "SAN":
				scope.Spec.SANs = []string{"extra.example.com"}
				request.Spec = scope.Spec
			case "provider":
				scope.Provider.ProviderID = "other-provider"
			case "zone":
				scope.Provider.ZoneID = "other-zone"
			case "credential revision":
				scope.Provider.Revision = "replacement-credential"
			case "CA":
				scope.CA = LetsEncryptStaging
			}
			request.Issuance = &scope
			requireCode(t, r.service.Authorize(ctx, request), "POLICY_SCOPE_DENIED")
		})
	}
	bound := policy.Scope.Consumers[0]
	bind := Authorization{Caller: caller, CertificateID: policy.Scope.CertificateID, Generation: 2, Consumer: &bound, Access: Bind}
	if err := r.service.Authorize(ctx, bind); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"plugin", "profile", "node", "SNI", "purpose", "generation"} {
		t.Run(field, func(t *testing.T) {
			request, consumer := bind, bound
			switch field {
			case "plugin":
				consumer.PluginID = "other.plugin"
			case "profile":
				consumer.ProfileID = "other-profile"
			case "node":
				consumer.NodeID = "other-node"
			case "SNI":
				consumer.SNI = "extra.example.com"
			case "purpose":
				consumer.Purpose = "panel.https"
			case "generation":
				request.Generation = 1
			}
			request.Consumer = &consumer
			requireCode(t, r.service.Authorize(ctx, request), "POLICY_SCOPE_DENIED")
		})
	}
	for _, access := range []Access{Issue, Import, TestIssue, Remove, ConfigureRenewal} {
		request := allowed
		request.Access = access
		requireCode(t, r.service.Authorize(ctx, request), "POLICY_SCOPE_DENIED")
	}
	request := allowed
	request.Caller.OperationID = "other-operation"
	requireCode(t, r.service.Authorize(ctx, request), "POLICY_REVOKED")
	request.Caller.OperationID = ""
	request.Access = Read
	requireCode(t, r.service.Authorize(ctx, request), "PERMISSION_DENIED")
}

func TestRenewalCredentialRevocationStopsBeforeOperationCreation(t *testing.T) {
	r := newRenewalFixture(t)
	r.confirmations.revoked = true
	r.due(t)
	requireCode(t, r.service.Tick(context.Background()), "POLICY_REVOKED")
	if r.operations.begins != 0 || r.authority.issues != 1 || r.policy(t).Enabled || !r.policy(t).NextAt.IsZero() {
		t.Fatal("revoked credential allowed an automatic operation")
	}
}

func TestRenewalConfirmationRejectsExtraConsumersAndDuplicatePolicies(t *testing.T) {
	r := newRenewalFixture(t, consumer())
	scope := r.scope
	extra := consumer()
	extra.NodeID = "other-node"
	scope.Consumers = append([]Consumer{extra}, scope.Consumers...)
	_, err := r.service.Enable(context.Background(), r.caller, "policy-extra", MissingRevision, scope)
	requireCode(t, err, "POLICY_SCOPE_DENIED")
	_, err = r.service.Enable(context.Background(), r.caller, "policy-duplicate", MissingRevision, r.scope)
	requireCode(t, err, "POLICY_SCOPE_DENIED")
	_, err = r.service.Revoke(context.Background(), r.caller, "policy-1", "stale")
	requireCode(t, err, "REVISION_CONFLICT")
}

func TestRenewalPublicViewDoesNotIncludePrivateActorOrJournal(t *testing.T) {
	r := newRenewalFixture(t)
	r.due(t)
	r.operations.beginFailure = true
	if err := r.service.Tick(context.Background()); err == nil {
		t.Fatal("test did not preserve a failed renewal")
	}
	view, err := r.service.Get(context.Background(), r.caller, "policy-1")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(view)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"owner_id", "operation_id", "attempt_id", "material_ref", "private_key", "lease_until", "run_number", "DO-NOT-EXPOSE"} {
		if strings.Contains(string(raw), forbidden) {
			t.Fatalf("public renewal view contained %s", forbidden)
		}
	}
}

func TestRenewalMalformedPersistedScopeOrLeaseFailsClosed(t *testing.T) {
	for _, field := range []string{"scope", "lease", "hash", "target"} {
		t.Run(field, func(t *testing.T) {
			r := newRenewalFixture(t)
			ledger, revision, err := r.service.load(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			policy := &ledger.Policies[0]
			switch field {
			case "scope":
				policy.Scope.Issuance.Spec.SANs = []string{"PROXY.EXAMPLE.COM"}
			case "lease":
				policy.Attempts, policy.RunNumber = 1, 1
				policy.Job = &renewalJob{AttemptID: "bad-lease", StartedAt: r.clock.Now(), LeaseUntil: r.clock.Now().Add(24 * time.Hour)}
			case "hash":
				policy.Issue = &renewalIssue{AttemptID: "bad-hash", ExpectedRevision: "1", Hash: strings.Repeat("z", 64)}
			case "target":
				policy.DeployGeneration = 2
			}
			if _, err := store.Save(context.Background(), r.private, renewalLedgerKey, revision, ledger); err != nil {
				t.Fatal(err)
			}
			requireCode(t, r.service.Tick(context.Background()), "STATE_INVALID")
			if r.operations.begins != 0 || r.authority.issues != 1 {
				t.Fatal("malformed state sent a CA order")
			}
		})
	}
}

func TestRenewalClaimPersistenceFailureSendsNoOperation(t *testing.T) {
	r := newRenewalFixture(t)
	r.due(t)
	r.private.FailPut = func(count int) error {
		if count == 2 {
			return fault.New("STATE_UNAVAILABLE", "disk full")
		}
		return nil
	}
	if err := r.service.Tick(context.Background()); err == nil {
		t.Fatal("failed claim was ignored")
	}
	if r.operations.begins != 0 || r.authority.issues != 1 {
		t.Fatal("service operation began before its claim was persistent")
	}
}

func TestRenewalActiveLeasePreventsAnotherServiceInstance(t *testing.T) {
	r := newRenewalFixture(t)
	ctx, cancel, _, _ := r.unfinished(t)
	defer cancel()
	r.restart(t)
	if err := r.service.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	if r.operations.begins != 1 || r.authority.issues != 1 {
		t.Fatal("another service instance replaced a live lease")
	}
}

func TestRenewalSharedLedgerBoundsJobsAcrossServiceInstances(t *testing.T) {
	r := newRenewalFixture(t)
	r.due(t)
	ledger, revision, err := r.service.load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	held := ledger.Policies[0]
	held.ID, held.Scope.CertificateID = "held-policy", "held-certificate"
	held.Attempts, held.RunNumber = 1, 1
	held.Job = &renewalJob{AttemptID: "held-attempt", OperationID: "held-operation", StartedAt: r.clock.Now(), LeaseUntil: r.clock.Now().Add(time.Minute)}
	ledger.Policies = append(ledger.Policies, held)
	if _, err := store.Save(context.Background(), r.private, renewalLedgerKey, revision, ledger); err != nil {
		t.Fatal(err)
	}
	service, err := NewRenewalService(RenewalOptions{Repository: r.private, Manager: r.manager, Confirmations: r.confirmations, Operations: r.operations, Contexts: fakeRenewalContexts{}, Clock: r.clock, MaxJobs: 1})
	if err != nil {
		t.Fatal(err)
	}
	if err := service.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	if r.operations.begins != 0 || r.authority.issues != 1 {
		t.Fatal("another service instance exceeded the shared lease budget")
	}
}
