// SPDX-License-Identifier: AGPL-3.0-only

package certificates

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/qwq-panel/qwq/internal/prerequisites/fault"
	"github.com/qwq-panel/qwq/internal/prerequisites/testsupport"
	"github.com/qwq-panel/qwq/internal/tlsmgr"
)

func TestIssuancePersistsGenerationsAndKeepsPublicViewsClean(t *testing.T) {
	f := newFixture(t)
	first := f.issue(t, "issue-1")
	if first.Stage != "issued" || !first.View.Ready || first.View.CurrentGeneration != 1 {
		t.Fatalf("first = %v", first)
	}
	f.clock.Advance(40 * 24 * time.Hour)
	second := f.issue(t, "issue-2")
	if second.View.CurrentGeneration != 2 || len(second.View.Generations) != 2 || !second.View.Generations[1].Metadata.NotAfter.After(first.View.Generations[0].Metadata.NotAfter) {
		t.Fatal("generation did not advance")
	}
	raw, err := json.Marshal(second.View)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "material-") || strings.Contains(string(raw), "material_ref") || strings.Contains(string(raw), "PRIVATE KEY") {
		t.Fatal("private reference or key reached public view")
	}
	f.clock.Advance(91 * 24 * time.Hour)
	view, err := f.manager.Get(context.Background(), f.caller, "certificate-1")
	if err != nil || view.Ready {
		t.Fatal("expired certificate reported ready")
	}
}

func TestLostIssuanceResponseRecoversWithCurrentOperation(t *testing.T) {
	f := newFixture(t)
	f.authority.lostReply = true
	request := IssueRequest{Caller: f.caller, CertificateID: "certificate-1", AttemptID: "lost-1", ExpectedRevision: MissingRevision, Scope: f.scope}
	result, err := f.manager.Issue(context.Background(), request, nil)
	requireCode(t, err, "OUTCOME_UNKNOWN")
	if result.View.Ready || result.View.CurrentGeneration != 0 || strings.Contains(err.Error(), "DO-NOT-EXPOSE") {
		t.Fatal("unknown result exposed private data or claimed ready")
	}
	current := f.caller
	current.OperationID = "operation-recover"
	view, err := f.manager.Get(context.Background(), current, "certificate-1")
	if err != nil {
		t.Fatal(err)
	}
	result, err = f.manager.Recover(context.Background(), current, "certificate-1", view.Revision, nil)
	if err != nil || result.Stage != "issued" || result.View.CurrentGeneration != 1 {
		t.Fatalf("recover = %v, %v", result, err)
	}
	if f.authority.issues != 1 || f.authority.reconciles != 1 || f.authority.cancels != 2 {
		t.Fatalf("CA calls = %d / %d / %d", f.authority.issues, f.authority.reconciles, f.authority.cancels)
	}
}

func TestFailedGenerationCommitNeverReturnsUnpersistedReady(t *testing.T) {
	f := newFixture(t)
	f.repository.FailPut = func(index int) error {
		if index == 3 {
			return errors.New("injected generation commit failure")
		}
		return nil
	}
	result, err := f.manager.Issue(context.Background(), IssueRequest{Caller: f.caller, CertificateID: "certificate-1", AttemptID: "commit-1", ExpectedRevision: MissingRevision, Scope: f.scope}, nil)
	requireCode(t, err, "OUTCOME_UNKNOWN")
	if result.View.Ready || result.View.CurrentGeneration != 0 || result.View.Pending != "issue" {
		t.Fatal("uncommitted generation claimed ready")
	}
	view, err := f.manager.Get(context.Background(), f.caller, "certificate-1")
	if err != nil {
		t.Fatal(err)
	}
	result, err = f.manager.Recover(context.Background(), f.caller, "certificate-1", view.Revision, nil)
	if err != nil || !result.View.Ready || result.View.CurrentGeneration != 1 {
		t.Fatalf("recover = %v, %v", result, err)
	}
	if f.authority.issues != 1 {
		t.Fatal("recovery issued a second certificate")
	}
}

func TestRateLimitRefusalAndRevisionGuards(t *testing.T) {
	f := newFixture(t)
	f.authority.refused = &fault.Error{Code: "RATE_LIMITED", Detail: "refused", RetryAt: f.clock.Now().Add(time.Hour), NotApplied: true}
	request := IssueRequest{Caller: f.caller, CertificateID: "certificate-1", AttemptID: "rate-1", ExpectedRevision: MissingRevision, Scope: f.scope}
	result, err := f.manager.Issue(context.Background(), request, nil)
	requireCode(t, err, "RATE_LIMITED")
	if result.View.Ready || result.View.Pending != "" {
		t.Fatal("refused task was not finalized")
	}
	if !fault.Retry(err).Equal(f.clock.Now().Add(time.Hour)) {
		t.Fatal("CA Retry-After was lost before persistence")
	}
	if _, err := f.manager.Issue(context.Background(), request, nil); fault.Code(err) != "RATE_LIMITED" || !fault.Retry(err).Equal(f.clock.Now().Add(time.Hour)) {
		t.Fatalf("refusal replay = %v", err)
	}
	f.authority.refused = nil
	request.AttemptID, request.ExpectedRevision = "rate-2", result.View.Revision
	if _, err := f.manager.Issue(context.Background(), request, nil); err != nil {
		t.Fatal(err)
	}
	request.AttemptID = "stale-1"
	_, err = f.manager.Issue(context.Background(), request, nil)
	requireCode(t, err, "REVISION_CONFLICT")
	if f.authority.issues != 2 {
		t.Fatalf("CA calls = %d", f.authority.issues)
	}
}

func TestCertificateScopeCannotExpandThroughReissue(t *testing.T) {
	f := newFixture(t)
	first := f.issue(t, "scope-1")
	scope := f.scope
	scope.Spec.SANs = []string{"proxy.example.com", "new.example.com"}
	_, err := f.manager.Issue(context.Background(), IssueRequest{Caller: f.caller, CertificateID: "certificate-1", AttemptID: "scope-2", ExpectedRevision: first.View.Revision, Scope: scope}, nil)
	requireCode(t, err, "SCOPE_CHANGE_REQUIRED")
	if f.authority.issues != 1 {
		t.Fatal("expanded scope reached CA")
	}
	scope.Spec.SANs = []string{"outside.attacker.test"}
	_, err = f.manager.Issue(context.Background(), IssueRequest{Caller: f.caller, CertificateID: "another-certificate", AttemptID: "scope-3", ExpectedRevision: MissingRevision, Scope: scope}, nil)
	requireCode(t, err, "ZONE_DENIED")
}

func TestImportUsesOwnedReferenceAndValidatesRealCryptography(t *testing.T) {
	f := newFixture(t)
	certificate, err := testsupport.SignedCertificate(f.clock.Now(), nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer certificate.Clear()
	f.materials.importKeys, f.materials.importRoots = map[string][]byte{"operation-key-1": certificate.Key}, certificate.Roots
	input := ImportRequest{Caller: f.caller, CertificateID: "certificate-1", AttemptID: "import-1", ExpectedRevision: MissingRevision, Spec: f.scope.Spec,
		ChainPEM: certificate.Chain, PrivateKeyRef: "operation-key-1", Trust: tlsmgr.PublicTrust}
	result, err := f.manager.ImportCertificate(context.Background(), input)
	if err != nil || result.View.CurrentGeneration != 1 || result.View.Generations[0].Source != Imported {
		t.Fatalf("import = %v, %v", result, err)
	}
	if _, err := f.manager.ImportCertificate(context.Background(), input); err != nil {
		t.Fatal(err)
	}
	if f.materials.imports != 1 {
		t.Fatal("import material was duplicated")
	}
	input.CertificateID, input.AttemptID, input.PrivateKeyRef = "foreign-certificate", "import-2", "foreign-ref"
	_, err = f.manager.ImportCertificate(context.Background(), input)
	requireCode(t, err, "PERMISSION_DENIED")
}

func TestInvalidIssuedSANIsDiscardedAndNeverPublished(t *testing.T) {
	f := newFixture(t)
	f.materials.invalidSAN = true
	result, err := f.manager.Issue(context.Background(), IssueRequest{Caller: f.caller, CertificateID: "certificate-1", AttemptID: "invalid-1", ExpectedRevision: MissingRevision, Scope: f.scope}, nil)
	requireCode(t, err, "SAN_MISMATCH")
	if result.View.Ready || result.View.CurrentGeneration != 0 || f.materials.removes != 1 {
		t.Fatal("invalid SAN was published or not discarded")
	}
}

func TestCancellationKeepsMaterialRecoverableAndCleansAttempt(t *testing.T) {
	f := newFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	f.authority.cancelOnIssue = cancel
	result, err := f.manager.Issue(ctx, IssueRequest{Caller: f.caller, CertificateID: "certificate-1", AttemptID: "cancel-1", ExpectedRevision: MissingRevision, Scope: f.scope}, nil)
	if !errors.Is(err, context.Canceled) || result.View.Ready || f.authority.cancels != 1 {
		t.Fatalf("cancel = %v, %v", result, err)
	}
	view, err := f.manager.Get(context.Background(), f.caller, "certificate-1")
	if err != nil {
		t.Fatal(err)
	}
	result, err = f.manager.Recover(context.Background(), f.caller, "certificate-1", view.Revision, nil)
	if err != nil || !result.View.Ready {
		t.Fatalf("recover = %v, %v", result, err)
	}
	if f.authority.issues != 1 {
		t.Fatal("cancel recovery issued again")
	}
}

func TestConcurrentManagersReconcileInsteadOfIssuingTwice(t *testing.T) {
	f := newFixture(t)
	f.authority.started, f.authority.release = make(chan struct{}, 1), make(chan struct{})
	second, err := New(Options{Repository: f.repository, Materials: f.materials, Authority: f.authority, Bindings: f.bindings, Authorizer: f.authorization, Clock: f.clock})
	if err != nil {
		t.Fatal(err)
	}
	request := IssueRequest{Caller: f.caller, CertificateID: "certificate-1", AttemptID: "race-1", ExpectedRevision: MissingRevision, Scope: f.scope}
	done := make(chan error, 1)
	go func() { _, err := f.manager.Issue(context.Background(), request, nil); done <- err }()
	select {
	case <-f.authority.started:
	case <-time.After(2 * time.Second):
		t.Fatal("CA did not start")
	}
	_, err = second.Issue(context.Background(), request, nil)
	requireCode(t, err, "OUTCOME_UNKNOWN")
	close(f.authority.release)
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("CA did not finish")
	}
	view, err := second.Get(context.Background(), f.caller, "certificate-1")
	if err != nil {
		t.Fatal(err)
	}
	result, err := second.Recover(context.Background(), f.caller, "certificate-1", view.Revision, nil)
	if err != nil || result.View.CurrentGeneration != 1 {
		t.Fatalf("race recovery = %v, %v", result, err)
	}
	if f.authority.issues != 1 {
		t.Fatal("race issued twice")
	}
}
