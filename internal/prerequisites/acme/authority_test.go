// SPDX-License-Identifier: AGPL-3.0-only

package acme

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/qwq-panel/qwq/internal/prerequisites/certificates"
	"github.com/qwq-panel/qwq/internal/prerequisites/dns"
	"github.com/qwq-panel/qwq/internal/prerequisites/fault"
	"github.com/qwq-panel/qwq/internal/prerequisites/store"
	"github.com/qwq-panel/qwq/internal/tlsmgr"
)

// ======================== 实际 ACME 客户端闭环与恢复回归 ========================

func TestRealACMEClientIssuesMultipleSANsWithMonotonicProgressAndEncryptedVault(t *testing.T) {
	f := newAuthorityFixture(t, []string{"*.proxy.example.com", "proxy.example.com"})
	previous := uint32(0)
	issued, err := f.authority.Issue(context.Background(), f.caller, "certificate-1", "attempt-1", f.scope, func(_ string, percent uint32) error {
		if percent < previous {
			t.Fatal("multi-SAN progress decreased")
		}
		previous = percent
		return nil
	})
	if err != nil || issued.Material == "" || issued.Trust != tlsmgr.StagingTrust {
		t.Fatalf("issue = %v %v", issued, err)
	}
	metadata, err := f.vault.Inspect(context.Background(), f.caller, "certificate-1", issued.Material, f.scope.Spec, tlsmgr.StagingTrust)
	if err != nil || !slices.Equal(metadata.SANs, f.scope.Spec.SANs) {
		t.Fatalf("material = %v %v", metadata, err)
	}
	if err := f.authority.Cancel(context.Background(), f.caller, "certificate-1", "attempt-1", f.scope); err != nil {
		t.Fatal(err)
	}
	if f.ca.orders != 1 || f.ca.finalizes != 1 || f.dns.created != 2 || f.dns.deleted != 2 || len(f.dns.records) != 0 {
		t.Fatal("CA or owned TXT was replayed or left behind")
	}
	again, err := f.authority.Reconcile(context.Background(), f.caller, "certificate-1", "attempt-1", f.scope, nil)
	if err != nil || again.Material != issued.Material || f.ca.orders != 1 || f.ca.finalizes != 1 {
		t.Fatal("completed attempt did not return original material")
	}
}

func TestACMELostOrderResponseNeverCreatesReplacementOrder(t *testing.T) {
	f := newAuthorityFixture(t, []string{"proxy.example.com"})
	f.ca.lostOrder = true
	if _, err := f.authority.Issue(context.Background(), f.caller, "certificate-1", "attempt-lost-order", f.scope, nil); fault.Code(err) != "CA_UNAVAILABLE" {
		t.Fatalf("lost order = %v", err)
	}
	caller := f.caller
	caller.OperationID = "operation-2"
	if _, err := f.authority.Reconcile(context.Background(), caller, "certificate-1", "attempt-lost-order", f.scope, nil); fault.Code(err) != "OUTCOME_UNKNOWN" {
		t.Fatalf("original order recovery = %v", err)
	}
	if f.ca.orders != 1 || f.ca.finalizes != 0 {
		t.Fatal("unknown order was replaced")
	}
}

func TestACMELostFinalizeReadsOriginalOrderAndKeepsOriginalKey(t *testing.T) {
	f := newAuthorityFixture(t, []string{"proxy.example.com"})
	f.ca.lostFinalize = true
	if _, err := f.authority.Issue(context.Background(), f.caller, "certificate-1", "attempt-finalize", f.scope, nil); err == nil {
		t.Fatal("lost finalize unexpectedly confirmed")
	}
	caller := f.caller
	caller.OperationID = "operation-2"
	issued, err := f.authority.Reconcile(context.Background(), caller, "certificate-1", "attempt-finalize", f.scope, nil)
	if err != nil || issued.Material == "" {
		t.Fatalf("finalize recovery = %v %v", issued, err)
	}
	if f.ca.orders != 1 || f.ca.finalizes != 1 {
		t.Fatal("original order or finalize was resent")
	}
	if err := f.authority.Cancel(context.Background(), caller, "certificate-1", "attempt-finalize", f.scope); err != nil {
		t.Fatal(err)
	}
}

func TestACMEExplicitRateLimitIsPersistedWithRetryAfter(t *testing.T) {
	f := newAuthorityFixture(t, []string{"proxy.example.com"})
	f.ca.rejectOrder = 429
	_, err := f.authority.Issue(context.Background(), f.caller, "certificate-1", "attempt-rate", f.scope, nil)
	if fault.Code(err) != "RATE_LIMITED" || fault.Retry(err).IsZero() {
		t.Fatalf("rate rejection = %v", err)
	}
	firstRetry := fault.Retry(err)
	_, err = f.authority.Reconcile(context.Background(), f.caller, "certificate-1", "attempt-rate", f.scope, nil)
	if fault.Code(err) != "RATE_LIMITED" || fault.Retry(err) != firstRetry || f.ca.orders != 1 {
		t.Fatalf("persisted rate rejection = %v", err)
	}
}

func TestACMERejectsUntrustedDirectoryAndRevokedScopeBeforeOrder(t *testing.T) {
	for _, revoked := range []bool{false, true} {
		t.Run(map[bool]string{false: "foreign directory", true: "revoked"}[revoked], func(t *testing.T) {
			f := newAuthorityFixture(t, []string{"proxy.example.com"})
			f.guard.revoked = revoked
			f.ca.foreignDirectory = !revoked
			if _, err := f.authority.Issue(context.Background(), f.caller, "certificate-1", "attempt-denied", f.scope, nil); err == nil {
				t.Fatal("untrusted CA/scope was accepted")
			}
			if f.ca.orders != 0 || f.ca.finalizes != 0 {
				t.Fatal("untrusted CA/scope sent an order")
			}
		})
	}
}

func TestACMEJournalRejectsSANMutationBeforeRemoteRecovery(t *testing.T) {
	f := newAuthorityFixture(t, []string{"proxy.example.com"})
	state, revision, err := f.authority.prepare(context.Background(), f.caller, "certificate-1", "attempt-state", f.scope)
	if err != nil {
		t.Fatal(err)
	}
	state.Scope.Spec.SANs = []string{"other.example.com"}
	if _, err := f.authority.save(context.Background(), f.caller, state, revision); err != nil {
		t.Fatal(err)
	}
	if _, err := f.authority.Reconcile(context.Background(), f.caller, "certificate-1", "attempt-state", f.scope, nil); fault.Code(err) != "STATE_INVALID" {
		t.Fatalf("state mutation = %v", err)
	}
	if f.ca.requests != 0 {
		t.Fatal("mutated journal reached CA")
	}
}

func TestACMELeaseRejectsAnotherInstanceWithoutRemoteCalls(t *testing.T) {
	f := newAuthorityFixture(t, []string{"proxy.example.com"})
	state, revision, err := f.authority.prepare(context.Background(), f.caller, "certificate-1", "attempt-lease", f.scope)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.authority.lease(context.Background(), f.caller, state, revision); err != nil {
		t.Fatal(err)
	}
	if _, err := f.authority.Reconcile(context.Background(), f.caller, "certificate-1", "attempt-lease", f.scope, nil); fault.Code(err) != "CERTIFICATE_BUSY" {
		t.Fatalf("active lease = %v", err)
	}
	if f.ca.requests != 0 {
		t.Fatal("active shared lease reached CA")
	}
}

func TestACMEProgressAndStateNeverExposeChallengeOrPrivateReferences(t *testing.T) {
	f := newAuthorityFixture(t, []string{"proxy.example.com"})
	stages := []string{}
	_, err := f.authority.Issue(context.Background(), f.caller, "certificate-1", "attempt-private", f.scope, func(stage string, _ uint32) error { stages = append(stages, stage); return nil })
	if err != nil {
		t.Fatal(err)
	}
	for _, stage := range stages {
		if strings.Contains(stage, "challenge") || strings.Contains(stage, "PRIVATE") || strings.Contains(stage, "ref_") {
			t.Fatal("progress exposed private fields")
		}
	}
	state, _, _, err := f.authority.load(context.Background(), f.caller, "certificate-1", "attempt-private", f.scope)
	if err != nil {
		t.Fatal(err)
	}
	if state.Material == certificates.MaterialRef("") {
		t.Fatal("fixture did not save material")
	}
}

type failIssuedStore struct {
	store.Repository
	failed bool
}

func (s *failIssuedStore) Put(ctx context.Context, key, revision string, value []byte) (string, error) {
	var state struct{ Phase string }
	if json.Unmarshal(value, &state) == nil && state.Phase == "issued" && !s.failed {
		s.failed = true
		return "", fault.New("STATE_UNAVAILABLE", "fixture final journal failure")
	}
	return s.Repository.Put(ctx, key, revision, value)
}

func TestACMERecoversEncryptedMaterialAfterFinalJournalCommitFailure(t *testing.T) {
	f := newAuthorityFixture(t, []string{"proxy.example.com"})
	f.authority.repository = &failIssuedStore{Repository: f.repository}
	issued, err := f.authority.Issue(context.Background(), f.caller, "certificate-1", "attempt-commit", f.scope, nil)
	if issued.Material == "" || err == nil {
		t.Fatalf("final journal failure = %v %v", issued, err)
	}
	caller := f.caller
	caller.OperationID = "operation-2"
	recovered, err := f.authority.Reconcile(context.Background(), caller, "certificate-1", "attempt-commit", f.scope, nil)
	if err != nil || recovered.Material != issued.Material || f.ca.orders != 1 || f.ca.finalizes != 1 {
		t.Fatalf("original encrypted material recovery = %v %v", recovered, err)
	}
}

func TestACMECleanupKeepsOtherTXTAndRejectsOtherOwner(t *testing.T) {
	f := newAuthorityFixture(t, []string{"proxy.example.com"})
	f.dns.records = []dns.Record{{ID: "other-record", Type: dns.TXT, Name: "_acme-challenge.proxy.example.com", Value: "unrelated", TTL: 300}}
	if _, err := f.authority.Issue(context.Background(), f.caller, "certificate-1", "attempt-cleanup", f.scope, nil); err != nil {
		t.Fatal(err)
	}
	foreign := f.caller
	foreign.OwnerID = "owner-2"
	if err := f.authority.Cancel(context.Background(), foreign, "certificate-1", "attempt-cleanup", f.scope); fault.Code(err) != "PERMISSION_DENIED" {
		t.Fatalf("foreign cleanup = %v", err)
	}
	if err := f.authority.Cancel(context.Background(), f.caller, "certificate-1", "attempt-cleanup", f.scope); err != nil {
		t.Fatal(err)
	}
	if len(f.dns.records) != 1 || f.dns.records[0].ID != "other-record" || f.dns.deleted != 1 {
		t.Fatal("cleanup deleted unrelated TXT")
	}
}
