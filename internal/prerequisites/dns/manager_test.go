// SPDX-License-Identifier: AGPL-3.0-only

package dns

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/qwq-panel/qwq/internal/prerequisites/fault"
	"github.com/qwq-panel/qwq/internal/prerequisites/store"
)

func TestDNS01PreservesOtherTXTAndCleansIdempotently(t *testing.T) {
	f := newFixture(t)
	f.provider.records = []Record{{ID: "foreign", Type: TXT, Name: "_acme-challenge.proxy.example.com", Value: "existing", TTL: 300}}
	request := f.challenge(t, "challenge-1")
	result, err := f.manager.PresentChallenge(context.Background(), request)
	if err != nil || result.State != Applied {
		t.Fatalf("present = %v, %v", result, err)
	}
	if _, err := f.manager.PresentChallenge(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	creates, _, _ := f.provider.counts()
	if creates != 1 {
		t.Fatalf("creates = %d", creates)
	}
	for range 2 {
		if err := f.manager.CleanupChallenge(context.Background(), f.caller, f.scope, "certificate-1", "challenge-1"); err != nil {
			t.Fatal(err)
		}
	}
	records, err := f.provider.List(context.Background(), f.scope)
	if err != nil || len(records) != 1 || records[0].ID != "foreign" {
		t.Fatalf("remaining records = %v, %v", records, err)
	}
	_, _, deletes := f.provider.counts()
	if deletes != 1 {
		t.Fatalf("deletes = %d", deletes)
	}
}

func TestLostCreateResponseRequiresVerifiableOwnership(t *testing.T) {
	for _, tc := range []struct {
		name              string
		noMarkers, mirror bool
		wantApplied       bool
	}{
		{"persistent marker", false, false, true},
		{"no provider ownership", true, false, false},
		{"ambiguous ownership", false, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			f.provider.lostCreate, f.provider.noMarkers, f.provider.mirrorMarker = true, tc.noMarkers, tc.mirror
			request := f.challenge(t, "lost-1")
			result, err := f.manager.PresentChallenge(context.Background(), request)
			if tc.wantApplied {
				if err != nil || result.State != Applied {
					t.Fatalf("present = %v, %v", result, err)
				}
				if err := f.manager.CleanupChallenge(context.Background(), f.caller, f.scope, "certificate-1", "lost-1"); err != nil {
					t.Fatal(err)
				}
			} else {
				requireCode(t, err, "OUTCOME_UNKNOWN")
				if strings.Contains(err.Error(), "DO-NOT-EXPOSE") {
					t.Fatal("upstream token reached public error")
				}
				if _, err := f.manager.PresentChallenge(context.Background(), request); fault.Code(err) != "OUTCOME_UNKNOWN" {
					t.Fatalf("replay = %v", err)
				}
				requireCode(t, f.manager.CleanupChallenge(context.Background(), f.caller, f.scope, "certificate-1", "lost-1"), "OUTCOME_UNKNOWN")
			}
			creates, _, deletes := f.provider.counts()
			if creates != 1 || (!tc.wantApplied && deletes != 0) {
				t.Fatalf("writes = create %d, delete %d", creates, deletes)
			}
		})
	}
}

func TestConfirmedRecordIDSurvivesFailedFinalCommit(t *testing.T) {
	f := newFixture(t)
	f.provider.noMarkers = true
	f.repository.FailPut = func(index int) error {
		if index == 3 {
			return errors.New("injected commit failure")
		}
		return nil
	}
	request := f.challenge(t, "commit-1")
	_, err := f.manager.PresentChallenge(context.Background(), request)
	requireCode(t, err, "STATE_UNAVAILABLE")
	result, err := f.manager.PresentChallenge(context.Background(), request)
	if err != nil || result.State != Applied {
		t.Fatalf("reconcile = %v, %v", result, err)
	}
	creates, _, _ := f.provider.counts()
	if creates != 1 {
		t.Fatalf("create replayed %d times", creates)
	}
}

func TestRateLimitExplicitRefusalAllowsFreshPlan(t *testing.T) {
	f := newFixture(t)
	retryAt := f.clock.Now().Add(time.Minute)
	f.provider.createRejected = &fault.Error{Code: "RATE_LIMITED", Detail: "refused", RetryAt: retryAt, NotApplied: true}
	change := Change{Action: Create, Record: Record{Type: A, Name: "proxy.example.com", Value: "192.0.2.10", TTL: 300}}
	request := f.request(t, "rate-1", change)
	result, err := f.manager.Apply(context.Background(), request)
	requireCode(t, err, "RATE_LIMITED")
	if result.State != Rejected || !fault.Retry(err).Equal(retryAt) {
		t.Fatalf("refusal = %v, %v", result, err)
	}
	if _, err := f.manager.Apply(context.Background(), request); fault.Code(err) != "RATE_LIMITED" {
		t.Fatalf("replay = %v", err)
	}
	f.provider.createRejected = nil
	if _, err := f.manager.Apply(context.Background(), f.request(t, "rate-2", change)); err != nil {
		t.Fatal(err)
	}
	creates, _, _ := f.provider.counts()
	if creates != 2 {
		t.Fatalf("creates = %d", creates)
	}
}

func TestConcurrentRecoveryNeverResendsMutation(t *testing.T) {
	f := newFixture(t)
	f.provider.started, f.provider.release = make(chan struct{}, 1), make(chan struct{})
	second, err := New(Options{Repository: f.repository, Providers: fakeProviders{f.provider, f.scope}, Authorizer: f.authorization, Clock: f.clock})
	if err != nil {
		t.Fatal(err)
	}
	request := f.request(t, "race-1", Change{Action: Create, Record: Record{Type: A, Name: "proxy.example.com", Value: "192.0.2.10", TTL: 300}})
	done := make(chan error, 1)
	go func() { _, err := f.manager.Apply(context.Background(), request); done <- err }()
	select {
	case <-f.provider.started:
	case <-time.After(2 * time.Second):
		t.Fatal("create did not start")
	}
	_, err = second.Apply(context.Background(), request)
	requireCode(t, err, "OUTCOME_UNKNOWN")
	close(f.provider.release)
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("create did not return")
	}
	result, err := second.Apply(context.Background(), request)
	if err != nil || result.State != Applied {
		t.Fatalf("final reconcile = %v, %v", result, err)
	}
	creates, _, _ := f.provider.counts()
	if creates != 1 {
		t.Fatalf("mutation replayed %d times", creates)
	}
}

func TestCleanupProtectsOwnerCertificateAndExternalChanges(t *testing.T) {
	f := newFixture(t)
	request := f.challenge(t, "protected-1")
	result, err := f.manager.PresentChallenge(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	wrongOwner := f.caller
	wrongOwner.OwnerID = "another.plugin"
	requireCode(t, f.manager.CleanupChallenge(context.Background(), wrongOwner, f.scope, "certificate-1", "protected-1"), "PERMISSION_DENIED")
	requireCode(t, f.manager.CleanupChallenge(context.Background(), f.caller, f.scope, "another-certificate", "protected-1"), "PERMISSION_DENIED")
	f.provider.edit(result.RecordID, func(record *Record) { record.Value = "external-new-value" })
	requireCode(t, f.manager.CleanupChallenge(context.Background(), f.caller, f.scope, "certificate-1", "protected-1"), "RECORD_CONFLICT")
	_, _, deletes := f.provider.counts()
	if deletes != 0 {
		t.Fatal("externally edited TXT was deleted")
	}
}

func TestCancellationAlwaysCleansConfirmedTXT(t *testing.T) {
	for _, cancelDuringCreate := range []bool{false, true} {
		t.Run(map[bool]string{false: "verification", true: "create response"}[cancelDuringCreate], func(t *testing.T) {
			f := newFixture(t)
			f.provider.records = []Record{{ID: "foreign", Type: TXT, Name: "_acme-challenge.proxy.example.com", Value: "existing", TTL: 300}}
			request := f.challenge(t, "cancel-1")
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if cancelDuringCreate {
				f.provider.cancelOnCreate = cancel
			}
			err := f.manager.WithChallenge(ctx, request, func(ctx context.Context) error { cancel(); return ctx.Err() })
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("cancel result = %v", err)
			}
			creates, _, deletes := f.provider.counts()
			if creates != 1 || deletes != 1 {
				t.Fatalf("writes = %d create, %d delete", creates, deletes)
			}
			records, _ := f.provider.List(context.Background(), f.scope)
			if len(records) != 1 || records[0].ID != "foreign" {
				t.Fatal("cancel did not preserve foreign TXT")
			}
		})
	}
}

func TestExpectedRevisionsAndCNAMEAreCheckedBeforeWrite(t *testing.T) {
	f := newFixture(t)
	f.provider.records = []Record{{ID: "existing", Type: A, Name: "proxy.example.com", Value: "192.0.2.10", TTL: 300}}
	request := f.request(t, "stale-1", Change{Action: Create, Record: Record{Type: A, Name: "new.example.com", Value: "192.0.2.11", TTL: 300}})
	f.provider.edit("existing", func(record *Record) { record.TTL = 600 })
	_, err := f.manager.Apply(context.Background(), request)
	requireCode(t, err, "REVISION_CONFLICT")
	request = f.request(t, "cname-1", Change{Action: Create, Record: Record{Type: CNAME, Name: "proxy.example.com", Value: "target.example.net", TTL: 300}})
	_, err = f.manager.Apply(context.Background(), request)
	requireCode(t, err, "CNAME_CONFLICT")
	request = f.request(t, "outside-1", Change{Action: Create, Record: Record{Type: A, Name: "example.com.attacker.test", Value: "192.0.2.11", TTL: 300}})
	_, err = f.manager.Apply(context.Background(), request)
	requireCode(t, err, "ZONE_DENIED")
	creates, _, _ := f.provider.counts()
	if creates != 0 {
		t.Fatalf("invalid requests sent %d writes", creates)
	}
}

func TestUpdateAndDeleteBindRecordFingerprint(t *testing.T) {
	f := newFixture(t)
	f.provider.records = []Record{{ID: "existing", Type: AAAA, Name: "proxy.example.com", Value: "2001:db8::10", TTL: 300}}
	snapshot, err := f.manager.List(context.Background(), f.caller, f.scope)
	if err != nil {
		t.Fatal(err)
	}
	before := snapshot.Records[0]
	desired := before
	desired.Value = "2001:db8::11"
	request := Request{Caller: f.caller, Scope: f.scope, AttemptID: "update-1", ExpectedRevision: snapshot.Revision,
		Change: Change{Action: Update, Record: desired, ExpectedRecordRevision: before.Revision}}
	result, err := f.manager.Apply(context.Background(), request)
	if err != nil || result.State != Applied {
		t.Fatalf("update = %v, %v", result, err)
	}
	snapshot, err = f.manager.List(context.Background(), f.caller, f.scope)
	if err != nil {
		t.Fatal(err)
	}
	request = Request{Caller: f.caller, Scope: f.scope, AttemptID: "delete-1", ExpectedRevision: snapshot.Revision,
		Change: Change{Action: Delete, Record: snapshot.Records[0], ExpectedRecordRevision: snapshot.Records[0].Revision}}
	f.provider.lostDelete = true
	if _, err := f.manager.Apply(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	if _, err := f.manager.Apply(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	_, updates, deletes := f.provider.counts()
	if updates != 1 || deletes != 1 {
		t.Fatalf("writes = %d update, %d delete", updates, deletes)
	}
}

func TestRevocationAndPublicViews(t *testing.T) {
	f := newFixture(t)
	request := f.challenge(t, "public-1")
	if _, err := f.manager.PresentChallenge(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	snapshot, err := f.manager.List(context.Background(), f.caller, f.scope)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(snapshot)
	if err != nil || strings.Contains(string(raw), "managed_by") {
		t.Fatal("private ownership marker reached public view")
	}
	f.authorization.revoke()
	requireCode(t, f.manager.CleanupChallenge(context.Background(), f.caller, f.scope, "certificate-1", "public-1"), "CREDENTIAL_REVOKED")
	_, _, deletes := f.provider.counts()
	if deletes != 0 {
		t.Fatal("revoked credentials were reused")
	}
}

func TestExpiredChallengeRetainsReferenceEvidence(t *testing.T) {
	f := newFixture(t)
	f.manager.maxReceipts = 1
	request := f.challenge(t, "retained-1")
	if _, err := f.manager.PresentChallenge(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	f.clock.Advance(31 * time.Minute)
	change := Change{Action: Create, Record: Record{Type: A, Name: "new.example.com", Value: "192.0.2.12", TTL: 300}}
	_, err := f.manager.Apply(context.Background(), f.request(t, "retained-2", change))
	requireCode(t, err, "RESOURCE_EXHAUSTED")
	if err := f.manager.CleanupChallenge(context.Background(), f.caller, f.scope, "certificate-1", "retained-1"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.manager.Apply(context.Background(), f.request(t, "retained-3", change)); err != nil {
		t.Fatal(err)
	}
}

func TestMalformedCleanupStateIsRejectedBeforeDeletion(t *testing.T) {
	f := newFixture(t)
	request := f.challenge(t, "invalid-state-1")
	if _, err := f.manager.PresentChallenge(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	state, revision, err := f.manager.load(context.Background(), f.scope)
	if err != nil {
		t.Fatal(err)
	}
	saved := state.Receipts[0]
	saved.Cleaning, saved.State, saved.Record = true, Submitted, nil
	state.Active, state.Receipts = &saved, nil
	if _, err := store.Save(context.Background(), f.repository, journalKey(f.scope), revision, state); err != nil {
		t.Fatal(err)
	}
	requireCode(t, f.manager.CleanupChallenge(context.Background(), f.caller, f.scope, "certificate-1", "invalid-state-1"), "STATE_INVALID")
	_, _, deletes := f.provider.counts()
	if deletes != 0 {
		t.Fatal("malformed state caused deletion")
	}
}

func TestExpiredUnknownSubmissionCannotBeReplaced(t *testing.T) {
	f := newFixture(t)
	f.provider.noMarkers, f.provider.lostCreate = true, true
	_, err := f.manager.PresentChallenge(context.Background(), f.challenge(t, "unknown-1"))
	requireCode(t, err, "OUTCOME_UNKNOWN")
	f.clock.Advance(24 * time.Hour)
	request := f.request(t, "unknown-2", Change{Action: Create, Record: Record{Type: A, Name: "different.example.com", Value: "192.0.2.33", TTL: 300}})
	_, err = f.manager.Apply(context.Background(), request)
	requireCode(t, err, "DNS_BUSY")
	creates, _, _ := f.provider.counts()
	if creates != 1 {
		t.Fatal("unknown submission was silently retried or replaced")
	}
}

func TestPlanReadsWithoutDispatchedOperationButApplyRefuses(t *testing.T) {
	f := newFixture(t)
	request := f.request(t, "plan-1", Change{Action: Create, Record: Record{Type: A, Name: "proxy.example.com", Value: "192.0.2.33", TTL: 300}})
	request.Caller.OperationID = ""
	if _, err := f.manager.PlanChange(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	_, err := f.manager.Apply(context.Background(), request)
	requireCode(t, err, "PERMISSION_DENIED")
	creates, _, _ := f.provider.counts()
	if creates != 0 {
		t.Fatal("plan or unbound caller modified DNS")
	}
}
