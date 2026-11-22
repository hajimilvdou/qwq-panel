// SPDX-License-Identifier: AGPL-3.0-only

package dns

import (
	"context"
	"testing"

	"github.com/qwq-panel/qwq/internal/prerequisites/fault"
)

// ======================== 不复用旧派发权限的恢复回归 ========================

func TestRecoverDNSAttemptUsesCurrentOperationWithoutResending(t *testing.T) {
	f := newFixture(t)
	request := f.challenge(t, "challenge-recover")
	f.provider.listFailures = map[int]error{3: fault.New("PROVIDER_UNAVAILABLE", "fixture read failure")}
	result, err := f.manager.PresentChallenge(context.Background(), request)
	if result.State != Unknown || fault.Code(err) != "OUTCOME_UNKNOWN" {
		t.Fatalf("pending = %v %v", result, err)
	}
	current := f.caller
	current.OperationID = "operation-2"
	result, err = f.manager.RecoverAttempt(context.Background(), current, f.scope, request.CertificateID, request.AttemptID)
	if err != nil || result.State != Applied {
		t.Fatalf("current operation recovery = %v %v", result, err)
	}
	creates, _, _ := f.provider.counts()
	if creates != 1 {
		t.Fatal("original DNS write was resent")
	}
}

func TestRecoverDNSAttemptRejectsOtherCertificateOwnerAndRevocation(t *testing.T) {
	f := newFixture(t)
	request := f.challenge(t, "challenge-scope")
	if _, err := f.manager.PresentChallenge(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	if _, err := f.manager.RecoverAttempt(context.Background(), f.caller, f.scope, "other-certificate", request.AttemptID); fault.Code(err) != "NOT_FOUND" {
		t.Fatalf("other certificate = %v", err)
	}
	foreign := f.caller
	foreign.OwnerID = "foreign-owner"
	if _, err := f.manager.RecoverAttempt(context.Background(), foreign, f.scope, request.CertificateID, request.AttemptID); fault.Code(err) != "PERMISSION_DENIED" {
		t.Fatalf("other owner = %v", err)
	}
	f.authorization.revoke()
	if _, err := f.manager.RecoverAttempt(context.Background(), f.caller, f.scope, request.CertificateID, request.AttemptID); fault.Code(err) != "CREDENTIAL_REVOKED" {
		t.Fatalf("revoked recovery = %v", err)
	}
	creates, _, _ := f.provider.counts()
	if creates != 1 {
		t.Fatal("unauthorized recovery wrote DNS")
	}
}

func TestRecoverDNSAttemptRequiresCurrentDispatchedOperation(t *testing.T) {
	f := newFixture(t)
	caller := f.caller
	caller.OperationID = ""
	if _, err := f.manager.RecoverAttempt(context.Background(), caller, f.scope, "certificate-1", "challenge-1"); fault.Code(err) != "PERMISSION_DENIED" {
		t.Fatalf("missing operation = %v", err)
	}
}
