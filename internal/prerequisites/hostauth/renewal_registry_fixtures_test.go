// SPDX-License-Identifier: AGPL-3.0-only

package hostauth

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/qwq-panel/qwq/internal/actor"
	"github.com/qwq-panel/qwq/internal/authz"
	"github.com/qwq-panel/qwq/internal/operations"
	"github.com/qwq-panel/qwq/internal/prerequisites/certificates"
	"github.com/qwq-panel/qwq/internal/storage"
)

// ======================== 实际审批/私有scope；mint只由独立Root入口负责 ========================

type unexpectedRenewalMint struct{ calls int }

func (s *unexpectedRenewalMint) EnsureRenewalService(context.Context, actor.Actor, RenewalServiceRequest) (string, error) {
	s.calls++
	return "", errors.New("fixture forbids mint from private policy preparation")
}

type renewalRegistryFixture struct {
	binding reservationFixture
	call    *fixtureCall
	args    RenewalPolicyArgs
	mint    *unexpectedRenewalMint
}

func newRenewalRegistryFixture(t *testing.T, full bool) renewalRegistryFixture {
	t.Helper()
	binding := newReservationFixture(t)
	reservation := binding.reserve(t)
	confirmed, _, _, _, _ := binding.confirm(t, reservation)
	confirmed.finish()
	provider, _, _ := binding.f.register(t)
	provider.finish()
	zone, _, _ := binding.f.zone(t, binding.f.human, "absent")
	zone.finish()
	args := RenewalPolicyArgs{PolicyID: "policy-one", CertificateID: fixtureCertificate, ProviderID: fixtureProvider, ZoneID: fixtureZone,
		CA: certificates.LetsEncrypt, BindingRefs: []string{reservation.BindingRef}, ExpiresAt: binding.f.clock.Now().Add(24 * time.Hour)}
	if full {
		binding.f.ctx = operations.WithPermissionMode(binding.f.ctx, operations.PermissionFull)
	}
	var call *fixtureCall
	if full {
		job, invocation := binding.f.dispatchCall(t, binding.f.human, "tls.certificates", "renewal.configure", renewalPolicySubject(args.PolicyID), "absent", args)
		// 真正发起时的完全模式同样传到当前worker；不补造Approval或确认者。
		ctx, release, err := binding.f.authority.Begin(operations.WithPermissionMode(job.ctx, operations.PermissionFull), invocation)
		if err != nil {
			t.Fatal(err)
		}
		call = &fixtureCall{ctx: ctx, invocation: invocation, job: job, release: release}
		t.Cleanup(call.finish)
	} else {
		call = binding.f.start(t, binding.f.human, "tls.certificates", "renewal.configure", renewalPolicySubject(args.PolicyID), "absent", args)
	}
	mint := &unexpectedRenewalMint{}
	binding.f.authority.renewalServices = mint
	return renewalRegistryFixture{binding: binding, call: call, args: args, mint: mint}
}

func (f renewalRegistryFixture) register(t *testing.T) RenewalPolicyView {
	t.Helper()
	view, err := f.binding.f.authority.RegisterRenewalPolicy(f.call.ctx, f.args.PolicyID, "absent")
	if err != nil {
		t.Fatal(err)
	}
	return view
}

func (f renewalRegistryFixture) service(t *testing.T, name string, role authz.Role, scope *authz.ServiceScope) authz.ServiceAccount {
	t.Helper()
	var service authz.ServiceAccount
	if err := f.binding.f.db.Update(f.binding.f.ctx, func(tx *storage.Tx) error {
		created, err := f.binding.f.authz.CreateServiceAccount(f.binding.f.ctx, tx, authz.CreateServiceAccountInput{
			Actor: f.binding.f.human, Name: name, Role: role, Scope: scope})
		if err != nil {
			return err
		}
		service = created.ServiceAccount // 令牌不进入任何fixture结果或日志。
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return service
}
