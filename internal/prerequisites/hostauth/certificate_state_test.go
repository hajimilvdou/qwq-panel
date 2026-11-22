// SPDX-License-Identifier: AGPL-3.0-only

package hostauth

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/qwq-panel/qwq/internal/authz"
	"github.com/qwq-panel/qwq/internal/operations"
	"github.com/qwq-panel/qwq/internal/platform/ids"
	"github.com/qwq-panel/qwq/internal/prerequisites/certificates"
	"github.com/qwq-panel/qwq/internal/prerequisites/fault"
	"github.com/qwq-panel/qwq/internal/prerequisites/store"
	"github.com/qwq-panel/qwq/internal/storage"
	"github.com/qwq-panel/qwq/internal/tlsmgr"
)

// ======================== 固定共享 owner 与私有登记完整性 ========================

func TestHostCertificateRegistrationPreservesSharedOwnerAndExactSpec(t *testing.T) {
	f := newAuthorityFixture(t)
	first, ctx, request := f.testCertificate(t)
	state, revision, found, err := f.authority.loadCertificate(f.ctx, fixtureCertificate)
	if err != nil || !found || state.OwnerID != "installation" || state.CreatedBy.ID != f.human.ID {
		t.Fatal("证书登记没有固定宿主 owner 或真实创建者")
	}
	first.finish()
	second := f.user(t, "certificate-second-admin", authz.RoleAdmin)
	input := TestCertificateArgs{CertificateID: fixtureCertificate, AttemptID: "second-attempt", Spec: request.Spec}
	call := f.start(t, second, "tls.certificates", "certificates.test", certificateSubject(fixtureCertificate), stringsDigest('a'), input)
	secondCtx, secondCaller, err := f.authority.CertificateContext(call.ctx, fixtureCertificate, input.AttemptID, stringsDigest('a'))
	if err != nil || secondCaller.OwnerID != request.Caller.OwnerID {
		t.Fatal("合法同作用域操作者不能使用共享证书登记")
	}
	current, currentRevision, _, err := f.authority.loadCertificate(f.ctx, fixtureCertificate)
	if err != nil || currentRevision != revision || current.CreatedBy != state.CreatedBy || current.OperationID != state.OperationID {
		t.Fatal("同作用域操作覆盖了原登记审计事实")
	}
	if _, err := f.authority.AcceptedTestRequest(secondCtx); err != nil {
		t.Fatal(err)
	}
	call.finish()
	input.Spec.SANs = []string{"other.example.test"}
	changed := f.start(t, second, "tls.certificates", "certificates.test", certificateSubject(fixtureCertificate), stringsDigest('a'), input)
	_, _, err = f.authority.CertificateContext(changed.ctx, fixtureCertificate, input.AttemptID, stringsDigest('a'))
	requireCode(t, err, "SAN_MISMATCH")
	requireCode(t, (CertificateAuthorizer{Authority: f.authority}).Authorize(ctx, certificates.Authorization{Caller: request.Caller, CertificateID: fixtureCertificate, Access: certificates.Read}), "PERMISSION_DENIED")
}

func TestHostCertificateRegistryRejectsCorruptPrivateFacts(t *testing.T) {
	f := newAuthorityFixture(t)
	_, ctx, request := f.testCertificate(t)
	state, revision, _, err := f.authority.loadCertificate(f.ctx, fixtureCertificate)
	if err != nil {
		t.Fatal(err)
	}
	key, err := f.authority.certificateKey(fixtureCertificate)
	if err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*certificateRegistration){
		func(r *certificateRegistration) { r.OwnerID = "foreign-owner" },
		func(r *certificateRegistration) { r.NodeID = "foreign-node" },
		func(r *certificateRegistration) { r.ID = "foreign-certificate" },
		func(r *certificateRegistration) { r.Version = 2 },
		func(r *certificateRegistration) { r.OperationID = "not-an-operation" },
		func(r *certificateRegistration) { r.ArgsDigest = stringsDigest('a') },
		func(r *certificateRegistration) { r.CreatedBy.ID = "not-a-user" },
		func(r *certificateRegistration) { r.Spec.SANs = []string{"PROXY.EXAMPLE.TEST"} },
		func(r *certificateRegistration) { r.Spec.Purpose = tlsmgr.ServerTLS; r.Spec.SANs = nil },
	} {
		invalid := state
		invalid.Spec = cloneCertificateSpec(state.Spec)
		change(&invalid)
		revision, err = store.Save(f.ctx, f.authority.repository, key, revision, invalid)
		if err != nil {
			t.Fatal(err)
		}
		_, _, _, err = f.authority.loadCertificate(f.ctx, fixtureCertificate)
		requireCode(t, err, "STATE_INVALID")
		revision, err = store.Save(f.ctx, f.authority.repository, key, revision, state)
		if err != nil {
			t.Fatal(err)
		}
	}
	changed := state
	changed.OperationID = f.ids.New(ids.Operation)
	if _, err := store.Save(f.ctx, f.authority.repository, key, revision, changed); err != nil {
		t.Fatal(err)
	}
	requireCode(t, (CertificateAuthorizer{Authority: f.authority}).Authorize(ctx, certificates.Authorization{Caller: request.Caller, CertificateID: fixtureCertificate, Access: certificates.Read}), "PERMISSION_DENIED")
}

func TestHostCertificateConcurrentRegistrationAndRelease(t *testing.T) {
	f := newAuthorityFixture(t)
	input := TestCertificateArgs{CertificateID: fixtureCertificate, AttemptID: fixtureCertificateAttempt, Spec: certificateSpec(tlsmgr.TestServerTLS)}
	first := f.start(t, f.human, "tls.certificates", "certificates.test", certificateSubject(fixtureCertificate), "absent", input)
	input.AttemptID = "concurrent-attempt"
	second := f.start(t, f.human, "tls.certificates", "certificates.test", certificateSubject(fixtureCertificate), "absent", input)
	started := make(chan struct{})
	results := make(chan error, 2)
	var wait sync.WaitGroup
	for _, test := range []struct {
		call    *fixtureCall
		attempt string
	}{{first, fixtureCertificateAttempt}, {second, input.AttemptID}} {
		wait.Add(1)
		go func(call *fixtureCall, attempt string) {
			defer wait.Done()
			<-started
			_, _, err := f.authority.CertificateContext(call.ctx, fixtureCertificate, attempt, "absent")
			results <- err
		}(test.call, test.attempt)
	}
	close(started)
	wait.Wait()
	close(results)
	accepted := 0
	for err := range results {
		if err == nil {
			accepted++
		} else if fault.Code(err) != "REVISION_CONFLICT" {
			t.Fatal(err)
		}
	}
	if accepted == 0 {
		t.Fatal("并发创建没有提交任何合法 CAS 登记")
	}
	ctx, caller, err := f.authority.CertificateContext(first.ctx, fixtureCertificate, fixtureCertificateAttempt, "absent")
	if err != nil {
		t.Fatal(err)
	}
	started = make(chan struct{})
	for range 3 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-started
			_, _ = f.authority.AcceptedTestRequest(ctx)
		}()
	}
	close(started)
	first.release()
	wait.Wait()
	if ctx.Err() != context.Canceled {
		t.Fatal("释放原 operation 没有取消证书上下文")
	}
	if _, err := f.authority.certificateGrant(ctx, caller); err == nil {
		t.Fatal("释放后的证书范围仍可重放")
	}
}

// ======================== 真实取消、RBAC、凭据与 zone 撤销 ========================

func TestHostCertificateRechecksCurrentAuthorizationAndProvider(t *testing.T) {
	for _, stop := range []string{"actor", "cancel", "deadline", "read_only", "provider", "zone", "credential"} {
		t.Run(stop, func(t *testing.T) {
			f := newAuthorityFixture(t)
			registration, providerRevision, zoneRevision := f.certificateProvider(t)
			call, ctx, request := f.issueCertificate(t)
			switch stop {
			case "actor":
				if err := f.db.Update(f.ctx, func(tx *storage.Tx) error {
					_, err := tx.ExecContext(f.ctx, "UPDATE users SET disabled = 1, revision = revision + 1 WHERE user_id = ?", f.human.ID)
					return err
				}); err != nil {
					t.Fatal(err)
				}
			case "cancel":
				if _, err := f.ops.Cancel(f.ctx, operations.CancelRequest{Actor: f.human, OperationID: call.invocation.OperationID,
					Idempotency: operations.Idempotency{Key: f.ids.New(ids.Operation), Method: "POST", Route: "/fixture/certificate-cancel"}}); err != nil {
					t.Fatal(err)
				}
			case "deadline":
				f.clock.Advance(time.Minute + time.Second)
			case "read_only":
				ctx = operations.WithPermissionMode(ctx, operations.PermissionReadOnly)
			case "provider":
				revoke := f.start(t, f.human, "domain.dns", "providers.revoke", providerSubject(fixtureProvider), providerRevision, ProviderArgs{ProviderID: fixtureProvider})
				if _, err := f.authority.RevokeProvider(revoke.ctx, fixtureProvider, providerRevision); err != nil {
					t.Fatal(err)
				}
				revoke.finish()
			case "zone":
				revoke := f.start(t, f.human, "domain.dns", "zones.revoke", zoneSubject(fixtureProvider, fixtureZone), zoneRevision, ZoneArgs{ProviderID: fixtureProvider, ZoneID: fixtureZone})
				if _, err := f.authority.RevokeZone(revoke.ctx, fixtureProvider, fixtureZone, zoneRevision); err != nil {
					t.Fatal(err)
				}
				revoke.finish()
			case "credential":
				if err := f.db.Update(f.ctx, func(tx *storage.Tx) error { return f.secrets.Delete(f.ctx, tx, registration.CredentialRef) }); err != nil {
					t.Fatal(err)
				}
			}
			if err := (CertificateAuthorizer{Authority: f.authority}).Authorize(ctx, certificates.Authorization{Caller: request.Caller,
				CertificateID: request.CertificateID, Spec: request.Scope.Spec, Issuance: &request.Scope, Access: certificates.Issue}); err == nil {
				t.Fatal("当前权限、operation 或提供商变化后仍允许签发")
			}
			if _, err := f.authority.AcceptedIssueRequest(ctx); err == nil {
				t.Fatal("撤权后仍可构造签发请求")
			}
		})
	}
}

func TestHostCertificateRemovalPinsExactGeneration(t *testing.T) {
	f := newAuthorityFixture(t)
	created, _, _ := f.testCertificate(t)
	created.finish()
	input := CertificateTargetArgs{CertificateID: fixtureCertificate, AttemptID: "remove-generation-one", Generation: 1}
	call := f.start(t, f.human, "tls.certificates", "generations.remove", certificateSubject(fixtureCertificate), stringsDigest('a'), input)
	ctx, caller, err := f.authority.CertificateContext(call.ctx, fixtureCertificate, input.AttemptID, stringsDigest('a'))
	if err != nil {
		t.Fatal(err)
	}
	authorizer := CertificateAuthorizer{Authority: f.authority}
	if err := authorizer.Authorize(ctx, certificates.Authorization{Caller: caller, CertificateID: fixtureCertificate, Generation: 1, Access: certificates.Remove}); err != nil {
		t.Fatal(err)
	}
	for _, generation := range []uint64{0, 2} {
		requireCode(t, authorizer.Authorize(ctx, certificates.Authorization{Caller: caller, CertificateID: fixtureCertificate, Generation: generation, Access: certificates.Remove}), "PERMISSION_DENIED")
	}
	target, err := f.authority.AcceptedCertificateTarget(ctx)
	if err != nil || target.CertificateID != input.CertificateID || target.AttemptID != input.AttemptID || target.Generation != input.Generation || target.ExpectedRevision != stringsDigest('a') {
		t.Fatal("原删除目标被扩大或丢失版本")
	}
}
