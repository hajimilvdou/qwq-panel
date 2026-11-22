// SPDX-License-Identifier: AGPL-3.0-only

package hostauth

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/qwq-panel/qwq/internal/prerequisites/dns"
	"github.com/qwq-panel/qwq/internal/storage"
)

// ======================== 原已接受 CA 请求与正常恢复 ========================

func TestHostOriginalCARequestControlsDNSSubmissionAndRecovery(t *testing.T) {
	f := newCleanupRequestFixture(t)
	f.present(t)
	before, _ := f.backend.counts()
	for _, mutate := range []func(*dns.ChallengeRequest){
		func(r *dns.ChallengeRequest) { r.CertificateID = "other-certificate" },
		func(r *dns.ChallengeRequest) { r.AttemptID = "other-dns-attempt" },
		func(r *dns.ChallengeRequest) { r.SAN = "other.example.test" },
		func(r *dns.ChallengeRequest) { r.Value = strings.Repeat("X", 43) },
		func(r *dns.ChallengeRequest) { r.ExpectedRevision = stringsDigest('b') },
		func(r *dns.ChallengeRequest) { r.Caller.OperationID = "other-operation" },
	} {
		foreign := f.challenge
		mutate(&foreign)
		if _, err := f.manager.PresentChallenge(f.dnsCtx, foreign); err == nil {
			t.Fatal("同 zone 的另一个实际请求借用了原 CA 权限")
		}
	}
	result, err := f.manager.RecoverAttempt(f.dnsCtx, f.challenge.Caller, f.challenge.Scope, f.challenge.CertificateID, f.challenge.AttemptID)
	if err != nil || result.State != dns.Applied || result.RecordID != "original-record" {
		t.Fatalf("正常原请求恢复未接真实私有委托：%v", err)
	}
	if after, _ := f.backend.counts(); after != before {
		t.Fatal("已确认收据恢复或被拒绝的请求访问了提供商")
	}
}

func TestHostOriginalCARequestRecoveryUsesANewActualOperation(t *testing.T) {
	f := newCleanupRequestFixture(t)
	f.present(t)
	_, revision, found, err := f.authority.loadCertificate(f.ctx, f.request.CertificateID)
	if err != nil || !found {
		t.Fatal("原证书登记不存在")
	}
	call := f.start(t, f.human, "tls.certificates", "certificates.issue", certificateSubject(f.request.CertificateID), revision, issueCertificateArgs())
	ctx, caller, err := f.authority.CertificateContext(call.ctx, f.request.CertificateID, f.request.AttemptID, revision)
	if err != nil {
		t.Fatal(err)
	}
	ctx, err = (CertificateDNSContexts{Authority: f.authority}).Context(ctx, caller, f.request.CertificateID, f.request.AttemptID, f.request.Scope, false)
	if err != nil {
		t.Fatal(err)
	}
	result, err := f.manager.RecoverAttempt(ctx, dns.Caller{OwnerID: caller.OwnerID, OperationID: caller.OperationID}, f.challenge.Scope, f.challenge.CertificateID, f.challenge.AttemptID)
	if err != nil || result.State != dns.Applied || caller.OperationID == f.request.Caller.OperationID {
		t.Fatalf("新真实 operation 未重新取得原 DNS 请求范围：%v", err)
	}
}

// ======================== 取消补偿仅删除原已确认 TXT ========================

func TestHostCleanupCancellationUsesOnlyTheOriginalConfirmedRecord(t *testing.T) {
	f := newCleanupRequestFixture(t)
	f.present(t)
	f.cancel(t)
	if _, err := f.authority.current(context.WithoutCancel(f.certificateCtx)); err == nil {
		t.Fatal("取消后普通派发权限被放宽")
	}
	source, stopSource, owned := f.source(t)
	defer stopSource()
	before, _ := f.backend.counts()
	if _, err := f.manager.List(source, f.challenge.Caller, f.challenge.Scope); err == nil {
		t.Fatal("Source-only 读取获得了提供商网络权限")
	}
	if credentials, err := (CredentialSource{Authority: f.authority}).Read(source, f.challenge.Scope); err == nil {
		credentials.Clear()
		t.Fatal("Source-only 读取获得了提供商凭据")
	}
	if after, _ := f.backend.counts(); after != before {
		t.Fatal("Source-only 被拒绝后仍访问了提供商")
	}
	bound, stopRecord, err := f.contexts.ForChallenge(source, f.request.Caller, f.request.CertificateID, f.request.AttemptID, f.request.Scope, owned)
	if err != nil {
		t.Fatal(err)
	}
	defer stopRecord()
	credentials, err := (CleanupCredentials{Authority: f.authority}).Read(bound, f.challenge.Scope)
	defer credentials.Clear()
	if err != nil || len(credentials.Token) == 0 {
		t.Fatalf("原记录补偿未取得受限真实凭据：%v", err)
	}
	if err := f.manager.CleanupChallenge(bound, f.challenge.Caller, f.challenge.Scope, f.challenge.CertificateID, f.challenge.AttemptID); err != nil {
		t.Fatal(err)
	}
	if err := f.manager.CleanupChallenge(bound, f.challenge.Caller, f.challenge.Scope, f.challenge.CertificateID, f.challenge.AttemptID); err != nil {
		t.Fatal(err)
	}
	if _, deletes := f.backend.counts(); deletes != 1 {
		t.Fatal("原已确认记录没有且仅有一次删除")
	}
}

func TestHostCleanupRejectsForgedOrDifferentRecordFacts(t *testing.T) {
	f := newCleanupRequestFixture(t)
	f.present(t)
	source, stopSource, owned := f.source(t)
	defer stopSource()
	before, _ := f.backend.counts()
	if _, stop, err := f.contexts.ForChallenge(source, f.request.Caller, f.request.CertificateID, f.request.AttemptID, f.request.Scope, dns.OwnedChallenge{}); err == nil {
		stop()
		t.Fatal("零值或 DTO 伪造记录获得了清理许可")
	}
	if _, stop, err := f.contexts.ForChallenge(source, f.request.Caller, "other-certificate", f.request.AttemptID, f.request.Scope, owned); err == nil {
		stop()
		t.Fatal("另一个证书借用了原记录许可")
	}
	changed := f.request.Scope
	changed.Provider.Revision = stringsDigest('b')
	if _, stop, err := f.contexts.ForChallenge(source, f.request.Caller, f.request.CertificateID, f.request.AttemptID, changed, owned); err == nil {
		stop()
		t.Fatal("另一 scope 借用了原记录许可")
	}
	if after, _ := f.backend.counts(); after != before {
		t.Fatal("错误记录事实发起了提供商请求")
	}
}

func TestHostCleanupPrivateCredentialFailureDoesNotFallback(t *testing.T) {
	f := newCleanupRequestFixture(t)
	ordinary, err := f.authority.Read(f.dnsCtx, f.challenge.Scope)
	if err != nil {
		t.Fatal(err)
	}
	ordinary.Clear()
	for _, private := range []context.Context{
		context.WithValue(f.dnsCtx, cleanupPreparationKey{}, false),
		context.WithValue(f.dnsCtx, cleanupExecutionKey{}, (*cleanupExecution)(nil)),
	} {
		credentials, err := (CredentialSource{Authority: f.authority}).Read(private, f.challenge.Scope)
		credentials.Clear()
		if err == nil {
			t.Fatal("错误私有清理 context 回落到了可用普通凭据路径")
		}
		if err := (RequestDNSAuthorizer{DNSAuthorizer{Authority: f.authority}}).Authorize(private, f.challenge.Caller, f.challenge.Scope, dns.Read); err == nil {
			t.Fatal("错误私有清理 context 回落到了普通 DNS 权限")
		}
	}
}

func TestHostCleanupRechecksActorCredentialsReleaseAndExpiry(t *testing.T) {
	for _, stop := range []string{"actor", "credential", "release", "expiry"} {
		t.Run(stop, func(t *testing.T) {
			f := newCleanupRequestFixture(t)
			f.present(t)
			bound, finish := f.bound(t)
			defer finish()
			switch stop {
			case "actor":
				if err := f.db.Update(f.ctx, func(tx *storage.Tx) error {
					_, err := tx.ExecContext(f.ctx, "UPDATE users SET disabled = 1, revision = revision + 1 WHERE user_id = ?", f.human.ID)
					return err
				}); err != nil {
					t.Fatal(err)
				}
			case "credential":
				registration, _, found, err := f.authority.loadProvider(f.ctx, fixtureProvider)
				if err != nil || !found {
					t.Fatal("原提供商不存在")
				}
				if err := f.db.Update(f.ctx, func(tx *storage.Tx) error { return f.secrets.Delete(f.ctx, tx, registration.CredentialRef) }); err != nil {
					t.Fatal(err)
				}
			case "release":
				f.call.release()
			case "expiry":
				f.clock.Advance(16 * time.Second)
			}
			before, deletes := f.backend.counts()
			credentials, err := (CredentialSource{Authority: f.authority}).Read(bound, f.challenge.Scope)
			credentials.Clear()
			if err == nil {
				t.Fatal("失效清理许可仍取得了凭据")
			}
			if err := f.manager.CleanupChallenge(bound, f.challenge.Caller, f.challenge.Scope, f.challenge.CertificateID, f.challenge.AttemptID); err == nil {
				t.Fatal("失效清理许可仍删除了记录")
			}
			if after, actualDeletes := f.backend.counts(); after != before || actualDeletes != deletes {
				t.Fatal("失效清理许可发起了网络请求")
			}
		})
	}
}

func TestHostCleanupOriginalSourceWindowIncludesReadingAndCannotReopen(t *testing.T) {
	f := newCleanupRequestFixture(t)
	f.present(t)
	f.contexts.Timeout = time.Second
	source, stopSource, owned := f.source(t)
	defer stopSource()
	f.clock.Advance(2 * time.Second)
	if _, stop, err := f.contexts.ForChallenge(source, f.request.Caller, f.request.CertificateID, f.request.AttemptID, f.request.Scope, owned); err == nil {
		stop()
		t.Fatal("原私有读取耗尽窗口后仍能 mint 记录许可")
	}
	f.contexts.Timeout = 30 * time.Second
	if _, stop, err := f.contexts.Source(context.WithoutCancel(f.certificateCtx), f.request.Caller, f.request.CertificateID, f.request.AttemptID, f.request.Scope); err == nil {
		stop()
		t.Fatal("较长 TTL 的 fresh Source 重开了原 executor 窗口")
	}
	if _, deletes := f.backend.counts(); deletes != 0 {
		t.Fatal("已耗尽读取窗口仍执行了删除")
	}
}
