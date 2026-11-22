// SPDX-License-Identifier: AGPL-3.0-only

package hostauth

import (
	"context"
	"sync/atomic"
	"testing"

	"github.com/qwq-panel/qwq/internal/prerequisites/dns"
	"github.com/qwq-panel/qwq/internal/prerequisites/fault"
	"github.com/qwq-panel/qwq/internal/prerequisites/store"
)

// ======================== 普通 DNS 的实际授权与同 Manager 未知结果恢复 ========================

// 网络数据复用原凭据 fixture；只有第三次列表请求注入未知响应，不替代实际授权。
type recoveryCredentialProvider struct {
	*cleanupCredentialProvider
	lists  atomic.Int32
	writes atomic.Int32
}

func (p *recoveryCredentialProvider) For(ctx context.Context, scope dns.Scope) (dns.Provider, error) {
	if err := p.authorize(ctx, scope); err != nil {
		return nil, err
	}
	return p, nil
}

func (p *recoveryCredentialProvider) List(ctx context.Context, scope dns.Scope) ([]dns.Record, error) {
	if p.lists.Add(1) == 3 {
		return nil, fault.New("PROVIDER_UNAVAILABLE", "fixture 原写响应后列表暂不可用")
	}
	return p.cleanupCredentialProvider.List(ctx, scope)
}

func (p *recoveryCredentialProvider) Create(ctx context.Context, scope dns.Scope, record dns.Record) (dns.Record, error) {
	p.writes.Add(1)
	return p.cleanupCredentialProvider.Create(ctx, scope, record)
}

type onlyDNSPermission struct{ source dns.Authorizer }

func (p onlyDNSPermission) Authorize(ctx context.Context, caller dns.Caller, scope dns.Scope, access dns.Access) error {
	return p.source.Authorize(ctx, caller, scope, access)
}

func TestHostDNSRecoveryRequiresOriginalAttemptAndNeverResendsWrite(t *testing.T) {
	f := newAuthorityFixture(t)
	registered, _, _ := f.register(t)
	registered.finish()
	confirmed, scope, _ := f.zone(t, f.human, "absent")
	confirmed.finish()
	repository, err := store.NewEncrypted(store.EncryptedOptions{DB: f.db, Secrets: f.secrets, Namespace: "dns"})
	if err != nil {
		t.Fatal(err)
	}
	backend := &recoveryCredentialProvider{cleanupCredentialProvider: &cleanupCredentialProvider{
		credentials: CredentialSource{Authority: f.authority}, scope: scope}}
	authorization := DNSAuthorizer{Authority: f.authority}
	manager, err := dns.New(dns.Options{Repository: repository, Providers: backend, Authorizer: authorization, Clock: f.clock})
	if err != nil {
		t.Fatal(err)
	}
	read := f.start(t, f.human, "domain.dns", "records.list", zoneSubject(fixtureProvider, fixtureZone), "absent",
		DNSArgs{ProviderID: fixtureProvider, ZoneID: fixtureZone})
	readCtx, caller, _, err := f.authority.DNSContext(read.ctx, fixtureProvider, fixtureZone)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := manager.List(readCtx, caller, scope)
	if err != nil {
		t.Fatal(err)
	}
	read.finish()
	change := dns.Change{Action: dns.Create, Record: dns.Record{Type: dns.A, Name: "a.example.test", Value: "192.0.2.42", TTL: 300}}
	apply := f.start(t, f.human, "domain.dns", "records.apply", zoneSubject(fixtureProvider, fixtureZone), snapshot.Revision,
		DNSArgs{ProviderID: fixtureProvider, ZoneID: fixtureZone, AttemptID: "ordinary-attempt", Change: &change})
	applyCtx, _, _, err := f.authority.DNSContext(apply.ctx, fixtureProvider, fixtureZone)
	if err != nil {
		t.Fatal(err)
	}
	request, err := f.authority.AcceptedDNSRequest(applyCtx)
	if err != nil {
		t.Fatal(err)
	}
	if receipt, err := manager.Apply(applyCtx, request); fault.Code(err) != "OUTCOME_UNKNOWN" || receipt.State != dns.Unknown {
		t.Fatal("fixture 没有产生原写已发出的未知收据")
	}
	apply.finish()
	current := f.start(t, f.human, "domain.dns", "records.reconcile", zoneSubject(fixtureProvider, fixtureZone), snapshot.Revision,
		DNSArgs{ProviderID: fixtureProvider, ZoneID: fixtureZone, AttemptID: request.AttemptID})
	ctx, caller, scope, err := f.authority.DNSContext(current.ctx, fixtureProvider, fixtureZone)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.RecoverAttempt(ctx, caller, scope, "", "another-attempt"); fault.Code(err) != "PERMISSION_DENIED" {
		t.Fatal("普通恢复读取了原意图之外的attempt")
	}
	other := scope
	other.ZoneID = "22222222222222222222222222222222"
	if _, err := manager.RecoverAttempt(ctx, caller, other, "", request.AttemptID); err == nil {
		t.Fatal("普通恢复扩展到另一zone")
	}
	forged := request
	forged.Caller = caller
	if _, err := manager.Apply(ctx, forged); fault.Code(err) != "PERMISSION_DENIED" {
		t.Fatal("Reconcile 取得了外部DNS写许可")
	}
	if receipt, err := manager.RecoverAttempt(ctx, caller, scope, "", request.AttemptID); err != nil || receipt.State != dns.Applied || receipt.RecordID != "original-record" {
		t.Fatalf("当前新operation未能只读恢复原收据：%v", err)
	}
	if backend.writes.Load() != 1 {
		t.Fatal("普通DNS对账重新发送了已不确定的原写")
	}
	missing, err := dns.New(dns.Options{Repository: repository, Providers: backend, Authorizer: onlyDNSPermission{source: authorization}, Clock: f.clock})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := missing.RecoverAttempt(ctx, caller, scope, "", request.AttemptID); fault.Code(err) != "BACKEND_REQUIRED" {
		t.Fatal("缺少原attempt窄来源仍允许普通恢复")
	}
	current.release()
	if _, err := manager.RecoverAttempt(ctx, caller, scope, "", request.AttemptID); err == nil || backend.writes.Load() != 1 {
		t.Fatal("释放后的来源继续对账或发送了外部写")
	}
}
