// SPDX-License-Identifier: AGPL-3.0-only

package hostauth

import (
	"bytes"
	"net/http"
	"testing"

	"github.com/qwq-panel/qwq/internal/prerequisites/dns"
	"github.com/qwq-panel/qwq/internal/storage"
)

// ======================== 私有凭据复制、明确撤权与网络边界 ========================

func TestHostProviderRegistrationUsesAcceptedEncryptedCredentials(t *testing.T) {
	f := newAuthorityFixture(t)
	call, registration, revision := f.register(t)
	if registration.Phase != providerActive || !registration.InputCredentialRef.Valid() || !registration.CredentialRef.Valid() || registration.CredentialRef == registration.InputCredentialRef || registration.CreatedBy.ID != f.human.ID || registration.OwnerID != "installation" {
		t.Fatal("提供商登记未固定宿主 owner、原意图与独立凭据")
	}
	zones, replay, err := f.authority.RegisterProvider(call.ctx, fixtureProvider, "absent")
	if err != nil || replay != revision || len(zones) != 1 || f.api.count() != 1 {
		t.Fatalf("同意图重入产生了发现或版本变化：%v", err)
	}
	zones[0].Name = "changed.test"
	loaded, _, _, err := f.authority.loadProvider(f.ctx, fixtureProvider)
	if err != nil || loaded.Zones[0].Name != "example.test" {
		t.Fatal("公开结果修改了私有发现事实")
	}
	key, err := f.authority.providerKey(fixtureProvider)
	if err != nil {
		t.Fatal(err)
	}
	entry, _, err := f.authority.repository.Get(f.ctx, key)
	if err != nil || bytes.Contains(entry.Value, []byte(f.api.token)) {
		t.Fatal("授权状态包含了提供商明文凭据")
	}
	clear(entry.Value)
	if err := f.db.Update(f.ctx, func(tx *storage.Tx) error { return f.secrets.Delete(f.ctx, tx, registration.InputCredentialRef) }); err != nil {
		t.Fatal(err)
	}
	call.finish()
	confirmed, _, _ := f.zone(t, f.human, "absent")
	confirmed.finish()
	read := f.start(t, f.human, "domain.dns", "records.list", zoneSubject(fixtureProvider, fixtureZone), "", DNSArgs{ProviderID: fixtureProvider, ZoneID: fixtureZone})
	ctx, _, scope, err := f.authority.DNSContext(read.ctx, fixtureProvider, fixtureZone)
	if err != nil {
		t.Fatal(err)
	}
	credentials, err := f.authority.Read(ctx, scope)
	if err != nil || string(credentials.Token) != f.api.token {
		t.Fatalf("原 operation 秘密删除后宿主复制丢失：%v", err)
	}
	credentials.Clear()
	again, err := f.authority.Read(ctx, scope)
	defer again.Clear()
	if err != nil || string(again.Token) != f.api.token {
		t.Fatal("凭据缓冲清零影响了下一次独立读取")
	}
}

func TestHostRevokedProviderCannotReactivateOriginalRegistration(t *testing.T) {
	f := newAuthorityFixture(t)
	registrationCall, before, revision := f.register(t)
	confirmed, _, _ := f.zone(t, f.human, "absent")
	confirmed.finish()
	read := f.start(t, f.human, "domain.dns", "records.list", zoneSubject(fixtureProvider, fixtureZone), "", DNSArgs{ProviderID: fixtureProvider, ZoneID: fixtureZone})
	ctx, _, scope, err := f.authority.DNSContext(read.ctx, fixtureProvider, fixtureZone)
	if err != nil {
		t.Fatal(err)
	}
	revoke := f.start(t, f.human, "domain.dns", "providers.revoke", providerSubject(fixtureProvider), revision, ProviderArgs{ProviderID: fixtureProvider})
	updated, err := f.authority.RevokeProvider(revoke.ctx, fixtureProvider, revision)
	if err != nil {
		t.Fatal(err)
	}
	again, err := f.authority.RevokeProvider(revoke.ctx, fixtureProvider, revision)
	if err != nil || again != updated {
		t.Fatal("同撤权意图重入覆盖了原证据")
	}
	_, _, err = f.authority.RegisterProvider(registrationCall.ctx, fixtureProvider, "absent")
	requireCode(t, err, "CREDENTIAL_REVOKED")
	_, err = f.authority.Read(ctx, scope)
	if err == nil {
		t.Fatal("提供商撤权后旧 DNS scope 仍可取凭据")
	}
	after, _, found, err := f.authority.loadProvider(f.ctx, fixtureProvider)
	if err != nil || !found || after.Phase != providerRevoked || after.CredentialRef != before.CredentialRef || after.InputCredentialRef != before.InputCredentialRef || after.OperationID != before.OperationID || after.Revocation.OperationID != revoke.invocation.OperationID || f.api.count() != 1 {
		t.Fatal("撤权后原登记/凭据证据被覆盖或出现额外网络请求")
	}
}

func TestHostDiscoveryRechecksRevocationBetweenPages(t *testing.T) {
	f := newAuthorityFixture(t)
	f.api.pages = 2
	f.api.afterFirst = func(*http.Request) error {
		pending, revision, found, err := f.authority.loadProvider(f.ctx, fixtureProvider)
		if err != nil || !found || pending.Phase != providerPending {
			t.Fatal("发现前没有持久 pending 意图")
		}
		revoke := f.start(t, f.human, "domain.dns", "providers.revoke", providerSubject(fixtureProvider), revision, ProviderArgs{ProviderID: fixtureProvider})
		_, err = f.authority.RevokeProvider(revoke.ctx, fixtureProvider, revision)
		revoke.finish()
		return err
	}
	call := f.start(t, f.human, "domain.dns", "providers.register", providerSubject(fixtureProvider), "absent",
		map[string]any{"provider_id": fixtureProvider, "kind": dns.Cloudflare, "name": "分页撤权", "credential": map[string]string{"token": f.api.token}})
	if _, _, err := f.authority.RegisterProvider(call.ctx, fixtureProvider, "absent"); err == nil {
		t.Fatal("发现期间撤权仍报告 active")
	}
	state, _, found, err := f.authority.loadProvider(f.ctx, fixtureProvider)
	if err != nil || !found || state.Phase != providerRevoked || f.api.count() != 1 {
		t.Fatal("撤权后发送了后续分页或重新激活登记")
	}
	_, _, err = f.authority.RegisterProvider(call.ctx, fixtureProvider, "absent")
	requireCode(t, err, "CREDENTIAL_REVOKED")
}

func TestHostDiscoveryRechecksCredentialDeletionAndActor(t *testing.T) {
	for _, revoked := range []string{"credential", "actor"} {
		t.Run(revoked, func(t *testing.T) {
			f := newAuthorityFixture(t)
			f.api.pages = 2
			f.api.afterFirst = func(*http.Request) error {
				registration, _, found, err := f.authority.loadProvider(f.ctx, fixtureProvider)
				if err != nil || !found {
					return err
				}
				return f.db.Update(f.ctx, func(tx *storage.Tx) error {
					if revoked == "credential" {
						return f.secrets.Delete(f.ctx, tx, registration.CredentialRef)
					}
					_, err := tx.ExecContext(f.ctx, "UPDATE users SET disabled = 1, revision = revision + 1 WHERE user_id = ?", f.human.ID)
					return err
				})
			}
			call := f.start(t, f.human, "domain.dns", "providers.register", providerSubject(fixtureProvider), "absent",
				map[string]any{"provider_id": fixtureProvider, "kind": dns.Cloudflare, "name": "发现凭据重查", "credential": map[string]string{"token": f.api.token}})
			if _, _, err := f.authority.RegisterProvider(call.ctx, fixtureProvider, "absent"); err == nil {
				t.Fatal("凭据或操作者失效后完成了发现")
			}
			state, _, found, err := f.authority.loadProvider(f.ctx, fixtureProvider)
			if err != nil || !found || state.Phase != providerPending || f.api.count() != 1 {
				t.Fatal("失效后发送了后续分页或发布 active")
			}
		})
	}
}
