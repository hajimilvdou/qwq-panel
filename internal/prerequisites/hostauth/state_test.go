// SPDX-License-Identifier: AGPL-3.0-only

package hostauth

import (
	"encoding/json"
	"testing"

	"github.com/qwq-panel/qwq/internal/actor"
	"github.com/qwq-panel/qwq/internal/authz"
	"github.com/qwq-panel/qwq/internal/platform/ids"
	"github.com/qwq-panel/qwq/internal/prerequisites/dns"
	"github.com/qwq-panel/qwq/internal/prerequisites/provider"
	"github.com/qwq-panel/qwq/internal/prerequisites/store"
	"github.com/qwq-panel/qwq/internal/secrets"
	"github.com/qwq-panel/qwq/internal/storage"
)

// ======================== 固定 owner、共享资源管理与确认版本 ========================

func TestHostZoneRevocationRequiresNewIntentAndAllowsScopedOperator(t *testing.T) {
	f := newAuthorityFixture(t)
	registered, registration, _ := f.register(t)
	registered.finish()
	confirmed, originalScope, originalRevision := f.zone(t, f.human, "absent")
	operator := f.user(t, "second-operator", authz.RoleOperator)
	revoke := f.start(t, operator, "domain.dns", "zones.revoke", zoneSubject(fixtureProvider, fixtureZone), originalRevision,
		ZoneArgs{ProviderID: fixtureProvider, ZoneID: fixtureZone})
	revoked, err := f.authority.RevokeZone(revoke.ctx, fixtureProvider, fixtureZone, originalRevision)
	if err != nil {
		t.Fatal(err)
	}
	again, err := f.authority.RevokeZone(revoke.ctx, fixtureProvider, fixtureZone, originalRevision)
	if err != nil || again != revoked {
		t.Fatal("重复撤权改变了原意图证据")
	}
	_, _, err = f.authority.AuthorizeZone(confirmed.ctx, fixtureProvider, fixtureZone, "absent")
	requireCode(t, err, "ZONE_DENIED")
	confirmed.finish()
	revoke.finish()
	if err := f.db.Update(f.ctx, func(tx *storage.Tx) error {
		_, err := tx.ExecContext(f.ctx, "UPDATE users SET disabled = 1, revision = revision + 1 WHERE user_id = ?", f.human.ID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	reauthorized, scope, _ := f.zone(t, operator, revoked)
	if scope.Revision == originalScope.Revision {
		t.Fatal("重新确认没有使旧 scope 失效")
	}
	zone, _, found, err := f.authority.loadZone(f.ctx, fixtureProvider, fixtureZone)
	if err != nil || !found || zone.ConfirmedBy.ID != operator.ID || zone.OwnerID != "installation" || registration.CreatedBy.ID != f.human.ID {
		t.Fatal("资源 owner 被永久绑定首次用户，或确认人与创建人混合")
	}
	reauthorized.finish()
	read := f.start(t, operator, "domain.dns", "records.list", zoneSubject(fixtureProvider, fixtureZone), "", DNSArgs{ProviderID: fixtureProvider, ZoneID: fixtureZone})
	ctx, _, actual, err := f.authority.DNSContext(read.ctx, fixtureProvider, fixtureZone)
	if err != nil {
		t.Fatal(err)
	}
	credentials, err := f.authority.Read(ctx, actual)
	credentials.Clear()
	if err != nil {
		t.Fatal("同作用域合法操作者不能使用共享资源")
	}
}

func TestHostZoneOnlyAcceptsDiscoveredIDAndOperationRevision(t *testing.T) {
	f := newAuthorityFixture(t)
	registered, _, _ := f.register(t)
	registered.finish()
	unknown := "33333333333333333333333333333333"
	call := f.start(t, f.human, "domain.dns", "zones.authorize", zoneSubject(fixtureProvider, unknown), "absent", ZoneArgs{ProviderID: fixtureProvider, ZoneID: unknown})
	_, _, err := f.authority.AuthorizeZone(call.ctx, fixtureProvider, unknown, "absent")
	requireCode(t, err, "ZONE_DENIED")
	call.finish()
	confirmed, scope, revision := f.zone(t, f.human, "absent")
	again, same, err := f.authority.AuthorizeZone(confirmed.ctx, fixtureProvider, fixtureZone, "absent")
	if err != nil || again != scope || same != revision {
		t.Fatal("同确认意图重入产生新 scope")
	}
	_, _, err = f.authority.AuthorizeZone(confirmed.ctx, fixtureProvider, fixtureZone, revision)
	requireCode(t, err, "PERMISSION_DENIED")
	other, err := New(f.options("other-installation", "local"))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, found, err := other.loadProvider(f.ctx, fixtureProvider); err != nil || found {
		t.Fatal("另一 owner 看见了原提供商登记")
	}
	otherNode, err := New(f.options("installation", "other-node"))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, found, err := otherNode.loadZone(f.ctx, fixtureProvider, fixtureZone); err != nil || found {
		t.Fatal("另一节点看见了原 zone 登记")
	}
}

// ======================== 私有持久状态完整性与失败预算 ========================

func TestHostProviderStateRejectsIncompleteAndForgedFacts(t *testing.T) {
	f := newAuthorityFixture(t)
	call, original, revision := f.register(t)
	call.finish()
	key, err := f.authority.providerKey(fixtureProvider)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name   string
		mutate func(*providerRegistration)
	}{
		{"owner", func(v *providerRegistration) { v.OwnerID = "foreign" }},
		{"node", func(v *providerRegistration) { v.NodeID = "other-node" }},
		{"kind", func(v *providerRegistration) { v.Kind = "custom" }},
		{"name", func(v *providerRegistration) { v.Name = "invalid\nname" }},
		{"actor", func(v *providerRegistration) { v.CreatedBy = actor.SystemActor("reconciler") }},
		{"operation", func(v *providerRegistration) { v.OperationID = "not-an-operation" }},
		{"digest", func(v *providerRegistration) { v.ArgsDigest = "bad" }},
		{"phase", func(v *providerRegistration) { v.Phase = "enabled" }},
		{"active_without_credential", func(v *providerRegistration) { v.CredentialRef = "" }},
		{"input_reference", func(v *providerRegistration) { v.InputCredentialRef = secrets.Ref("invalid") }},
		{"wrong_reference", func(v *providerRegistration) { v.CredentialRef = v.InputCredentialRef }},
		{"pending_with_zones", func(v *providerRegistration) { v.Phase = providerPending }},
		{"revoked_without_evidence", func(v *providerRegistration) { v.Phase = providerRevoked }},
		{"duplicate_zones", func(v *providerRegistration) { v.Zones = []provider.Zone{v.Zones[0], v.Zones[0]} }},
		{"noncanonical_zone", func(v *providerRegistration) { v.Zones = []provider.Zone{{ID: fixtureZone, Name: "Example.TEST"}} }},
	} {
		t.Run(test.name, func(t *testing.T) {
			mutated := original
			test.mutate(&mutated)
			var err error
			revision, err = store.Save(f.ctx, f.authority.repository, key, revision, mutated)
			if err != nil {
				t.Fatal(err)
			}
			_, _, _, err = f.authority.loadProvider(f.ctx, fixtureProvider)
			requireCode(t, err, "STATE_INVALID")
		})
	}
	if _, err := store.Save(f.ctx, f.authority.repository, key, revision, original); err != nil {
		t.Fatal(err)
	}
}

func TestHostZoneStateRejectsIncompleteScopeAndMembership(t *testing.T) {
	f := newAuthorityFixture(t)
	call, _, _ := f.register(t)
	call.finish()
	confirmed, _, revision := f.zone(t, f.human, "absent")
	confirmed.finish()
	original, _, _, err := f.authority.loadZone(f.ctx, fixtureProvider, fixtureZone)
	if err != nil {
		t.Fatal(err)
	}
	key, err := f.authority.zoneKey(fixtureProvider, fixtureZone)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name   string
		mutate func(*zoneRegistration)
	}{
		{"owner", func(v *zoneRegistration) { v.OwnerID = "foreign" }},
		{"node", func(v *zoneRegistration) { v.NodeID = "other-node" }},
		{"kind", func(v *zoneRegistration) { v.Kind = "custom" }},
		{"name", func(v *zoneRegistration) { v.Name = "Example.TEST" }},
		{"confirmer", func(v *zoneRegistration) {
			v.ConfirmedBy = actor.Actor{Kind: actor.Service, ID: f.ids.New(ids.Service)}
		}},
		{"operation", func(v *zoneRegistration) { v.OperationID = "invalid" }},
		{"digest", func(v *zoneRegistration) { v.ArgsDigest = "bad" }},
		{"provider_revision", func(v *zoneRegistration) { v.ProviderRevision = "bad" }},
		{"base_revision", func(v *zoneRegistration) { v.BaseRevision = "bad" }},
		{"revoked_without_evidence", func(v *zoneRegistration) { v.Enabled = false }},
	} {
		t.Run(test.name, func(t *testing.T) {
			mutated := original
			test.mutate(&mutated)
			var err error
			revision, err = store.Save(f.ctx, f.authority.repository, key, revision, mutated)
			if err != nil {
				t.Fatal(err)
			}
			_, _, _, err = f.authority.loadZone(f.ctx, fixtureProvider, fixtureZone)
			requireCode(t, err, "STATE_INVALID")
		})
	}
	changed := original
	changed.Name = "other.test"
	if _, err := store.Save(f.ctx, f.authority.repository, key, revision, changed); err != nil {
		t.Fatal(err)
	}
	_, _, _, err = f.authority.resolveScope(f.ctx, fixtureProvider, fixtureZone)
	requireCode(t, err, "STATE_INVALID")
}

func TestHostCopiedCredentialsRefusesForeignOwnerAndPurpose(t *testing.T) {
	for _, foreign := range []string{"owner", "purpose"} {
		t.Run(foreign, func(t *testing.T) {
			f := newAuthorityFixture(t)
			call, registration, _ := f.register(t)
			owner, purpose := credentialOwner(f.authority.ownerID, f.authority.nodeID, registration.ID), credentialPurpose(registration.OperationID)
			if foreign == "owner" {
				owner = "plugins/foreign"
			} else {
				purpose = "plugin.operation"
			}
			raw, err := json.Marshal(map[string]string{"token": f.api.token})
			if err != nil {
				t.Fatal(err)
			}
			defer clear(raw)
			var ref secrets.Ref
			if err := f.db.Update(f.ctx, func(tx *storage.Tx) error {
				var err error
				ref, err = f.secrets.EnsureOwned(f.ctx, tx, owner, purpose, raw)
				return err
			}); err != nil {
				t.Fatal(err)
			}
			registration.CredentialRef = ref
			_, err = f.authority.providerCredentials(call.ctx, registration)
			requireCode(t, err, "CREDENTIAL_REVOKED")
		})
	}
}

func TestHostRegistrationQuotaFailsBeforeCredentialCopy(t *testing.T) {
	f := newAuthorityFixture(t)
	bounded, err := store.NewEncrypted(store.EncryptedOptions{DB: f.db, Secrets: f.secrets, Namespace: "authorizations", MaxEntries: 1})
	if err != nil {
		t.Fatal(err)
	}
	f.authority.repository = bounded
	call, _, _ := f.register(t)
	call.finish()
	second := "provider-second"
	request := f.start(t, f.human, "domain.dns", "providers.register", providerSubject(second), "absent",
		map[string]any{"provider_id": second, "kind": dns.Cloudflare, "name": "预算边界", "credential": map[string]string{"token": f.api.token}})
	_, _, err = f.authority.RegisterProvider(request.ctx, second, "absent")
	requireCode(t, err, "RESOURCE_EXHAUSTED")
	_, found, err := f.secrets.FindOwned(f.ctx, credentialOwner(f.authority.ownerID, f.authority.nodeID, second), credentialPurpose(request.invocation.OperationID))
	if err != nil || found || f.api.count() != 1 {
		t.Fatal("登记预算失败仍复制了宿主凭据或发出发现请求")
	}
}
