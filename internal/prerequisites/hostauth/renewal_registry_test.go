// SPDX-License-Identifier: AGPL-3.0-only

package hostauth

import (
	"context"
	"testing"
	"time"

	"github.com/qwq-panel/qwq/internal/authz"
	"github.com/qwq-panel/qwq/internal/prerequisites/fault"
	"github.com/qwq-panel/qwq/internal/prerequisites/store"
	"github.com/qwq-panel/qwq/internal/storage"
)

// ======================== 确認后等待服務與只讀准备，不复活原job ========================

func TestHostRenewalPreparationUsesConfirmedLocalScopeWithoutMint(t *testing.T) {
	f := newRenewalRegistryFixture(t, false)
	view := f.register(t)
	if view.State != "awaiting_service" || view.ServiceAccountID != "" {
		t.Fatal("没有实际服务账号便宣称自动续期已启用")
	}
	f.call.finish()
	request, err := f.binding.f.authority.PrepareRenewalService(f.binding.f.ctx, f.binding.f.human, f.args.PolicyID, view.Revision)
	if err != nil || request.PolicyID != f.args.PolicyID || request.Scope.OwnerID != "installation" || request.Scope.CertificateID != fixtureCertificate ||
		request.Scope.Issuance.Provider.ProviderID != fixtureProvider || request.Scope.Issuance.Provider.ZoneID != fixtureZone || request.Scope.Issuance.CA != f.args.CA ||
		len(request.Scope.Consumers) != 1 || request.Scope.Consumers[0] != f.binding.want || !request.ExpiresAt.Equal(f.args.ExpiresAt) {
		t.Fatalf("准备未读取原私有完整范围：%v", err)
	}
	request.Scope.Issuance.Spec.SANs[0] = "other.example.test"
	request.Scope.Consumers[0].ProfileID = "other-profile"
	actual, err := f.binding.f.authority.PrepareRenewalService(f.binding.f.ctx, f.binding.f.human, f.args.PolicyID, view.Revision)
	if err != nil || actual.Scope.Issuance.Spec.SANs[0] == "other.example.test" || actual.Scope.Consumers[0] != f.binding.want || f.mint.calls != 0 {
		t.Fatal("准备DTO改写了私有范围，或误调用服务创建器")
	}
	// Root同步bootstrap持有写事务时，这条只读准备不能重入db.Update。
	if err := f.binding.f.db.Update(f.binding.f.ctx, func(*storage.Tx) error {
		_, err := f.binding.f.authority.PrepareRenewalService(f.binding.f.ctx, f.binding.f.human, f.args.PolicyID, view.Revision)
		return err
	}); err != nil {
		t.Fatalf("持有写事务时准备不可完成：%v", err)
	}
}

// ======================== 读取期间撤权、取消与持久CAS事实 ========================

func TestHostRenewalPreparationRechecksBindingChangedDuringSourceRead(t *testing.T) {
	f := newRenewalRegistryFixture(t, false)
	view := f.register(t)
	f.call.finish()
	source := f.binding.f.authority.consumers.(*consumerSourceFixture)
	source.before = func() {
		source.before = nil
		state, revision, err := f.binding.f.authority.loadBindingLedger(f.binding.f.ctx)
		if err != nil {
			t.Fatal(err)
		}
		state.Entries[0].Phase = bindingRevoked
		if err := f.binding.f.authority.saveBindingLedger(f.binding.f.ctx, state, revision); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := f.binding.f.authority.PrepareRenewalService(f.binding.f.ctx, f.binding.f.human, f.args.PolicyID, view.Revision); err == nil || f.mint.calls != 0 {
		t.Fatal("源读取期间撤销的绑定仍产生可用续期范围")
	}
}

func TestHostRenewalPreparationRejectsCurrentRevocationAndCancelledContext(t *testing.T) {
	for _, failure := range []string{"actor-during-read", "cancelled", "credentials", "zone"} {
		t.Run(failure, func(t *testing.T) {
			f := newRenewalRegistryFixture(t, false)
			view := f.register(t)
			f.call.finish()
			ctx := f.binding.f.ctx
			switch failure {
			case "actor-during-read":
				source := f.binding.f.authority.consumers.(*consumerSourceFixture)
				source.before = func() {
					source.before = nil
					if err := f.binding.f.db.Update(ctx, func(tx *storage.Tx) error {
						_, err := tx.ExecContext(ctx, "UPDATE users SET role='viewer' WHERE user_id=?", f.binding.f.human.ID)
						return err
					}); err != nil {
						t.Fatal(err)
					}
				}
			case "cancelled":
				cancelled, cancel := context.WithCancel(ctx)
				cancel()
				ctx = cancelled
			case "credentials":
				provider, _, found, err := f.binding.f.authority.loadProvider(ctx, fixtureProvider)
				if err != nil || !found {
					t.Fatal("真实提供商登记缺失")
				}
				if err := f.binding.f.db.Update(ctx, func(tx *storage.Tx) error {
					return f.binding.f.secrets.Delete(ctx, tx, provider.CredentialRef)
				}); err != nil {
					t.Fatal(err)
				}
			case "zone":
				zone, revision, found, err := f.binding.f.authority.loadZone(ctx, fixtureProvider, fixtureZone)
				if err != nil || !found {
					t.Fatal("真实zone登记缺失")
				}
				// 合法的新确认版本也必须使旧固定scope失效。
				zone.BaseRevision = revision
				key, err := f.binding.f.authority.zoneKey(fixtureProvider, fixtureZone)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := store.Save(ctx, f.binding.f.authority.repository, key, revision, zone); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := f.binding.f.authority.PrepareRenewalService(ctx, f.binding.f.human, f.args.PolicyID, view.Revision); err == nil || f.mint.calls != 0 {
				t.Fatal("撤权、取消或DNS事实变更后仍准备了续期范围")
			}
		})
	}
}

func TestHostRenewalLedgerRejectsMalformedScopeAndPreservesCAS(t *testing.T) {
	f := newRenewalRegistryFixture(t, false)
	view := f.register(t)
	f.call.finish()
	state, original, err := f.binding.f.authority.loadRenewalLedger(f.binding.f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	state.Entries[0].Version++
	if err := f.binding.f.authority.saveRenewalLedger(f.binding.f.ctx, state, original); err != nil {
		t.Fatal(err)
	}
	if err := f.binding.f.authority.saveRenewalLedger(f.binding.f.ctx, state, original); fault.Code(err) != "REVISION_CONFLICT" {
		t.Fatalf("旧CAS覆盖了实际新版本：%v", err)
	}
	if _, err := f.binding.f.authority.PrepareRenewalService(f.binding.f.ctx, f.binding.f.human, f.args.PolicyID, view.Revision); fault.Code(err) != "REVISION_CONFLICT" {
		t.Fatal("旧公开策略revision未失效")
	}
	state, current, err := f.binding.f.authority.loadRenewalLedger(f.binding.f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	state.Entries[0].ConfirmationActor.ID = "unknown-confirmation"
	if err := f.binding.f.authority.saveRenewalLedger(f.binding.f.ctx, state, current); err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.binding.f.authority.loadRenewalLedger(f.binding.f.ctx); fault.Code(err) != "STATE_INVALID" {
		t.Fatal("损坏的持久确认人被当作真实审批事实")
	}
}

func TestHostRenewalPolicyRequiresActualApprovedHumanConfirmation(t *testing.T) {
	f := newRenewalRegistryFixture(t, true)
	if _, err := f.binding.f.authority.RegisterRenewalPolicy(f.call.ctx, f.args.PolicyID, "absent"); fault.Code(err) != "APPROVAL_REQUIRED" {
		t.Fatalf("FullMode缺真实确认者仍建立可mint策略：%v", err)
	}
	if _, err := f.binding.f.authority.PrepareRenewalService(f.binding.f.ctx, f.binding.f.human, f.args.PolicyID, "absent"); err == nil || f.mint.calls != 0 {
		t.Fatal("没有已确认策略仍可准备或mint服务")
	}
}

func TestHostRenewalPreparationRejectsRevisionViewerRevocationAndExpiry(t *testing.T) {
	for _, failure := range []string{"revision", "viewer", "actor", "expiry", "consumer"} {
		t.Run(failure, func(t *testing.T) {
			f := newRenewalRegistryFixture(t, false)
			view := f.register(t)
			f.call.finish()
			who, revision := f.binding.f.human, view.Revision
			if failure == "revision" {
				revision = stringsDigest('f')
			}
			if failure == "viewer" {
				who = f.binding.f.user(t, "renew-viewer", authz.RoleViewer)
			}
			if failure == "actor" {
				if err := f.binding.f.db.Update(f.binding.f.ctx, func(tx *storage.Tx) error {
					_, err := tx.ExecContext(f.binding.f.ctx, "UPDATE users SET disabled=1, revision=revision+1 WHERE user_id=?", f.binding.f.human.ID)
					return err
				}); err != nil {
					t.Fatal(err)
				}
			}
			if failure == "expiry" {
				f.binding.f.clock.Advance(25 * time.Hour)
			}
			if failure == "consumer" {
				source := f.binding.f.authority.consumers.(*consumerSourceFixture)
				source.facts.Consumer.SNI = "other.example.test"
			}
			if _, err := f.binding.f.authority.PrepareRenewalService(f.binding.f.ctx, who, f.args.PolicyID, revision); err == nil || f.mint.calls != 0 {
				t.Fatal("策略/权限/消费者失效仍可准备服务范围")
			}
		})
	}
}

func TestHostRenewalServiceAttachmentRequiresActualExactAccount(t *testing.T) {
	f := newRenewalRegistryFixture(t, false)
	view := f.register(t)
	f.call.finish()
	scope := &authz.ServiceScope{Actions: []string{"tls.certificates/renew_existing"}, NodeIDs: []string{"local"},
		Subjects: []string{certificateSubject(fixtureCertificate)}, ExpiresAt: f.args.ExpiresAt}
	wrong := f.service(t, "renew-wrong-role", authz.RoleAdmin, scope)
	input := RenewalServiceArgs{PolicyID: f.args.PolicyID, ServiceAccountID: wrong.ID}
	call := f.binding.f.start(t, f.binding.f.human, "tls.certificates", "renewal.attach_service", renewalPolicySubject(f.args.PolicyID), view.Revision, input)
	if _, err := f.binding.f.authority.AttachRenewalService(call.ctx, f.args.PolicyID, view.Revision); err == nil {
		t.Fatal("宽角色服务账号被登记为精确续期账号")
	}
	call.finish()
	actual := f.service(t, "renew-exact", authz.RoleOperator, scope)
	input.ServiceAccountID = actual.ID
	call = f.binding.f.start(t, f.binding.f.human, "tls.certificates", "renewal.attach_service", renewalPolicySubject(f.args.PolicyID), view.Revision, input)
	active, err := f.binding.f.authority.AttachRenewalService(call.ctx, f.args.PolicyID, view.Revision)
	if err != nil || active.State != "active" || active.ServiceAccountID != actual.ID || f.mint.calls != 0 {
		t.Fatalf("实际精确服务账号未激活私有授权：%v", err)
	}
}
