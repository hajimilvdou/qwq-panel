// SPDX-License-Identifier: AGPL-3.0-only

package hostauth

import (
	"context"
	"testing"

	"github.com/qwq-panel/qwq/internal/actor"
	"github.com/qwq-panel/qwq/internal/authz"
	"github.com/qwq-panel/qwq/internal/prerequisites/certificates"
)

// ======================== 实际API主体与候选消费范围，不伪造配置job ========================

func TestHostBindingConfigurationRejectsOtherScopePermissionAndTestUpgrade(t *testing.T) {
	f := newReservationFixture(t)
	reservation := f.reserve(t)
	viewer := f.f.user(t, "binding-viewer", authz.RoleViewer)
	for _, change := range []func(*actor.Actor, *string, *string, *string, *ConsumerConfiguration){
		func(who *actor.Actor, _, _, _ *string, _ *ConsumerConfiguration) { *who = viewer },
		func(who *actor.Actor, _, _, _ *string, _ *ConsumerConfiguration) {
			*who = actor.Actor{Kind: actor.System, ID: "system"}
		},
		func(_ *actor.Actor, node, _, _ *string, _ *ConsumerConfiguration) { *node = "other-node" },
		func(_ *actor.Actor, _, plugin, _ *string, _ *ConsumerConfiguration) { *plugin = "other-plugin" },
		func(_ *actor.Actor, _, _, revision *string, _ *ConsumerConfiguration) { *revision = "1" },
		func(_ *actor.Actor, _, _, _ *string, use *ConsumerConfiguration) {
			use.BindingRef = "certbind_00000000000000000000000000"
		},
		func(_ *actor.Actor, _, _, _ *string, use *ConsumerConfiguration) {
			use.Consumer.ProfileID = "other-profile"
		},
		func(_ *actor.Actor, _, _, _ *string, use *ConsumerConfiguration) {
			use.Consumer.SNI = "other.example.test"
		},
		func(_ *actor.Actor, _, _, _ *string, use *ConsumerConfiguration) { use.Consumer.Test = true },
	} {
		who, node, plugin, revision := f.f.human, "local", "core.xray", "0"
		use := ConsumerConfiguration{BindingRef: reservation.BindingRef, Consumer: f.want}
		change(&who, &node, &plugin, &revision, &use)
		if err := f.f.authority.ValidateConsumerConfiguration(f.f.ctx, who, node, plugin, revision, []ConsumerConfiguration{use}); err == nil {
			t.Fatal("候选配置取得了其他范围、权限或测试信任")
		}
	}
}

func TestHostBindingConfigurationAfterConfirmationReadsActualFactsWithoutOldJob(t *testing.T) {
	f := newReservationFixture(t)
	reservation := f.reserve(t)
	call, _, _, host, source := f.confirm(t, reservation)
	if host.ID != reservation.BindingRef || host.Consumer != f.want || host.Generation != 1 {
		t.Fatal("确认没有固定原稳定绑定和generation")
	}
	call.finish()
	use := []ConsumerConfiguration{{BindingRef: reservation.BindingRef, Consumer: f.want}}
	before := source.calls
	if err := f.f.authority.ValidateConsumerConfiguration(f.f.ctx, f.f.human, "local", "core.xray", "1", use); err != nil {
		t.Fatalf("原预留revision0阻断了已确认配置revision1的正常更新：%v", err)
	}
	if source.calls <= before {
		t.Fatal("后续配置许可没有重新读取当前真实事实")
	}
	source.facts.BindingRef = "certbind_00000000000000000000000000"
	if err := f.f.authority.ValidateConsumerConfiguration(f.f.ctx, f.f.human, "local", "core.xray", "1", use); err == nil {
		t.Fatal("真实配置改用其他绑定仍可消费旧许可")
	}
}

func TestHostBindingContextNeverAcceptsOtherGenerationOrConsumer(t *testing.T) {
	f := newReservationFixture(t)
	reservation := f.reserve(t)
	call, ctx, request, _, _ := f.confirm(t, reservation)
	valid := certificates.Authorization{Caller: request.Caller, CertificateID: fixtureCertificate, Generation: 1, Consumer: &request.Consumer, Access: certificates.Bind}
	authorizer := CertificateAuthorizer{Authority: f.f.authority}
	if err := authorizer.Authorize(ctx, valid); err != nil {
		t.Fatal(err)
	}
	changed := valid
	changed.Generation = 2
	if err := authorizer.Authorize(ctx, changed); err == nil {
		t.Fatal("绑定context可以升级到其他generation")
	}
	other := request.Consumer
	other.ProfileID = "other-profile"
	changed = valid
	changed.Consumer = &other
	if err := authorizer.Authorize(ctx, changed); err == nil {
		t.Fatal("绑定context可以换用其他消费者")
	}
	if _, err := f.f.authority.AcceptedBindRequest(context.Background()); err == nil {
		t.Fatal("序列化的参数或裸context可重建绑定许可")
	}
	call.release()
	if err := authorizer.Authorize(ctx, valid); err == nil {
		t.Fatal("释放后仍可消费原绑定context")
	}
}
