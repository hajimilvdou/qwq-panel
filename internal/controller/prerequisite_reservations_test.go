// SPDX-License-Identifier: AGPL-3.0-only

package controller

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/qwq-panel/qwq/internal/actor"
	"github.com/qwq-panel/qwq/internal/authz"
	"github.com/qwq-panel/qwq/internal/catalog"
	"github.com/qwq-panel/qwq/internal/operations"
	"github.com/qwq-panel/qwq/internal/platform/clock"
	"github.com/qwq-panel/qwq/internal/platform/ids"
	"github.com/qwq-panel/qwq/internal/platform/problem"
	"github.com/qwq-panel/qwq/internal/prerequisites/certificates"
	"github.com/qwq-panel/qwq/internal/prerequisites/hostauth"
	"github.com/qwq-panel/qwq/internal/prerequisites/testsupport"
	"github.com/qwq-panel/qwq/internal/storage"
	"github.com/qwq-panel/qwq/sdk/manifest"
)

// ======================== 复用真实基础宿主与既有阻塞插件执行器 ========================

type prerequisiteHeldClient struct{ blockingJobClient }

func (*prerequisiteHeldClient) Cancel(context.Context, string) error { return nil }

type prerequisiteReservationFixture struct {
	c         *Controller
	host      *testsupport.HostFixture
	authority *hostauth.Authority
	client    *prerequisiteHeldClient
	want      certificates.Consumer
}

func newPrerequisiteReservationFixture(t *testing.T) prerequisiteReservationFixture {
	t.Helper()
	catalog, err := catalog.New(catalogFloor, catalogReachability)
	if err != nil {
		t.Fatal(err)
	}
	m := &manifest.Manifest{ID: "tls.certificates", Placement: operations.PlacementController,
		Capabilities: []manifest.Capability{{Name: "system.certificates.manage", Scope: "self"}},
		Operations: []manifest.Operation{{Name: "bindings.reserve", APIVersion: "v1", Summary: "私有预留来源回归",
			Permission: "system.certificates:manage", Mode: operations.ModeJob, Effect: operations.EffectWrite, Risk: operations.RiskHigh,
			Idempotent: true, Approval: manifest.ApprovalConfirm, TimeoutMS: 60000,
			RequestSchema: "request.json", ResponseSchema: "response.json"}}}
	if err := catalog.SetPlugin(m, func(string) ([]byte, error) { return []byte(`{"type":"object"}`), nil }); err != nil {
		t.Fatal(err)
	}
	client := &prerequisiteHeldClient{blockingJobClient{rt: &PluginRuntime{}, started: make(chan struct{})}}
	host := testsupport.NewHost(t, clock.System{}, catalogAdapter{catalog: catalog}, &pluginDispatcher{clients: &fakeClients{client: client}})
	host.User(t, "reservation-admin", authz.RoleAdmin)
	c := &Controller{db: host.DB, sec: host.Secrets, id: host.Identity, auth: host.Authorizer, ops: host.Operations, cat: catalog, ids: host.IDs}
	storePrerequisiteFixtureVersion(t, c.db, prerequisiteFixtureVersion())
	c.SetUpdater(loadStoredPluginUpdater(t, c.db))
	authority, err := hostauth.New(hostauth.Options{DB: host.DB, Secrets: host.Secrets, Operations: host.Operations, Authorizer: host.Authorizer,
		NodeID: "local", OwnerID: "installation", Consumers: c.PrerequisiteConsumerSource(), Reservations: c.PrerequisiteReservationSource()})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.SetPrerequisiteAuthority(authority); err != nil {
		t.Fatal(err)
	}
	return prerequisiteReservationFixture{c: c, host: host, authority: authority, client: client,
		want: certificates.Consumer{NodeID: "local", PluginID: "core.xray", ProfileID: "h2_fixture", Purpose: "proxy.hysteria2", SNI: "proxy.example.test"}}
}

func (f prerequisiteReservationFixture) start(t *testing.T, who actor.Actor) (context.Context, func(), hostauth.Invocation) {
	t.Helper()
	const subject = "plugins/tls.certificates/resources/certificates/certificate_fixture"
	raw, err := json.Marshal(hostauth.ReserveBindingArgs{CertificateID: "certificate_fixture", Consumer: f.want, ExpectedConfigRevision: "0"})
	if err != nil {
		t.Fatal(err)
	}
	defer clear(raw)
	response, err := f.host.Operations.Run(t.Context(), operations.RunRequest{Actor: who, Action: "tls.certificates/bindings.reserve",
		Target: operations.Target{PluginID: "tls.certificates", Subject: subject}, Args: raw,
		Idempotency: operations.Idempotency{Key: f.host.IDs.New(ids.Operation), Method: "POST", Route: "/fixture/reservation"}})
	if err != nil || response == nil || response.Operation == nil || response.Operation.Status != operations.AwaitingApproval {
		t.Fatalf("预留没有经过真实审批链: %v", err)
	}
	approval, err := f.host.Operations.GetApproval(t.Context(), f.host.Human, response.Operation.ApprovalID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.host.Operations.Decide(t.Context(), operations.DecisionRequest{Actor: f.host.Human, ApprovalID: approval.ID,
		Decision: operations.DecisionApprove, ExpectedRevision: approval.Revision,
		Idempotency: operations.Idempotency{Key: f.host.IDs.New(ids.Operation), Method: "POST", Route: "/fixture/reservation/decision"}}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-f.client.started:
	case <-time.After(5 * time.Second):
		t.Fatal("原插件 executor 没有实际启动")
	}
	origin := hostauth.Invocation{PluginID: "tls.certificates", InstanceID: "default", OperationID: response.Operation.ID,
		Operation: "bindings.reserve", Subject: subject}
	ctx, release, err := f.authority.Begin(t.Context(), origin)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(release)
	return ctx, release, origin
}

func TestPrerequisiteReservationRequiresPrivateSourceAndFixedArguments(t *testing.T) {
	f := newPrerequisiteReservationFixture(t)
	ctx, release, origin := f.start(t, f.host.Human)
	source := f.c.PrerequisiteReservationSource()
	requested := f.want
	requested.Test = true
	facts, err := source.AuthorizeReservation(ctx, origin, requested)
	if err != nil || facts.Consumer != f.want || facts.ConfigRevision != "0" || facts.PluginVersion != "0.2.0+consumer-fixture" {
		t.Fatalf("原派发不能预留精确首次配置: %v", err)
	}
	if _, err := f.c.PrerequisiteConsumerSource().CurrentConsumer(t.Context(), origin, f.want); err == nil {
		t.Fatal("planned 预留冒充了已存在的 H2 profile")
	}
	if _, err := source.AuthorizeReservation(t.Context(), origin, f.want); err == nil {
		t.Fatal("普通上下文借用了运行中的 operation")
	}
	changed := f.want
	changed.SNI = "other.example.test"
	if _, err := source.AuthorizeReservation(ctx, origin, changed); err == nil {
		t.Fatal("请求替换了原 ReserveBindingArgs 消费者")
	}
	alternate := origin
	alternate.Subject = "plugins/tls.certificates/resources/certificates/other"
	if _, err := source.AuthorizeReservation(ctx, alternate, f.want); err == nil {
		t.Fatal("来源替换了原证书 subject")
	}
	release()
	if _, err := source.AuthorizeReservation(ctx, origin, f.want); err == nil {
		t.Fatal("已释放来源继续预留")
	}
}

func TestPrerequisiteReservationRechecksConfigRevisionAndActorPermission(t *testing.T) {
	t.Run("配置换代", func(t *testing.T) {
		f := newPrerequisiteReservationFixture(t)
		ctx, _, origin := f.start(t, f.host.Human)
		storeAppliedPluginConfig(t, f.c.db, "core.xray", 1, prerequisiteConsumerFixtureJSON)
		f.c.SetUpdater(loadStoredPluginUpdater(t, f.c.db))
		if _, err := f.c.PrerequisiteReservationSource().AuthorizeReservation(ctx, origin, f.want); !problem.HasCode(err, problem.RevisionConflict) {
			t.Fatalf("原配置版本被换用: %v", err)
		}
	})
	t.Run("委托缺配置范围", func(t *testing.T) {
		f := newPrerequisiteReservationFixture(t)
		who := f.host.Delegate(t, f.host.Human, authz.Policy{Actions: []string{"tls.certificates/bindings.reserve"}, NodeIDs: []string{"local"}})
		ctx, _, origin := f.start(t, who)
		if _, err := f.c.PrerequisiteReservationSource().AuthorizeReservation(ctx, origin, f.want); err == nil {
			t.Fatal("证书权限代替了额外配置写权限")
		}
	})
	t.Run("真实角色撤销", func(t *testing.T) {
		f := newPrerequisiteReservationFixture(t)
		ctx, _, origin := f.start(t, f.host.Human)
		if err := f.host.DB.Update(t.Context(), func(tx *storage.Tx) error {
			_, err := tx.ExecContext(t.Context(), "UPDATE users SET role='viewer' WHERE user_id=?", f.host.Human.ID)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := f.c.PrerequisiteReservationSource().AuthorizeReservation(ctx, origin, f.want); err == nil {
			t.Fatal("预留继续使用撤销前的角色")
		}
	})
}

func TestPrerequisiteReservationRejectsCanceledOperationAndAuthorityReplacement(t *testing.T) {
	f := newPrerequisiteReservationFixture(t)
	ctx, _, origin := f.start(t, f.host.Human)
	if err := f.c.SetPrerequisiteAuthority(f.authority); !problem.HasCode(err, problem.StateConflict) {
		t.Fatalf("授权后端可以换用: %v", err)
	}
	if _, err := f.host.Operations.Cancel(t.Context(), operations.CancelRequest{Actor: f.host.Human, OperationID: origin.OperationID,
		Idempotency: operations.Idempotency{Key: f.host.IDs.New(ids.Operation), Method: "POST", Route: "/fixture/reservation/cancel"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.c.PrerequisiteReservationSource().AuthorizeReservation(ctx, origin, f.want); err == nil {
		t.Fatal("取消后的 operation 仍授权预留")
	}
	var missing *Controller
	if err := missing.SetPrerequisiteAuthority(f.authority); !problem.HasCode(err, problem.Unavailable) {
		t.Fatalf("不存在宿主仍装配授权: %v", err)
	}
}
