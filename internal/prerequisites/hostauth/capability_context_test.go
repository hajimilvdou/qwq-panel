// SPDX-License-Identifier: AGPL-3.0-only

package hostauth

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/qwq-panel/qwq/internal/actor"
	"github.com/qwq-panel/qwq/internal/authz"
	"github.com/qwq-panel/qwq/internal/prerequisites/fault"
	"github.com/qwq-panel/qwq/internal/storage"
)

// ======================== 真实 capability 路由与原 executor 来源 ========================

func TestHostCapabilityBeginResolvesOnlyFixedActualOperation(t *testing.T) {
	f := newAuthorityFixture(t)
	call := f.start(t, f.human, "domain.dns", "records.list", zoneSubject(fixtureProvider, fixtureZone), "absent",
		DNSArgs{ProviderID: fixtureProvider, ZoneID: fixtureZone})
	inv := call.invocation
	metadata := Invocation{PluginID: inv.PluginID, InstanceID: inv.InstanceID, OperationID: inv.OperationID}
	ctx, release, err := f.authority.BeginCapability(f.ctx, metadata, "records.list")
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	actual, err := f.authority.CurrentInvocation(ctx)
	if err != nil || actual != inv {
		t.Fatal("capability 没有读取实际固定 operation/完整目标")
	}
	if scope, cleanup, err := f.authority.BeginCapability(f.ctx, metadata, "records.apply"); err == nil || scope != nil {
		if cleanup != nil {
			cleanup()
		}
		t.Fatal("只读 RPC 选择了另一固定 operation")
	}
	release()
	if _, err := f.authority.CurrentInvocation(ctx); err == nil {
		t.Fatal("释放后仍读取了 invocation")
	}
}

func TestHostCapabilityJobContextKeepsExecutorAndRejectsReleasedSource(t *testing.T) {
	f := newAuthorityFixture(t)
	call := f.start(t, f.human, "domain.dns", "records.list", zoneSubject(fixtureProvider, fixtureZone), "absent",
		DNSArgs{ProviderID: fixtureProvider, ZoneID: fixtureZone})
	worker, release, err := f.authority.JobContext(call.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	call.release()
	if worker.Err() != nil {
		t.Fatal("原 job 被 unary 来源释放截断")
	}
	if _, cleanup, err := f.authority.JobContext(call.ctx); err == nil {
		if cleanup != nil {
			cleanup()
		}
		t.Fatal("释放后的私有来源重新兑换了任务上下文")
	}
	if _, _, err := f.authority.JobContext(context.Background()); err == nil {
		t.Fatal("Background 伪造了执行权限")
	}
}

func TestHostCapabilityExtraPermissionRequiresCurrentPrivateActor(t *testing.T) {
	f := newAuthorityFixture(t)
	call := f.start(t, f.human, "domain.dns", "records.list", zoneSubject(fixtureProvider, fixtureZone), "absent",
		DNSArgs{ProviderID: fixtureProvider, ZoneID: fixtureZone})
	resource := authz.Resource{Name: "host.plugins", NodeID: "local", Subject: "plugins/core.xray/config"}
	if err := f.authority.AuthorizeCurrent(call.ctx, "host.plugins:config", resource); err != nil {
		t.Fatal(err)
	}
	other, err := New(f.options("installation", "local"))
	if err != nil {
		t.Fatal(err)
	}
	for _, ctx := range []context.Context{nil, context.Background()} {
		if err := f.authority.AuthorizeCurrent(ctx, "host.plugins:config", resource); err == nil {
			t.Fatal("普通上下文获得额外宿主权限")
		}
	}
	if err := other.AuthorizeCurrent(call.ctx, "host.plugins:config", resource); err == nil {
		t.Fatal("不同Authority复用了私有来源")
	}
	systemJob, systemInvocation := f.dispatchCall(t, actor.SystemActor("fixture-system"), "domain.dns", "records.list", zoneSubject(fixtureProvider, fixtureZone), "absent",
		DNSArgs{ProviderID: fixtureProvider, ZoneID: fixtureZone})
	systemCtx, releaseSystem, err := f.authority.Begin(systemJob.ctx, systemInvocation)
	if err == nil {
		defer releaseSystem()
		if err := f.authority.AuthorizeCurrent(systemCtx, "host.plugins:config", resource); err == nil {
			t.Fatal("内部System身份绕过额外宿主权限")
		}
	} else {
		requireCode(t, err, "PERMISSION_DENIED")
	}
	if err := f.db.Update(f.ctx, func(tx *storage.Tx) error {
		_, err := tx.ExecContext(f.ctx, "UPDATE users SET role='viewer', revision=revision+1 WHERE user_id=?", f.human.ID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := f.authority.AuthorizeCurrent(call.ctx, "host.plugins:config", resource); err == nil {
		t.Fatal("调用者角色撤销后仍具有配置权限")
	}
}

func TestHostCapabilityExtraPermissionRechecksReleaseAndCancellation(t *testing.T) {
	f := newAuthorityFixture(t)
	call := f.start(t, f.human, "domain.dns", "records.list", zoneSubject(fixtureProvider, fixtureZone), "absent",
		DNSArgs{ProviderID: fixtureProvider, ZoneID: fixtureZone})
	resource := authz.Resource{Name: "host.plugins", NodeID: "local", Subject: "plugins/core.xray/config"}
	cancelled, stop := context.WithCancel(call.ctx)
	stop()
	if err := f.authority.AuthorizeCurrent(cancelled, "host.plugins:config", resource); err == nil {
		t.Fatal("已取消上下文仍获得额外配置许可")
	}
	var parallel sync.WaitGroup
	for range 4 {
		parallel.Add(1)
		go func() {
			defer parallel.Done()
			_ = f.authority.AuthorizeCurrent(call.ctx, "host.plugins:config", resource)
		}()
	}
	call.release()
	parallel.Wait()
	if err := f.authority.AuthorizeCurrent(call.ctx, "host.plugins:config", resource); err == nil {
		t.Fatal("release之后仍获得额外配置许可")
	}
}

func TestHostCapabilityTaskBudgetBoundsRealDelegationAndInterval(t *testing.T) {
	f := newAuthorityFixture(t)
	who := f.base.Delegate(t, f.human, authz.DefaultPolicy())
	call := f.start(t, who, "domain.dns", "records.list", zoneSubject(fixtureProvider, fixtureZone), "absent",
		DNSArgs{ProviderID: fixtureProvider, ZoneID: fixtureZone})
	if group, limit, err := f.authority.TaskBudget(call.ctx, 5*time.Second); err != nil || group == "" || limit != 1 {
		t.Fatal("默认委托没有为实际业务保留一半请求预算")
	}
	for _, interval := range []time.Duration{0, -time.Second, time.Nanosecond, time.Minute} {
		if _, _, err := f.authority.TaskBudget(call.ctx, interval); fault.Code(err) != "VALIDATION_FAILED" {
			t.Fatal("非法监视间隔进入容量计算")
		}
	}
	if _, _, err := f.authority.TaskBudget(call.ctx, 100*time.Millisecond); fault.Code(err) != "RATE_LIMITED" {
		t.Fatal("快速监视器突破实际委托请求预算")
	}
}
