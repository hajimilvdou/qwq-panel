// SPDX-License-Identifier: AGPL-3.0-only

package hostauth

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/qwq-panel/qwq/internal/actor"
	"github.com/qwq-panel/qwq/internal/authz"
	"github.com/qwq-panel/qwq/internal/operations"
	"github.com/qwq-panel/qwq/internal/platform/ids"
	"github.com/qwq-panel/qwq/internal/prerequisites/dns"
	"github.com/qwq-panel/qwq/internal/storage"
)

// ======================== 宿主身份与不可重放上下文 ========================

var _ fmt.Stringer = (*execution)(nil)
var _ fmt.GoStringer = (*execution)(nil)
var _ json.Marshaler = (*execution)(nil)

func TestHostExecutionPointerRedactionPreservesBoundary(t *testing.T) {
	value := &execution{invocation: Invocation{OperationID: "private-operation"},
		snapshot: operations.DispatchedContext{Args: json.RawMessage(`{"private":"private-payload"}`)}}
	value.mu.Lock()
	defer value.mu.Unlock()
	encoded, err := json.Marshal(value)
	if err != nil || string(encoded) != `{"redacted":true}` {
		t.Fatal("执行指针的 JSON 脱敏边界改变")
	}
	for _, rendered := range []string{fmt.Sprint(value), fmt.Sprintf("%#v", value)} {
		if rendered != "hostauth.execution{[REDACTED]}" {
			t.Fatal("执行指针在持锁时输出了私有状态")
		}
	}
}

func TestHostAuthorityRequiresRealBackendsAndExactDispatch(t *testing.T) {
	if _, err := New(Options{OwnerID: "installation", NodeID: "local"}); err == nil {
		t.Fatal("缺失真实后端被接受")
	}
	f := newAuthorityFixture(t)
	call := f.start(t, f.human, "domain.dns", "records.list", zoneSubject(fixtureProvider, fixtureZone), "",
		DNSArgs{ProviderID: fixtureProvider, ZoneID: fixtureZone})
	for _, change := range []func(*Invocation){
		func(v *Invocation) { v.PluginID = "core.xray" },
		func(v *Invocation) { v.InstanceID = "other" },
		func(v *Invocation) { v.OperationID = f.ids.New(ids.Operation) },
		func(v *Invocation) { v.Operation = "records.apply" },
		func(v *Invocation) { v.Subject = zoneSubject(fixtureProvider, "other") },
	} {
		invocation := call.invocation
		change(&invocation)
		if _, release, err := f.authority.Begin(f.ctx, invocation); err == nil {
			release()
			t.Fatal("错误派发目标被接受")
		}
	}
	if _, err := f.authority.current(context.Background()); err == nil {
		t.Fatal("普通 context 获得宿主权限")
	}
	other, err := New(f.options("installation", "local"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := other.current(call.ctx); err == nil {
		t.Fatal("另一 Authority 复用了私有上下文")
	}
	if err := f.authority.RequireRevision(call.ctx, "replacement"); err == nil {
		t.Fatal("替代 revision 被接受")
	}
	raw, err := json.Marshal(call.invocation)
	if err != nil || bytes.Contains(raw, []byte(call.invocation.OperationID)) || bytes.Contains([]byte(fmt.Sprintf("%#v", call.invocation)), []byte(fixtureProvider)) {
		t.Fatal("私有派发事实进入 JSON 或格式化日志")
	}
}

func TestHostAuthorityReleaseCancelsAndCannotReplay(t *testing.T) {
	f := newAuthorityFixture(t)
	call := f.start(t, f.human, "domain.dns", "records.list", zoneSubject(fixtureProvider, fixtureZone), "",
		DNSArgs{ProviderID: fixtureProvider, ZoneID: fixtureZone})
	var wait sync.WaitGroup
	started := make(chan struct{})
	for range 4 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-started
			for range 3 {
				_, _ = DecodeArguments[DNSArgs](call.ctx, f.authority)
			}
		}()
	}
	close(started)
	call.release()
	wait.Wait()
	call.release()
	if call.ctx.Err() != context.Canceled {
		t.Fatal("release 没有取消派生 context")
	}
	if _, err := DecodeArguments[DNSArgs](call.ctx, f.authority); err == nil {
		t.Fatal("已释放 context 可以重放参数")
	}
	value := call.ctx.Value(executionKey{}).(*execution)
	value.mu.RLock()
	defer value.mu.RUnlock()
	if !value.released || len(value.snapshot.Args) != 0 {
		t.Fatal("释放后保留了私有参数")
	}
}

func TestHostAuthorityRechecksActorCancellationAndDeadline(t *testing.T) {
	for _, stop := range []string{"actor", "cancel", "deadline", "read_only"} {
		t.Run(stop, func(t *testing.T) {
			f := newAuthorityFixture(t)
			call := f.start(t, f.human, "domain.dns", "providers.revoke", providerSubject(fixtureProvider), "revision",
				ProviderArgs{ProviderID: fixtureProvider})
			ctx := call.ctx
			switch stop {
			case "actor":
				if err := f.db.Update(f.ctx, func(tx *storage.Tx) error {
					_, err := tx.ExecContext(f.ctx, "UPDATE users SET disabled = 1, revision = revision + 1 WHERE user_id = ?", f.human.ID)
					return err
				}); err != nil {
					t.Fatal(err)
				}
			case "cancel":
				_, err := f.ops.Cancel(f.ctx, operations.CancelRequest{Actor: f.human, OperationID: call.invocation.OperationID,
					Idempotency: operations.Idempotency{Key: f.ids.New(ids.Operation), Method: "POST", Route: "/fixture/cancel"}})
				if err != nil {
					t.Fatal(err)
				}
			case "deadline":
				f.clock.Advance(time.Minute + time.Second)
			case "read_only":
				ctx = operations.WithPermissionMode(ctx, operations.PermissionReadOnly)
			}
			if _, err := f.authority.current(ctx); err == nil {
				t.Fatal("权限或执行状态变化后仍接受原上下文")
			}
		})
	}
}

func TestHostServiceCannotBorrowDNSRegistrationRole(t *testing.T) {
	f := newAuthorityFixture(t)
	var service authz.CreatedServiceAccount
	if err := f.db.Update(f.ctx, func(tx *storage.Tx) error {
		var err error
		service, err = f.authz.CreateServiceAccount(f.ctx, tx, authz.CreateServiceAccountInput{Actor: f.human, Name: "dns-test", Role: authz.RoleAdmin})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	who, err := f.authz.AuthenticateBearer(f.ctx, service.Token)
	if err != nil || who.Kind != actor.Service {
		t.Fatalf("真实服务账号认证失败：%v", err)
	}
	job, invocation := f.dispatchCall(t, who, "domain.dns", "providers.revoke", providerSubject(fixtureProvider), "revision", ProviderArgs{ProviderID: fixtureProvider})
	if _, release, err := f.authority.Begin(job.ctx, invocation); err == nil {
		release()
		t.Fatal("粗 admin 服务角色扩成了 DNS 管理权限")
	}
}

// ======================== 原 DNS 参数与不可扩大的调用范围 ========================

func TestHostDNSContextRejectsUnknownAccessAndForeignScopes(t *testing.T) {
	f := newAuthorityFixture(t)
	registered, _, _ := f.register(t)
	registered.finish()
	confirmed, _, _ := f.zone(t, f.human, "absent")
	confirmed.finish()
	viewer := f.user(t, "scope-viewer", authz.RoleViewer)
	call := f.start(t, viewer, "domain.dns", "records.list", zoneSubject(fixtureProvider, fixtureZone), "",
		DNSArgs{ProviderID: fixtureProvider, ZoneID: fixtureZone})
	ctx, caller, scope, err := f.authority.DNSContext(call.ctx, fixtureProvider, fixtureZone)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.authority.checkDNS(ctx, caller, scope, dns.Read); err != nil {
		t.Fatal(err)
	}
	for _, access := range []dns.Access{dns.Manage, dns.Challenge, dns.Cleanup, "", "unknown"} {
		requireCode(t, f.authority.checkDNS(ctx, caller, scope, access), "PERMISSION_DENIED")
	}
	for _, change := range []func(*dns.Scope){
		func(s *dns.Scope) { s.ProviderID = "other" },
		func(s *dns.Scope) { s.ZoneID = "other" },
		func(s *dns.Scope) { s.ZoneName = "example.test.attacker.test" },
		func(s *dns.Scope) { s.Kind = dns.Aliyun },
		func(s *dns.Scope) { s.Revision = stringsDigest('a') },
	} {
		changed := scope
		change(&changed)
		requireCode(t, f.authority.checkDNS(ctx, caller, changed, dns.Read), "PERMISSION_DENIED")
	}
	foreign := caller
	foreign.OwnerID = "other"
	requireCode(t, f.authority.checkDNS(ctx, foreign, scope, dns.Read), "PERMISSION_DENIED")
	foreign = caller
	foreign.OperationID = f.ids.New(ids.Operation)
	requireCode(t, f.authority.checkDNS(ctx, foreign, scope, dns.Read), "PERMISSION_DENIED")
	if _, _, _, err := f.authority.DNSContext(call.ctx, fixtureProvider, "other"); err == nil {
		t.Fatal("替代 zone 被接受")
	}
}

func TestHostDNSRequestUsesAcceptedIntentAndSnapshot(t *testing.T) {
	f := newAuthorityFixture(t)
	registered, _, _ := f.register(t)
	registered.finish()
	confirmed, _, _ := f.zone(t, f.human, "absent")
	confirmed.finish()
	change := dns.Change{Action: dns.Create, Record: dns.Record{Type: dns.TXT, Name: "_proof.example.test", Value: "accepted-proof", TTL: 60}}
	input := DNSArgs{ProviderID: fixtureProvider, ZoneID: fixtureZone, AttemptID: "attempt-one", Change: &change}
	call := f.start(t, f.human, "domain.dns", "records.apply", zoneSubject(fixtureProvider, fixtureZone), stringsDigest('a'), input)
	ctx, caller, scope, err := f.authority.DNSContext(call.ctx, fixtureProvider, fixtureZone)
	if err != nil {
		t.Fatal(err)
	}
	request, err := f.authority.AcceptedDNSRequest(ctx)
	if err != nil || request.Caller != caller || request.Scope != scope || request.Change != change || request.AttemptID != input.AttemptID || request.ExpectedRevision != stringsDigest('a') || request.CertificateID != "" {
		t.Fatalf("原 DNS 意图没有完整绑定：%v", err)
	}
	change.Record.Value = "changed-outside"
	again, err := f.authority.AcceptedDNSRequest(ctx)
	if err != nil || again.Change.Record.Value != "accepted-proof" {
		t.Fatal("调用方缓冲修改了原已接受参数")
	}
	if _, err := f.authority.AcceptedDNSCheck(ctx); err == nil {
		t.Fatal("写上下文被换成其他检查意图")
	}
}

func stringsDigest(char byte) string { return string(bytes.Repeat([]byte{char}, 64)) }
