// SPDX-License-Identifier: AGPL-3.0-only

package operations

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/qwq-panel/qwq/internal/actor"
	"github.com/qwq-panel/qwq/internal/platform/problem"
	"github.com/qwq-panel/qwq/internal/storage"
)

// ======================== 真实批准元数据与不可构造的执行 proof ========================

func cleanupFixtureFingerprint() string { return strings.Repeat("a", 64) }

func TestCleanupLeaseHasActualConfirmationAndRejectsForgedSnapshots(t *testing.T) {
	f := newCleanupAuthorityFixture(t, "human", true)
	e := f.env
	snapshot := f.accepted(t)
	if !snapshot.Approved || snapshot.ConfirmationActor.Kind != actor.Human || snapshot.ConfirmationActor.ID != f.human.ID ||
		snapshot.ConfirmationActor.SessionID != "" || snapshot.ConfirmationActor.MFA || snapshot.ConfirmationActor.IsHumanSession() {
		t.Fatal("审批确认没有来自真实 DecidedBy，或被扩成新登录会话")
	}
	lease, err := e.svc.NewCleanupLease(e.ctx, snapshot, f.source, cleanupFixtureRecord, cleanupFixtureFingerprint(), 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*DispatchedContext){
		func(s *DispatchedContext) { s.runtimeProof = nil },
		func(s *DispatchedContext) { s.OperationID = e.newKey() },
		func(s *DispatchedContext) { s.Actor.SessionID = f.human.SessionID },
		func(s *DispatchedContext) { s.ConfirmationActor.ID = "foreign-user" },
		func(s *DispatchedContext) {
			s.Target.Subject = "plugins/tls.certificates/resources/certificates/foreign"
		},
		func(s *DispatchedContext) { s.ArgsDigest = "sha256:" + strings.Repeat("b", 64) },
	} {
		changed := snapshot
		change(&changed)
		if _, err := e.svc.NewCleanupLease(e.ctx, changed, f.source, cleanupFixtureRecord, cleanupFixtureFingerprint(), 30*time.Second); err == nil {
			t.Fatal("可变 DTO 或缺失私有 proof 可以 mint 清理许可")
		}
	}
	if err := e.svc.CheckCleanupLease(e.ctx, lease, f.source, "other-txt", cleanupFixtureFingerprint()); err == nil {
		t.Fatal("许可扩成其他记录 ID")
	}
	if err := e.svc.CheckCleanupLease(e.ctx, lease, f.source, cleanupFixtureRecord, strings.Repeat("b", 64)); err == nil {
		t.Fatal("许可接受了其他记录完整指纹")
	}
	foreign := f.source
	foreign.DNSAttemptID = "foreign-dns-attempt"
	if err := e.svc.CheckCleanupLease(e.ctx, lease, foreign, cleanupFixtureRecord, cleanupFixtureFingerprint()); err == nil {
		t.Fatal("许可扩成了其他 DNS attempt")
	}
	for _, change := range []func(*CleanupSource){
		func(s *CleanupSource) { s.CertificateID = "foreign-certificate" },
		func(s *CleanupSource) { s.IssueAttemptID = "foreign-issue" },
		func(s *CleanupSource) { s.DNSAttemptID = "invalid\r\n" },
	} {
		changed := f.source
		change(&changed)
		if err := e.svc.CheckCleanupSource(e.ctx, snapshot, changed, 30*time.Second); err == nil {
			t.Fatal("候选读取不是原证书/签发/DNS attempt")
		}
	}
	raw, err := json.Marshal(lease)
	if err != nil || strings.Contains(string(raw)+fmt.Sprintf("%#v", lease), cleanupFixtureRecord) {
		t.Fatal("私有清理许可进入 JSON 或日志")
	}
	if string(raw) != `{"redacted":true}` || e.svc.CheckCleanupLease(e.ctx, &CleanupLease{}, f.source, cleanupFixtureRecord, cleanupFixtureFingerprint()) == nil {
		t.Fatal("序列化结果恢复了清理权限")
	}
}

func TestCleanupLeaseWithoutApprovalDoesNotInventConfirmation(t *testing.T) {
	f := newCleanupAuthorityFixture(t, "human", false)
	snapshot := f.accepted(t)
	if snapshot.Approved || snapshot.ConfirmationActor != (actor.Actor{}) {
		t.Fatal("没有审批时伪造了人类确认元数据")
	}
}

// ======================== 取消后窄清理；普通派发状态继续严格拒绝 ========================

func TestCleanupLeaseCanceledExecutorCannotUseOrdinaryDispatch(t *testing.T) {
	f := newCleanupAuthorityFixture(t, "human", true)
	e := f.env
	snapshot := f.accepted(t)
	f.cancel(t)
	if _, err := e.svc.ResolveDispatched(e.ctx, f.exact, f.id); !problem.HasCode(err, problem.PermissionDenied) {
		t.Fatal("普通 ResolveDispatched 允许取消后的写权限")
	}
	lease, err := e.svc.NewCleanupLease(e.ctx, snapshot, f.source, cleanupFixtureRecord, cleanupFixtureFingerprint(), 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.svc.CheckCleanupLease(e.ctx, lease, f.source, cleanupFixtureRecord, cleanupFixtureFingerprint()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel, err := e.svc.CleanupContext(e.ctx, lease, f.source, cleanupFixtureRecord, cleanupFixtureFingerprint())
	if err != nil {
		t.Fatal(err)
	}
	defer cancel()
	deadline, found := ctx.Deadline()
	if !found || time.Until(deadline) > 30*time.Second {
		t.Fatal("派生清理 context 没有硬期限")
	}
	snapshot.Clear()
	if err := e.svc.CheckCleanupLease(e.ctx, lease, f.source, cleanupFixtureRecord, cleanupFixtureFingerprint()); err != nil {
		t.Fatal("清理许可依赖可变公开 Args 缓冲")
	}
}

func TestCleanupLeaseSourceStartsWindowAndFreshSnapshotsCannotExtendIt(t *testing.T) {
	f := newCleanupAuthorityFixture(t, "human", true)
	e := f.env
	first := f.accepted(t)
	if err := e.svc.CheckCleanupSource(e.ctx, first, f.source, 5*time.Second); err != nil {
		t.Fatal(err)
	}
	e.clock.Advance(2 * time.Second)
	fresh := f.accepted(t)
	lease, err := e.svc.NewCleanupLease(e.ctx, fresh, f.source, cleanupFixtureRecord, cleanupFixtureFingerprint(), 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if !lease.deadline.Equal(e.clock.Now().Add(3 * time.Second)) {
		t.Fatal("读取阶段耗时没有计入同 executor 硬窗口")
	}
	e.clock.Advance(4 * time.Second)
	fresh = f.accepted(t)
	if _, err := e.svc.NewCleanupLease(e.ctx, fresh, f.source, cleanupFixtureRecord, cleanupFixtureFingerprint(), 30*time.Second); err == nil {
		t.Fatal("窗口到期后 fresh snapshot 重新 mint 并延长权限")
	}
	if err := e.svc.CheckCleanupSource(e.ctx, fresh, f.source, 30*time.Second); err == nil {
		t.Fatal("窗口到期后仍开放候选事实读取")
	}
}

func TestCleanupLeaseInitialJournalSourceCannotMintWithoutOwnedDNSAttempt(t *testing.T) {
	f := newCleanupAuthorityFixture(t, "human", true)
	e := f.env
	snapshot := f.accepted(t)
	journalSource := f.source
	journalSource.DNSAttemptID = ""
	if err := e.svc.CheckCleanupSource(e.ctx, snapshot, journalSource, 5*time.Second); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.NewCleanupLease(e.ctx, snapshot, journalSource, cleanupFixtureRecord, cleanupFixtureFingerprint(), 30*time.Second); err == nil {
		t.Fatal("仅原 journal 读取权限被扩成记录清理许可")
	}
	e.clock.Advance(6 * time.Second)
	if _, err := e.svc.NewCleanupLease(e.ctx, f.accepted(t), f.source, cleanupFixtureRecord, cleanupFixtureFingerprint(), 30*time.Second); err == nil {
		t.Fatal("原 journal 读取耗尽窗口后重新开启 DNS 清理窗口")
	}
}

func TestCleanupLeaseRejectsInvalidTTLAndCurrentAttemptChanges(t *testing.T) {
	f := newCleanupAuthorityFixture(t, "human", true)
	e := f.env
	snapshot := f.accepted(t)
	for _, ttl := range []time.Duration{0, -time.Second, 31 * time.Second} {
		if _, err := e.svc.NewCleanupLease(e.ctx, snapshot, f.source, cleanupFixtureRecord, cleanupFixtureFingerprint(), ttl); err == nil {
			t.Fatal("无效或过长 TTL 被接受")
		}
	}
	lease, err := e.svc.NewCleanupLease(e.ctx, snapshot, f.source, cleanupFixtureRecord, cleanupFixtureFingerprint(), 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.db.Update(e.ctx, func(tx *storage.Tx) error {
		_, err := tx.ExecContext(e.ctx, "UPDATE operations SET attempt = attempt + 1 WHERE operation_id = ?", f.id)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.CheckCleanupLease(e.ctx, lease, f.source, cleanupFixtureRecord, cleanupFixtureFingerprint()); err == nil {
		t.Fatal("原指针下的 attempt 已改变仍可使用许可")
	}
}

func TestCleanupLeaseRejectsExecutorExitReplacementAndAnotherService(t *testing.T) {
	for _, stop := range []string{"exit", "replace", "service"} {
		t.Run(stop, func(t *testing.T) {
			f := newCleanupAuthorityFixture(t, "human", true)
			e := f.env
			snapshot := f.accepted(t)
			lease, err := e.svc.NewCleanupLease(e.ctx, snapshot, f.source, cleanupFixtureRecord, cleanupFixtureFingerprint(), 30*time.Second)
			if err != nil {
				t.Fatal(err)
			}
			service := e.svc
			switch stop {
			case "exit":
				f.job.finish()
				select {
				case <-snapshot.runtimeProof.job.done:
				case <-time.After(5 * time.Second):
					t.Fatal("真实 executor 没有退出")
				}
			case "replace":
				// 受控故障注入：用实际注册/注销函数替换映射，旧 proof 必须失效。
				e.svc.unregisterRunning(f.id)
				if !e.svc.registerRunning(f.id, func() {}) {
					t.Fatal("替换 executor 注入失败")
				}
			case "service":
				service, err = New(Options{DB: e.db, Clock: e.clock, IDs: e.ids, Catalog: e.catalog, Dispatcher: e.dispatcher,
					Authorizer: f.rbac, Policy: dispatchPolicies{backend: f.authz}, NodeID: "local"})
				if err != nil {
					t.Fatal(err)
				}
			}
			if err := service.CheckCleanupLease(e.ctx, lease, f.source, cleanupFixtureRecord, cleanupFixtureFingerprint()); err == nil {
				t.Fatal("结束、替换或新宿主实例接受了旧 executor 许可")
			}
		})
	}
}

// ======================== 每步实际人类、service、委托与策略撤权 ========================

func TestCleanupLeaseRechecksCurrentPrincipalsAndPermissionMode(t *testing.T) {
	for _, principal := range []string{"human", "service", "delegation", "read_only"} {
		t.Run(principal, func(t *testing.T) {
			kind := principal
			if kind == "read_only" {
				kind = "human"
			}
			f := newCleanupAuthorityFixture(t, kind, true)
			e := f.env
			snapshot := f.accepted(t)
			lease, err := e.svc.NewCleanupLease(e.ctx, snapshot, f.source, cleanupFixtureRecord, cleanupFixtureFingerprint(), 30*time.Second)
			if err != nil {
				t.Fatal(err)
			}
			ctx := e.ctx
			switch principal {
			case "human":
				if err := e.db.Update(e.ctx, func(tx *storage.Tx) error {
					_, err := tx.ExecContext(e.ctx, "UPDATE users SET disabled = 1, revision = revision + 1 WHERE user_id = ?", f.human.ID)
					return err
				}); err != nil {
					t.Fatal(err)
				}
			case "service", "delegation":
				if err := f.revoke(); err != nil {
					t.Fatal(err)
				}
			case "read_only":
				ctx = WithPermissionMode(ctx, PermissionReadOnly)
			}
			if err := e.svc.CheckCleanupLease(ctx, lease, f.source, cleanupFixtureRecord, cleanupFixtureFingerprint()); err == nil {
				t.Fatal("当前主体撤权或策略收紧后仍执行清理")
			}
		})
	}
}

func TestCleanupLeaseAuthorizationRaceChecksRunMapWithoutHoldingItsLock(t *testing.T) {
	f := newCleanupAuthorityFixture(t, "human", true)
	e := f.env
	snapshot := f.accepted(t)
	var once sync.Once
	f.rbac.mu.Lock()
	f.rbac.after = func(context.Context) error {
		once.Do(func() {
			e.svc.unregisterRunning(f.id)
			e.svc.registerRunning(f.id, func() {})
		})
		return nil
	}
	f.rbac.mu.Unlock()
	ctx, cancel := context.WithTimeout(e.ctx, time.Second)
	defer cancel()
	if err := e.svc.CheckCleanupSource(ctx, snapshot, f.source, 30*time.Second); err == nil {
		t.Fatal("授权期间 executor 替换后仍接受原 proof")
	}
}

func TestCleanupLeaseAuthorizationReceivesTheSameHardBudget(t *testing.T) {
	f := newCleanupAuthorityFixture(t, "human", true)
	e := f.env
	snapshot := f.accepted(t)
	var checked atomic.Bool
	f.rbac.mu.Lock()
	f.rbac.after = func(ctx context.Context) error {
		deadline, found := ctx.Deadline()
		if !found || time.Until(deadline) > 5*time.Second {
			return problem.New(problem.PermissionDenied, "权限查询没有共享原清理硬预算")
		}
		checked.Store(true)
		return nil
	}
	f.rbac.mu.Unlock()
	if err := e.svc.CheckCleanupSource(e.ctx, snapshot, f.source, 5*time.Second); err != nil {
		t.Fatal(err)
	}
	if !checked.Load() {
		t.Fatal("没有实际执行受限权限查询")
	}
}
