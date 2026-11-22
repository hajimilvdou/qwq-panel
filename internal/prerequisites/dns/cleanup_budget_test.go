// SPDX-License-Identifier: AGPL-3.0-only

package dns

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/qwq-panel/qwq/internal/prerequisites/fault"
	"github.com/qwq-panel/qwq/internal/prerequisites/store"
)

// ======================== 实际查询与 CAS 持久化接收同一期限 ========================

type cleanupBudgetRepository struct {
	store.Repository
	puts     int
	deadline time.Time
	err      error
}

func (r *cleanupBudgetRepository) Put(ctx context.Context, key, revision string, value []byte) (string, error) {
	r.puts++
	r.deadline, _ = ctx.Deadline()
	r.err = ctx.Err()
	return r.Repository.Put(ctx, key, revision, value)
}

type cleanupBudgetProvider struct {
	*fakeProvider
	deadline time.Time
	err      error
	failure  bool
}

func (p *cleanupBudgetProvider) List(ctx context.Context, scope Scope) ([]Record, error) {
	p.deadline, _ = ctx.Deadline()
	p.err = ctx.Err()
	if p.failure {
		return nil, errors.New("fixture DNS query unavailable")
	}
	return p.fakeProvider.List(ctx, scope)
}

type cleanupBudgetProviders struct{ provider Provider }

func (p cleanupBudgetProviders) For(context.Context, Scope) (Provider, error) { return p.provider, nil }

func pendingCleanupFixture(t *testing.T) (fixture, context.Context, journal, string) {
	t.Helper()
	f, request, _ := requestAwareFixture(t)
	if _, err := f.manager.PresentChallenge(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	owned, found, err := f.manager.OwnedChallenge(context.Background(), request.Caller, request.Scope, request.CertificateID, request.AttemptID)
	if err != nil || !found {
		t.Fatal("缺少实际原自有记录")
	}
	state, revision, err := f.manager.load(context.Background(), f.scope)
	if err != nil || len(state.Receipts) != 1 {
		t.Fatal("缺少实际 DNS 收据")
	}
	saved := state.Receipts[0]
	saved.Cleaning, saved.State = true, Submitted
	state.Active, state.Receipts = &saved, []attempt{}
	revision, err = store.Save(context.Background(), f.repository, journalKey(f.scope), revision, state)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.WithValue(context.Background(), ownedCleanupKey{}, owned)
	return f, ctx, state, revision
}

func TestDNSCleanupCanceledQueryAndFinalReceiptKeepTheEarlierDeadline(t *testing.T) {
	for _, outcome := range []string{"finish", "unknown"} {
		t.Run(outcome, func(t *testing.T) {
			f, original, state, revision := pendingCleanupFixture(t)
			parent, cancelParent := context.WithTimeout(original, 5*time.Second)
			deadline, _ := parent.Deadline()
			cancelParent()
			provider := &cleanupBudgetProvider{fakeProvider: f.provider, failure: outcome == "unknown"}
			provider.records = nil // 已发送删除；对账必须确认原 ID 消失。
			f.manager.providers = cleanupBudgetProviders{provider: provider}
			repository := &cleanupBudgetRepository{Repository: f.repository}
			f.manager.repository = repository
			result, err := f.manager.reconcileCleanup(parent, f.caller, f.scope, &state, revision)
			if outcome == "finish" && (err != nil || result.State != Cleaned) {
				t.Fatalf("取消后的原删除结果未受控持久化：%v", err)
			}
			if outcome == "unknown" && fault.Code(err) != "OUTCOME_UNKNOWN" {
				t.Fatalf("提供商故障未保留原未知删除结果：%v", err)
			}
			if !provider.deadline.Equal(deadline) || !repository.deadline.Equal(deadline) || provider.err != nil || repository.err != nil || repository.puts != 1 {
				t.Fatal("查询、finish 或 markUnknown 重新延长了原期限，或未脱离普通取消")
			}
		})
	}
}

func TestDNSCleanupExpiredWindowCannotQueryOrPersistFinishAndUnknown(t *testing.T) {
	for _, stage := range []string{"query", "save", "finish", "unknown"} {
		t.Run(stage, func(t *testing.T) {
			f, original, state, revision := pendingCleanupFixture(t)
			expired, cancel := context.WithDeadline(original, time.Now().Add(-time.Second))
			defer cancel()
			repository := &cleanupBudgetRepository{Repository: f.repository}
			f.manager.repository = repository
			provider := &cleanupBudgetProvider{fakeProvider: f.provider}
			f.manager.providers = cleanupBudgetProviders{provider: provider}
			var err error
			switch stage {
			case "query":
				_, err = f.manager.reconcileCleanup(expired, f.caller, f.scope, &state, revision)
			case "save":
				_, err = f.manager.saveDetached(expired, f.scope, revision, state)
			case "finish":
				_, err = f.manager.finish(expired, f.scope, &state, revision, Cleaned)
			case "unknown":
				_, err = f.manager.markUnknown(expired, f.scope, &state, revision, "fixture unknown")
			}
			if err == nil || repository.puts != 0 || !provider.deadline.IsZero() {
				t.Fatal("到期清理窗口重新发起了查询或持久化预算")
			}
			stored, _, err := f.manager.load(context.Background(), f.scope)
			if err != nil || stored.Active == nil || !stored.Active.Cleaning {
				t.Fatal("到期后的原未知删除证据丢失")
			}
		})
	}
}

func TestDNSOwnedPendingCreateReconcileKeepsTheCleanupDeadline(t *testing.T) {
	for _, expired := range []bool{false, true} {
		name := "canceled"
		if expired {
			name = "expired"
		}
		t.Run(name, func(t *testing.T) {
			f, original, state, revision := pendingCleanupFixture(t)
			state.Active.Cleaning = false // 原记录已有 ID，仍需完成创建响应对账。
			var err error
			revision, err = store.Save(context.Background(), f.repository, journalKey(f.scope), revision, state)
			if err != nil {
				t.Fatal(err)
			}
			deadline := time.Now().Add(5 * time.Second)
			if expired {
				deadline = time.Now().Add(-time.Second)
			}
			parent, cancelParent := context.WithDeadline(original, deadline)
			defer cancelParent()
			cancelParent()
			provider := &cleanupBudgetProvider{fakeProvider: f.provider}
			f.manager.providers = cleanupBudgetProviders{provider: provider}
			repository := &cleanupBudgetRepository{Repository: f.repository}
			f.manager.repository = repository
			result, err := f.manager.reconcile(parent, f.caller, f.scope, &state, revision)
			if expired {
				if err == nil || !provider.deadline.IsZero() || repository.puts != 0 {
					t.Fatal("未标 Cleaning 的到期原记录重新获得查询或提交预算")
				}
				return
			}
			if err != nil || result.State != Applied || !provider.deadline.Equal(deadline) || !repository.deadline.Equal(deadline) {
				t.Fatalf("原已确认创建的对账延长了清理期限：%v", err)
			}
		})
	}
}
