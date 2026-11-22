// SPDX-License-Identifier: AGPL-3.0-only

package dns

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/qwq-panel/qwq/internal/prerequisites/fault"
)

// ======================== 缺失私有证据不能推断没有外部写入 ========================

func TestDNSOwnedMissingReceiptCannotProveNoWrite(t *testing.T) {
	f, request, _ := requestAwareFixture(t)
	if _, err := f.manager.PresentChallenge(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	entry, found, err := f.repository.Get(context.Background(), journalKey(f.scope))
	if err != nil || !found {
		t.Fatal("实际写入日志不存在")
	}
	if err := f.repository.Delete(context.Background(), journalKey(f.scope), entry.Revision); err != nil {
		t.Fatal(err)
	}
	_, found, err = f.manager.OwnedChallenge(context.Background(), request.Caller, request.Scope, request.CertificateID, request.AttemptID)
	if found || fault.Code(err) != "OUTCOME_UNKNOWN" {
		t.Fatalf("已有外部记录但缺失私有日志被当作没有写入：%v", err)
	}
	if creates, _, deletes := f.provider.counts(); creates != 1 || deletes != 0 {
		t.Fatal("缺失日志被自动重发或删除")
	}
}

func TestDNSDirectCleanupRequiresExplicitCompletionReceipt(t *testing.T) {
	for _, outcome := range []string{"missing", "lost", "cleaned", "rejected"} {
		t.Run(outcome, func(t *testing.T) {
			// 这里复用协议故障 fixture，仅核验直接清理入口的证据语义。
			f := newFixture(t)
			request := f.challenge(t, "direct-cleanup")
			if outcome == "rejected" {
				f.provider.createRejected = &fault.Error{Code: "RATE_LIMITED", Detail: "fixture refusal", NotApplied: true}
			}
			if outcome != "missing" {
				_, err := f.manager.PresentChallenge(context.Background(), request)
				if outcome == "rejected" {
					if fault.Code(err) != "RATE_LIMITED" {
						t.Fatal("明确拒绝没有保存原收据")
					}
				} else if err != nil {
					t.Fatal(err)
				}
			}
			if outcome == "cleaned" {
				if err := f.manager.CleanupChallenge(context.Background(), request.Caller, request.Scope, request.CertificateID, request.AttemptID); err != nil {
					t.Fatal(err)
				}
			}
			if outcome == "lost" {
				entry, found, err := f.repository.Get(context.Background(), journalKey(f.scope))
				if err != nil || !found {
					t.Fatal("已确认创建的私有日志不存在")
				}
				if err := f.repository.Delete(context.Background(), journalKey(f.scope), entry.Revision); err != nil {
					t.Fatal(err)
				}
			}
			_, _, before := f.provider.counts()
			err := f.manager.CleanupChallenge(context.Background(), request.Caller, request.Scope, request.CertificateID, request.AttemptID)
			unknown := outcome == "missing" || outcome == "lost"
			if (unknown && fault.Code(err) != "OUTCOME_UNKNOWN") || (!unknown && err != nil) {
				t.Fatalf("直接清理没有按明确收据区分完成与未知：%v", err)
			}
			if _, _, after := f.provider.counts(); after != before {
				t.Fatal("缺失或已完成收据仍然发送删除")
			}
		})
	}
}

func TestDNSWithChallengeCleanupKeepsEarlierDeadline(t *testing.T) {
	for _, outcome := range []string{"canceled", "expired"} {
		t.Run(outcome, func(t *testing.T) {
			f := newFixture(t)
			request := f.challenge(t, "bounded-with-challenge")
			provider := &cleanupBudgetProvider{fakeProvider: f.provider}
			f.manager.providers = cleanupBudgetProviders{provider: provider}
			repository := &cleanupBudgetRepository{Repository: f.repository}
			f.manager.repository = repository
			timeout := 5 * time.Second
			if outcome == "expired" {
				timeout = 50 * time.Millisecond
			}
			parent, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()
			deadline, _ := parent.Deadline()
			err := f.manager.WithChallenge(parent, request, func(ctx context.Context) error {
				provider.deadline, repository.deadline, repository.puts = time.Time{}, time.Time{}, 0
				if outcome == "expired" {
					<-ctx.Done()
					return nil
				}
				cancel()
				return ctx.Err()
			})
			_, _, deletes := f.provider.counts()
			if outcome == "expired" {
				if !errors.Is(err, context.DeadlineExceeded) || deletes != 0 || !provider.deadline.IsZero() || repository.puts != 0 {
					t.Fatalf("辅助入口到期后重新取得清理或持久化预算：%v", err)
				}
				return
			}
			if !errors.Is(err, context.Canceled) || deletes != 1 || !provider.deadline.Equal(deadline) || !repository.deadline.Equal(deadline) {
				t.Fatalf("辅助入口取消清理丢弃了更早deadline：%v", err)
			}
		})
	}
}

func TestDNSOwnedKnownCleanedAndRejectedReceiptsRemainExplicitlyComplete(t *testing.T) {
	for _, outcome := range []string{"cleaned", "rejected"} {
		t.Run(outcome, func(t *testing.T) {
			f, request, _ := requestAwareFixture(t)
			if outcome == "rejected" {
				f.provider.createRejected = &fault.Error{Code: "RATE_LIMITED", Detail: "fixture refusal", NotApplied: true}
			}
			_, err := f.manager.PresentChallenge(context.Background(), request)
			if outcome == "rejected" {
				if fault.Code(err) != "RATE_LIMITED" {
					t.Fatal("原明确拒绝没有持久化")
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
				owned, found, err := f.manager.OwnedChallenge(context.Background(), request.Caller, request.Scope, request.CertificateID, request.AttemptID)
				if err != nil || !found {
					t.Fatal("原记录事实未取得")
				}
				ctx := context.WithValue(context.Background(), ownedCleanupKey{}, owned)
				if err := f.manager.CleanupChallenge(ctx, request.Caller, request.Scope, request.CertificateID, request.AttemptID); err != nil {
					t.Fatal(err)
				}
			}
			_, found, err := f.manager.OwnedChallenge(context.Background(), request.Caller, request.Scope, request.CertificateID, request.AttemptID)
			if found || err != nil {
				t.Fatal("有明确完成或拒绝收据却返回未知状态")
			}
		})
	}
}

// ======================== 真实 Manager 持锁网络竞争的整体返回预算 ========================

func blockManagerMutation(t *testing.T, f fixture) func() {
	t.Helper()
	request := f.request(t, "blocking-normal", Change{Action: Create, Record: Record{Type: A, Name: "blocking.example.com", Value: "192.0.2.10", TTL: 60}})
	started, release := make(chan struct{}, 1), make(chan struct{})
	f.provider.started, f.provider.release = started, release
	finished := make(chan struct{})
	var result error
	go func() {
		defer close(finished)
		_, result = f.manager.Apply(context.Background(), request)
	}()
	var once sync.Once
	stop := func() { once.Do(func() { close(release) }) }
	t.Cleanup(func() {
		stop()
		select {
		case <-finished:
			if result != nil {
				t.Errorf("原正常变更未完成：%v", result)
			}
		case <-time.After(5 * time.Second):
			t.Error("正常变更测试线程未退出")
		}
	})
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("正常 Manager 未进入持锁网络变更")
	}
	return stop
}

func TestDNSCleanupLockCompetitionHonorsOverallDeadline(t *testing.T) {
	for _, lookup := range []string{"owned", "cleanup"} {
		t.Run(lookup, func(t *testing.T) {
			f, request, _ := requestAwareFixture(t)
			if _, err := f.manager.PresentChallenge(context.Background(), request); err != nil {
				t.Fatal(err)
			}
			owned, found, err := f.manager.OwnedChallenge(context.Background(), request.Caller, request.Scope, request.CertificateID, request.AttemptID)
			if err != nil || !found {
				t.Fatal("缺少原自有记录")
			}
			release := blockManagerMutation(t, f)
			base := context.WithValue(context.Background(), ownedCleanupKey{}, owned)
			ctx, cancel := context.WithTimeout(base, 50*time.Millisecond)
			defer cancel()
			finished := make(chan struct{})
			var result error
			go func() {
				defer close(finished)
				if lookup == "owned" {
					_, _, result = f.manager.OwnedChallenge(ctx, request.Caller, request.Scope, request.CertificateID, request.AttemptID)
				} else {
					result = f.manager.CleanupChallenge(ctx, request.Caller, request.Scope, request.CertificateID, request.AttemptID)
				}
			}()
			t.Cleanup(func() {
				release()
				select {
				case <-finished:
				case <-time.After(5 * time.Second):
					t.Error("清理竞争测试线程未退出")
				}
			})
			select {
			case <-finished:
				if !errors.Is(result, context.DeadlineExceeded) {
					t.Fatalf("锁等待不是由原期限结束：%v", result)
				}
			case <-time.After(500 * time.Millisecond):
				t.Fatal("等待正常变更的锁超过整体清理硬预算")
			}
			if _, _, deletes := f.provider.counts(); deletes != 0 {
				t.Fatal("锁等待到期后仍删除原记录")
			}
		})
	}
}
