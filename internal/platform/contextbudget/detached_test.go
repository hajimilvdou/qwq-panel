// SPDX-License-Identifier: AGPL-3.0-only

package contextbudget

import (
	"context"
	"errors"
	"testing"
	"time"
)

type scopeKey struct{}

// ======================== 取消可独立，期限绝不重开 ========================

func TestDetachedUsesItsOwnBoundedBudgetWithoutAParentDeadline(t *testing.T) {
	before := time.Now()
	ctx, cancel := Detached(context.WithValue(context.Background(), scopeKey{}, "original"), time.Second)
	defer cancel()
	deadline, found := ctx.Deadline()
	if !found || deadline.Before(before) || deadline.After(time.Now().Add(time.Second)) || ctx.Value(scopeKey{}) != "original" {
		t.Fatal("无父期限时没有有界预算或丢失原作用域")
	}
}

func TestDetachedKeepsAnEarlierDeadlineWhenTheParentIsCanceled(t *testing.T) {
	parent, cancelParent := context.WithTimeout(context.Background(), time.Second)
	deadline, _ := parent.Deadline()
	cancelParent()
	ctx, cancel := Detached(parent, time.Minute)
	defer cancel()
	actual, found := ctx.Deadline()
	if !found || !actual.Equal(deadline) || ctx.Err() != nil {
		t.Fatal("正常取消没有脱离 cancellation 或重新延长了原期限")
	}
}

func TestDetachedDoesNotRenewExpiredOrInvalidBudgets(t *testing.T) {
	expired, stop := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer stop()
	for _, test := range []struct {
		name    string
		parent  context.Context
		timeout time.Duration
	}{
		{"expired", expired, time.Minute},
		{"zero", context.Background(), 0},
		{"negative", context.Background(), -time.Second},
		{"nil", nil, time.Minute},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx, cancel := Detached(test.parent, test.timeout)
			defer cancel()
			if !errors.Is(ctx.Err(), context.DeadlineExceeded) {
				t.Fatal("到期或无效预算被重新打开")
			}
		})
	}
}

func TestDetachedCancellationWithoutAParentDeadlineRemainsLocallyCancelable(t *testing.T) {
	parent, cancelParent := context.WithCancel(context.Background())
	cancelParent()
	ctx, cancel := Detached(parent, time.Second)
	if ctx.Err() != nil {
		cancel()
		t.Fatal("正常取消阻止了独立有界补偿")
	}
	cancel()
	if !errors.Is(ctx.Err(), context.Canceled) {
		t.Fatal("返回的补偿 context 不能主动结束")
	}
}
