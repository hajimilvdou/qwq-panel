// SPDX-License-Identifier: AGPL-3.0-only

package acme

import (
	"context"
	"testing"
	"time"

	"github.com/qwq-panel/qwq/internal/prerequisites/store"
)

// ======================== 实际加密订单提交不重开补偿预算 ========================

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

func TestACMEJournalCanceledSaveKeepsOriginalDeadlineAndEncryptedBackend(t *testing.T) {
	f := newOriginalChallengeFixture(t, []string{"proxy.example.com"})
	repository := &cleanupBudgetRepository{Repository: f.authority.repository}
	f.authority.repository = repository
	parent, cancelParent := context.WithTimeout(context.Background(), 5*time.Second)
	deadline, _ := parent.Deadline()
	cancelParent()
	if _, err := f.authority.saveDetached(parent, f.caller, f.state, f.revision); err != nil {
		t.Fatal(err)
	}
	if repository.puts != 1 || repository.err != nil || !repository.deadline.Equal(deadline) {
		t.Fatal("窄加密订单提交继承了 cancellation 或延长了原期限")
	}
}

func TestACMEJournalExpiredSaveDoesNotTouchTheBackend(t *testing.T) {
	f := newOriginalChallengeFixture(t, []string{"proxy.example.com"})
	repository := &cleanupBudgetRepository{Repository: f.authority.repository}
	f.authority.repository = repository
	expired, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	if _, err := f.authority.saveDetached(expired, f.caller, f.state, f.revision); err == nil || repository.puts != 0 {
		t.Fatal("到期订单提交重新访问了加密后端")
	}
}
