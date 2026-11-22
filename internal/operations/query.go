// SPDX-License-Identifier: AGPL-3.0-only

package operations

import (
	"context"
	"time"

	"github.com/qwq-panel/qwq/internal/actor"
	"github.com/qwq-panel/qwq/internal/platform/problem"
)

// Get returns one operation the actor may read.
func (s *Service) Get(ctx context.Context, a actor.Actor, id string) (*Operation, error) {
	op, err := loadOperation(ctx, s.db.Reader(), id)
	if err != nil {
		return nil, err
	}
	if !canRead(a, op) {
		// Do not confirm that an operation exists to a caller that may not see
		// it (OpenAPI NotFound: no such resource, or the caller may not see it).
		return nil, notFound("operation")
	}
	s.ResultRedactor(ctx, a)(op)
	return op, nil
}

// List returns one page of operations, newest first (OpenAPI listOperations).
func (s *Service) List(ctx context.Context, a actor.Actor, f ListFilter) (*OperationPage, error) {
	items, err := s.queryOperations(ctx, s.db.Reader(), f, a)
	if err != nil {
		return nil, err
	}
	limit := clampLimit(f.Limit)
	page := &OperationPage{Revision: s.pageRevision(), Delta: f.SinceRevision != ""}
	if len(items) > limit {
		items = items[:limit]
		page.NextCursor = encodeCursor(items[len(items)-1].ID)
	}
	if items == nil {
		items = []Operation{}
	}
	redact := s.ResultRedactor(ctx, a)
	for i := range items {
		redact(&items[i])
	}
	page.Items = items
	return page, nil
}

// Wait long-polls an operation until it reaches a terminal state, needs
// approval, or the timeout elapses (ADR-0004 D8 wait tool, HostInvokeService
// WaitOperation). It polls on the configured clock, which keeps tests free of
// sleeps.
func (s *Service) Wait(ctx context.Context, a actor.Actor, id string, timeout time.Duration) (*Operation, error) {
	if timeout <= 0 {
		return s.Get(ctx, a, id)
	}
	deadline := s.clock.Now().Add(timeout)
	for {
		op, err := s.Get(ctx, a, id)
		if err != nil {
			return nil, err
		}
		if isTerminal(op.Status) || op.Status == AwaitingApproval || !s.clock.Now().Before(deadline) {
			return op, nil
		}
		select {
		case <-ctx.Done():
			return nil, problem.From(ctx.Err())
		case <-s.clock.After(50 * time.Millisecond):
		}
	}
}
