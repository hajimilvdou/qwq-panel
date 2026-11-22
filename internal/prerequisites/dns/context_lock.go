// SPDX-License-Identifier: AGPL-3.0-only

package dns

import (
	"context"
	"sync"

	"github.com/qwq-panel/qwq/internal/prerequisites/fault"
)

// ======================== 零值可用的私有有界串行门 ========================

type contextLock struct {
	once  sync.Once
	token chan struct{}
}

func (m *contextLock) Lock(ctx context.Context) error {
	if ctx == nil {
		return fault.New("VALIDATION_FAILED", "DNS 串行操作缺少上下文")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	m.once.Do(func() { m.token = make(chan struct{}, 1) })
	select {
	case m.token <- struct{}{}:
		if err := ctx.Err(); err != nil {
			m.Unlock()
			return err
		}
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (m *contextLock) Unlock() { <-m.token }
