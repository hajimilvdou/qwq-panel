// SPDX-License-Identifier: AGPL-3.0-only

package dns

import (
	"context"
	"errors"
	"testing"
)

type cancelAfterPrecheck struct {
	context.Context
	cancel context.CancelFunc
	checks int
}

func (c *cancelAfterPrecheck) Err() error {
	c.checks++
	if c.checks == 2 {
		c.cancel()
	}
	return c.Context.Err()
}

// ======================== acquire 前后取消检查与 token 回收 ========================

func TestDNSContextLockRejectsCancellationBeforeAndAfterAcquire(t *testing.T) {
	for _, when := range []string{"before", "after"} {
		t.Run(when, func(t *testing.T) {
			var lock contextLock
			parent, cancel := context.WithCancel(context.Background())
			defer cancel()
			ctx := context.Context(parent)
			if when == "before" {
				cancel()
			} else {
				ctx = &cancelAfterPrecheck{Context: parent, cancel: cancel}
			}
			if err := lock.Lock(ctx); !errors.Is(err, context.Canceled) {
				t.Fatalf("取消没有在acquire边界拒绝：%v", err)
			}
			if err := lock.Lock(context.Background()); err != nil {
				t.Fatal("失败acquire遗留了token")
			}
			lock.Unlock()
		})
	}
}
