// SPDX-License-Identifier: AGPL-3.0-only

// Package contextbudget 只传播有界时间预算，不承担业务授权或重试。
package contextbudget

import (
	"context"
	"time"
)

// Detached 允许取消后的窄补偿继续，但保留父 context 的更早 deadline。
// 无父期限时使用 timeout；非正预算、已过期期限或 nil 父 context 立即到期。
func Detached(ctx context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	if ctx == nil {
		ctx, timeout = context.Background(), 0
	}
	deadline := time.Now().Add(timeout)
	if inherited, found := ctx.Deadline(); found && inherited.Before(deadline) {
		deadline = inherited
	}
	return context.WithDeadline(context.WithoutCancel(ctx), deadline)
}
