// SPDX-License-Identifier: AGPL-3.0-only

// Package testutil 提供只由测试导入的有界运行态观测工具。
package testutil

import (
	"bytes"
	"runtime"
	"testing"
)

// GoPluginProcessWaiterFrame 是已核库源码中外层 Client 的进程等待入口。
const GoPluginProcessWaiterFrame = "github.com/hashicorp/go-plugin.(*Client).reattach.func1"

// ======================== 只统计指定协程帧；不输出整份可能含私有地址的栈 ========================

// CountGoroutineFrame 取得完整且有界的栈快照；截断不能冒充没有资源残留。
func CountGoroutineFrame(t testing.TB, frame string) int {
	t.Helper()
	for size := 64 << 10; size <= 8<<20; size *= 2 {
		buffer := make([]byte, size)
		n := runtime.Stack(buffer, true)
		if n < len(buffer) {
			count := bytes.Count(buffer[:n], []byte(frame))
			clear(buffer)
			return count
		}
		clear(buffer)
	}
	t.Fatal("协程栈超过观测上限，不能确认清理完成")
	return 0
}
