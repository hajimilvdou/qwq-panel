// SPDX-License-Identifier: AGPL-3.0-only

package controller

import (
	"os"
	"testing"

	"github.com/qwq-panel/qwq/internal/testutil"
)

// ======================== updater 的真实连接释放与进程生命周期分离 ========================

func TestUpdaterReconnectReleasesProcessWatchers(t *testing.T) {
	before := testutil.CountGoroutineFrame(t, testutil.GoPluginProcessWaiterFrame)
	f := newRuntimeFixture(t)
	f.systemctl.setRunning(os.Getpid())
	for range 6 {
		handle, err := f.rt.Attach(t.Context(), f.spec())
		if err != nil {
			t.Fatalf("真实插件启动/接管未完成：%v", err)
		}
		if current := f.rt.liveFor(f.pluginID); current == nil || current.mainPID != os.Getpid() {
			t.Fatal("必须连接仍存活的受控 PID，不能用进程退出清理等待协程")
		}
		if err := f.rt.Health(t.Context(), handle); err != nil {
			t.Fatalf("原版本/初始化健康链路未成功：%v", err)
		}
		if err := f.rt.Release(t.Context(), handle); err != nil {
			t.Fatal(err)
		}
	}
	after := testutil.CountGoroutineFrame(t, testutil.GoPluginProcessWaiterFrame)
	if after != before {
		t.Errorf("释放连接保留了活 PID 监视协程：before=%d after=%d", before, after)
	}
	if _, stops, kills := f.systemctl.counts(); stops != 0 || kills != 0 {
		t.Fatal("连接释放停止了本应由 systemd 管理的进程")
	}
}
