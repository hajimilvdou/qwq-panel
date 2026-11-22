// SPDX-License-Identifier: AGPL-3.0-only

package supervisor

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/qwq-panel/qwq/internal/testutil"
	platformv1 "github.com/qwq-panel/qwq/sdk/gen/qwq/platform/v1"
)

// ======================== 真实 Unix/H2 重连关闭后，不得留下活 PID 等待协程 ========================

func TestSupervisorReconnectReleasesProcessWatchers(t *testing.T) {
	before := testutil.CountGoroutineFrame(t, testutil.GoPluginProcessWaiterFrame)
	e := newEnv(t)
	e.pluginFor(t, "alpha").setPlan(func(context.Context, *platformv1.PlanOperationRequest) (*platformv1.PlanOperationResponse, error) {
		return &platformv1.PlanOperationResponse{}, nil
	})
	for range 6 {
		instance := e.ensure(t, "alpha")
		if instance.MainPID() != os.Getpid() {
			t.Fatal("必须连接仍存活的受控 PID，退出进程不能掩盖等待协程泄漏")
		}
		if _, err := instance.Client().Plan(t.Context(), &platformv1.PlanOperationRequest{}); err != nil {
			t.Fatalf("真实插件连接未完成原 RPC：%v", err)
		}
		if err := e.sup.Stop(t.Context(), "alpha"); err != nil {
			t.Fatal(err)
		}
	}
	e.sup.Close()
	after := testutil.CountGoroutineFrame(t, testutil.GoPluginProcessWaiterFrame)
	if after != before {
		t.Errorf("关闭重连保留了活 PID 监视协程：before=%d after=%d", before, after)
	}
}

func TestPluginConnectionClosesOnCancellationAndTimeout(t *testing.T) {
	for _, mode := range []string{"canceled", "missing socket"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			want := context.DeadlineExceeded
			if mode == "canceled" {
				cancel()
				want = context.Canceled
			}
			before := testutil.CountGoroutineFrame(t, testutil.GoPluginProcessWaiterFrame)
			connection, err := OpenPluginConnection(ctx, filepath.Join(shortTempDir(t), "missing.sock"), 30*time.Millisecond)
			if connection != nil {
				_ = connection.Close()
				t.Error("失败连接仍把句柄交给了调用方")
			}
			if !errors.Is(err, want) {
				t.Errorf("失败连接没有保留真实取消/超时原因：%v", err)
			}
			if after := testutil.CountGoroutineFrame(t, testutil.GoPluginProcessWaiterFrame); after != before {
				t.Error("失败连接留下了进程等待协程")
			}
		})
	}
}
