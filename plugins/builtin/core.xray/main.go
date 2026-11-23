// SPDX-License-Identifier: AGPL-3.0-only

// Command core.xray 只连接 pluginsdk 的 systemd 传输与生命周期。
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/qwq-panel/qwq/sdk/pluginsdk"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx); err != nil {
		fmt.Fprintln(os.Stderr, "core.xray:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context) error {
	return superviseDriver(ctx, func(child context.Context, plugin *Plugin) error {
		return pluginsdk.ServeSystemd(child, pluginsdk.SystemdOptions{PluginID: os.Getenv(pluginsdk.EnvPluginID)}, pluginsdk.Options{Plugin: plugin, Manifest: Manifest()})
	})
}

var errRuntimeFailure = errors.New("core.xray: managed runtime requires recovery")

// superviseDriver 保持插件 RPC 通道存活；核心进程在耗尽 coreproc 有界退避重启后仅记录规范降级原因，
// 不再调用 os.Exit(1) 自杀，确保管理员仍可通过 core.status / core.apply 下发修复配置。
func superviseDriver(ctx context.Context, serve func(context.Context, *Plugin) error) error {
	plugin := New()
	plugin.onFailure = func(error) {
		fmt.Fprintln(os.Stderr, errRuntimeFailure.Error())
	}
	return serve(ctx, plugin)
}
