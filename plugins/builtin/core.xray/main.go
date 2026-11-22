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

// superviseDriver 保留规范故障原因，让 systemd 将核心与驱动作为同一故障域重启。
func superviseDriver(ctx context.Context, serve func(context.Context, *Plugin) error) error {
	child, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	plugin := New()
	plugin.onFailure = func(error) { cancel(errRuntimeFailure) }
	err := serve(child, plugin)
	if ctx.Err() == nil && context.Cause(child) != nil {
		return context.Cause(child)
	}
	return err
}
