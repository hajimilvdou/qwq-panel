// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/qwq-panel/qwq/sdk/pluginsdk"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := pluginsdk.ServeSystemd(ctx, pluginsdk.SystemdOptions{PluginID: os.Getenv(pluginsdk.EnvPluginID)}, pluginsdk.Options{Plugin: New(), Manifest: Manifest()}); err != nil {
		fmt.Fprintln(os.Stderr, "proxy.advanced:", err)
		os.Exit(1)
	}
}
