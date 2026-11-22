// SPDX-License-Identifier: AGPL-3.0-only

// Command noop is the process entry point of the built-in empty plugin.
//
// The plugin logic lives in plugin.go; this file only wires the process to the
// SDK transport. ADR-0003 selects systemd socket activation plus a per-plugin
// host UDS: systemd owns the listening socket and passes its descriptor to the
// process, and the Agent serves the host channel on a private bind mount. Both
// halves are implemented by pluginsdk.ServeSystemd, so the entry point stays a
// thin call: replacing the transport never touches the plugin or the SDK.
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
	if err := run(ctx); err != nil {
		fmt.Fprintln(os.Stderr, "noop:", err)
		os.Exit(1)
	}
}

// run serves the plugin until ctx is canceled or the process receives
// SIGTERM/SIGINT. The transport reads the inherited descriptor, connects to
// the Agent's host socket, registers the PluginService and drains on shutdown.
func run(ctx context.Context) error {
	return pluginsdk.ServeSystemd(ctx, pluginsdk.SystemdOptions{
		PluginID: os.Getenv(pluginsdk.EnvPluginID),
	}, pluginsdk.Options{
		Plugin:   New(),
		Manifest: Manifest(),
	})
}
