// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"log"
	"os"

	"github.com/qwq-panel/qwq/sdk/pluginsdk"
)

func main() {
	err := pluginsdk.ServeSystemd(
		context.Background(),
		pluginsdk.SystemdOptions{PluginID: os.Getenv(pluginsdk.EnvPluginID)},
		pluginsdk.Options{Plugin: New(), Manifest: Manifest()},
	)
	if err != nil {
		log.Fatal(err)
	}
}
