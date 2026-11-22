// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/qwq-panel/qwq/internal/agent"
	"github.com/qwq-panel/qwq/internal/controller"
	"github.com/qwq-panel/qwq/internal/platform/clock"
	"github.com/qwq-panel/qwq/internal/platform/config"
	"github.com/qwq-panel/qwq/internal/platform/logging"
	"github.com/qwq-panel/qwq/internal/pluginhost/supervisor"
	"github.com/qwq-panel/qwq/internal/sandbox"
)

// runServeAgent implements `qwq serve-agent`: load the bootstrap file, build the
// supervisor with the systemd unit manager and the per-plugin host channel, and
// run until SIGTERM/SIGINT.
//
// The agent process owns plugin process lifecycle only. In a standalone
// installation it is the same binary family as serve-controller but a separate
// process; without a database the host channel serves state and peer checks and
// reports the journal, audit, secret and invoke services as UNAVAILABLE.
func runServeAgent(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("serve-agent", flag.ContinueOnError)
	fs.SetOutput(stderr)
	configPath := fs.String("config", config.DefaultPath, "bootstrap configuration file")
	pluginsDir := fs.String("plugins-dir", controller.DefaultPluginsDir, "installed plugin package directory")
	runDir := fs.String("run-dir", "", "runtime directory (default: run_dir from the bootstrap file)")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	// config.Validate rejects role=agent in this release, so an agent node is
	// configured as standalone until split deployments are released. The
	// validation is deliberately not relaxed here.
	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(stderr, "qwq serve-agent: %v\n", err)
		return 2
	}
	if *runDir != "" {
		if !filepath.IsAbs(*runDir) || filepath.Clean(*runDir) != *runDir {
			fmt.Fprintf(stderr, "qwq serve-agent: --run-dir %q must be a clean absolute path\n", *runDir)
			return 2
		}
		cfg.RunDir = filepath.Clean(*runDir)
	}
	dir := filepath.Clean(*pluginsDir)
	if !filepath.IsAbs(dir) {
		fmt.Fprintf(stderr, "qwq serve-agent: --plugins-dir %q must be an absolute path\n", *pluginsDir)
		return 2
	}
	level, err := logging.ParseLevel(cfg.Log.Level)
	if err != nil {
		fmt.Fprintf(stderr, "qwq serve-agent: %v\n", err)
		return 2
	}
	logger := logging.New(stderr, logging.Options{Service: "agent", Level: level, Format: cfg.Log.Format})

	if info, statErr := os.Stat(dir); statErr != nil || !info.IsDir() {
		logger.Warn("the plugin directory is not available; plugins cannot be attached",
			"plugins_dir", dir, "error", statErr)
	}

	// The runtime owns the supervisor, the systemd unit manager and the host
	// channel factory; the agent process adds only lifetime handling.
	rt, err := newAgentRuntime(cfg, dir, controller.UnitManagerAdapter{
		Systemctl: sandbox.NewExecSystemctl(sandbox.ExecRunner{}),
		NodeID:    "local",
	}, logger)
	if err != nil {
		fmt.Fprintf(stderr, "qwq serve-agent: %v\n", err)
		return 1
	}
	defer rt.Stop()
	// The agent has no database: its host channels keep state and peer
	// verification and report the journal-dependent services as UNAVAILABLE.
	if err := rt.Start(context.Background(), controller.HostDeps{
		Clock:  clock.System{},
		Logger: logger,
		NodeID: "local",
	}); err != nil {
		fmt.Fprintf(stderr, "qwq serve-agent: start the plugin runtime: %v\n", err)
		return 1
	}

	a, err := agent.New(agent.Options{
		Config:      cfg,
		Logger:      logger,
		Supervisor:  rt.Supervisor(),
		HostFactory: rt.HostServer,
	})
	if err != nil {
		fmt.Fprintf(stderr, "qwq serve-agent: %v\n", err)
		return 1
	}

	fmt.Fprintf(stdout, "qwq serve-agent: node local, plugins %s, run dir %s\n", dir, cfg.RunDir)
	if err := a.Run(context.Background()); err != nil {
		fmt.Fprintf(stderr, "qwq serve-agent: %v\n", err)
		return 1
	}
	return 0
}

// newAgentRuntime builds the plugin runtime of the agent process. It is split
// from runServeAgent so tests can pass a fake unit manager and never touch
// systemd; it performs no I/O beyond what the caller already did.
func newAgentRuntime(cfg config.Config, pluginsDir string, units supervisor.UnitManager, logger *slog.Logger) (*controller.PluginRuntime, error) {
	return controller.NewPluginRuntime(controller.PluginRuntimeOptions{
		Units:     units,
		PluginDir: controller.PluginDirResolver(pluginsDir),
		RunDir:    cfg.RunDir,
		StateDir:  filepath.Join(cfg.DataDir, "plugin-state"),
		Logger:    logger,
		NodeID:    "local",
	})
}
