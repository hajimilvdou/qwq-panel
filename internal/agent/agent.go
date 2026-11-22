// SPDX-License-Identifier: AGPL-3.0-only

// Package agent wires the node agent process: it owns the bootstrap
// configuration, the plugin supervisor and graceful shutdown, and exposes the
// host-channel multiplexer the supervisor needs (ADR-0003, ARCH 3.1, 6.4).
//
// The agent does not decide which plugins should run. Desired state lives in the
// controller and reaches the supervisor through Ensure; this package owns process
// lifecycle only and never talks to a plugin itself.
package agent

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/qwq-panel/qwq/internal/platform/config"
	"github.com/qwq-panel/qwq/internal/platform/problem"
	"github.com/qwq-panel/qwq/internal/pluginhost/supervisor"
)

// Options configure New and Run.
type Options struct {
	// Config is the loaded bootstrap configuration.
	Config config.Config
	// Logger defaults to slog.Default.
	Logger *slog.Logger
	// Supervisor is required; the agent starts and closes it.
	Supervisor *supervisor.Supervisor
	// HostFactory builds the host-channel server of one plugin. It is optional:
	// a nil factory makes the multiplexer fail with UNAVAILABLE, which lets the
	// agent start before internal/hostsvc is wired in.
	HostFactory func(pluginID string) (supervisor.HostServer, error)
}

// Agent is the node agent process.
type Agent struct {
	cfg    config.Config
	logger *slog.Logger
	sup    *supervisor.Supervisor
	host   supervisor.HostServer
}

// New validates opts. A Config value that omits the directories is completed from
// config.Default(); configuration loaded by config.Load is already complete.
func New(opts Options) (*Agent, error) {
	if opts.Supervisor == nil {
		return nil, problem.New(problem.ValidationFailed, "agent: a supervisor is required")
	}
	cfg := opts.Config
	def := config.Default()
	if cfg.Role == "" {
		cfg.Role = def.Role
	}
	if cfg.RunDir == "" {
		cfg.RunDir = def.RunDir
	}
	if cfg.DataDir == "" {
		cfg.DataDir = def.DataDir
	}
	if !filepath.IsAbs(cfg.RunDir) || filepath.Clean(cfg.RunDir) != cfg.RunDir {
		return nil, problem.New(problem.ValidationFailed,
			"agent: run_dir %q must be a clean absolute path", cfg.RunDir)
	}
	if !filepath.IsAbs(cfg.DataDir) || filepath.Clean(cfg.DataDir) != cfg.DataDir {
		return nil, problem.New(problem.ValidationFailed,
			"agent: data_dir %q must be a clean absolute path", cfg.DataDir)
	}
	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}
	return &Agent{
		cfg:    cfg,
		logger: logger,
		sup:    opts.Supervisor,
		host:   HostMux(opts.HostFactory),
	}, nil
}

// HostServer returns the multiplexer built from Options.HostFactory. The main
// session passes it to supervisor.Options.Host. Serve delegates to the factory
// and returns UNAVAILABLE while the factory is nil.
func (a *Agent) HostServer() supervisor.HostServer { return a.host }

// Run starts the supervisor, serves until the process receives SIGTERM/SIGINT or
// ctx is cancelled, and then closes the supervisor: host channels are torn down
// and plugin connections are closed, but plugin processes are left to systemd,
// which the next agent process reattaches to.
func (a *Agent) Run(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	runCtx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := a.sup.Start(runCtx); err != nil {
		return err
	}
	defer a.sup.Close()
	a.logger.InfoContext(runCtx, "agent running",
		"role", a.cfg.Role, "run_dir", a.cfg.RunDir, "data_dir", a.cfg.DataDir)

	<-runCtx.Done()
	a.logger.Info("agent stopping", "reason", runCtx.Err())
	return nil
}
