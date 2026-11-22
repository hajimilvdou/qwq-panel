// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"runtime/debug"
	"syscall"
	"time"

	"github.com/qwq-panel/qwq/internal/agentapi"
	"github.com/qwq-panel/qwq/internal/api"
	"github.com/qwq-panel/qwq/internal/capability/firewall"
	"github.com/qwq-panel/qwq/internal/controller"
	"github.com/qwq-panel/qwq/internal/platform/config"
	"github.com/qwq-panel/qwq/internal/platform/logging"
	"github.com/qwq-panel/qwq/internal/pluginhost/install"
	"github.com/qwq-panel/qwq/internal/pluginhost/updater"
	"github.com/qwq-panel/qwq/internal/pluginpublic"
	"github.com/qwq-panel/qwq/internal/pluginui"
	"github.com/qwq-panel/qwq/internal/sandbox"
	"github.com/qwq-panel/qwq/internal/webui"
)

// defaultTrustDir is the node-local trust root of plugin publisher keys.
const defaultTrustDir = "/etc/qwq/trust"

// runServe implements `qwq serve-controller`: load the bootstrap file, open the
// host services, mount the public API and serve the management listener until
// SIGTERM/SIGINT.
func runServe(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("serve-controller", flag.ContinueOnError)
	fs.SetOutput(stderr)
	configPath := fs.String("config", config.DefaultPath, "bootstrap configuration file")
	pluginsDir := fs.String("plugins-dir", controller.DefaultPluginsDir,
		"installed plugin package directory; the plugin runtime stays disabled when it does not exist")
	trustDir := fs.String("trust-dir", defaultTrustDir,
		"trusted plugin publisher public keys (*.pem); the plugin updater stays disabled when it does not exist")
	stagingDir := fs.String("staging-dir", controller.DefaultStagingRoot,
		"verified plugin staging directory; must be writable by this process and match the helper's --staging-root")
	privSocket := fs.String("privileged-socket", sandbox.DefaultPrivilegedSocket,
		"root helper socket that performs privileged plugin installs; empty disables it")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if !filepath.IsAbs(*pluginsDir) {
		fmt.Fprintf(stderr, "qwq serve-controller: --plugins-dir %q must be an absolute path\n", *pluginsDir)
		return 2
	}
	if !filepath.IsAbs(*trustDir) {
		fmt.Fprintf(stderr, "qwq serve-controller: --trust-dir %q must be an absolute path\n", *trustDir)
		return 2
	}
	if !filepath.IsAbs(*stagingDir) {
		fmt.Fprintf(stderr, "qwq serve-controller: --staging-dir %q must be an absolute path\n", *stagingDir)
		return 2
	}
	if *privSocket != "" && !filepath.IsAbs(*privSocket) {
		fmt.Fprintf(stderr, "qwq serve-controller: --privileged-socket %q must be an absolute path\n", *privSocket)
		return 2
	}

	if os.Getenv("GOMEMLIMIT") == "" {
		// OPT-01: 1C1G 软内存水位线（96 MiB），避免 GC 峰值抖动；若外部显式传入 GOMEMLIMIT 则尊重外部设置。
		debug.SetMemoryLimit(96 << 20)
	}
	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(stderr, "qwq serve-controller: %v\n", err)
		return 2
	}
	level, err := logging.ParseLevel(cfg.Log.Level)
	if err != nil {
		fmt.Fprintf(stderr, "qwq serve-controller: %v\n", err)
		return 2
	}
	logger := logging.New(stderr, logging.Options{Service: "controller", Level: level, Format: cfg.Log.Format})
	helper, err := newPrivilegedHelper(*privSocket, os.Geteuid(), logger)
	if err != nil {
		fmt.Fprintf(stderr, "qwq serve-controller: %v\n", err)
		return 2
	}

	// life bounds the host services and is cancelled only by the shutdown
	// sequence, after HTTP drained; sig only receives the signal. Tying the
	// services to the signal would tear down the host channel, the job workers
	// and the event hub while in-flight requests still need them.
	life, cancelLife := context.WithCancel(context.Background())
	defer cancelLife()
	sig, stopSig := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stopSig()

	// The plugin runtime is built before the controller because the operation
	// manager needs its dispatcher at construction; its host services are bound
	// after the controller opened the database.
	rt, dirs, err := newPluginRuntime(cfg, *pluginsDir, logger)
	if err != nil {
		fmt.Fprintf(stderr, "qwq serve-controller: %v\n", err)
		return 1
	}
	// Operations are deferred: an approved operation recovered now would fail
	// for good, because the plugin runtime, the updater and the host action
	// handlers are not ready yet. StartOperations runs once they are.
	c, err := controller.New(life, controller.Options{
		Config: cfg, Logger: logger, PluginRuntime: rt, DeferOperations: true,
	})
	if err != nil {
		if rt != nil {
			rt.Stop()
		}
		fmt.Fprintf(stderr, "qwq serve-controller: %v\n", err)
		return 1
	}
	// The services stop after HTTP drained, within a fixed budget: Close
	// waits on every plugin's host channel, and systemd kills the unit at
	// TimeoutStopSec. Deferred calls run in reverse, so life is cancelled
	// first and the deferred cancelLife above is a no-op by then.
	defer closeHost(c, cancelLife, hostCloseTimeout, logger)

	prereqs, err := wirePrerequisites(c, rt, helper, logger)
	if err != nil {
		fmt.Fprintf(stderr, "qwq serve-controller: %v\n", err)
		return 1
	}
	defer closePrerequisites(prereqs, prerequisitesCloseTimeout, logger)

	if rt != nil {
		if err := rt.Start(life, c.HostDeps()); err != nil {
			fmt.Fprintf(stderr, "qwq serve-controller: start the plugin runtime: %v\n", err)
			return 1
		}
	}

	// The updater needs the open database, so it is built after the controller
	// and installed with SetUpdater. Recover runs before requests are served:
	// it resolves unfinished sagas and republishes the routes.
	up, err := newUpdater(c, *pluginsDir, *trustDir, *stagingDir, helper, logger)
	if err != nil {
		fmt.Fprintf(stderr, "qwq serve-controller: %v\n", err)
		return 1
	}
	if up != nil {
		c.SetUpdater(up)
		// Retained versions make a directory scan ambiguous after the first
		// update; from here on the plugin directory follows the ACTIVE version.
		dirs.SetActive(func(id string) (string, bool) { v, ok := up.Active(id); return v.Version, ok })
		// The updater is the single owner of unit starts and the ABI
		// bootstrap; the supervisor only attaches from here on (PLG-07).
		rt.SetRestore(up.EnsureActive)
		recoverSagas(life, up, sagaRecoverTimeout, logger)
		restoreActive(life, up, restoreTimeout, logger)
	}

	// The HTTP adapter owns the upload staging directory and reads the config
	// schema from the immutable version tree. A failure to prepare it disables
	// package routes but keeps the version list and plugin operations working.
	var (
		pluginAPI api.PluginManager
		uploads   *api.PluginUploads
	)
	if up != nil {
		pluginAPI = newPluginManager(c, *pluginsDir, logger)
		uploads, err = api.NewPluginUploads(filepath.Clean(*stagingDir), api.DefaultPluginUploadTTL, c.Clock())
		if err != nil {
			logger.Error("plugin package uploads disabled", "staging_dir", *stagingDir, "error", err)
			uploads = nil
		}
		// The versioned static prefix serves the published ui/ trees of
		// installed versions (GAPS gap 3); it exists only with an updater.
		c.Gateway().MountPluginUI(pluginui.NewHandler(newPluginUIResolver(up, *pluginsDir)))
		if rt != nil {
			rt.SyncPublicRoutes()
			c.Gateway().MountPublicRoutes(rt.PublicGateway())
		}
		// Staged packages expire even when nothing queries them (GW-07).
		if uploads != nil {
			go uploads.Run(life, time.Minute)
		}
	}

	// Routes are registered before the listener exists: a duplicate or invalid
	// route must fail startup, not the first request that hits it.
	routes, err := registerPublicRoutes(c, pluginAPI, uploads, logger)
	if err != nil {
		fmt.Fprintf(stderr, "qwq serve-controller: %v\n", err)
		return 1
	}
	logger.Info("routes registered", "routes", routes, "plugin_runtime", rt != nil)
	c.Gateway().MountShell(webui.Handler())

	// Every executor is in place now: the plugin runtime is started, the
	// updater recovered its sagas and api.Register added the host action
	// handlers. Jobs run and recovered operations resume from here on.
	c.StartOperations(life)

	// Certificate renewal and expiry warnings run in the background for the
	// lifetime of the process; the listener keeps serving the previous
	// certificate while a new one is prepared.
	go c.TLS().Maintain(life)
	go prereqs.Renewals.Run(life, func(err error) {
		logger.Warn("certificate renewal run failed", "error", err)
	})

	rootHandler := c.Handler()
	if rt != nil {
		var trustedPrefixes []netip.Prefix
		for _, raw := range cfg.HTTP.TrustedProxies {
			if pfx, err := netip.ParsePrefix(raw); err == nil {
				trustedPrefixes = append(trustedPrefixes, pfx)
			} else if addr, err := netip.ParseAddr(raw); err == nil {
				trustedPrefixes = append(trustedPrefixes, netip.PrefixFrom(addr.Unmap(), addr.Unmap().BitLen()))
			}
		}
		rootHandler = pluginpublic.NewCustomDomainRouter(cfg.HTTP.PublicOrigins, trustedPrefixes, rt.PublicGateway(), rootHandler)
	}

	srv := &http.Server{
		Addr:              cfg.HTTP.Listen,
		Handler:           rootHandler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       60 * time.Second,
		WriteTimeout:      0, // SSE responses are long-lived; handlers bound themselves
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    64 << 10,
		ErrorLog:          slog.NewLogLogger(logger.Handler(), slog.LevelWarn),
		BaseContext:       func(net.Listener) context.Context { return life },
	}
	// Shutdown waits for handlers, but the two SSE streams only end when their
	// broker closes; closing both as Shutdown begins keeps an open dashboard
	// from holding the drain for the whole budget.
	srv.RegisterOnShutdown(c.Gateway().Close)
	srv.RegisterOnShutdown(func() {
		if s := c.AgentSessions(); s != nil {
			s.Close()
		}
	})

	errCh := make(chan error, 1)
	go func() {
		ln, err := net.Listen("tcp", cfg.HTTP.Listen)
		if err != nil {
			errCh <- err
			return
		}
		fmt.Fprintf(stdout, "listening on %s (tls %s)\n", ln.Addr(), cfg.HTTP.TLS.Mode)
		if cfg.HTTP.TLS.Mode != config.TLSProxy {
			srv.TLSConfig = c.TLS().TLSConfig()
			if fp := c.TLS().Fingerprint(); fp != "" {
				fmt.Fprintf(stdout, "certificate fingerprint sha256 %s\n", fp)
			}
			errCh <- srv.ServeTLS(ln, "", "")
			return
		}
		errCh <- srv.Serve(ln)
	}()

	select {
	case err := <-errCh:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			fmt.Fprintf(stderr, "qwq serve-controller: %v\n", err)
			return 1
		}
		return 0
	case <-sig.Done():
	}

	logger.Info("shutting down")
	sctx, cancel := context.WithTimeout(context.Background(), httpShutdownTimeout)
	defer cancel()
	if err := srv.Shutdown(sctx); err != nil {
		logger.Warn("http shutdown timed out; closing connections", "error", err)
		_ = srv.Close()
	}
	return 0
}

// sagaRecoverTimeout bounds startup saga recovery: a plugin that never answers
// must not keep the listener closed while systemd reports the unit as running.
const sagaRecoverTimeout = 2 * time.Minute

// sagaRecoverer is the part of the updater that startup recovery uses.
type sagaRecoverer interface {
	Recover(ctx context.Context) ([]string, error)
}

// recoverSagas resolves unfinished update sagas within timeout. Any failure,
// including the timeout, is logged and startup continues: the affected plugin
// stays degraded while the panel itself serves.
func recoverSagas(life context.Context, up sagaRecoverer, timeout time.Duration, logger *slog.Logger) {
	ctx, cancel := context.WithTimeout(life, timeout)
	defer cancel()
	recovered, err := up.Recover(ctx)
	switch {
	case err != nil:
		// A saga that cannot be resumed is recorded as failed by the updater;
		// the host keeps serving instead of hiding every plugin behind a
		// startup failure.
		logger.Error("plugin update saga recovery failed; the host continues",
			"recovered", recovered, "timed_out", errors.Is(ctx.Err(), context.DeadlineExceeded), "error", err)
	case len(recovered) > 0:
		logger.Info("plugin update sagas recovered", "sagas", recovered)
	}
}

// restoreTimeout bounds the startup restore of one plugin.
const restoreTimeout = 30 * time.Second

// activeRestorer is the part of the updater that the startup restore uses.
type activeRestorer interface {
	Routes() *updater.RouteTable
	EnsureActive(ctx context.Context, pluginID string) error
}

// restoreActive brings every ACTIVE plugin back to a ready, active instance
// after a host restart (ARCH §12 step 3). Plugins are restored one at a time
// (1C1G hosts), each within timeout; a failure is logged and the next plugin
// follows, so one broken plugin cannot keep the panel down.
func restoreActive(life context.Context, up activeRestorer, timeout time.Duration, logger *slog.Logger) {
	for _, route := range up.Routes().List() {
		ctx, cancel := context.WithTimeout(life, timeout)
		err := up.EnsureActive(ctx, route.PluginID)
		cancel()
		if err != nil {
			logger.Warn("plugin could not be restored at startup; the next operation retries",
				"plugin_id", route.PluginID, "version", route.Version, "error", err)
		}
	}
}

// ---------------------------------------------------------------------------
// 关停预算：HTTP drain + 子系统关闭 < systemd TimeoutStopSec(30s)
// ---------------------------------------------------------------------------

const (
	// httpShutdownTimeout bounds the drain of in-flight requests.
	httpShutdownTimeout = 15 * time.Second
	// hostCloseTimeout bounds Controller.Close after the drain.
	hostCloseTimeout = 10 * time.Second
)

// closeHost cancels the service lifetime and closes the controller, giving up
// after timeout so a stuck plugin cannot push the stop past TimeoutStopSec.
// The process exits right after, so an abandoned Close does not leak.
func closeHost(c *controller.Controller, cancelLife context.CancelFunc, timeout time.Duration, logger *slog.Logger) {
	cancelLife()
	done := make(chan struct{})
	go func() {
		if err := c.Close(); err != nil {
			logger.Warn("host services closed with an error", "error", err)
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(timeout):
		logger.Error("host services did not stop in time", "timeout", timeout)
	}
}

// newPluginRuntime builds the plugin runtime when this host can own one. The
// standalone role runs the plugin units of its own node (ARCH §3.1); any other
// role only manages them through an agent, so the runtime stays nil. A missing
// plugin directory disables the runtime with a warning instead of failing
// startup: a host without installed plugins is a valid installation.
//
// The returned PluginDirs is bound to the updater by the caller.
func newPluginRuntime(cfg config.Config, pluginsDir string, logger *slog.Logger) (*controller.PluginRuntime, *controller.PluginDirs, error) {
	if cfg.Role != config.RoleStandalone {
		logger.Info("plugin runtime disabled", "role", cfg.Role,
			"reason", "only the standalone role manages plugin units in this release")
		return nil, nil, nil
	}
	dir := filepath.Clean(pluginsDir)
	info, err := os.Stat(dir)
	if err != nil || !info.IsDir() {
		logger.Warn("plugin runtime disabled: the plugin directory is not available",
			"plugins_dir", dir, "error", err)
		return nil, nil, nil
	}
	dirs := &controller.PluginDirs{Root: dir}
	managementPorts, err := firewall.ManagementPorts(cfg.HTTP)
	if err != nil {
		return nil, nil, fmt.Errorf("build management port guards: %w", err)
	}
	systemd := sandbox.NewSystemctl(sandbox.ExecRunner{})
	if _, compat := systemd.(*sandbox.CompatUnitctlClient); compat {
		logger.Info("plugin unit control uses legacy-polkit compat patch", "socket", sandbox.DefaultCompatUnitctlSocket)
	}
	rt, err := controller.NewPluginRuntime(controller.PluginRuntimeOptions{
		Units: controller.UnitManagerAdapter{
			Systemctl: systemd,
			NodeID:    "local",
		},
		PluginDir:       dirs.Resolve,
		ManagementPorts: managementPorts,
		// Installed plugins get their resident host channel at Start, before
		// systemd may restart one of them on its own.
		PluginsRoot: dir,
		RunDir:      cfg.RunDir,
		StateDir:    filepath.Join(cfg.DataDir, "plugin-state"),
		Logger:      logger,
		NodeID:      "local",
	})
	if err != nil {
		return nil, nil, fmt.Errorf("build the plugin runtime: %w", err)
	}
	return rt, dirs, nil
}

// newUpdater builds the P3 install/update service when this host can run it.
//
// It requires the P2 plugin runtime (it serves the resident host channel the
// updater ensures before every unit start), an existing plugins directory and an
// existing trust directory. A host without installed plugins or without a trust
// root is a valid installation, so a missing directory disables the updater
// with a warning. A construction failure is fatal: the database is migrated by
// then, so failing to open the updater means the wiring or the schema is wrong
// and updates must not silently do nothing.
func newUpdater(c *controller.Controller, pluginsDir, trustDir, stagingDir string, helper *sandbox.HelperClient, logger *slog.Logger) (*updater.Updater, error) {
	if c.PluginRuntime() == nil {
		logger.Info("plugin updater disabled", "reason", "the plugin runtime is not enabled")
		return nil, nil
	}
	plugins := filepath.Clean(pluginsDir)
	if info, err := os.Stat(plugins); err != nil || !info.IsDir() {
		logger.Warn("plugin updater disabled: the plugin directory is not available",
			"plugins_dir", plugins, "error", err)
		return nil, nil
	}
	trust := filepath.Clean(trustDir)
	if info, err := os.Stat(trust); err != nil || !info.IsDir() {
		logger.Warn("plugin updater disabled: the trust directory is not available",
			"trust_dir", trust, "error", err)
		return nil, nil
	}
	systemd := sandbox.NewSystemctl(sandbox.ExecRunner{})
	installer := &controller.PluginInstaller{
		PluginsRoot: plugins,
		DataRoot:    sandbox.DefaultPluginDataRoot,
		StateDir:    filepath.Join(c.Config().DataDir, "plugin-state"),
		StagingRoot: filepath.Clean(stagingDir),
		TrustDir:    trust,
		HostBinary:  sandbox.DefaultHostBinary,
		Sandbox:     sandbox.DefaultInstaller(sandbox.ExecRunner{}),
		Helper:      helper,
		Systemctl:   systemd,
		Tokens:      &controller.PluginTokens{DB: c.DB()},
		// The resident host channel closes with the plugin's last version.
		HostChannels: c.PluginRuntime(),
		Preflight:    sandboxPreflight(c.Config().RunDir),
		Logger:       logger,
	}
	// A crash can leave a staging directory behind; only entries older than an
	// hour are removed, so a concurrent install is never disturbed.
	if removed, cerr := install.CleanupStale(installer.StagingRoot, time.Hour); cerr != nil {
		logger.Warn("plugin staging cleanup failed", "staging_dir", installer.StagingRoot, "error", cerr)
	} else if len(removed) > 0 {
		logger.Info("removed stale plugin staging directories", "count", len(removed))
	}
	runtime := &controller.UpdaterRuntime{
		Systemctl:   systemd,
		PluginsRoot: plugins,
		DataRoot:    sandbox.DefaultPluginDataRoot,
		RunDir:      c.Config().RunDir,
		Clock:       c.Clock(),
		Logger:      logger,
		NodeID:      "local",
		// host.sock must exist before the unit starts (PLG-01).
		HostChannels: c.PluginRuntime(),
	}
	up, err := updater.New(updater.Options{
		DB:        c.DB(),
		Runtime:   runtime,
		Installer: installer,
		Memory:    &controller.HostMemory{},
		Clock:     c.Clock(),
		Logger:    logger,
		// The systemd unit is per plugin, not per version: the updater must
		// never choose the blue-green strategy, including on rollback.
		RestartOnly: true,
	})
	if err != nil {
		return nil, fmt.Errorf("build the plugin updater: %w", err)
	}
	logger.Info("plugin updater enabled",
		"plugins_dir", plugins, "staging_dir", installer.StagingRoot, "trust_dir", trust,
		"privileged_helper", installer.Helper != nil)
	return up, nil
}

// newPrivilegedHelper returns the client for the root helper. serve-controller
// runs as qwq and cannot write /etc/systemd/system, so a non-root host always
// uses the helper, whether or not its socket exists yet, and refuses to start
// without one. Only a root host (tests, development) may run installs
// in-process: with no socket configured, or when the path is not a socket.
func newPrivilegedHelper(socket string, euid int, logger *slog.Logger) (*sandbox.HelperClient, error) {
	if socket == "" {
		if euid != 0 {
			return nil, errors.New("--privileged-socket is required when not running as root")
		}
		logger.Info("privileged helper disabled", "reason", "no --privileged-socket was configured")
		return nil, nil // root development mode: in-process installs
	}
	if euid != 0 {
		// A non-root host can never install in-process. The socket may not
		// exist yet (the helper starts later); each call then reports
		// UNAVAILABLE instead of silently falling back to an EACCES path.
		logger.Info("plugin installs use the privileged helper", "socket", socket)
		return sandbox.NewHelperClient(socket), nil
	}
	info, err := os.Stat(socket)
	if err != nil || info.Mode()&os.ModeSocket == 0 {
		logger.Warn("privileged helper not available; plugin installs fall back to the in-process installer",
			"socket", socket, "error", err)
		return nil, nil
	}
	logger.Info("plugin installs use the privileged helper", "socket", socket)
	return sandbox.NewHelperClient(socket), nil
}

// registerPublicRoutes mounts the public API and the agent tools on the
// controller's gateway and returns the number of routes. It must run before the
// listener starts. plugins and uploads are nil on a host without an updater.
func registerPublicRoutes(c *controller.Controller, plugins api.PluginManager, uploads *api.PluginUploads, logger *slog.Logger) (int, error) {
	if c == nil || c.Gateway() == nil {
		return 0, errors.New("the controller has no gateway")
	}
	// The native agent backend is built here, once, and handed to the API: it
	// needs the operation manager (runner and approval bridge), the action
	// catalog and the secret store, which only the controller has (ADR-0010 §5).
	agentSessions, err := c.NewAgentSessions(context.Background())
	if err != nil {
		return 0, fmt.Errorf("build the agent session backend: %w", err)
	}
	if err := api.Register(c.Gateway(), api.Deps{
		Config:         c.Config(),
		DB:             c.DB(),
		Clock:          c.Clock(),
		IDs:            c.IDs(),
		Logger:         logger,
		Identity:       c.Identity(),
		Authz:          c.Authorizer(),
		Ops:            c.Operations(),
		Catalog:        c.Catalog(),
		Secrets:        c.Secrets(),
		PrivateExports: c.PrivateExports(),
		TLS:            c.TLS(),
		NodeID:         "local",
		AgentSessions:  agentSessions,
		Plugins:        plugins,
		PluginUploads:  uploads,
	}); err != nil {
		return 0, fmt.Errorf("register the public API: %w", err)
	}
	if err := agentapi.Register(c.Gateway(), agentapi.Deps{
		DB:       c.DB(),
		Clock:    c.Clock(),
		IDs:      c.IDs(),
		Logger:   logger,
		Identity: c.Identity(),
		Authz:    c.Authorizer(),
		Ops:      c.Operations(),
		Catalog:  c.Catalog(),
		NodeID:   "local",
	}); err != nil {
		return 0, fmt.Errorf("register the agent tools: %w", err)
	}
	return len(c.Gateway().Routes()), nil
}
