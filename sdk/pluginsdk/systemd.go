// SPDX-License-Identifier: Apache-2.0

package pluginsdk

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/health"
	grpc_health_v1 "google.golang.org/grpc/health/grpc_health_v1"
)

// DefaultListenFD is the first descriptor systemd passes to a socket-activated
// service (SD_LISTEN_FDS_START).
const DefaultListenFD = 3

// DefaultHealthService is the gRPC health service name that reports plugin
// process readiness. The empty name is always registered as well; go-plugin's
// gRPC client and the host's liveness probe use "".
const DefaultHealthService = "plugin"

// DefaultHostSocketWait bounds how long [ServeSystemd] waits for the Agent's
// host socket to appear before it fails the start. The Agent creates the host
// socket before it starts the unit, so the wait only covers a start race.
const DefaultHostSocketWait = 5 * time.Second

// DefaultShutdownGrace bounds the graceful gRPC drain during shutdown. After
// it, [grpc.Server.Stop] closes the remaining calls instead of hanging.
const DefaultShutdownGrace = 10 * time.Second

// Environment variables the transport reads. The Agent and the rendered systemd
// units set them; they are never a source of identity, only of addresses.
const (
	// EnvHostSocket is the per-plugin host channel path. Inside the plugin it
	// is the private bind mount /run/qwq/link/host.sock.
	EnvHostSocket = "QWQ_HOST_SOCKET"
	// EnvPluginSocket is the listener path systemd owns. The plugin does not
	// need it (it receives the descriptor), but the transport logs it, and a
	// mismatch between the unit and the runtime is easier to diagnose with it.
	EnvPluginSocket = "QWQ_PLUGIN_SOCKET"
	// EnvPluginID names the plugin instance for logs. The manifest is the
	// identity the SDK validates; this variable is convenience only.
	EnvPluginID = "QWQ_PLUGIN_ID"
	// EnvCredentialsDirectory is set by systemd when the unit uses
	// LoadCredential=/LoadCredentialEncrypted=.
	EnvCredentialsDirectory = "CREDENTIALS_DIRECTORY"
)

// TokenCredentialName is the credential name of the plugin token
// (LoadCredential=qwq-token:...).
const TokenCredentialName = "qwq-token"

// HostTokenMetadataKey is the gRPC metadata key that carries the plugin token
// on every host channel call. The host compares its SHA-256 with the digest it
// recorded at install time and rejects a missing or wrong token as
// UNAUTHENTICATED (ADR-0013).
const HostTokenMetadataKey = "qwq-plugin-token"

// SystemdOptions configures [ServeSystemd].
type SystemdOptions struct {
	// PluginID labels the logs. Empty falls back to $QWQ_PLUGIN_ID.
	PluginID string
	// HostSocket is the Agent's host channel socket. Empty falls back to
	// $QWQ_HOST_SOCKET.
	HostSocket string
	// ListenFD is the inherited listening descriptor. 0 means
	// DefaultListenFD (3).
	ListenFD int
	// HealthService is the extra gRPC health service name reported as
	// SERVING. Empty means DefaultHealthService; the empty name is always
	// registered.
	HealthService string
	// HostSocketWait bounds the wait for HostSocket to appear. 0 means
	// DefaultHostSocketWait.
	HostSocketWait time.Duration
	// ShutdownGrace bounds the graceful drain when the process stops. 0 means
	// DefaultShutdownGrace.
	ShutdownGrace time.Duration
	// IdleTTL overrides serveOptions.IdleTTL when > 0.
	IdleTTL time.Duration
	// Logger receives transport diagnostics. Nil uses Options.Logger from
	// serveOptions, or the SDK default.
	Logger *slog.Logger
}

// ServeSystemd serves a plugin over the socket systemd activated.
//
// The transport is the process wiring the SDK deliberately does not own
// (ADR-0003): it adopts the inherited listening descriptor, registers the
// PluginService and the gRPC health service on one *grpc.Server, connects to
// the Agent's per-plugin host channel, and drains the server when ctx is
// canceled or SIGTERM/SIGINT arrives. It does not require go-plugin's Serve():
// that function always creates its own listener and cannot adopt an inherited
// descriptor.
//
// Error contract:
//   - A missing or inconsistent activation environment (LISTEN_FDS,
//     LISTEN_PID, descriptor kind) is an error; the process must not fall back
//     to an unauthenticated TCP or a second listener.
//   - A missing host socket is an error after HostSocketWait. Plugins cannot
//     serve without the reverse channel; starting half-wired would look
//     healthy while every host call fails.
//   - A canceled ctx or SIGTERM/SIGINT stops the server and returns nil.
//
// ServeSystemd does not validate peer credentials: the Agent-side host channel
// authenticates the plugin by SO_PEERCRED and by the plugin token, which is
// read from $CREDENTIALS_DIRECTORY/qwq-token and sent as
// HostTokenMetadataKey on every host call; systemd owns the plugin socket with
// SocketUser/SocketMode (P2-T1).
func ServeSystemd(ctx context.Context, opts SystemdOptions, serveOptions Options) error {
	if ctx == nil {
		ctx = context.Background()
	}
	pluginID := opts.PluginID
	if pluginID == "" {
		pluginID = os.Getenv(EnvPluginID)
	}
	log := opts.Logger
	if log == nil {
		log = serveOptions.Logger
	}
	if log == nil {
		log = defaultLogger()
	}
	log = log.With(slog.String("plugin", pluginID), slog.Int("pid", os.Getpid()))

	listenFD := opts.ListenFD
	if listenFD == 0 {
		listenFD = DefaultListenFD
	}
	ln, err := listenerFromSystemd(listenFD)
	if err != nil {
		return fmt.Errorf("pluginsdk: %w", err)
	}
	defer func() { _ = ln.Close() }()
	log.Info("adopted the systemd listener",
		slog.String("addr", ln.Addr().String()),
		slog.Int("fd", listenFD),
		slog.String("listen_fds", os.Getenv("LISTEN_FDS")),
		slog.String("listen_fdnames", os.Getenv("LISTEN_FDNAMES")),
		slog.String("plugin_socket", os.Getenv(EnvPluginSocket)))

	cred := readCredential(log)
	if cred.present {
		log.Info("plugin credential available",
			slog.Int("bytes", cred.size), slog.String("sha256_8", cred.digest))
	} else {
		log.Warn("plugin credential is not available", slog.String("error", cred.err))
	}

	hostConn, err := connectHostSocket(ctx, opts.HostSocket, opts.HostSocketWait, cred.token, log)
	if err != nil {
		return fmt.Errorf("pluginsdk: %w", err)
	}
	defer func() { _ = hostConn.Close() }()

	healthService := opts.HealthService
	if healthService == "" {
		healthService = DefaultHealthService
	}
	srv := grpc.NewServer(grpc.WaitForHandlers(true))
	healthSrv := health.NewServer()
	grpc_health_v1.RegisterHealthServer(srv, healthSrv)

	idleDrainCh := make(chan struct{})
	var idleDrainOnce sync.Once
	onIdleDrain := serveOptions.OnIdleDrain
	if onIdleDrain == nil {
		onIdleDrain = func() {
			idleDrainOnce.Do(func() { close(idleDrainCh) })
		}
	}
	idleTTL := opts.IdleTTL
	if idleTTL <= 0 {
		idleTTL = serveOptions.IdleTTL
	}

	pluginServer, err := Serve(ctx, Options{
		Plugin:             serveOptions.Plugin,
		Manifest:           serveOptions.Manifest,
		Registrar:          srv,
		Host:               hostConn,
		Logger:             log,
		DefaultGracePeriod: serveOptions.DefaultGracePeriod,
		ReleaseGracePeriod: serveOptions.ReleaseGracePeriod,
		CrashOnPanic:       serveOptions.CrashOnPanic,
		IdleTTL:            idleTTL,
		OnIdleDrain:        onIdleDrain,
	})
	if err != nil {
		return err
	}
	defer pluginServer.Close()

	healthSrv.SetServingStatus("", grpc_health_v1.HealthCheckResponse_SERVING)
	if healthService != "" {
		healthSrv.SetServingStatus(healthService, grpc_health_v1.HealthCheckResponse_SERVING)
	}

	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.Serve(ln) }()

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGTERM, syscall.SIGINT)
	defer signal.Stop(sigs)

	select {
	case err := <-serveErr:
		if err == nil || errors.Is(err, grpc.ErrServerStopped) {
			return nil
		}
		return fmt.Errorf("pluginsdk: serve: %w", err)
	case sig := <-sigs:
		log.Info("signal received, shutting down", slog.String("signal", sig.String()))
	case <-idleDrainCh:
		log.Info("idle TTL expired, hibernating plugin process")
	case <-ctx.Done():
		log.Info("context canceled, shutting down", slog.String("error", ctx.Err().Error()))
	}
	shutdownGRPC(srv, healthSrv, opts.ShutdownGrace, log)
	return nil
}

// listenerFromSystemd validates the socket-activation environment and adopts
// the listening descriptor. It refuses to guess: a stale LISTEN_PID would make
// an arbitrary descriptor look like a listener.
func listenerFromSystemd(fd int) (net.Listener, error) {
	if fd < DefaultListenFD {
		return nil, fmt.Errorf("listen fd %d is below the socket-activation start (%d)", fd, DefaultListenFD)
	}
	rawFDs := os.Getenv("LISTEN_FDS")
	if rawFDs == "" {
		return nil, errors.New("LISTEN_FDS is not set; the plugin must be started by systemd socket activation")
	}
	n, err := strconv.Atoi(rawFDs)
	if err != nil || n < 1 {
		return nil, fmt.Errorf("LISTEN_FDS=%q is not a positive descriptor count", rawFDs)
	}
	if n != 1 {
		return nil, fmt.Errorf("LISTEN_FDS=%d, the plugin expects exactly one listening socket", n)
	}
	rawPID := os.Getenv("LISTEN_PID")
	if rawPID == "" {
		return nil, errors.New("LISTEN_PID is not set; the activation environment is incomplete")
	}
	owner, err := strconv.Atoi(rawPID)
	if err != nil {
		return nil, fmt.Errorf("LISTEN_PID=%q is not a pid", rawPID)
	}
	if owner != os.Getpid() {
		return nil, fmt.Errorf("LISTEN_PID=%d does not match this process (%d)", owner, os.Getpid())
	}

	file := os.NewFile(uintptr(fd), "systemd-listen-fd")
	if file == nil {
		return nil, fmt.Errorf("descriptor %d is not open", fd)
	}
	ln, ferr := net.FileListener(file)
	// os.NewFile took ownership of the descriptor. net.FileListener duplicated
	// it, so the inherited descriptor can be closed now.
	_ = file.Close()
	if ferr != nil {
		return nil, fmt.Errorf("descriptor %d is not a listening socket: %w", fd, ferr)
	}
	unix, ok := ln.(*net.UnixListener)
	if !ok {
		_ = ln.Close()
		return nil, fmt.Errorf("descriptor %d is a %T; the plugin transport only accepts a Unix domain socket", fd, ln)
	}
	// systemd owns the socket path. Closing our duplicate must never unlink it,
	// or the next activation would find no listener.
	unix.SetUnlinkOnClose(false)
	return unix, nil
}

// connectHostSocket returns a lazy gRPC connection to the Agent's host channel.
// grpc.NewClient does not dial, so the wait is about the socket appearing, not
// about the Agent answering: systemd may start the plugin microseconds before
// the Agent's listener is bound in tests and debugging runs.
func connectHostSocket(ctx context.Context, explicit string, wait time.Duration, token []byte, log *slog.Logger) (*grpc.ClientConn, error) {
	path := explicit
	if path == "" {
		path = os.Getenv(EnvHostSocket)
	}
	if path == "" {
		return nil, fmt.Errorf("the host socket is not configured (set SystemdOptions.HostSocket or %s)", EnvHostSocket)
	}
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, fmt.Errorf("host socket %q is not a clean absolute path", path)
	}
	if wait <= 0 {
		wait = DefaultHostSocketWait
	}
	if err := waitForSocket(ctx, path, wait); err != nil {
		return nil, err
	}
	dialOpts := []grpc.DialOption{grpc.WithTransportCredentials(insecure.NewCredentials())}
	if len(token) > 0 {
		dialOpts = append(dialOpts, grpc.WithPerRPCCredentials(hostToken(token)))
	}
	conn, err := grpc.NewClient("unix://"+path, dialOpts...)
	if err != nil {
		return nil, fmt.Errorf("creating the host channel client: %w", err)
	}
	log.Info("host channel configured", slog.String("host_socket", path))
	return conn, nil
}

// hostToken attaches the plugin token to every host channel call. The channel
// is a local Unix socket whose peer the host verifies by SO_PEERCRED, so it
// does not require transport security.
type hostToken []byte

func (t hostToken) GetRequestMetadata(context.Context, ...string) (map[string]string, error) {
	return map[string]string{HostTokenMetadataKey: string(t)}, nil
}

func (hostToken) RequireTransportSecurity() bool { return false }

// waitForSocket waits until path is a socket or the wait budget expires.
func waitForSocket(ctx context.Context, path string, wait time.Duration) error {
	deadline := time.Now().Add(wait)
	for {
		fi, err := os.Lstat(path)
		switch {
		case err == nil && fi.Mode()&os.ModeSocket != 0:
			return nil
		case err == nil:
			return fmt.Errorf("host socket %s is not a socket (mode %s)", path, fi.Mode())
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("the host socket %s did not appear within %s: %w", path, wait, err)
		}
		timer := time.NewTimer(25 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return fmt.Errorf("waiting for the host socket %s: %w", path, ctx.Err())
		case <-timer.C:
		}
	}
}

// credentialReport is the non-secret description of the plugin credential.
type credentialReport struct {
	present bool
	size    int
	digest  string
	err     string
	// token is sent to the host on every call; it is never logged.
	token []byte
}

// readCredential reads the plugin token and reports its presence, length and
// the first eight bytes of its SHA-256. The token itself is never logged.
func readCredential(log *slog.Logger) credentialReport {
	dir := os.Getenv(EnvCredentialsDirectory)
	if dir == "" {
		return credentialReport{err: EnvCredentialsDirectory + " is not set"}
	}
	raw, err := os.ReadFile(filepath.Join(dir, TokenCredentialName))
	if err != nil {
		return credentialReport{err: err.Error()}
	}
	sum := sha256.Sum256(raw)
	if log != nil {
		log.Debug("credential loaded", slog.Int("bytes", len(raw)))
	}
	return credentialReport{present: true, size: len(raw), digest: hex.EncodeToString(sum[:8]), token: raw}
}

// shutdownGRPC reports NOT_SERVING, drains in-flight calls and then forces the
// server closed. health.Server.Shutdown also refuses later SetServingStatus
// calls, so a background goroutine cannot resurrect a stopping process.
func shutdownGRPC(srv *grpc.Server, healthSrv *health.Server, grace time.Duration, log *slog.Logger) {
	if grace <= 0 {
		grace = DefaultShutdownGrace
	}
	healthSrv.Shutdown()
	done := make(chan struct{})
	var once sync.Once
	stop := func() {
		once.Do(func() {
			srv.Stop()
			close(done)
		})
	}
	go func() {
		srv.GracefulStop()
		stop()
	}()
	timer := time.NewTimer(grace)
	defer timer.Stop()
	select {
	case <-done:
	case <-timer.C:
		log.Warn("graceful shutdown timed out; stopping the server", slog.Duration("grace", grace))
		stop()
	}
}
