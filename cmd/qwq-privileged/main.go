// SPDX-License-Identifier: AGPL-3.0-only

// Command qwq-privileged is the root-only half of plugin installation.
//
// The controller (serve-controller) runs as the unprivileged qwq user and
// cannot write /etc/systemd/system, /var/lib/qwq-plugins or the runtime
// directories. It verifies a package into /var/lib/qwq/staging and sends the
// staged tree, then the rendered UnitSpec and a fresh plugin token, over a Unix
// socket; this process publishes the immutable version directory, writes the
// unit, the resource drop-in, the tmpfiles snippet, the credential and the
// runtime directories, then reloads systemd and enables the plugin socket.
//
// It is a systemd socket-activated service: the socket unit passes one
// listening descriptor (LISTEN_FDS=1), one activation serves one request and
// exits, so an idle host runs no helper process and an idle host has no
// resident root service to attack. `--socket` starts a manual listener for
// debugging on a machine without systemd.
//
// Security posture:
//
//   - It refuses to run unless euid is 0 and the OS is Linux.
//   - It listens only on an AF_UNIX socket, owned root:<socket-group> 0660.
//   - Every request is one size-bounded JSON object; unknown fields are
//     rejected.
//   - A request can only name paths below the configured plugin root, unit dir,
//     tmpfiles dir and runtime base; nothing else is writable.
//   - No command comes from a request: the only external programs it runs are
//     an allowlisted systemctl argument set and the shadow group tools.
//   - It never logs a token and never opens a network connection.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"runtime"
	"syscall"

	"github.com/qwq-panel/qwq/internal/sandbox"
)

// geteuid is os.Geteuid; tests replace it so the refusal needs no privileges.
var geteuid = os.Geteuid

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := run(ctx, os.Args[1:], os.Stdout, os.Stderr, os.Getenv, logger)
	stop()
	os.Exit(code)
}

// run is the testable entry point. Exit status: 0 success, 1 runtime error,
// 2 usage.
func run(ctx context.Context, args []string, stdout, stderr io.Writer, getenv func(string) string, logger *slog.Logger) int {
	cfg := defaultHelperConfig()
	flags := flag.NewFlagSet("qwq-privileged", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.StringVar(&cfg.Socket, "socket", cfg.Socket, "Unix socket to listen on")
	flags.StringVar(&cfg.UnitDir, "unit-dir", cfg.UnitDir, "systemd unit directory")
	flags.StringVar(&cfg.TmpfilesDir, "tmpfiles-dir", cfg.TmpfilesDir, "tmpfiles.d directory")
	flags.StringVar(&cfg.RuntimeBase, "runtime-base", cfg.RuntimeBase, "systemd %t for system services")
	flags.StringVar(&cfg.PluginsRoot, "plugins-root", cfg.PluginsRoot, "installed plugin version root")
	flags.StringVar(&cfg.DataRoot, "plugin-data-root", cfg.DataRoot, "logical plugin persistent data root")
	flags.StringVar(&cfg.PrivateDataRoot, "private-plugin-data-root", cfg.PrivateDataRoot, "DynamicUser private persistent data root")
	flags.StringVar(&cfg.StagingRoot, "staging-root", cfg.StagingRoot, "verified plugin staging root (read-only for publish)")
	flags.StringVar(&cfg.AgentUser, "agent-user", cfg.AgentUser, "user that owns the plugin socket")
	flags.StringVar(&cfg.SocketGroup, "socket-group", cfg.SocketGroup, "group that may connect to the helper socket")
	flags.Usage = func() {
		fmt.Fprint(stderr, `usage: qwq-privileged [flags]

Linux only, root only. Serves the privileged half of plugin installation over a
Unix socket: publish, install, remove, reload and ping. It is meant to be
started by deployments/systemd/qwq-privileged.socket (LISTEN_FDS=1); it exits
after one socket-activated request, so the host has no idle root helper
process.

flags:
`)
		flags.PrintDefaults()
	}
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if flags.NArg() > 0 {
		fmt.Fprintf(stderr, "qwq-privileged: unexpected argument %q\n", flags.Arg(0))
		return 2
	}
	if runtime.GOOS != "linux" {
		fmt.Fprintln(stderr, "qwq-privileged: only supported on Linux")
		return 1
	}
	if geteuid() != 0 {
		fmt.Fprintln(stderr, "qwq-privileged: must run as root")
		return 1
	}
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	srv, err := newHelperServer(cfg, sandbox.ExecRunner{}, logger)
	if err != nil {
		fmt.Fprintf(stderr, "qwq-privileged: %v\n", err)
		return 1
	}
	ln, activated, err := listenSocket(cfg.Socket, cfg.SocketGroup, getenv)
	if err != nil {
		fmt.Fprintf(stderr, "qwq-privileged: %v\n", err)
		return 1
	}
	defer func() { _ = ln.Close() }()
	if activated {
		logger.Info("serving a socket-activated request",
			"socket", cfg.Socket, "unit_dir", cfg.UnitDir, "plugins_root", cfg.PluginsRoot)
	} else {
		fmt.Fprintf(stdout, "listening on %s\n", cfg.Socket)
		logger.Info("serving until SIGTERM",
			"socket", cfg.Socket, "unit_dir", cfg.UnitDir, "plugins_root", cfg.PluginsRoot)
	}
	if err := srv.serve(ctx, ln, activated); err != nil {
		fmt.Fprintf(stderr, "qwq-privileged: %v\n", err)
		return 1
	}
	return 0
}

// listenSocket 复用两个 helper 的共同 socket 激活与访问控制实现。
func listenSocket(socketPath, socketGroup string, getenv func(string) string) (net.Listener, bool, error) {
	path, err := cleanAbsPath("socket", socketPath)
	if err != nil {
		return nil, false, err
	}
	return sandbox.ListenHelperSocket(path, socketGroup, getenv)
}

// activatedFDCount 保留既有测试入口，所有校验由共用实现负责。
func activatedFDCount(getenv func(string) string, pid int) (int, error) {
	return sandbox.ActivatedFDCount(getenv, pid)
}
