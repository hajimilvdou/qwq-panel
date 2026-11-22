// SPDX-License-Identifier: AGPL-3.0-only

// Command qwq-compat-unitctl is the optional legacy-polkit compatibility patch
// helper (qwq-compat-polkit) for Linux distributions whose polkit cannot read
// JavaScript rules (e.g. Ubuntu 22.04 with polkit 0.105, Debian 11).
//
// Native distributions with polkit >= 0.106 (Debian 12+, Ubuntu 24.04+,
// Rocky/Alma 9+) never install or run this binary.
//
// Security posture:
//   - Linux only, root only (euid 0).
//   - Socket activated by qwq-compat-unitctl.socket (root:qwq 0660, LISTEN_FDS=1);
//     serves one request per activation and exits (zero idle memory).
//   - Verifies SO_PEERCRED on every connection: only uid 0 or the qwq user may connect.
//   - Enforces the exact same allowlist as deployments/polkit/qwq-plugin.rules:
//     only start, stop and kill on qwq-plugin@<valid-id>.(service|socket).
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"syscall"

	"github.com/qwq-panel/qwq/internal/buildinfo"
	"github.com/qwq-panel/qwq/internal/sandbox"
)

var geteuid = os.Geteuid

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := run(ctx, os.Args[1:], os.Stdout, os.Stderr, os.Getenv, logger)
	stop()
	os.Exit(code)
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer, getenv func(string) string, logger *slog.Logger) int {
	flags := flag.NewFlagSet("qwq-compat-unitctl", flag.ContinueOnError)
	flags.SetOutput(stderr)
	socketPath := flags.String("socket", sandbox.DefaultCompatUnitctlSocket, "Unix socket to listen on")
	socketGroup := flags.String("socket-group", sandbox.DefaultAgentUser, "group that may connect to the compat socket")
	agentUser := flags.String("agent-user", sandbox.DefaultAgentUser, "unprivileged user authorized to send unit commands")
	credentialsDir := flags.String("credentials-dir", defaultCredentialsRoot, "host /run/credentials directory (or bind target) for systemd 247 compat")
	flags.Usage = func() {
		fmt.Fprint(stderr, `usage: qwq-compat-unitctl [flags]

Linux only, root only. Optional legacy-polkit compatibility helper that allows
only the qwq user to start, stop and kill qwq-plugin@* units when the host OS
lacks polkit >= 0.106 (JavaScript rules).

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
		fmt.Fprintf(stderr, "qwq-compat-unitctl: unexpected argument %q\n", flags.Arg(0))
		return 2
	}
	if runtime.GOOS != "linux" {
		fmt.Fprintln(stderr, "qwq-compat-unitctl: only supported on Linux")
		return 1
	}
	if geteuid() != 0 {
		fmt.Fprintln(stderr, "qwq-compat-unitctl: must run as root")
		return 1
	}
	if !filepath.IsAbs(*socketPath) || filepath.Clean(*socketPath) != *socketPath {
		fmt.Fprintf(stderr, "qwq-compat-unitctl: --socket %q must be a clean absolute path\n", *socketPath)
		return 2
	}
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	ln, activated, err := sandbox.ListenHelperSocket(*socketPath, *socketGroup, getenv)
	if err != nil {
		fmt.Fprintf(stderr, "qwq-compat-unitctl: %v\n", err)
		return 1
	}
	defer func() { _ = ln.Close() }()

	srv := newCompatServer(sandbox.NewExecSystemctl(sandbox.ExecRunner{}), *agentUser, buildinfo.Read().String(), logger)
	if *credentialsDir != "" {
		srv.credentialsDir = filepath.Clean(*credentialsDir)
	}
	if activated {
		logger.Info("serving socket-activated compat unitctl request", "socket", *socketPath)
	} else {
		fmt.Fprintf(stdout, "listening on %s\n", *socketPath)
		logger.Info("serving compat unitctl until SIGTERM", "socket", *socketPath)
	}
	if err := srv.serve(ctx, ln, activated); err != nil {
		fmt.Fprintf(stderr, "qwq-compat-unitctl: %v\n", err)
		return 1
	}
	return 0
}
