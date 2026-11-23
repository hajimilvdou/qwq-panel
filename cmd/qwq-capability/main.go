// SPDX-License-Identifier: AGPL-3.0-only

// Command qwq-capability 是独立、socket 激活的 root 能力 helper。
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
	"runtime"
	"syscall"

	"github.com/qwq-panel/qwq/internal/buildinfo"
	"github.com/qwq-panel/qwq/internal/capability"
	"github.com/qwq-panel/qwq/internal/capability/docker"
	"github.com/qwq-panel/qwq/internal/capability/sysctl"
	"github.com/qwq-panel/qwq/internal/sandbox"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := run(ctx, os.Args[1:], os.Stdout, os.Stderr, os.Getenv, os.Geteuid)
	stop()
	os.Exit(code)
}

// run 的路径/组来自 root 启动配置，能力请求不能覆盖这些参数。
func run(ctx context.Context, args []string, stdout, stderr io.Writer, getenv func(string) string, geteuid func() int) int {
	flags := flag.NewFlagSet("qwq-capability", flag.ContinueOnError)
	flags.SetOutput(stderr)
	socket := sandbox.DefaultCapabilitySocket
	group := sandbox.DefaultAgentUser
	flags.StringVar(&socket, "socket", socket, "Unix capability socket")
	flags.StringVar(&group, "socket-group", group, "group allowed to connect")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if flags.NArg() != 0 {
		return 2
	}
	if runtime.GOOS != "linux" || ctx == nil {
		fmt.Fprintln(stderr, "qwq-capability: Linux and a context are required")
		return 1
	}
	if geteuid() != 0 {
		fmt.Fprintln(stderr, "qwq-capability: must run as root")
		return 1
	}
	logger := slog.New(slog.NewJSONHandler(stderr, nil))
	runner := newDockerDispatchRunner(
		newSysctlDispatchRunner(capability.SystemRunner(), sysctl.NewService()),
		docker.NewService(),
	)
	listener, activated, err := sandbox.ListenHelperSocket(socket, group, getenv)
	if err != nil {
		fmt.Fprintln(stderr, "qwq-capability: could not open the controlled Unix socket")
		return 1
	}
	defer listener.Close()
	server := newCapabilityServer(runner, logger, buildinfo.Read().Version)
	if !activated {
		fmt.Fprintln(stdout, "qwq-capability: serving the configured Unix socket")
	}
	if err := server.serve(ctx, listener, activated); err != nil {
		fmt.Fprintln(stderr, "qwq-capability: request serving failed")
		return 1
	}
	return 0
}
