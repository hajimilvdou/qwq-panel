// SPDX-License-Identifier: AGPL-3.0-only

// Command qwq-agent 是轻量化边缘节点守护进程，支持 SPKI 钉扎入网、TLS 1.3 mTLS 长连接、
// 32 MiB 有界离线 SQLite Spool 续传与 512MB 低配探针档位（probe_512m，GOMEMLIMIT=24MiB）。
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"runtime/debug"
	"strings"
	"syscall"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/qwq-panel/qwq/internal/buildinfo"
	"github.com/qwq-panel/qwq/internal/cluster"
	"github.com/qwq-panel/qwq/internal/nodespool"
	nodev1 "github.com/qwq-panel/qwq/sdk/gen/qwq/node/v1"
)

const defaultAgentDataDir = "/var/lib/qwq-agent"

// ======================== 入口与子命令派发 ========================

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	os.Exit(runWithContext(ctx, os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	return runWithContext(context.Background(), args, stdout, stderr)
}

func runWithContext(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		usage(stderr)
		return 2
	}
	switch args[0] {
	case "version", "--version", "-v":
		fmt.Fprintln(stdout, "qwq-agent", buildinfo.Read())
		return 0
	case "help", "--help", "-h":
		usage(stdout)
		return 0
	case "enroll":
		return runEnroll(ctx, args[1:], stdout, stderr)
	case "run":
		return runAgent(ctx, args[1:], stdout, stderr)
	default:
		fmt.Fprintf(stderr, "qwq-agent: unknown command %q\n\n", args[0])
		usage(stderr)
		return 2
	}
}

func usage(w io.Writer) {
	fmt.Fprint(w, `usage: qwq-agent <command> [flags]

commands:
  enroll   enroll this node with the controller using SPKI pin + one-time token
  run      run the mTLS edge node session (supports --mode full|probe_512m)
  version  print version and ABI information
  help     show this help
`)
}

// ======================== enroll 子命令 ========================

func runEnroll(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("enroll", flag.ContinueOnError)
	fs.SetOutput(stderr)

	controllerAddr := fs.String("controller", "", "controller enrollment gRPC address (HOST:PORT)")
	caHash := fs.String("ca-hash", "", "expected cluster CA SPKI SHA-256 pin (sha256:<64hex>)")
	token := fs.String("token", "", "one-time node enrollment token")
	dataDir := fs.String("data-dir", defaultAgentDataDir, "local agent state directory")
	timeout := fs.Duration("timeout", 30*time.Second, "enrollment RPC timeout")

	if err := fs.Parse(args); err != nil {
		return 2
	}
	if strings.TrimSpace(*controllerAddr) == "" || strings.TrimSpace(*caHash) == "" || strings.TrimSpace(*token) == "" {
		fmt.Fprintln(stderr, "qwq-agent enroll: --controller, --ca-hash and --token are required")
		return 2
	}

	res, err := cluster.EnrollAgent(ctx, cluster.EnrollOptions{
		ControllerAddr: strings.TrimSpace(*controllerAddr),
		CAHash:         strings.TrimSpace(*caHash),
		Token:          strings.TrimSpace(*token),
		DataDir:        strings.TrimSpace(*dataDir),
		AgentVersion:   buildinfo.Read().Version,
		DialTimeout:    *timeout,
	})
	if err != nil {
		fmt.Fprintf(stderr, "qwq-agent enroll failed: %v\n", err)
		return 1
	}

	fmt.Fprintf(stdout, "enrolled node_id=%s cert_serial=%s expires_at=%s\n",
		res.NodeID, res.CertSerial, res.CertExpiresAt.UTC().Format(time.RFC3339))
	return 0
}

// ======================== run 子命令与 probe_512m 档位 ========================

func applyRuntimeMode(mode string, stdout io.Writer) error {
	switch mode {
	case cluster.ModeFull:
		fmt.Fprintf(stdout, "qwq-agent: mode=%s\n", mode)
		return nil
	case cluster.ModeProbe512M:
		debug.SetMemoryLimit(cluster.Probe512MMemoryLimitBytes)
		fmt.Fprintf(stdout, "qwq-agent: mode=%s memory_limit_bytes=%d max_plugin_memory_mb=%d\n",
			mode, cluster.DefaultProbe512MPolicy.MemoryLimitBytes, cluster.DefaultProbe512MPolicy.MaxPluginMemoryMB)
		return nil
	default:
		return fmt.Errorf("unsupported --mode %q (want %q or %q)", mode, cluster.ModeFull, cluster.ModeProbe512M)
	}
}

func runAgent(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	fs.SetOutput(stderr)

	controllerAddr := fs.String("controller", "", "controller mTLS session gRPC address (HOST:PORT)")
	mode := fs.String("mode", cluster.ModeFull, "node operating profile: full | probe_512m")
	dataDir := fs.String("data-dir", defaultAgentDataDir, "local agent state directory")
	serverName := fs.String("server-name", "", "optional TLS server name override")
	spoolMaxMB := fs.Int("spool-max-mb", 32, "max bounded offline SQLite spool size in MiB")

	if err := fs.Parse(args); err != nil {
		return 2
	}
	if strings.TrimSpace(*controllerAddr) == "" {
		fmt.Fprintln(stderr, "qwq-agent run: --controller is required")
		return 2
	}
	if err := applyRuntimeMode(strings.TrimSpace(*mode), stdout); err != nil {
		fmt.Fprintf(stderr, "qwq-agent run: %v\n", err)
		return 2
	}
	if *spoolMaxMB <= 0 || *spoolMaxMB > 512 {
		fmt.Fprintln(stderr, "qwq-agent run: --spool-max-mb must be between 1 and 512")
		return 2
	}

	spoolPath := filepath.Join(strings.TrimSpace(*dataDir), "spool.db")
	spool, err := nodespool.Open(ctx, spoolPath, int64(*spoolMaxMB)<<20)
	if err != nil {
		fmt.Fprintf(stderr, "qwq-agent run: open spool failed: %v\n", err)
		return 1
	}
	defer spool.Close()

	backoff := time.Second
	for {
		err := cluster.AgentSession(ctx, cluster.SessionOptions{
			ControllerAddr: strings.TrimSpace(*controllerAddr),
			DataDir:        strings.TrimSpace(*dataDir),
			Mode:           strings.TrimSpace(*mode),
			AgentVersion:   buildinfo.Read().Version,
			ServerName:     strings.TrimSpace(*serverName),
			Spool:          spool,
			OnWelcome: func(w *nodev1.Welcome) {
				backoff = time.Second
				fmt.Fprintf(stdout, "qwq-agent: connected node_id=%s protocol=v%d last_ack_seq=%d\n",
					w.GetNodeId(), w.GetProtocolVersion(), w.GetLastEventSequence())
			},
		})
		if ctx.Err() != nil || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return 0
		}
		if status.Code(err) == codes.PermissionDenied {
			fmt.Fprintf(stderr, "qwq-agent: node access revoked by controller: %v\n", err)
			return 1
		}
		if err != nil {
			fmt.Fprintf(stderr, "qwq-agent: session disconnected (%v), retrying in %s\n", err, backoff)
		}
		timer := time.NewTimer(backoff)
		select {
		case <-ctx.Done():
			timer.Stop()
			return 0
		case <-timer.C:
		}
		backoff = min(backoff*2, 30*time.Second)
	}
}
