// SPDX-License-Identifier: AGPL-3.0-only

// Command agent is the minimal P2-T1 host agent. It listens on one host-service
// socket per plugin, attaches to each plugin through go-plugin's ReattachConfig,
// verifies both directions with SO_PEERCRED, and records a generation derived
// from systemd's MainPID, the cgroup unit and the process start time.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

func main() {
	var (
		ids          = flag.String("plugins", "", "comma separated plugin ids")
		hostDir      = flag.String("host-dir", "/run/qwq-spike/host", "per-plugin host socket directory")
		stateDir     = flag.String("state-dir", "/run/qwq-spike/state", "state output directory")
		pluginSocket = flag.String("plugin-socket", "/run/qwq-spike/plugin/%s/plugin.sock", "plugin socket path pattern")
		pluginUnit   = flag.String("plugin-unit", "qwq-spike-plugin@%s.service", "plugin service unit pattern")
		socketUnit   = flag.String("plugin-socket-unit", "qwq-spike-plugin@%s.socket", "plugin socket unit pattern")
		agentUnit    = flag.String("agent-unit", "qwq-spike-agent.service", "agent service unit name")
		linkDir      = flag.String("link-dir", "/run/qwq-spike/link", "bind-mount path used inside the plugin")

		once  = flag.Bool("once", false, "attach once, write state and exit")
		probe = flag.Bool("probe", true, "run cross-plugin probe checks after attaching")
	)
	flag.Parse()

	log := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo})).
		With("agent_pid", os.Getpid(), "agent_uid", os.Getuid())

	a := &agent{
		ids:          splitIDs(*ids),
		hostDir:      *hostDir,
		stateDir:     *stateDir,
		pluginSocket: *pluginSocket,
		pluginUnit:   *pluginUnit,
		socketUnit:   *socketUnit,
		agentUnit:    *agentUnit,
		linkDir:      *linkDir,
		runProbe:     *probe,
		log:          log,
		mainPIDs:     map[string]int{},
	}
	if len(a.ids) == 0 {
		log.Error("no plugins requested")
		os.Exit(2)
	}
	if err := os.MkdirAll(a.stateDir, 0o755); err != nil {
		log.Error("cannot create state dir", "err", err)
		os.Exit(1)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := a.startHostServers(ctx); err != nil {
		log.Error("cannot start host servers", "err", err)
		os.Exit(1)
	}
	for _, id := range a.ids {
		st, err := a.attach(ctx, id)
		if err != nil {
			log.Error("attach failed", "plugin", id, "err", err)
			if st != nil {
				_ = writeState(a.stateDir, id, st)
			}
			continue
		}
		if err := writeState(a.stateDir, id, st); err != nil {
			log.Error("write state", "plugin", id, "err", err)
		}
	}
	if a.runProbe {
		if err := a.probeCrossPlugin(ctx); err != nil {
			log.Warn("cross-plugin probe incomplete", "err", err)
		}
	}
	if *once {
		a.close()
		return
	}

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGTERM, syscall.SIGINT)
	sig := <-sigs
	log.Info("signal received, shutting down", "signal", sig.String())
	a.close()
}

func splitIDs(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// generation derives the plugin generation from systemd and kernel facts only.
func generation(unit string, pid int, startTime uint64) (string, error) {
	if pid <= 0 {
		return "", fmt.Errorf("no main pid for %s", unit)
	}
	sum := sha256Sum(fmt.Sprintf("%s|%d|%d", unit, pid, startTime))
	return sum[:16], nil
}

const attachTimeout = 15 * time.Second
