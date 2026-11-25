// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/qwq-panel/qwq/internal/panelaccess"
	"github.com/qwq-panel/qwq/internal/platform/config"
	"github.com/qwq-panel/qwq/internal/sandbox"
)

// runAccess implements `qwq access show` and `qwq access reset` so an operator
// locked out by a forgotten entry path, wrong reverse-proxy domain, or listen
// host can inspect or recover the live SQLite panel_access_settings from SSH.
func runAccess(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		accessUsage(stdout)
		if len(args) == 0 {
			return 2
		}
		return 0
	}
	switch args[0] {
	case "show":
		return runAccessShow(args[1:], stdout, stderr)
	case "reset":
		return runAccessReset(args[1:], stdout, stderr)
	default:
		fmt.Fprintf(stderr, "qwq access: unknown subcommand %q\n\n", args[0])
		accessUsage(stderr)
		return 2
	}
}

func accessUsage(w io.Writer) {
	fmt.Fprint(w, `usage: sudo qwq access <show|reset> [flags]

commands:
  show   print the live panel listener, secret entry path, domain and rescue URL
  reset  update listen host/port, clear panel domain, or reset the secret entry path
         (restart qwq-controller after reset: sudo systemctl restart qwq-controller)
`)
}

func runAccessShow(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("access show", flag.ContinueOnError)
	fs.SetOutput(stderr)
	configPath := fs.String("config", config.DefaultPath, "bootstrap configuration file")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 {
		fmt.Fprintf(stderr, "qwq access show: 不接受多余位置参数 %q\n", strings.Join(fs.Args(), " "))
		return 2
	}
	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(stderr, "qwq access show: %v\n", err)
		return 2
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	logger := slog.New(slog.NewTextHandler(stderr, &slog.HandlerOptions{Level: slog.LevelWarn})).With("service", "access")
	local, closeDB, err := openLocalDatabase(ctx, cfg, logger)
	if err != nil {
		fmt.Fprintf(stderr, "qwq access show: %v\n", err)
		return 1
	}
	defer closeDB()

	listenAddr, _, rawEntryPath, panelDomain, _ := panelaccess.ReadEffectiveFromDB(ctx, local.DB, cfg.HTTP)
	host, portStr, err := net.SplitHostPort(listenAddr)
	port := 8443
	if err == nil {
		if p, perr := strconv.Atoi(portStr); perr == nil && p > 0 {
			port = p
		}
	}
	fmt.Fprint(stdout, formatAccessHelp(host, port, rawEntryPath, panelDomain, cfg.HTTP.TLS.Mode))
	return 0
}

func runAccessReset(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("access reset", flag.ContinueOnError)
	fs.SetOutput(stderr)
	configPath := fs.String("config", config.DefaultPath, "bootstrap configuration file")
	listenHost := fs.String("listen", "", "new listen host (127.0.0.1, 0.0.0.0, ::1, :: or NIC IP)")
	port := fs.Int("port", 0, "new TCP listen port (1-65535)")
	entryPath := fs.String("entry-path", "", "new secret entry path (use 'none' to disable)")
	clearDomain := fs.Bool("clear-domain", false, "clear panel_domain to restore direct IP access")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 {
		fmt.Fprintf(stderr, "qwq access reset: 不接受多余位置参数 %q（端口请使用 --port N）\n", strings.Join(fs.Args(), " "))
		return 2
	}
	portSet := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "port" {
			portSet = true
		}
	})
	if portSet && (*port < 1 || *port > 65535) {
		fmt.Fprintf(stderr, "qwq access reset: --port 必须在 1..65535 之间（收到 %d）\n", *port)
		return 2
	}
	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(stderr, "qwq access reset: %v\n", err)
		return 2
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	logger := slog.New(slog.NewTextHandler(stderr, &slog.HandlerOptions{Level: slog.LevelWarn})).With("service", "access")
	local, closeDB, err := openLocalDatabase(ctx, cfg, logger)
	if err != nil {
		fmt.Fprintf(stderr, "qwq access reset: %v\n", err)
		return 1
	}
	defer closeDB()

	mgr, err := panelaccess.NewManager(ctx, panelaccess.Options{
		DB:        local.DB,
		Clock:     local.Clock,
		Bootstrap: cfg.HTTP,
	})
	if err != nil {
		fmt.Fprintf(stderr, "qwq access reset: %v\n", err)
		return 1
	}

	var in panelaccess.UpdateInput
	if strings.TrimSpace(*listenHost) != "" {
		h := strings.TrimSpace(*listenHost)
		in.ListenHost = &h
	}
	if portSet {
		p := *port
		in.Port = &p
	}
	if *clearDomain {
		empty := ""
		in.PanelDomain = &empty
	}
	if strings.TrimSpace(*entryPath) != "" {
		ep := strings.TrimSpace(*entryPath)
		if strings.EqualFold(ep, "none") {
			ep = ""
		}
		in.EntryPath = &ep
	}
	if in.ListenHost == nil && in.Port == nil && in.PanelDomain == nil && in.EntryPath == nil {
		// Default emergency reset: clear domain and disable entry gate on current port.
		empty := ""
		in.PanelDomain = &empty
		in.EntryPath = &empty
	}

	snap, _, err := mgr.Update(ctx, in)
	if err != nil {
		fmt.Fprintf(stderr, "qwq access reset: %v\n", err)
		return 1
	}
	syncAccessResetRuntime(ctx, snap, stdout)
	fmt.Fprint(stdout, formatAccessHelp(snap.ListenHost, snap.Port, snap.EntryPath, snap.PanelDomain, snap.TLSMode))
	return 0
}

func syncAccessResetRuntime(ctx context.Context, snap panelaccess.Snapshot, stdout io.Writer) {
	signaled := false
	if _, err := exec.LookPath("systemctl"); err == nil {
		actCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		active := exec.CommandContext(actCtx, "systemctl", "is-active", "--quiet", "qwq-controller.service").Run() == nil
		cancel()
		if active {
			pidCtx, pcancel := context.WithTimeout(ctx, 5*time.Second)
			out, perr := exec.CommandContext(pidCtx, "systemctl", "show", "-p", "MainPID", "--value", "qwq-controller.service").Output()
			pcancel()
			if perr == nil {
				if pid, aerr := strconv.Atoi(strings.TrimSpace(string(out))); aerr == nil && pid > 1 {
					// Both qwq access reset (after dropToOwner) and qwq-controller run as
					// the same qwq user, so signaling MainPID directly succeeds without polkit.
					// Signaling BEFORE firewall sync lets Reload() rebind first and update
					// nftables in the safe non-lockout order.
					if kerr := syscall.Kill(pid, syscall.SIGHUP); kerr == nil {
						signaled = true
					}
				}
			}
			if !signaled {
				hupCtx, hcancel := context.WithTimeout(ctx, 5*time.Second)
				if kerr := exec.CommandContext(hupCtx, "systemctl", "kill", "-s", "HUP", "--kill-who=main", "qwq-controller.service").Run(); kerr == nil {
					signaled = true
				}
				hcancel()
			}
		}
	}
	if signaled {
		fmt.Fprintln(stdout, "提示：配置已写入数据库并向运行中的 qwq-controller 发送 SIGHUP 热重载生效。")
		return
	}
	// Controller is not running (or SIGHUP did not reach it): sync firewall port
	// hint directly so the next start / firewall restore reflects the new port.
	if snap.Port > 0 && snap.Port <= 65535 {
		payload, _ := json.Marshal(struct {
			Port       int    `json:"port"`
			ListenHost string `json:"listen_host,omitempty"`
		}{
			Port:       snap.Port,
			ListenHost: snap.ListenHost,
		})
		capCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		resp, cerr := sandbox.NewCapabilityClient(sandbox.DefaultCapabilitySocket).Call(capCtx, sandbox.CapabilityRequest{
			Op:         "firewall.sync-panel-port",
			ID:         "controller",
			ParamsJSON: payload,
		})
		cancel()
		if cerr != nil || !resp.OK {
			_ = panelaccess.WriteCapabilityPanelPortWithHost(panelaccess.DefaultCapabilityPanelPortFile, snap.Port, snap.ListenHost)
		}
	}
	fmt.Fprintln(stdout, "提示：配置已写入数据库，如面板正在运行请执行 `sudo systemctl restart qwq-controller` 使新配置立即生效。")
}

func formatAccessHelp(listenHost string, port int, entryPath, panelDomain, tlsMode string) string {
	scheme := "https"
	if tlsMode == config.TLSProxy {
		scheme = "http"
	}
	host := listenHost
	if host == "" || host == "0.0.0.0" || host == "::" {
		if pubIP := detectLocalPublicIP(); pubIP != "" {
			host = pubIP
		} else {
			host = "<你的服务器IP>"
		}
	}
	if strings.Contains(host, ":") && !strings.HasPrefix(host, "[") {
		host = "[" + host + "]"
	}
	entry := strings.Trim(entryPath, "/")
	directURL := fmt.Sprintf("%s://%s:%d/", scheme, host, port)
	if entry != "" {
		directURL += entry
	}
	var b strings.Builder
	fmt.Fprintf(&b, "当前面板实时入口配置（含数据库热覆盖）：\n")
	fmt.Fprintf(&b, "  监听地址 : %s\n", net.JoinHostPort(listenHost, strconv.Itoa(port)))
	if entry != "" {
		fmt.Fprintf(&b, "  安全密道 : /%s\n", entry)
	} else {
		fmt.Fprintf(&b, "  安全密道 : （已关闭）\n")
	}
	if panelDomain != "" {
		fmt.Fprintf(&b, "  反代域名 : https://%s/\n", panelDomain)
	}
	fmt.Fprintf(&b, "  面板地址 : %s\n", directURL)
	if listenHost == "127.0.0.1" || listenHost == "::1" {
		fmt.Fprintf(&b, "  开启公网 : sudo qwq access reset --listen 0.0.0.0\n")
	}
	fmt.Fprintf(&b, "  应急重置 : sudo qwq access reset [--listen 0.0.0.0|127.0.0.1] [--port N] [--entry-path none|<path>] [--clear-domain]\n")
	return b.String()
}
