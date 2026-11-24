// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/qwq-panel/qwq/internal/panelaccess"
	"github.com/qwq-panel/qwq/internal/platform/config"
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
	fmt.Fprint(stdout, formatAccessHelp(snap.ListenHost, snap.Port, snap.EntryPath, snap.PanelDomain, snap.TLSMode))
	fmt.Fprintln(stdout, "提示：配置已写入数据库，如面板正在运行请执行 `sudo systemctl restart qwq-controller` 使新配置立即生效。")
	return 0
}

func formatAccessHelp(listenHost string, port int, entryPath, panelDomain, tlsMode string) string {
	scheme := "https"
	if tlsMode == config.TLSProxy {
		scheme = "http"
	}
	host := listenHost
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "<你的服务器IP>"
	} else if strings.Contains(host, ":") {
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
	fmt.Fprintf(&b, "  直连/救援: %s\n", directURL)
	if listenHost == "127.0.0.1" {
		fmt.Fprintf(&b, "  SSH 隧道 : ssh -L %d:127.0.0.1:%d root@<你的服务器IP>\n", port, port)
	} else if listenHost == "::1" {
		fmt.Fprintf(&b, "  SSH 隧道 : ssh -L %d:[::1]:%d root@<你的服务器IP>\n", port, port)
	}
	fmt.Fprintf(&b, "  应急重置 : sudo qwq access reset [--listen 127.0.0.1|0.0.0.0] [--port N] [--entry-path none|<path>] [--clear-domain]\n")
	return b.String()
}
