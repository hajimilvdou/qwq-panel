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
	"github.com/qwq-panel/qwq/internal/tlsmgr"
)

// exitInitialized 表示安装已初始化，不再签发 setup token。
const exitInitialized = 3

// runSetupToken implements `qwq setup-token` (ARCH §4.1.1): on a fresh
// installation it mints the one-time setup token and prints the setup link.
// The token travels in the URL fragment so it never reaches access logs, and
// it is printed only to the operator's terminal, never to the journal.
// Every call invalidates the previous unused token.
func runSetupToken(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("setup-token", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprint(stderr, `usage: sudo qwq setup-token [--config FILE] [--origin https://host:port]

Prints a one-time setup link (valid 30 minutes). Each call invalidates the
previously issued, unused link. Exit status: 0 issued, 1 error, 2 usage,
3 already initialized (use "sudo qwq recover" to reset a password).

`)
		fs.PrintDefaults()
	}
	configPath := fs.String("config", config.DefaultPath, "bootstrap configuration file")
	origin := fs.String("origin", "", "origin the browser reaches the panel at (default: first public_origins entry, else the listener)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(stderr, "qwq setup-token: %v\n", err)
		return 2
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	logger := slog.New(slog.NewTextHandler(stderr, &slog.HandlerOptions{Level: slog.LevelWarn})).
		With("service", "setup-token")
	local, closeDB, err := openLocalDatabase(ctx, cfg, logger)
	if err != nil {
		fmt.Fprintf(stderr, "qwq setup-token: %v\n", err)
		return 1
	}
	defer closeDB()

	listenAddr, effectiveEntryPath, rawEntryPath, panelDomain, bypassReason := panelaccess.ReadEffectiveFromDB(ctx, local.DB, cfg.HTTP)
	effectiveHTTP := cfg.HTTP
	effectiveHTTP.Listen = listenAddr
	effectiveHTTP.PanelDomain = panelDomain
	if *origin == "" {
		if panelDomain != "" && bypassReason != "" {
			*origin = "https://" + panelDomain
		} else {
			*origin = resolveSetupOrigin(effectiveHTTP)
		}
	}
	*origin = strings.TrimRight(*origin, "/")

	initialized, err := local.Identity.SetupInitialized(ctx)
	if err != nil {
		fmt.Fprintf(stderr, "qwq setup-token: %v\n", err)
		return 1
	}
	if initialized {
		fmt.Fprintln(stderr, "qwq setup-token: 已初始化；忘记密码请用 `sudo qwq recover`，查看或重置面板入口请用 `sudo qwq access show`")
		host, portStr, perr := net.SplitHostPort(listenAddr)
		if perr == nil {
			if p, aerr := strconv.Atoi(portStr); aerr == nil && p > 0 {
				fmt.Fprint(stderr, formatAccessHelp(host, p, rawEntryPath, panelDomain, cfg.HTTP.TLS.Mode))
			}
		}
		return exitInitialized
	}
	token, _, err := local.Identity.NewSetupToken(ctx)
	if err != nil {
		fmt.Fprintf(stderr, "qwq setup-token: %v\n", err)
		return 1
	}
	setupBase := *origin
	if effectiveEntryPath != "" {
		setupBase += "/" + effectiveEntryPath
	}
	fmt.Fprintln(stdout, "====================================================================")
	fmt.Fprintln(stdout, "  qwq 面板初始化信息（30 分钟内有效 · 仅用一次 · 重跑会作废旧令牌）")
	fmt.Fprintln(stdout, "====================================================================")
	fmt.Fprintf(stdout, "  初始化链接  ：%s/setup#token=%s\n", setupBase, token)
	fmt.Fprintf(stdout, "  初始化令牌  ：%s\n", token)
	if effectiveEntryPath != "" {
		fmt.Fprintf(stdout, "  面板安全密道：/%s（密道不对时自动触发无服务伪装）\n", effectiveEntryPath)
	}
	if cfg.HTTP.TLS.Mode == config.TLSSelfSigned {
		if fp, err := tlsmgr.SelfSignedFingerprint(cfg.DataDir); err == nil {
			fmt.Fprintf(stdout, "  证书指纹    ：SHA256:%s\n", fp)
		}
	}
	fmt.Fprintln(stdout, "====================================================================")
	return 0
}

// resolveSetupOrigin picks the most reachable browser origin when --origin is
// omitted: explicit PublicOrigins first, then a detected global host IP when
// listening on 0.0.0.0 / ::, falling back to defaultOrigin.
func resolveSetupOrigin(h config.HTTP) string {
	if len(h.PublicOrigins) > 0 {
		return h.PublicOrigins[0]
	}
	host, port, err := net.SplitHostPort(h.Listen)
	if err != nil {
		return defaultOrigin(h)
	}
	if ip := net.ParseIP(host); host == "" || (ip != nil && ip.IsUnspecified()) {
		if pub := detectLocalPublicIP(); pub != "" {
			return "https://" + net.JoinHostPort(pub, port)
		}
	}
	return defaultOrigin(h)
}

// detectLocalPublicIP inspects local outbound routes without network I/O to
// find a global non-private IPv4 (preferred) or IPv6 address on this host.
func detectLocalPublicIP() string {
	for _, probe := range []struct {
		network string
		target  string
	}{
		{"udp4", "1.1.1.1:80"},
		{"udp6", "[2606:4700:4700::1111]:80"},
	} {
		conn, err := net.DialTimeout(probe.network, probe.target, 200*time.Millisecond)
		if err != nil {
			continue
		}
		addr, _ := conn.LocalAddr().(*net.UDPAddr)
		_ = conn.Close()
		if addr == nil || addr.IP == nil {
			continue
		}
		if isPublicUnicastIP(addr.IP) {
			return addr.IP.String()
		}
	}
	return ""
}

func isPublicUnicastIP(ip net.IP) bool {
	if ip == nil || !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
		return false
	}
	if v4 := ip.To4(); v4 != nil {
		// Exclude CGNAT 100.64.0.0/10
		if v4[0] == 100 && v4[1] >= 64 && v4[1] <= 127 {
			return false
		}
	}
	return true
}

// defaultOrigin 由配置推导浏览器访问面板的 origin。监听在通配地址时
// 用回环地址（配合 SSH 隧道），运维人员可用 --origin 覆盖。
func defaultOrigin(h config.HTTP) string {
	if len(h.PublicOrigins) > 0 {
		return h.PublicOrigins[0]
	}
	host, port, err := net.SplitHostPort(h.Listen)
	if err != nil {
		return "https://" + h.Listen
	}
	if ip := net.ParseIP(host); host == "" || (ip != nil && ip.IsUnspecified()) {
		host = "127.0.0.1"
	}
	return "https://" + net.JoinHostPort(host, port)
}
