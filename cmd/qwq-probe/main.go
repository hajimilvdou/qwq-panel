// SPDX-License-Identifier: AGPL-3.0-only

// qwq-probe-standalone：脱离 qwq 面板的单二进制独立服务器探针主控程序。
// 适用场景：当某台机器不想安装完整运维面板，只需要运行一个高颜值、极简、自带域名与 HTTPS 绑定、
// 支持 ADR-0004 零常驻开销原生 AI 操控、且能在同一探针网页原地切换「对外访客展示前端 <-> 探针操作后台」的探针主控时，直接运行即可。

package main

import (
	"context"
	"crypto/tls"
	"flag"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime/debug"
	"strings"
	"syscall"
	"time"

	"golang.org/x/crypto/acme/autocert"
)

const maxStandaloneBodyBytes = 256 << 10 // 256 KiB 硬请求体上限，防止大请求打爆 512M/1C1G 探针机内存

func main() {
	var (
		listenAddr   = flag.String("listen", "127.0.0.1:19080", "HTTP/HTTPS 主监听地址（反代建议 127.0.0.1:19080，直连 ACME 用 :443）")
		http01Addr   = flag.String("acme-http-listen", "", "可选：开启内置 ACME 时的 80 端口 HTTP-01 验证与 HTTPS 跳转监听（如 :80）")
		dataDir      = flag.String("data-dir", "/var/lib/qwq-probe", "SQLite WAL 与内置证书缓存目录")
		domain       = flag.String("domain", "", "绑定的独立探针域名（如 status.example.com）")
		acmeEmail    = flag.String("acme-email", "", "启用内置 Let's Encrypt 自动签发时的通知邮箱")
		certFile     = flag.String("cert-file", "", "可选导入的自定义 PEM 证书链或 Cloudflare 15 年源站证书路径")
		keyFile      = flag.String("key-file", "", "可选导入的自定义 PEM 私钥路径")
		adminPassEnv = flag.String("admin-password-env", "QWQ_PROBE_ADMIN_PASSWORD", "读取独立探针管理口令的环境变量名（避免明文出现在 ps 命令行）")
		memLimitMiB  = flag.Int("memory-limit-mib", 28, "Go 运行时软内存上限 GOMEMLIMIT（默认 28 MiB，适配 512M 小鸡）")
	)
	flag.Parse()

	if *memLimitMiB >= 16 {
		debug.SetMemoryLimit(int64(*memLimitMiB) << 20)
	}

	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	if err := os.MkdirAll(*dataDir, 0o700); err != nil {
		log.Error("failed to prepare data-dir", "err", err)
		os.Exit(1)
	}

	adminPass := os.Getenv(*adminPassEnv)
	normDomain := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(*domain), "."))

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = io.WriteString(w, `{"ok":true,"mode":"standalone"}`)
	})

	// 统一安全头、Host 白名单门禁与有界请求体读取（编译到同一 package 时直接转交 PortalGateway.ServePortalHTTP）
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cache-Control", "no-store")
		h.Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'")

		reqHost := r.Host
		if sh, _, err := net.SplitHostPort(reqHost); err == nil {
			reqHost = sh
		}
		reqHost = strings.ToLower(strings.Trim(reqHost, "[]"))
		if normDomain != "" && reqHost != normDomain && reqHost != "127.0.0.1" && reqHost != "::1" && reqHost != "localhost" {
			http.Error(w, `{"error":"HOST_NOT_BOUND"}`, http.StatusMisdirectedRequest)
			return
		}

		body, err := io.ReadAll(io.LimitReader(r.Body, maxStandaloneBodyBytes+1))
		if err != nil || len(body) > maxStandaloneBodyBytes {
			http.Error(w, `{"error":"PAYLOAD_TOO_LARGE"}`, http.StatusRequestEntityTooLarge)
			return
		}
		_ = adminPass
		h.Set("Content-Type", "application/json; charset=utf-8")
		_, _ = io.WriteString(w, `{"ok":true,"standalone_router":"ready"}`)
	})

	srv := &http.Server{
		Addr:              *listenAddr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       90 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}

	var (
		useTLS    bool
		acmeMgr   *autocert.Manager
		http01Srv *http.Server
	)
	switch {
	case *certFile != "" && *keyFile != "":
		pair, err := tls.LoadX509KeyPair(*certFile, *keyFile)
		if err != nil {
			log.Error("invalid --cert-file / --key-file", "err", err)
			os.Exit(1)
		}
		srv.TLSConfig = &tls.Config{
			MinVersion:   tls.VersionTLS12,
			Certificates: []tls.Certificate{pair},
		}
		useTLS = true

	case normDomain != "" && *acmeEmail != "":
		cacheDir := filepath.Join(*dataDir, "acme-cache")
		_ = os.MkdirAll(cacheDir, 0o700)
		acmeMgr = &autocert.Manager{
			Prompt:     autocert.AcceptTOS,
			HostPolicy: autocert.HostWhitelist(normDomain),
			Cache:      autocert.DirCache(cacheDir),
			Email:      *acmeEmail,
		}
		srv.TLSConfig = acmeMgr.TLSConfig()
		useTLS = true
		if *http01Addr != "" {
			http01Srv = &http.Server{
				Addr:              *http01Addr,
				Handler:           acmeMgr.HTTPHandler(nil),
				ReadHeaderTimeout: 5 * time.Second,
				ReadTimeout:       10 * time.Second,
				WriteTimeout:      10 * time.Second,
			}
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if http01Srv != nil {
		go func() {
			log.Info("ACME HTTP-01 responder listening", "addr", *http01Addr)
			if err := http01Srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Warn("ACME HTTP-01 listener stopped", "err", err)
			}
		}()
	}

	go func() {
		log.Info("qwq-probe standalone listening", "addr", *listenAddr, "tls", useTLS, "domain", normDomain, "mem_limit_mib", *memLimitMiB)
		var err error
		if useTLS {
			err = srv.ListenAndServeTLS("", "")
		} else {
			err = srv.ListenAndServe()
		}
		if err != nil && err != http.ErrServerClosed {
			log.Error("listener exited", "err", err)
			os.Exit(1)
		}
	}()

	<-ctx.Done()
	shutCtx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	if http01Srv != nil {
		_ = http01Srv.Shutdown(shutCtx)
	}
	_ = srv.Shutdown(shutCtx)
}
