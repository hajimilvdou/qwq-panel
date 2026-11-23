// SPDX-License-Identifier: AGPL-3.0-only

// qwq-probe-standalone：脱离 qwq 面板的单二进制独立服务器探针主控程序。
// 接入真实 SQLite WAL 持久层、单向 Agent 遥测上报、公开脱敏快照与独立管理接口。

package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime/debug"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/crypto/acme/autocert"
	_ "modernc.org/sqlite"

	"github.com/qwq-panel/qwq/sdk/pluginsdk/sqlitedb"
)

const maxStandaloneBodyBytes = 256 << 10 // 256 KiB 硬请求体上限

type standaloneNode struct {
	ID            string  `json:"id"`
	Name          string  `json:"name"`
	RegionCode    string  `json:"region_code"`
	TokenSHA256   string  `json:"-"`
	CPUCores      int     `json:"cpu_cores"`
	CPUPercent    float64 `json:"cpu_pct"`
	MemTotal      uint64  `json:"mem_total"`
	MemUsed       uint64  `json:"mem_used"`
	DiskTotal     uint64  `json:"disk_total"`
	DiskUsed      uint64  `json:"disk_used"`
	NetRxBps      uint64  `json:"net_rx_bps"`
	NetTxBps      uint64  `json:"net_tx_bps"`
	Load1         float64 `json:"load1"`
	OSName        string  `json:"os_name"`
	KernelVersion string  `json:"kernel"`
	HasIPv4       bool    `json:"has_ipv4"`
	HasIPv6       bool    `json:"has_ipv6"`
	LastSeenAt    int64   `json:"last_seen_at"`
	Online        bool    `json:"online"`
}

type standaloneStore struct {
	mu       sync.RWMutex
	db       *sqlitedb.DualPool
	nodes    map[string]*standaloneNode
	sessions map[[32]byte]int64
	adminPwd string
}

const standaloneSchemaSQL = `
CREATE TABLE IF NOT EXISTS standalone_nodes (
	id TEXT PRIMARY KEY,
	name TEXT NOT NULL,
	region_code TEXT NOT NULL DEFAULT 'UN',
	token_sha256 TEXT NOT NULL,
	cpu_cores INTEGER NOT NULL DEFAULT 1,
	mem_total INTEGER NOT NULL DEFAULT 0,
	disk_total INTEGER NOT NULL DEFAULT 0,
	os_name TEXT NOT NULL DEFAULT '',
	kernel_version TEXT NOT NULL DEFAULT '',
	has_ipv4 INTEGER NOT NULL DEFAULT 0,
	has_ipv6 INTEGER NOT NULL DEFAULT 0,
	last_seen_at INTEGER NOT NULL DEFAULT 0
) STRICT;
`

func openStandaloneStore(dataDir, adminPass string) (*standaloneStore, error) {
	pool, err := sqlitedb.OpenDualSQLite("sqlite", filepath.Join(dataDir, "probe-standalone.db"), 4)
	if err != nil {
		return nil, err
	}
	if _, err := pool.Writer.Exec(standaloneSchemaSQL); err != nil {
		_ = pool.Close()
		return nil, err
	}
	st := &standaloneStore{
		db:       pool,
		nodes:    make(map[string]*standaloneNode),
		sessions: make(map[[32]byte]int64),
		adminPwd: strings.TrimSpace(adminPass),
	}
	rows, err := pool.Reader.Query(`SELECT id, name, region_code, token_sha256, cpu_cores, mem_total, disk_total, os_name, kernel_version, has_ipv4, has_ipv6, last_seen_at FROM standalone_nodes`)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var n standaloneNode
			var v4, v6 int
			var memT, diskT int64
			if rows.Scan(&n.ID, &n.Name, &n.RegionCode, &n.TokenSHA256, &n.CPUCores, &memT, &diskT, &n.OSName, &n.KernelVersion, &v4, &v6, &n.LastSeenAt) == nil {
				n.MemTotal = uint64(max(0, memT))
				n.DiskTotal = uint64(max(0, diskT))
				n.HasIPv4 = v4 != 0
				n.HasIPv6 = v6 != 0
				cp := n
				st.nodes[n.ID] = &cp
			}
		}
	}
	return st, nil
}

func (s *standaloneStore) close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

func (s *standaloneStore) verifyAdmin(token string, now time.Time) bool {
	if !strings.HasPrefix(token, "prb_adm_") {
		return false
	}
	sum := sha256.Sum256([]byte(token))
	s.mu.Lock()
	defer s.mu.Unlock()
	exp, ok := s.sessions[sum]
	if !ok || exp <= now.Unix() {
		delete(s.sessions, sum)
		return false
	}
	return true
}

func (s *standaloneStore) serveHTTP(w http.ResponseWriter, r *http.Request, normDomain string) {
	h := w.Header()
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Cache-Control", "no-store")
	h.Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'")

	reqHost := r.Host
	if sh, _, err := net.SplitHostPort(reqHost); err == nil {
		reqHost = sh
	}
	reqHost = strings.ToLower(strings.Trim(reqHost, "[]"))
	if normDomain != "" && reqHost != normDomain && reqHost != "127.0.0.1" && reqHost != "::1" && reqHost != "localhost" {
		writeStandaloneJSON(w, http.StatusMisdirectedRequest, map[string]any{"error": "HOST_NOT_BOUND"})
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, maxStandaloneBodyBytes+1))
	if err != nil || len(body) > maxStandaloneBodyBytes {
		writeStandaloneJSON(w, http.StatusRequestEntityTooLarge, map[string]any{"error": "PAYLOAD_TOO_LARGE"})
		return
	}
	now := time.Now()
	path := r.URL.Path

	switch {
	case path == "/api/probe/v1/report" && r.Method == http.MethodPost:
		s.handleReport(w, r, body, now)
	case path == "/api/public/snapshot" && r.Method == http.MethodGet:
		s.handleSnapshot(w, now)
	case path == "/api/admin/login" && r.Method == http.MethodPost:
		s.handleLogin(w, body, now)
	case path == "/api/admin/nodes" && r.Method == http.MethodPost:
		if !s.verifyAdmin(strings.TrimSpace(r.Header.Get("X-Probe-Admin-Token")), now) {
			writeStandaloneJSON(w, http.StatusUnauthorized, map[string]any{"error": "ADMIN_AUTH_REQUIRED"})
			return
		}
		s.handleCreateNode(w, r, body, normDomain)
	case strings.HasPrefix(path, "/api/admin/nodes/") && r.Method == http.MethodDelete:
		if !s.verifyAdmin(strings.TrimSpace(r.Header.Get("X-Probe-Admin-Token")), now) {
			writeStandaloneJSON(w, http.StatusUnauthorized, map[string]any{"error": "ADMIN_AUTH_REQUIRED"})
			return
		}
		id := strings.TrimPrefix(path, "/api/admin/nodes/")
		s.mu.Lock()
		delete(s.nodes, id)
		s.mu.Unlock()
		_, _ = s.db.Writer.ExecContext(r.Context(), `DELETE FROM standalone_nodes WHERE id = ?`, id)
		writeStandaloneJSON(w, http.StatusOK, map[string]any{"removed": id})
	default:
		s.handleSnapshot(w, now)
	}
}

func (s *standaloneStore) handleReport(w http.ResponseWriter, r *http.Request, body []byte, now time.Time) {
	bearer := strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
	var rep struct {
		NodeID        string  `json:"node_id"`
		CPUCores      int     `json:"cpu_cores"`
		CPUPercent    float64 `json:"cpu_pct"`
		MemTotal      uint64  `json:"mem_total"`
		MemUsed       uint64  `json:"mem_used"`
		DiskTotal     uint64  `json:"disk_total"`
		DiskUsed      uint64  `json:"disk_used"`
		NetRxBps      uint64  `json:"net_rx_bps"`
		NetTxBps      uint64  `json:"net_tx_bps"`
		Load1         float64 `json:"load1"`
		OSName        string  `json:"os_name"`
		KernelVersion string  `json:"kernel"`
		HasIPv4       bool    `json:"has_ipv4"`
		HasIPv6       bool    `json:"has_ipv6"`
	}
	if err := json.Unmarshal(body, &rep); err != nil || rep.NodeID == "" {
		writeStandaloneJSON(w, http.StatusBadRequest, map[string]any{"error": "INVALID_JSON"})
		return
	}
	sum := sha256.Sum256([]byte(bearer))
	gotHex := hex.EncodeToString(sum[:])

	s.mu.Lock()
	node, ok := s.nodes[rep.NodeID]
	if !ok || subtle.ConstantTimeCompare([]byte(gotHex), []byte(node.TokenSHA256)) != 1 {
		s.mu.Unlock()
		writeStandaloneJSON(w, http.StatusUnauthorized, map[string]any{"error": "UNAUTHORIZED_AGENT"})
		return
	}
	if rep.CPUCores > 0 {
		node.CPUCores = rep.CPUCores
	}
	node.CPUPercent = rep.CPUPercent
	node.MemTotal = rep.MemTotal
	node.MemUsed = rep.MemUsed
	node.DiskTotal = rep.DiskTotal
	node.DiskUsed = rep.DiskUsed
	node.NetRxBps = rep.NetRxBps
	node.NetTxBps = rep.NetTxBps
	node.Load1 = rep.Load1
	node.OSName = rep.OSName
	node.KernelVersion = rep.KernelVersion
	node.HasIPv4 = rep.HasIPv4
	node.HasIPv6 = rep.HasIPv6
	node.LastSeenAt = now.Unix()
	cp := *node
	s.mu.Unlock()

	v4, v6 := 0, 0
	if cp.HasIPv4 {
		v4 = 1
	}
	if cp.HasIPv6 {
		v6 = 1
	}
	_, _ = s.db.Writer.ExecContext(r.Context(), `
		UPDATE standalone_nodes SET cpu_cores=?, mem_total=?, disk_total=?, os_name=?, kernel_version=?, has_ipv4=?, has_ipv6=?, last_seen_at=? WHERE id=?`,
		cp.CPUCores, int64(cp.MemTotal), int64(cp.DiskTotal), cp.OSName, cp.KernelVersion, v4, v6, cp.LastSeenAt, cp.ID,
	)
	writeStandaloneJSON(w, http.StatusOK, map[string]any{
		"accepted":            true,
		"server_time_unix":    now.Unix(),
		"report_interval_sec": 2,
	})
}

func (s *standaloneStore) handleSnapshot(w http.ResponseWriter, now time.Time) {
	nowUnix := now.Unix()
	s.mu.RLock()
	nodes := make([]standaloneNode, 0, len(s.nodes))
	for _, n := range s.nodes {
		cp := *n
		cp.Online = cp.LastSeenAt > 0 && nowUnix-cp.LastSeenAt <= 15
		nodes = append(nodes, cp)
	}
	s.mu.RUnlock()
	slices.SortFunc(nodes, func(a, b standaloneNode) int { return strings.Compare(a.ID, b.ID) })
	writeStandaloneJSON(w, http.StatusOK, map[string]any{
		"mode":             "standalone",
		"server_time_unix": nowUnix,
		"nodes":            nodes,
	})
}

func (s *standaloneStore) handleLogin(w http.ResponseWriter, body []byte, now time.Time) {
	var req struct {
		Password string `json:"password"`
	}
	if err := json.Unmarshal(body, &req); err != nil || s.adminPwd == "" || subtle.ConstantTimeCompare([]byte(req.Password), []byte(s.adminPwd)) != 1 {
		writeStandaloneJSON(w, http.StatusUnauthorized, map[string]any{"error": "INVALID_CREDENTIALS"})
		return
	}
	buf := make([]byte, 24)
	if _, err := rand.Read(buf); err != nil {
		writeStandaloneJSON(w, http.StatusInternalServerError, map[string]any{"error": "SESSION_MINT_FAILED"})
		return
	}
	tok := "prb_adm_" + hex.EncodeToString(buf)
	sum := sha256.Sum256([]byte(tok))
	exp := now.Add(8 * time.Hour).Unix()
	s.mu.Lock()
	s.sessions[sum] = exp
	s.mu.Unlock()
	writeStandaloneJSON(w, http.StatusOK, map[string]any{"admin_token": tok, "expires_at": exp})
}

func (s *standaloneStore) handleCreateNode(w http.ResponseWriter, r *http.Request, body []byte, normDomain string) {
	var req struct {
		ID         string `json:"id"`
		Name       string `json:"name"`
		RegionCode string `json:"region_code"`
	}
	if err := json.Unmarshal(body, &req); err != nil || strings.TrimSpace(req.Name) == "" {
		writeStandaloneJSON(w, http.StatusBadRequest, map[string]any{"error": "VALIDATION_FAILED"})
		return
	}
	buf := make([]byte, 24)
	if _, err := rand.Read(buf); err != nil {
		writeStandaloneJSON(w, http.StatusInternalServerError, map[string]any{"error": "TOKEN_GEN_FAILED"})
		return
	}
	plainTok := "prb_agt_" + base64.RawURLEncoding.EncodeToString(buf)
	sum := sha256.Sum256([]byte(plainTok))
	shaHex := hex.EncodeToString(sum[:])

	id := strings.TrimSpace(req.ID)
	if id == "" {
		id = "node_" + hex.EncodeToString(buf[:4])
	}
	region := strings.ToUpper(strings.TrimSpace(req.RegionCode))
	if region == "" {
		region = "UN"
	}
	node := &standaloneNode{
		ID:          id,
		Name:        strings.TrimSpace(req.Name),
		RegionCode:  region,
		TokenSHA256: shaHex,
		CPUCores:    1,
	}
	s.mu.Lock()
	s.nodes[id] = node
	s.mu.Unlock()

	_, _ = s.db.Writer.ExecContext(r.Context(), `
		INSERT INTO standalone_nodes (id, name, region_code, token_sha256, cpu_cores)
		VALUES (?, ?, ?, ?, 1)
		ON CONFLICT(id) DO UPDATE SET name=excluded.name, region_code=excluded.region_code`,
		node.ID, node.Name, node.RegionCode, node.TokenSHA256,
	)
	endpoint := "/api/probe/v1/report"
	if normDomain != "" {
		endpoint = fmt.Sprintf("https://%s/api/probe/v1/report", normDomain)
	} else if r.Host != "" {
		scheme := "http"
		if r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https") {
			scheme = "https"
		}
		endpoint = fmt.Sprintf("%s://%s/api/probe/v1/report", scheme, r.Host)
	}
	writeStandaloneJSON(w, http.StatusCreated, map[string]any{
		"node_id":         id,
		"one_time_token":  plainTok,
		"report_endpoint": endpoint,
	})
}

func writeStandaloneJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

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

	store, err := openStandaloneStore(*dataDir, adminPass)
	if err != nil {
		log.Error("failed to open standalone probe store", "err", err)
		os.Exit(1)
	}
	defer func() { _ = store.close() }()

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = io.WriteString(w, `{"ok":true,"mode":"standalone"}`)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		store.serveHTTP(w, r, normDomain)
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
