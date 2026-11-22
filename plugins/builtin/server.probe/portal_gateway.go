// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io/fs"
	"net/http"
	"strings"
	"sync"
	"time"
)

//go:embed portal_ui/*
var embeddedPortalFS embed.FS

// PortalGateway 同时处理：
// 1. 宿主公开路由 /p/server.probe/portal/* 与独立绑定域名根路径 /（访客展示前端 + 独立探针后台原地切换）；
// 2. 宿主公开路由 /p/server.probe/agent/* 与 /api/probe/v1/report（外部小鸡单向零指令上报）。
//
// 安全隔离：
// - 独立探针后台使用专属令牌头 X-Probe-Admin-Token: prb_adm_*（永不读写宿主 Cookie，永不共享宿主会话）；
// - 登录校验具备 2 槽并发限制（保护 1C1G CPU）与按 IP 失败渐进冷却。
type PortalGateway struct {
	store            *ProbeStore
	domains          *DomainBindingCoordinator
	ai               *AINativeController
	adminSalt        [16]byte
	adminSecretKey   [32]byte
	hasAdminPassword bool
	signingSecret    [32]byte
	hashSlots        chan struct{}
	mu               sync.Mutex
	adminSessions    map[string]int64 // tokenSHA -> expiresUnix (硬上限 256)
	failedLoginsByIP map[string]loginAttempt
	now              func() time.Time
}

type loginAttempt struct {
	fails      int
	lockedTill int64
}

// stretchAdminPassword 使用 64,000 轮带独立随机盐的 HMAC-SHA256 密钥拉伸（零外部依赖，配合 2 槽信号量兼顾抗爆破与 1C1G CPU 预算）。
func stretchAdminPassword(salt [16]byte, password string) [32]byte {
	mac := hmac.New(sha256.New, salt[:])
	_, _ = mac.Write([]byte("qwq-probe-adm-kdf-v1:" + password))
	cur := mac.Sum(nil)
	for i := 0; i < 64000; i++ {
		mac.Reset()
		_, _ = mac.Write(cur)
		cur = mac.Sum(cur[:0])
	}
	var out [32]byte
	copy(out[:], cur)
	return out
}

func NewPortalGateway(store *ProbeStore, domains *DomainBindingCoordinator, ai *AINativeController, initialAdminPassword string, now func() time.Time) *PortalGateway {
	if now == nil {
		now = time.Now
	}
	if ai == nil {
		ai = NewAINativeController(store, domains)
	}
	var (
		secret [32]byte
		salt   [16]byte
		key    [32]byte
	)
	_, _ = rand.Read(secret[:])
	_, _ = rand.Read(salt[:])

	hasPW := initialAdminPassword != ""
	if hasPW {
		key = stretchAdminPassword(salt, initialAdminPassword)
	}
	return &PortalGateway{
		store:            store,
		domains:          domains,
		ai:               ai,
		adminSalt:        salt,
		adminSecretKey:   key,
		hasAdminPassword: hasPW,
		signingSecret:    secret,
		hashSlots:        make(chan struct{}, 2), // 1C1G 保护：最多 2 个并发拉伸校验
		adminSessions:    make(map[string]int64),
		failedLoginsByIP: make(map[string]loginAttempt),
		now:              now,
	}
}

// ServePortalHTTP 处理独立探针页（公开展示 + 独立管理 API）与 Agent 单向上报。
func (g *PortalGateway) ServePortalHTTP(route, method, subpath, clientIP string, headers map[string]string, body []byte) (status int, respHeaders map[string]string, respBody []byte) {
	now := g.now()
	cleanSub := "/" + strings.TrimPrefix(subpath, "/")

	// 通道 1：外部小鸡单向零指令上报端点
	if route == "agent" || cleanSub == "/api/probe/v1/report" || cleanSub == "/v1/report" {
		if method != http.MethodPost {
			return jsonResp(http.StatusMethodNotAllowed, map[string]any{"error": "METHOD_NOT_ALLOWED"})
		}
		bearer := extractHeaderCI(headers, "Authorization")
		bearer = strings.TrimSpace(strings.TrimPrefix(bearer, "Bearer "))
		var payload AgentReportPayload
		if err := json.Unmarshal(body, &payload); err != nil {
			return jsonResp(http.StatusBadRequest, map[string]any{"error": "INVALID_JSON"})
		}
		pullCfg, err := g.store.IngestAgentReport(now, clientIP, bearer, payload)
		if err != nil {
			return jsonResp(http.StatusUnauthorized, map[string]any{"error": err.Error()})
		}
		return jsonResp(http.StatusOK, pullCfg)
	}

	// 通道 2：公开脱敏快照 API（若开启了私有探针访客口令则校验 X-Probe-Visitor-Token）
	if cleanSub == "/api/public/snapshot" && method == http.MethodGet {
		g.store.mu.RLock()
		visHash := g.store.settings.VisitorPasswordSHA256
		cfg := g.store.settings
		mons := make([]ServiceMonitor, 0, len(g.store.monitors))
		for _, m := range g.store.monitors {
			if m.PublicVisible {
				mons = append(mons, *m)
			}
		}
		g.store.mu.RUnlock()

		if visHash != "" && !g.verifyVisitorToken(extractHeaderCI(headers, "X-Probe-Visitor-Token"), now) &&
			!g.verifyAdminToken(extractHeaderCI(headers, "X-Probe-Admin-Token"), now) {
			return jsonResp(http.StatusLocked, map[string]any{
				"locked":     true,
				"site_title": cfg.SiteTitle,
				"message":    "当前探针已启用私有访问保护，请输入访客查看口令",
			})
		}

		return jsonResp(http.StatusOK, map[string]any{
			"server_time_unix": now.Unix(),
			"site_title":       cfg.SiteTitle,
			"site_subtitle":    cfg.SiteSubtitle,
			"default_view":     cfg.DefaultView,
			"default_palette":  cfg.DefaultPalette,
			"allow_theme":      cfg.AllowVisitorThemeSwitch,
			"banner_level":     cfg.StatusBannerLevel,
			"banner_text":      cfg.StatusBannerText,
			"nodes":            g.store.BuildPublicNodes(now),
			"service_monitors": mons,
		})
	}

	// 通道 3：私有探针访客口令解锁
	if cleanSub == "/api/public/unlock" && method == http.MethodPost {
		var req struct {
			Password string `json:"password"`
		}
		if err := json.Unmarshal(body, &req); err != nil {
			return jsonResp(http.StatusBadRequest, map[string]any{"error": "INVALID_JSON"})
		}
		g.store.mu.RLock()
		visHash := g.store.settings.VisitorPasswordSHA256
		g.store.mu.RUnlock()
		sum := sha256.Sum256([]byte("qwq-probe-vis-v1:" + req.Password))
		if visHash == "" || subtle.ConstantTimeCompare([]byte(hex.EncodeToString(sum[:])), []byte(visHash)) != 1 {
			return jsonResp(http.StatusUnauthorized, map[string]any{"error": "VISITOR_PASSWORD_INCORRECT"})
		}
		return jsonResp(http.StatusOK, map[string]any{"visitor_token": g.mintVisitorToken(now)})
	}

	// 通道 4：独立探针页管理员原地登录（签发独立 prb_adm_* 会话，供「只安装探针」直接切换前后台！）
	if cleanSub == "/api/admin/login" && method == http.MethodPost {
		return g.handleStandaloneAdminLogin(now, clientIP, body)
	}

	// 通道 4.5：独立探针模式下的 ADR-0004 原生 AI 操控面（接受真人 prb_adm_* 或受限委托令牌 prb_dlg_*）
	if strings.HasPrefix(cleanSub, "/api/ai/v1/") {
		return g.handleStandaloneAINative(now, method, cleanSub, headers, body)
	}

	// 通道 5：受 prb_adm_* 保护的独立探针管理 API（节点增删、一键安装脚本生成、隐私与双轨域名绑定）
	if strings.HasPrefix(cleanSub, "/api/admin/") {
		if !g.verifyAdminToken(extractHeaderCI(headers, "X-Probe-Admin-Token"), now) {
			return jsonResp(http.StatusUnauthorized, map[string]any{"error": "ADMIN_AUTH_REQUIRED"})
		}
		return g.handleStandaloneAdminAction(now, method, cleanSub, body)
	}

	// 通道 6：静态门户 SPA 资源（index.html / portal.css / portal.js）
	return serveEmbeddedPortalAsset(cleanSub)
}

func (g *PortalGateway) handleStandaloneAdminLogin(now time.Time, clientIP string, body []byte) (int, map[string]string, []byte) {
	nowUnix := now.Unix()
	g.mu.Lock()
	att := g.failedLoginsByIP[clientIP]
	if att.lockedTill > nowUnix {
		g.mu.Unlock()
		return jsonResp(http.StatusTooManyRequests, map[string]any{
			"error":               "TOO_MANY_ATTEMPTS",
			"retry_after_seconds": att.lockedTill - nowUnix,
		})
	}
	g.mu.Unlock()

	select {
	case g.hashSlots <- struct{}{}:
		defer func() { <-g.hashSlots }()
	default:
		return jsonResp(http.StatusServiceUnavailable, map[string]any{"error": "AUTH_BUSY"})
	}

	var req struct {
		Password string `json:"password"`
	}
	if err := json.Unmarshal(body, &req); err != nil || !g.hasAdminPassword || len(req.Password) > 256 {
		return jsonResp(http.StatusUnauthorized, map[string]any{"error": "INVALID_CREDENTIALS"})
	}
	cand := stretchAdminPassword(g.adminSalt, req.Password)
	ok := subtle.ConstantTimeCompare(cand[:], g.adminSecretKey[:]) == 1

	g.mu.Lock()
	defer g.mu.Unlock()
	// 硬上限防伪造源 IP 撑爆内存（512M/1C1G 保护）
	if len(g.failedLoginsByIP) >= 2048 {
		clear(g.failedLoginsByIP)
	}
	if !ok {
		att.fails++
		if att.fails >= 5 {
			att.lockedTill = nowUnix + int64(min(900, 30*(1<<min(4, att.fails-5))))
		}
		g.failedLoginsByIP[clientIP] = att
		return jsonResp(http.StatusUnauthorized, map[string]any{"error": "INVALID_CREDENTIALS"})
	}
	delete(g.failedLoginsByIP, clientIP)

	if len(g.adminSessions) >= 256 {
		for k, exp := range g.adminSessions {
			if exp <= nowUnix {
				delete(g.adminSessions, k)
			}
		}
		if len(g.adminSessions) >= 256 {
			clear(g.adminSessions)
		}
	}
	raw := make([]byte, 24)
	_, _ = rand.Read(raw)
	plain := "prb_adm_" + base64.RawURLEncoding.EncodeToString(raw)
	tokenSum := sha256.Sum256([]byte(plain))
	exp := nowUnix + int64((8 * time.Hour).Seconds())
	g.adminSessions[hex.EncodeToString(tokenSum[:])] = exp

	return jsonResp(http.StatusOK, map[string]any{
		"admin_token": plain,
		"expires_at":  exp,
	})
}

func (g *PortalGateway) handleStandaloneAINative(now time.Time, method, path string, headers map[string]string, body []byte) (int, map[string]string, []byte) {
	admTok := extractHeaderCI(headers, "X-Probe-Admin-Token")
	dlgBearer := strings.TrimSpace(strings.TrimPrefix(extractHeaderCI(headers, "Authorization"), "Bearer "))

	isHumanAdmin := g.verifyAdminToken(admTok, now)
	dlg, isDelegatedAI := g.ai.VerifyDelegation(now, dlgBearer)
	if !isHumanAdmin && !isDelegatedAI {
		return jsonResp(http.StatusUnauthorized, map[string]any{"error": "AI_OR_ADMIN_CREDENTIAL_REQUIRED"})
	}

	switch {
	case path == "/api/ai/v1/actions" && method == http.MethodGet:
		return jsonResp(http.StatusOK, map[string]any{
			"actions": []map[string]any{
				{"id": "probe.ai.digest", "effect": "read", "risk": "low", "summary": "读取 <2KiB 异常优先全景摘要"},
				{"id": "probe.settings.update", "effect": "write", "risk": "medium", "plannable": true, "undo": "probe.settings.rollback"},
				{"id": "probe.nodes.upsert", "effect": "write", "risk": "medium", "plannable": true},
				{"id": "probe.domain.bind", "effect": "write", "risk": "high", "plannable": true},
			},
		})

	case path == "/api/ai/v1/digest" && method == http.MethodGet:
		return jsonResp(http.StatusOK, g.ai.BuildCompactDigest(now))

	case path == "/api/ai/v1/plan/settings" && method == http.MethodPost:
		// read_only 委托模式禁止创建写变更计划
		if isDelegatedAI && !isHumanAdmin && dlg.Mode == AIModeReadOnly {
			return jsonResp(http.StatusForbidden, map[string]any{"error": ErrDelegationModeDenied.Error()})
		}
		var patch PortalSettingsPatch
		if err := json.Unmarshal(body, &patch); err != nil {
			return jsonResp(http.StatusBadRequest, map[string]any{"error": "INVALID_JSON"})
		}
		actorLabel := "human-admin"
		if isDelegatedAI {
			actorLabel = "ai_agent:" + dlg.Label + " (" + string(dlg.Mode) + ")"
		}
		plan, err := g.ai.CreateSettingsPlan(now, actorLabel, patch)
		if err != nil {
			return jsonResp(http.StatusUnprocessableEntity, map[string]any{"error": err.Error()})
		}
		return jsonResp(http.StatusOK, plan)

	case path == "/api/ai/v1/approve" && method == http.MethodPost:
		// ADR-0004 D6 硬性安全边界：AI 委托令牌调用批准接口一律 403 拒绝！必须由真人会话批准！
		if !isHumanAdmin {
			return jsonResp(http.StatusForbidden, map[string]any{"error": ErrDelegationCannotAppr.Error()})
		}
		var req struct {
			PlanID string `json:"plan_id"`
		}
		if err := json.Unmarshal(body, &req); err != nil {
			return jsonResp(http.StatusBadRequest, map[string]any{"error": "INVALID_JSON"})
		}
		updated, err := g.ai.ApproveAndExecuteSettingsPlan(now, admTok, req.PlanID)
		if err != nil {
			code := http.StatusConflict
			return jsonResp(code, map[string]any{"error": err.Error()})
		}
		return jsonResp(http.StatusOK, updated)
	}
	return jsonResp(http.StatusNotFound, map[string]any{"error": "UNKNOWN_AI_ENDPOINT"})
}

func (g *PortalGateway) handleStandaloneAdminAction(now time.Time, method, path string, body []byte) (int, map[string]string, []byte) {
	switch {
	case path == "/api/admin/state" && method == http.MethodGet:
		g.store.mu.RLock()
		nodes := make([]NodeRecord, 0, len(g.store.nodes))
		for _, n := range g.store.nodes {
			cp := *n
			cp.AgentTokenSHA256 = "" // 绝不导出令牌哈希
			nodes = append(nodes, cp)
		}
		cfg := g.store.settings
		g.store.mu.RUnlock()
		return jsonResp(http.StatusOK, map[string]any{
			"nodes":            nodes,
			"settings":         cfg,
			"dnc_capabilities": g.domains.InspectEnvironment(),
			"proxy_snippets":   BuildReverseProxySnippets(cfg.CustomDomain, cfg.BuiltinListenAddr),
		})

	case path == "/api/admin/nodes" && method == http.MethodPost:
		var req struct {
			ID         string    `json:"id"`
			Name       string    `json:"name"`
			RegionCode string    `json:"region_code"`
			GroupName  string    `json:"group_name"`
			QuotaBytes uint64    `json:"quota_bytes"`
			QuotaMode  QuotaMode `json:"quota_mode"`
			ResetDay   int       `json:"reset_day"`
		}
		if err := json.Unmarshal(body, &req); err != nil || strings.TrimSpace(req.Name) == "" {
			return jsonResp(http.StatusBadRequest, map[string]any{"error": "VALIDATION_FAILED"})
		}
		plainTok, shaHex, prefix, err := GenerateAgentToken()
		if err != nil {
			return jsonResp(http.StatusInternalServerError, map[string]any{"error": "TOKEN_GEN_FAILED"})
		}
		id := strings.TrimSpace(req.ID)
		if id == "" {
			id = "node_" + strings.ToLower(hex.EncodeToString([]byte(plainTok[8:14])))
		}
		if !isValidNodeID(id) {
			return jsonResp(http.StatusBadRequest, map[string]any{"error": "INVALID_NODE_ID"})
		}
		if req.ResetDay < 1 || req.ResetDay > 31 {
			req.ResetDay = 1
		}
		if req.QuotaMode == "" {
			req.QuotaMode = QuotaBoth
		}
		g.store.mu.Lock()
		if _, exists := g.store.nodes[id]; !exists && len(g.store.nodes) >= 512 {
			g.store.mu.Unlock()
			return jsonResp(http.StatusUnprocessableEntity, map[string]any{"error": "NODE_LIMIT_EXCEEDED"})
		}
		g.store.nodes[id] = &NodeRecord{
			ID:               id,
			Name:             truncateSafe(req.Name, 64),
			RegionCode:       truncateSafe(strings.ToUpper(req.RegionCode), 8),
			GroupName:        truncateSafe(req.GroupName, 32),
			AgentTokenSHA256: shaHex,
			AgentTokenPrefix: prefix,
			ReportInterval:   2,
			QuotaBytes:       req.QuotaBytes,
			QuotaMode:        req.QuotaMode,
			ResetDay:         req.ResetDay,
			OnlineState:      "pending",
			Revision:         "r1",
		}
		dom := g.store.settings.CustomDomain
		g.store.mu.Unlock()

		endpoint := "/p/server.probe/agent/v1/report"
		if dom != "" {
			endpoint = "https://" + dom + "/api/probe/v1/report"
		}
		return jsonResp(http.StatusCreated, map[string]any{
			"node_id":         id,
			"one_time_token":  plainTok,
			"report_endpoint": endpoint,
			"linux_install":   BuildAgentInstallCommand("linux", endpoint, id, plainTok),
		})

	case path == "/api/admin/domain/bind" && method == http.MethodPost:
		var req struct {
			CustomDomain       string `json:"custom_domain"`
			BindingTrack       string `json:"binding_track"`
			PanelCertRef       string `json:"panel_cert_binding_ref"`
			ACMEEmail          string `json:"acme_email"`
			CertPEM            string `json:"cert_pem"`
			KeyPEM             string `json:"key_pem"`
			TrustCloudflareIPs bool   `json:"trust_cloudflare_ips"`
		}
		if err := json.Unmarshal(body, &req); err != nil {
			return jsonResp(http.StatusBadRequest, map[string]any{"error": "INVALID_JSON"})
		}
		g.store.mu.Lock()
		candidate := g.store.settings
		candidate.DomainEnabled = true
		candidate.CustomDomain = req.CustomDomain
		candidate.BindingTrack = req.BindingTrack
		candidate.PanelCertBindingRef = req.PanelCertRef
		candidate.BuiltinACMEEmail = req.ACMEEmail
		candidate.TrustCloudflareIPs = req.TrustCloudflareIPs
		summary, err := g.domains.ValidateAndApply(now, &candidate, []byte(req.CertPEM), []byte(req.KeyPEM))
		if err != nil {
			g.store.mu.Unlock()
			return jsonResp(http.StatusUnprocessableEntity, map[string]any{"error": err.Error()})
		}
		g.store.settings = candidate
		g.store.mu.Unlock()
		return jsonResp(http.StatusOK, map[string]any{
			"bound":          summary,
			"proxy_snippets": BuildReverseProxySnippets(candidate.CustomDomain, candidate.BuiltinListenAddr),
		})
	}
	return jsonResp(http.StatusNotFound, map[string]any{"error": "UNKNOWN_ADMIN_ENDPOINT"})
}

// BuildAgentInstallCommand 拼装单向安全探针 Agent 一键部署命令（带严格单引号转义防 Shell/PowerShell 注入）。
func BuildAgentInstallCommand(platform, reportURL, nodeID, token string) string {
	if platform == "windows" {
		psEsc := func(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }
		return "irm https://get.qwq.panel/probe-agent.ps1 | iex; Install-QwqProbeAgent -Endpoint " + psEsc(reportURL) + " -Node " + psEsc(nodeID) + " -Token " + psEsc(token)
	}
	shEsc := func(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }
	return "curl -fsSL https://get.qwq.panel/install-probe-agent.sh | sudo bash -s -- --endpoint " + shEsc(reportURL) + " --node " + shEsc(nodeID) + " --token " + shEsc(token)
}

func isValidNodeID(id string) bool {
	if len(id) < 1 || len(id) > 48 {
		return false
	}
	for idx := 0; idx < len(id); idx++ {
		c := id[idx]
		isAlnum := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
		if idx == 0 && !isAlnum {
			return false
		}
		if !isAlnum && c != '.' && c != '_' && c != '-' {
			return false
		}
	}
	return true
}

func (g *PortalGateway) verifyAdminToken(raw string, now time.Time) bool {
	tok := strings.TrimSpace(raw)
	if !strings.HasPrefix(tok, "prb_adm_") {
		return false
	}
	sum := sha256.Sum256([]byte(tok))
	key := hex.EncodeToString(sum[:])

	g.mu.Lock()
	defer g.mu.Unlock()
	exp, ok := g.adminSessions[key]
	if !ok {
		return false
	}
	if exp <= now.Unix() {
		delete(g.adminSessions, key)
		return false
	}
	return true
}

func (g *PortalGateway) mintVisitorToken(now time.Time) string {
	exp := now.Add(24 * time.Hour).Unix()
	payload := base64.RawURLEncoding.EncodeToString([]byte(time.Unix(exp, 0).UTC().Format(time.RFC3339)))
	mac := hmac.New(sha256.New, g.signingSecret[:])
	_, _ = mac.Write([]byte("vis:" + payload))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return "prb_vis_" + payload + "." + sig
}

func (g *PortalGateway) verifyVisitorToken(tok string, now time.Time) bool {
	trimmed, ok := strings.CutPrefix(strings.TrimSpace(tok), "prb_vis_")
	if !ok {
		return false
	}
	payload, sig, ok := strings.Cut(trimmed, ".")
	if !ok {
		return false
	}
	mac := hmac.New(sha256.New, g.signingSecret[:])
	_, _ = mac.Write([]byte("vis:" + payload))
	want := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	if subtle.ConstantTimeCompare([]byte(sig), []byte(want)) != 1 {
		return false
	}
	rawTime, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		return false
	}
	t, err := time.Parse(time.RFC3339, string(rawTime))
	return err == nil && now.Before(t)
}

func serveEmbeddedPortalAsset(cleanSub string) (int, map[string]string, []byte) {
	rel := strings.TrimPrefix(cleanSub, "/")
	if strings.Contains(rel, "..") || strings.Contains(rel, "/") || strings.Contains(rel, "\\") {
		rel = "index.html"
	}
	if rel == "" || !strings.Contains(rel, ".") {
		rel = "index.html"
	}
	data, err := fs.ReadFile(embeddedPortalFS, "portal_ui/"+rel)
	if err != nil {
		return jsonResp(http.StatusNotFound, map[string]any{"error": "ASSET_NOT_FOUND"})
	}
	ctype := "text/html; charset=utf-8"
	switch {
	case strings.HasSuffix(rel, ".css"):
		ctype = "text/css; charset=utf-8"
	case strings.HasSuffix(rel, ".js"):
		ctype = "application/javascript; charset=utf-8"
	}
	return http.StatusOK, map[string]string{"Content-Type": ctype}, data
}

func extractHeaderCI(headers map[string]string, want string) string {
	for k, v := range headers {
		if strings.EqualFold(k, want) {
			return v
		}
	}
	return ""
}

func jsonResp(code int, v any) (int, map[string]string, []byte) {
	b, _ := json.Marshal(v)
	return code, map[string]string{"Content-Type": "application/json; charset=utf-8"}, b
}
