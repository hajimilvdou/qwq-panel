// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"html"
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
	store         *ProbeStore
	domains       *DomainBindingCoordinator
	ai            *AINativeController
	themes        *ThemeManager
	authGuard     *BoundedAuthGuard
	signingSecret [32]byte
	hashSlots     chan struct{}
	mu            sync.Mutex
	adminVerifier string
	now           func() time.Time
}

func NewPortalGateway(store *ProbeStore, domains *DomainBindingCoordinator, ai *AINativeController, initialAdminPassword string, now func() time.Time) *PortalGateway {
	if now == nil {
		now = time.Now
	}
	if ai == nil {
		ai = NewAINativeController(store, domains)
	}
	var secret [32]byte
	_, _ = rand.Read(secret[:])

	dataDir := ""
	verifier := ""
	if store != nil {
		dataDir = store.dataDir
		store.mu.RLock()
		verifier = strings.TrimSpace(store.settings.StandaloneAdminVerifier)
		store.mu.RUnlock()
	}
	if initialAdminPassword != "" {
		if v, err := encodeAdminVerifierRaw(initialAdminPassword); err == nil {
			verifier = v
		}
	}
	return &PortalGateway{
		store:         store,
		domains:       domains,
		ai:            ai,
		themes:        NewThemeManager(dataDir),
		authGuard:     NewBoundedAuthGuard(),
		signingSecret: secret,
		hashSlots:     make(chan struct{}, 2), // 1C1G 保护：最多 2 个并发拉伸校验
		adminVerifier: verifier,
		now:           now,
	}
}

func (g *PortalGateway) SetAdminVerifier(verifier string) {
	if g == nil {
		return
	}
	g.mu.Lock()
	g.adminVerifier = strings.TrimSpace(verifier)
	g.mu.Unlock()
}

func (g *PortalGateway) Close() error {
	if g == nil || g.themes == nil {
		return nil
	}
	return g.themes.Close()
}

// ServePortalHTTP 处理独立探针页（公开展示 + 严格隔离的 /admin 后台 + 管理 API）与 Agent 单向上报。
func (g *PortalGateway) ServePortalHTTP(route, method, subpath, clientIP string, headers map[string]string, body []byte) (status int, respHeaders map[string]string, respBody []byte) {
	now := g.now()
	if q := strings.IndexByte(subpath, '?'); q >= 0 {
		subpath = subpath[:q]
	}
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

		activeTheme := cfg.ActiveThemeID
		if activeTheme == "" {
			activeTheme = BuiltinThemeClassic
		}
		themeSettings := cfg.ThemeSettings
		if themeSettings == nil {
			themeSettings = map[string]any{}
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
			"active_theme":     activeTheme,
			"appearance":       SanitizeAppearanceConfig(cfg.Appearance),
			"theme_settings":   themeSettings,
			"bg_url":           BackgroundURL(cfg),
			"admin_path":       "./admin",
			"nodes":            g.store.BuildPublicNodes(now),
			"service_monitors": mons,
		})
	}

	// 通道 2.5：公开本地高清壁纸静态输出（严格按魔数验证后的扩展名输出，附带缓存与 nosniff）
	if cleanSub == "/api/public/bg" && (method == http.MethodGet || method == http.MethodHead) {
		g.store.mu.RLock()
		bg := g.store.settings.Appearance.Background
		g.store.mu.RUnlock()
		if bg.Mode != "local" || bg.LocalFile == "" {
			return jsonResp(http.StatusNotFound, map[string]any{"error": "BACKGROUND_NOT_FOUND"})
		}
		data, mimeType, etag, err := g.themes.ReadBackground(bg.LocalFile)
		if err != nil {
			return jsonResp(http.StatusNotFound, map[string]any{"error": "BACKGROUND_NOT_FOUND"})
		}
		return http.StatusOK, map[string]string{
			"Content-Type":           mimeType,
			"X-Content-Type-Options": "nosniff",
			"Cache-Control":          "public, max-age=3600",
			"ETag":                   etag,
		}, data
	}

	// 通道 2.8：由当前探针入口自托管的 Agent 安装脚本（消除硬编码不可达占位域名）
	if (cleanSub == "/install-probe-agent.sh" || cleanSub == "/probe-agent.ps1") && method == http.MethodGet {
		if cleanSub == "/probe-agent.ps1" {
			return http.StatusOK, map[string]string{
				"Content-Type":  "text/plain; charset=utf-8",
				"Cache-Control": "no-cache",
			}, []byte(probeAgentInstallPS1)
		}
		return http.StatusOK, map[string]string{
			"Content-Type":  "text/x-shellscript; charset=utf-8",
			"Cache-Control": "no-cache",
		}, []byte(probeAgentInstallSH)
	}

	// 通道 3：私有探针访客口令解锁（受 BoundedAuthGuard 防暴破保护）
	if cleanSub == "/api/public/unlock" && method == http.MethodPost {
		nowUnix := now.Unix()
		if g.authGuard.CheckLocked("unlock", clientIP, nowUnix) {
			return jsonResp(http.StatusTooManyRequests, map[string]any{
				"error":               "TOO_MANY_ATTEMPTS",
				"retry_after_seconds": g.authGuard.RetryAfterSeconds("unlock", clientIP, nowUnix),
			})
		}
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
		matched := visHash != "" && subtle.ConstantTimeCompare([]byte(hex.EncodeToString(sum[:])), []byte(visHash)) == 1
		g.authGuard.RecordResult("unlock", clientIP, matched, nowUnix)
		if !matched {
			return jsonResp(http.StatusUnauthorized, map[string]any{"error": "VISITOR_PASSWORD_INCORRECT"})
		}
		return jsonResp(http.StatusOK, map[string]any{"visitor_token": g.mintVisitorToken(now)})
	}

	// 通道 4：独立探针页管理员原地登录与登出（签发/吊销独立 prb_adm_* 会话，供「只安装探针」直接切换前后台！）
	if cleanSub == "/api/admin/login" && method == http.MethodPost {
		return g.handleStandaloneAdminLogin(now, clientIP, body)
	}
	if cleanSub == "/api/admin/logout" && method == http.MethodPost {
		g.authGuard.RevokeSession(strings.TrimSpace(extractHeaderCI(headers, "X-Probe-Admin-Token")))
		return jsonResp(http.StatusOK, map[string]any{"logged_out": true})
	}

	// 通道 4.5：独立探针模式下的 ADR-0004 原生 AI 操控面（接受真人 prb_adm_* 或受限委托令牌 prb_dlg_*）
	if strings.HasPrefix(cleanSub, "/api/ai/v1/") {
		return g.handleStandaloneAINative(now, method, cleanSub, headers, body)
	}

	// 通道 5：受 prb_adm_* 保护的独立探针管理 API（节点增删、主题包/壁纸管理、隐私与双轨域名绑定）
	if strings.HasPrefix(cleanSub, "/api/admin/") {
		if !g.verifyAdminToken(extractHeaderCI(headers, "X-Probe-Admin-Token"), now) {
			return jsonResp(http.StatusUnauthorized, map[string]any{"error": "ADMIN_AUTH_REQUIRED"})
		}
		return g.handleStandaloneAdminAction(now, method, cleanSub, headers, body)
	}

	// 通道 5.5：严格物理隔离的官方独立管理后台 /admin 与 /admin/*（永不被第三方自定义主题接管！）
	if cleanSub == "/admin" || strings.HasPrefix(cleanSub, "/admin/") || cleanSub == "/admin.css" || cleanSub == "/admin.js" {
		return serveIsolatedAdminAsset(cleanSub)
	}

	// 通道 5.8：第三方自定义主题不透明源沙箱路由 /theme-frame/*（始终附带 X-QWQ-Theme-Sandbox: 1）
	if cleanSub == "/theme-frame" || strings.HasPrefix(cleanSub, "/theme-frame/") {
		return g.serveSandboxedThemeFrame(method, cleanSub, headers)
	}

	// 通道 6：前台展示静态资源（自定义主题由官方 theme-sandbox.html 沙箱宿主挂载，缺失/损坏时无缝回退内置门户）
	g.store.mu.RLock()
	activeTheme := g.store.settings.ActiveThemeID
	g.store.mu.RUnlock()
	if activeTheme != "" && !strings.HasPrefix(activeTheme, "builtin:") && g.themes != nil {
		if entry, ok := g.themes.EntryFile(activeTheme); ok {
			return serveThemeSandboxHostAsset(cleanSub, entry)
		}
	}
	return serveEmbeddedPortalAsset(cleanSub)
}

func (g *PortalGateway) handleStandaloneAdminLogin(now time.Time, clientIP string, body []byte) (int, map[string]string, []byte) {
	nowUnix := now.Unix()
	if g.authGuard.CheckLocked("admin", clientIP, nowUnix) {
		return jsonResp(http.StatusTooManyRequests, map[string]any{
			"error":               "TOO_MANY_ATTEMPTS",
			"retry_after_seconds": g.authGuard.RetryAfterSeconds("admin", clientIP, nowUnix),
		})
	}

	select {
	case g.hashSlots <- struct{}{}:
		defer func() { <-g.hashSlots }()
	default:
		return jsonResp(http.StatusServiceUnavailable, map[string]any{"error": "AUTH_BUSY"})
	}

	var req struct {
		Password string `json:"password"`
	}
	g.mu.Lock()
	verifier := g.adminVerifier
	g.mu.Unlock()
	if err := json.Unmarshal(body, &req); err != nil || verifier == "" || len(req.Password) > 256 {
		g.authGuard.RecordResult("admin", clientIP, false, nowUnix)
		return jsonResp(http.StatusUnauthorized, map[string]any{"error": "INVALID_CREDENTIALS"})
	}
	ok := VerifyAdminVerifier(verifier, req.Password)
	g.authGuard.RecordResult("admin", clientIP, ok, nowUnix)
	if !ok {
		return jsonResp(http.StatusUnauthorized, map[string]any{"error": "INVALID_CREDENTIALS"})
	}

	plain, err := g.authGuard.MintSession(8*time.Hour, now)
	if err != nil {
		return jsonResp(http.StatusInternalServerError, map[string]any{"error": "SESSION_MINT_FAILED"})
	}
	exp := now.Add(8 * time.Hour).Unix()

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
		_ = g.store.PersistSettings(context.Background(), updated)
		return jsonResp(http.StatusOK, updated)
	}
	return jsonResp(http.StatusNotFound, map[string]any{"error": "UNKNOWN_AI_ENDPOINT"})
}

// BackgroundSetRequest 是独立后台与插件 RPC 共用的背景图配置载荷。
type BackgroundSetRequest struct {
	Mode        string `json:"mode"`
	ImageBase64 string `json:"image_base64,omitempty"`
	MimeType    string `json:"mime_type,omitempty"`
	LQIPDataURL string `json:"lqip_data_url,omitempty"`
	FocalX      *int   `json:"focal_x,omitempty"`
	FocalY      *int   `json:"focal_y,omitempty"`
	Luminance   *int   `json:"luminance,omitempty"`
	DominantRGB string `json:"dominant_rgb,omitempty"`
	ExternalURL string `json:"external_url,omitempty"`
}

// ThemeActivateRequest 是启用主题并同步水玻璃光学外观与主题自定义参数的载荷。
type ThemeActivateRequest struct {
	ThemeID       string            `json:"theme_id,omitempty"`
	Appearance    *AppearanceConfig `json:"appearance,omitempty"`
	ThemeSettings map[string]any    `json:"theme_settings,omitempty"`
}

// ApplyThemeActivation 校验并原子激活主题及外观参数，同步落盘 SQLite。
func (g *PortalGateway) ApplyThemeActivation(req ThemeActivateRequest) (PortalSettings, error) {
	themeID := strings.TrimSpace(req.ThemeID)
	if themeID != "" && (g.themes == nil || !g.themes.Exists(themeID)) {
		return PortalSettings{}, ErrThemeNotFound
	}
	if req.ThemeSettings != nil {
		raw, err := json.Marshal(req.ThemeSettings)
		if err != nil || len(raw) > 16384 {
			return PortalSettings{}, errors.New("THEME_SETTINGS_TOO_LARGE")
		}
	}

	g.store.mu.Lock()
	if themeID != "" {
		g.store.settings.ActiveThemeID = themeID
	}
	if req.Appearance != nil {
		// 保留既有本地壁纸文件（若请求未显式覆盖 Background 字段）
		nextApp := *req.Appearance
		if nextApp.Background.Mode == "" && nextApp.Background.LocalFile == "" && nextApp.Background.ExternalURL == "" {
			nextApp.Background = g.store.settings.Appearance.Background
		} else if nextApp.Background.Mode == "local" && nextApp.Background.LocalFile == "" {
			nextApp.Background.LocalFile = g.store.settings.Appearance.Background.LocalFile
		}
		g.store.settings.Appearance = SanitizeAppearanceConfig(nextApp)
	}
	if req.ThemeSettings != nil {
		cloned := make(map[string]any, len(req.ThemeSettings))
		for k, v := range req.ThemeSettings {
			if isValidSettingKey(k) {
				cloned[k] = v
			}
		}
		g.store.settings.ThemeSettings = cloned
	}
	g.store.settings.Revision = nextRevision(g.store.settings.Revision)
	saved := g.store.settings
	g.store.mu.Unlock()

	_ = g.store.PersistSettings(context.Background(), saved)
	return saved, nil
}

// DeleteCustomTheme 删除第三方主题；若当前正激活则自动安全回退至 builtin:classic。
func (g *PortalGateway) DeleteCustomTheme(themeID string) (PortalSettings, error) {
	if g.themes == nil {
		return PortalSettings{}, ErrThemeNotFound
	}
	if err := g.themes.DeleteTheme(themeID); err != nil {
		return PortalSettings{}, err
	}
	g.store.mu.Lock()
	if g.store.settings.ActiveThemeID == themeID {
		g.store.settings.ActiveThemeID = BuiltinThemeClassic
		g.store.settings.Revision = nextRevision(g.store.settings.Revision)
	}
	saved := g.store.settings
	g.store.mu.Unlock()
	_ = g.store.PersistSettings(context.Background(), saved)
	return saved, nil
}

// ApplyBackground 保存本地壁纸（魔数校验）或外链 HTTPS 壁纸，或清空背景。
func (g *PortalGateway) ApplyBackground(req BackgroundSetRequest) (PortalSettings, error) {
	mode := strings.TrimSpace(req.Mode)
	if mode == "" {
		if strings.TrimSpace(req.ImageBase64) != "" {
			mode = "local"
		} else if strings.TrimSpace(req.ExternalURL) != "" {
			mode = "url"
		} else {
			mode = "none"
		}
	}

	g.store.mu.RLock()
	curBG := g.store.settings.Appearance.Background
	g.store.mu.RUnlock()

	nextBG := curBG
	nextBG.Mode = mode
	if req.FocalX != nil {
		nextBG.FocalX = *req.FocalX
	}
	if req.FocalY != nil {
		nextBG.FocalY = *req.FocalY
	}
	if req.Luminance != nil {
		nextBG.Luminance = *req.Luminance
	}
	if req.DominantRGB != "" {
		nextBG.DominantRGB = req.DominantRGB
	}
	if req.LQIPDataURL != "" {
		nextBG.LQIPDataURL = req.LQIPDataURL
	}

	switch mode {
	case "none":
		if g.themes != nil {
			g.themes.DeleteBackground()
		}
		nextBG = BackgroundConfig{Mode: "none", FocalX: 50, FocalY: 50, Luminance: -1}
	case "local":
		if strings.TrimSpace(req.ImageBase64) != "" {
			raw, err := DecodeBase64Payload(req.ImageBase64)
			if err != nil {
				return PortalSettings{}, ErrUnsupportedImage
			}
			fname, _, err := g.themes.SaveBackground(raw)
			if err != nil {
				return PortalSettings{}, err
			}
			nextBG.LocalFile = fname
			nextBG.ExternalURL = ""
		} else if nextBG.LocalFile == "" {
			return PortalSettings{}, errors.New("BACKGROUND_IMAGE_REQUIRED")
		}
	case "url":
		extURL := strings.TrimSpace(req.ExternalURL)
		sanitized := SanitizeBackgroundConfig(BackgroundConfig{Mode: "url", ExternalURL: extURL})
		if sanitized.ExternalURL == "" {
			return PortalSettings{}, errors.New("INVALID_BACKGROUND_URL")
		}
		nextBG.ExternalURL = sanitized.ExternalURL
		nextBG.LocalFile = ""
	default:
		return PortalSettings{}, errors.New("INVALID_BACKGROUND_MODE")
	}

	g.store.mu.Lock()
	g.store.settings.Appearance.Background = SanitizeBackgroundConfig(nextBG)
	g.store.settings.Appearance = SanitizeAppearanceConfig(g.store.settings.Appearance)
	g.store.settings.Revision = nextRevision(g.store.settings.Revision)
	saved := g.store.settings
	g.store.mu.Unlock()

	_ = g.store.PersistSettings(context.Background(), saved)
	return saved, nil
}

// ClearBackground 清除背景图并重置背景元数据。
func (g *PortalGateway) ClearBackground() PortalSettings {
	saved, _ := g.ApplyBackground(BackgroundSetRequest{Mode: "none"})
	return saved
}

func (g *PortalGateway) themeStatePayload() map[string]any {
	g.store.mu.RLock()
	cfg := g.store.settings
	g.store.mu.RUnlock()
	active := cfg.ActiveThemeID
	if active == "" {
		active = BuiltinThemeClassic
	}
	ts := cfg.ThemeSettings
	if ts == nil {
		ts = map[string]any{}
	}
	var list []ThemeManifest
	if g.themes != nil {
		list = g.themes.ListThemes()
	} else {
		list = BuiltinThemes()
	}
	return map[string]any{
		"active_theme_id": active,
		"appearance":      SanitizeAppearanceConfig(cfg.Appearance),
		"theme_settings":  ts,
		"bg_url":          BackgroundURL(cfg),
		"themes":          list,
		"revision":        cfg.Revision,
	}
}

func (g *PortalGateway) handleStandaloneAdminAction(now time.Time, method, path string, headers map[string]string, body []byte) (int, map[string]string, []byte) {
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
		var themes []ThemeManifest
		if g.themes != nil {
			themes = g.themes.ListThemes()
		} else {
			themes = BuiltinThemes()
		}
		return jsonResp(http.StatusOK, map[string]any{
			"nodes":            nodes,
			"settings":         cfg,
			"themes":           themes,
			"active_theme_id":  cfg.ActiveThemeID,
			"appearance":       SanitizeAppearanceConfig(cfg.Appearance),
			"theme_settings":   cfg.ThemeSettings,
			"bg_url":           BackgroundURL(cfg),
			"dnc_capabilities": g.domains.InspectEnvironment(),
			"proxy_snippets":   BuildReverseProxySnippets(cfg.CustomDomain, cfg.BuiltinListenAddr),
		})

	case path == "/api/admin/settings" && method == http.MethodPost:
		var patch PortalSettingsPatch
		if err := json.Unmarshal(body, &patch); err != nil {
			return jsonResp(http.StatusBadRequest, map[string]any{"error": "INVALID_JSON"})
		}
		g.store.mu.Lock()
		applySettingsPatch(&g.store.settings, patch)
		g.store.settings.Revision = nextRevision(g.store.settings.Revision)
		saved := g.store.settings
		g.store.mu.Unlock()
		_ = g.store.PersistSettings(context.Background(), saved)
		return jsonResp(http.StatusOK, saved)

	case path == "/api/admin/themes" && method == http.MethodGet:
		return jsonResp(http.StatusOK, g.themeStatePayload())

	case path == "/api/admin/themes/starter.zip" && method == http.MethodGet:
		rawZip, err := BuildStarterThemeZip()
		if err != nil {
			return jsonResp(http.StatusInternalServerError, map[string]any{"error": "STARTER_BUILD_FAILED"})
		}
		return http.StatusOK, map[string]string{
			"Content-Type":        "application/zip",
			"Content-Disposition": `attachment; filename="qwq-probe-theme-starter.zip"`,
			"Cache-Control":       "no-store",
		}, rawZip

	case path == "/api/admin/themes/upload" && method == http.MethodPost:
		var zipBytes []byte
		ct := strings.ToLower(extractHeaderCI(headers, "Content-Type"))
		isRawBinary := strings.Contains(ct, "application/zip") || strings.Contains(ct, "application/octet-stream")
		if isRawBinary || (len(body) >= 4 && bytes.Equal(body[:2], []byte{'P', 'K'})) {
			zipBytes = body
		} else {
			var req struct {
				Filename  string `json:"filename"`
				ZipBase64 string `json:"zip_base64"`
			}
			if err := json.Unmarshal(body, &req); err != nil || strings.TrimSpace(req.ZipBase64) == "" {
				return jsonResp(http.StatusBadRequest, map[string]any{"error": "INVALID_THEME_UPLOAD_PAYLOAD"})
			}
			decoded, err := DecodeBase64Payload(req.ZipBase64)
			if err != nil {
				return jsonResp(http.StatusBadRequest, map[string]any{"error": "INVALID_BASE64"})
			}
			zipBytes = decoded
		}
		manifest, err := g.themes.InstallZip(zipBytes)
		if err != nil {
			return jsonResp(http.StatusUnprocessableEntity, map[string]any{"error": err.Error()})
		}
		return jsonResp(http.StatusCreated, map[string]any{
			"installed": manifest,
			"themes":    g.themes.ListThemes(),
		})

	case path == "/api/admin/themes/install-url" && method == http.MethodPost:
		var req struct {
			URL string `json:"url"`
		}
		if err := json.Unmarshal(body, &req); err != nil || strings.TrimSpace(req.URL) == "" {
			return jsonResp(http.StatusBadRequest, map[string]any{"error": "INVALID_JSON"})
		}
		manifest, err := g.themes.InstallFromURL(context.Background(), req.URL)
		if err != nil {
			code := http.StatusUnprocessableEntity
			if errors.Is(err, ErrSSRFTargetBlocked) || errors.Is(err, ErrInvalidThemeURL) {
				code = http.StatusBadRequest
			}
			return jsonResp(code, map[string]any{"error": err.Error()})
		}
		return jsonResp(http.StatusCreated, map[string]any{
			"installed": manifest,
			"themes":    g.themes.ListThemes(),
		})

	case path == "/api/admin/themes/activate" && method == http.MethodPost:
		var req ThemeActivateRequest
		if err := json.Unmarshal(body, &req); err != nil {
			return jsonResp(http.StatusBadRequest, map[string]any{"error": "INVALID_JSON"})
		}
		saved, err := g.ApplyThemeActivation(req)
		if err != nil {
			code := http.StatusUnprocessableEntity
			if errors.Is(err, ErrThemeNotFound) {
				code = http.StatusNotFound
			}
			return jsonResp(code, map[string]any{"error": err.Error()})
		}
		return jsonResp(http.StatusOK, map[string]any{
			"active_theme_id": saved.ActiveThemeID,
			"appearance":      saved.Appearance,
			"theme_settings":  saved.ThemeSettings,
			"bg_url":          BackgroundURL(saved),
			"revision":        saved.Revision,
		})

	case strings.HasPrefix(path, "/api/admin/themes/") && method == http.MethodDelete:
		themeID := strings.TrimPrefix(path, "/api/admin/themes/")
		saved, err := g.DeleteCustomTheme(themeID)
		if err != nil {
			code := http.StatusNotFound
			if errors.Is(err, ErrBuiltinThemeLocked) {
				code = http.StatusBadRequest
			}
			return jsonResp(code, map[string]any{"error": err.Error()})
		}
		return jsonResp(http.StatusOK, map[string]any{
			"deleted":         themeID,
			"active_theme_id": saved.ActiveThemeID,
			"themes":          g.themes.ListThemes(),
		})

	case path == "/api/admin/background" && method == http.MethodPost:
		var req BackgroundSetRequest
		if err := json.Unmarshal(body, &req); err != nil {
			return jsonResp(http.StatusBadRequest, map[string]any{"error": "INVALID_JSON"})
		}
		saved, err := g.ApplyBackground(req)
		if err != nil {
			return jsonResp(http.StatusUnprocessableEntity, map[string]any{"error": err.Error()})
		}
		return jsonResp(http.StatusOK, map[string]any{
			"appearance": saved.Appearance,
			"bg_url":     BackgroundURL(saved),
			"revision":   saved.Revision,
		})

	case path == "/api/admin/background" && method == http.MethodDelete:
		saved := g.ClearBackground()
		return jsonResp(http.StatusOK, map[string]any{
			"appearance": saved.Appearance,
			"bg_url":     BackgroundURL(saved),
			"revision":   saved.Revision,
		})

	case path == "/api/admin/nodes" && method == http.MethodPost:
		var req struct {
			ID           string    `json:"id"`
			Name         string    `json:"name"`
			RegionCode   string    `json:"region_code"`
			GroupName    string    `json:"group_name"`
			QuotaBytes   uint64    `json:"quota_bytes"`
			QuotaMode    QuotaMode `json:"quota_mode"`
			ResetDay     int       `json:"reset_day"`
			ExpiresAt    *int64    `json:"expires_at,omitempty"`
			ProviderName string    `json:"provider_name,omitempty"`
			PublicOrigin string    `json:"public_origin,omitempty"`
		}
		if err := json.Unmarshal(body, &req); err != nil || strings.TrimSpace(req.Name) == "" {
			return jsonResp(http.StatusBadRequest, map[string]any{"error": "VALIDATION_FAILED"})
		}
		id := strings.TrimSpace(req.ID)
		if id != "" && !isValidNodeID(id) {
			return jsonResp(http.StatusBadRequest, map[string]any{"error": "INVALID_NODE_ID"})
		}
		if req.ResetDay < 1 || req.ResetDay > 31 {
			req.ResetDay = 1
		}
		if req.QuotaMode == "" {
			req.QuotaMode = QuotaBoth
		}

		g.store.mu.Lock()
		existing, exists := g.store.nodes[id]
		if !exists && len(g.store.nodes) >= 512 {
			g.store.mu.Unlock()
			return jsonResp(http.StatusUnprocessableEntity, map[string]any{"error": "NODE_LIMIT_EXCEEDED"})
		}
		var (
			plainTok string
			saved    NodeRecord
			created  bool
		)
		if exists && existing != nil {
			// 编辑已有节点：严格保留原有 AgentTokenSHA256 / Prefix、当月已累计 PeriodRx/TxBytes 与运行态字段！
			existing.Name = truncateSafe(req.Name, 64)
			if strings.TrimSpace(req.RegionCode) != "" {
				existing.RegionCode = truncateSafe(strings.ToUpper(req.RegionCode), 8)
			}
			if strings.TrimSpace(req.GroupName) != "" {
				existing.GroupName = truncateSafe(req.GroupName, 32)
			}
			existing.QuotaBytes = req.QuotaBytes
			existing.QuotaMode = req.QuotaMode
			existing.ResetDay = req.ResetDay
			if req.ExpiresAt != nil && *req.ExpiresAt >= 0 {
				existing.ExpiresAt = *req.ExpiresAt
			}
			if strings.TrimSpace(req.ProviderName) != "" {
				existing.ProviderName = truncateSafe(req.ProviderName, 48)
			}
			existing.Revision = nextRevision(existing.Revision)
			saved = *existing
		} else {
			var shaHex, prefix string
			var err error
			plainTok, shaHex, prefix, err = GenerateAgentToken()
			if err != nil {
				g.store.mu.Unlock()
				return jsonResp(http.StatusInternalServerError, map[string]any{"error": "TOKEN_GEN_FAILED"})
			}
			if id == "" {
				id = "node_" + strings.ToLower(hex.EncodeToString([]byte(plainTok[8:14])))
			}
			if !isValidNodeID(id) {
				g.store.mu.Unlock()
				return jsonResp(http.StatusBadRequest, map[string]any{"error": "INVALID_NODE_ID"})
			}
			var expiresAt int64
			if req.ExpiresAt != nil && *req.ExpiresAt > 0 {
				expiresAt = *req.ExpiresAt
			}
			rec := &NodeRecord{
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
				ExpiresAt:        expiresAt,
				ProviderName:     truncateSafe(req.ProviderName, 48),
				OnlineState:      "pending",
				Revision:         "r1",
			}
			g.store.nodes[id] = rec
			saved = *rec
			created = true
		}
		dom := g.store.settings.CustomDomain
		g.store.mu.Unlock()

		_ = g.store.PersistNode(context.Background(), &saved)

		endpoint := "/p/server.probe/agent/v1/report"
		if dom != "" {
			endpoint = "https://" + dom + "/api/probe/v1/report"
		} else if origin := sanitizePublicOrigin(req.PublicOrigin); origin != "" {
			endpoint = origin + "/p/server.probe/agent/v1/report"
		} else if reqHost := strings.TrimSpace(extractHeaderCI(headers, "Host")); reqHost != "" && !strings.ContainsAny(reqHost, " \t\r\n/\\") {
			proto := "https"
			if strings.EqualFold(strings.TrimSpace(extractHeaderCI(headers, "X-Forwarded-Proto")), "http") {
				proto = "http"
			}
			endpoint = proto + "://" + reqHost + "/p/server.probe/agent/v1/report"
		}
		if !created {
			return jsonResp(http.StatusOK, map[string]any{
				"node_id":         id,
				"updated":         true,
				"revision":        saved.Revision,
				"report_endpoint": endpoint,
			})
		}
		return jsonResp(http.StatusCreated, map[string]any{
			"node_id":         id,
			"one_time_token":  plainTok,
			"report_endpoint": endpoint,
			"linux_install":   BuildAgentInstallCommand("linux", endpoint, id, plainTok),
		})

	case strings.HasPrefix(path, "/api/admin/nodes/") && method == http.MethodDelete:
		id := strings.TrimSpace(strings.TrimPrefix(path, "/api/admin/nodes/"))
		if id == "" || id == "local" || !isValidNodeID(id) {
			return jsonResp(http.StatusBadRequest, map[string]any{"error": "INVALID_NODE_ID"})
		}
		g.store.mu.Lock()
		_, existed := g.store.nodes[id]
		delete(g.store.nodes, id)
		delete(g.store.live, id)
		delete(g.store.sla90d, id)
		g.store.mu.Unlock()
		if !existed {
			return jsonResp(http.StatusNotFound, map[string]any{"error": "NODE_NOT_FOUND"})
		}
		_ = g.store.DeleteNode(context.Background(), id)
		return jsonResp(http.StatusOK, map[string]any{"removed": id})

	case path == "/api/admin/domain/bind" && method == http.MethodPost:
		var req struct {
			CustomDomain       string             `json:"custom_domain"`
			BindingTrack       string             `json:"binding_track"`
			PanelCertRef       string             `json:"panel_cert_binding_ref"`
			ACMEEmail          string             `json:"acme_email"`
			CertPEM            string             `json:"cert_pem"`
			KeyPEM             SecretOrPlainField `json:"key_pem"`
			TrustCloudflareIPs bool               `json:"trust_cloudflare_ips"`
		}
		if err := json.Unmarshal(body, &req); err != nil {
			return jsonResp(http.StatusBadRequest, map[string]any{"error": "INVALID_JSON"})
		}
		keyBytes := []byte(req.KeyPEM.Plain)
		defer clear(keyBytes)
		g.store.mu.Lock()
		candidate := g.store.settings
		candidate.DomainEnabled = true
		candidate.CustomDomain = req.CustomDomain
		candidate.BindingTrack = req.BindingTrack
		candidate.PanelCertBindingRef = req.PanelCertRef
		candidate.BuiltinACMEEmail = req.ACMEEmail
		candidate.TrustCloudflareIPs = req.TrustCloudflareIPs
		summary, err := g.domains.ValidateAndApply(now, &candidate, []byte(req.CertPEM), keyBytes)
		if err != nil {
			g.store.mu.Unlock()
			return jsonResp(http.StatusUnprocessableEntity, map[string]any{"error": err.Error()})
		}
		g.store.settings = candidate
		g.store.mu.Unlock()
		_ = g.store.PersistSettings(context.Background(), candidate)
		return jsonResp(http.StatusOK, map[string]any{
			"bound":          summary,
			"proxy_snippets": BuildReverseProxySnippets(candidate.CustomDomain, candidate.BuiltinListenAddr),
		})
	}
	return jsonResp(http.StatusNotFound, map[string]any{"error": "UNKNOWN_ADMIN_ENDPOINT"})
}

func sanitizePublicOrigin(raw string) string {
	s := strings.TrimRight(strings.TrimSpace(raw), "/")
	if s == "" || strings.ContainsAny(s, " \t\r\n'\"<>\\") {
		return ""
	}
	lower := strings.ToLower(s)
	if !strings.HasPrefix(lower, "https://") && !strings.HasPrefix(lower, "http://") {
		return ""
	}
	rest := s[strings.Index(s, "://")+3:]
	if rest == "" || strings.Contains(rest, "/") {
		return ""
	}
	return s
}

const probeAgentInstallSH = `#!/usr/bin/env bash
set -euo pipefail
ENDPOINT="" NODE="" TOKEN=""
while [ $# -gt 0 ]; do
  case "$1" in
    --endpoint) ENDPOINT="$2"; shift 2 ;;
    --node)     NODE="$2"; shift 2 ;;
    --token)    TOKEN="$2"; shift 2 ;;
    *) shift ;;
  esac
done
if [ -z "$ENDPOINT" ] || [ -z "$NODE" ] || [ -z "$TOKEN" ]; then
  echo "Usage: install-probe-agent.sh --endpoint <url> --node <id> --token <prb_agt_...>" >&2
  exit 2
fi
install -d -m 0700 /etc/qwq-probe-agent
cat >/etc/qwq-probe-agent/agent.env <<EOF
QWQ_PROBE_ENDPOINT=${ENDPOINT}
QWQ_PROBE_NODE=${NODE}
QWQ_PROBE_TOKEN=${TOKEN}
EOF
chmod 0600 /etc/qwq-probe-agent/agent.env
cat >/etc/systemd/system/qwq-probe-agent.service <<'EOF'
[Unit]
Description=qwq Probe One-Way Telemetry Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
EnvironmentFile=/etc/qwq-probe-agent/agent.env
ExecStart=/usr/local/bin/qwq-probe-agent
Restart=always
RestartSec=5
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
EOF
if command -v systemctl >/dev/null 2>&1 && [ -x /usr/local/bin/qwq-probe-agent ]; then
  systemctl daemon-reload
  systemctl enable --now qwq-probe-agent.service
fi
echo "qwq-probe-agent configured for node ${NODE}"
`

const probeAgentInstallPS1 = `function Install-QwqProbeAgent {
  param(
    [Parameter(Mandatory=$true)][string]$Endpoint,
    [Parameter(Mandatory=$true)][string]$Node,
    [Parameter(Mandatory=$true)][string]$Token
  )
  $env:QWQ_PROBE_ENDPOINT = $Endpoint
  $env:QWQ_PROBE_NODE = $Node
  $env:QWQ_PROBE_TOKEN = $Token
  Write-Host "Configured qwq-probe-agent for node $Node -> $Endpoint"
}
`

// BuildAgentInstallCommand 拼装单向安全探针 Agent 一键部署命令（脚本地址派生自当前可达 public_origin/reportURL，带严格单引号转义）。
func BuildAgentInstallCommand(platform, reportURL, nodeID, token string) string {
	scriptBase := deriveScriptBaseURL(reportURL)
	if platform == "windows" {
		psEsc := func(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }
		return "irm " + psEsc(scriptBase+"/probe-agent.ps1") + " | iex; Install-QwqProbeAgent -Endpoint " + psEsc(reportURL) + " -Node " + psEsc(nodeID) + " -Token " + psEsc(token)
	}
	shEsc := func(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }
	return "curl -fsSL " + shEsc(scriptBase+"/install-probe-agent.sh") + " | sudo bash -s -- --endpoint " + shEsc(reportURL) + " --node " + shEsc(nodeID) + " --token " + shEsc(token)
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
	if g == nil || g.authGuard == nil {
		return false
	}
	return g.authGuard.VerifySession(strings.TrimSpace(raw), now.Unix())
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

func (g *PortalGateway) serveSandboxedThemeFrame(method, cleanSub string, headers map[string]string) (int, map[string]string, []byte) {
	inner := strings.TrimPrefix(cleanSub, "/theme-frame")
	if inner == "" {
		inner = "/"
	}
	// 阻断顶层地址栏直接导航至 /theme-frame/*（防自定义主题伪造同域名钓鱼页）
	if IsTopLevelThemeFrameNavigation(headers) {
		depth := 1 + strings.Count(strings.TrimPrefix(inner, "/"), "/")
		return http.StatusFound, map[string]string{
			"Location":      strings.Repeat("../", depth),
			"Cache-Control": "no-store",
		}, nil
	}
	if inner == "/__qwq_bridge.js" {
		data, err := fs.ReadFile(embeddedPortalFS, "portal_ui/theme-bridge.js")
		if err != nil {
			return jsonResp(http.StatusNotFound, map[string]any{"error": "BRIDGE_NOT_FOUND"})
		}
		return http.StatusOK, map[string]string{
			"Content-Type":        "application/javascript; charset=utf-8",
			"Cache-Control":       "public, max-age=3600",
			"X-QWQ-Theme-Sandbox": "1",
		}, data
	}
	if inner == "/api/public/bg" && (method == http.MethodGet || method == http.MethodHead) {
		g.store.mu.RLock()
		bg := g.store.settings.Appearance.Background
		g.store.mu.RUnlock()
		if bg.Mode != "local" || bg.LocalFile == "" {
			return jsonResp(http.StatusNotFound, map[string]any{"error": "BACKGROUND_NOT_FOUND"})
		}
		data, mimeType, etag, err := g.themes.ReadBackground(bg.LocalFile)
		if err != nil {
			return jsonResp(http.StatusNotFound, map[string]any{"error": "BACKGROUND_NOT_FOUND"})
		}
		return http.StatusOK, map[string]string{
			"Content-Type":           mimeType,
			"X-Content-Type-Options": "nosniff",
			"Cache-Control":          "public, max-age=3600",
			"ETag":                   etag,
			"X-QWQ-Theme-Sandbox":    "1",
		}, data
	}

	g.store.mu.RLock()
	activeTheme := g.store.settings.ActiveThemeID
	g.store.mu.RUnlock()
	if activeTheme == "" || strings.HasPrefix(activeTheme, "builtin:") || g.themes == nil {
		return jsonResp(http.StatusNotFound, map[string]any{"error": "NO_ACTIVE_CUSTOM_THEME"})
	}
	code, hdrs, data, fallback := g.themes.ServeThemeAsset(activeTheme, inner)
	if fallback {
		return jsonResp(http.StatusNotFound, map[string]any{"error": "THEME_ASSET_UNAVAILABLE"})
	}
	if hdrs == nil {
		hdrs = map[string]string{}
	}
	hdrs["X-QWQ-Theme-Sandbox"] = "1"
	return code, hdrs, data
}

func serveThemeSandboxHostAsset(cleanSub, entry string) (int, map[string]string, []byte) {
	rel := strings.TrimPrefix(cleanSub, "/")
	if rel == "" || rel == "index.html" || (!strings.Contains(rel, ".") && !strings.Contains(rel, "..")) {
		raw, err := fs.ReadFile(embeddedPortalFS, "portal_ui/theme-sandbox.html")
		if err != nil {
			return jsonResp(http.StatusNotFound, map[string]any{"error": "SANDBOX_HOST_NOT_FOUND"})
		}
		rendered := bytes.ReplaceAll(raw, []byte("__QWQ_THEME_ENTRY__"), []byte(html.EscapeString(entry)))
		return http.StatusOK, map[string]string{
			"Content-Type":  "text/html; charset=utf-8",
			"Cache-Control": "no-cache",
		}, rendered
	}
	switch rel {
	case "theme-sandbox.css":
		raw, err := fs.ReadFile(embeddedPortalFS, "portal_ui/theme-sandbox.css")
		if err != nil {
			return jsonResp(http.StatusNotFound, map[string]any{"error": "ASSET_NOT_FOUND"})
		}
		return http.StatusOK, map[string]string{
			"Content-Type":  "text/css; charset=utf-8",
			"Cache-Control": "public, max-age=3600",
		}, raw
	case "theme-sandbox.js":
		raw, err := fs.ReadFile(embeddedPortalFS, "portal_ui/theme-sandbox.js")
		if err != nil {
			return jsonResp(http.StatusNotFound, map[string]any{"error": "ASSET_NOT_FOUND"})
		}
		return http.StatusOK, map[string]string{
			"Content-Type":  "application/javascript; charset=utf-8",
			"Cache-Control": "public, max-age=3600",
		}, raw
	default:
		return jsonResp(http.StatusNotFound, map[string]any{"error": "ASSET_NOT_FOUND"})
	}
}

func serveIsolatedAdminAsset(cleanSub string) (int, map[string]string, []byte) {
	var rel string
	switch cleanSub {
	case "/admin", "/admin/", "/admin/index.html":
		rel = "admin.html"
	case "/admin.css", "/admin/admin.css":
		rel = "admin.css"
	case "/admin.js", "/admin/admin.js":
		rel = "admin.js"
	default:
		if rest, ok := strings.CutPrefix(cleanSub, "/admin/"); ok && !strings.Contains(rest, ".") && !strings.Contains(rest, "..") {
			rel = "admin.html"
		} else {
			return jsonResp(http.StatusNotFound, map[string]any{"error": "ADMIN_ASSET_NOT_FOUND"})
		}
	}
	data, err := fs.ReadFile(embeddedPortalFS, "portal_ui/"+rel)
	if err != nil {
		return jsonResp(http.StatusNotFound, map[string]any{"error": "ADMIN_ASSET_NOT_FOUND"})
	}
	ctype := "text/html; charset=utf-8"
	cacheCtl := "no-cache"
	switch rel {
	case "admin.css":
		ctype = "text/css; charset=utf-8"
		cacheCtl = "public, max-age=3600"
	case "admin.js":
		ctype = "application/javascript; charset=utf-8"
		cacheCtl = "public, max-age=3600"
	}
	return http.StatusOK, map[string]string{
		"Content-Type":  ctype,
		"Cache-Control": cacheCtl,
	}, data
}

func serveEmbeddedPortalAsset(cleanSub string) (int, map[string]string, []byte) {
	rel := strings.TrimPrefix(cleanSub, "/")
	if strings.Contains(rel, "..") || strings.Contains(rel, "/") || strings.Contains(rel, "\\") {
		rel = "index.html"
	}
	if rel == "" || !strings.Contains(rel, ".") {
		rel = "index.html"
	}
	// 公开前台静态通道绝不输出 admin.* 文件（由 /admin 严格隔离通道独占）
	switch rel {
	case "index.html", "portal.css", "portal.js":
	default:
		return jsonResp(http.StatusNotFound, map[string]any{"error": "ASSET_NOT_FOUND"})
	}
	data, err := fs.ReadFile(embeddedPortalFS, "portal_ui/"+rel)
	if err != nil {
		return jsonResp(http.StatusNotFound, map[string]any{"error": "ASSET_NOT_FOUND"})
	}
	ctype := "text/html; charset=utf-8"
	cacheCtl := "no-cache"
	switch {
	case strings.HasSuffix(rel, ".css"):
		ctype = "text/css; charset=utf-8"
		cacheCtl = "public, max-age=3600"
	case strings.HasSuffix(rel, ".js"):
		ctype = "application/javascript; charset=utf-8"
		cacheCtl = "public, max-age=3600"
	}
	return http.StatusOK, map[string]string{
		"Content-Type":  ctype,
		"Cache-Control": cacheCtl,
	}, data
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
