// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"context"
	"crypto/tls"
	_ "embed"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"path/filepath"
	"strings"
	"sync"
	"time"

	platformv1 "github.com/qwq-panel/qwq/sdk/gen/qwq/platform/v1"
	"github.com/qwq-panel/qwq/sdk/pluginsdk"
)

//go:embed manifest.json
var manifestJSON []byte

//go:embed schema.sql
var embeddedSchemaSQL string

var buildVersion string

// Manifest 返回内嵌的 web.ingress 插件清单字节。
func Manifest() []byte {
	raw := append([]byte(nil), manifestJSON...)
	if buildVersion != "" {
		raw = bytes.Replace(raw, []byte(`"version": "0.1.0"`), []byte(`"version": "`+buildVersion+`"`), 1)
	}
	return raw
}

type pluginConfig struct {
	PreferredEngine  string   `json:"preferred_engine"`
	ListenAddr       string   `json:"listen_addr"`
	HTTPSListenAddr  string   `json:"https_listen_addr"`
	TrustedProxies   []string `json:"trusted_proxies"`
	ExportConfigPath string   `json:"export_config_path"`
}

func validateExportPath(raw, dataDir string) error {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	if strings.ContainsRune(raw, '\x00') || strings.Contains(raw, "..") {
		return pluginsdk.Errorf("INVALID_ARGUMENT", "export_config_path 包含非法字符或路径穿越")
	}
	clean := filepath.Clean(raw)
	if !filepath.IsAbs(clean) {
		return pluginsdk.Errorf("INVALID_ARGUMENT", "export_config_path 必须为绝对路径")
	}
	if dataDir != "" {
		prefix := filepath.Clean(dataDir) + string(filepath.Separator)
		if strings.HasPrefix(clean, prefix) {
			return nil
		}
	}
	return pluginsdk.Errorf("INVALID_ARGUMENT", "受沙箱 ProtectSystem=strict 隔离保护，export_config_path 仅允许写入当前插件数据目录（外部 Nginx/Caddy 请在配置预览页一键复制）")
}

func parseConfig(raw []byte, dataDir string) (pluginConfig, []netip.Prefix, error) {
	cfg := pluginConfig{PreferredEngine: "builtin-go"}
	if len(bytes.TrimSpace(raw)) > 0 {
		if err := json.Unmarshal(raw, &cfg); err != nil {
			return cfg, nil, pluginsdk.Errorf("INVALID_ARGUMENT", "解析 web.ingress 配置失败: %s", err.Error())
		}
	}
	if cfg.PreferredEngine == "" {
		cfg.PreferredEngine = "builtin-go"
	}
	cfg.ListenAddr, cfg.HTTPSListenAddr = NormalizeIngressListenAddrs(cfg.ListenAddr, cfg.HTTPSListenAddr)
	if err := validateExportPath(cfg.ExportConfigPath, dataDir); err != nil {
		return cfg, nil, err
	}
	trusted, err := parseTrustedProxies(cfg.TrustedProxies)
	if err != nil {
		return cfg, nil, pluginsdk.Errorf("INVALID_ARGUMENT", "%s", err.Error())
	}
	return cfg, trusted, nil
}

// Plugin 实现轻量反向代理与站点托管插件。
type Plugin struct {
	now func() time.Time
}

// New 构造默认 web.ingress 插件。
func New() *Plugin { return &Plugin{} }

func (p *Plugin) NewInstance(ctx context.Context, info pluginsdk.InstanceInfo) (pluginsdk.Instance, error) {
	cfg, trusted, err := parseConfig(info.Config, info.DataDir)
	if err != nil {
		return nil, err
	}
	nowFn := p.now
	if nowFn == nil {
		nowFn = time.Now
	}
	st, err := openIngressStore(info.DataDir, embeddedSchemaSQL, nowFn)
	if err != nil {
		return nil, pluginsdk.Errorf("INTERNAL", "初始化反代数据库失败: %s", err.Error())
	}
	sni := NewSNICertStore(info.DataDir)
	proxy := newBuiltinProxy(nowFn, sni)
	proxy.SetTrustedProxies(trusted)
	if sites, err := st.listSites(ctx); err == nil {
		proxy.Reload(sites)
		syncSiteBindingsToSNI(sni, sites)
	}
	inst := &instance{
		InstanceBase:   pluginsdk.NewInstanceBase(info),
		cfg:            cfg,
		configRevision: strings.TrimSpace(info.ConfigRevision),
		dataDir:        info.DataDir,
		store:          st,
		proxy:          proxy,
		sni:            sni,
		now:            nowFn,
	}
	if inst.configRevision == "" {
		inst.configRevision = "0"
	}
	if addr := strings.TrimSpace(cfg.ListenAddr); addr != "" {
		ln, lerr := net.Listen("tcp", addr)
		if lerr != nil {
			inst.httpListenErr = fmt.Sprintf("HTTP 监听 %s 失败: %s", addr, lerr.Error())
		} else {
			srv := &http.Server{
				Handler:           proxy,
				ReadHeaderTimeout: 10 * time.Second,
				IdleTimeout:       60 * time.Second,
			}
			inst.server = srv
			inst.boundAddr = ln.Addr().String()
			go func() { _ = srv.Serve(ln) }()
		}
	}
	if httpsAddr := strings.TrimSpace(cfg.HTTPSListenAddr); httpsAddr != "" {
		rawLn, lerr := net.Listen("tcp", httpsAddr)
		if lerr != nil {
			inst.httpsListenErr = fmt.Sprintf("HTTPS 监听 %s 失败: %s", httpsAddr, lerr.Error())
		} else {
			var initRoutes map[string]L4PassthroughTarget
			if rules, rerr := st.listSNIPassthroughs(ctx); rerr == nil && len(rules) > 0 {
				initRoutes = make(map[string]L4PassthroughTarget, len(rules))
				for _, r := range rules {
					if r.Enabled {
						initRoutes[r.SNIPattern] = L4PassthroughTarget{UpstreamAddr: r.UpstreamAddr}
					}
				}
			}
			muxLn := NewL4SNIMuxListenerWithRoutes(rawLn, initRoutes)
			tlsLn := tls.NewListener(muxLn, sni.TLSConfig())
			httpsSrv := &http.Server{
				Handler:           proxy,
				ReadHeaderTimeout: 10 * time.Second,
				IdleTimeout:       60 * time.Second,
			}
			inst.sniMux = muxLn
			inst.httpsServer = httpsSrv
			inst.httpsBoundAddr = rawLn.Addr().String()
			sni.SetHTTPSListenerActive(true)
			go func() { _ = httpsSrv.Serve(tlsLn) }()
		}
	}
	for _, op := range []string{
		"ingress.stat.sites",
		"ingress.checks.upstreams",
		"ingress.overview",
		"ingress.ai.digest",
		"ingress.site.upsert",
		"ingress.site.delete",
		"ingress.config.preview",
		"ingress.apply",
		"ingress.rollback",
		"ingress.upstream.probe",
		"ingress.tls.reload",
		"ingress.tls.inspect",
		"ingress.acme.present",
		"ingress.acme.cleanup",
		"ingress.sni_passthrough.upsert",
		"ingress.sni_passthrough.delete",
	} {
		opName := op
		inst.HandleInvoke(opName, func(c context.Context, req pluginsdk.Request) (pluginsdk.Response, error) {
			req.Operation = opName
			return inst.Invoke(c, req)
		})
	}
	inst.HandlePlan("ingress.site.upsert", inst.planSiteUpsert)
	return inst, nil
}

func (i *instance) planSiteUpsert(_ context.Context, req pluginsdk.Request) (pluginsdk.Plan, error) {
	var body struct {
		Domain              string            `json:"domain"`
		UpstreamURL         string            `json:"upstream_url"`
		PathPrefix          string            `json:"path_prefix"`
		TLSMode             string            `json:"tls_mode"`
		ExtraHeaders        map[string]string `json:"extra_headers"`
		UpstreamTLSInsecure bool              `json:"upstream_tls_insecure"`
		MaxBodyMB           int               `json:"max_body_mb"`
	}
	if err := json.Unmarshal(req.Payload, &body); err != nil {
		return pluginsdk.Plan{}, pluginsdk.Errorf("INVALID_ARGUMENT", "请求格式错误: %s", err.Error())
	}
	if body.MaxBodyMB < 0 || body.MaxBodyMB > 102400 {
		return pluginsdk.Plan{}, pluginsdk.Errorf("INVALID_ARGUMENT", "max_body_mb 超出允许范围 (0..102400)")
	}
	domain, err := validateDomain(body.Domain)
	if err != nil {
		return pluginsdk.Plan{}, pluginsdk.Errorf("INVALID_ARGUMENT", "%s", err.Error())
	}
	upstream, err := validateUpstreamURL(body.UpstreamURL)
	if err != nil {
		return pluginsdk.Plan{}, pluginsdk.Errorf("INVALID_ARGUMENT", "%s", err.Error())
	}
	if _, err := validatePathPrefix(body.PathPrefix); err != nil {
		return pluginsdk.Plan{}, pluginsdk.Errorf("INVALID_ARGUMENT", "%s", err.Error())
	}
	if _, err := validateHeaders(body.ExtraHeaders); err != nil {
		return pluginsdk.Plan{}, pluginsdk.Errorf("INVALID_ARGUMENT", "%s", err.Error())
	}
	plan := pluginsdk.Plan{
		Changes: []pluginsdk.PlannedChange{{
			Kind:        pluginsdk.ChangeUpdate,
			Subject:     "ingress_sites/" + domain,
			Reversible:  true,
			Description: fmt.Sprintf("配置域名 %s 反向代理至 %s（变更前自动生成可回滚快照）", domain, upstream),
		}},
	}
	if body.TLSMode == "off" {
		plan.Warnings = append(plan.Warnings, pluginsdk.FieldViolation{
			Pointer: "/tls_mode",
			Code:    "PLAIN_HTTP",
			Message: "当前站点未启用 TLS，仅适用于内网或上游已终止 HTTPS 的场景。",
		})
	}
	return plan, nil
}

type instance struct {
	*pluginsdk.InstanceBase
	cfgMu          sync.RWMutex
	applyMu        sync.Mutex
	cfg            pluginConfig
	configRevision string
	dataDir        string
	store          *ingressStore
	proxy          *BuiltinProxy
	sni            *SNICertStore
	server         *http.Server
	boundAddr      string
	httpListenErr  string
	sniMux         *L4SNIMuxListener
	httpsServer    *http.Server
	httpsBoundAddr string
	httpsListenErr string
	now            func() time.Time
}

func (i *instance) currentConfig() pluginConfig {
	i.cfgMu.RLock()
	defer i.cfgMu.RUnlock()
	return i.cfg
}

func (i *instance) currentConfigRevision() string {
	i.cfgMu.RLock()
	defer i.cfgMu.RUnlock()
	if i.configRevision == "" {
		return "0"
	}
	return i.configRevision
}

func (i *instance) currentBoundAddr() string {
	i.cfgMu.RLock()
	defer i.cfgMu.RUnlock()
	return i.boundAddr
}

func (i *instance) currentHTTPSBoundAddr() string {
	i.cfgMu.RLock()
	defer i.cfgMu.RUnlock()
	return i.httpsBoundAddr
}

func (i *instance) currentListenErrors() (httpErr, httpsErr string) {
	i.cfgMu.RLock()
	defer i.cfgMu.RUnlock()
	return i.httpListenErr, i.httpsListenErr
}

func (i *instance) Deactivate(ctx context.Context) error {
	i.cfgMu.Lock()
	srv := i.server
	httpsSrv := i.httpsServer
	mux := i.sniMux
	i.server = nil
	i.boundAddr = ""
	i.httpsServer = nil
	i.sniMux = nil
	i.httpsBoundAddr = ""
	i.cfgMu.Unlock()
	if i.sni != nil {
		i.sni.SetHTTPSListenerActive(false)
	}
	if srv != nil {
		sctx, cancel := context.WithTimeout(ctx, 3*time.Second)
		_ = srv.Shutdown(sctx)
		cancel()
	}
	if httpsSrv != nil {
		sctx, cancel := context.WithTimeout(ctx, 3*time.Second)
		_ = httpsSrv.Shutdown(sctx)
		cancel()
	}
	if mux != nil {
		_ = mux.Close()
	}
	i.proxy.Close()
	return i.store.Close()
}

func (i *instance) ValidateConfig(_ context.Context, cand pluginsdk.Config) (pluginsdk.ConfigValidation, error) {
	if _, _, err := parseConfig(cand.JSON, i.dataDir); err != nil {
		return pluginsdk.ConfigValidation{}, err
	}
	return pluginsdk.ConfigValidation{}, nil
}

func (i *instance) ApplyConfig(ctx context.Context, cand pluginsdk.Config) error {
	cfg, trusted, err := parseConfig(cand.JSON, i.dataDir)
	if err != nil {
		return err
	}
	newAddr := strings.TrimSpace(cfg.ListenAddr)
	newHTTPSAddr := strings.TrimSpace(cfg.HTTPSListenAddr)

	i.cfgMu.Lock()
	oldAddr := strings.TrimSpace(i.cfg.ListenAddr)
	oldHTTPSAddr := strings.TrimSpace(i.cfg.HTTPSListenAddr)
	var oldSrv, oldHTTPSSrv *http.Server
	var oldMux, newMux *L4SNIMuxListener
	var newSrv, newHTTPSSrv *http.Server
	var ln, httpsLn net.Listener
	var newBound, newHTTPSBound string

	httpAddrChanged := newAddr != oldAddr
	httpsAddrChanged := newHTTPSAddr != oldHTTPSAddr
	needHTTPChange := httpAddrChanged || (newAddr != "" && i.server == nil)
	needHTTPSChange := httpsAddrChanged || (newHTTPSAddr != "" && i.httpsServer == nil)
	var nextHTTPErr, nextHTTPSErr string

	// 两阶段切换：显式修改 listen_addr/https_listen_addr 时严格校验绑定失败即中止；
	// 若地址未改但启动时端口被占（如 core.xray 占 443），则尽力重试而不阻断无关配置保存。
	if needHTTPChange && newAddr != "" {
		ln, err = net.Listen("tcp", newAddr)
		if err != nil {
			if httpAddrChanged {
				i.cfgMu.Unlock()
				return pluginsdk.Errorf("FAILED_PRECONDITION", "热切换反代监听 %s 失败: %s", newAddr, err.Error())
			}
			nextHTTPErr = err.Error()
			needHTTPChange = false
		} else {
			newSrv = &http.Server{
				Handler:           i.proxy,
				ReadHeaderTimeout: 10 * time.Second,
				IdleTimeout:       60 * time.Second,
			}
			newBound = ln.Addr().String()
		}
	}
	if needHTTPSChange && newHTTPSAddr != "" {
		rawLn, lerr := net.Listen("tcp", newHTTPSAddr)
		if lerr != nil {
			if httpsAddrChanged {
				if ln != nil {
					_ = ln.Close()
				}
				i.cfgMu.Unlock()
				return pluginsdk.Errorf("FAILED_PRECONDITION", "热切换反代 HTTPS 监听 %s 失败: %s", newHTTPSAddr, lerr.Error())
			}
			nextHTTPSErr = lerr.Error()
			needHTTPSChange = false
		} else {
			var initRoutes map[string]L4PassthroughTarget
			if rules, rerr := i.store.listSNIPassthroughs(ctx); rerr == nil && len(rules) > 0 {
				initRoutes = make(map[string]L4PassthroughTarget, len(rules))
				for _, r := range rules {
					if r.Enabled {
						initRoutes[r.SNIPattern] = L4PassthroughTarget{UpstreamAddr: r.UpstreamAddr}
					}
				}
			}
			newMux = NewL4SNIMuxListenerWithRoutes(rawLn, initRoutes)
			httpsLn = tls.NewListener(newMux, i.sni.TLSConfig())
			newHTTPSSrv = &http.Server{
				Handler:           i.proxy,
				ReadHeaderTimeout: 10 * time.Second,
				IdleTimeout:       60 * time.Second,
			}
			newHTTPSBound = rawLn.Addr().String()
		}
	}

	if needHTTPChange {
		oldSrv = i.server
		i.server = newSrv
		i.boundAddr = newBound
		i.httpListenErr = ""
	} else if nextHTTPErr != "" {
		i.httpListenErr = nextHTTPErr
	}
	if needHTTPSChange {
		oldHTTPSSrv = i.httpsServer
		oldMux = i.sniMux
		i.httpsServer = newHTTPSSrv
		i.sniMux = newMux
		i.httpsBoundAddr = newHTTPSBound
		i.httpsListenErr = ""
		if i.sni != nil {
			i.sni.SetHTTPSListenerActive(newHTTPSSrv != nil)
		}
	} else if nextHTTPSErr != "" {
		i.httpsListenErr = nextHTTPSErr
	}
	i.cfg = cfg
	if rev := strings.TrimSpace(cand.Revision); rev != "" {
		i.configRevision = rev
	}
	i.cfgMu.Unlock()

	i.proxy.SetTrustedProxies(trusted)

	if newSrv != nil && ln != nil {
		go func() { _ = newSrv.Serve(ln) }()
	}
	if newHTTPSSrv != nil && httpsLn != nil {
		go func() { _ = newHTTPSSrv.Serve(httpsLn) }()
	}
	if oldSrv != nil {
		sctx, cancel := context.WithTimeout(ctx, 3*time.Second)
		_ = oldSrv.Shutdown(sctx)
		cancel()
	}
	if oldHTTPSSrv != nil {
		sctx, cancel := context.WithTimeout(ctx, 3*time.Second)
		_ = oldHTTPSSrv.Shutdown(sctx)
		cancel()
	}
	if oldMux != nil {
		_ = oldMux.Close()
	}
	return nil
}

func (i *instance) Health(context.Context) pluginsdk.Health {
	httpErr, httpsErr := i.currentListenErrors()
	var errs []string
	if httpErr != "" {
		errs = append(errs, httpErr)
	}
	if httpsErr != "" {
		errs = append(errs, httpsErr)
	}
	if len(errs) > 0 {
		details, _ := json.Marshal(map[string]any{
			"degraded":           true,
			"http_listen_error":  httpErr,
			"https_listen_error": httpsErr,
		})
		return pluginsdk.Health{
			Message: "web.ingress 端口监听告警: " + strings.Join(errs, "；"),
			Details: details,
		}
	}
	return pluginsdk.Health{Message: "web.ingress 运行正常"}
}

func (i *instance) Invoke(ctx context.Context, req pluginsdk.Request) (pluginsdk.Response, error) {
	switch req.Operation {
	case "ingress.stat.sites":
		return i.handleStatSites(ctx)
	case "ingress.checks.upstreams":
		return i.handleChecksUpstreams(ctx)
	case "ingress.overview":
		return i.handleOverview(ctx, req.Call().NodeID)
	case "ingress.ai.digest":
		return i.handleAIDigest(ctx)
	case "ingress.site.upsert":
		return i.handleSiteUpsert(ctx, req.Payload)
	case "ingress.site.delete":
		return i.handleSiteDelete(ctx, req.Payload)
	case "ingress.config.preview":
		return i.handleConfigPreview(ctx)
	case "ingress.apply":
		return i.handleApply(ctx)
	case "ingress.rollback":
		return i.handleRollback(ctx, req.Payload)
	case "ingress.upstream.probe":
		return i.handleUpstreamProbe(ctx, req.Payload)
	case "ingress.tls.reload":
		return i.handleTLSReload(ctx, req.Payload)
	case "ingress.tls.inspect":
		return i.handleTLSInspect(ctx, req.Payload)
	case "ingress.acme.present":
		return i.handleACMEPresent(ctx, req.Call(), req.Payload)
	case "ingress.acme.cleanup":
		return i.handleACMECleanup(ctx, req.Call(), req.Payload)
	case "ingress.sni_passthrough.upsert":
		return i.handleSNIPassthroughUpsert(ctx, req.Payload)
	case "ingress.sni_passthrough.delete":
		return i.handleSNIPassthroughDelete(ctx, req.Payload)
	default:
		return pluginsdk.Response{}, pluginsdk.Errorf("NOT_FOUND", "未知操作: %s", req.Operation)
	}
}

func jsonResp(v any) (pluginsdk.Response, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return pluginsdk.Response{}, pluginsdk.Errorf("INTERNAL", "序列化响应失败")
	}
	return pluginsdk.Response{Payload: raw}, nil
}

func (i *instance) handleStatSites(ctx context.Context) (pluginsdk.Response, error) {
	sites, err := i.store.listSites(ctx)
	if err != nil {
		return pluginsdk.Response{}, pluginsdk.Errorf("INTERNAL", "%s", err.Error())
	}
	enabled := 0
	for _, s := range sites {
		if s.Enabled {
			enabled++
		}
	}
	probe := detectBackends(i.currentConfig().PreferredEngine)
	return jsonResp(map[string]any{
		"value":  fmt.Sprintf("%d 站点", enabled),
		"unit":   probe.ActiveEngine,
		"status": "ok",
		"detail": fmt.Sprintf("总站点 %d，已生效路由 %d", len(sites), i.proxy.ActiveCount()),
	})
}

func (i *instance) handleChecksUpstreams(ctx context.Context) (pluginsdk.Response, error) {
	sites, err := i.store.listSites(ctx)
	if err != nil {
		return pluginsdk.Response{}, pluginsdk.Errorf("INTERNAL", "%s", err.Error())
	}
	items := make([]map[string]any, len(sites))
	sem := make(chan struct{}, 4)
	var wg sync.WaitGroup
	for idx, s := range sites {
		if !s.Enabled {
			items[idx] = map[string]any{"name": s.Domain, "status": "unknown", "message": "已停用"}
			continue
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(pos int, site SiteRecord) {
			defer wg.Done()
			defer func() { <-sem }()
			res := probeUpstream(ctx, site)
			if res.Reachable {
				items[pos] = map[string]any{
					"name":    site.Domain,
					"status":  "ok",
					"message": fmt.Sprintf("HTTP %d · %dms", res.StatusCode, res.LatencyMS),
				}
			} else {
				items[pos] = map[string]any{
					"name":    site.Domain,
					"status":  "error",
					"message": res.Error,
				}
			}
		}(idx, s)
	}
	wg.Wait()
	return jsonResp(map[string]any{"items": items})
}

func (i *instance) handleOverview(ctx context.Context, nodeID string) (pluginsdk.Response, error) {
	sites, err := i.store.listSites(ctx)
	if err != nil {
		return pluginsdk.Response{}, pluginsdk.Errorf("INTERNAL", "%s", err.Error())
	}
	snaps, err := i.store.listSnapshots(ctx)
	if err != nil {
		return pluginsdk.Response{}, pluginsdk.Errorf("INTERNAL", "%s", err.Error())
	}
	sniRules, err := i.store.listSNIPassthroughs(ctx)
	if err != nil {
		return pluginsdk.Response{}, pluginsdk.Errorf("INTERNAL", "%s", err.Error())
	}
	cfg := i.currentConfig()
	boundAddr := i.currentBoundAddr()
	httpsBoundAddr := i.currentHTTPSBoundAddr()
	httpErr, httpsErr := i.currentListenErrors()
	nodeID = strings.TrimSpace(nodeID)
	if nodeID == "" {
		nodeID = "local"
	}
	return jsonResp(map[string]any{
		"backend":                      detectBackends(cfg.PreferredEngine),
		"running":                      boundAddr != "" || httpsBoundAddr != "",
		"node_id":                      nodeID,
		"config_revision":              i.currentConfigRevision(),
		"bound_addr":                   boundAddr,
		"https_bound_addr":             httpsBoundAddr,
		"configured_listen_addr":       cfg.ListenAddr,
		"configured_https_listen_addr": cfg.HTTPSListenAddr,
		"http_listen_error":            httpErr,
		"https_listen_error":           httpsErr,
		"active_routes":                i.proxy.ActiveCount(),
		"sites":                        sites,
		"snapshots":                    snaps,
		"sni_passthroughs":             sniRules,
	})
}

func (i *instance) handleAIDigest(ctx context.Context) (pluginsdk.Response, error) {
	sites, _ := i.store.listSites(ctx)
	snaps, _ := i.store.listSnapshots(ctx)
	enabled := 0
	noTLS := make([]string, 0)
	for _, s := range sites {
		if s.Enabled {
			enabled++
			if s.TLSMode == "off" {
				noTLS = append(noTLS, s.Domain)
			}
		}
	}
	return jsonResp(map[string]any{
		"engine":          detectBackends(i.currentConfig().PreferredEngine).ActiveEngine,
		"sites_total":     len(sites),
		"sites_enabled":   enabled,
		"active_routes":   i.proxy.ActiveCount(),
		"snapshots_count": len(snaps),
		"plain_http_list": noTLS,
	})
}

func (i *instance) handleSiteUpsert(ctx context.Context, payload []byte) (pluginsdk.Response, error) {
	var req struct {
		ID                  string            `json:"id"`
		Domain              string            `json:"domain"`
		Enabled             *bool             `json:"enabled"`
		UpstreamURL         string            `json:"upstream_url"`
		PathPrefix          string            `json:"path_prefix"`
		WebSocket           *bool             `json:"websocket"`
		TLSMode             string            `json:"tls_mode"`
		CertID              string            `json:"cert_id"`
		ForceHTTPS          *bool             `json:"force_https"`
		RateLimitRPS        int               `json:"rate_limit_rps"`
		RateLimitBurst      int               `json:"rate_limit_burst"`
		BasicAuthUser       string            `json:"basic_auth_user"`
		BasicAuthPass       string            `json:"basic_auth_pass"`
		ClearBasicAuth      bool              `json:"clear_basic_auth"`
		ExtraHeaders        map[string]string `json:"extra_headers"`
		UpstreamTLSInsecure bool              `json:"upstream_tls_insecure"`
		MaxBodyMB           int               `json:"max_body_mb"`
		Notes               string            `json:"notes"`
	}
	if err := json.Unmarshal(payload, &req); err != nil {
		return pluginsdk.Response{}, pluginsdk.Errorf("INVALID_ARGUMENT", "请求格式错误: %s", err.Error())
	}
	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}
	ws := true
	if req.WebSocket != nil {
		ws = *req.WebSocket
	}
	forceHTTPS := true
	if req.ForceHTTPS != nil {
		forceHTTPS = *req.ForceHTTPS
	}
	site, err := i.store.upsertSite(ctx, siteUpsertParams{
		ID:                  strings.TrimSpace(req.ID),
		Domain:              req.Domain,
		Enabled:             enabled,
		UpstreamURL:         req.UpstreamURL,
		PathPrefix:          req.PathPrefix,
		WebSocket:           ws,
		TLSMode:             req.TLSMode,
		CertID:              req.CertID,
		ForceHTTPS:          forceHTTPS,
		RateLimitRPS:        req.RateLimitRPS,
		RateLimitBurst:      req.RateLimitBurst,
		BasicAuthUser:       req.BasicAuthUser,
		BasicAuthPass:       req.BasicAuthPass,
		ClearBasicAuth:      req.ClearBasicAuth,
		ExtraHeaders:        req.ExtraHeaders,
		UpstreamTLSInsecure: req.UpstreamTLSInsecure,
		MaxBodyMB:           req.MaxBodyMB,
		Notes:               req.Notes,
	})
	if err != nil {
		return pluginsdk.Response{}, pluginsdk.Errorf("INVALID_ARGUMENT", "%s", err.Error())
	}
	if _, _, err := i.reloadAndRenderLocked(ctx); err != nil {
		return pluginsdk.Response{}, err
	}
	return jsonResp(map[string]any{"site": site})
}

func (i *instance) handleSiteDelete(ctx context.Context, payload []byte) (pluginsdk.Response, error) {
	var req struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(payload, &req); err != nil || strings.TrimSpace(req.ID) == "" {
		return pluginsdk.Response{}, pluginsdk.Errorf("INVALID_ARGUMENT", "缺少站点 id")
	}
	deleted, err := i.store.deleteSite(ctx, strings.TrimSpace(req.ID))
	if err != nil {
		return pluginsdk.Response{}, pluginsdk.Errorf("INTERNAL", "%s", err.Error())
	}
	if deleted {
		if _, _, err := i.reloadAndRenderLocked(ctx); err != nil {
			return pluginsdk.Response{}, err
		}
	}
	return jsonResp(map[string]any{"deleted": deleted, "id": strings.TrimSpace(req.ID)})
}

func (i *instance) handleConfigPreview(ctx context.Context) (pluginsdk.Response, error) {
	sites, err := i.store.listSites(ctx)
	if err != nil {
		return pluginsdk.Response{}, pluginsdk.Errorf("INTERNAL", "%s", err.Error())
	}
	return jsonResp(map[string]any{
		"backend":   detectBackends(i.currentConfig().PreferredEngine),
		"caddyfile": renderCaddyfile(sites, i.dataDir),
		"nginx":     renderNginxConfig(sites, i.dataDir),
	})
}

func syncSiteBindingsToSNI(sni *SNICertStore, sites []SiteRecord) {
	if sni == nil {
		return
	}
	bindings := make(map[string]string)
	var scanned []*LoadedMaterializedBinding
	scannedOnce := false
	for _, s := range sites {
		if !s.Enabled || s.TLSMode == "off" {
			continue
		}
		if ref := strings.TrimSpace(s.CertID); ref != "" {
			bindings[s.Domain] = ref
			continue
		}
		// cert_id 为空时按域名（精确 SNI 或叶证书 SAN/泛域名）自动匹配已物化证书
		if !scannedOnce {
			scanned = ScanAllActiveConsumerBindings(sni.dataDir)
			scannedOnce = true
		}
		normDom := normalizeSNIDomain(s.Domain)
		for _, mat := range scanned {
			if mat.SNI == normDom || (mat.Leaf != nil && mat.Leaf.VerifyHostname(normDom) == nil) {
				bindings[s.Domain] = mat.BindingID
				break
			}
		}
	}
	_, _ = sni.ReloadFromBindings(bindings)
}

func (i *instance) syncSNIMuxRoutes(ctx context.Context) {
	i.cfgMu.RLock()
	mux := i.sniMux
	i.cfgMu.RUnlock()
	if mux == nil {
		return
	}
	if rules, err := i.store.listSNIPassthroughs(ctx); err == nil {
		mux.SetRulesFromRecords(rules)
	}
}

func (i *instance) handleSNIPassthroughUpsert(ctx context.Context, payload []byte) (pluginsdk.Response, error) {
	var req struct {
		ID           string `json:"id"`
		SNIPattern   string `json:"sni_pattern"`
		UpstreamAddr string `json:"upstream_addr"`
		Enabled      *bool  `json:"enabled"`
		Notes        string `json:"notes"`
	}
	if err := json.Unmarshal(payload, &req); err != nil {
		return pluginsdk.Response{}, pluginsdk.Errorf("INVALID_ARGUMENT", "请求格式错误: %s", err.Error())
	}
	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}
	rule, err := i.store.upsertSNIPassthrough(ctx, req.ID, req.SNIPattern, req.UpstreamAddr, enabled, req.Notes)
	if err != nil {
		return pluginsdk.Response{}, pluginsdk.Errorf("INVALID_ARGUMENT", "%s", err.Error())
	}
	i.syncSNIMuxRoutes(ctx)
	return jsonResp(map[string]any{"rule": rule})
}

func (i *instance) handleSNIPassthroughDelete(ctx context.Context, payload []byte) (pluginsdk.Response, error) {
	var req struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(payload, &req); err != nil || strings.TrimSpace(req.ID) == "" {
		return pluginsdk.Response{}, pluginsdk.Errorf("INVALID_ARGUMENT", "缺少透传规则 id")
	}
	deleted, err := i.store.deleteSNIPassthrough(ctx, req.ID)
	if err != nil {
		return pluginsdk.Response{}, pluginsdk.Errorf("INTERNAL", "%s", err.Error())
	}
	if deleted {
		i.syncSNIMuxRoutes(ctx)
	}
	return jsonResp(map[string]any{"deleted": deleted, "id": strings.TrimSpace(req.ID)})
}

func (i *instance) reloadAndRenderLocked(ctx context.Context) (int, []string, error) {
	i.applyMu.Lock()
	defer i.applyMu.Unlock()

	sites, err := i.store.listSites(ctx)
	if err != nil {
		return 0, nil, pluginsdk.Errorf("INTERNAL", "%s", err.Error())
	}
	cfg := i.currentConfig()
	active := i.proxy.Reload(sites)
	syncSiteBindingsToSNI(i.sni, sites)
	i.syncSNIMuxRoutes(ctx)

	writtenFiles := make([]string, 0, 3)
	caddyOut := filepath.Join(i.dataDir, "rendered", "Caddyfile")
	nginxOut := filepath.Join(i.dataDir, "rendered", "nginx-ingress.conf")
	caddyText := renderCaddyfile(sites, i.dataDir)
	nginxText := renderNginxConfig(sites, i.dataDir)
	if err := atomicWriteFile(caddyOut, []byte(caddyText)); err != nil {
		return active, nil, pluginsdk.Errorf("INTERNAL", "写入 Caddyfile 失败: %s", err.Error())
	}
	writtenFiles = append(writtenFiles, caddyOut)
	if err := atomicWriteFile(nginxOut, []byte(nginxText)); err != nil {
		return active, nil, pluginsdk.Errorf("INTERNAL", "写入 Nginx 配置失败: %s", err.Error())
	}
	writtenFiles = append(writtenFiles, nginxOut)
	if exp := strings.TrimSpace(cfg.ExportConfigPath); exp != "" {
		content := caddyText
		if strings.EqualFold(cfg.PreferredEngine, "nginx") {
			content = nginxText
		}
		if err := atomicWriteFile(exp, []byte(content)); err != nil {
			return active, nil, pluginsdk.Errorf("INTERNAL", "同步外部配置失败: %s", err.Error())
		}
		writtenFiles = append(writtenFiles, exp)
	}
	return active, writtenFiles, nil
}

func (i *instance) handleApply(ctx context.Context) (pluginsdk.Response, error) {
	cfg := i.currentConfig()
	active, writtenFiles, err := i.reloadAndRenderLocked(ctx)
	if err != nil {
		return pluginsdk.Response{}, err
	}
	return jsonResp(map[string]any{
		"applied":       true,
		"active_routes": active,
		"engine":        detectBackends(cfg.PreferredEngine).ActiveEngine,
		"written_files": writtenFiles,
	})
}

func (i *instance) handleRollback(ctx context.Context, payload []byte) (pluginsdk.Response, error) {
	var req struct {
		SnapshotID string `json:"snapshot_id"`
		Revision   int    `json:"revision"`
	}
	if err := json.Unmarshal(payload, &req); err != nil {
		return pluginsdk.Response{}, pluginsdk.Errorf("INVALID_ARGUMENT", "请求格式错误: %s", err.Error())
	}
	if strings.TrimSpace(req.SnapshotID) == "" && req.Revision <= 0 {
		return pluginsdk.Response{}, pluginsdk.Errorf("INVALID_ARGUMENT", "必须提供 snapshot_id 或 revision")
	}
	snap, _, err := i.store.rollbackToSnapshot(ctx, strings.TrimSpace(req.SnapshotID), req.Revision)
	if err != nil {
		return pluginsdk.Response{}, pluginsdk.Errorf("NOT_FOUND", "%s", err.Error())
	}
	active, _, err := i.reloadAndRenderLocked(ctx)
	if err != nil {
		return pluginsdk.Response{}, err
	}
	return jsonResp(map[string]any{
		"rolled_back":   true,
		"snapshot":      snap,
		"active_routes": active,
	})
}

func (i *instance) handleTLSReload(_ context.Context, payload []byte) (pluginsdk.Response, error) {
	var req struct {
		BindingRef       string `json:"binding_ref"`
		ProfileID        string `json:"profile_id"`
		Generation       uint64 `json:"generation"`
		PolicyRevision   string `json:"policy_revision"`
		FullchainSHA256  string `json:"fullchain_sha256"`
		PrivateKeySHA256 string `json:"private_key_sha256"`
		SNI              string `json:"sni"`
	}
	if err := json.Unmarshal(payload, &req); err != nil {
		return pluginsdk.Response{}, pluginsdk.Errorf("INVALID_ARGUMENT", "TLS 热重载请求格式无效: %s", err.Error())
	}
	if strings.TrimSpace(req.BindingRef) == "" || strings.TrimSpace(req.SNI) == "" || req.Generation == 0 {
		return pluginsdk.Response{}, pluginsdk.Errorf("INVALID_ARGUMENT", "缺少 binding_ref / sni / generation")
	}
	obs, err := i.sni.LoadBinding(
		req.BindingRef,
		req.Generation,
		req.PolicyRevision,
		req.FullchainSHA256,
		req.PrivateKeySHA256,
		req.SNI,
		i.currentHTTPSBoundAddr(),
	)
	if err != nil {
		return pluginsdk.Response{}, pluginsdk.Errorf("FAILED_PRECONDITION", "加载宿主物化 TLS 证书失败: %s", err.Error())
	}
	return jsonResp(obs)
}

func (i *instance) handleTLSInspect(_ context.Context, payload []byte) (pluginsdk.Response, error) {
	var req struct {
		BindingRef string `json:"binding_ref"`
		ProfileID  string `json:"profile_id"`
	}
	if err := json.Unmarshal(payload, &req); err != nil || strings.TrimSpace(req.BindingRef) == "" {
		return pluginsdk.Response{}, pluginsdk.Errorf("INVALID_ARGUMENT", "缺少 binding_ref")
	}
	obs := i.sni.InspectBinding(req.BindingRef, i.currentHTTPSBoundAddr())
	return jsonResp(obs)
}

func requireHostACMEActor(call pluginsdk.Call) error {
	if call.Actor == nil || call.Actor.GetKind() != platformv1.ActorKind_ACTOR_KIND_SYSTEM || call.Actor.GetId() != "host:acme-http01" {
		return pluginsdk.Errorf("PERMISSION_DENIED", "ACME HTTP-01 验证通道仅允许宿主证书引擎内部调用")
	}
	return nil
}

func (i *instance) handleACMEPresent(_ context.Context, call pluginsdk.Call, payload []byte) (pluginsdk.Response, error) {
	if err := requireHostACMEActor(call); err != nil {
		return pluginsdk.Response{}, err
	}
	var req struct {
		Token      string `json:"token"`
		KeyAuth    string `json:"key_auth"`
		TTLSeconds int    `json:"ttl_seconds"`
	}
	if err := json.Unmarshal(payload, &req); err != nil {
		return pluginsdk.Response{}, pluginsdk.Errorf("INVALID_ARGUMENT", "ACME HTTP-01 请求格式无效: %s", err.Error())
	}
	boundAddr := i.currentBoundAddr()
	if boundAddr == "" {
		httpErr, _ := i.currentListenErrors()
		detail := "请先在 web.ingress 插件配置中启用 HTTP 80 端口监听（或释放被占用的 80 端口）"
		if httpErr != "" {
			detail = httpErr
		}
		return pluginsdk.Response{}, pluginsdk.Errorf("FAILED_PRECONDITION", "内置反代 HTTP 监听未就绪，无法执行 HTTP-01 验证：%s", detail)
	}
	ttl := time.Duration(req.TTLSeconds) * time.Second
	if err := i.proxy.ACMEStore().Present(req.Token, req.KeyAuth, ttl); err != nil {
		return pluginsdk.Response{}, pluginsdk.Errorf("INVALID_ARGUMENT", "%s", err.Error())
	}
	return jsonResp(map[string]any{
		"ok":         true,
		"token":      strings.TrimSpace(req.Token),
		"bound_addr": boundAddr,
	})
}

func (i *instance) handleACMECleanup(_ context.Context, call pluginsdk.Call, payload []byte) (pluginsdk.Response, error) {
	if err := requireHostACMEActor(call); err != nil {
		return pluginsdk.Response{}, err
	}
	var req struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(payload, &req); err != nil || strings.TrimSpace(req.Token) == "" {
		return pluginsdk.Response{}, pluginsdk.Errorf("INVALID_ARGUMENT", "缺少待清理的 token")
	}
	i.proxy.ACMEStore().CleanUp(req.Token)
	return jsonResp(map[string]any{
		"ok":    true,
		"token": strings.TrimSpace(req.Token),
	})
}

func (i *instance) handleUpstreamProbe(ctx context.Context, payload []byte) (pluginsdk.Response, error) {
	var req struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(payload, &req); err != nil || strings.TrimSpace(req.ID) == "" {
		return pluginsdk.Response{}, pluginsdk.Errorf("INVALID_ARGUMENT", "缺少站点 id")
	}
	sites, err := i.store.listSites(ctx)
	if err != nil {
		return pluginsdk.Response{}, pluginsdk.Errorf("INTERNAL", "%s", err.Error())
	}
	for _, s := range sites {
		if s.ID == strings.TrimSpace(req.ID) {
			return jsonResp(probeUpstream(ctx, s))
		}
	}
	return pluginsdk.Response{}, pluginsdk.Errorf("NOT_FOUND", "站点不存在")
}
