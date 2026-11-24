// SPDX-License-Identifier: AGPL-3.0-only

package controller

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/qwq-panel/qwq/internal/actor"
	"github.com/qwq-panel/qwq/internal/operations"
	"github.com/qwq-panel/qwq/internal/platform/problem"
	"github.com/qwq-panel/qwq/internal/pluginhost/supervisor"
	"github.com/qwq-panel/qwq/internal/pluginpublic"
	"github.com/qwq-panel/qwq/internal/sandbox"
	"github.com/qwq-panel/qwq/internal/secrets"
	platformv1 "github.com/qwq-panel/qwq/sdk/gen/qwq/platform/v1"
	"github.com/qwq-panel/qwq/sdk/manifest"
	"github.com/qwq-panel/qwq/sdk/pluginsdk"
)

// ======================== ADR-0024 宿主公开 HTTP 路由转发 ========================

type publicRouteClient interface {
	ServePublicRoute(ctx context.Context, req *platformv1.ServePublicRouteRequest) (*platformv1.ServePublicRouteResponse, error)
}

// PublicGateway 返回绑定到本运行时的 /p/{plugin_id}/{route}/ 公开网关。
func (rt *PluginRuntime) PublicGateway() *pluginpublic.Gateway {
	if rt == nil {
		return nil
	}
	rt.mu.Lock()
	defer rt.mu.Unlock()
	if rt.publicGateway == nil {
		rt.publicGateway = pluginpublic.NewGateway(rt, rt.opts.Clock.Now)
	}
	return rt.publicGateway
}

// ServePublicRoute 实现 pluginpublic.Dispatcher：仅转发至已运行插件（live），绝不隐式拉起停用插件。
func (rt *PluginRuntime) ServePublicRoute(ctx context.Context, pluginID string, req pluginpublic.PublicRequest) (pluginpublic.PublicResponse, error) {
	client, err := rt.live(pluginID)
	if err != nil {
		return pluginpublic.PublicResponse{}, err
	}
	prClient, ok := client.(publicRouteClient)
	if !ok {
		return pluginpublic.PublicResponse{}, problem.New(problem.PluginUnavailable, "plugin does not support public routes")
	}

	headers := make([]*platformv1.HttpHeader, 0, 4)
	if req.UserAgent != "" {
		headers = append(headers, &platformv1.HttpHeader{Name: "User-Agent", Value: req.UserAgent})
	}
	if req.ContentType != "" {
		headers = append(headers, &platformv1.HttpHeader{Name: "Content-Type", Value: req.ContentType})
	}
	if req.ClientIP != "" {
		headers = append(headers, &platformv1.HttpHeader{Name: "X-QWQ-Client-IP", Value: req.ClientIP})
	}
	if req.RelayAuthBearer != "" {
		headers = append(headers, &platformv1.HttpHeader{Name: "X-QWQ-Relay-Token", Value: req.RelayAuthBearer})
		if strings.HasPrefix(req.RelayAuthBearer, "rly_sess_") {
			headers = append(headers, &platformv1.HttpHeader{Name: "X-Relay-Session", Value: req.RelayAuthBearer})
		}
	}
	for k, v := range req.ExtraHeaders {
		if v != "" {
			headers = append(headers, &platformv1.HttpHeader{Name: k, Value: v})
		}
	}

	resp, err := prClient.ServePublicRoute(ctx, &platformv1.ServePublicRouteRequest{
		Context: &platformv1.RequestContext{
			NodeId:     rt.opts.NodeID,
			InstanceId: DefaultInstanceID,
		},
		Route:    req.Route,
		Method:   req.Method,
		Path:     req.Path,
		RawQuery: req.RawQuery,
		Headers:  headers,
		Body:     req.Body,
	})
	if err != nil {
		return pluginpublic.PublicResponse{}, err
	}

	outHeaders := make(map[string]string, len(resp.GetHeaders()))
	for _, h := range resp.GetHeaders() {
		if h != nil && h.GetName() != "" {
			outHeaders[h.GetName()] = h.GetValue()
		}
	}
	return pluginpublic.PublicResponse{
		StatusCode: int(resp.GetStatus()),
		Headers:    outHeaders,
		Body:       resp.GetBody(),
	}, nil
}

var streamBufferPool = &bytesSlicePool{size: 32 << 10}

type bytesSlicePool struct {
	size int
	pool sync.Pool
}

func (p *bytesSlicePool) Get() []byte {
	if v := p.pool.Get(); v != nil {
		return *(v.(*[]byte))
	}
	return make([]byte, p.size)
}

func (p *bytesSlicePool) Put(b []byte) {
	if cap(b) >= p.size {
		b = b[:p.size]
		p.pool.Put(&b)
	}
}

var allowedPublicStreamResponseHeaders = map[string]struct{}{
	http.CanonicalHeaderKey("Content-Type"):            {},
	http.CanonicalHeaderKey("Content-Length"):          {},
	http.CanonicalHeaderKey("Content-Encoding"):        {},
	http.CanonicalHeaderKey("Cache-Control"):           {},
	http.CanonicalHeaderKey("ETag"):                    {},
	http.CanonicalHeaderKey("Last-Modified"):           {},
	http.CanonicalHeaderKey("Vary"):                    {},
	http.CanonicalHeaderKey("Content-Disposition"):     {},
	http.CanonicalHeaderKey("Location"):                {},
	http.CanonicalHeaderKey("Subscription-Userinfo"):   {},
	http.CanonicalHeaderKey("Profile-Update-Interval"): {},
	http.CanonicalHeaderKey("X-Request-Id"):            {},
	http.CanonicalHeaderKey("X-Relay-Request-Id"):      {},
	http.CanonicalHeaderKey("Anthropic-Version"):       {},
	http.CanonicalHeaderKey("Retry-After"):             {},
	http.CanonicalHeaderKey("X-Accel-Buffering"):       {},
}

func isAllowedPublicStreamResponseHeader(name string) bool {
	canon := http.CanonicalHeaderKey(strings.TrimSpace(name))
	if canon == "" {
		return false
	}
	if _, ok := allowedPublicStreamResponseHeaders[canon]; ok {
		return true
	}
	return strings.HasPrefix(canon, "X-Ratelimit-")
}

func sanitizePublicStreamResponseHeaders(h http.Header) {
	for k := range h {
		if !isAllowedPublicStreamResponseHeader(k) {
			h.Del(k)
		}
	}
}

func ensurePublicStreamSecurityHeaders(h http.Header) {
	if h.Get("X-Content-Type-Options") == "" {
		h.Set("X-Content-Type-Options", "nosniff")
	}
	if h.Get("X-Frame-Options") == "" {
		h.Set("X-Frame-Options", "SAMEORIGIN")
	}
	if h.Get("Referrer-Policy") == "" {
		h.Set("Referrer-Policy", "no-referrer")
	}
}

// resolvePublicStreamSocketPath checks the dedicated plugin-writable stream
// runtime directory (e.g. /run/qwq-plugin-stream-<id>/public-stream.sock)
// before falling back to HostDir/public-stream.sock.
func resolvePublicStreamSocketPath(runDir, pluginID string) string {
	hostSock := supervisor.HostSocketPath(runDir, pluginID)
	cleanRunDir := filepath.Clean(runDir)
	candidates := make([]string, 0, 3)
	if cleanRunDir != "" && cleanRunDir != "." {
		// Standard layout: runDir=/run/qwq -> runtimeBase=/run -> /run/qwq-plugin-stream-<id>/public-stream.sock
		candidates = append(candidates,
			filepath.Join(filepath.Dir(cleanRunDir), "qwq-plugin-stream-"+pluginID, pluginsdk.PublicStreamSocketName),
			filepath.Join(cleanRunDir, "qwq-plugin-stream-"+pluginID, pluginsdk.PublicStreamSocketName),
		)
	}
	candidates = append(candidates, filepath.Join(filepath.Dir(hostSock), pluginsdk.PublicStreamSocketName))

	for _, cand := range candidates {
		if st, err := os.Stat(cand); err == nil && (st.Mode()&os.ModeSocket) != 0 {
			return cand
		}
	}
	return ""
}

// ServePublicStream implements pluginpublic.StreamDispatcher for zero-buffer
// HTTP/SSE public routes over the plugin's private public-stream.sock UDS.
// When a plugin has not exposed public-stream.sock yet, it falls back cleanly
// to the buffered ABI route.
func (rt *PluginRuntime) ServePublicStream(
	ctx context.Context,
	pluginID string,
	req pluginpublic.PublicRequest,
	body io.Reader,
	w http.ResponseWriter,
) error {
	if err := sandbox.ValidateID(pluginID); err != nil {
		return problem.New(problem.ValidationFailed, "invalid plugin id")
	}
	if _, err := rt.live(pluginID); err != nil {
		return err
	}
	streamSock := resolvePublicStreamSocketPath(rt.opts.RunDir, pluginID)
	if streamSock == "" {
		return rt.fallbackBufferedPublicStream(ctx, pluginID, req, body, w)
	}

	targetPath := req.Path
	if !strings.HasPrefix(targetPath, "/") {
		targetPath = "/" + targetPath
	}
	if req.Route != "" && !strings.HasPrefix(targetPath, "/"+req.Route+"/") && targetPath != "/"+req.Route {
		targetPath = "/" + req.Route + targetPath
	}
	u := &url.URL{
		Scheme:   "http",
		Host:     pluginID + ".qwq.internal",
		Path:     targetPath,
		RawQuery: req.RawQuery,
	}

	outReq, err := http.NewRequestWithContext(ctx, req.Method, u.String(), body)
	if err != nil {
		return err
	}

	dialer := &net.Dialer{Timeout: 3 * time.Second, KeepAlive: 30 * time.Second}
	transport := &http.Transport{
		DialContext: func(dctx context.Context, _, _ string) (net.Conn, error) {
			return dialer.DialContext(dctx, "unix", streamSock)
		},
		DisableCompression:    true,
		MaxIdleConns:          8,
		IdleConnTimeout:       30 * time.Second,
		ResponseHeaderTimeout: 180 * time.Second,
	}
	defer transport.CloseIdleConnections()

	var proxyErr error
	ensurePublicStreamSecurityHeaders(w.Header())
	rp := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.Out.URL = u
			pr.Out.Host = u.Host
			injectCanonicalPublicHeaders(pr.Out.Header, req)
		},
		Transport:     transport,
		FlushInterval: -1,
		BufferPool:    streamBufferPool,
		ModifyResponse: func(resp *http.Response) error {
			sanitizePublicStreamResponseHeaders(resp.Header)
			sanitizePublicStreamResponseHeaders(resp.Trailer)
			return nil
		},
		ErrorHandler: func(_ http.ResponseWriter, _ *http.Request, e error) {
			proxyErr = e
		},
	}
	rp.ServeHTTP(w, outReq)
	if proxyErr != nil && !errors.Is(proxyErr, context.Canceled) {
		return fmt.Errorf("public stream proxy %s: %w", pluginID, proxyErr)
	}
	return nil
}

func injectCanonicalPublicHeaders(hdr http.Header, req pluginpublic.PublicRequest) {
	if req.UserAgent != "" {
		hdr.Set("User-Agent", req.UserAgent)
	}
	if req.ContentType != "" {
		hdr.Set("Content-Type", req.ContentType)
	}
	if req.ClientIP != "" {
		hdr.Set("X-QWQ-Client-IP", req.ClientIP)
	}
	if req.RelayAuthBearer != "" {
		hdr.Set("X-QWQ-Relay-Token", req.RelayAuthBearer)
		if strings.HasPrefix(req.RelayAuthBearer, "rly_sess_") {
			hdr.Set("X-Relay-Session", req.RelayAuthBearer)
		}
	}
	for k, v := range req.ExtraHeaders {
		if v != "" {
			hdr.Set(k, v)
		}
	}
}

func (rt *PluginRuntime) fallbackBufferedPublicStream(
	ctx context.Context,
	pluginID string,
	req pluginpublic.PublicRequest,
	body io.Reader,
	w http.ResponseWriter,
) error {
	if body != nil {
		raw, err := io.ReadAll(io.LimitReader(body, (4<<20)+1))
		if err != nil {
			return err
		}
		if len(raw) > (4 << 20) {
			http.Error(w, `{"error":"payload_exceeds_buffered_abi_limit"}`, http.StatusRequestEntityTooLarge)
			return nil
		}
		req.Body = raw
	}
	resp, err := rt.ServePublicRoute(ctx, pluginID, req)
	if err != nil {
		return err
	}
	ensurePublicStreamSecurityHeaders(w.Header())
	for k, v := range resp.Headers {
		if isAllowedPublicStreamResponseHeader(k) {
			w.Header().Set(k, v)
		}
	}
	code := resp.StatusCode
	if code < 100 || code > 599 {
		code = http.StatusOK
	}
	w.WriteHeader(code)
	_, _ = w.Write(resp.Body)
	return nil
}

var _ pluginpublic.StreamDispatcher = (*PluginRuntime)(nil)

// SyncPublicRoutes 扫描已安装活动插件的 manifest.json，按 public.route:<name> 能力原子重建公开路由表。
func (rt *PluginRuntime) SyncPublicRoutes() {
	if rt == nil || rt.opts.PluginsRoot == "" || rt.opts.PluginDir == nil {
		return
	}
	gw := rt.PublicGateway()
	entries, err := os.ReadDir(rt.opts.PluginsRoot)
	if err != nil {
		return
	}
	var specs []pluginpublic.RouteSpec
	for _, e := range entries {
		if !e.IsDir() || sandbox.ValidateID(e.Name()) != nil {
			continue
		}
		pluginID := e.Name()
		dir, err := rt.opts.PluginDir(pluginID)
		if err != nil {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
		if err != nil {
			continue
		}
		m, err := manifest.Parse(raw)
		if err != nil {
			continue
		}
		for _, capDecl := range m.Capabilities {
			if capDecl.Name != "public.route" || capDecl.Scope == "" {
				continue
			}
			spec := pluginpublic.RouteSpec{
				PluginID:        pluginID,
				Route:           capDecl.Scope,
				RateLimitPerMin: 60,
			}
			switch {
			case pluginID == "ai.relay" && (capDecl.Scope == "v1" || capDecl.Scope == "v1beta"):
				spec.Streaming = true
				spec.AllowCORS = true
				spec.RateLimitPerMin = 600
				spec.AllowedMethods = []string{http.MethodGet, http.MethodHead, http.MethodPost, http.MethodOptions}
			case pluginID == "ai.relay" && capDecl.Scope == "portal":
				spec.PortalSPA = true
				spec.RateLimitPerMin = 120
				spec.AllowedMethods = []string{http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut, http.MethodDelete}
			case pluginID == "server.probe" && capDecl.Scope == "portal":
				spec.PortalSPA = true
				spec.RateLimitPerMin = 120
				spec.AllowedMethods = []string{http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut, http.MethodDelete}
			case pluginID == "server.probe" && capDecl.Scope == "agent":
				spec.RateLimitPerMin = 600
				spec.AllowedMethods = []string{http.MethodPost}
			default:
				spec.AllowedMethods = []string{http.MethodGet, http.MethodHead}
			}
			specs = append(specs, spec)
		}
	}
	gw.ReplaceRoutes(specs)
}

// ======================== ADR-0023 H2 跨插件配置读写后端 ========================

type runtimePluginConfigBackend struct {
	rt *PluginRuntime
}

func (b *runtimePluginConfigBackend) GetPluginConfig(ctx context.Context, targetPluginID string) ([]byte, string, error) {
	if b.rt == nil {
		return nil, "", problem.New(problem.Unavailable, "plugin runtime is unavailable")
	}
	b.rt.mu.Lock()
	db := b.rt.deps.DB
	b.rt.mu.Unlock()
	if db == nil {
		return nil, "", problem.New(problem.Unavailable, "configuration database is unavailable")
	}
	var raw string
	var rev int64
	err := db.View(ctx, func(tx *sql.Tx) error {
		return tx.QueryRowContext(ctx,
			`SELECT config_json, revision FROM plugin_configs WHERE plugin_id = ? AND active = 1`,
			targetPluginID,
		).Scan(&raw, &rev)
	})
	if errors.Is(err, sql.ErrNoRows) {
		return []byte("{}"), "0", nil
	}
	if err != nil {
		return nil, "", problem.New(problem.Unavailable, "failed to load target plugin configuration")
	}
	return []byte(raw), strconv.FormatInt(rev, 10), nil
}

func (b *runtimePluginConfigBackend) PutPluginConfig(ctx context.Context, targetPluginID string, mergedJSON []byte, expectedRevision string, triggerApply bool) (string, string, error) {
	if b.rt == nil {
		return "", "", problem.New(problem.Unavailable, "plugin runtime is unavailable")
	}
	b.rt.mu.Lock()
	deps := b.rt.deps
	pluginDir := b.rt.opts.PluginDir
	nodeID := b.rt.opts.NodeID
	b.rt.mu.Unlock()
	if deps.DB == nil {
		return "", "", problem.New(problem.Unavailable, "configuration database is unavailable")
	}

	// 若目标插件提供了 config.schema.json 且宿主配置了 Secrets store，提取新写入的敏感明文为目标插件归属密文。
	toStore := mergedJSON
	var extracted []secrets.Extracted
	if deps.Secrets != nil && pluginDir != nil {
		if dir, err := pluginDir(targetPluginID); err == nil {
			schemaPath := filepath.Join(dir, "schemas", "config.schema.json")
			if schemaBytes, rerr := os.ReadFile(schemaPath); rerr == nil && len(schemaBytes) > 0 {
				redacted, ex, eerr := deps.Secrets.ExtractSecrets(ctx, schemaBytes, mergedJSON, secrets.ExtractOptions{
					Owner:                   "plugins/" + targetPluginID,
					Purpose:                 pluginSecretPurpose,
					AllowExistingReferences: true,
				})
				if eerr != nil {
					return "", "", eerr
				}
				toStore = redacted
				extracted = ex
			}
		}
	}

	shouldApply := false
	if triggerApply && deps.Ops != nil && deps.Catalog != nil {
		if _, ok := deps.Catalog.Get(targetPluginID + "/core.apply"); ok {
			shouldApply = true
		} else {
			if len(extracted) > 0 && deps.Secrets != nil {
				_ = deps.Secrets.DiscardExtracted(ctx, extracted)
			}
			return "", "", problem.New(problem.PluginUnavailable, "目标核心插件 %s 尚未安装或未启用", targetPluginID)
		}
	}

	// Commit DB revision (retaining last 5 revisions for secret GC) and sync
	// Updater's in-memory ActiveConfig cache immediately.
	revStr, _, err := CommitAndSyncPluginConfig(
		ctx,
		deps.DB,
		nil,
		deps.SyncActiveConfig,
		targetPluginID,
		toStore,
		expectedRevision,
		b.rt.opts.Clock.Now().UTC(),
		nodeID,
		false,
		nil,
	)
	if err != nil {
		if len(extracted) > 0 && deps.Secrets != nil {
			_ = deps.Secrets.DiscardExtracted(ctx, extracted)
		}
		return "", "", err
	}

	// 尽力通知正在运行的 live 目标插件更新内存 desired 快照（ApplyConfig）。
	type configApplier interface {
		ApplyConfig(ctx context.Context, req *platformv1.ApplyConfigRequest) (*platformv1.ApplyConfigResponse, error)
	}
	if client, lerr := b.rt.live(targetPluginID); lerr == nil {
		if applier, ok := client.(configApplier); ok {
			_, _ = applier.ApplyConfig(ctx, &platformv1.ApplyConfigRequest{
				Context:          &platformv1.RequestContext{NodeId: nodeID, InstanceId: DefaultInstanceID},
				ConfigJson:       toStore,
				ProposedRevision: revStr,
			})
		}
	}

	// 可选触发目标插件的受控重应用（例如 core.xray/core.apply），完整走 operations.Run 审计链并校验状态。
	var applyOpID string
	if shouldApply {
		actionID := targetPluginID + "/core.apply"
		payload, _ := json.Marshal(map[string]string{"config_revision": revStr})
		opCtx := operations.WithPermissionMode(ctx, operations.PermissionFull)
		resp, rerr := deps.Ops.Run(opCtx, operations.RunRequest{
			Actor:  actor.SystemActor("pluginconfig"),
			Action: actionID,
			NodeID: nodeID,
			Target: operations.Target{NodeID: nodeID, PluginID: targetPluginID, InstanceID: DefaultInstanceID},
			Args:   payload,
			Idempotency: operations.Idempotency{
				Key:    "pluginconfig-apply:" + targetPluginID + ":" + revStr,
				Method: "POST",
				Route:  "/internal/pluginconfig/apply",
			},
		})
		if rerr != nil {
			return revStr, "", problem.From(rerr)
		}
		if resp != nil && resp.Operation != nil {
			applyOpID = strings.TrimSpace(resp.Operation.ID)
			finalOp := resp.Operation
			// core.apply 为异步 mode="job"：短暂轮询至终态，让上游调用立即获知真实启动结果或报错细节。
			if applyOpID != "" && !isTerminalOperationStatus(finalOp.Status) {
				waitCtx, cancelWait := context.WithTimeout(ctx, 12*time.Second)
				ticker := time.NewTicker(150 * time.Millisecond)
				sysActor := actor.SystemActor("pluginconfig")
			waitLoop:
				for {
					select {
					case <-waitCtx.Done():
						break waitLoop
					case <-ticker.C:
						if cur, gerr := deps.Ops.Get(waitCtx, sysActor, applyOpID); gerr == nil && cur != nil {
							finalOp = cur
							if isTerminalOperationStatus(cur.Status) {
								break waitLoop
							}
						}
					}
				}
				ticker.Stop()
				cancelWait()
			}
			if finalOp.Status == operations.Failed || finalOp.Status == operations.Rejected ||
				finalOp.Status == operations.Canceled || finalOp.Status == operations.Expired {
				msg := "core.apply failed"
				if finalOp.Error != nil && finalOp.Error.Detail != "" {
					msg = finalOp.Error.Detail
				}
				return revStr, applyOpID, problem.New(problem.PluginUnavailable, "%s", msg)
			}
		}
	}

	return revStr, applyOpID, nil
}

func isTerminalOperationStatus(s operations.Status) bool {
	switch s {
	case operations.Succeeded, operations.Failed, operations.Canceled, operations.Rejected, operations.Expired:
		return true
	default:
		return false
	}
}
