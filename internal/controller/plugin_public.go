// SPDX-License-Identifier: AGPL-3.0-only

package controller

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/qwq-panel/qwq/internal/actor"
	"github.com/qwq-panel/qwq/internal/operations"
	"github.com/qwq-panel/qwq/internal/platform/problem"
	"github.com/qwq-panel/qwq/internal/pluginpublic"
	"github.com/qwq-panel/qwq/internal/sandbox"
	"github.com/qwq-panel/qwq/internal/secrets"
	platformv1 "github.com/qwq-panel/qwq/sdk/gen/qwq/platform/v1"
	"github.com/qwq-panel/qwq/sdk/manifest"
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
			if resp.Operation.Status == operations.Failed || resp.Operation.Status == operations.Rejected {
				msg := "core.apply failed"
				if resp.Operation.Error != nil && resp.Operation.Error.Detail != "" {
					msg = resp.Operation.Error.Detail
				}
				return revStr, applyOpID, problem.New(problem.PluginUnavailable, "%s", msg)
			}
		}
	}

	return revStr, applyOpID, nil
}
