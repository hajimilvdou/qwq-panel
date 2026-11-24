// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	dockerv1 "github.com/qwq-panel/qwq/sdk/gen/qwq/capability/docker/v1"
	"github.com/qwq-panel/qwq/sdk/pluginsdk"
)

//go:embed manifest.json
var manifestJSON []byte

//go:embed schema.sql
var embeddedSchemaSQL string

var buildVersion string

// Manifest 返回内嵌的 containers.docker 插件清单字节。
func Manifest() []byte {
	raw := append([]byte(nil), manifestJSON...)
	if buildVersion != "" {
		raw = bytes.Replace(raw, []byte(`"version": "0.1.0"`), []byte(`"version": "`+buildVersion+`"`), 1)
	}
	return raw
}

type pluginConfig struct {
	DockerSocket       string `json:"docker_socket"`
	HTTPTimeoutSeconds int    `json:"http_timeout_seconds"`
}

func parseConfig(raw []byte) (pluginConfig, error) {
	cfg := pluginConfig{DockerSocket: defaultDockerSocket, HTTPTimeoutSeconds: 10}
	if len(bytes.TrimSpace(raw)) == 0 {
		return cfg, nil
	}
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return cfg, pluginsdk.Errorf("INVALID_ARGUMENT", "解析 containers.docker 配置失败: %s", err.Error())
	}
	if strings.TrimSpace(cfg.DockerSocket) == "" {
		cfg.DockerSocket = defaultDockerSocket
	}
	if cfg.HTTPTimeoutSeconds <= 0 || cfg.HTTPTimeoutSeconds > 60 {
		cfg.HTTPTimeoutSeconds = 10
	}
	return cfg, nil
}

// Plugin 实现轻量容器与 Compose 编排管理插件。
type Plugin struct {
	now func() time.Time
}

// New 构造默认 containers.docker 插件。
func New() *Plugin { return &Plugin{} }

func (p *Plugin) NewInstance(_ context.Context, info pluginsdk.InstanceInfo) (pluginsdk.Instance, error) {
	cfg, err := parseConfig(info.Config)
	if err != nil {
		return nil, err
	}
	nowFn := p.now
	if nowFn == nil {
		nowFn = time.Now
	}
	st, err := openStackStore(info.DataDir, embeddedSchemaSQL, nowFn)
	if err != nil {
		return nil, pluginsdk.Errorf("INTERNAL", "初始化 Compose 状态库失败: %s", err.Error())
	}
	base := pluginsdk.NewInstanceBase(info)
	inst := &instance{
		InstanceBase: base,
		cfg:          cfg,
		docker:       newDockerClient(cfg.DockerSocket, time.Duration(cfg.HTTPTimeoutSeconds)*time.Second, base.Host()),
		stacks:       st,
	}
	for _, op := range []string{
		"docker.stat.containers",
		"docker.checks.health",
		"docker.overview",
		"docker.ai.digest",
		"docker.container.inspect",
		"docker.container.settings.get",
		"docker.container.logs",
		"docker.container.action",
		"docker.container.limits",
		"docker.container.remove",
		"docker.images.prune",
		"docker.images.remove",
		"docker.volumes.prune",
		"docker.volumes.remove",
		"docker.compose.remove",
		"docker.network.list",
		"docker.network.create",
		"docker.network.membership",
		"docker.container.proxy.delete",
	} {
		opName := op
		inst.HandleInvoke(opName, func(c context.Context, req pluginsdk.Request) (pluginsdk.Response, error) {
			req.Operation = opName
			return inst.Invoke(c, req)
		})
	}
	inst.HandleJob("docker.compose.deploy", inst.handleComposeDeployJob)
	inst.HandleJob("docker.images.pull", inst.handleImagesPullJob)
	inst.HandleJob("docker.container.ports.apply", inst.handleContainerPortsApplyJob)
	inst.HandleJob("docker.container.proxy.upsert", inst.handleContainerProxyUpsertJob)
	inst.HandlePlan("docker.compose.deploy", inst.planComposeDeploy)
	return inst, nil
}

func (i *instance) planComposeDeploy(_ context.Context, req pluginsdk.Request) (pluginsdk.Plan, error) {
	var body struct {
		Name        string `json:"name"`
		ComposeYAML string `json:"compose_yaml"`
	}
	if err := json.Unmarshal(req.Payload, &body); err != nil {
		return pluginsdk.Plan{}, pluginsdk.Errorf("INVALID_ARGUMENT", "请求格式错误: %s", err.Error())
	}
	safeName, err := validateStackName(body.Name)
	if err != nil {
		return pluginsdk.Plan{}, pluginsdk.Errorf("INVALID_ARGUMENT", "%s", err.Error())
	}
	warnings, err := analyzeComposeYAML(body.ComposeYAML)
	if err != nil {
		return pluginsdk.Plan{}, pluginsdk.Errorf("INVALID_ARGUMENT", "%s", err.Error())
	}
	plan := pluginsdk.Plan{
		Changes: []pluginsdk.PlannedChange{{
			Kind:        pluginsdk.ChangeUpdate,
			Subject:     "compose_stacks/" + safeName,
			Reversible:  true,
			Description: fmt.Sprintf("保存并部署 Compose 编排栈 %s", safeName),
		}},
	}
	for _, w := range warnings {
		plan.Warnings = append(plan.Warnings, pluginsdk.FieldViolation{
			Pointer: "/compose_yaml",
			Code:    "SECURITY_WARNING",
			Message: w,
		})
	}
	return plan, nil
}

type instance struct {
	*pluginsdk.InstanceBase
	mu     sync.RWMutex
	cfg    pluginConfig
	docker *dockerClient
	stacks *stackStore
}

func (i *instance) currentDocker() *dockerClient {
	i.mu.RLock()
	defer i.mu.RUnlock()
	return i.docker
}

func (i *instance) Deactivate(_ context.Context) error {
	return nil
}

func (i *instance) Release(_ context.Context) error {
	if i.stacks == nil {
		return nil
	}
	return i.stacks.Close()
}

func (i *instance) ValidateConfig(_ context.Context, cand pluginsdk.Config) (pluginsdk.ConfigValidation, error) {
	if _, err := parseConfig(cand.JSON); err != nil {
		return pluginsdk.ConfigValidation{}, err
	}
	return pluginsdk.ConfigValidation{}, nil
}

func (i *instance) ApplyConfig(_ context.Context, cand pluginsdk.Config) error {
	cfg, err := parseConfig(cand.JSON)
	if err != nil {
		return err
	}
	nextClient := newDockerClient(cfg.DockerSocket, time.Duration(cfg.HTTPTimeoutSeconds)*time.Second, i.Host())
	i.mu.Lock()
	i.cfg = cfg
	i.docker = nextClient
	i.mu.Unlock()
	return nil
}

func (i *instance) Health(context.Context) pluginsdk.Health {
	return pluginsdk.Health{Message: "containers.docker 运行正常"}
}

func (i *instance) Invoke(ctx context.Context, req pluginsdk.Request) (pluginsdk.Response, error) {
	switch req.Operation {
	case "docker.stat.containers":
		return i.handleStatContainers(ctx)
	case "docker.checks.health":
		return i.handleChecksHealth(ctx)
	case "docker.overview":
		return i.handleOverview(ctx)
	case "docker.ai.digest":
		return i.handleAIDigest(ctx)
	case "docker.container.inspect":
		return i.handleContainerInspect(ctx, req.Payload)
	case "docker.container.settings.get":
		return i.handleContainerSettingsGet(ctx, req.Payload)
	case "docker.container.logs":
		return i.handleContainerLogs(ctx, req.Payload)
	case "docker.container.action":
		return i.handleContainerAction(ctx, req.Payload)
	case "docker.container.limits":
		return i.handleContainerLimits(ctx, req.Payload)
	case "docker.container.remove":
		return i.handleContainerRemove(ctx, req.Payload)
	case "docker.images.prune":
		return i.handleImagesPrune(ctx, req.Payload)
	case "docker.images.remove":
		return i.handleImagesRemove(ctx, req.Payload)
	case "docker.volumes.prune":
		return i.handleVolumesPrune(ctx)
	case "docker.volumes.remove":
		return i.handleVolumesRemove(ctx, req.Payload)
	case "docker.compose.deploy":
		return i.handleComposeDeploy(ctx, req.Payload)
	case "docker.compose.remove":
		return i.handleComposeRemove(ctx, req.Payload)
	case "docker.network.list":
		return i.handleNetworkList(ctx)
	case "docker.network.create":
		return i.handleNetworkCreate(ctx, req.Payload)
	case "docker.network.membership":
		return i.handleNetworkMembership(ctx, req.Payload)
	case "docker.container.proxy.delete":
		return i.handleContainerProxyDelete(ctx, req.Payload)
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

func (i *instance) handleStatContainers(ctx context.Context) (pluginsdk.Response, error) {
	info := i.currentDocker().probeInfo(ctx)
	if !info.Available {
		return jsonResp(map[string]any{
			"value":  "未连接",
			"unit":   "Docker 不可用",
			"status": "unknown",
			"detail": info.Reason,
		})
	}
	status := "ok"
	if info.ContainersStopped > 0 {
		status = "warn"
	}
	return jsonResp(map[string]any{
		"value":  fmt.Sprintf("%d / %d", info.ContainersRunning, info.ContainersTotal),
		"unit":   "运行中 / 总数",
		"status": status,
		"detail": fmt.Sprintf("Docker %s · 本地镜像 %d", info.ServerVersion, info.ImagesCount),
	})
}

func (i *instance) handleChecksHealth(ctx context.Context) (pluginsdk.Response, error) {
	dk := i.currentDocker()
	info := dk.probeInfo(ctx)
	if !info.Available {
		return jsonResp(map[string]any{
			"items": []map[string]any{{
				"name":    "dockerd",
				"status":  "unknown",
				"message": info.Reason,
			}},
		})
	}
	list, err := dk.listContainers(ctx)
	if err != nil {
		return pluginsdk.Response{}, pluginsdk.Errorf("UNAVAILABLE", "%s", err.Error())
	}
	items := make([]map[string]any, 0, len(list))
	for _, c := range list {
		st := "ok"
		if c.State != "running" {
			st = "warn"
		}
		if strings.Contains(strings.ToLower(c.Status), "unhealthy") {
			st = "error"
		}
		items = append(items, map[string]any{
			"name":    c.Name,
			"status":  st,
			"message": c.Status,
		})
	}
	return jsonResp(map[string]any{"items": items})
}

func (i *instance) handleOverview(ctx context.Context) (pluginsdk.Response, error) {
	dk := i.currentDocker()
	info := dk.probeInfo(ctx)
	containers := make([]ContainerSummary, 0)
	images := make([]ImageSummary, 0)
	volumes := make([]VolumeSummary, 0)
	if info.Available {
		if list, err := dk.listContainers(ctx); err == nil {
			containers = list
		}
		if imgs, err := dk.listImages(ctx); err == nil {
			images = imgs
		}
		if vols, err := dk.listVolumes(ctx); err == nil {
			volumes = vols
		}
	}
	stacks, err := i.stacks.listStacks(ctx)
	if err != nil {
		return pluginsdk.Response{}, pluginsdk.Errorf("INTERNAL", "%s", err.Error())
	}
	if info.Available {
		reconcileStackStatuses(stacks, containers)
	}
	composeAvail := dk.useHostCapability()
	if !composeAvail {
		composeBin, _ := detectComposeCmd()
		composeAvail = composeBin != ""
	}
	ingressLinks, err := ListAllContainerIngressLinksByName(ctx, i.stacks.db)
	if err != nil {
		ingressLinks = map[string][]ContainerIngressLink{}
	}
	return jsonResp(map[string]any{
		"daemon":            info,
		"compose_available": composeAvail,
		"containers":        containers,
		"images":            images,
		"volumes":           volumes,
		"stacks":            stacks,
		"ingress_links":     ingressLinks,
		"proxy_links":       ingressLinks,
	})
}

// reconcileStackStatuses 将实时容器运行状态对账回 compose_stacks 展示状态：
// 关联容器全停显示 stopped，存在退出或 unhealthy 容器时显示 degraded，全部健康运行显示 running。
func reconcileStackStatuses(stacks []ComposeStack, containers []ContainerSummary) {
	for idx := range stacks {
		proj := "qwq_" + stacks[idx].Name
		total, running, abnormal := 0, 0, 0
		for _, c := range containers {
			matched := c.ComposeProject == proj ||
				strings.HasPrefix(c.Name, proj+"-") ||
				strings.HasPrefix(c.Name, proj+"_")
			if !matched {
				continue
			}
			total++
			if c.State == "running" {
				running++
				if strings.Contains(strings.ToLower(c.Status), "unhealthy") {
					abnormal++
				}
			} else {
				abnormal++
			}
		}
		if total > 0 {
			switch {
			case running == 0:
				stacks[idx].Status = "stopped"
			case abnormal > 0:
				stacks[idx].Status = "degraded"
			default:
				stacks[idx].Status = "running"
			}
		} else if stacks[idx].Status == "running" {
			stacks[idx].Status = "stopped"
		}
	}
}

func (i *instance) handleAIDigest(ctx context.Context) (pluginsdk.Response, error) {
	dk := i.currentDocker()
	info := dk.probeInfo(ctx)
	stacks, _ := i.stacks.listStacks(ctx)
	anomalies := make([]map[string]any, 0)
	if info.Available {
		if list, err := dk.listContainers(ctx); err == nil {
			for _, c := range list {
				if c.State != "running" || strings.Contains(strings.ToLower(c.Status), "unhealthy") {
					anomalies = append(anomalies, map[string]any{
						"id": c.ShortID, "name": c.Name, "state": c.State, "status": c.Status,
					})
					if len(anomalies) >= 10 {
						break
					}
				}
			}
		}
	}
	return jsonResp(map[string]any{
		"daemon_available":   info.Available,
		"daemon_reason":      info.Reason,
		"containers_running": info.ContainersRunning,
		"containers_total":   info.ContainersTotal,
		"images_count":       info.ImagesCount,
		"stacks_count":       len(stacks),
		"anomalies":          anomalies,
	})
}

func (i *instance) handleContainerInspect(ctx context.Context, payload []byte) (pluginsdk.Response, error) {
	var req struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(payload, &req); err != nil {
		return pluginsdk.Response{}, pluginsdk.Errorf("INVALID_ARGUMENT", "请求格式错误")
	}
	ref, err := validateContainerRef(req.ID)
	if err != nil {
		return pluginsdk.Response{}, pluginsdk.Errorf("INVALID_ARGUMENT", "%s", err.Error())
	}
	detail, err := i.currentDocker().inspectWithStats(ctx, ref)
	if err != nil {
		return pluginsdk.Response{}, pluginsdk.Errorf("UNAVAILABLE", "%s", err.Error())
	}
	return jsonResp(map[string]any{"container": detail})
}

func (i *instance) handleContainerLogs(ctx context.Context, payload []byte) (pluginsdk.Response, error) {
	var req struct {
		ID   string `json:"id"`
		Tail int    `json:"tail"`
	}
	if err := json.Unmarshal(payload, &req); err != nil {
		return pluginsdk.Response{}, pluginsdk.Errorf("INVALID_ARGUMENT", "请求格式错误")
	}
	ref, err := validateContainerRef(req.ID)
	if err != nil {
		return pluginsdk.Response{}, pluginsdk.Errorf("INVALID_ARGUMENT", "%s", err.Error())
	}
	text, truncated, err := i.currentDocker().containerLogs(ctx, ref, req.Tail)
	if err != nil {
		return pluginsdk.Response{}, pluginsdk.Errorf("UNAVAILABLE", "%s", err.Error())
	}
	return jsonResp(map[string]any{
		"id":        ref,
		"logs":      text,
		"truncated": truncated,
	})
}

func (i *instance) handleContainerAction(ctx context.Context, payload []byte) (pluginsdk.Response, error) {
	var req struct {
		ID     string `json:"id"`
		Action string `json:"action"`
	}
	if err := json.Unmarshal(payload, &req); err != nil {
		return pluginsdk.Response{}, pluginsdk.Errorf("INVALID_ARGUMENT", "请求格式错误")
	}
	ref, err := validateContainerRef(req.ID)
	if err != nil {
		return pluginsdk.Response{}, pluginsdk.Errorf("INVALID_ARGUMENT", "%s", err.Error())
	}
	if err := i.currentDocker().containerAction(ctx, ref, req.Action); err != nil {
		return pluginsdk.Response{}, pluginsdk.Errorf("FAILED_PRECONDITION", "%s", err.Error())
	}
	return jsonResp(map[string]any{"ok": true, "id": ref, "action": req.Action})
}

func (i *instance) handleContainerLimits(ctx context.Context, payload []byte) (pluginsdk.Response, error) {
	var req struct {
		ID              string  `json:"id"`
		MemoryMB        int64   `json:"memory_mb"`
		CPUs            float64 `json:"cpus"`
		RestartPolicy   string  `json:"restart_policy"`
		RestartMaxRetry int     `json:"restart_max_retry"`
	}
	if err := json.Unmarshal(payload, &req); err != nil {
		return pluginsdk.Response{}, pluginsdk.Errorf("INVALID_ARGUMENT", "请求格式错误")
	}
	ref, err := validateContainerRef(req.ID)
	if err != nil {
		return pluginsdk.Response{}, pluginsdk.Errorf("INVALID_ARGUMENT", "%s", err.Error())
	}
	if req.MemoryMB < 0 || req.MemoryMB > 65536 || req.CPUs < 0 || req.CPUs > 64 {
		return pluginsdk.Response{}, pluginsdk.Errorf("INVALID_ARGUMENT", "资源限额参数超出允许范围")
	}
	if err := i.currentDocker().updateContainerLimits(ctx, ref, req.MemoryMB, req.CPUs, req.RestartPolicy, req.RestartMaxRetry); err != nil {
		return pluginsdk.Response{}, pluginsdk.Errorf("FAILED_PRECONDITION", "%s", err.Error())
	}
	return jsonResp(map[string]any{
		"ok":             true,
		"id":             ref,
		"memory_mb":      req.MemoryMB,
		"cpus":           req.CPUs,
		"restart_policy": strings.TrimSpace(req.RestartPolicy),
	})
}

func (i *instance) handleContainerRemove(ctx context.Context, payload []byte) (pluginsdk.Response, error) {
	var req struct {
		ID                   string `json:"id"`
		Force                bool   `json:"force"`
		CleanupLinkedProxies *bool  `json:"cleanup_linked_proxies"`
	}
	if err := json.Unmarshal(payload, &req); err != nil {
		return pluginsdk.Response{}, pluginsdk.Errorf("INVALID_ARGUMENT", "请求格式错误")
	}
	ref, err := validateContainerRef(req.ID)
	if err != nil {
		return pluginsdk.Response{}, pluginsdk.Errorf("INVALID_ARGUMENT", "%s", err.Error())
	}
	dk := i.currentDocker()
	targetName := normalizeContainerName(ref)
	if detail, ierr := dk.inspectWithStats(ctx, ref); ierr == nil && detail.Name != "" {
		targetName = normalizeContainerName(detail.Name)
	}
	if err := dk.removeContainer(ctx, ref, req.Force); err != nil {
		return pluginsdk.Response{}, pluginsdk.Errorf("FAILED_PRECONDITION", "%s", err.Error())
	}
	cleanup := true
	if req.CleanupLinkedProxies != nil {
		cleanup = *req.CleanupLinkedProxies
	}
	cleaned := 0
	if cleanup {
		cleaned, _ = CleanupProxiesForContainer(ctx, i.stacks.db, newHostPluginInvoker(i.Host()), targetName)
	}
	return jsonResp(map[string]any{"removed": true, "id": ref, "cleaned_proxies": cleaned})
}

func (i *instance) handleImagesPrune(ctx context.Context, payload []byte) (pluginsdk.Response, error) {
	var req struct {
		All bool `json:"all"`
	}
	if len(bytes.TrimSpace(payload)) > 0 {
		if err := json.Unmarshal(payload, &req); err != nil {
			return pluginsdk.Response{}, pluginsdk.Errorf("INVALID_ARGUMENT", "请求格式错误")
		}
	}
	res, err := i.currentDocker().pruneImages(ctx, req.All)
	if err != nil {
		return pluginsdk.Response{}, pluginsdk.Errorf("UNAVAILABLE", "%s", err.Error())
	}
	return jsonResp(res)
}

func (i *instance) handleImagesPullJob(ctx context.Context, req pluginsdk.Request, progress pluginsdk.Progress) (pluginsdk.Result, error) {
	var body struct {
		Image string `json:"image"`
	}
	if err := json.Unmarshal(req.Payload, &body); err != nil || strings.TrimSpace(body.Image) == "" {
		return pluginsdk.Result{}, pluginsdk.Errorf("INVALID_ARGUMENT", "缺少镜像名称 image")
	}
	ref, err := validateImagePullRef(body.Image)
	if err != nil {
		return pluginsdk.Result{}, pluginsdk.Errorf("INVALID_ARGUMENT", "%s", err.Error())
	}
	if progress != nil {
		_ = progress(pluginsdk.ProgressUpdate{Percent: 15, Step: "pull", Message: "正在拉取镜像 " + ref + "（大镜像最长支持 10 分钟）"})
	}
	statusText, err := i.currentDocker().pullImage(ctx, ref)
	if err != nil {
		return pluginsdk.Result{}, pluginsdk.Errorf("FAILED_PRECONDITION", "拉取镜像失败: %s", err.Error())
	}
	if progress != nil {
		_ = progress(pluginsdk.ProgressUpdate{Percent: 100, Step: "done", Message: "镜像拉取完成"})
	}
	raw, err := json.Marshal(map[string]any{"image": ref, "pulled": true, "status": statusText})
	if err != nil {
		return pluginsdk.Result{}, pluginsdk.Errorf("INTERNAL", "序列化响应失败")
	}
	return pluginsdk.Result{Payload: raw}, nil
}

func (i *instance) handleImagesRemove(ctx context.Context, payload []byte) (pluginsdk.Response, error) {
	var req struct {
		ID    string `json:"id"`
		Force bool   `json:"force"`
	}
	if err := json.Unmarshal(payload, &req); err != nil || strings.TrimSpace(req.ID) == "" {
		return pluginsdk.Response{}, pluginsdk.Errorf("INVALID_ARGUMENT", "缺少镜像 id")
	}
	ref, err := validateImageRef(req.ID)
	if err != nil {
		return pluginsdk.Response{}, pluginsdk.Errorf("INVALID_ARGUMENT", "%s", err.Error())
	}
	if err := i.currentDocker().removeImage(ctx, ref, req.Force); err != nil {
		return pluginsdk.Response{}, pluginsdk.Errorf("FAILED_PRECONDITION", "删除镜像失败: %s", err.Error())
	}
	return jsonResp(map[string]any{"removed": true, "id": ref})
}

func (i *instance) handleVolumesPrune(ctx context.Context) (pluginsdk.Response, error) {
	res, err := i.currentDocker().pruneVolumes(ctx)
	if err != nil {
		return pluginsdk.Response{}, pluginsdk.Errorf("UNAVAILABLE", "%s", err.Error())
	}
	return jsonResp(res)
}

func (i *instance) handleVolumesRemove(ctx context.Context, payload []byte) (pluginsdk.Response, error) {
	var req struct {
		Name  string `json:"name"`
		Force bool   `json:"force"`
	}
	if err := json.Unmarshal(payload, &req); err != nil || strings.TrimSpace(req.Name) == "" {
		return pluginsdk.Response{}, pluginsdk.Errorf("INVALID_ARGUMENT", "缺少存储卷名称 name")
	}
	if err := i.currentDocker().removeVolume(ctx, req.Name, req.Force); err != nil {
		return pluginsdk.Response{}, pluginsdk.Errorf("FAILED_PRECONDITION", "删除存储卷失败: %s", err.Error())
	}
	return jsonResp(map[string]any{"removed": true, "name": strings.TrimSpace(req.Name)})
}

func (i *instance) handleComposeDeployJob(ctx context.Context, req pluginsdk.Request, progress pluginsdk.Progress) (pluginsdk.Result, error) {
	if progress != nil {
		_ = progress(pluginsdk.ProgressUpdate{Percent: 10, Step: "validate", Message: "正在执行 Compose YAML 安全扫描并准备部署"})
	}
	resp, err := i.handleComposeDeploy(ctx, req.Payload)
	if err != nil {
		return pluginsdk.Result{}, err
	}
	if progress != nil {
		_ = progress(pluginsdk.ProgressUpdate{Percent: 100, Step: "done", Message: "Compose 编排栈部署完成"})
	}
	return pluginsdk.Result(resp), nil
}

func (i *instance) handleComposeDeploy(ctx context.Context, payload []byte) (pluginsdk.Response, error) {
	var req struct {
		Name        string `json:"name"`
		ComposeYAML string `json:"compose_yaml"`
		DryRun      bool   `json:"dry_run"`
	}
	if err := json.Unmarshal(payload, &req); err != nil {
		return pluginsdk.Response{}, pluginsdk.Errorf("INVALID_ARGUMENT", "请求格式错误: %s", err.Error())
	}
	warnings, err := analyzeComposeYAML(req.ComposeYAML)
	if err != nil {
		return pluginsdk.Response{}, pluginsdk.Errorf("INVALID_ARGUMENT", "%s", err.Error())
	}
	if req.DryRun {
		st, err := i.stacks.saveStack(ctx, req.Name, req.ComposeYAML, "saved", "", warnings)
		if err != nil {
			return pluginsdk.Response{}, pluginsdk.Errorf("INVALID_ARGUMENT", "%s", err.Error())
		}
		return jsonResp(map[string]any{"deployed": false, "dry_run": true, "stack": st})
	}
	if i.Host() != nil && i.Host().Conn() != nil {
		st, err := i.stacks.saveStack(ctx, req.Name, req.ComposeYAML, "saved", "", warnings)
		if err != nil {
			return pluginsdk.Response{}, pluginsdk.Errorf("INVALID_ARGUMENT", "%s", err.Error())
		}
		hc, err := i.Host().CapabilityContext(ctx)
		if err != nil {
			return pluginsdk.Response{}, err
		}
		resp, err := dockerv1.NewDockerServiceClient(i.Host().Conn()).ComposeAction(ctx, &dockerv1.ComposeActionRequest{
			Context:     hc,
			StackName:   st.Name,
			Action:      "up",
			YamlContent: req.ComposeYAML,
		})
		if err != nil {
			_, _ = i.stacks.saveStack(ctx, st.Name, req.ComposeYAML, "error", err.Error(), warnings)
			return pluginsdk.Response{}, pluginsdk.Errorf("FAILED_PRECONDITION", "docker compose up 失败: %s", err.Error())
		}
		if e := resp.GetError(); e != nil && e.GetCode() != "" {
			_, _ = i.stacks.saveStack(ctx, st.Name, req.ComposeYAML, "error", e.GetMessage(), warnings)
			return pluginsdk.Response{}, pluginsdk.Errorf(e.GetCode(), "docker compose up 失败: %s", e.GetMessage())
		}
		mergedWarnings := warnings
		if len(resp.GetWarnings()) > 0 {
			mergedWarnings = resp.GetWarnings()
		}
		st, _ = i.stacks.saveStack(ctx, st.Name, req.ComposeYAML, "running", "", mergedWarnings)
		return jsonResp(map[string]any{"deployed": true, "dry_run": false, "stack": st})
	}
	bin, baseArgs := detectComposeCmd()
	if bin == "" {
		st, _ := i.stacks.saveStack(ctx, req.Name, req.ComposeYAML, "saved", "宿主机未安装 docker compose CLI", warnings)
		return pluginsdk.Response{}, pluginsdk.Errorf("UNAVAILABLE", "宿主机未安装 docker compose，已将编排文件安全暂存至栈 %s", st.Name)
	}
	st, err := i.stacks.saveStack(ctx, req.Name, req.ComposeYAML, "saved", "", warnings)
	if err != nil {
		return pluginsdk.Response{}, pluginsdk.Errorf("INVALID_ARGUMENT", "%s", err.Error())
	}
	cctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	args := append(append([]string{}, baseArgs...), "-f", filepath.Join(st.WorkDir, "compose.yml"), "-p", "qwq_"+st.Name, "up", "-d", "--remove-orphans")
	cmd := exec.CommandContext(cctx, bin, args...)
	cmd.Dir = st.WorkDir
	outRing := newTailRingBuffer(maxLogBytes)
	cmd.Stdout = outRing
	cmd.Stderr = outRing
	runErr := cmd.Run()
	if runErr != nil {
		msg := strings.TrimSpace(outRing.String())
		if len(msg) > 512 {
			msg = msg[len(msg)-512:]
		}
		_, _ = i.stacks.saveStack(ctx, st.Name, req.ComposeYAML, "error", msg, warnings)
		return pluginsdk.Response{}, pluginsdk.Errorf("FAILED_PRECONDITION", "docker compose up 失败: %s", msg)
	}
	st, _ = i.stacks.saveStack(ctx, st.Name, req.ComposeYAML, "running", "", warnings)
	return jsonResp(map[string]any{"deployed": true, "dry_run": false, "stack": st})
}

func (i *instance) handleComposeRemove(ctx context.Context, payload []byte) (pluginsdk.Response, error) {
	var req struct {
		Name                 string `json:"name"`
		CleanupLinkedProxies *bool  `json:"cleanup_linked_proxies"`
	}
	if err := json.Unmarshal(payload, &req); err != nil || strings.TrimSpace(req.Name) == "" {
		return pluginsdk.Response{}, pluginsdk.Errorf("INVALID_ARGUMENT", "缺少栈名称 name")
	}
	safeName, err := validateStackName(req.Name)
	if err != nil {
		return pluginsdk.Response{}, pluginsdk.Errorf("INVALID_ARGUMENT", "%s", err.Error())
	}
	if i.Host() != nil && i.Host().Conn() != nil {
		if hc, hcErr := i.Host().CapabilityContext(ctx); hcErr == nil {
			_, _ = dockerv1.NewDockerServiceClient(i.Host().Conn()).ComposeAction(ctx, &dockerv1.ComposeActionRequest{
				Context:   hc,
				StackName: safeName,
				Action:    "down",
			})
		}
	} else if bin, baseArgs := detectComposeCmd(); bin != "" {
		workDir := filepath.Join(i.stacks.dataDir, "stacks", safeName)
		cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		args := append(append([]string{}, baseArgs...), "-f", filepath.Join(workDir, "compose.yml"), "-p", "qwq_"+safeName, "down")
		_ = exec.CommandContext(cctx, bin, args...).Run()
		cancel()
	}
	deleted, _, err := i.stacks.deleteStack(ctx, safeName)
	if err != nil {
		return pluginsdk.Response{}, pluginsdk.Errorf("INTERNAL", "%s", err.Error())
	}
	cleanup := true
	if req.CleanupLinkedProxies != nil {
		cleanup = *req.CleanupLinkedProxies
	}
	cleaned := 0
	if cleanup {
		cleaned, _ = CleanupProxiesForStack(ctx, i.stacks.db, newHostPluginInvoker(i.Host()), safeName)
	}
	return jsonResp(map[string]any{"removed": deleted, "name": safeName, "cleaned_proxies": cleaned})
}

// ======================== 容器设置五分页工作台、网络、端口与反代证书联动操作 ========================

func (i *instance) handleContainerSettingsGet(ctx context.Context, payload []byte) (pluginsdk.Response, error) {
	var req struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(payload, &req); err != nil {
		return pluginsdk.Response{}, pluginsdk.Errorf("INVALID_ARGUMENT", "请求格式错误")
	}
	ref, err := validateContainerRef(req.ID)
	if err != nil {
		return pluginsdk.Response{}, pluginsdk.Errorf("INVALID_ARGUMENT", "%s", err.Error())
	}
	dk := i.currentDocker()
	networksAll, err := dk.listNetworks(ctx)
	if err != nil {
		networksAll = []DockerNetworkSummary{}
	}
	bundle, err := dk.inspectContainerFull(ctx, ref, networksAll)
	if err != nil {
		return pluginsdk.Response{}, pluginsdk.Errorf("UNAVAILABLE", "%s", err.Error())
	}
	bindableIPs, err := dk.listBindableIPs(ctx)
	if err != nil {
		bindableIPs = fallbackLocalBindableIPs()
	}
	readiness := ProbeProxyIntegrationStatus(ctx, i.Host())
	links, err := ListContainerIngressLinks(ctx, i.stacks.db, bundle.Container.Name)
	if err != nil {
		links = []ContainerIngressLink{}
	}
	return jsonResp(map[string]any{
		"container":           bundle.Container,
		"port_rules":          bundle.PortRules,
		"image_exposed_ports": bundle.ImageExposedPorts,
		"host_bindable_ips":   bindableIPs,
		"networks_connected":  bundle.NetworksConnected,
		"networks_all":        networksAll,
		"mounts":              bundle.Mounts,
		"env":                 bundle.Env,
		"proxy_readiness":     readiness,
		"proxy_links":         links,
	})
}

func (i *instance) handleNetworkList(ctx context.Context) (pluginsdk.Response, error) {
	dk := i.currentDocker()
	networks, err := dk.listNetworks(ctx)
	if err != nil {
		return pluginsdk.Response{}, pluginsdk.Errorf("UNAVAILABLE", "%s", err.Error())
	}
	bindableIPs, err := dk.listBindableIPs(ctx)
	if err != nil {
		bindableIPs = fallbackLocalBindableIPs()
	}
	return jsonResp(map[string]any{
		"networks":     networks,
		"bindable_ips": bindableIPs,
	})
}

func (i *instance) handleNetworkCreate(ctx context.Context, payload []byte) (pluginsdk.Response, error) {
	var req struct {
		Name              string            `json:"name"`
		Driver            string            `json:"driver"`
		Subnet            string            `json:"subnet"`
		SubnetCIDR        string            `json:"subnet_cidr"`
		Gateway           string            `json:"gateway"`
		GatewayIP         string            `json:"gateway_ip"`
		Internal          bool              `json:"internal"`
		EnableIPv6        bool              `json:"enable_ipv6"`
		Labels            map[string]string `json:"labels"`
		AttachContainerID string            `json:"attach_container_id"`
	}
	if err := json.Unmarshal(payload, &req); err != nil {
		return pluginsdk.Response{}, pluginsdk.Errorf("INVALID_ARGUMENT", "请求格式错误")
	}
	netName, err := validateContainerRef(req.Name)
	if err != nil {
		return pluginsdk.Response{}, pluginsdk.Errorf("INVALID_ARGUMENT", "非法网络名称: %s", err.Error())
	}
	subnet := strings.TrimSpace(req.Subnet)
	if subnet == "" {
		subnet = strings.TrimSpace(req.SubnetCIDR)
	}
	gateway := strings.TrimSpace(req.Gateway)
	if gateway == "" {
		gateway = strings.TrimSpace(req.GatewayIP)
	}
	dk := i.currentDocker()
	netID, createdName, err := dk.createNetwork(ctx, createNetworkParams{
		Name:       netName,
		Driver:     req.Driver,
		Subnet:     subnet,
		Gateway:    gateway,
		Internal:   req.Internal,
		EnableIPv6: req.EnableIPv6,
		Labels:     req.Labels,
	})
	if err != nil {
		return pluginsdk.Response{}, pluginsdk.Errorf("FAILED_PRECONDITION", "%s", err.Error())
	}
	if createdName == "" {
		createdName = netName
	}
	attached := false
	if strings.TrimSpace(req.AttachContainerID) != "" {
		attachRef, aerr := validateContainerRef(req.AttachContainerID)
		if aerr != nil {
			return pluginsdk.Response{}, pluginsdk.Errorf("INVALID_ARGUMENT", "非法 attach_container_id")
		}
		if merr := dk.mutateContainerNetwork(ctx, mutateNetworkParams{
			ContainerID: attachRef,
			NetworkID:   createdName,
			Action:      "connect",
		}); merr != nil {
			return pluginsdk.Response{}, pluginsdk.Errorf("FAILED_PRECONDITION", "网络 %s 已创建，但自动接入容器失败: %s", createdName, merr.Error())
		}
		attached = true
	}
	return jsonResp(map[string]any{
		"network_id": netID,
		"name":       createdName,
		"attached":   attached,
	})
}

func (i *instance) handleNetworkMembership(ctx context.Context, payload []byte) (pluginsdk.Response, error) {
	var req struct {
		ContainerID string   `json:"container_id"`
		NetworkID   string   `json:"network_id"`
		Action      string   `json:"action"`
		Aliases     []string `json:"aliases"`
		IPv4Address string   `json:"ipv4_address"`
		IPv6Address string   `json:"ipv6_address"`
		Force       bool     `json:"force"`
	}
	if err := json.Unmarshal(payload, &req); err != nil {
		return pluginsdk.Response{}, pluginsdk.Errorf("INVALID_ARGUMENT", "请求格式错误")
	}
	ctRef, err := validateContainerRef(req.ContainerID)
	if err != nil {
		return pluginsdk.Response{}, pluginsdk.Errorf("INVALID_ARGUMENT", "非法容器标识")
	}
	netRef, err := validateContainerRef(req.NetworkID)
	if err != nil {
		return pluginsdk.Response{}, pluginsdk.Errorf("INVALID_ARGUMENT", "非法网络标识")
	}
	action := strings.ToLower(strings.TrimSpace(req.Action))
	if action != "connect" && action != "disconnect" {
		return pluginsdk.Response{}, pluginsdk.Errorf("INVALID_ARGUMENT", "action 仅支持 connect 或 disconnect")
	}
	if err := i.currentDocker().mutateContainerNetwork(ctx, mutateNetworkParams{
		ContainerID: ctRef,
		NetworkID:   netRef,
		Action:      action,
		Aliases:     req.Aliases,
		IPv4Address: strings.TrimSpace(req.IPv4Address),
		IPv6Address: strings.TrimSpace(req.IPv6Address),
		Force:       req.Force,
	}); err != nil {
		return pluginsdk.Response{}, pluginsdk.Errorf("FAILED_PRECONDITION", "%s", err.Error())
	}
	return jsonResp(map[string]any{
		"ok":           true,
		"container_id": ctRef,
		"network_id":   netRef,
		"action":       action,
	})
}

type applyPortsRequest struct {
	ContainerID               string            `json:"container_id"`
	Rules                     []PortMappingRule `json:"rules"`
	Bindings                  []PortMappingRule `json:"bindings"`
	CommitWritableLayer       bool              `json:"commit_writable_layer"`
	AllowDiscardWritableLayer bool              `json:"allow_discard_writable_layer"`
	StartAfterRecreate        *bool             `json:"start_after_recreate,omitempty"`
}

type applyPortsResult struct {
	OldContainerID    string            `json:"old_container_id"`
	NewContainerID    string            `json:"new_container_id"`
	ContainerName     string            `json:"container_name"`
	AppliedRules      []PortMappingRule `json:"applied_rules"`
	SyncedProxies     int               `json:"synced_proxies"`
	CommittedImage    string            `json:"committed_image,omitempty"`
	Warnings          []string          `json:"warnings,omitempty"`
	WritableSizeBytes int64             `json:"writable_size_bytes"`
}

func (i *instance) handleContainerPortsApplyJob(ctx context.Context, req pluginsdk.Request, progress pluginsdk.Progress) (pluginsdk.Result, error) {
	var in applyPortsRequest
	if err := json.Unmarshal(req.Payload, &in); err != nil {
		return pluginsdk.Result{}, pluginsdk.Errorf("INVALID_ARGUMENT", "请求格式错误: %s", err.Error())
	}
	res, err := i.applyContainerPorts(ctx, in, progress)
	if err != nil {
		return pluginsdk.Result{}, err
	}
	raw, err := json.Marshal(res)
	if err != nil {
		return pluginsdk.Result{}, pluginsdk.Errorf("INTERNAL", "序列化端口更新结果失败")
	}
	return pluginsdk.Result{Payload: raw}, nil
}

func (i *instance) applyContainerPorts(ctx context.Context, in applyPortsRequest, progress pluginsdk.Progress) (applyPortsResult, error) {
	ctRef, err := validateContainerRef(in.ContainerID)
	if err != nil {
		return applyPortsResult{}, pluginsdk.Errorf("INVALID_ARGUMENT", "非法容器标识")
	}
	rules := in.Rules
	if len(rules) == 0 && len(in.Bindings) > 0 {
		rules = in.Bindings
	}
	if len(rules) > 64 {
		return applyPortsResult{}, pluginsdk.Errorf("INVALID_ARGUMENT", "单容器最多配置 64 条端口映射规则")
	}

	reportProgress := func(pct uint32, step, msg string) {
		if progress != nil {
			_ = progress(pluginsdk.ProgressUpdate{Percent: pct, Step: step, Message: msg})
		}
	}

	reportProgress(10, "inspect", "检查容器类型与当前端口映射")
	dk := i.currentDocker()
	bundle, err := dk.inspectContainerFull(ctx, ctRef, nil)
	if err != nil {
		return applyPortsResult{}, pluginsdk.Errorf("FAILED_PRECONDITION", "读取容器配置失败: %s", err.Error())
	}

	inv := newHostPluginInvoker(i.Host())

	// 路径 A：受管 Compose 容器 -> 精准改写 compose.yml 并重拉防编排漂移
	if bundle.Container.StackName != "" && bundle.Container.ServiceName != "" {
		stackName := bundle.Container.StackName
		svcName := bundle.Container.ServiceName
		reportProgress(30, "compose_rewrite", fmt.Sprintf("同步改写受管 Compose 栈 %s 服务 %s 的 ports 配置", stackName, svcName))
		st, found, err := i.stacks.getStack(ctx, stackName)
		if err != nil {
			return applyPortsResult{}, pluginsdk.Errorf("INTERNAL", "读取 Compose 栈失败: %s", err.Error())
		}
		if !found {
			return applyPortsResult{}, pluginsdk.Errorf("NOT_FOUND", "未找到受管 Compose 栈 %s", stackName)
		}
		formatted := FormatComposePortItems(rules)
		newYAML, err := RewriteComposeServicePorts(st.ComposeYAML, svcName, formatted)
		if err != nil {
			return applyPortsResult{}, pluginsdk.Errorf("FAILED_PRECONDITION", "%s", err.Error())
		}
		warnings, err := analyzeComposeYAML(newYAML)
		if err != nil {
			return applyPortsResult{}, pluginsdk.Errorf("INVALID_ARGUMENT", "改写后的 Compose 配置未通过安全校验: %s", err.Error())
		}

		reportProgress(55, "compose_up", "平滑重拉 Compose 栈使新端口生效")
		if err := i.runComposeUp(ctx, stackName, newYAML, warnings); err != nil {
			return applyPortsResult{}, err
		}

		// 重新查询重建后的容器 ID 与实际生效端口
		reportProgress(80, "sync_ingress", "同步关联反向代理上游端口")
		newID := bundle.Container.ID
		appliedRules := rules
		if afterBundle, aerr := dk.inspectContainerFull(ctx, bundle.Container.Name, nil); aerr == nil {
			newID = afterBundle.Container.ID
			appliedRules = afterBundle.PortRules
		}
		portMap := buildPortTargetMap(appliedRules)
		synced, _ := SyncContainerProxyAfterPortChange(ctx, i.stacks.db, inv, bundle.Container.Name, portMap)
		reportProgress(100, "done", "受管 Compose 端口更新完成")
		return applyPortsResult{
			OldContainerID:    bundle.Container.ID,
			NewContainerID:    newID,
			ContainerName:     bundle.Container.Name,
			AppliedRules:      appliedRules,
			SyncedProxies:     synced,
			Warnings:          warnings,
			WritableSizeBytes: bundle.Container.WritableSizeBytes,
		}, nil
	}

	// 路径 B：独立容器 -> 调用宿主原子换名回滚重建 Saga
	reportProgress(40, "recreate", "正在通过宿主无损事务重建容器并应用端口映射")
	recRes, err := dk.recreateContainerPorts(ctx, recreatePortsParams{
		ContainerID:               bundle.Container.ID,
		Rules:                     rules,
		CommitWritableLayer:       in.CommitWritableLayer,
		AllowDiscardWritableLayer: in.AllowDiscardWritableLayer,
		StartAfterRecreate:        in.StartAfterRecreate,
	})
	if err != nil {
		return applyPortsResult{}, pluginsdk.Errorf("FAILED_PRECONDITION", "%s", err.Error())
	}

	reportProgress(85, "sync_ingress", "正在同步更新关联 web.ingress 反代上游端口")
	portMap := buildPortTargetMap(recRes.AppliedRules)
	synced, _ := SyncContainerProxyAfterPortChange(ctx, i.stacks.db, inv, recRes.ContainerName, portMap)
	reportProgress(100, "done", "端口映射已无损更新")
	return applyPortsResult{
		OldContainerID:    recRes.OldContainerID,
		NewContainerID:    recRes.NewContainerID,
		ContainerName:     recRes.ContainerName,
		AppliedRules:      recRes.AppliedRules,
		SyncedProxies:     synced,
		CommittedImage:    recRes.CommittedImage,
		Warnings:          recRes.Warnings,
		WritableSizeBytes: recRes.WritableSizeBytes,
	}, nil
}

func (i *instance) runComposeUp(ctx context.Context, stackName, yamlContent string, warnings []string) error {
	if i.Host() != nil && i.Host().Conn() != nil {
		st, err := i.stacks.saveStack(ctx, stackName, yamlContent, "saved", "", warnings)
		if err != nil {
			return pluginsdk.Errorf("INVALID_ARGUMENT", "%s", err.Error())
		}
		hc, err := i.Host().CapabilityContext(ctx)
		if err != nil {
			return err
		}
		resp, err := dockerv1.NewDockerServiceClient(i.Host().Conn()).ComposeAction(ctx, &dockerv1.ComposeActionRequest{
			Context:     hc,
			StackName:   st.Name,
			Action:      "up",
			YamlContent: yamlContent,
		})
		if err != nil {
			_, _ = i.stacks.saveStack(ctx, st.Name, yamlContent, "error", err.Error(), warnings)
			return pluginsdk.Errorf("FAILED_PRECONDITION", "docker compose up 失败: %s", err.Error())
		}
		if e := resp.GetError(); e != nil && e.GetCode() != "" {
			_, _ = i.stacks.saveStack(ctx, st.Name, yamlContent, "error", e.GetMessage(), warnings)
			return pluginsdk.Errorf(e.GetCode(), "docker compose up 失败: %s", e.GetMessage())
		}
		mergedWarnings := warnings
		if len(resp.GetWarnings()) > 0 {
			mergedWarnings = resp.GetWarnings()
		}
		_, _ = i.stacks.saveStack(ctx, st.Name, yamlContent, "running", "", mergedWarnings)
		return nil
	}
	bin, baseArgs := detectComposeCmd()
	if bin == "" {
		return pluginsdk.Errorf("UNAVAILABLE", "宿主机未安装 docker compose CLI")
	}
	st, err := i.stacks.saveStack(ctx, stackName, yamlContent, "saved", "", warnings)
	if err != nil {
		return pluginsdk.Errorf("INVALID_ARGUMENT", "%s", err.Error())
	}
	cctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	args := append(append([]string{}, baseArgs...), "-f", filepath.Join(st.WorkDir, "compose.yml"), "-p", "qwq_"+st.Name, "up", "-d", "--remove-orphans")
	cmd := exec.CommandContext(cctx, bin, args...)
	cmd.Dir = st.WorkDir
	outRing := newTailRingBuffer(maxLogBytes)
	cmd.Stdout = outRing
	cmd.Stderr = outRing
	if runErr := cmd.Run(); runErr != nil {
		msg := strings.TrimSpace(outRing.String())
		if len(msg) > 512 {
			msg = msg[len(msg)-512:]
		}
		_, _ = i.stacks.saveStack(ctx, st.Name, yamlContent, "error", msg, warnings)
		return pluginsdk.Errorf("FAILED_PRECONDITION", "docker compose up 失败: %s", msg)
	}
	_, _ = i.stacks.saveStack(ctx, st.Name, yamlContent, "running", "", warnings)
	return nil
}

func buildPortTargetMap(rules []PortMappingRule) map[uint16]PortTarget {
	out := make(map[uint16]PortTarget, len(rules))
	for _, r := range rules {
		if r.ContainerPort == 0 || r.HostPort == 0 {
			continue
		}
		proto := strings.ToLower(strings.TrimSpace(r.Protocol))
		if proto == "udp" {
			continue
		}
		if _, exists := out[r.ContainerPort]; !exists || r.BindMode == "loopback" {
			bindIP := r.BindIP
			if bindIP == "" || bindIP == "0.0.0.0" || bindIP == "::" {
				bindIP = "127.0.0.1"
			}
			out[r.ContainerPort] = PortTarget{BindIP: bindIP, HostPort: r.HostPort}
		}
	}
	return out
}

func (i *instance) handleContainerProxyUpsertJob(ctx context.Context, req pluginsdk.Request, progress pluginsdk.Progress) (pluginsdk.Result, error) {
	var in ContainerProxyUpsertRequest
	if err := json.Unmarshal(req.Payload, &in); err != nil {
		return pluginsdk.Result{}, pluginsdk.Errorf("INVALID_ARGUMENT", "请求格式错误: %s", err.Error())
	}
	ctRef, err := validateContainerRef(in.ContainerID)
	if err != nil {
		return pluginsdk.Result{}, pluginsdk.Errorf("INVALID_ARGUMENT", "非法容器标识")
	}
	if in.ContainerPort == 0 {
		return pluginsdk.Result{}, pluginsdk.Errorf("INVALID_ARGUMENT", "container_port 必须在 1..65535 之间")
	}
	if strings.TrimSpace(in.Domain) == "" {
		return pluginsdk.Result{}, pluginsdk.Errorf("INVALID_ARGUMENT", "domain 不能为空")
	}

	reportProgress := func(pct uint32, step, msg string) {
		if progress != nil {
			_ = progress(pluginsdk.ProgressUpdate{Percent: pct, Step: step, Message: msg})
		}
	}

	reportProgress(15, "inspect", "正在读取容器当前端口映射")
	dk := i.currentDocker()
	bundle, err := dk.inspectContainerFull(ctx, ctRef, nil)
	if err != nil {
		return pluginsdk.Result{}, pluginsdk.Errorf("FAILED_PRECONDITION", "读取容器配置失败: %s", err.Error())
	}

	strat := strings.TrimSpace(in.UpstreamPortStrategy)
	if strat == "" {
		var matched *PortMappingRule
		for idx := range bundle.PortRules {
			r := &bundle.PortRules[idx]
			if r.ContainerPort == in.ContainerPort && strings.ToLower(r.Protocol) != "udp" {
				matched = r
				if r.BindMode == "loopback" {
					break
				}
			}
		}
		if matched == nil {
			strat = "auto_map_loopback"
		} else if matched.BindMode == "public" && in.AutoClosePublicPort {
			strat = "converge_loopback"
		} else {
			strat = "use_existing"
			if in.ExistingHostPort == 0 {
				in.ExistingHostPort = matched.HostPort
			}
		}
	}

	nextContainerID := bundle.Container.ID
	var hostBindIP string
	var hostPort uint16
	var allWarnings []string

	switch strat {
	case "use_existing":
		for _, r := range bundle.PortRules {
			if r.ContainerPort == in.ContainerPort && strings.ToLower(r.Protocol) != "udp" {
				if in.ExistingHostPort == 0 || r.HostPort == in.ExistingHostPort {
					hostPort = r.HostPort
					hostBindIP = r.BindIP
					break
				}
			}
		}
		if hostPort == 0 && in.ExistingHostPort > 0 {
			hostPort = in.ExistingHostPort
			hostBindIP = "127.0.0.1"
		}
		if hostPort == 0 {
			return pluginsdk.Result{}, pluginsdk.Errorf("FAILED_PRECONDITION", "未找到容器端口 %d 对应的已映射宿主机端口", in.ContainerPort)
		}

	case "converge_loopback", "auto_map_loopback":
		nextRules := append([]PortMappingRule(nil), bundle.PortRules...)
		if strat == "converge_loopback" {
			found := false
			for idx := range nextRules {
				if nextRules[idx].ContainerPort == in.ContainerPort && strings.ToLower(nextRules[idx].Protocol) != "udp" {
					nextRules[idx].BindMode = "loopback"
					nextRules[idx].BindIP = "127.0.0.1"
					found = true
					break
				}
			}
			if !found {
				nextRules = append(nextRules, PortMappingRule{
					BindMode:      "loopback",
					BindIP:        "127.0.0.1",
					HostPort:      in.ExistingHostPort,
					ContainerPort: in.ContainerPort,
					Protocol:      "tcp",
				})
			}
		} else {
			nextRules = append(nextRules, PortMappingRule{
				BindMode:      "loopback",
				BindIP:        "127.0.0.1",
				HostPort:      0,
				ContainerPort: in.ContainerPort,
				Protocol:      "tcp",
			})
		}

		commitLayer := in.CommitWritableLayer
		if !commitLayer && !in.AllowDiscardWritableLayer && bundle.Container.WritableSizeBytes > 0 {
			commitLayer = true
		}
		reportProgress(35, "port_rebind", "正在将容器端口映射收敛至 127.0.0.1 本机安全回环")
		applyRes, aerr := i.applyContainerPorts(ctx, applyPortsRequest{
			ContainerID:               bundle.Container.ID,
			Rules:                     nextRules,
			CommitWritableLayer:       commitLayer,
			AllowDiscardWritableLayer: in.AllowDiscardWritableLayer,
		}, nil)
		if aerr != nil {
			return pluginsdk.Result{}, aerr
		}
		nextContainerID = applyRes.NewContainerID
		allWarnings = append(allWarnings, applyRes.Warnings...)
		for _, r := range applyRes.AppliedRules {
			if r.ContainerPort == in.ContainerPort && strings.ToLower(r.Protocol) != "udp" {
				hostPort = r.HostPort
				hostBindIP = r.BindIP
				if r.BindMode == "loopback" {
					break
				}
			}
		}
		if hostPort == 0 {
			return pluginsdk.Result{}, pluginsdk.Errorf("FAILED_PRECONDITION", "端口收敛后未能获取容器端口 %d 的回环映射端口", in.ContainerPort)
		}

	default:
		return pluginsdk.Result{}, pluginsdk.Errorf("INVALID_ARGUMENT", "不支持的 upstream_port_strategy %q", strat)
	}

	reportProgress(70, "ingress_upsert", "正在签发/复用证书并写入 web.ingress 反代站点")
	inv := newHostPluginInvoker(i.Host())
	link, proxyWarns, err := UpsertContainerProxyAndCert(ctx, i.stacks.db, inv, i.Host(), in, resolvedProxyTarget{
		ContainerName: bundle.Container.Name,
		StackName:     bundle.Container.StackName,
		ServiceName:   bundle.Container.ServiceName,
		ContainerPort: in.ContainerPort,
		HostBindIP:    hostBindIP,
		HostPort:      hostPort,
	})
	allWarnings = append(allWarnings, proxyWarns...)
	if err != nil {
		return pluginsdk.Result{}, pluginsdk.Errorf("FAILED_PRECONDITION", "%s", err.Error())
	}

	reportProgress(100, "done", "容器反向代理与证书联动配置完成")
	out, err := json.Marshal(map[string]any{
		"link":             link,
		"new_container_id": nextContainerID,
		"warnings":         allWarnings,
	})
	if err != nil {
		return pluginsdk.Result{}, pluginsdk.Errorf("INTERNAL", "序列化反代绑定结果失败")
	}
	return pluginsdk.Result{Payload: out}, nil
}

func (i *instance) handleContainerProxyDelete(ctx context.Context, payload []byte) (pluginsdk.Response, error) {
	var req struct {
		LinkID string `json:"link_id"`
		ID     string `json:"id"`
	}
	if err := json.Unmarshal(payload, &req); err != nil {
		return pluginsdk.Response{}, pluginsdk.Errorf("INVALID_ARGUMENT", "请求格式错误")
	}
	linkID := strings.TrimSpace(req.LinkID)
	if linkID == "" {
		linkID = strings.TrimSpace(req.ID)
	}
	if linkID == "" {
		return pluginsdk.Response{}, pluginsdk.Errorf("INVALID_ARGUMENT", "缺少 link_id")
	}
	deleted, err := DeleteContainerProxy(ctx, i.stacks.db, newHostPluginInvoker(i.Host()), linkID)
	if err != nil {
		return pluginsdk.Response{}, pluginsdk.Errorf("FAILED_PRECONDITION", "%s", err.Error())
	}
	return jsonResp(map[string]any{
		"deleted": deleted,
		"link_id": linkID,
	})
}
