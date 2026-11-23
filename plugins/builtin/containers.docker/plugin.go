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
	inst := &instance{
		InstanceBase: pluginsdk.NewInstanceBase(info),
		cfg:          cfg,
		docker:       newDockerClient(cfg.DockerSocket, time.Duration(cfg.HTTPTimeoutSeconds)*time.Second),
		stacks:       st,
	}
	for _, op := range []string{
		"docker.stat.containers",
		"docker.checks.health",
		"docker.overview",
		"docker.ai.digest",
		"docker.container.inspect",
		"docker.container.logs",
		"docker.container.action",
		"docker.container.limits",
		"docker.container.remove",
		"docker.images.prune",
		"docker.compose.deploy",
		"docker.compose.remove",
	} {
		opName := op
		inst.HandleInvoke(opName, func(c context.Context, req pluginsdk.Request) (pluginsdk.Response, error) {
			req.Operation = opName
			return inst.Invoke(c, req)
		})
	}
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
	nextClient := newDockerClient(cfg.DockerSocket, time.Duration(cfg.HTTPTimeoutSeconds)*time.Second)
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
	case "docker.compose.deploy":
		return i.handleComposeDeploy(ctx, req.Payload)
	case "docker.compose.remove":
		return i.handleComposeRemove(ctx, req.Payload)
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
	if info.Available {
		if list, err := dk.listContainers(ctx); err == nil {
			containers = list
		}
		if imgs, err := dk.listImages(ctx); err == nil {
			images = imgs
		}
	}
	stacks, err := i.stacks.listStacks(ctx)
	if err != nil {
		return pluginsdk.Response{}, pluginsdk.Errorf("INTERNAL", "%s", err.Error())
	}
	composeBin, _ := detectComposeCmd()
	return jsonResp(map[string]any{
		"daemon":            info,
		"compose_available": composeBin != "",
		"containers":        containers,
		"images":            images,
		"stacks":            stacks,
	})
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
		ID       string  `json:"id"`
		MemoryMB int64   `json:"memory_mb"`
		CPUs     float64 `json:"cpus"`
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
	if err := i.currentDocker().updateContainerLimits(ctx, ref, req.MemoryMB, req.CPUs); err != nil {
		return pluginsdk.Response{}, pluginsdk.Errorf("FAILED_PRECONDITION", "%s", err.Error())
	}
	return jsonResp(map[string]any{"ok": true, "id": ref, "memory_mb": req.MemoryMB, "cpus": req.CPUs})
}

func (i *instance) handleContainerRemove(ctx context.Context, payload []byte) (pluginsdk.Response, error) {
	var req struct {
		ID    string `json:"id"`
		Force bool   `json:"force"`
	}
	if err := json.Unmarshal(payload, &req); err != nil {
		return pluginsdk.Response{}, pluginsdk.Errorf("INVALID_ARGUMENT", "请求格式错误")
	}
	ref, err := validateContainerRef(req.ID)
	if err != nil {
		return pluginsdk.Response{}, pluginsdk.Errorf("INVALID_ARGUMENT", "%s", err.Error())
	}
	if err := i.currentDocker().removeContainer(ctx, ref, req.Force); err != nil {
		return pluginsdk.Response{}, pluginsdk.Errorf("FAILED_PRECONDITION", "%s", err.Error())
	}
	return jsonResp(map[string]any{"removed": true, "id": ref})
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
	bin, baseArgs := detectComposeCmd()
	if bin == "" {
		st, _ := i.stacks.saveStack(ctx, req.Name, req.ComposeYAML, "saved", "宿主机未安装 docker compose CLI", warnings)
		return pluginsdk.Response{}, pluginsdk.Errorf("UNAVAILABLE", "宿主机未安装 docker compose，已将编排文件安全暂存至栈 %s", st.Name)
	}
	st, err := i.stacks.saveStack(ctx, req.Name, req.ComposeYAML, "saved", "", warnings)
	if err != nil {
		return pluginsdk.Response{}, pluginsdk.Errorf("INVALID_ARGUMENT", "%s", err.Error())
	}
	cctx, cancel := context.WithTimeout(ctx, 60*time.Second)
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
		Name string `json:"name"`
	}
	if err := json.Unmarshal(payload, &req); err != nil || strings.TrimSpace(req.Name) == "" {
		return pluginsdk.Response{}, pluginsdk.Errorf("INVALID_ARGUMENT", "缺少栈名称 name")
	}
	safeName, err := validateStackName(req.Name)
	if err != nil {
		return pluginsdk.Response{}, pluginsdk.Errorf("INVALID_ARGUMENT", "%s", err.Error())
	}
	if bin, baseArgs := detectComposeCmd(); bin != "" {
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
	return jsonResp(map[string]any{"removed": deleted, "name": safeName})
}
