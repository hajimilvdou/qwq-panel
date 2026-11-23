// SPDX-License-Identifier: AGPL-3.0-only

// Package docker 实现受控宿主 Docker 能力执行器（PLG-FIX-04 / PLG-FIX-05）：
// 在 socket 激活的 qwq-capability 中以固定 /var/run/docker.sock 与严格端点白名单代理 Engine API，
// 并在插件 32 MiB cgroup 之外执行经过二次 YAML 安全扫描的 docker compose 编排。
package docker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/qwq-panel/qwq/internal/sandbox"
)

const (
	DefaultDockerSocket = "/var/run/docker.sock"
	DefaultStacksRoot   = "/var/lib/qwq-plugin-data/containers.docker/default/stacks"
	// maxProxyResponseBytes 保证 base64 编码进 helper JSON 后仍严格低于 1 MiB MaxHelperMessage。
	maxProxyResponseBytes = 512 << 10
)

var (
	containerRefPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)
	stackNamePattern    = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,47}$`)
)

// ProxyAPIInput 是 docker.api.read / docker.api.write 的结构化入参。
type ProxyAPIInput struct {
	Method   string `json:"method"`
	Path     string `json:"path"`
	RawQuery string `json:"raw_query,omitempty"`
	Body     []byte `json:"body,omitempty"`
}

// ProxyAPIOutput 是 docker.api.read / docker.api.write 的结构化出参。
type ProxyAPIOutput struct {
	StatusCode int    `json:"status_code"`
	Body       []byte `json:"body,omitempty"`
}

// ComposeInput 是 docker.compose 的结构化入参。
type ComposeInput struct {
	StackName   string `json:"stack_name"`
	Action      string `json:"action"`
	YAMLContent string `json:"yaml_content,omitempty"`
}

// ComposeOutput 是 docker.compose 的结构化出参。
type ComposeOutput struct {
	Output   string   `json:"output"`
	Warnings []string `json:"warnings,omitempty"`
}

// ControlledDockerCapabilityRunner 运行在 socket 激活的 qwq-capability（euid=0，请求间零常驻内存）中：
//  1. 固定连接 /var/run/docker.sock（绝不接受插件传入任意 socket 路径）；
//  2. 仅转发白名单 REST 端点，严禁暴露 /containers/create、/exec、/volumes/create 等特权逃逸端点；
//  3. docker.compose 在执行前二次核验 ValidateComposeYAMLStrict，并以干净环境运行 docker compose，
//     清除 GOMEMLIMIT 污染避免 32M cgroup OOMKill。
type ControlledDockerCapabilityRunner struct {
	SocketPath string // 默认固定 "/var/run/docker.sock"
	StacksRoot string // 默认固定 "/var/lib/qwq-plugin-data/containers.docker/default/stacks"

	// composeRunner 仅用于测试注入，生产留 nil 走系统 docker CLI。
	composeRunner func(ctx context.Context, workDir string, env []string, args []string) (string, error)
}

func (r *ControlledDockerCapabilityRunner) dialClient(timeout time.Duration) *http.Client {
	sock := r.SocketPath
	if sock == "" {
		sock = DefaultDockerSocket
	}
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			Proxy: nil,
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, "unix", sock)
			},
			MaxIdleConns:    2,
			IdleConnTimeout: 10 * time.Second,
		},
	}
}

// ProxyAllowlistedRequest 严格校验白名单方法与路径后请求宿主 Docker Engine API。
func (r *ControlledDockerCapabilityRunner) ProxyAllowlistedRequest(
	ctx context.Context,
	method string,
	cleanRelPath string,
	query url.Values,
	jsonBody []byte,
) (int, []byte, error) {
	if !isAllowedDockerEndpoint(method, cleanRelPath) {
		return 0, nil, errors.New("DOCKER_ENDPOINT_FORBIDDEN: 该 Docker API 端点不在受控白名单内")
	}
	u := &url.URL{
		Scheme:   "http",
		Host:     "docker",
		Path:     "/v1.41" + cleanRelPath,
		RawQuery: query.Encode(),
	}
	var bodyReader io.Reader
	if len(jsonBody) > 0 {
		bodyReader = bytes.NewReader(jsonBody)
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), bodyReader)
	if err != nil {
		return 0, nil, err
	}
	if len(jsonBody) > 0 {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := r.dialClient(25 * time.Second).Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxProxyResponseBytes))
	return resp.StatusCode, raw, err
}

func isAllowedDockerEndpoint(method, p string) bool {
	if p == "" || !strings.HasPrefix(p, "/") || strings.ContainsAny(p, "?#\r\n\t\x00\\ ") || strings.Contains(p, "..") {
		return false
	}
	if path.Clean(p) != p {
		return false
	}
	segs := strings.Split(strings.TrimPrefix(p, "/"), "/")
	switch method {
	case http.MethodGet:
		if p == "/info" || p == "/containers/json" || p == "/images/json" {
			return true
		}
		if len(segs) == 3 && segs[0] == "containers" && isValidContainerID(segs[1]) {
			return segs[2] == "json" || segs[2] == "stats" || segs[2] == "logs"
		}
		return false
	case http.MethodPost:
		if p == "/images/prune" {
			return true
		}
		if len(segs) == 3 && segs[0] == "containers" && isValidContainerID(segs[1]) {
			return segs[2] == "start" || segs[2] == "stop" || segs[2] == "restart" || segs[2] == "update"
		}
		return false
	case http.MethodDelete:
		return len(segs) == 2 && segs[0] == "containers" && isValidContainerID(segs[1])
	default:
		return false
	}
}

func isValidContainerID(id string) bool {
	return containerRefPattern.MatchString(id) && !strings.Contains(id, "..")
}

// ExecuteVerifiedCompose 在宿主 helper 侧二次核验 YAML 后执行受管栈编排（最长 85s，有界输出 64KiB）。
func (r *ControlledDockerCapabilityRunner) ExecuteVerifiedCompose(
	ctx context.Context,
	stackName string,
	yamlContent string,
	action string, // "up" | "down"
) (string, []string, error) {
	safeName := strings.ToLower(strings.TrimSpace(stackName))
	if !stackNamePattern.MatchString(safeName) {
		return "", nil, errors.New("非法的 Compose 栈名称")
	}
	var warnings []string
	if action == "up" {
		var err error
		warnings, err = ValidateComposeYAMLStrict(yamlContent)
		if err != nil {
			return "", nil, err
		}
	} else if action != "down" {
		return "", nil, errors.New("unsupported compose action")
	}

	stacksRoot := r.StacksRoot
	if stacksRoot == "" {
		stacksRoot = DefaultStacksRoot
	}
	workDir := filepath.Join(stacksRoot, safeName)
	if action == "up" {
		if err := os.MkdirAll(workDir, 0o755); err != nil {
			return "", nil, fmt.Errorf("准备 Compose 工作目录失败: %w", err)
		}
	}

	// 将已通过 ValidateComposeYAMLStrict 核验的 YAML 写入独立临时文件，
	// 消除磁盘 compose.yml 的 TOCTOU 替换风险，且不在插件 StateDirectory 内遗留 root 属主文件。
	var tmpComposePath string
	if action == "up" || strings.TrimSpace(yamlContent) != "" {
		if action == "down" && strings.TrimSpace(yamlContent) != "" {
			if _, err := ValidateComposeYAMLStrict(yamlContent); err != nil {
				return "", nil, err
			}
		}
		tmpFile, err := os.CreateTemp("", "qwq-compose-*.yml")
		if err != nil {
			return "", nil, fmt.Errorf("创建临时编排文件失败: %w", err)
		}
		tmpComposePath = tmpFile.Name()
		defer func() { _ = os.Remove(tmpComposePath) }()
		if _, err := tmpFile.WriteString(yamlContent); err != nil {
			_ = tmpFile.Close()
			return "", nil, fmt.Errorf("写入临时编排文件失败: %w", err)
		}
		if err := tmpFile.Close(); err != nil {
			return "", nil, err
		}
	}

	sock := r.SocketPath
	if sock == "" {
		sock = DefaultDockerSocket
	}
	args := []string{"compose", "-p", "qwq_" + safeName}
	if tmpComposePath != "" {
		args = append(args, "--project-directory", workDir, "-f", tmpComposePath)
	}
	switch action {
	case "up":
		args = append(args, "up", "-d", "--remove-orphans")
	case "down":
		args = append(args, "down", "--remove-orphans")
	}

	// 显式构造干净环境变量，剔除小内存 GOMEMLIMIT 污染，确保 docker compose 在 1C1G 上稳定运行。
	env := []string{
		"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
		"HOME=/tmp",
		"DOCKER_HOST=unix://" + sock,
	}

	runCtx, cancel := context.WithTimeout(ctx, 85*time.Second)
	defer cancel()

	if r.composeRunner != nil {
		out, err := r.composeRunner(runCtx, workDir, env, args)
		return out, warnings, err
	}

	bin, err := exec.LookPath("docker")
	if err != nil {
		return "", nil, errors.New("未检测到宿主 docker CLI")
	}
	cmd := exec.CommandContext(runCtx, bin, args...)
	if st, statErr := os.Stat(workDir); statErr == nil && st.IsDir() {
		cmd.Dir = workDir
	}
	cmd.Env = env
	var out bytes.Buffer
	lim := &boundedWriter{buf: &out, max: MaxComposeOutput}
	cmd.Stdout = lim
	cmd.Stderr = lim
	err = cmd.Run()
	return out.String(), warnings, err
}

type boundedWriter struct {
	buf *bytes.Buffer
	max int
}

func (w *boundedWriter) Write(p []byte) (int, error) {
	rem := w.max - w.buf.Len()
	if rem > 0 {
		if len(p) > rem {
			_, _ = w.buf.Write(p[:rem])
		} else {
			_, _ = w.buf.Write(p)
		}
	}
	return len(p), nil
}

// Service 将 ControlledDockerCapabilityRunner 适配为 sandbox.CapabilityRunner。
type Service struct {
	Runner *ControlledDockerCapabilityRunner
}

// NewService 创建默认固定宿主机路径的受控 Docker 能力服务。
func NewService() *Service {
	return &Service{
		Runner: &ControlledDockerCapabilityRunner{
			SocketPath: DefaultDockerSocket,
			StacksRoot: DefaultStacksRoot,
		},
	}
}

// Run 处理 docker.api.read / docker.api.write / docker.compose 封闭能力 verb。
func (s *Service) Run(ctx context.Context, req sandbox.CapabilityRequest) (sandbox.CapabilityResponse, error) {
	if s == nil || s.Runner == nil {
		return sandbox.CapabilityResponse{Code: "UNAVAILABLE", Error: "受控 Docker 能力服务未配置"}, nil
	}
	switch req.Op {
	case "docker.api.read":
		return s.handleProxyAPI(ctx, req.ParamsJSON, false)
	case "docker.api.write":
		return s.handleProxyAPI(ctx, req.ParamsJSON, true)
	case "docker.compose":
		return s.handleCompose(ctx, req.ParamsJSON)
	default:
		return sandbox.CapabilityResponse{Code: "UNIMPLEMENTED", Error: "不支持的 docker 能力操作"}, nil
	}
}

func (s *Service) handleProxyAPI(ctx context.Context, payload []byte, write bool) (sandbox.CapabilityResponse, error) {
	var in ProxyAPIInput
	if err := sandbox.DecodeHelperDocument(payload, &in); err != nil {
		return sandbox.CapabilityResponse{Code: "VALIDATION_FAILED", Error: "docker API 请求参数格式无效"}, nil
	}
	method := strings.ToUpper(strings.TrimSpace(in.Method))
	if !write {
		if method == "" {
			method = http.MethodGet
		}
		if method != http.MethodGet {
			return sandbox.CapabilityResponse{Code: "PERMISSION_DENIED", Error: "只读 Docker 能力仅允许 GET 请求"}, nil
		}
	} else {
		if method != http.MethodPost && method != http.MethodDelete {
			return sandbox.CapabilityResponse{Code: "PERMISSION_DENIED", Error: "写 Docker 能力仅允许 POST 或 DELETE 请求"}, nil
		}
	}
	if !isAllowedDockerEndpoint(method, in.Path) {
		return sandbox.CapabilityResponse{Code: "PERMISSION_DENIED", Error: "DOCKER_ENDPOINT_FORBIDDEN: 该 Docker API 端点不在受控白名单内"}, nil
	}
	query, err := url.ParseQuery(in.RawQuery)
	if err != nil {
		return sandbox.CapabilityResponse{Code: "VALIDATION_FAILED", Error: "查询参数格式无效"}, nil
	}
	code, body, err := s.Runner.ProxyAllowlistedRequest(ctx, method, in.Path, query, in.Body)
	if err != nil {
		return sandbox.CapabilityResponse{Code: "UNAVAILABLE", Error: err.Error()}, nil
	}
	return okResponse(ProxyAPIOutput{StatusCode: code, Body: body})
}

func (s *Service) handleCompose(ctx context.Context, payload []byte) (sandbox.CapabilityResponse, error) {
	var in ComposeInput
	if err := sandbox.DecodeHelperDocument(payload, &in); err != nil {
		return sandbox.CapabilityResponse{Code: "VALIDATION_FAILED", Error: "docker.compose 请求参数格式无效"}, nil
	}
	action := strings.ToLower(strings.TrimSpace(in.Action))
	if action != "up" && action != "down" {
		return sandbox.CapabilityResponse{Code: "VALIDATION_FAILED", Error: "docker.compose 仅支持 up 或 down"}, nil
	}
	out, warnings, err := s.Runner.ExecuteVerifiedCompose(ctx, in.StackName, in.YAMLContent, action)
	if err != nil {
		msg := strings.TrimSpace(out)
		if msg == "" {
			msg = err.Error()
		}
		if len(msg) > 512 {
			msg = msg[len(msg)-512:]
		}
		errCode := "FAILED_PRECONDITION"
		if action == "up" && out == "" {
			// YAML 校验或栈名校验失败归入 VALIDATION_FAILED。
			if strings.Contains(err.Error(), "compose_yaml") || strings.Contains(err.Error(), "第 ") || strings.Contains(err.Error(), "栈名称") {
				errCode = "VALIDATION_FAILED"
			} else if strings.Contains(err.Error(), "未检测到宿主 docker CLI") {
				errCode = "UNAVAILABLE"
			}
		}
		return sandbox.CapabilityResponse{Code: errCode, Error: msg}, nil
	}
	return okResponse(ComposeOutput{Output: out, Warnings: warnings})
}

func okResponse(v any) (sandbox.CapabilityResponse, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return sandbox.CapabilityResponse{Code: "INTERNAL", Error: "序列化 docker 能力响应失败"}, nil
	}
	return sandbox.CapabilityResponse{OK: true, ResultJSON: raw}, nil
}
