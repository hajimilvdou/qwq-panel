// SPDX-License-Identifier: AGPL-3.0-only

// Package docker 实现受控宿主 Docker 能力执行器（PLG-FIX-04 / PLG-FIX-05）：
// 在 socket 激活的 qwq-capability 中以固定 /var/run/docker.sock 与严格端点白名单代理 Engine API，
// 并在插件 32 MiB cgroup 之外执行经过二次 YAML 安全扫描的 docker compose 编排。
package docker

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
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
	imageRefPattern     = regexp.MustCompile(`^(?:sha256:)?[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$`)
	imagePullRefPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/:@-]{0,254}$`)
	imageTagPattern     = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$`)
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
	httpTimeout := 25 * time.Second
	isImagePull := method == http.MethodPost && cleanRelPath == "/images/create"
	encodedQuery := query.Encode()
	if isImagePull {
		if len(jsonBody) > 0 {
			return 0, nil, errors.New("INVALID_ARGUMENT: 拉取镜像请求不允许携带请求体")
		}
		cleanQ, err := validateImagePullQuery(query)
		if err != nil {
			return 0, nil, err
		}
		encodedQuery = cleanQ.Encode()
		httpTimeout = 10 * time.Minute
	}
	u := &url.URL{
		Scheme:   "http",
		Host:     "docker",
		Path:     "/v1.41" + cleanRelPath,
		RawQuery: encodedQuery,
	}
	if strings.Contains(cleanRelPath, "%") {
		if unescaped, uerr := url.PathUnescape(cleanRelPath); uerr == nil {
			u.Path = "/v1.41" + unescaped
			u.RawPath = "/v1.41" + cleanRelPath
		}
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
	resp, err := r.dialClient(httpTimeout).Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	if isImagePull && resp.StatusCode >= 200 && resp.StatusCode < 300 {
		summary, pullErr := drainDockerPullNDJSON(resp.Body)
		if pullErr != nil {
			return 0, nil, pullErr
		}
		out, _ := json.Marshal(map[string]string{"status": summary})
		return resp.StatusCode, out, nil
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxProxyResponseBytes))
	return resp.StatusCode, raw, err
}

func drainDockerPullNDJSON(r io.Reader) (string, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 32<<10), 256<<10)
	lastStatus := "Image pull completed"
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var ev struct {
			Status      string `json:"status"`
			Error       string `json:"error"`
			ErrorDetail *struct {
				Message string `json:"message"`
			} `json:"errorDetail"`
		}
		if json.Unmarshal([]byte(line), &ev) == nil {
			if msg := strings.TrimSpace(ev.Error); msg != "" {
				return "", fmt.Errorf("docker pull failed: %s", msg)
			}
			if ev.ErrorDetail != nil && strings.TrimSpace(ev.ErrorDetail.Message) != "" {
				return "", fmt.Errorf("docker pull failed: %s", strings.TrimSpace(ev.ErrorDetail.Message))
			}
			if st := strings.TrimSpace(ev.Status); st != "" {
				lastStatus = st
			}
		}
	}
	if err := sc.Err(); err != nil {
		return "", fmt.Errorf("docker pull stream error: %w", err)
	}
	return lastStatus, nil
}

var blockedRegistryPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("0000::/8"),
	netip.MustParsePrefix("fd00:ec2::254/128"),
}

func isForbiddenRegistryHost(fromImage string) bool {
	firstSeg, _, hasSlash := strings.Cut(fromImage, "/")
	if !hasSlash {
		return false
	}
	// Docker treats first segment as a registry host only when it contains '.', ':', or equals 'localhost'.
	if !strings.ContainsAny(firstSeg, ".:") && !strings.EqualFold(firstSeg, "localhost") {
		return false
	}
	host := firstSeg
	if h, _, err := net.SplitHostPort(firstSeg); err == nil {
		host = h
	}
	host = strings.ToLower(strings.Trim(strings.TrimSpace(host), "[]"))
	if host == "" || host == "localhost" || strings.HasSuffix(host, ".localhost") ||
		host == "metadata.google.internal" || host == "metadata.goog" {
		return true
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		u := ip.Unmap()
		if !u.IsValid() || u.IsLoopback() || u.IsPrivate() || u.IsLinkLocalUnicast() ||
			u.IsLinkLocalMulticast() || u.IsMulticast() || u.IsUnspecified() {
			return true
		}
		for _, pfx := range blockedRegistryPrefixes {
			if pfx.Contains(u) {
				return true
			}
		}
	}
	return false
}

func validateImagePullQuery(query url.Values) (url.Values, error) {
	if len(query["fromImage"]) != 1 {
		return nil, errors.New("INVALID_ARGUMENT: 拉取镜像必须且只能携带单个 fromImage 参数")
	}
	fromImage := strings.TrimSpace(query["fromImage"][0])
	if fromImage == "" || strings.Contains(fromImage, "..") || !imagePullRefPattern.MatchString(fromImage) {
		return nil, errors.New("INVALID_ARGUMENT: 拉取镜像缺少合法的 fromImage 参数")
	}
	if isForbiddenRegistryHost(fromImage) {
		return nil, errors.New("DOCKER_ENDPOINT_FORBIDDEN: 禁止从回环、内网或云元数据地址拉取镜像")
	}
	clean := url.Values{}
	clean.Set("fromImage", fromImage)
	for k, vals := range query {
		switch k {
		case "fromImage":
		case "tag":
			if len(vals) != 1 {
				return nil, errors.New("INVALID_ARGUMENT: 非法的重复 tag 参数")
			}
			tag := strings.TrimSpace(vals[0])
			if tag != "" {
				if !imageTagPattern.MatchString(tag) {
					return nil, errors.New("INVALID_ARGUMENT: 非法的镜像 tag 参数")
				}
				clean.Set("tag", tag)
			}
		default:
			return nil, fmt.Errorf("DOCKER_ENDPOINT_FORBIDDEN: 拉取镜像不支持参数 %q", k)
		}
	}
	return clean, nil
}

func isValidImageInspectSegment(seg string) bool {
	if seg == "" || len(seg) > 384 || strings.Contains(seg, "..") {
		return false
	}
	decoded, err := url.PathUnescape(seg)
	if err != nil || decoded == "" || strings.Contains(decoded, "..") || strings.ContainsAny(decoded, "\\\x00\r\n\t ?#") {
		return false
	}
	return imageRefPattern.MatchString(decoded) || imagePullRefPattern.MatchString(decoded)
}

func isAllowedDockerEndpoint(method, p string) bool {
	if p == "" || !strings.HasPrefix(p, "/") || strings.ContainsAny(p, "?#\r\n\t\x00\\ ") || strings.Contains(p, "..") {
		return false
	}
	if path.Clean(p) != p {
		return false
	}
	segs := strings.Split(strings.TrimPrefix(p, "/"), "/")
	if IsAllowedNetworkOrInspectEndpoint(method, p, segs) {
		return true
	}
	switch method {
	case http.MethodGet:
		if p == "/info" || p == "/containers/json" || p == "/images/json" || p == "/volumes" {
			return true
		}
		if len(segs) == 3 && segs[0] == "containers" && isValidContainerID(segs[1]) {
			return segs[2] == "json" || segs[2] == "stats" || segs[2] == "logs"
		}
		return false
	case http.MethodPost:
		if p == "/images/prune" || p == "/images/create" || p == "/volumes/prune" {
			return true
		}
		if len(segs) == 3 && segs[0] == "containers" && isValidContainerID(segs[1]) {
			return segs[2] == "start" || segs[2] == "stop" || segs[2] == "restart" || segs[2] == "update"
		}
		return false
	case http.MethodDelete:
		if len(segs) == 2 && segs[0] == "containers" && isValidContainerID(segs[1]) {
			return true
		}
		if len(segs) == 2 && segs[0] == "images" && isValidImageRef(segs[1]) {
			return true
		}
		if len(segs) == 2 && segs[0] == "volumes" && isValidContainerID(segs[1]) {
			return true
		}
		return false
	default:
		return false
	}
}

func isValidContainerID(id string) bool {
	return containerRefPattern.MatchString(id) && !strings.Contains(id, "..")
}

func isValidImageRef(id string) bool {
	return imageRefPattern.MatchString(id) && !strings.Contains(id, "..")
}

// ExecuteVerifiedCompose 在宿主 helper 侧二次核验 YAML 后执行受管栈编排（最长 10 分钟，有界输出 64KiB）。
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
		if err := ValidateComposeBindSymlinks(stacksRoot, workDir, yamlContent); err != nil {
			return "", nil, err
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

	runCtx, cancel := context.WithTimeout(ctx, 10*time.Minute)
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
	// ReservedPortsFunc 返回 helper 侧独立核验的保留端口（如 SSH 监听端口），与宿主注入的面板端口合并防抢占。
	ReservedPortsFunc func(context.Context) []uint16
}

// NewService 创建默认固定宿主机路径的受控 Docker 能力服务。
func NewService() *Service {
	return &Service{
		Runner: &ControlledDockerCapabilityRunner{
			SocketPath: DefaultDockerSocket,
			StacksRoot: DefaultStacksRoot,
		},
		ReservedPortsFunc: discoverHostSSHReservedPorts,
	}
}

func discoverHostSSHReservedPorts(ctx context.Context) []uint16 {
	ports := []uint16{22}
	seen := map[uint16]bool{22: true}
	bin, err := exec.LookPath("sshd")
	if err != nil {
		return ports
	}
	runCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	out, err := exec.CommandContext(runCtx, bin, "-T").Output()
	if err != nil {
		return ports
	}
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && strings.EqualFold(fields[0], "port") {
			if p, perr := strconv.ParseUint(fields[1], 10, 16); perr == nil && p > 0 {
				if !seen[uint16(p)] {
					seen[uint16(p)] = true
					ports = append(ports, uint16(p))
				}
			}
		}
	}
	return ports
}

// BindableIPsOutput 是 docker.bindable_ips 的出参。
type BindableIPsOutput struct {
	IPs []HostBindableIP `json:"ips"`
}

// CreateNetworkOutput 是 docker.network.create 的出参。
type CreateNetworkOutput struct {
	NetworkID string `json:"network_id"`
	Name      string `json:"name"`
}

// Run 处理 docker.* 封闭能力 verb。
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
	case "docker.bindable_ips":
		return s.handleBindableIPs()
	case "docker.network.create":
		return s.handleCreateNetwork(ctx, req.ParamsJSON)
	case "docker.network.membership":
		return s.handleNetworkMembership(ctx, req.ParamsJSON)
	case "docker.recreate_ports":
		return s.handleRecreatePorts(ctx, req.ParamsJSON)
	default:
		return sandbox.CapabilityResponse{Code: "UNIMPLEMENTED", Error: "不支持的 docker 能力操作"}, nil
	}
}

func (s *Service) handleBindableIPs() (sandbox.CapabilityResponse, error) {
	ips, err := ListHostBindableIPs()
	if err != nil {
		return sandbox.CapabilityResponse{Code: "UNAVAILABLE", Error: err.Error()}, nil
	}
	return okResponse(BindableIPsOutput{IPs: ips})
}

func (s *Service) handleCreateNetwork(ctx context.Context, payload []byte) (sandbox.CapabilityResponse, error) {
	var in CreateNetworkInput
	if err := sandbox.DecodeHelperDocument(payload, &in); err != nil {
		return sandbox.CapabilityResponse{Code: "VALIDATION_FAILED", Error: "docker.network.create 请求参数格式无效"}, nil
	}
	id, err := s.Runner.CreateControlledBridgeNetwork(ctx, in)
	if err != nil {
		return sandbox.CapabilityResponse{Code: classifyDockerErrCode(err), Error: err.Error()}, nil
	}
	return okResponse(CreateNetworkOutput{NetworkID: id, Name: strings.TrimSpace(in.Name)})
}

func (s *Service) handleNetworkMembership(ctx context.Context, payload []byte) (sandbox.CapabilityResponse, error) {
	var in NetworkMembershipInput
	if err := sandbox.DecodeHelperDocument(payload, &in); err != nil {
		return sandbox.CapabilityResponse{Code: "VALIDATION_FAILED", Error: "docker.network.membership 请求参数格式无效"}, nil
	}
	if err := s.Runner.MutateContainerNetwork(ctx, in); err != nil {
		return sandbox.CapabilityResponse{Code: classifyDockerErrCode(err), Error: err.Error()}, nil
	}
	return okResponse(map[string]bool{"ok": true})
}

func (s *Service) handleRecreatePorts(ctx context.Context, payload []byte) (sandbox.CapabilityResponse, error) {
	var in RecreatePortsInput
	if err := sandbox.DecodeHelperDocument(payload, &in); err != nil {
		return sandbox.CapabilityResponse{Code: "VALIDATION_FAILED", Error: "docker.recreate_ports 请求参数格式无效"}, nil
	}
	reserved := make([]uint16, 0, len(in.ReservedHostPorts)+4)
	reserved = append(reserved, in.ReservedHostPorts...)
	if s.ReservedPortsFunc != nil {
		reserved = append(reserved, s.ReservedPortsFunc(ctx)...)
	}
	out, err := s.Runner.RecreateContainerWithPortBindings(ctx, in, reserved)
	if err != nil {
		return sandbox.CapabilityResponse{Code: classifyDockerErrCode(err), Error: err.Error()}, nil
	}
	return okResponse(out)
}

func classifyDockerErrCode(err error) string {
	if err == nil {
		return ""
	}
	msg := err.Error()
	switch {
	case strings.HasPrefix(msg, "INVALID_"),
		strings.HasPrefix(msg, "DUPLICATE_PORT_RULE"),
		strings.HasPrefix(msg, "TOO_MANY_PORT_RULES"),
		strings.HasPrefix(msg, "UNSUPPORTED_NETWORK_"):
		return "VALIDATION_FAILED"
	case strings.HasPrefix(msg, "PRIVILEGED_CONTAINER_REFUSED"),
		strings.HasPrefix(msg, "PORT_RESERVED_HOST"):
		return "PERMISSION_DENIED"
	case strings.HasPrefix(msg, "WRITABLE_LAYER_DIRTY"),
		strings.HasPrefix(msg, "PORT_IN_USE"),
		strings.HasPrefix(msg, "PORT_EXHAUSTED"),
		strings.HasPrefix(msg, "LAST_NETWORK_PROTECTED"),
		strings.HasPrefix(msg, "NETWORK_MODE_"),
		strings.HasPrefix(msg, "MANAGED_COMPOSE_CONTAINER"):
		return "FAILED_PRECONDITION"
	case strings.Contains(msg, "不存在") || strings.Contains(msg, "(404)"):
		return "NOT_FOUND"
	default:
		return "FAILED_PRECONDITION"
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
