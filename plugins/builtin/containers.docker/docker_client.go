// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	dockerv1 "github.com/qwq-panel/qwq/sdk/gen/qwq/capability/docker/v1"
	"github.com/qwq-panel/qwq/sdk/pluginsdk"
)

const (
	defaultDockerSocket = "/var/run/docker.sock"
	dockerAPIVersion    = "v1.41"
	maxLogBytes         = 64 * 1024
	maxLogStreamRead    = 8 * 1024 * 1024
	maxLogLines         = 500
	maxRespBytes        = 4 * 1024 * 1024
)

// tailRingBuffer 是一个并发安全的固定容量环形尾部缓冲区（默认 64 KiB），
// 既可防止镜像拉取/大日志流撑爆 1C1G 内存，又能确保始终保留最新的崩溃尾部而非最早头部。
type tailRingBuffer struct {
	mu        sync.Mutex
	buf       []byte
	cap       int
	writePos  int
	full      bool
	truncated bool
}

func newTailRingBuffer(capacity int) *tailRingBuffer {
	if capacity <= 0 {
		capacity = maxLogBytes
	}
	return &tailRingBuffer{
		buf: make([]byte, capacity),
		cap: capacity,
	}
}

func (r *tailRingBuffer) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := len(p)
	if n == 0 {
		return 0, nil
	}
	if n >= r.cap {
		if n > r.cap || r.full || r.writePos > 0 {
			r.truncated = true
		}
		copy(r.buf, p[n-r.cap:])
		r.writePos = 0
		r.full = true
		return n, nil
	}
	if r.full {
		r.truncated = true
	}
	rem := r.cap - r.writePos
	if n <= rem {
		copy(r.buf[r.writePos:], p)
		r.writePos += n
		if r.writePos == r.cap {
			r.writePos = 0
			r.full = true
		}
		return n, nil
	}
	copy(r.buf[r.writePos:], p[:rem])
	copy(r.buf[0:], p[rem:])
	r.writePos = n - rem
	r.full = true
	r.truncated = true
	return n, nil
}

func (r *tailRingBuffer) Bytes() []byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.full {
		out := make([]byte, r.writePos)
		copy(out, r.buf[:r.writePos])
		return out
	}
	out := make([]byte, r.cap)
	tailLen := r.cap - r.writePos
	copy(out, r.buf[r.writePos:])
	copy(out[tailLen:], r.buf[:r.writePos])
	return out
}

func (r *tailRingBuffer) String() string {
	return string(r.Bytes())
}

func (r *tailRingBuffer) Truncated() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.truncated
}

var containerIDRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)

func validateContainerRef(id string) (string, error) {
	id = strings.TrimSpace(id)
	if !containerIDRe.MatchString(id) || strings.Contains(id, "..") {
		return "", errors.New("非法容器 ID 或名称")
	}
	return id, nil
}

// DockerInfo 描述 Docker 守护进程实时可用性与摘要信息。
type DockerInfo struct {
	Available         bool   `json:"available"`
	SocketPath        string `json:"socket_path"`
	Reason            string `json:"reason,omitempty"`
	ServerVersion     string `json:"server_version,omitempty"`
	ContainersTotal   int    `json:"containers_total"`
	ContainersRunning int    `json:"containers_running"`
	ContainersStopped int    `json:"containers_stopped"`
	ImagesCount       int    `json:"images_count"`
	MemTotalMB        int64  `json:"mem_total_mb"`
}

// ContainerSummary 是容器列表中的轻量视图。
type ContainerSummary struct {
	ID             string   `json:"id"`
	ShortID        string   `json:"short_id"`
	Name           string   `json:"name"`
	Image          string   `json:"image"`
	State          string   `json:"state"`
	Status         string   `json:"status"`
	Created        int64    `json:"created"`
	Ports          []string `json:"ports,omitempty"`
	ComposeProject string   `json:"compose_project,omitempty"`
}

// ContainerDetail 结合 inspect 与单次实时资源统计（含 OOMKilled 标志）。
type ContainerDetail struct {
	ID            string  `json:"id"`
	Name          string  `json:"name"`
	Image         string  `json:"image"`
	State         string  `json:"state"`
	Running       bool    `json:"running"`
	OOMKilled     bool    `json:"oom_killed"`
	RestartCount  int     `json:"restart_count"`
	MemoryMB      float64 `json:"memory_mb"`
	MemoryLimitMB float64 `json:"memory_limit_mb"`
	CPUPercent    float64 `json:"cpu_percent"`
}

// ImageSummary 描述本地镜像摘要。
type ImageSummary struct {
	ID      string   `json:"id"`
	Tags    []string `json:"tags"`
	SizeMB  float64  `json:"size_mb"`
	Created int64    `json:"created"`
}

// PruneResult 描述清理悬空镜像释放的空间。
type PruneResult struct {
	DeletedCount     int     `json:"deleted_count"`
	SpaceReclaimedMB float64 `json:"space_reclaimed_mb"`
}

type dockerClient struct {
	socketPath string
	httpClient *http.Client
	host       *pluginsdk.Host
}

func newDockerClient(socketPath string, timeout time.Duration, host *pluginsdk.Host) *dockerClient {
	if strings.TrimSpace(socketPath) == "" {
		socketPath = defaultDockerSocket
	}
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	tr := &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, "unix", socketPath)
		},
		MaxIdleConns:    4,
		IdleConnTimeout: 30 * time.Second,
	}
	return &dockerClient{
		socketPath: socketPath,
		httpClient: &http.Client{Transport: tr, Timeout: timeout},
		host:       host,
	}
}

func (c *dockerClient) useHostCapability() bool {
	return c != nil && c.host != nil && c.host.Conn() != nil
}

func splitPathAndQuery(pathWithQuery string) (cleanPath, rawQuery string) {
	if idx := strings.IndexByte(pathWithQuery, '?'); idx >= 0 {
		return pathWithQuery[:idx], pathWithQuery[idx+1:]
	}
	return pathWithQuery, ""
}

func (c *dockerClient) doRaw(ctx context.Context, method, pathWithQuery string, rawBody []byte) (int, []byte, error) {
	if c.useHostCapability() {
		cleanPath, rawQuery := splitPathAndQuery(pathWithQuery)
		client := dockerv1.NewDockerServiceClient(c.host.Conn())
		if method == http.MethodGet {
			hc, err := c.host.CapabilityContextReadOnly(ctx)
			if err != nil {
				return 0, nil, err
			}
			resp, err := client.ProxyRead(ctx, &dockerv1.ProxyReadRequest{
				Context:  hc,
				Path:     cleanPath,
				RawQuery: rawQuery,
			})
			if err != nil {
				return 0, nil, err
			}
			if e := resp.GetError(); e != nil && e.GetCode() != "" {
				return 0, nil, fmt.Errorf("%s: %s", e.GetCode(), e.GetMessage())
			}
			return int(resp.GetStatusCode()), resp.GetBody(), nil
		}
		hc, err := c.host.CapabilityContext(ctx)
		if err != nil {
			return 0, nil, err
		}
		resp, err := client.ProxyWrite(ctx, &dockerv1.ProxyWriteRequest{
			Context:  hc,
			Method:   method,
			Path:     cleanPath,
			RawQuery: rawQuery,
			Body:     rawBody,
		})
		if err != nil {
			return 0, nil, err
		}
		if e := resp.GetError(); e != nil && e.GetCode() != "" {
			return 0, nil, fmt.Errorf("%s: %s", e.GetCode(), e.GetMessage())
		}
		return int(resp.GetStatusCode()), resp.GetBody(), nil
	}

	var bodyReader io.Reader
	if len(rawBody) > 0 {
		bodyReader = bytes.NewReader(rawBody)
	}
	req, err := http.NewRequestWithContext(ctx, method, "http://docker/"+dockerAPIVersion+pathWithQuery, bodyReader)
	if err != nil {
		return 0, nil, err
	}
	if len(rawBody) > 0 {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxRespBytes))
	return resp.StatusCode, raw, err
}

func (c *dockerClient) doJSON(ctx context.Context, method, path string, body any, out any) error {
	var rawBody []byte
	if body != nil {
		switch v := body.(type) {
		case []byte:
			rawBody = v
		case json.RawMessage:
			rawBody = v
		default:
			var err error
			rawBody, err = json.Marshal(body)
			if err != nil {
				return err
			}
		}
	}
	statusCode, raw, err := c.doRaw(ctx, method, path, rawBody)
	if err != nil {
		return err
	}
	if statusCode < 200 || statusCode >= 300 {
		var errBody struct {
			Message string `json:"message"`
		}
		if json.Unmarshal(raw, &errBody) == nil && errBody.Message != "" {
			return fmt.Errorf("docker API %d: %s", statusCode, errBody.Message)
		}
		return fmt.Errorf("docker API %d: %s", statusCode, strings.TrimSpace(string(raw)))
	}
	if out != nil && len(raw) > 0 {
		return json.Unmarshal(raw, out)
	}
	return nil
}

func (c *dockerClient) probeInfo(ctx context.Context) DockerInfo {
	info := DockerInfo{SocketPath: c.socketPath}
	if c.useHostCapability() {
		info.SocketPath = "host://system.docker"
	} else if _, err := os.Stat(c.socketPath); err != nil {
		info.Reason = fmt.Sprintf("Docker socket %s 不存在或不可访问", c.socketPath)
		return info
	}
	var raw struct {
		ServerVersion     string `json:"ServerVersion"`
		Containers        int    `json:"Containers"`
		ContainersRunning int    `json:"ContainersRunning"`
		ContainersStopped int    `json:"ContainersStopped"`
		Images            int    `json:"Images"`
		MemTotal          int64  `json:"MemTotal"`
	}
	if err := c.doJSON(ctx, http.MethodGet, "/info", nil, &raw); err != nil {
		info.Reason = err.Error()
		return info
	}
	info.Available = true
	info.ServerVersion = raw.ServerVersion
	info.ContainersTotal = raw.Containers
	info.ContainersRunning = raw.ContainersRunning
	info.ContainersStopped = raw.ContainersStopped
	info.ImagesCount = raw.Images
	info.MemTotalMB = raw.MemTotal / (1024 * 1024)
	return info
}

func (c *dockerClient) listContainers(ctx context.Context) ([]ContainerSummary, error) {
	var raw []struct {
		ID      string            `json:"Id"`
		Names   []string          `json:"Names"`
		Image   string            `json:"Image"`
		State   string            `json:"State"`
		Status  string            `json:"Status"`
		Created int64             `json:"Created"`
		Labels  map[string]string `json:"Labels"`
		Ports   []struct {
			IP          string `json:"IP"`
			PrivatePort int    `json:"PrivatePort"`
			PublicPort  int    `json:"PublicPort"`
			Type        string `json:"Type"`
		} `json:"Ports"`
	}
	if err := c.doJSON(ctx, http.MethodGet, "/containers/json?all=1", nil, &raw); err != nil {
		return nil, err
	}
	out := make([]ContainerSummary, 0, len(raw))
	for _, r := range raw {
		short := r.ID
		if len(short) > 12 {
			short = short[:12]
		}
		name := short
		if len(r.Names) > 0 {
			name = strings.TrimPrefix(r.Names[0], "/")
		}
		ports := make([]string, 0, len(r.Ports))
		for _, p := range r.Ports {
			if p.PublicPort > 0 {
				ports = append(ports, fmt.Sprintf("%d->%d/%s", p.PublicPort, p.PrivatePort, p.Type))
			} else if p.PrivatePort > 0 {
				ports = append(ports, fmt.Sprintf("%d/%s", p.PrivatePort, p.Type))
			}
		}
		out = append(out, ContainerSummary{
			ID:             r.ID,
			ShortID:        short,
			Name:           name,
			Image:          r.Image,
			State:          r.State,
			Status:         r.Status,
			Created:        r.Created,
			Ports:          ports,
			ComposeProject: r.Labels["com.docker.compose.project"],
		})
	}
	return out, nil
}

func (c *dockerClient) inspectWithStats(ctx context.Context, id string) (ContainerDetail, error) {
	ref, err := validateContainerRef(id)
	if err != nil {
		return ContainerDetail{}, err
	}
	var ins struct {
		ID           string `json:"Id"`
		Name         string `json:"Name"`
		RestartCount int    `json:"RestartCount"`
		Config       struct {
			Image string `json:"Image"`
		} `json:"Config"`
		State struct {
			Status    string `json:"Status"`
			Running   bool   `json:"Running"`
			OOMKilled bool   `json:"OOMKilled"`
		} `json:"State"`
		HostConfig struct {
			Memory int64 `json:"Memory"`
		} `json:"HostConfig"`
	}
	if err := c.doJSON(ctx, http.MethodGet, "/containers/"+url.PathEscape(ref)+"/json", nil, &ins); err != nil {
		return ContainerDetail{}, err
	}
	detail := ContainerDetail{
		ID:            ins.ID,
		Name:          strings.TrimPrefix(ins.Name, "/"),
		Image:         ins.Config.Image,
		State:         ins.State.Status,
		Running:       ins.State.Running,
		OOMKilled:     ins.State.OOMKilled,
		RestartCount:  ins.RestartCount,
		MemoryLimitMB: float64(ins.HostConfig.Memory) / (1024 * 1024),
	}
	if ins.State.Running {
		var st struct {
			MemoryStats struct {
				Usage uint64 `json:"usage"`
				Limit uint64 `json:"limit"`
			} `json:"memory_stats"`
			CPUStats struct {
				CPUUsage struct {
					TotalUsage uint64 `json:"total_usage"`
				} `json:"cpu_usage"`
				SystemCPUUsage uint64 `json:"system_cpu_usage"`
				OnlineCPUs     uint64 `json:"online_cpus"`
			} `json:"cpu_stats"`
			PreCPUStats struct {
				CPUUsage struct {
					TotalUsage uint64 `json:"total_usage"`
				} `json:"cpu_usage"`
				SystemCPUUsage uint64 `json:"system_cpu_usage"`
			} `json:"precpu_stats"`
		}
		if err := c.doJSON(ctx, http.MethodGet, "/containers/"+url.PathEscape(ref)+"/stats?stream=false", nil, &st); err == nil {
			detail.MemoryMB = float64(st.MemoryStats.Usage) / (1024 * 1024)
			if st.MemoryStats.Limit > 0 {
				detail.MemoryLimitMB = float64(st.MemoryStats.Limit) / (1024 * 1024)
			}
			if st.CPUStats.CPUUsage.TotalUsage > st.PreCPUStats.CPUUsage.TotalUsage &&
				st.CPUStats.SystemCPUUsage > st.PreCPUStats.SystemCPUUsage {
				cpuDelta := float64(st.CPUStats.CPUUsage.TotalUsage - st.PreCPUStats.CPUUsage.TotalUsage)
				sysDelta := float64(st.CPUStats.SystemCPUUsage - st.PreCPUStats.SystemCPUUsage)
				cpus := float64(st.CPUStats.OnlineCPUs)
				if cpus <= 0 {
					cpus = 1
				}
				detail.CPUPercent = (cpuDelta / sysDelta) * cpus * 100.0
			}
		}
	}
	return detail, nil
}

func (c *dockerClient) containerLogs(ctx context.Context, id string, tail int) (string, bool, error) {
	ref, err := validateContainerRef(id)
	if err != nil {
		return "", false, err
	}
	if tail <= 0 {
		tail = 100
	}
	if tail > maxLogLines {
		tail = maxLogLines
	}
	if c.useHostCapability() {
		pathWithQuery := fmt.Sprintf("/containers/%s/logs?stdout=1&stderr=1&timestamps=1&tail=%d", url.PathEscape(ref), tail)
		statusCode, raw, err := c.doRaw(ctx, http.MethodGet, pathWithQuery, nil)
		if err != nil {
			return "", false, err
		}
		if statusCode < 200 || statusCode >= 300 {
			return "", false, fmt.Errorf("docker logs %d: %s", statusCode, strings.TrimSpace(string(raw)))
		}
		ring := newTailRingBuffer(maxLogBytes)
		if err := demuxDockerStreamToRing(bytes.NewReader(raw), ring); err != nil {
			return "", false, err
		}
		return ring.String(), ring.Truncated(), nil
	}
	u := fmt.Sprintf("http://docker/%s/containers/%s/logs?stdout=1&stderr=1&timestamps=1&tail=%d",
		dockerAPIVersion, url.PathEscape(ref), tail)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return "", false, err
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		errRaw, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return "", false, fmt.Errorf("docker logs %d: %s", resp.StatusCode, strings.TrimSpace(string(errRaw)))
	}
	ring := newTailRingBuffer(maxLogBytes)
	if err := demuxDockerStreamToRing(io.LimitReader(resp.Body, maxLogStreamRead), ring); err != nil {
		return "", false, err
	}
	return ring.String(), ring.Truncated(), nil
}

// demuxDockerStreamToRing 流式解析 Docker Engine 8 字节多路复用日志帧并写入 64 KiB 环形尾部缓冲区；
// 若为 TTY 纯文本流则直接流式写入环形缓冲区，确保保留最新日志尾部且内存恒定有界。
func demuxDockerStreamToRing(r io.Reader, ring *tailRingBuffer) error {
	var first [8]byte
	n, err := io.ReadFull(r, first[:])
	if err == io.EOF {
		return nil
	}
	if err == io.ErrUnexpectedEOF {
		_, _ = ring.Write(first[:n])
		return nil
	}
	if err != nil {
		return err
	}
	isMux := (first[0] == 1 || first[0] == 2) && first[1] == 0 && first[2] == 0 && first[3] == 0
	if !isMux {
		_, _ = ring.Write(first[:n])
		_, err = io.Copy(ring, r)
		return err
	}
	hdr := first
	for {
		sz := int64(binary.BigEndian.Uint32(hdr[4:8]))
		if sz > 0 {
			if _, err := io.CopyN(ring, r, sz); err != nil {
				if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
					return nil
				}
				return err
			}
		}
		n, err := io.ReadFull(r, hdr[:])
		if err == io.EOF {
			return nil
		}
		if err == io.ErrUnexpectedEOF {
			_, _ = ring.Write(hdr[:n])
			return nil
		}
		if err != nil {
			return err
		}
		if (hdr[0] != 1 && hdr[0] != 2) || hdr[1] != 0 || hdr[2] != 0 || hdr[3] != 0 {
			_, _ = ring.Write(hdr[:n])
			_, err = io.Copy(ring, r)
			return err
		}
	}
}

func (c *dockerClient) containerAction(ctx context.Context, id, action string) error {
	ref, err := validateContainerRef(id)
	if err != nil {
		return err
	}
	switch action {
	case "start", "stop", "restart":
	default:
		return fmt.Errorf("不支持的容器动作 %q", action)
	}
	path := "/containers/" + url.PathEscape(ref) + "/" + action
	if action == "stop" || action == "restart" {
		path += "?t=10"
	}
	return c.doJSON(ctx, http.MethodPost, path, nil, nil)
}

func (c *dockerClient) updateContainerLimits(ctx context.Context, id string, memoryMB int64, cpus float64, restartPolicy string, restartMaxRetry int) error {
	ref, err := validateContainerRef(id)
	if err != nil {
		return err
	}
	payload, err := BuildSafeDockerUpdatePayloadWithRestart(memoryMB, cpus*100, restartPolicy, restartMaxRetry)
	if err != nil {
		return err
	}
	return c.doJSON(ctx, http.MethodPost, "/containers/"+url.PathEscape(ref)+"/update", payload, nil)
}

func (c *dockerClient) removeContainer(ctx context.Context, id string, force bool) error {
	ref, err := validateContainerRef(id)
	if err != nil {
		return err
	}
	path := "/containers/" + url.PathEscape(ref) + "?force=" + strconv.FormatBool(force)
	return c.doJSON(ctx, http.MethodDelete, path, nil, nil)
}

func (c *dockerClient) listImages(ctx context.Context) ([]ImageSummary, error) {
	var raw []struct {
		ID       string   `json:"Id"`
		RepoTags []string `json:"RepoTags"`
		Size     int64    `json:"Size"`
		Created  int64    `json:"Created"`
	}
	if err := c.doJSON(ctx, http.MethodGet, "/images/json", nil, &raw); err != nil {
		return nil, err
	}
	out := make([]ImageSummary, 0, len(raw))
	for _, r := range raw {
		short := strings.TrimPrefix(r.ID, "sha256:")
		if len(short) > 12 {
			short = short[:12]
		}
		tags := r.RepoTags
		if tags == nil {
			tags = []string{}
		}
		out = append(out, ImageSummary{
			ID:      short,
			Tags:    tags,
			SizeMB:  float64(r.Size) / (1024 * 1024),
			Created: r.Created,
		})
	}
	return out, nil
}

func (c *dockerClient) pruneImages(ctx context.Context, all bool) (PruneResult, error) {
	var raw struct {
		ImagesDeleted  []map[string]any `json:"ImagesDeleted"`
		SpaceReclaimed int64            `json:"SpaceReclaimed"`
	}
	path := "/images/prune"
	if all {
		path += "?filters=" + url.QueryEscape(`{"dangling":["false"]}`)
	}
	if err := c.doJSON(ctx, http.MethodPost, path, nil, &raw); err != nil {
		return PruneResult{}, err
	}
	return PruneResult{
		DeletedCount:     len(raw.ImagesDeleted),
		SpaceReclaimedMB: float64(raw.SpaceReclaimed) / (1024 * 1024),
	}, nil
}

// HostBindableIP 描述宿主机可供容器端口映射绑定的地址。
type HostBindableIP struct {
	IP          string `json:"ip"`
	Interface   string `json:"interface"`
	Scope       string `json:"scope"`
	IsIPv6      bool   `json:"is_ipv6"`
	Recommended bool   `json:"recommended,omitempty"`
	Label       string `json:"label"`
}

// PortMappingRule 是容器端口映射工作台与宿主重建 RPC 使用的结构化规则。
type PortMappingRule struct {
	BindMode      string `json:"bind_mode"`
	BindIP        string `json:"bind_ip,omitempty"`
	IncludeIPv6   bool   `json:"include_ipv6,omitempty"`
	HostPort      uint16 `json:"host_port"`
	ContainerPort uint16 `json:"container_port"`
	Protocol      string `json:"protocol"`
}

// ContainerNetworkAttachment 描述容器当前挂载的单个 Docker 网络。
type ContainerNetworkAttachment struct {
	Name      string   `json:"name"`
	NetworkID string   `json:"network_id,omitempty"`
	IPv4      string   `json:"ipv4,omitempty"`
	IPv6      string   `json:"ipv6,omitempty"`
	Aliases   []string `json:"aliases,omitempty"`
	Internal  bool     `json:"internal"`
}

// DockerNetworkSummary 描述宿主机 Docker 网络列表项。
type DockerNetworkSummary struct {
	ID              string `json:"id"`
	Name            string `json:"name"`
	Driver          string `json:"driver"`
	Subnet          string `json:"subnet,omitempty"`
	Internal        bool   `json:"internal"`
	EnableIPv6      bool   `json:"enable_ipv6"`
	ContainersCount int    `json:"containers_count"`
}

// ContainerMountSummary 描述容器挂载卷清单项。
type ContainerMountSummary struct {
	Type        string `json:"type"`
	Name        string `json:"name,omitempty"`
	Source      string `json:"source"`
	Destination string `json:"destination"`
	RW          bool   `json:"rw"`
}

// ContainerSettingsDetail 聚合五分页容器设置抽屉所需的容器核心字段。
type ContainerSettingsDetail struct {
	ID                string  `json:"id"`
	ShortID           string  `json:"short_id"`
	Name              string  `json:"name"`
	Image             string  `json:"image"`
	State             string  `json:"state"`
	Running           bool    `json:"running"`
	OOMKilled         bool    `json:"oom_killed"`
	RestartCount      int     `json:"restart_count"`
	RestartPolicy     string  `json:"restart_policy"`
	RestartMaxRetry   int     `json:"restart_max_retry"`
	NetworkMode       string  `json:"network_mode"`
	StackName         string  `json:"stack_name,omitempty"`
	ServiceName       string  `json:"service_name,omitempty"`
	WritableSizeBytes int64   `json:"writable_size_bytes"`
	MemoryMB          float64 `json:"memory_mb"`
	MemoryLimitMB     float64 `json:"memory_limit_mb"`
	CPUPercent        float64 `json:"cpu_percent"`
	CPUsLimit         float64 `json:"cpus_limit"`
}

// ContainerFullInspectBundle 是 inspectContainerFull 的结构化返回值。
type ContainerFullInspectBundle struct {
	Container         ContainerSettingsDetail
	PortRules         []PortMappingRule
	ImageExposedPorts []string
	NetworksConnected []ContainerNetworkAttachment
	Mounts            []ContainerMountSummary
	Env               []string
}

func (c *dockerClient) inspectContainerFull(ctx context.Context, id string, networksAll []DockerNetworkSummary) (ContainerFullInspectBundle, error) {
	ref, err := validateContainerRef(id)
	if err != nil {
		return ContainerFullInspectBundle{}, err
	}
	var ins struct {
		ID           string `json:"Id"`
		Name         string `json:"Name"`
		Image        string `json:"Image"`
		RestartCount int    `json:"RestartCount"`
		SizeRw       int64  `json:"SizeRw"`
		Config       struct {
			Image        string              `json:"Image"`
			Env          []string            `json:"Env"`
			Labels       map[string]string   `json:"Labels"`
			ExposedPorts map[string]struct{} `json:"ExposedPorts"`
		} `json:"Config"`
		State struct {
			Status    string `json:"Status"`
			Running   bool   `json:"Running"`
			OOMKilled bool   `json:"OOMKilled"`
		} `json:"State"`
		HostConfig struct {
			Memory        int64  `json:"Memory"`
			NanoCpus      int64  `json:"NanoCpus"`
			CPUQuota      int64  `json:"CpuQuota"`
			CPUPeriod     int64  `json:"CpuPeriod"`
			NetworkMode   string `json:"NetworkMode"`
			RestartPolicy struct {
				Name              string `json:"Name"`
				MaximumRetryCount int    `json:"MaximumRetryCount"`
			} `json:"RestartPolicy"`
			PortBindings map[string][]struct {
				HostIP   string `json:"HostIp"`
				HostPort string `json:"HostPort"`
			} `json:"PortBindings"`
		} `json:"HostConfig"`
		Mounts []struct {
			Type        string `json:"Type"`
			Name        string `json:"Name"`
			Source      string `json:"Source"`
			Destination string `json:"Destination"`
			RW          bool   `json:"RW"`
		} `json:"Mounts"`
		NetworkSettings struct {
			Networks map[string]struct {
				NetworkID         string   `json:"NetworkID"`
				IPAddress         string   `json:"IPAddress"`
				GlobalIPv6Address string   `json:"GlobalIPv6Address"`
				Aliases           []string `json:"Aliases"`
			} `json:"Networks"`
		} `json:"NetworkSettings"`
	}
	if err := c.doJSON(ctx, http.MethodGet, "/containers/"+url.PathEscape(ref)+"/json?size=true", nil, &ins); err != nil {
		return ContainerFullInspectBundle{}, err
	}

	shortID := ins.ID
	if len(shortID) > 12 {
		shortID = shortID[:12]
	}
	cleanName := normalizeContainerName(ins.Name)
	var cpusLimit float64
	if ins.HostConfig.NanoCpus > 0 {
		cpusLimit = float64(ins.HostConfig.NanoCpus) / 1e9
	} else if ins.HostConfig.CPUQuota > 0 && ins.HostConfig.CPUPeriod > 0 {
		cpusLimit = float64(ins.HostConfig.CPUQuota) / float64(ins.HostConfig.CPUPeriod)
	}
	rp := strings.TrimSpace(ins.HostConfig.RestartPolicy.Name)
	if rp == "" {
		rp = "no"
	}
	stackName := ""
	serviceName := ""
	if proj := ins.Config.Labels["com.docker.compose.project"]; strings.HasPrefix(proj, "qwq_") {
		stackName = strings.TrimPrefix(proj, "qwq_")
		serviceName = strings.TrimSpace(ins.Config.Labels["com.docker.compose.service"])
	}

	ct := ContainerSettingsDetail{
		ID:                ins.ID,
		ShortID:           shortID,
		Name:              cleanName,
		Image:             ins.Config.Image,
		State:             ins.State.Status,
		Running:           ins.State.Running,
		OOMKilled:         ins.State.OOMKilled,
		RestartCount:      ins.RestartCount,
		RestartPolicy:     rp,
		RestartMaxRetry:   ins.HostConfig.RestartPolicy.MaximumRetryCount,
		NetworkMode:       ins.HostConfig.NetworkMode,
		StackName:         stackName,
		ServiceName:       serviceName,
		WritableSizeBytes: ins.SizeRw,
		MemoryLimitMB:     float64(ins.HostConfig.Memory) / (1024 * 1024),
		CPUsLimit:         cpusLimit,
	}

	if ins.State.Running {
		if statsDetail, serr := c.inspectWithStats(ctx, ref); serr == nil {
			ct.MemoryMB = statsDetail.MemoryMB
			if statsDetail.MemoryLimitMB > 0 && ct.MemoryLimitMB == 0 {
				ct.MemoryLimitMB = statsDetail.MemoryLimitMB
			}
			ct.CPUPercent = statsDetail.CPUPercent
		}
	}

	// 解析宿主机端口映射为结构化 PortMappingRule（自动合并 IPv4+IPv6 对）
	type ruleKey struct {
		cPort uint16
		proto string
		hPort uint16
		mode  string
		ip    string
	}
	ruleMap := make(map[ruleKey]*PortMappingRule)
	v6Present := make(map[string]bool)
	for cSpec, bindings := range ins.HostConfig.PortBindings {
		cPort, proto := parseDockerPortKey(cSpec)
		if cPort == 0 {
			continue
		}
		for _, b := range bindings {
			hp, perr := strconv.Atoi(strings.TrimSpace(b.HostPort))
			if perr != nil || hp <= 0 || hp > 65535 {
				continue
			}
			ip := strings.TrimSpace(b.HostIP)
			if ip == "::" || ip == "::1" {
				v6Present[fmt.Sprintf("%d/%s/%d/%s", cPort, proto, hp, ip)] = true
				continue
			}
			mode := "public"
			bindIP := "0.0.0.0"
			if ip == "127.0.0.1" {
				mode = "loopback"
				bindIP = "127.0.0.1"
			} else if ip != "" && ip != "0.0.0.0" {
				mode = "specific_ip"
				bindIP = ip
			}
			k := ruleKey{cPort: cPort, proto: proto, hPort: uint16(hp), mode: mode, ip: bindIP}
			if _, exists := ruleMap[k]; !exists {
				ruleMap[k] = &PortMappingRule{
					BindMode:      mode,
					BindIP:        bindIP,
					HostPort:      uint16(hp),
					ContainerPort: cPort,
					Protocol:      proto,
				}
			}
		}
	}
	portRules := make([]PortMappingRule, 0, len(ruleMap))
	for _, r := range ruleMap {
		if r.BindMode == "loopback" && v6Present[fmt.Sprintf("%d/%s/%d/::1", r.ContainerPort, r.Protocol, r.HostPort)] {
			r.IncludeIPv6 = true
		} else if r.BindMode == "public" && v6Present[fmt.Sprintf("%d/%s/%d/::", r.ContainerPort, r.Protocol, r.HostPort)] {
			r.IncludeIPv6 = true
		}
		portRules = append(portRules, *r)
	}
	sort.Slice(portRules, func(i, j int) bool {
		if portRules[i].ContainerPort != portRules[j].ContainerPort {
			return portRules[i].ContainerPort < portRules[j].ContainerPort
		}
		if portRules[i].HostPort != portRules[j].HostPort {
			return portRules[i].HostPort < portRules[j].HostPort
		}
		return portRules[i].Protocol < portRules[j].Protocol
	})

	// 汇总镜像声明端口（容器 Config.ExposedPorts + /images/{id}/json Config.ExposedPorts）
	exposedSet := make(map[string]bool)
	for k := range ins.Config.ExposedPorts {
		if strings.TrimSpace(k) != "" {
			exposedSet[strings.TrimSpace(k)] = true
		}
	}
	imgRef := strings.TrimSpace(ins.Image)
	if imgRef == "" {
		imgRef = strings.TrimSpace(ins.Config.Image)
	}
	if imgRef != "" {
		if imgExposed, ierr := c.listImageExposedPorts(ctx, imgRef); ierr == nil {
			for _, p := range imgExposed {
				exposedSet[p] = true
			}
		}
	}
	exposedPorts := make([]string, 0, len(exposedSet))
	for p := range exposedSet {
		exposedPorts = append(exposedPorts, p)
	}
	sort.Strings(exposedPorts)

	// 关联网络状态
	internalByName := make(map[string]bool, len(networksAll))
	for _, n := range networksAll {
		internalByName[n.Name] = n.Internal
	}
	netsConnected := make([]ContainerNetworkAttachment, 0, len(ins.NetworkSettings.Networks))
	for name, ep := range ins.NetworkSettings.Networks {
		aliases := ep.Aliases
		if aliases == nil {
			aliases = []string{}
		}
		netsConnected = append(netsConnected, ContainerNetworkAttachment{
			Name:      name,
			NetworkID: ep.NetworkID,
			IPv4:      ep.IPAddress,
			IPv6:      ep.GlobalIPv6Address,
			Aliases:   aliases,
			Internal:  internalByName[name],
		})
	}
	sort.Slice(netsConnected, func(i, j int) bool { return netsConnected[i].Name < netsConnected[j].Name })

	mounts := make([]ContainerMountSummary, 0, len(ins.Mounts))
	for _, m := range ins.Mounts {
		mounts = append(mounts, ContainerMountSummary{
			Type:        m.Type,
			Name:        m.Name,
			Source:      m.Source,
			Destination: m.Destination,
			RW:          m.RW,
		})
	}
	env := ins.Config.Env
	if env == nil {
		env = []string{}
	}

	return ContainerFullInspectBundle{
		Container:         ct,
		PortRules:         portRules,
		ImageExposedPorts: exposedPorts,
		NetworksConnected: netsConnected,
		Mounts:            mounts,
		Env:               env,
	}, nil
}

func parseDockerPortKey(spec string) (uint16, string) {
	pStr, proto, ok := strings.Cut(strings.TrimSpace(spec), "/")
	if !ok || proto == "" {
		proto = "tcp"
	}
	n, err := strconv.Atoi(pStr)
	if err != nil || n <= 0 || n > 65535 {
		return 0, ""
	}
	return uint16(n), strings.ToLower(proto)
}

func (c *dockerClient) listImageExposedPorts(ctx context.Context, imageRef string) ([]string, error) {
	imageRef = strings.TrimSpace(imageRef)
	if imageRef == "" || strings.Contains(imageRef, "..") {
		return nil, errors.New("invalid image ref")
	}
	var img struct {
		Config struct {
			ExposedPorts map[string]struct{} `json:"ExposedPorts"`
		} `json:"Config"`
	}
	if err := c.doJSON(ctx, http.MethodGet, "/images/"+url.PathEscape(imageRef)+"/json", nil, &img); err != nil {
		return nil, err
	}
	out := make([]string, 0, len(img.Config.ExposedPorts))
	for k := range img.Config.ExposedPorts {
		if strings.TrimSpace(k) != "" {
			out = append(out, strings.TrimSpace(k))
		}
	}
	sort.Strings(out)
	return out, nil
}

func (c *dockerClient) listNetworks(ctx context.Context) ([]DockerNetworkSummary, error) {
	var raw []struct {
		ID         string `json:"Id"`
		Name       string `json:"Name"`
		Driver     string `json:"Driver"`
		Internal   bool   `json:"Internal"`
		EnableIPv6 bool   `json:"EnableIPv6"`
		IPAM       struct {
			Config []struct {
				Subnet string `json:"Subnet"`
			} `json:"Config"`
		} `json:"IPAM"`
		Containers map[string]any `json:"Containers"`
	}
	if err := c.doJSON(ctx, http.MethodGet, "/networks", nil, &raw); err != nil {
		return nil, err
	}
	out := make([]DockerNetworkSummary, 0, len(raw))
	for _, n := range raw {
		subnet := ""
		if len(n.IPAM.Config) > 0 {
			subnet = n.IPAM.Config[0].Subnet
		}
		shortID := n.ID
		if len(shortID) > 12 {
			shortID = shortID[:12]
		}
		out = append(out, DockerNetworkSummary{
			ID:              shortID,
			Name:            n.Name,
			Driver:          n.Driver,
			Subnet:          subnet,
			Internal:        n.Internal,
			EnableIPv6:      n.EnableIPv6,
			ContainersCount: len(n.Containers),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (c *dockerClient) listBindableIPs(ctx context.Context) ([]HostBindableIP, error) {
	if c.useHostCapability() {
		hc, err := c.host.CapabilityContextReadOnly(ctx)
		if err != nil {
			return nil, err
		}
		resp, err := dockerv1.NewDockerServiceClient(c.host.Conn()).ListBindableIPs(ctx, &dockerv1.ListBindableIPsRequest{
			Context: hc,
		})
		if err != nil {
			return nil, err
		}
		if e := resp.GetError(); e != nil && e.GetCode() != "" {
			return nil, fmt.Errorf("%s: %s", e.GetCode(), e.GetMessage())
		}
		out := make([]HostBindableIP, 0, len(resp.GetIps()))
		for _, item := range resp.GetIps() {
			out = append(out, HostBindableIP{
				IP:          item.GetIp(),
				Interface:   item.GetIface(),
				Scope:       item.GetScope(),
				IsIPv6:      item.GetIsIpv6(),
				Recommended: item.GetRecommended(),
				Label:       item.GetLabel(),
			})
		}
		return out, nil
	}
	return fallbackLocalBindableIPs(), nil
}

func fallbackLocalBindableIPs() []HostBindableIP {
	out := []HostBindableIP{
		{IP: "127.0.0.1", Interface: "lo", Scope: "loopback", IsIPv6: false, Recommended: true, Label: "127.0.0.1（仅本机回环 · 隐身推荐）"},
		{IP: "0.0.0.0", Interface: "*", Scope: "public", IsIPv6: false, Label: "0.0.0.0（所有 IPv4 网卡 · 公网直连）"},
	}
	ifaces, err := net.Interfaces()
	if err != nil {
		return out
	}
	seen := map[string]bool{"127.0.0.1": true, "0.0.0.0": true}
	for _, iface := range ifaces {
		if (iface.Flags & net.FlagUp) == 0 {
			continue
		}
		name := iface.Name
		if name == "docker0" || strings.HasPrefix(name, "veth") || strings.HasPrefix(name, "br-") || strings.HasPrefix(name, "virbr") {
			continue
		}
		addrs, _ := iface.Addrs()
		for _, rawAddr := range addrs {
			var ipStr string
			switch v := rawAddr.(type) {
			case *net.IPNet:
				ipStr = v.IP.String()
			case *net.IPAddr:
				ipStr = v.IP.String()
			}
			addr, perr := netip.ParseAddr(ipStr)
			if perr != nil {
				continue
			}
			addr = addr.Unmap()
			if !addr.IsValid() || addr.IsLinkLocalUnicast() || addr.IsMulticast() || addr.IsUnspecified() {
				continue
			}
			canon := addr.String()
			if seen[canon] {
				continue
			}
			seen[canon] = true
			scope := "public"
			if addr.IsLoopback() {
				scope = "loopback"
			} else if addr.IsPrivate() {
				scope = "overlay_or_lan"
			}
			out = append(out, HostBindableIP{
				IP:        canon,
				Interface: name,
				Scope:     scope,
				IsIPv6:    addr.Is6(),
				Label:     fmt.Sprintf("%s（%s）", canon, name),
			})
		}
	}
	return out
}

type createNetworkParams struct {
	Name       string
	Driver     string
	Subnet     string
	Gateway    string
	Internal   bool
	EnableIPv6 bool
	Labels     map[string]string
}

func (c *dockerClient) createNetwork(ctx context.Context, p createNetworkParams) (string, string, error) {
	if c.useHostCapability() {
		hc, err := c.host.CapabilityContext(ctx)
		if err != nil {
			return "", "", err
		}
		resp, err := dockerv1.NewDockerServiceClient(c.host.Conn()).CreateNetwork(ctx, &dockerv1.CreateNetworkRequest{
			Context:    hc,
			Name:       strings.TrimSpace(p.Name),
			Driver:     strings.TrimSpace(p.Driver),
			Subnet:     strings.TrimSpace(p.Subnet),
			Gateway:    strings.TrimSpace(p.Gateway),
			Internal:   p.Internal,
			EnableIpv6: p.EnableIPv6,
			Labels:     p.Labels,
		})
		if err != nil {
			return "", "", err
		}
		if e := resp.GetError(); e != nil && e.GetCode() != "" {
			return "", "", fmt.Errorf("%s: %s", e.GetCode(), e.GetMessage())
		}
		return resp.GetNetworkId(), resp.GetName(), nil
	}
	driver := strings.TrimSpace(p.Driver)
	if driver == "" {
		driver = "bridge"
	}
	if driver != "bridge" {
		return "", "", fmt.Errorf("仅允许创建 bridge 网络，拒绝驱动 %q", driver)
	}
	body := map[string]any{
		"Name":           strings.TrimSpace(p.Name),
		"CheckDuplicate": true,
		"Driver":         driver,
		"Internal":       p.Internal,
		"EnableIPv6":     p.EnableIPv6,
		"Labels":         map[string]string{"com.qwq.managed": "true"},
	}
	var created struct {
		ID string `json:"Id"`
	}
	if err := c.doJSON(ctx, http.MethodPost, "/networks/create", body, &created); err != nil {
		return "", "", err
	}
	return created.ID, strings.TrimSpace(p.Name), nil
}

type mutateNetworkParams struct {
	ContainerID string
	NetworkID   string
	Action      string
	Aliases     []string
	IPv4Address string
	IPv6Address string
	Force       bool
}

func (c *dockerClient) mutateContainerNetwork(ctx context.Context, p mutateNetworkParams) error {
	if c.useHostCapability() {
		hc, err := c.host.CapabilityContext(ctx)
		if err != nil {
			return err
		}
		resp, err := dockerv1.NewDockerServiceClient(c.host.Conn()).MutateContainerNetwork(ctx, &dockerv1.MutateContainerNetworkRequest{
			Context:     hc,
			ContainerId: p.ContainerID,
			Action:      p.Action,
			NetworkId:   p.NetworkID,
			Aliases:     p.Aliases,
			Ipv4Address: p.IPv4Address,
			Ipv6Address: p.IPv6Address,
			Force:       p.Force,
		})
		if err != nil {
			return err
		}
		if e := resp.GetError(); e != nil && e.GetCode() != "" {
			return fmt.Errorf("%s: %s", e.GetCode(), e.GetMessage())
		}
		return nil
	}
	netRef, err := validateContainerRef(p.NetworkID)
	if err != nil {
		return err
	}
	ctRef, err := validateContainerRef(p.ContainerID)
	if err != nil {
		return err
	}
	switch p.Action {
	case "connect":
		epCfg := map[string]any{}
		if len(p.Aliases) > 0 {
			epCfg["Aliases"] = p.Aliases
		}
		if p.IPv4Address != "" || p.IPv6Address != "" {
			ipam := map[string]string{}
			if p.IPv4Address != "" {
				ipam["IPv4Address"] = p.IPv4Address
			}
			if p.IPv6Address != "" {
				ipam["IPv6Address"] = p.IPv6Address
			}
			epCfg["IPAMConfig"] = ipam
		}
		return c.doJSON(ctx, http.MethodPost, "/networks/"+url.PathEscape(netRef)+"/connect", map[string]any{
			"Container":      ctRef,
			"EndpointConfig": epCfg,
		}, nil)
	case "disconnect":
		return c.doJSON(ctx, http.MethodPost, "/networks/"+url.PathEscape(netRef)+"/disconnect", map[string]any{
			"Container": ctRef,
			"Force":     p.Force,
		}, nil)
	default:
		return fmt.Errorf("不支持的网络操作 %q", p.Action)
	}
}

type recreatePortsParams struct {
	ContainerID               string
	Rules                     []PortMappingRule
	CommitWritableLayer       bool
	AllowDiscardWritableLayer bool
	StartAfterRecreate        *bool
}

type RecreatePortsResult struct {
	OldContainerID    string            `json:"old_container_id"`
	NewContainerID    string            `json:"new_container_id"`
	ContainerName     string            `json:"container_name"`
	AppliedRules      []PortMappingRule `json:"applied_rules"`
	CommittedImage    string            `json:"committed_image,omitempty"`
	Warnings          []string          `json:"warnings,omitempty"`
	WritableSizeBytes int64             `json:"writable_size_bytes"`
}

func (c *dockerClient) recreateContainerPorts(ctx context.Context, p recreatePortsParams) (RecreatePortsResult, error) {
	if !c.useHostCapability() {
		return RecreatePortsResult{}, errors.New("宿主受控 Docker 能力服务未连接，无法执行原子端口重建")
	}
	hc, err := c.host.CapabilityContext(ctx)
	if err != nil {
		return RecreatePortsResult{}, err
	}
	specs := make([]*dockerv1.PortBindingSpec, 0, len(p.Rules))
	for _, r := range p.Rules {
		specs = append(specs, &dockerv1.PortBindingSpec{
			ContainerPort: int32(r.ContainerPort),
			Protocol:      r.Protocol,
			HostIp:        r.BindIP,
			HostPort:      int32(r.HostPort),
			BindMode:      r.BindMode,
			IncludeIpv6:   r.IncludeIPv6,
		})
	}
	resp, err := dockerv1.NewDockerServiceClient(c.host.Conn()).RecreateContainerPorts(ctx, &dockerv1.RecreateContainerPortsRequest{
		Context:                   hc,
		ContainerId:               p.ContainerID,
		Bindings:                  specs,
		CommitWritableLayer:       p.CommitWritableLayer,
		AllowDiscardWritableLayer: p.AllowDiscardWritableLayer,
		StartAfterRecreate:        p.StartAfterRecreate,
	})
	if err != nil {
		return RecreatePortsResult{}, err
	}
	if e := resp.GetError(); e != nil && e.GetCode() != "" {
		return RecreatePortsResult{WritableSizeBytes: resp.GetWritableSizeBytes()}, fmt.Errorf("%s: %s", e.GetCode(), e.GetMessage())
	}
	applied := make([]PortMappingRule, 0, len(resp.GetAppliedBindings()))
	for _, b := range resp.GetAppliedBindings() {
		applied = append(applied, PortMappingRule{
			BindMode:      b.GetBindMode(),
			BindIP:        b.GetHostIp(),
			IncludeIPv6:   b.GetIncludeIpv6(),
			HostPort:      uint16(b.GetHostPort()),
			ContainerPort: uint16(b.GetContainerPort()),
			Protocol:      b.GetProtocol(),
		})
	}
	return RecreatePortsResult{
		OldContainerID:    resp.GetOldContainerId(),
		NewContainerID:    resp.GetNewContainerId(),
		ContainerName:     resp.GetContainerName(),
		AppliedRules:      applied,
		CommittedImage:    resp.GetCommittedImage(),
		Warnings:          resp.GetWarnings(),
		WritableSizeBytes: resp.GetWritableSizeBytes(),
	}, nil
}
