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
	"net/url"
	"os"
	"regexp"
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

func (c *dockerClient) updateContainerLimits(ctx context.Context, id string, memoryMB int64, cpus float64) error {
	ref, err := validateContainerRef(id)
	if err != nil {
		return err
	}
	payload, err := BuildSafeDockerUpdatePayload(memoryMB, cpus*100)
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
