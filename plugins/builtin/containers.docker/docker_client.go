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
	"time"
)

const (
	defaultDockerSocket = "/var/run/docker.sock"
	dockerAPIVersion    = "v1.41"
	maxLogBytes         = 64 * 1024
	maxLogLines         = 500
	maxRespBytes        = 4 * 1024 * 1024
)

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
	ID      string   `json:"id"`
	ShortID string   `json:"short_id"`
	Name    string   `json:"name"`
	Image   string   `json:"image"`
	State   string   `json:"state"`
	Status  string   `json:"status"`
	Created int64    `json:"created"`
	Ports   []string `json:"ports,omitempty"`
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
}

func newDockerClient(socketPath string, timeout time.Duration) *dockerClient {
	if strings.TrimSpace(socketPath) == "" {
		socketPath = defaultDockerSocket
	}
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	tr := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, "unix", socketPath)
		},
		MaxIdleConns:    4,
		IdleConnTimeout: 30 * time.Second,
	}
	return &dockerClient{
		socketPath: socketPath,
		httpClient: &http.Client{Transport: tr, Timeout: timeout},
	}
}

func (c *dockerClient) doJSON(ctx context.Context, method, path string, body any, out any) error {
	var bodyReader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return err
		}
		bodyReader = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, "http://docker/"+dockerAPIVersion+path, bodyReader)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxRespBytes))
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		var errBody struct {
			Message string `json:"message"`
		}
		if json.Unmarshal(raw, &errBody) == nil && errBody.Message != "" {
			return fmt.Errorf("docker API %d: %s", resp.StatusCode, errBody.Message)
		}
		return fmt.Errorf("docker API %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	if out != nil && len(raw) > 0 {
		return json.Unmarshal(raw, out)
	}
	return nil
}

func (c *dockerClient) probeInfo(ctx context.Context) DockerInfo {
	info := DockerInfo{SocketPath: c.socketPath}
	if _, err := os.Stat(c.socketPath); err != nil {
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
		ID      string   `json:"Id"`
		Names   []string `json:"Names"`
		Image   string   `json:"Image"`
		State   string   `json:"State"`
		Status  string   `json:"Status"`
		Created int64    `json:"Created"`
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
			ID:      r.ID,
			ShortID: short,
			Name:    name,
			Image:   r.Image,
			State:   r.State,
			Status:  r.Status,
			Created: r.Created,
			Ports:   ports,
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
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxLogBytes+1))
	if err != nil {
		return "", false, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", false, fmt.Errorf("docker logs %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	truncated := len(raw) > maxLogBytes
	if truncated {
		raw = raw[:maxLogBytes]
	}
	return demuxDockerStream(raw), truncated, nil
}

// demuxDockerStream 解析 Docker Engine 8 字节多路复用日志帧（若为 TTY 纯文本流则原样返回）。
func demuxDockerStream(raw []byte) string {
	if len(raw) < 8 || (raw[0] != 1 && raw[0] != 2) || raw[1] != 0 || raw[2] != 0 || raw[3] != 0 {
		return string(raw)
	}
	var out bytes.Buffer
	pos := 0
	for pos+8 <= len(raw) {
		streamType := raw[pos]
		if (streamType != 1 && streamType != 2) || raw[pos+1] != 0 || raw[pos+2] != 0 || raw[pos+3] != 0 {
			return string(raw)
		}
		sz := int(binary.BigEndian.Uint32(raw[pos+4 : pos+8]))
		pos += 8
		if sz < 0 || pos+sz > len(raw) {
			out.Write(raw[pos:])
			break
		}
		out.Write(raw[pos : pos+sz])
		pos += sz
	}
	return out.String()
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
	body := map[string]any{}
	if memoryMB > 0 {
		memBytes := memoryMB * 1024 * 1024
		body["Memory"] = memBytes
		body["MemorySwap"] = memBytes
	}
	if cpus > 0 {
		body["NanoCpus"] = int64(cpus * 1e9)
	}
	if len(body) == 0 {
		return errors.New("至少指定 memory_mb 或 cpus 之一")
	}
	return c.doJSON(ctx, http.MethodPost, "/containers/"+url.PathEscape(ref)+"/update", body, nil)
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
