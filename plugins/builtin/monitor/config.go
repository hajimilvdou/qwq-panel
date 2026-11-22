// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"errors"
	"path"
	"regexp"
	"slices"
	"strings"

	"github.com/qwq-panel/qwq/internal/sandbox"
)

type threshold struct {
	Warn float64 `json:"warn"`
	Crit float64 `json:"crit"`
}
type thresholds struct {
	CPU    threshold `json:"cpu"`
	Memory threshold `json:"mem"`
	Disk   threshold `json:"disk"`
}
type config struct {
	SampleInterval int        `json:"sample_interval_ms"`
	CoarseInterval int        `json:"coarse_interval_ms"`
	FinePoints     int        `json:"fine_points"`
	CoarsePoints   int        `json:"coarse_points"`
	DiskMounts     []string   `json:"disk_mounts"`
	NetInterfaces  []string   `json:"net_interfaces"`
	Thresholds     thresholds `json:"thresholds"`
}

func defaultConfig() config {
	return config{SampleInterval: 1000, CoarseInterval: 10000, FinePoints: 300, CoarsePoints: 360, DiskMounts: []string{"/"}, NetInterfaces: []string{}, Thresholds: thresholds{CPU: threshold{70, 90}, Memory: threshold{75, 90}, Disk: threshold{80, 92}}}
}

// primaryDiskMount 优先已选根挂载点，其余配置使用第一个真实目标。
func (c config) primaryDiskMount() string {
	if slices.Contains(c.DiskMounts, "/") {
		return "/"
	}
	if len(c.DiskMounts) == 0 {
		return ""
	}
	return c.DiskMounts[0]
}

// level 共用现有 ok/warn/bad 状态，缺失数据不伪造为零使用率。
func (t threshold) level(value *float64) string {
	if value == nil {
		return "unavailable"
	}
	if *value >= t.Crit {
		return "bad"
	}
	if *value >= t.Warn {
		return "warn"
	}
	return "ok"
}

var interfaceName = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.:-]{0,63}$`)

func parseConfig(raw []byte) (config, error) {
	result := defaultConfig()
	if len(bytes.TrimSpace(raw)) == 0 {
		raw = []byte("{}")
	}
	if len(raw) > 64<<10 || sandbox.DecodeHelperDocument(raw, &result) != nil {
		return config{}, errors.New("监控配置格式无效")
	}
	if result.SampleInterval < 500 || result.SampleInterval > 5000 || result.CoarseInterval < 5000 || result.CoarseInterval > 60000 || result.CoarseInterval < result.SampleInterval || result.FinePoints < 60 || result.FinePoints > 600 || result.CoarsePoints < 60 || result.CoarsePoints > 720 {
		return config{}, errors.New("监控采样间隔或历史长度超出范围")
	}
	if len(result.DiskMounts) == 0 || len(result.DiskMounts) > 32 || len(result.NetInterfaces) > 32 {
		return config{}, errors.New("监控挂载点或网卡数量超出范围")
	}
	seen := make(map[string]bool)
	for _, mount := range result.DiskMounts {
		if !path.IsAbs(mount) || path.Clean(mount) != mount || len(mount) > 512 || strings.ContainsAny(mount, "\x00\r\n") || seen[mount] {
			return config{}, errors.New("监控挂载点格式无效或重复")
		}
		seen[mount] = true
	}
	seen = make(map[string]bool)
	for _, name := range result.NetInterfaces {
		if name == "lo" || !interfaceName.MatchString(name) || seen[name] {
			return config{}, errors.New("监控网卡格式无效或重复")
		}
		seen[name] = true
	}
	for _, level := range []threshold{result.Thresholds.CPU, result.Thresholds.Memory, result.Thresholds.Disk} {
		if level.Warn < 0 || level.Warn >= level.Crit || level.Crit > 100 {
			return config{}, errors.New("监控阈值必须满足 0 ≤ warn < crit ≤ 100")
		}
	}
	result.DiskMounts, result.NetInterfaces = slices.Clone(result.DiskMounts), slices.Clone(result.NetInterfaces)
	return result, nil
}
