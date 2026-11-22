// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"fmt"

	"github.com/qwq-panel/qwq/sdk/pluginsdk"
)

type emptyRequest struct{}
type diskSnapshot struct {
	Mount      string    `json:"mount"`
	UsedPct    *float64  `json:"used_pct"`
	Level      string    `json:"level"`
	Thresholds threshold `json:"thresholds"`
}
type snapshotResponse struct {
	Current          Point          `json:"current"`
	Points           []Point        `json:"points"`
	Status           string         `json:"status"`
	ResetEpoch       uint64         `json:"reset_epoch"`
	Uptime           uint64         `json:"uptime_seconds"`
	Disks            []diskSnapshot `json:"disks"`
	PrimaryDiskMount string         `json:"primary_disk_mount"`
}
type historyRequest struct {
	Range  string `json:"range,omitempty"`
	Metric string `json:"metric,omitempty"`
}
type historyResponse struct {
	Points     []Point `json:"points"`
	Resolution int     `json:"resolution_ms"`
	ResetEpoch uint64  `json:"reset_epoch"`
}
type statResponse struct {
	Value   float64   `json:"value"`
	Unit    string    `json:"unit"`
	Percent float64   `json:"percent"`
	Sub     string    `json:"sub"`
	Level   string    `json:"level"`
	Spark   []float64 `json:"spark"`
}
type seriesLine struct {
	Name   string       `json:"name"`
	Color  string       `json:"color"`
	Points [][2]float64 `json:"points"`
}
type seriesResponse struct {
	Unit   string       `json:"unit"`
	Max    *float64     `json:"max,omitempty"`
	Series []seriesLine `json:"series"`
}

// register 只注册七项只读处理器，采样及历史由本实例维护。
func (i *instance) register() {
	pluginsdk.HandleInvoke(i, "monitor.snapshot", i.snapshot)
	pluginsdk.HandleInvoke(i, "monitor.history", i.history)
	pluginsdk.HandleInvoke(i, "monitor.stat.cpu", func(ctx context.Context, _ emptyRequest) (statResponse, error) { return i.stat(ctx, "cpu") })
	pluginsdk.HandleInvoke(i, "monitor.stat.mem", func(ctx context.Context, _ emptyRequest) (statResponse, error) { return i.stat(ctx, "mem") })
	pluginsdk.HandleInvoke(i, "monitor.stat.disk", func(ctx context.Context, _ emptyRequest) (statResponse, error) { return i.stat(ctx, "disk") })
	pluginsdk.HandleInvoke(i, "monitor.series.net", func(ctx context.Context, _ emptyRequest) (seriesResponse, error) { return i.series(ctx, "net") })
	pluginsdk.HandleInvoke(i, "monitor.series.load", func(ctx context.Context, _ emptyRequest) (seriesResponse, error) { return i.series(ctx, "load") })
}

func (i *instance) snapshot(_ context.Context, _ emptyRequest) (snapshotResponse, error) {
	i.samples.mu.Lock()
	defer i.samples.mu.Unlock()
	points := i.samples.fine.latest(i.samples.cfg.FinePoints)
	current := Point{}
	if len(points) > 0 {
		current = points[len(points)-1]
	}
	status := "ready"
	if len(points) == 0 || i.samples.lastError != "" {
		status = "unavailable"
	}
	return snapshotResponse{Current: current, Points: points, Status: status, ResetEpoch: i.samples.resetEpoch, Uptime: i.samples.uptime, Disks: i.samples.diskSnapshotsLocked(), PrimaryDiskMount: i.samples.cfg.primaryDiskMount()}, nil
}

// diskSnapshotsLocked 仅暴露配置选中的真实挂载点，缺失目标保留 unavailable。
func (s *sampler) diskSnapshotsLocked() []diskSnapshot {
	result := make([]diskSnapshot, 0, len(s.cfg.DiskMounts))
	for _, mount := range s.cfg.DiskMounts {
		disk := diskSnapshot{Mount: mount, Thresholds: s.cfg.Thresholds.Disk}
		if s.previous != nil {
			for _, source := range s.previous.Disks {
				if source != nil && source.Mount == mount {
					disk.UsedPct = percentage(source.UsedBytes, source.TotalBytes)
					break
				}
			}
		}
		disk.Level = disk.Thresholds.level(disk.UsedPct)
		result = append(result, disk)
	}
	return result
}

func (i *instance) history(_ context.Context, request historyRequest) (historyResponse, error) {
	if request.Range == "" {
		request.Range = "1h"
	}
	if request.Range != "5m" && request.Range != "1h" {
		return historyResponse{}, pluginsdk.Errorf("VALIDATION_FAILED", "历史范围必须为 5m 或 1h")
	}
	if request.Metric != "" && request.Metric != "cpu" && request.Metric != "mem" && request.Metric != "disk" && request.Metric != "net" && request.Metric != "load" && request.Metric != "disk_io" {
		return historyResponse{}, pluginsdk.Errorf("VALIDATION_FAILED", "监控指标无效")
	}
	i.samples.mu.Lock()
	defer i.samples.mu.Unlock()
	points, resolution := i.samples.coarse.latest(i.samples.cfg.CoarsePoints), i.samples.cfg.CoarseInterval
	if request.Range == "5m" {
		points, resolution = i.samples.fine.latest(i.samples.cfg.FinePoints), i.samples.cfg.SampleInterval
	}
	for index := range points {
		points[index] = points[index].selectedMetric(request.Metric)
	}
	return historyResponse{Points: points, Resolution: resolution, ResetEpoch: i.samples.resetEpoch}, nil
}

func (i *instance) stat(_ context.Context, metric string) (statResponse, error) {
	i.samples.mu.Lock()
	defer i.samples.mu.Unlock()
	points := i.samples.fine.latest(60)
	if len(points) == 0 || i.samples.lastError != "" {
		return statResponse{}, pluginsdk.Errorf("UNAVAILABLE", "等待有效宿主采样")
	}
	var value *float64
	var level threshold
	var sub string
	selectValue := func(point Point) *float64 {
		switch metric {
		case "cpu":
			return point.CPU
		case "mem":
			return point.Memory
		default:
			return point.Disk
		}
	}
	value = selectValue(points[len(points)-1])
	switch metric {
	case "cpu":
		level = i.samples.cfg.Thresholds.CPU
		sub = fmt.Sprintf("%d 核", i.samples.cores)
	case "mem":
		level = i.samples.cfg.Thresholds.Memory
		sub = "宿主可用内存"
	default:
		level = i.samples.cfg.Thresholds.Disk
		mount := i.samples.cfg.primaryDiskMount()
		sub = mount + " 挂载点"
		if mount == "/" {
			sub = "根挂载点"
		}
	}
	if value == nil {
		return statResponse{}, pluginsdk.Errorf("UNAVAILABLE", "该指标暂不可用")
	}
	color := level.level(value)
	spark := make([]float64, 0, len(points))
	for _, point := range points {
		if value := selectValue(point); value != nil {
			spark = append(spark, *value)
		}
	}
	return statResponse{Value: *value, Percent: *value, Unit: "%", Sub: sub, Level: color, Spark: spark}, nil
}

func (i *instance) series(_ context.Context, metric string) (seriesResponse, error) {
	i.samples.mu.Lock()
	defer i.samples.mu.Unlock()
	lines := []seriesLine{{Name: "入", Color: "teal", Points: [][2]float64{}}, {Name: "出", Color: "violet", Points: [][2]float64{}}}
	unit := "Mbps"
	if metric == "load" {
		lines[0].Name, lines[1].Name, unit = "CPU", "内存", "%"
	}
	for _, point := range i.samples.fine.latest(60) {
		values := []*float64{point.NetRX, point.NetTX}
		if metric == "load" {
			values = []*float64{point.CPU, point.Memory}
		}
		for index, value := range values {
			if value != nil {
				v := *value
				if metric == "net" {
					v /= 1e6
				}
				lines[index].Points = append(lines[index].Points, [2]float64{float64(point.T), v})
			}
		}
	}
	response := seriesResponse{Unit: unit, Series: lines}
	if metric == "load" {
		maximum := 100.0
		response.Max = &maximum
	}
	return response, nil
}
