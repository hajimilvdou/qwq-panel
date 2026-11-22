// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"encoding/json"
	"testing"

	metricsv1 "github.com/qwq-panel/qwq/sdk/gen/qwq/capability/metrics/v1"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

// ======================== 配置选中实际资源，其他资源不能污染或清空结果 ========================

func TestMonitorPrimaryDiskUsesConfiguredMount(t *testing.T) {
	current := sample(2000, 25, 75, 1000, 2)
	current.Disks = append(current.Disks, &metricsv1.Disk{Mount: "/data", Device: "vdb", TotalBytes: 100, UsedBytes: 91})
	cfg := defaultConfig()
	cfg.DiskMounts = []string{"/data"}
	expectMetric(t, derive(current, nil, cfg, 0).Disk, 91)
	cfg.DiskMounts = []string{"/data", "/"}
	expectMetric(t, derive(current, nil, cfg, 0).Disk, 80)
}

func TestMonitorConfiguredNetworkIgnoresUnselectedInvalidName(t *testing.T) {
	previous, current := sample(1000, 0, 0, 0, 0), sample(2000, 25, 75, 1000, 2)
	previous.Nets = append(previous.Nets, &metricsv1.NetIf{Name: "veth@if2", RxBytes: 4000, TxBytes: 4000})
	current.Nets = append(current.Nets, &metricsv1.NetIf{Name: "veth@if2", RxBytes: 9000, TxBytes: 9000})
	cfg := defaultConfig()
	cfg.NetInterfaces = []string{"eth0"}
	expectMetric(t, derive(current, previous, cfg, 1).NetRX, 8000)
}

func TestMonitorDefaultNetworkSurvivesTransientVirtualInterfaces(t *testing.T) {
	for _, name := range []string{"veth123", "tun0"} {
		t.Run(name, func(t *testing.T) {
			previous, current := sample(1000, 0, 0, 0, 0), sample(2000, 25, 75, 1000, 2)
			previous.Nets = append(previous.Nets, &metricsv1.NetIf{Name: name, RxBytes: 5000, TxBytes: 5000})
			expectMetric(t, derive(current, previous, defaultConfig(), 1).NetRX, 8000)
			previous.Nets = previous.Nets[:len(previous.Nets)-1]
			current.Nets = append(current.Nets, &metricsv1.NetIf{Name: name, RxBytes: 5000, TxBytes: 5000})
			expectMetric(t, derive(current, previous, defaultConfig(), 1).NetRX, 8000)
		})
	}
}

func TestMonitorHistoryMetricFiltersOnlyItsCopy(t *testing.T) {
	s := mustSampler(t, defaultConfig(), nil)
	s.fine.add(Point{T: 1000, CPU: number(25), Memory: number(60), Disk: number(80),
		NetRX: number(8000), NetTX: number(4000), Load: number(1), DiskRead: number(1024), DiskWrite: number(512)})
	i := &instance{samples: s}
	response, err := i.history(t.Context(), historyRequest{Range: "5m", Metric: "cpu"})
	if err != nil || len(response.Points) != 1 {
		t.Fatal("CPU 历史读取失败")
	}
	point := response.Points[0]
	if point.CPU == nil || point.Memory != nil || point.Disk != nil || point.NetRX != nil || point.NetTX != nil ||
		point.Load != nil || point.DiskRead != nil || point.DiskWrite != nil {
		t.Fatal("历史指标筛选仍返回无关指标")
	}
	all, err := i.history(t.Context(), historyRequest{Range: "5m"})
	if err != nil || len(all.Points) != 1 || all.Points[0].Memory == nil || all.Points[0].NetRX == nil {
		t.Fatal("筛选历史改变了原始环存储")
	}
}

func TestMonitorSnapshotExposesAllConfiguredDiskThresholds(t *testing.T) {
	current := sample(1000, 0, 0, 0, 0)
	current.Disks = append(current.Disks, &metricsv1.Disk{Mount: "/data", Device: "vdb", TotalBytes: 100, UsedBytes: 95})
	cfg := defaultConfig()
	cfg.DiskMounts = []string{"/", "/data"}
	s := mustSampler(t, cfg, &sequenceSource{values: []*metricsv1.MetricsSnapshot{current}})
	if err := s.collect(t.Context()); err != nil {
		t.Fatal(err)
	}
	response, err := (&instance{samples: s}).snapshot(t.Context(), emptyRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if response.PrimaryDiskMount != "/" {
		t.Fatal("快照主磁盘归属与实际根挂载点不一致")
	}
	raw, err := json.Marshal(response)
	if err != nil {
		t.Fatal(err)
	}
	assertMonitorSnapshotSchema(t, raw)
	var decoded struct {
		Disks []struct {
			Mount      string    `json:"mount"`
			UsedPct    *float64  `json:"used_pct"`
			Level      string    `json:"level"`
			Thresholds threshold `json:"thresholds"`
		} `json:"disks"`
	}
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	if len(decoded.Disks) != 2 || decoded.Disks[0].Mount != "/" || decoded.Disks[1].Mount != "/data" ||
		decoded.Disks[0].Level != "warn" || decoded.Disks[1].Level != "bad" || decoded.Disks[1].Thresholds != cfg.Thresholds.Disk {
		t.Fatal("快照未按配置暴露全部挂载点及其告警阈值")
	}
	expectMetric(t, decoded.Disks[0].UsedPct, 80)
	expectMetric(t, decoded.Disks[1].UsedPct, 95)
}

// ======================== 空值和发布契约必须保留真实资源边界 ========================

func TestMonitorSnapshotMissingDiskKeepsUnavailable(t *testing.T) {
	for _, collected := range []bool{false, true} {
		t.Run(map[bool]string{false: "首次采样前", true: "缺失配置挂载点"}[collected], func(t *testing.T) {
			cfg := defaultConfig()
			cfg.DiskMounts = []string{"/data", "/missing"}
			current := sample(1000, 0, 0, 0, 0)
			current.Disks = append(current.Disks, &metricsv1.Disk{Mount: "/data", Device: "vdb", TotalBytes: 100, UsedBytes: 91})
			s := mustSampler(t, cfg, &sequenceSource{values: []*metricsv1.MetricsSnapshot{current}})
			if collected {
				if err := s.collect(t.Context()); err != nil {
					t.Fatal(err)
				}
			}
			i := &instance{samples: s}
			response, err := i.snapshot(t.Context(), emptyRequest{})
			if err != nil {
				t.Fatal(err)
			}
			if response.PrimaryDiskMount != "/data" {
				t.Fatal("快照未提供实际主磁盘归属")
			}
			raw, err := json.Marshal(response)
			if err != nil {
				t.Fatal(err)
			}
			assertMonitorSnapshotSchema(t, raw)
			if len(response.Disks) != 2 || response.Disks[1].Mount != "/missing" || response.Disks[1].UsedPct != nil || response.Disks[1].Level != "unavailable" {
				t.Fatal("缺失挂载点被报告为有效使用率")
			}
			if !collected {
				if response.Disks[0].UsedPct != nil || response.Disks[0].Level != "unavailable" || response.Status != "unavailable" {
					t.Fatal("首次采样前伪造了磁盘状态")
				}
				return
			}
			expectMetric(t, response.Current.Disk, 91)
			stat, err := i.stat(t.Context(), "disk")
			if err != nil || stat.Sub != "/data 挂载点" || stat.Level != "warn" {
				t.Fatal("主磁盘微件没有使用实际配置挂载点")
			}
		})
	}
}

func assertMonitorSnapshotSchema(t *testing.T, raw []byte) {
	t.Helper()
	schema, err := jsonschema.NewCompiler().Compile("schemas/snapshot.response.json")
	if err != nil {
		t.Fatal(err)
	}
	payload, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	if err := schema.Validate(payload); err != nil {
		t.Fatalf("监控快照不符合发布契约: %v", err)
	}
}

func TestMonitorConfiguredVirtualNetworkStillTracksItsCounters(t *testing.T) {
	for _, name := range []string{"veth123", "tun0"} {
		t.Run(name, func(t *testing.T) {
			previous, current := sample(1000, 0, 0, 0, 0), sample(2000, 25, 75, 1000, 2)
			previous.Nets = append(previous.Nets, &metricsv1.NetIf{Name: name, RxBytes: 5000, TxBytes: 5000})
			current.Nets = append(current.Nets, &metricsv1.NetIf{Name: name, RxBytes: 6000, TxBytes: 5500})
			cfg := defaultConfig()
			cfg.NetInterfaces = []string{name}
			point := derive(current, previous, cfg, 1)
			expectMetric(t, point.NetRX, 8000)
			expectMetric(t, point.NetTX, 4000)
			current.Nets = current.Nets[:len(current.Nets)-1]
			if derive(current, previous, cfg, 1).NetRX != nil {
				t.Fatal("显式虚拟网卡消失后伪造了有效速率")
			}
		})
	}
}
