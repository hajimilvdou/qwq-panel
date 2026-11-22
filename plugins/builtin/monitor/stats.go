// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"math"
	"slices"
	"strings"

	metricsv1 "github.com/qwq-panel/qwq/sdk/gen/qwq/capability/metrics/v1"
)

// Point 用 nil 表示不可用；新采样和重置不能被绘制成虚构的零值。
type Point struct {
	T         int64    `json:"t"`
	CPU       *float64 `json:"cpu_pct"`
	Memory    *float64 `json:"mem_pct"`
	Disk      *float64 `json:"disk_pct"`
	NetRX     *float64 `json:"net_rx_bps"`
	NetTX     *float64 `json:"net_tx_bps"`
	Load      *float64 `json:"load1"`
	DiskRead  *float64 `json:"disk_read_bps"`
	DiskWrite *float64 `json:"disk_write_bps"`
}

func number(value float64) *float64 {
	if math.IsNaN(value) || math.IsInf(value, 0) || value < 0 {
		return nil
	}
	return &value
}
func percentage(used, total uint64) *float64 {
	if total == 0 || used > total {
		return nil
	}
	return number(float64(used) / float64(total) * 100)
}
func cloneNumber(value *float64) *float64 {
	if value == nil {
		return nil
	}
	copy := *value
	return &copy
}
func (p Point) clone() Point {
	p.CPU, p.Memory, p.Disk, p.NetRX, p.NetTX, p.Load, p.DiskRead, p.DiskWrite = cloneNumber(p.CPU), cloneNumber(p.Memory), cloneNumber(p.Disk), cloneNumber(p.NetRX), cloneNumber(p.NetTX), cloneNumber(p.Load), cloneNumber(p.DiskRead), cloneNumber(p.DiskWrite)
	return p
}

func derive(current, previous *metricsv1.MetricsSnapshot, cfg config, elapsed float64) Point {
	if current == nil {
		return Point{}
	}
	point := Point{T: current.CollectedAtUnixMs}
	if memory := current.Memory; memory != nil && memory.AvailableBytes <= memory.TotalBytes {
		point.Memory = percentage(memory.TotalBytes-memory.AvailableBytes, memory.TotalBytes)
	}
	for _, disk := range current.Disks {
		if disk != nil && disk.Mount == cfg.primaryDiskMount() {
			point.Disk = percentage(disk.UsedBytes, disk.TotalBytes)
			break
		}
	}
	if current.Load != nil {
		point.Load = number(current.Load.Load1)
	}
	if previous == nil || current.CollectedAtUnixMs <= previous.CollectedAtUnixMs || elapsed <= 0 {
		return point
	}
	point.CPU = cpuPercent(current.Cpu, previous.Cpu)
	point.NetRX, point.NetTX = networkRates(current.Nets, previous.Nets, cfg.NetInterfaces, elapsed)
	point.DiskRead, point.DiskWrite = diskRates(current.Disks, previous.Disks, cfg.DiskMounts, elapsed)
	return point
}

func cpuPercent(current, previous *metricsv1.Cpu) *float64 {
	if current == nil || previous == nil || current.CoreCount == 0 || current.CoreCount != previous.CoreCount {
		return nil
	}
	a := []uint64{current.User, current.Nice, current.System, current.Idle, current.Iowait, current.Irq, current.Softirq, current.Steal}
	b := []uint64{previous.User, previous.Nice, previous.System, previous.Idle, previous.Iowait, previous.Irq, previous.Softirq, previous.Steal}
	var total, idle float64
	for index, value := range a {
		if value < b[index] {
			return nil
		}
		delta := float64(value - b[index])
		total += delta
		if index == 3 || index == 4 {
			idle += delta
		}
	}
	if total <= 0 {
		return nil
	}
	return number(math.Max(0, math.Min(100, (total-idle)/total*100)))
}

func networkRates(current, previous []*metricsv1.NetIf, names []string, dt float64) (*float64, *float64) {
	if len(current) > 256 || len(previous) > 256 || dt <= 0 {
		return nil, nil
	}
	old := make(map[string]*metricsv1.NetIf, len(previous))
	for _, iface := range previous {
		if iface == nil {
			return nil, nil
		}
		if !selectedNetwork(iface.Name, names) {
			continue
		}
		if !interfaceName.MatchString(iface.Name) || old[iface.Name] != nil {
			return nil, nil
		}
		old[iface.Name] = iface
	}
	seen := make(map[string]bool)
	var rx, tx float64
	for _, iface := range current {
		if iface == nil {
			return nil, nil
		}
		if !selectedNetwork(iface.Name, names) {
			continue
		}
		if !interfaceName.MatchString(iface.Name) || seen[iface.Name] {
			return nil, nil
		}
		seen[iface.Name] = true
		before := old[iface.Name]
		if before == nil || iface.RxBytes < before.RxBytes || iface.TxBytes < before.TxBytes {
			return nil, nil
		}
		rx += float64(iface.RxBytes-before.RxBytes) * 8 / dt
		tx += float64(iface.TxBytes-before.TxBytes) * 8 / dt
	}
	if len(seen) == 0 {
		return nil, nil
	}
	if len(names) != 0 {
		for _, name := range names {
			if !seen[name] {
				return nil, nil
			}
		}
	} else {
		for name := range old {
			if name != "lo" && !seen[name] {
				return nil, nil
			}
		}
	}
	return number(rx), number(tx)
}

// selectedNetwork 显式目标先过滤再校验；默认不重复累计 veth/tun 转发接口。
func selectedNetwork(name string, names []string) bool {
	if name == "lo" {
		return false
	}
	if len(names) != 0 {
		return slices.Contains(names, name)
	}
	return !strings.HasPrefix(name, "veth") && !strings.HasPrefix(name, "tun")
}

// selectedMetric 只处理已经从环复制出的点，默认保留原完整响应。
func (p Point) selectedMetric(metric string) Point {
	result := Point{T: p.T}
	switch metric {
	case "cpu":
		result.CPU = p.CPU
	case "mem":
		result.Memory = p.Memory
	case "disk":
		result.Disk = p.Disk
	case "net":
		result.NetRX, result.NetTX = p.NetRX, p.NetTX
	case "load":
		result.Load = p.Load
	case "disk_io":
		result.DiskRead, result.DiskWrite = p.DiskRead, p.DiskWrite
	default:
		return p
	}
	return result
}

func diskRates(current, previous []*metricsv1.Disk, mounts []string, dt float64) (*float64, *float64) {
	if len(current) > 32 || len(previous) > 32 || dt <= 0 {
		return nil, nil
	}
	old := make(map[string]*metricsv1.Disk, len(previous))
	for _, disk := range previous {
		if disk == nil {
			continue
		}
		old[disk.Mount] = disk
	}
	seenMounts, seenDevices := make(map[string]bool), make(map[string]bool)
	var read, write float64
	for _, disk := range current {
		if disk == nil || !slices.Contains(mounts, disk.Mount) {
			continue
		}
		if seenMounts[disk.Mount] {
			return nil, nil
		}
		seenMounts[disk.Mount] = true
		before := old[disk.Mount]
		if before == nil || disk.Device == "" || disk.Device != before.Device || disk.ReadSectors < before.ReadSectors || disk.WriteSectors < before.WriteSectors {
			return nil, nil
		}
		if seenDevices[disk.Device] {
			continue
		}
		seenDevices[disk.Device] = true
		read += float64(disk.ReadSectors-before.ReadSectors) * 512 / dt
		write += float64(disk.WriteSectors-before.WriteSectors) * 512 / dt
	}
	for _, mount := range mounts {
		if !seenMounts[mount] {
			return nil, nil
		}
	}
	return number(read), number(write)
}
