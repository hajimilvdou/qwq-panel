// SPDX-License-Identifier: AGPL-3.0-only

// Package metrics 在宿主命名空间读取瞬时原始指标，不维护差分或插件状态。
package metrics

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/qwq-panel/qwq/internal/platform/clock"
	metricsv1 "github.com/qwq-panel/qwq/sdk/gen/qwq/capability/metrics/v1"
)

// ======================== 采集边界与可替换来源 ========================
const (
	MaxProcBytes  = 1 << 20
	MaxMounts     = 32
	MaxInterfaces = 256
	maxDevices    = 4096
)

// ErrUnavailable 表示没有任何有效采集源，不把读取失败伪装成零值。
var ErrUnavailable = errors.New("metrics: 没有可用的宿主指标")

// Mount 是宿主受控的挂载配置；Device 为空时按 mountinfo 的设备号匹配。
type Mount struct{ Path, Device string }

// DiskUsage 是容量字节数，和 diskstats 的累计 IO 计数器分离。
type DiskUsage struct{ TotalBytes, UsedBytes uint64 }

// Options 的 Proc/StatFS/Clock 均可替换；默认只读 /proc、statfs(/) 和系统时钟。
type Options struct {
	Proc   fs.FS
	Mounts []Mount
	StatFS func(context.Context, string) (DiskUsage, error)
	Clock  clock.Clock
}

// Collector 是无状态采集器，可以并发使用；New 不执行文件、网络或进程操作。
type Collector struct {
	proc   fs.FS
	mounts []Mount
	statFS func(context.Context, string) (DiskUsage, error)
	clock  clock.Clock
}

// New 校验受控挂载路径并复制配置，不将调用方切片作为共享可变状态。
func New(options Options) (*Collector, error) {
	if options.Proc == nil {
		options.Proc = os.DirFS("/proc")
	}
	if options.Clock == nil {
		options.Clock = clock.System{}
	}
	if options.StatFS == nil {
		options.StatFS = defaultStatFS
	}
	if len(options.Mounts) == 0 {
		options.Mounts = []Mount{{Path: "/"}}
	}
	if len(options.Mounts) > MaxMounts {
		return nil, errors.New("metrics: 挂载点数量超过上限")
	}
	seen := make(map[string]bool, len(options.Mounts))
	for _, mount := range options.Mounts {
		if !filepath.IsAbs(mount.Path) || filepath.Clean(mount.Path) != mount.Path || strings.ContainsAny(mount.Path, "\x00\r\n") || seen[mount.Path] || (mount.Device != "" && !validDeviceName(mount.Device)) {
			return nil, errors.New("metrics: 挂载配置无效")
		}
		seen[mount.Path] = true
	}
	return &Collector{proc: options.Proc, mounts: append([]Mount(nil), options.Mounts...), statFS: options.StatFS, clock: options.Clock}, nil
}

// Collect 返回单次采样的原始计数器；局部故障只使该字段缺省，不生成伪造零值。
func (c *Collector) Collect(ctx context.Context) (*metricsv1.MetricsSnapshot, error) {
	if ctx == nil {
		return nil, errors.New("metrics: context 不能为空")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	snapshot := &metricsv1.MetricsSnapshot{CollectedAtUnixMs: c.clock.Now().UnixMilli()}
	available := false
	if data, err := c.read(ctx, "stat"); err == nil {
		snapshot.Cpu = parseCPU(data)
		available = available || snapshot.Cpu != nil
	}
	if data, err := c.read(ctx, "meminfo"); err == nil {
		snapshot.Memory = parseMemory(data)
		available = available || snapshot.Memory != nil
	}
	if data, err := c.read(ctx, "loadavg"); err == nil {
		snapshot.Load = parseLoad(data)
		available = available || snapshot.Load != nil
	}
	if data, err := c.read(ctx, "uptime"); err == nil {
		if value, ok := parseUptime(data); ok {
			snapshot.UptimeSeconds = value
			available = true
		}
	}
	if data, err := c.read(ctx, "net/dev"); err == nil {
		snapshot.Nets = parseNet(data)
		available = available || len(snapshot.Nets) > 0
	}
	counters := diskTable{}
	if data, err := c.read(ctx, "diskstats"); err == nil {
		counters = parseDiskStats(data)
	}
	mountInfo := make(map[string]string)
	if data, err := c.read(ctx, "self/mountinfo"); err == nil {
		mountInfo = parseMountInfo(data)
	}
	for _, mount := range c.mounts {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		usage, usageErr := c.statFS(ctx, mount.Path)
		if usageErr == nil && usage.UsedBytes > usage.TotalBytes {
			usageErr = ErrUnavailable
		}
		counter, hasCounter := counters.byNumber[mountInfo[mount.Path]]
		if mount.Device != "" {
			counter, hasCounter = counters.byName[mount.Device]
		}
		if usageErr != nil && !hasCounter {
			continue
		}
		disk := &metricsv1.Disk{Mount: mount.Path, Device: mount.Device}
		if usageErr == nil {
			disk.TotalBytes = usage.TotalBytes
			disk.UsedBytes = usage.UsedBytes
			available = true
		}
		if hasCounter {
			disk.Device = counter.name
			disk.ReadSectors = counter.read
			disk.WriteSectors = counter.write
			disk.IoTicksMs = counter.ticks
			available = true
		}
		snapshot.Disks = append(snapshot.Disks, disk)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !available {
		return nil, ErrUnavailable
	}
	return snapshot, nil
}

func (c *Collector) read(ctx context.Context, name string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	file, err := c.proc.Open(name)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()
	data, err := io.ReadAll(io.LimitReader(file, MaxProcBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > MaxProcBytes {
		return nil, errors.New("metrics: proc 来源超过上限")
	}
	return data, nil
}
