// SPDX-License-Identifier: AGPL-3.0-only

// Package metrics 在宿主命名空间读取瞬时原始指标，不维护差分或插件状态。
package metrics

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"math"
	"os"
	"path"
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

// ErrInvalidMounts 表示请求传入的磁盘挂载点列表无效或超过上限。
var ErrInvalidMounts = errors.New("metrics: 挂载配置无效")

// Mount 是宿主受控的挂载配置；Device 为空时按 mountinfo 的设备号匹配。
type Mount struct{ Path, Device string }

// DiskUsage 是容量字节数，和 diskstats 的累计 IO 计数器分离。
type DiskUsage struct{ TotalBytes, UsedBytes uint64 }

// diskUsageFromStatfs 按非特权可用块 Bavail（与 df -h 对齐）计算已用与总字节数。
func diskUsageFromStatfs(blocks, bfree, bavail uint64, bsize int64) (DiskUsage, error) {
	if bsize <= 0 || bfree > blocks || bavail > blocks || blocks > math.MaxUint64/uint64(bsize) {
		return DiskUsage{}, errors.New("metrics: statfs 数据无效或溢出")
	}
	unit := uint64(bsize)
	return DiskUsage{
		TotalBytes: blocks * unit,
		UsedBytes:  (blocks - bavail) * unit,
	}, nil
}

// validMountPath 仅接受规范 POSIX 绝对路径，拒绝 ..、NUL、换行及反斜杠。
func validMountPath(p string) bool {
	if len(p) == 0 || len(p) > 512 || !strings.HasPrefix(p, "/") {
		return false
	}
	if strings.ContainsAny(p, "\x00\r\n\\") {
		return false
	}
	if path.Clean(p) != p {
		return false
	}
	for _, seg := range strings.Split(p, "/") {
		if seg == "." || seg == ".." {
			return false
		}
	}
	return true
}

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
		if !validMountPath(mount.Path) || seen[mount.Path] || (mount.Device != "" && !validDeviceName(mount.Device)) {
			return nil, ErrInvalidMounts
		}
		seen[mount.Path] = true
	}
	return &Collector{proc: options.Proc, mounts: append([]Mount(nil), options.Mounts...), statFS: options.StatFS, clock: options.Clock}, nil
}

// Collect 返回单次采样的原始计数器；局部故障只使该字段缺省，不生成伪造零值。
func (c *Collector) Collect(ctx context.Context) (*metricsv1.MetricsSnapshot, error) {
	return c.CollectMounts(ctx, nil)
}

// CollectMounts 按调用方请求的受控挂载点列表执行单次采集；requestedMounts 为空时回退默认挂载点。
func (c *Collector) CollectMounts(ctx context.Context, requestedMounts []string) (*metricsv1.MetricsSnapshot, error) {
	if ctx == nil {
		return nil, errors.New("metrics: context 不能为空")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	mounts, err := c.resolveMounts(requestedMounts)
	if err != nil {
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
	for _, mount := range mounts {
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

func (c *Collector) resolveMounts(requested []string) ([]Mount, error) {
	if len(requested) == 0 {
		return c.mounts, nil
	}
	if len(requested) > MaxMounts {
		return nil, ErrInvalidMounts
	}
	defaultDevices := make(map[string]string, len(c.mounts))
	for _, m := range c.mounts {
		if m.Device != "" {
			defaultDevices[m.Path] = m.Device
		}
	}
	seen := make(map[string]bool, len(requested))
	resolved := make([]Mount, 0, len(requested))
	for _, raw := range requested {
		if !validMountPath(raw) {
			return nil, ErrInvalidMounts
		}
		if seen[raw] {
			continue
		}
		seen[raw] = true
		resolved = append(resolved, Mount{Path: raw, Device: defaultDevices[raw]})
	}
	return resolved, nil
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
