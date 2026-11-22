// SPDX-License-Identifier: AGPL-3.0-only

package metrics

import (
	"context"
	"errors"
	"io/fs"
	"strings"
	"sync"
	"testing"
	"testing/fstest"
	"time"

	"github.com/qwq-panel/qwq/internal/platform/clock"
	"github.com/qwq-panel/qwq/internal/pluginhost/hostsvc"
)

func procFixture() fstest.MapFS {
	return fstest.MapFS{
		"stat":           {Data: []byte("cpu 100 20 30 400 5 6 7 8 9 10\ncpu0 0\ncpu1 0\n")},
		"meminfo":        {Data: []byte("MemTotal: 1048576 kB\nMemAvailable: 524288 kB\nBuffers: 1024 kB\nCached: 2048 kB\nSwapTotal: 4096 kB\nSwapFree: 1024 kB\n")},
		"loadavg":        {Data: []byte("0.50 0.25 0.10 1/123 456\n")},
		"uptime":         {Data: []byte("1234.56 1000.00\n")},
		"net/dev":        {Data: []byte("Inter-| Receive | Transmit\n face |bytes packets errs drop fifo frame compressed multicast|bytes packets errs drop fifo colls carrier compressed\n eth0: 1000 10 0 0 0 0 0 0 2000 20 0 0 0 0 0 0\n")},
		"diskstats":      {Data: []byte("8 1 vda1 10 0 20 0 30 0 40 0 0 50 0\n")},
		"self/mountinfo": {Data: []byte("36 25 8:1 / / rw,relatime - ext4 /dev/vda1 rw\n")},
	}
}

func fixtureCollector(t *testing.T, proc fs.FS) *Collector {
	t.Helper()
	collector, err := New(Options{
		Proc: proc, Clock: clock.NewFake(time.UnixMilli(4242000)),
		StatFS: func(ctx context.Context, path string) (DiskUsage, error) {
			if err := ctx.Err(); err != nil {
				return DiskUsage{}, err
			}
			if path != "/" {
				return DiskUsage{}, errors.New("unexpected mount")
			}
			return DiskUsage{TotalBytes: 1 << 30, UsedBytes: 1 << 28}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return collector
}

func TestCollectRawHostMetrics(t *testing.T) {
	collector := fixtureCollector(t, procFixture())
	snapshot, err := collector.Collect(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.CollectedAtUnixMs != 4242000 || snapshot.Cpu.User != 100 || snapshot.Cpu.Idle != 400 || snapshot.Cpu.CoreCount != 2 || snapshot.Cpu.Steal != 8 {
		t.Fatal("CPU 原始计数器或采样时间错误")
	}
	if snapshot.Memory.TotalBytes != 1<<30 || snapshot.Memory.AvailableBytes != 1<<29 || snapshot.Memory.SwapTotalBytes != 4<<20 {
		t.Fatal("meminfo 单位转换错误")
	}
	if snapshot.Load.Load1 != 0.5 || snapshot.UptimeSeconds != 1234 {
		t.Fatal("负载/uptime 错误")
	}
	if len(snapshot.Nets) != 1 || snapshot.Nets[0].Name != "eth0" || snapshot.Nets[0].RxBytes != 1000 || snapshot.Nets[0].TxPackets != 20 {
		t.Fatal("读取了错误的网卡字段")
	}
	if len(snapshot.Disks) != 1 || snapshot.Disks[0].Device != "vda1" || snapshot.Disks[0].ReadSectors != 20 || snapshot.Disks[0].WriteSectors != 40 || snapshot.Disks[0].IoTicksMs != 50 || snapshot.Disks[0].UsedBytes != 1<<28 {
		t.Fatal("磁盘字段位置/挂载点容量错误")
	}
	second, err := collector.Collect(t.Context())
	if err != nil || second.Cpu.User != snapshot.Cpu.User {
		t.Fatal("agent 不应把累计计数器变成速率")
	}
}

func TestCollectPartialFailure(t *testing.T) {
	proc := procFixture()
	delete(proc, "meminfo")
	proc["loadavg"] = &fstest.MapFile{Data: []byte("NaN Inf -1 1/1 1")}
	proc["net/dev"] = &fstest.MapFile{Data: []byte("eth0: invalid")}
	snapshot, err := fixtureCollector(t, proc).Collect(t.Context())
	if err != nil || snapshot.Cpu == nil || snapshot.Memory != nil || snapshot.Load != nil || len(snapshot.Nets) != 0 {
		t.Fatal("局部读取失败破坏了其余指标或伪造零值")
	}
}

func TestCollectUnavailableAndCancellation(t *testing.T) {
	collector, err := New(Options{Proc: fstest.MapFS{}, StatFS: func(context.Context, string) (DiskUsage, error) { return DiskUsage{}, errors.New("missing") }})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := collector.Collect(t.Context()); !errors.Is(err, ErrUnavailable) {
		t.Fatal("整体不可用未明确报告")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := collector.Collect(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal("未尊重取消")
	}
}

func TestCollectRejectsOverflowAndOversizedSource(t *testing.T) {
	proc := procFixture()
	proc["meminfo"] = &fstest.MapFile{Data: []byte("MemTotal: 18446744073709551615 kB\n")}
	proc["stat"] = &fstest.MapFile{Data: []byte(strings.Repeat("x", MaxProcBytes+1))}
	snapshot, err := fixtureCollector(t, proc).Collect(t.Context())
	if err != nil || snapshot.Cpu != nil || snapshot.Memory != nil || snapshot.Load == nil {
		t.Fatal("溢出/超限数据未隔离")
	}
}

func TestCollectorConcurrentAndForwarder(t *testing.T) {
	collector := fixtureCollector(t, procFixture())
	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			for range 8 {
				if _, err := collector.Collect(t.Context()); err != nil {
					t.Error(err)
				}
			}
		})
	}
	wg.Wait()
	forwarder := Forwarder{Collector: collector}
	result, err := forwarder.Forward(t.Context(), hostsvc.CapabilityCall{Service: "metrics", Method: "ReadMetrics", Verb: "metrics.read"})
	if err != nil || result.Response == nil {
		t.Fatal("本地 metrics 转发失败")
	}
	if _, err := forwarder.Forward(t.Context(), hostsvc.CapabilityCall{Service: "account", Method: "SetPassword"}); err == nil {
		t.Fatal("metrics forwarder 接受了其他能力")
	}
}

func TestCollectorTrustedMountBounds(t *testing.T) {
	for _, mounts := range [][]Mount{{{Path: "../outside"}}, make([]Mount, MaxMounts+1)} {
		if _, err := New(Options{Proc: procFixture(), Mounts: mounts}); err == nil {
			t.Fatal("非法挂载配置未被拒绝")
		}
	}
}

func TestCollectorRejectsInvalidCapacityWithoutFakeDisk(t *testing.T) {
	proc := procFixture()
	delete(proc, "diskstats")
	collector, err := New(Options{Proc: proc, StatFS: func(context.Context, string) (DiskUsage, error) { return DiskUsage{TotalBytes: 1, UsedBytes: 2}, nil }})
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := collector.Collect(t.Context())
	if err != nil || len(snapshot.Disks) != 0 || snapshot.Cpu == nil {
		t.Fatal("无效容量制造了假磁盘零值或破坏其他指标")
	}
}
