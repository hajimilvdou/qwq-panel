// SPDX-License-Identifier: AGPL-3.0-only

package api

import (
	"context"
	"math"
	"net/http"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/qwq-panel/qwq/internal/capability/metrics"
	"github.com/qwq-panel/qwq/internal/platform/problem"
	metricsv1 "github.com/qwq-panel/qwq/sdk/gen/qwq/capability/metrics/v1"
)

const (
	hostMetricsSampleFloor = 2 * time.Second
	hostMetricsHistoryCap  = 40
)

type systemMetricsDTO struct {
	CollectedAt string               `json:"collected_at"`
	Host        systemMetricsHostDTO `json:"host"`
	CPU         systemMetricsCPUDTO  `json:"cpu"`
	Memory      systemMetricsMemDTO  `json:"memory"`
	Disk        systemMetricsDiskDTO `json:"disk"`
	Network     systemMetricsNetDTO  `json:"network"`
}

type systemMetricsHostDTO struct {
	Hostname      string `json:"hostname"`
	OS            string `json:"os"`
	Kernel        string `json:"kernel"`
	Arch          string `json:"arch"`
	UptimeSeconds uint64 `json:"uptime_seconds"`
}

type systemMetricsCPUDTO struct {
	UsagePercent float64   `json:"usage_percent"`
	Cores        uint32    `json:"cores"`
	Load1        float64   `json:"load_1"`
	Load5        float64   `json:"load_5"`
	Load15       float64   `json:"load_15"`
	History      []float64 `json:"history"`
}

type systemMetricsMemDTO struct {
	UsedBytes      uint64    `json:"used_bytes"`
	TotalBytes     uint64    `json:"total_bytes"`
	AvailableBytes uint64    `json:"available_bytes"`
	CachedBytes    uint64    `json:"cached_bytes"`
	UsagePercent   float64   `json:"usage_percent"`
	SwapUsedBytes  uint64    `json:"swap_used_bytes"`
	SwapTotalBytes uint64    `json:"swap_total_bytes"`
	History        []float64 `json:"history"`
}

type systemMetricsMountDTO struct {
	Mount        string  `json:"mount"`
	Device       string  `json:"device,omitempty"`
	UsedBytes    uint64  `json:"used_bytes"`
	TotalBytes   uint64  `json:"total_bytes"`
	UsagePercent float64 `json:"usage_percent"`
}

type systemMetricsDiskDTO struct {
	Mount        string                  `json:"mount"`
	UsedBytes    uint64                  `json:"used_bytes"`
	TotalBytes   uint64                  `json:"total_bytes"`
	UsagePercent float64                 `json:"usage_percent"`
	Mounts       []systemMetricsMountDTO `json:"mounts"`
}

type systemMetricsNetDTO struct {
	RxBytesPerSec float64   `json:"rx_bytes_per_sec"`
	TxBytesPerSec float64   `json:"tx_bytes_per_sec"`
	RxTotalBytes  uint64    `json:"rx_total_bytes"`
	TxTotalBytes  uint64    `json:"tx_total_bytes"`
	RxHistory     []float64 `json:"rx_history"`
	TxHistory     []float64 `json:"tx_history"`
}

type hostMetricsTracker struct {
	mu          sync.Mutex
	collector   *metrics.Collector
	prevSnap    *metricsv1.MetricsSnapshot
	lastDTO     *systemMetricsDTO
	lastSampled time.Time
	cpuHistory  []float64
	memHistory  []float64
	rxHistory   []float64
	txHistory   []float64
	hostname    string
	osPretty    string
	kernel      string
}

func newHostMetricsTracker() *hostMetricsTracker {
	col, _ := metrics.New(metrics.Options{})
	hostname, _ := os.Hostname()
	if strings.TrimSpace(hostname) == "" {
		hostname = "localhost"
	}
	return &hostMetricsTracker{
		collector: col,
		hostname:  strings.TrimSpace(hostname),
		osPretty:  readHostOSPrettyName(),
		kernel:    readHostKernelRelease(),
	}
}

func readHostOSPrettyName() string {
	raw, err := os.ReadFile("/etc/os-release")
	if err == nil {
		for _, line := range strings.Split(string(raw), "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "PRETTY_NAME=") {
				v := strings.TrimPrefix(line, "PRETTY_NAME=")
				v = strings.Trim(v, `"'`)
				if v != "" {
					return v
				}
			}
		}
	}
	return runtime.GOOS
}

func readHostKernelRelease() string {
	raw, err := os.ReadFile("/proc/sys/kernel/osrelease")
	if err == nil {
		if v := strings.TrimSpace(string(raw)); v != "" {
			return v
		}
	}
	return runtime.GOOS + "/" + runtime.GOARCH
}

func appendHistoryPoint(hist []float64, v float64) []float64 {
	if math.IsNaN(v) || math.IsInf(v, 0) || v < 0 {
		v = 0
	}
	hist = append(hist, math.Round(v*10)/10)
	if len(hist) > hostMetricsHistoryCap {
		hist = append([]float64(nil), hist[len(hist)-hostMetricsHistoryCap:]...)
	}
	return hist
}

func sumNetBytes(nets []*metricsv1.NetIf) (rx, tx uint64) {
	for _, n := range nets {
		if n == nil || n.Name == "lo" || strings.HasPrefix(n.Name, "veth") || strings.HasPrefix(n.Name, "docker") || strings.HasPrefix(n.Name, "br-") {
			continue
		}
		rx += n.RxBytes
		tx += n.TxBytes
	}
	return rx, tx
}

func cpuBusyTotal(c *metricsv1.Cpu) (busy, total uint64) {
	if c == nil {
		return 0, 0
	}
	idle := c.Idle + c.Iowait
	nonIdle := c.User + c.Nice + c.System + c.Irq + c.Softirq + c.Steal
	return nonIdle, idle + nonIdle
}

func (t *hostMetricsTracker) sample(ctx context.Context, now time.Time) (systemMetricsDTO, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.lastDTO != nil && now.Sub(t.lastSampled) < hostMetricsSampleFloor {
		return cloneMetricsDTO(*t.lastDTO), nil
	}
	if t.collector == nil {
		return systemMetricsDTO{}, problem.New(problem.Unavailable, "Host metrics collector is unavailable on this platform.")
	}

	snap, err := t.collector.Collect(ctx)
	if err != nil {
		if t.lastDTO != nil {
			return cloneMetricsDTO(*t.lastDTO), nil
		}
		// Non-Linux / sandboxed test fallback: return host metadata with zeroed gauges rather than 500.
		dto := systemMetricsDTO{
			CollectedAt: now.UTC().Format(time.RFC3339),
			Host: systemMetricsHostDTO{
				Hostname: t.hostname,
				OS:       t.osPretty,
				Kernel:   t.kernel,
				Arch:     runtime.GOARCH,
			},
			CPU: systemMetricsCPUDTO{
				Cores:   uint32(runtime.NumCPU()),
				History: []float64{},
			},
			Memory: systemMetricsMemDTO{
				History: []float64{},
			},
			Disk: systemMetricsDiskDTO{
				Mount:  "/",
				Mounts: []systemMetricsMountDTO{},
			},
			Network: systemMetricsNetDTO{
				RxHistory: []float64{},
				TxHistory: []float64{},
			},
		}
		return dto, nil
	}

	// On very first sample, take a brief 120ms baseline delta so initial CPU/Net isn't stuck at 0%.
	if t.prevSnap == nil {
		t.prevSnap = snap
		timer := time.NewTimer(120 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
		case <-timer.C:
			if second, err2 := t.collector.Collect(ctx); err2 == nil {
				snap = second
			}
		}
	}

	var cpuPct float64
	if t.prevSnap != nil && t.prevSnap.Cpu != nil && snap.Cpu != nil {
		b0, tot0 := cpuBusyTotal(t.prevSnap.Cpu)
		b1, tot1 := cpuBusyTotal(snap.Cpu)
		if tot1 > tot0 && b1 >= b0 {
			cpuPct = float64(b1-b0) / float64(tot1-tot0) * 100
		}
	}
	cpuPct = math.Min(100, math.Max(0, math.Round(cpuPct*10)/10))

	var cores uint32 = uint32(runtime.NumCPU())
	if snap.Cpu != nil && snap.Cpu.CoreCount > 0 {
		cores = snap.Cpu.CoreCount
	}

	var load1, load5, load15 float64
	if snap.Load != nil {
		load1 = math.Round(snap.Load.Load1*100) / 100
		load5 = math.Round(snap.Load.Load5*100) / 100
		load15 = math.Round(snap.Load.Load15*100) / 100
	}

	var memUsed, memTotal, memAvail, memCached, swapUsed, swapTotal uint64
	var memPct float64
	if snap.Memory != nil {
		memTotal = snap.Memory.TotalBytes
		memAvail = snap.Memory.AvailableBytes
		memCached = snap.Memory.CachedBytes + snap.Memory.BuffersBytes
		if memTotal >= memAvail {
			memUsed = memTotal - memAvail
		}
		if memTotal > 0 {
			memPct = math.Round(float64(memUsed)/float64(memTotal)*1000) / 10
		}
		swapTotal = snap.Memory.SwapTotalBytes
		if swapTotal >= snap.Memory.SwapFreeBytes {
			swapUsed = swapTotal - snap.Memory.SwapFreeBytes
		}
	}

	mounts := make([]systemMetricsMountDTO, 0, len(snap.Disks))
	var rootMount systemMetricsMountDTO
	rootMount.Mount = "/"
	for _, d := range snap.Disks {
		if d == nil || d.TotalBytes == 0 {
			continue
		}
		pct := math.Round(float64(d.UsedBytes)/float64(d.TotalBytes)*1000) / 10
		m := systemMetricsMountDTO{
			Mount:        d.Mount,
			Device:       d.Device,
			UsedBytes:    d.UsedBytes,
			TotalBytes:   d.TotalBytes,
			UsagePercent: pct,
		}
		mounts = append(mounts, m)
		if d.Mount == "/" {
			rootMount = m
		}
	}
	if rootMount.TotalBytes == 0 && len(mounts) > 0 {
		rootMount = mounts[0]
	}

	rxTotal, txTotal := sumNetBytes(snap.Nets)
	var rxRate, txRate float64
	if t.prevSnap != nil {
		dt := float64(snap.CollectedAtUnixMs-t.prevSnap.CollectedAtUnixMs) / 1000.0
		if dt > 0.05 {
			prevRx, prevTx := sumNetBytes(t.prevSnap.Nets)
			if rxTotal >= prevRx {
				rxRate = math.Round(float64(rxTotal-prevRx) / dt)
			}
			if txTotal >= prevTx {
				txRate = math.Round(float64(txTotal-prevTx) / dt)
			}
		}
	}

	t.cpuHistory = appendHistoryPoint(t.cpuHistory, cpuPct)
	t.memHistory = appendHistoryPoint(t.memHistory, memPct)
	t.rxHistory = appendHistoryPoint(t.rxHistory, rxRate)
	t.txHistory = appendHistoryPoint(t.txHistory, txRate)
	t.prevSnap = snap
	t.lastSampled = now

	dto := systemMetricsDTO{
		CollectedAt: now.UTC().Format(time.RFC3339),
		Host: systemMetricsHostDTO{
			Hostname:      t.hostname,
			OS:            t.osPretty,
			Kernel:        t.kernel,
			Arch:          runtime.GOARCH,
			UptimeSeconds: snap.UptimeSeconds,
		},
		CPU: systemMetricsCPUDTO{
			UsagePercent: cpuPct,
			Cores:        cores,
			Load1:        load1,
			Load5:        load5,
			Load15:       load15,
			History:      append([]float64(nil), t.cpuHistory...),
		},
		Memory: systemMetricsMemDTO{
			UsedBytes:      memUsed,
			TotalBytes:     memTotal,
			AvailableBytes: memAvail,
			CachedBytes:    memCached,
			UsagePercent:   memPct,
			SwapUsedBytes:  swapUsed,
			SwapTotalBytes: swapTotal,
			History:        append([]float64(nil), t.memHistory...),
		},
		Disk: systemMetricsDiskDTO{
			Mount:        rootMount.Mount,
			UsedBytes:    rootMount.UsedBytes,
			TotalBytes:   rootMount.TotalBytes,
			UsagePercent: rootMount.UsagePercent,
			Mounts:       mounts,
		},
		Network: systemMetricsNetDTO{
			RxBytesPerSec: rxRate,
			TxBytesPerSec: txRate,
			RxTotalBytes:  rxTotal,
			TxTotalBytes:  txTotal,
			RxHistory:     append([]float64(nil), t.rxHistory...),
			TxHistory:     append([]float64(nil), t.txHistory...),
		},
	}
	t.lastDTO = &dto
	return cloneMetricsDTO(dto), nil
}

func cloneMetricsDTO(in systemMetricsDTO) systemMetricsDTO {
	in.CPU.History = append([]float64(nil), in.CPU.History...)
	in.Memory.History = append([]float64(nil), in.Memory.History...)
	in.Disk.Mounts = append([]systemMetricsMountDTO(nil), in.Disk.Mounts...)
	in.Network.RxHistory = append([]float64(nil), in.Network.RxHistory...)
	in.Network.TxHistory = append([]float64(nil), in.Network.TxHistory...)
	return in
}

// getSystemMetrics implements GET /api/v1/system/metrics.
// Provides built-in lightweight host CPU/Memory/Disk/Network telemetry for the
// Home dashboard without requiring any external monitoring plugin.
func (a *api) getSystemMetrics(w http.ResponseWriter, r *http.Request) {
	act, err := a.caller(r)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	if err := a.authorize(r.Context(), act, "host.system:read", ""); err != nil {
		a.fail(w, r, err)
		return
	}
	dto, err := a.hostMetrics.sample(r.Context(), a.d.Clock.Now().UTC())
	if err != nil {
		a.fail(w, r, err)
		return
	}
	a.writeResource(w, r, http.StatusOK, dto, nil)
}
