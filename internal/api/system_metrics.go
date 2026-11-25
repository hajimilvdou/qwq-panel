// SPDX-License-Identifier: AGPL-3.0-only

package api

import (
	"context"
	"math"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/qwq-panel/qwq/internal/capability/metrics"
	"github.com/qwq-panel/qwq/internal/platform/clock"
	"github.com/qwq-panel/qwq/internal/platform/problem"
	metricsv1 "github.com/qwq-panel/qwq/sdk/gen/qwq/capability/metrics/v1"
)

const (
	hostMetricsSampleFloor  = 2 * time.Second
	hostMetricsBgInterval   = 5 * time.Second
	hostMetricsHistoryCap   = 40
	hostMetricsFineCap      = 720  // 1 hour @ 5s resolution
	hostMetricsCoarseCap    = 1440 // 24 hours @ 1m resolution
	hostMetricsMaxReturnPts = 120
	hostMetricsDefaultRange = "15m"
)

type systemMetricsDTO struct {
	CollectedAt           string                  `json:"collected_at"`
	Range                 string                  `json:"range,omitempty"`
	SampleIntervalSeconds int                     `json:"sample_interval_seconds,omitempty"`
	Host                  systemMetricsHostDTO    `json:"host"`
	CPU                   systemMetricsCPUDTO     `json:"cpu"`
	Memory                systemMetricsMemDTO     `json:"memory"`
	Disk                  systemMetricsDiskDTO    `json:"disk"`
	Network               systemMetricsNetDTO     `json:"network"`
	HistoryPoints         []systemMetricsPointDTO `json:"history_points,omitempty"`
}

type systemMetricsPointDTO struct {
	Ts    int64   `json:"ts"`
	CPU   float64 `json:"cpu"`
	Mem   float64 `json:"mem"`
	RxBps float64 `json:"rx_bps"`
	TxBps float64 `json:"tx_bps"`
}

type systemMetricsProcDTO struct {
	PID        int32   `json:"pid"`
	Name       string  `json:"name"`
	CPUPercent float64 `json:"cpu_percent"`
	MemBytes   uint64  `json:"mem_bytes"`
	MemPercent float64 `json:"mem_percent"`
}

type systemMetricsHostDTO struct {
	Hostname      string `json:"hostname"`
	OS            string `json:"os"`
	Kernel        string `json:"kernel"`
	Arch          string `json:"arch"`
	UptimeSeconds uint64 `json:"uptime_seconds"`
}

type systemMetricsCPUDTO struct {
	UsagePercent  float64                `json:"usage_percent"`
	Cores         uint32                 `json:"cores"`
	Model         string                 `json:"model,omitempty"`
	UserPercent   float64                `json:"user_percent"`
	SystemPercent float64                `json:"system_percent"`
	IowaitPercent float64                `json:"iowait_percent"`
	Load1         float64                `json:"load_1"`
	Load5         float64                `json:"load_5"`
	Load15        float64                `json:"load_15"`
	History       []float64              `json:"history"`
	TopProcesses  []systemMetricsProcDTO `json:"top_processes,omitempty"`
}

type systemMetricsMemDTO struct {
	UsedBytes      uint64                 `json:"used_bytes"`
	TotalBytes     uint64                 `json:"total_bytes"`
	AvailableBytes uint64                 `json:"available_bytes"`
	CachedBytes    uint64                 `json:"cached_bytes"`
	BuffersBytes   uint64                 `json:"buffers_bytes"`
	UsagePercent   float64                `json:"usage_percent"`
	SwapUsedBytes  uint64                 `json:"swap_used_bytes"`
	SwapTotalBytes uint64                 `json:"swap_total_bytes"`
	History        []float64              `json:"history"`
	TopProcesses   []systemMetricsProcDTO `json:"top_processes,omitempty"`
}

type systemMetricsMountDTO struct {
	Mount        string  `json:"mount"`
	Device       string  `json:"device,omitempty"`
	UsedBytes    uint64  `json:"used_bytes"`
	TotalBytes   uint64  `json:"total_bytes"`
	UsagePercent float64 `json:"usage_percent"`
}

type systemMetricsDiskDTO struct {
	Mount            string                  `json:"mount"`
	UsedBytes        uint64                  `json:"used_bytes"`
	TotalBytes       uint64                  `json:"total_bytes"`
	UsagePercent     float64                 `json:"usage_percent"`
	ReadBytesPerSec  float64                 `json:"read_bytes_per_sec"`
	WriteBytesPerSec float64                 `json:"write_bytes_per_sec"`
	Mounts           []systemMetricsMountDTO `json:"mounts"`
}

type systemMetricsNetIfDTO struct {
	Name          string  `json:"name"`
	RxBytesPerSec float64 `json:"rx_bytes_per_sec"`
	TxBytesPerSec float64 `json:"tx_bytes_per_sec"`
	RxTotalBytes  uint64  `json:"rx_total_bytes"`
	TxTotalBytes  uint64  `json:"tx_total_bytes"`
}

type systemMetricsNetDTO struct {
	RxBytesPerSec  float64                 `json:"rx_bytes_per_sec"`
	TxBytesPerSec  float64                 `json:"tx_bytes_per_sec"`
	RxTotalBytes   uint64                  `json:"rx_total_bytes"`
	TxTotalBytes   uint64                  `json:"tx_total_bytes"`
	TCPConnections uint32                  `json:"tcp_connections"`
	RxHistory      []float64               `json:"rx_history"`
	TxHistory      []float64               `json:"tx_history"`
	Interfaces     []systemMetricsNetIfDTO `json:"interfaces,omitempty"`
}

type diskIOSample struct {
	readSectors  uint64
	writeSectors uint64
	at           time.Time
}

type coarseBucket struct {
	minute int64
	count  int
	cpuSum float64
	memSum float64
	rxSum  float64
	txSum  float64
}

type hostMetricsTracker struct {
	mu            sync.Mutex
	collector     *metrics.Collector
	prevSnap      *metricsv1.MetricsSnapshot
	lastDTO       *systemMetricsDTO
	lastSampled   time.Time
	cpuHistory    []float64
	memHistory    []float64
	rxHistory     []float64
	txHistory     []float64
	finePoints    []systemMetricsPointDTO
	coarsePoints  []systemMetricsPointDTO
	activeBucket  *coarseBucket
	prevProcTicks map[int32]uint64
	prevDiskIO    *diskIOSample
	hostname      string
	osPretty      string
	kernel        string
	cpuModel      string
	bgOnce        sync.Once
}

func newHostMetricsTracker() *hostMetricsTracker {
	col, _ := metrics.New(metrics.Options{})
	hostname, _ := os.Hostname()
	if strings.TrimSpace(hostname) == "" {
		hostname = "localhost"
	}
	return &hostMetricsTracker{
		collector:     col,
		prevProcTicks: make(map[int32]uint64),
		hostname:      strings.TrimSpace(hostname),
		osPretty:      readHostOSPrettyName(),
		kernel:        readHostKernelRelease(),
		cpuModel:      readHostCPUModel(),
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

func readHostCPUModel() string {
	raw, err := os.ReadFile("/proc/cpuinfo")
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(raw), "\n") {
		if idx := strings.IndexByte(line, ':'); idx > 0 {
			key := strings.TrimSpace(line[:idx])
			if key == "model name" || key == "Model" || key == "Hardware" {
				val := strings.TrimSpace(line[idx+1:])
				if val != "" {
					if len(val) > 120 {
						val = val[:120]
					}
					return val
				}
			}
		}
	}
	return ""
}

func isPrimaryBlockDevice(name string) bool {
	if name == "" || strings.HasPrefix(name, "loop") || strings.HasPrefix(name, "ram") || strings.HasPrefix(name, "dm-") || strings.HasPrefix(name, "sr") {
		return false
	}
	for _, pfx := range []string{"sd", "vd", "xvd", "hd"} {
		if strings.HasPrefix(name, pfx) {
			rest := name[len(pfx):]
			if len(rest) == 0 {
				return false
			}
			for i := 0; i < len(rest); i++ {
				if rest[i] < 'a' || rest[i] > 'z' {
					return false
				}
			}
			return true
		}
	}
	if strings.HasPrefix(name, "nvme") || strings.HasPrefix(name, "mmcblk") {
		return !strings.Contains(name, "p")
	}
	return false
}

func readDiskIOSectors() (readSectors, writeSectors uint64, ok bool) {
	raw, err := os.ReadFile("/proc/diskstats")
	if err != nil {
		return 0, 0, false
	}
	var primaryR, primaryW uint64
	var fallbackR, fallbackW uint64
	var hasPrimary bool
	for _, line := range strings.Split(string(raw), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 10 {
			continue
		}
		dev := fields[2]
		if strings.HasPrefix(dev, "loop") || strings.HasPrefix(dev, "ram") {
			continue
		}
		rSec, err1 := strconv.ParseUint(fields[5], 10, 64)
		wSec, err2 := strconv.ParseUint(fields[9], 10, 64)
		if err1 != nil || err2 != nil {
			continue
		}
		if isPrimaryBlockDevice(dev) {
			hasPrimary = true
			primaryR += rSec
			primaryW += wSec
		} else {
			fallbackR += rSec
			fallbackW += wSec
		}
	}
	if hasPrimary {
		return primaryR, primaryW, true
	}
	return fallbackR, fallbackW, true
}

func countActiveTCPConnections() uint32 {
	var total uint32
	for _, p := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		raw, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		lines := strings.Split(string(raw), "\n")
		for i := 1; i < len(lines); i++ {
			fields := strings.Fields(lines[i])
			if len(fields) >= 4 && fields[3] == "01" {
				total++
			}
		}
	}
	return total
}

func sampleTopProcesses(prevTicks map[int32]uint64, totalCPUTicksDelta uint64, memTotalBytes uint64) (topCPU, topMem []systemMetricsProcDTO, nextTicks map[int32]uint64) {
	nextTicks = make(map[int32]uint64, len(prevTicks))
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, nil, nextTicks
	}
	pageSize := uint64(os.Getpagesize())
	all := make([]systemMetricsProcDTO, 0, 64)
	scanned := 0
	for _, ent := range entries {
		if !ent.IsDir() {
			continue
		}
		pid64, err := strconv.ParseInt(ent.Name(), 10, 32)
		if err != nil || pid64 <= 0 {
			continue
		}
		scanned++
		if scanned > 512 {
			break
		}
		pid := int32(pid64)
		statBytes, err := os.ReadFile(filepath.Join("/proc", ent.Name(), "stat"))
		if err != nil {
			continue
		}
		statStr := string(statBytes)
		openIdx := strings.IndexByte(statStr, '(')
		closeIdx := strings.LastIndexByte(statStr, ')')
		if openIdx < 0 || closeIdx <= openIdx || closeIdx+2 >= len(statStr) {
			continue
		}
		name := strings.TrimSpace(statStr[openIdx+1 : closeIdx])
		if name == "" {
			continue
		}
		if len(name) > 48 {
			name = name[:48]
		}
		rest := strings.Fields(statStr[closeIdx+2:])
		if len(rest) < 13 {
			continue
		}
		utime, err1 := strconv.ParseUint(rest[11], 10, 64)
		stime, err2 := strconv.ParseUint(rest[12], 10, 64)
		if err1 != nil || err2 != nil {
			continue
		}
		ticks := utime + stime
		nextTicks[pid] = ticks

		var cpuPct float64
		if prev, ok := prevTicks[pid]; ok && ticks >= prev && totalCPUTicksDelta > 0 {
			cpuPct = float64(ticks-prev) / float64(totalCPUTicksDelta) * 100.0
			cpuPct = math.Min(100, math.Max(0, math.Round(cpuPct*10)/10))
		}

		var rssBytes uint64
		if statmBytes, err := os.ReadFile(filepath.Join("/proc", ent.Name(), "statm")); err == nil {
			mf := strings.Fields(string(statmBytes))
			if len(mf) >= 2 {
				if pages, perr := strconv.ParseUint(mf[1], 10, 64); perr == nil {
					rssBytes = pages * pageSize
				}
			}
		}
		var memPct float64
		if memTotalBytes > 0 && rssBytes > 0 {
			memPct = math.Min(100, math.Round(float64(rssBytes)/float64(memTotalBytes)*1000)/10)
		}
		all = append(all, systemMetricsProcDTO{
			PID:        pid,
			Name:       name,
			CPUPercent: cpuPct,
			MemBytes:   rssBytes,
			MemPercent: memPct,
		})
	}
	if len(all) == 0 {
		return nil, nil, nextTicks
	}

	byCPU := append([]systemMetricsProcDTO(nil), all...)
	sort.Slice(byCPU, func(i, j int) bool {
		if byCPU[i].CPUPercent != byCPU[j].CPUPercent {
			return byCPU[i].CPUPercent > byCPU[j].CPUPercent
		}
		return byCPU[i].MemBytes > byCPU[j].MemBytes
	})
	if len(byCPU) > 5 {
		byCPU = byCPU[:5]
	}

	byMem := append([]systemMetricsProcDTO(nil), all...)
	sort.Slice(byMem, func(i, j int) bool {
		if byMem[i].MemBytes != byMem[j].MemBytes {
			return byMem[i].MemBytes > byMem[j].MemBytes
		}
		return byMem[i].CPUPercent > byMem[j].CPUPercent
	})
	if len(byMem) > 5 {
		byMem = byMem[:5]
	}
	return byCPU, byMem, nextTicks
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

// Start launches a lightweight 24/7 background sampler goroutine so host trend
// history is recorded continuously even when no browser is viewing the Home page.
func (t *hostMetricsTracker) Start(ctx context.Context, clk clock.Clock) {
	if ctx == nil || ctx.Err() != nil {
		return
	}
	if clk == nil {
		clk = clock.System{}
	}
	t.bgOnce.Do(func() {
		go func() {
			// Take an initial baseline sample right at startup.
			_, _ = t.sample(ctx, clk.Now().UTC(), hostMetricsDefaultRange)
			ticker := time.NewTicker(hostMetricsBgInterval)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					_, _ = t.sample(ctx, clk.Now().UTC(), hostMetricsDefaultRange)
				}
			}
		}()
	})
}

func parseMetricsRange(raw string) (string, time.Duration, int, bool) {
	switch strings.TrimSpace(raw) {
	case "", "15m":
		return "15m", 15 * time.Minute, 5, true
	case "5m":
		return "5m", 5 * time.Minute, 5, true
	case "1h":
		return "1h", time.Hour, 30, true
	case "6h":
		return "6h", 6 * time.Hour, 180, true
	case "24h":
		return "24h", 24 * time.Hour, 720, true
	default:
		return "", 0, 0, false
	}
}

func appendCappedPoint(pts []systemMetricsPointDTO, pt systemMetricsPointDTO, capN int) []systemMetricsPointDTO {
	if n := len(pts); n > 0 && pts[n-1].Ts == pt.Ts {
		pts[n-1] = pt
		return pts
	}
	pts = append(pts, pt)
	if len(pts) > capN {
		pts = append([]systemMetricsPointDTO(nil), pts[len(pts)-capN:]...)
	}
	return pts
}

func (t *hostMetricsTracker) recordPointLocked(pt systemMetricsPointDTO) {
	t.finePoints = appendCappedPoint(t.finePoints, pt, hostMetricsFineCap)

	minute := pt.Ts - (pt.Ts % 60)
	if t.activeBucket == nil {
		t.activeBucket = &coarseBucket{
			minute: minute,
			count:  1,
			cpuSum: pt.CPU,
			memSum: pt.Mem,
			rxSum:  pt.RxBps,
			txSum:  pt.TxBps,
		}
		return
	}
	if minute == t.activeBucket.minute {
		t.activeBucket.count++
		t.activeBucket.cpuSum += pt.CPU
		t.activeBucket.memSum += pt.Mem
		t.activeBucket.rxSum += pt.RxBps
		t.activeBucket.txSum += pt.TxBps
		return
	}
	if minute > t.activeBucket.minute {
		b := t.activeBucket
		c := float64(b.count)
		if c > 0 {
			t.coarsePoints = appendCappedPoint(t.coarsePoints, systemMetricsPointDTO{
				Ts:    b.minute + 30,
				CPU:   clampPct(b.cpuSum / c),
				Mem:   clampPct(b.memSum / c),
				RxBps: math.Round(b.rxSum / c),
				TxBps: math.Round(b.txSum / c),
			}, hostMetricsCoarseCap)
		}
		t.activeBucket = &coarseBucket{
			minute: minute,
			count:  1,
			cpuSum: pt.CPU,
			memSum: pt.Mem,
			rxSum:  pt.RxBps,
			txSum:  pt.TxBps,
		}
	}
}

func downsampleMetricsPoints(pts []systemMetricsPointDTO, maxPts int) []systemMetricsPointDTO {
	if len(pts) <= maxPts || maxPts < 2 {
		return append([]systemMetricsPointDTO(nil), pts...)
	}
	out := make([]systemMetricsPointDTO, 0, maxPts)
	bucketSize := float64(len(pts)) / float64(maxPts)
	for i := 0; i < maxPts; i++ {
		start := int(math.Floor(float64(i) * bucketSize))
		end := int(math.Floor(float64(i+1) * bucketSize))
		if i == maxPts-1 || end > len(pts) {
			end = len(pts)
		}
		if start >= len(pts) {
			break
		}
		if end <= start {
			end = start + 1
		}
		var cpuSum, memSum, rxSum, txSum float64
		count := float64(end - start)
		for k := start; k < end; k++ {
			cpuSum += pts[k].CPU
			memSum += pts[k].Mem
			rxSum += pts[k].RxBps
			txSum += pts[k].TxBps
		}
		// Keep last point's exact timestamp on the final bucket so X-axis reaches "now".
		ts := pts[(start+end-1)/2].Ts
		if i == maxPts-1 {
			ts = pts[end-1].Ts
		}
		out = append(out, systemMetricsPointDTO{
			Ts:    ts,
			CPU:   clampPct(cpuSum / count),
			Mem:   clampPct(memSum / count),
			RxBps: math.Round(rxSum / count),
			TxBps: math.Round(txSum / count),
		})
	}
	return out
}

func (t *hostMetricsTracker) pointsForRangeLocked(rng string, now time.Time) []systemMetricsPointDTO {
	_, dur, _, ok := parseMetricsRange(rng)
	if !ok {
		dur = 15 * time.Minute
	}
	cutoff := now.Unix() - int64(dur.Seconds())

	var src []systemMetricsPointDTO
	if dur <= time.Hour {
		src = t.finePoints
	} else {
		// Combine coarse 1m history with current in-progress fine tail so the rightmost point is always live.
		src = make([]systemMetricsPointDTO, 0, len(t.coarsePoints)+len(t.finePoints))
		var lastCoarseTs int64
		for _, p := range t.coarsePoints {
			if p.Ts >= cutoff {
				src = append(src, p)
				lastCoarseTs = p.Ts
			}
		}
		for _, p := range t.finePoints {
			if p.Ts >= cutoff && p.Ts > lastCoarseTs {
				src = append(src, p)
			}
		}
	}

	filtered := make([]systemMetricsPointDTO, 0, len(src))
	for _, p := range src {
		if p.Ts >= cutoff {
			if n := len(filtered); n > 0 && filtered[n-1].Ts >= p.Ts {
				if filtered[n-1].Ts == p.Ts {
					filtered[n-1] = p
				}
				continue
			}
			filtered = append(filtered, p)
		}
	}
	if len(filtered) == 0 && len(t.finePoints) > 0 {
		filtered = append(filtered, t.finePoints[len(t.finePoints)-1])
	}
	return downsampleMetricsPoints(filtered, hostMetricsMaxReturnPts)
}

func isRelevantNetIf(name string) bool {
	if name == "" || name == "lo" || strings.HasPrefix(name, "veth") || strings.HasPrefix(name, "docker") || strings.HasPrefix(name, "br-") {
		return false
	}
	return true
}

func sumNetBytes(nets []*metricsv1.NetIf) (rx, tx uint64) {
	for _, n := range nets {
		if n == nil || !isRelevantNetIf(n.Name) {
			continue
		}
		rx += n.RxBytes
		tx += n.TxBytes
	}
	return rx, tx
}

func buildNetInterfaces(prev, cur []*metricsv1.NetIf, dt float64) []systemMetricsNetIfDTO {
	prevByName := make(map[string]*metricsv1.NetIf, len(prev))
	for _, n := range prev {
		if n != nil && isRelevantNetIf(n.Name) {
			prevByName[n.Name] = n
		}
	}
	out := make([]systemMetricsNetIfDTO, 0, len(cur))
	for _, n := range cur {
		if n == nil || !isRelevantNetIf(n.Name) {
			continue
		}
		var rxRate, txRate float64
		if dt > 0.05 {
			if p, ok := prevByName[n.Name]; ok {
				if n.RxBytes >= p.RxBytes {
					rxRate = math.Round(float64(n.RxBytes-p.RxBytes) / dt)
				}
				if n.TxBytes >= p.TxBytes {
					txRate = math.Round(float64(n.TxBytes-p.TxBytes) / dt)
				}
			}
		}
		out = append(out, systemMetricsNetIfDTO{
			Name:          n.Name,
			RxBytesPerSec: rxRate,
			TxBytesPerSec: txRate,
			RxTotalBytes:  n.RxBytes,
			TxTotalBytes:  n.TxBytes,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		return (out[i].RxTotalBytes + out[i].TxTotalBytes) > (out[j].RxTotalBytes + out[j].TxTotalBytes)
	})
	if len(out) > 8 {
		out = out[:8]
	}
	return out
}

func cpuBusyTotal(c *metricsv1.Cpu) (busy, total uint64) {
	if c == nil {
		return 0, 0
	}
	idle := c.Idle + c.Iowait
	nonIdle := c.User + c.Nice + c.System + c.Irq + c.Softirq + c.Steal
	return nonIdle, idle + nonIdle
}

func clampPct(v float64) float64 {
	if math.IsNaN(v) || math.IsInf(v, 0) {
		return 0
	}
	return math.Min(100, math.Max(0, math.Round(v*10)/10))
}

func (t *hostMetricsTracker) sample(ctx context.Context, now time.Time, rng string) (systemMetricsDTO, error) {
	normRange, _, intervalSec, ok := parseMetricsRange(rng)
	if !ok {
		normRange = hostMetricsDefaultRange
		intervalSec = 5
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	if t.lastDTO != nil && now.Sub(t.lastSampled) < hostMetricsSampleFloor {
		out := cloneMetricsDTO(*t.lastDTO)
		out.Range = normRange
		out.SampleIntervalSeconds = intervalSec
		out.HistoryPoints = t.pointsForRangeLocked(normRange, now)
		return out, nil
	}
	if t.collector == nil {
		return systemMetricsDTO{}, problem.New(problem.Unavailable, "Host metrics collector is unavailable on this platform.")
	}

	snap, err := t.collector.Collect(ctx)
	if err != nil {
		if t.lastDTO != nil {
			out := cloneMetricsDTO(*t.lastDTO)
			out.Range = normRange
			out.SampleIntervalSeconds = intervalSec
			out.HistoryPoints = t.pointsForRangeLocked(normRange, now)
			return out, nil
		}
		dto := systemMetricsDTO{
			CollectedAt:           now.UTC().Format(time.RFC3339),
			Range:                 normRange,
			SampleIntervalSeconds: intervalSec,
			Host: systemMetricsHostDTO{
				Hostname: t.hostname,
				OS:       t.osPretty,
				Kernel:   t.kernel,
				Arch:     runtime.GOARCH,
			},
			CPU: systemMetricsCPUDTO{
				Cores:   uint32(runtime.NumCPU()),
				Model:   t.cpuModel,
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
			HistoryPoints: []systemMetricsPointDTO{},
		}
		return dto, nil
	}

	// On very first sample, take a brief 120ms baseline delta so initial CPU/Net/Process stats aren't stuck at 0%.
	if t.prevSnap == nil {
		t.prevSnap = snap
		if rSec, wSec, ok := readDiskIOSectors(); ok {
			t.prevDiskIO = &diskIOSample{readSectors: rSec, writeSectors: wSec, at: now}
		}
		_, _, t.prevProcTicks = sampleTopProcesses(t.prevProcTicks, 0, 0)
		timer := time.NewTimer(120 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
		case <-timer.C:
			if second, err2 := t.collector.Collect(ctx); err2 == nil {
				snap = second
				now = time.Now().UTC()
			}
		}
	}

	var cpuPct, userPct, sysPct, iowaitPct float64
	var totalCPUTicksDelta uint64
	if t.prevSnap != nil && t.prevSnap.Cpu != nil && snap.Cpu != nil {
		b0, tot0 := cpuBusyTotal(t.prevSnap.Cpu)
		b1, tot1 := cpuBusyTotal(snap.Cpu)
		if tot1 > tot0 {
			totalCPUTicksDelta = tot1 - tot0
			if b1 >= b0 {
				cpuPct = clampPct(float64(b1-b0) / float64(totalCPUTicksDelta) * 100)
			}
			u0 := t.prevSnap.Cpu.User + t.prevSnap.Cpu.Nice
			u1 := snap.Cpu.User + snap.Cpu.Nice
			if u1 >= u0 {
				userPct = clampPct(float64(u1-u0) / float64(totalCPUTicksDelta) * 100)
			}
			s0 := t.prevSnap.Cpu.System + t.prevSnap.Cpu.Irq + t.prevSnap.Cpu.Softirq + t.prevSnap.Cpu.Steal
			s1 := snap.Cpu.System + snap.Cpu.Irq + snap.Cpu.Softirq + snap.Cpu.Steal
			if s1 >= s0 {
				sysPct = clampPct(float64(s1-s0) / float64(totalCPUTicksDelta) * 100)
			}
			if snap.Cpu.Iowait >= t.prevSnap.Cpu.Iowait {
				iowaitPct = clampPct(float64(snap.Cpu.Iowait-t.prevSnap.Cpu.Iowait) / float64(totalCPUTicksDelta) * 100)
			}
		}
	}

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

	var memUsed, memTotal, memAvail, memCached, memBuffers, swapUsed, swapTotal uint64
	var memPct float64
	if snap.Memory != nil {
		memTotal = snap.Memory.TotalBytes
		memAvail = snap.Memory.AvailableBytes
		memBuffers = snap.Memory.BuffersBytes
		memCached = snap.Memory.CachedBytes + snap.Memory.BuffersBytes
		if memTotal >= memAvail {
			memUsed = memTotal - memAvail
		}
		if memTotal > 0 {
			memPct = clampPct(float64(memUsed) / float64(memTotal) * 100)
		}
		swapTotal = snap.Memory.SwapTotalBytes
		if swapTotal >= snap.Memory.SwapFreeBytes {
			swapUsed = swapTotal - snap.Memory.SwapFreeBytes
		}
	}

	topCPU, topMem, nextProcTicks := sampleTopProcesses(t.prevProcTicks, totalCPUTicksDelta, memTotal)
	t.prevProcTicks = nextProcTicks

	mounts := make([]systemMetricsMountDTO, 0, len(snap.Disks))
	var rootMount systemMetricsMountDTO
	rootMount.Mount = "/"
	for _, d := range snap.Disks {
		if d == nil || d.TotalBytes == 0 {
			continue
		}
		pct := clampPct(float64(d.UsedBytes) / float64(d.TotalBytes) * 100)
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

	var diskReadRate, diskWriteRate float64
	if rSec, wSec, ok := readDiskIOSectors(); ok {
		if t.prevDiskIO != nil {
			dt := now.Sub(t.prevDiskIO.at).Seconds()
			if dt > 0.05 {
				if rSec >= t.prevDiskIO.readSectors {
					diskReadRate = math.Round(float64(rSec-t.prevDiskIO.readSectors) * 512.0 / dt)
				}
				if wSec >= t.prevDiskIO.writeSectors {
					diskWriteRate = math.Round(float64(wSec-t.prevDiskIO.writeSectors) * 512.0 / dt)
				}
			}
		}
		t.prevDiskIO = &diskIOSample{readSectors: rSec, writeSectors: wSec, at: now}
	}

	rxTotal, txTotal := sumNetBytes(snap.Nets)
	var rxRate, txRate float64
	var netDT float64
	if t.prevSnap != nil {
		netDT = float64(snap.CollectedAtUnixMs-t.prevSnap.CollectedAtUnixMs) / 1000.0
		if netDT > 0.05 {
			prevRx, prevTx := sumNetBytes(t.prevSnap.Nets)
			if rxTotal >= prevRx {
				rxRate = math.Round(float64(rxTotal-prevRx) / netDT)
			}
			if txTotal >= prevTx {
				txRate = math.Round(float64(txTotal-prevTx) / netDT)
			}
		}
	}
	var prevNets []*metricsv1.NetIf
	if t.prevSnap != nil {
		prevNets = t.prevSnap.Nets
	}
	netIfs := buildNetInterfaces(prevNets, snap.Nets, netDT)
	tcpConns := countActiveTCPConnections()

	t.cpuHistory = appendHistoryPoint(t.cpuHistory, cpuPct)
	t.memHistory = appendHistoryPoint(t.memHistory, memPct)
	t.rxHistory = appendHistoryPoint(t.rxHistory, rxRate)
	t.txHistory = appendHistoryPoint(t.txHistory, txRate)
	t.recordPointLocked(systemMetricsPointDTO{
		Ts:    now.Unix(),
		CPU:   cpuPct,
		Mem:   memPct,
		RxBps: rxRate,
		TxBps: txRate,
	})
	t.prevSnap = snap
	t.lastSampled = now

	dto := systemMetricsDTO{
		CollectedAt:           now.UTC().Format(time.RFC3339),
		Range:                 normRange,
		SampleIntervalSeconds: intervalSec,
		Host: systemMetricsHostDTO{
			Hostname:      t.hostname,
			OS:            t.osPretty,
			Kernel:        t.kernel,
			Arch:          runtime.GOARCH,
			UptimeSeconds: snap.UptimeSeconds,
		},
		CPU: systemMetricsCPUDTO{
			UsagePercent:  cpuPct,
			Cores:         cores,
			Model:         t.cpuModel,
			UserPercent:   userPct,
			SystemPercent: sysPct,
			IowaitPercent: iowaitPct,
			Load1:         load1,
			Load5:         load5,
			Load15:        load15,
			History:       append([]float64(nil), t.cpuHistory...),
			TopProcesses:  topCPU,
		},
		Memory: systemMetricsMemDTO{
			UsedBytes:      memUsed,
			TotalBytes:     memTotal,
			AvailableBytes: memAvail,
			CachedBytes:    memCached,
			BuffersBytes:   memBuffers,
			UsagePercent:   memPct,
			SwapUsedBytes:  swapUsed,
			SwapTotalBytes: swapTotal,
			History:        append([]float64(nil), t.memHistory...),
			TopProcesses:   topMem,
		},
		Disk: systemMetricsDiskDTO{
			Mount:            rootMount.Mount,
			UsedBytes:        rootMount.UsedBytes,
			TotalBytes:       rootMount.TotalBytes,
			UsagePercent:     rootMount.UsagePercent,
			ReadBytesPerSec:  diskReadRate,
			WriteBytesPerSec: diskWriteRate,
			Mounts:           mounts,
		},
		Network: systemMetricsNetDTO{
			RxBytesPerSec:  rxRate,
			TxBytesPerSec:  txRate,
			RxTotalBytes:   rxTotal,
			TxTotalBytes:   txTotal,
			TCPConnections: tcpConns,
			RxHistory:      append([]float64(nil), t.rxHistory...),
			TxHistory:      append([]float64(nil), t.txHistory...),
			Interfaces:     netIfs,
		},
		HistoryPoints: t.pointsForRangeLocked(normRange, now),
	}
	t.lastDTO = &dto
	return cloneMetricsDTO(dto), nil
}

func cloneMetricsDTO(in systemMetricsDTO) systemMetricsDTO {
	in.CPU.History = append([]float64(nil), in.CPU.History...)
	in.CPU.TopProcesses = append([]systemMetricsProcDTO(nil), in.CPU.TopProcesses...)
	in.Memory.History = append([]float64(nil), in.Memory.History...)
	in.Memory.TopProcesses = append([]systemMetricsProcDTO(nil), in.Memory.TopProcesses...)
	in.Disk.Mounts = append([]systemMetricsMountDTO(nil), in.Disk.Mounts...)
	in.Network.RxHistory = append([]float64(nil), in.Network.RxHistory...)
	in.Network.TxHistory = append([]float64(nil), in.Network.TxHistory...)
	in.Network.Interfaces = append([]systemMetricsNetIfDTO(nil), in.Network.Interfaces...)
	in.HistoryPoints = append([]systemMetricsPointDTO(nil), in.HistoryPoints...)
	return in
}

// getSystemMetrics implements GET /api/v1/system/metrics?range=5m|15m|1h|6h|24h.
// Provides built-in lightweight host CPU/Memory/Disk/Network telemetry backed by
// continuous 24/7 background ring buffers without requiring any external plugin.
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
	rawRange := r.URL.Query().Get("range")
	normRange, _, _, ok := parseMetricsRange(rawRange)
	if !ok {
		a.fail(w, r, problem.New(problem.ValidationFailed, "range must be one of 5m, 15m, 1h, 6h, 24h."))
		return
	}
	dto, err := a.hostMetrics.sample(r.Context(), a.d.Clock.Now().UTC(), normRange)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	a.writeResource(w, r, http.StatusOK, dto, nil)
}
