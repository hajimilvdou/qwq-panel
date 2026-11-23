// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/qwq-panel/qwq/internal/capability/sysctl"
	"github.com/qwq-panel/qwq/internal/sandbox"
	"github.com/qwq-panel/qwq/sdk/pluginsdk"
)

const (
	maxTuningSnapshots = 20
	sysctlDropInPath   = "/etc/sysctl.d/99-qwq-tcpfit.conf"
)

var sweepPeerRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,252}$`)

// hostTuningProfile 对应 Kylin010/tcpfit 的宿主机规格与当前内核网络画像。
type hostTuningProfile struct {
	OS              string            `json:"os"`
	KernelVersion   string            `json:"kernel_version"`
	CPUs            int               `json:"cpus"`
	TotalRAMMB      int64             `json:"total_ram_mb"`
	SwapTotalMB     int64             `json:"swap_total_mb"`
	SwapFreeMB      int64             `json:"swap_free_mb"`
	Iperf3Available bool              `json:"iperf3_available"`
	SysctlAvailable bool              `json:"sysctl_available"`
	CurrentSysctl   map[string]string `json:"current_sysctl"`
}

// tcpfitPlanRequest 是动态 BDP + 内存预算推导输入。
type tcpfitPlanRequest struct {
	Role          string `json:"role"`           // proxy | relay | web
	BandwidthMbps int    `json:"bandwidth_mbps"` // 标称或实测带宽 (Mbps)
	RTTMs         int    `json:"rtt_ms"`         // 典型往返时延 (ms)
	MemBudgetPct  int    `json:"mem_budget_pct"` // TCP 缓冲区占物理内存上限百分比 (5..30, 默认 12)
	PreferCC      string `json:"prefer_cc"`      // auto | bbr | brutal | cubic
}

type sysctlDiffItem struct {
	Key         string `json:"key"`
	Current     string `json:"current"`
	Recommended string `json:"recommended"`
	Reason      string `json:"reason"`
}

// tcpfitPlanResult 是动态推导后的完整调优方案与 /etc/sysctl.d/99-qwq-tcpfit.conf 渲染文本。
type tcpfitPlanResult struct {
	Profile            hostTuningProfile `json:"profile"`
	Role               string            `json:"role"`
	BandwidthMbps      int               `json:"bandwidth_mbps"`
	RTTMs              int               `json:"rtt_ms"`
	BDPBytes           int64             `json:"bdp_bytes"`
	MaxBufferBytes     int64             `json:"max_buffer_bytes"`
	MemBudgetBytes     int64             `json:"mem_budget_bytes"`
	SelectedCC         string            `json:"selected_cc"`
	SwapRecommendation string            `json:"swap_recommendation,omitempty"`
	Changes            []sysctlDiffItem  `json:"changes"`
	SysctlMap          map[string]string `json:"sysctl_map"`
	RenderedConf       string            `json:"rendered_conf"`
}

type tuningSnapshotRecord struct {
	ID            string            `json:"id"`
	Revision      int64             `json:"revision"`
	Reason        string            `json:"reason"`
	Role          string            `json:"role"`
	BandwidthMbps int               `json:"bandwidth_mbps"`
	RTTMs         int               `json:"rtt_ms"`
	Applied       bool              `json:"applied"`
	Pinned        bool              `json:"pinned"`
	SysctlMap     map[string]string `json:"sysctl_map,omitempty"`
	CreatedAt     int64             `json:"created_at"`
}

var trackedSysctlKeys = []string{
	"net.core.default_qdisc",
	"net.ipv4.tcp_congestion_control",
	"net.core.rmem_max",
	"net.core.wmem_max",
	"net.ipv4.tcp_rmem",
	"net.ipv4.tcp_wmem",
	"net.ipv4.tcp_mtu_probing",
	"net.ipv4.tcp_slow_start_after_idle",
	"net.ipv4.tcp_notsent_lowat",
	"net.ipv4.tcp_tw_reuse",
	"net.core.somaxconn",
	"net.core.netdev_max_backlog",
	"net.ipv4.ip_forward",
	"net.ipv6.conf.all.forwarding",
	"net.netfilter.nf_conntrack_max",
}

func readProcSysctl(key string) string {
	path := "/proc/sys/" + strings.ReplaceAll(key, ".", "/")
	raw, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.Join(strings.Fields(string(raw)), " ")
}

func readMemInfoMB() (totalMB, swapTotalMB, swapFreeMB int64) {
	raw, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 1024, 0, 0
	}
	for _, line := range strings.Split(string(raw), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		valKB, err := strconv.ParseInt(fields[1], 10, 64)
		if err != nil {
			continue
		}
		switch fields[0] {
		case "MemTotal:":
			totalMB = valKB / 1024
		case "SwapTotal:":
			swapTotalMB = valKB / 1024
		case "SwapFree:":
			swapFreeMB = valKB / 1024
		}
	}
	if totalMB <= 0 {
		totalMB = 1024
	}
	return totalMB, swapTotalMB, swapFreeMB
}

func detectHostProfile() hostTuningProfile {
	totalRAM, swapTotal, swapFree := readMemInfoMB()
	cur := make(map[string]string, len(trackedSysctlKeys))
	for _, k := range trackedSysctlKeys {
		cur[k] = readProcSysctl(k)
	}
	kernelVer := ""
	if b, err := os.ReadFile("/proc/sys/kernel/osrelease"); err == nil {
		kernelVer = strings.TrimSpace(string(b))
	}
	_, iperfErr := exec.LookPath("iperf3")
	_, sysctlErr := exec.LookPath("sysctl")
	return hostTuningProfile{
		OS:              runtime.GOOS,
		KernelVersion:   kernelVer,
		CPUs:            runtime.NumCPU(),
		TotalRAMMB:      totalRAM,
		SwapTotalMB:     swapTotal,
		SwapFreeMB:      swapFree,
		Iperf3Available: iperfErr == nil,
		SysctlAvailable: sysctlErr == nil,
		CurrentSysctl:   cur,
	}
}

// computeTcpfitPlan 遵循 Kylin010/tcpfit 核心算法：根据实测物理内存预算 + 带宽/RTT 算 BDP，
// 动态推导安全不爆内存的 TCP 缓冲区与拥塞/队列参数。
func computeTcpfitPlan(profile hostTuningProfile, brutal brutalEnvInfo, in tcpfitPlanRequest) (tcpfitPlanResult, error) {
	role := strings.ToLower(strings.TrimSpace(in.Role))
	if role == "" {
		role = "proxy"
	}
	if role != "proxy" && role != "relay" && role != "web" {
		return tcpfitPlanResult{}, pluginsdk.Errorf("INVALID_ARGUMENT", "role 仅支持 proxy / relay / web")
	}
	bw := in.BandwidthMbps
	if bw == 0 {
		bw = 500
	}
	if bw < 10 || bw > 10000 {
		return tcpfitPlanResult{}, pluginsdk.Errorf("INVALID_ARGUMENT", "bandwidth_mbps 须在 10..10000 之间")
	}
	rtt := in.RTTMs
	if rtt == 0 {
		rtt = 150
	}
	if rtt < 1 || rtt > 1000 {
		return tcpfitPlanResult{}, pluginsdk.Errorf("INVALID_ARGUMENT", "rtt_ms 须在 1..1000 之间")
	}
	pct := in.MemBudgetPct
	if pct == 0 {
		pct = 12
	}
	if pct < 5 || pct > 30 {
		return tcpfitPlanResult{}, pluginsdk.Errorf("INVALID_ARGUMENT", "mem_budget_pct 须在 5..30 之间")
	}

	// BDP (Bytes) = Mbps * 125,000 * (RTT_ms / 1000)
	bdp := int64(bw) * 125 * int64(rtt)
	memBudget := (profile.TotalRAMMB * 1024 * 1024) * int64(pct) / 100

	// 1C1G/小内存 VPS 安全封顶，避免经典一键脚本 64MB/128MB 固定值撑爆 OOM。
	hardCap := int64(64 * 1024 * 1024)
	if profile.TotalRAMMB <= 768 {
		hardCap = 8 * 1024 * 1024
	} else if profile.TotalRAMMB <= 1536 {
		hardCap = 16 * 1024 * 1024
	} else if profile.TotalRAMMB <= 3072 {
		hardCap = 32 * 1024 * 1024
	}
	if memBudget > hardCap {
		memBudget = hardCap
	}

	targetBuf := bdp * 2
	if role == "relay" {
		targetBuf = bdp * 5 / 2
	}
	const minBuf = 2 * 1024 * 1024
	if targetBuf < minBuf {
		targetBuf = minBuf
	}
	if targetBuf > memBudget {
		targetBuf = memBudget
	}
	// 对齐到 4 KiB 页边界
	targetBuf = (targetBuf / 4096) * 4096
	if targetBuf < minBuf {
		targetBuf = minBuf
	}

	// 拥塞控制算法优选：严禁在全局 sysctl 启用 brutal（否则未执行 TCP_BRUTAL_PARAMS 的整机连接会被限速至 ~1 Mbps）！
	// 全局恒使用 bbr（单端口超发请使用下方 TCP Brutal 透明接管器），仅显式指定 cubic 时切 cubic。
	selectedCC := "bbr"
	ccReason := "全局恒使用 bbr 拥塞控制（如需 TCP Brutal 超发，请通过下方单端口透明接管器按端口启用）"
	hasBBR := false
	for _, cc := range brutal.AvailableCC {
		if cc == "bbr" {
			hasBBR = true
		}
	}
	switch strings.ToLower(strings.TrimSpace(in.PreferCC)) {
	case "brutal":
		selectedCC = "bbr"
		ccReason = "已拒绝全局设置 tcp_congestion_control=brutal（防止普通连接退化至 ~1 Mbps），全局保持 bbr；请使用下方 TCP Brutal 透明接管器按端口开启"
	case "cubic":
		selectedCC = "cubic"
		ccReason = "按用户偏好选择全局 cubic 拥塞控制"
	case "bbr":
		selectedCC = "bbr"
	default:
		if hasBBR || len(brutal.AvailableCC) == 0 {
			selectedCC = "bbr"
		} else {
			selectedCC = "bbr"
			for _, cc := range brutal.AvailableCC {
				if cc == "cubic" || cc == "reno" {
					selectedCC = cc
					break
				}
			}
		}
	}

	somaxconn := 4096
	backlog := 4096
	if profile.TotalRAMMB >= 2048 {
		somaxconn = 8192
		backlog = 16384
	}
	notsentLowat := 16384
	if role == "relay" {
		notsentLowat = 32768
	}

	recMap := map[string]string{
		"net.core.default_qdisc":             "fq",
		"net.ipv4.tcp_congestion_control":    selectedCC,
		"net.core.rmem_max":                  strconv.FormatInt(targetBuf, 10),
		"net.core.wmem_max":                  strconv.FormatInt(targetBuf, 10),
		"net.ipv4.tcp_rmem":                  fmt.Sprintf("4096 131072 %d", targetBuf),
		"net.ipv4.tcp_wmem":                  fmt.Sprintf("4096 65536 %d", targetBuf),
		"net.ipv4.tcp_mtu_probing":           "1",
		"net.ipv4.tcp_slow_start_after_idle": "0",
		"net.ipv4.tcp_notsent_lowat":         strconv.Itoa(notsentLowat),
		"net.ipv4.tcp_tw_reuse":              "1",
		"net.core.somaxconn":                 strconv.Itoa(somaxconn),
		"net.core.netdev_max_backlog":        strconv.Itoa(backlog),
	}
	if role == "relay" {
		recMap["net.ipv4.ip_forward"] = "1"
		recMap["net.ipv6.conf.all.forwarding"] = "1"
		recMap["net.netfilter.nf_conntrack_max"] = "262144"
	}

	reasons := map[string]string{
		"net.core.default_qdisc":             "BBR / Brutal 精准发包节奏依赖 fq 队列调度",
		"net.ipv4.tcp_congestion_control":    ccReason,
		"net.core.rmem_max":                  fmt.Sprintf("基于 BDP(%d KiB) 与内存上限(%d MiB) 动态封顶，兼顾吞吐与防 OOM", bdp/1024, hardCap/(1024*1024)),
		"net.core.wmem_max":                  "与接收窗口对齐并受小内存预算约束",
		"net.ipv4.tcp_rmem":                  "动态推导的 TCP 接收缓冲区最小/默认/上限",
		"net.ipv4.tcp_wmem":                  "动态推导的 TCP 发送缓冲区最小/默认/上限",
		"net.ipv4.tcp_mtu_probing":           "自动探测黑洞路径 MTU，减少跨境分片丢包",
		"net.ipv4.tcp_slow_start_after_idle": "关闭空闲后重进慢启动，提升代理短连接首包速度",
		"net.ipv4.tcp_notsent_lowat":         "抑制内核未发送队列膨胀，显著降低交互延迟 (Bufferbloat)",
		"net.ipv4.tcp_tw_reuse":              "高并发代理转发下安全复用 TIME_WAIT 套接字",
		"net.core.somaxconn":                 "适配代理监听队列深度",
		"net.core.netdev_max_backlog":        "提升网卡软中断突发包接收能力",
		"net.ipv4.ip_forward":                "中转机 (relay) 必须开启 IPv4 转发",
		"net.ipv6.conf.all.forwarding":       "中转机 (relay) 必须开启 IPv6 转发",
		"net.netfilter.nf_conntrack_max":     "提高中转机连接追踪表上限至 262144，防止高并发丢包",
	}

	changes := make([]sysctlDiffItem, 0, len(recMap))
	for _, k := range trackedSysctlKeys {
		recVal, ok := recMap[k]
		if !ok {
			continue
		}
		changes = append(changes, sysctlDiffItem{
			Key:         k,
			Current:     profile.CurrentSysctl[k],
			Recommended: recVal,
			Reason:      reasons[k],
		})
	}

	swapRec := ""
	if profile.TotalRAMMB <= 2048 && profile.SwapTotalMB == 0 {
		swapRec = "检测到小内存主机且无 Swap，建议配置 1G–2G Swap 防止高并发转发 OOM（参考：fallocate -l 1G /swapfile && chmod 600 /swapfile && mkswap /swapfile && swapon /swapfile）。"
	}

	return tcpfitPlanResult{
		Profile:            profile,
		Role:               role,
		BandwidthMbps:      bw,
		RTTMs:              rtt,
		BDPBytes:           bdp,
		MaxBufferBytes:     targetBuf,
		MemBudgetBytes:     memBudget,
		SelectedCC:         selectedCC,
		SwapRecommendation: swapRec,
		Changes:            changes,
		SysctlMap:          recMap,
		RenderedConf:       renderSysctlConf(role, bw, rtt, recMap),
	}, nil
}

func isAllowedSysctlKey(key string) bool {
	for _, k := range trackedSysctlKeys {
		if k == key {
			return true
		}
	}
	return false
}

func renderSysctlConf(role string, bw, rtt int, kv map[string]string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Generated by qwq proxy.advanced (tcpfit dynamic tuner) — role=%s bw=%dMbps rtt=%dms\n", role, bw, rtt)
	keys := make([]string, 0, len(kv))
	for k := range kv {
		if isAllowedSysctlKey(k) {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	for _, k := range keys {
		v := strings.TrimSpace(kv[k])
		if v == "" || strings.ContainsAny(v, "\r\n\x00;") {
			continue
		}
		fmt.Fprintf(&b, "%s = %s\n", k, v)
	}
	return b.String()
}

func (s *proxyStore) SaveTuningSnapshot(ctx context.Context, reason, role string, bw, rtt int, sysctlMap map[string]string, applied bool) (tuningSnapshotRecord, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return tuningSnapshotRecord{}, err
	}
	defer func() { _ = tx.Rollback() }()

	var nextRev int64
	_ = tx.QueryRowContext(ctx, `SELECT COALESCE(MAX(revision), 0) + 1 FROM tuning_snapshots`).Scan(&nextRev)
	if nextRev <= 0 {
		nextRev = 1
	}
	raw, _ := json.Marshal(sysctlMap)
	if len(raw) == 0 || string(raw) == "null" {
		raw = []byte("{}")
	}
	var pinnedCount int
	_ = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM tuning_snapshots WHERE pinned = 1`).Scan(&pinnedCount)
	pinned := reason == "pre_apply_baseline" && pinnedCount == 0

	id := "tsnp_" + strconv.FormatInt(nextRev, 10) + "_" + strconv.FormatInt(s.now().Unix(), 10)
	nowMs := s.now().UTC().UnixMilli()
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO tuning_snapshots(id, revision, reason, role, bandwidth_mbps, rtt_ms, sysctl_json, applied, pinned, created_at)
		VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		id, nextRev, reason, role, bw, rtt, string(raw), boolToInt(applied), boolToInt(pinned), nowMs); err != nil {
		return tuningSnapshotRecord{}, err
	}
	_, _ = tx.ExecContext(ctx, `
		DELETE FROM tuning_snapshots
		WHERE pinned = 0
		  AND id NOT IN (SELECT id FROM tuning_snapshots ORDER BY revision DESC LIMIT ?)`,
		maxTuningSnapshots)
	if err := tx.Commit(); err != nil {
		return tuningSnapshotRecord{}, err
	}
	return tuningSnapshotRecord{
		ID:            id,
		Revision:      nextRev,
		Reason:        reason,
		Role:          role,
		BandwidthMbps: bw,
		RTTMs:         rtt,
		Applied:       applied,
		Pinned:        pinned,
		SysctlMap:     sysctlMap,
		CreatedAt:     nowMs,
	}, nil
}

func (s *proxyStore) ListTuningSnapshots(ctx context.Context) ([]tuningSnapshotRecord, error) {
	rows, err := s.readDB().QueryContext(ctx, `
		SELECT id, revision, reason, role, bandwidth_mbps, rtt_ms, sysctl_json, applied, pinned, created_at
		FROM tuning_snapshots ORDER BY pinned DESC, revision DESC LIMIT ?`, maxTuningSnapshots+1)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]tuningSnapshotRecord, 0)
	for rows.Next() {
		var r tuningSnapshotRecord
		var raw string
		var ap, pin int
		if err := rows.Scan(&r.ID, &r.Revision, &r.Reason, &r.Role, &r.BandwidthMbps, &r.RTTMs, &raw, &ap, &pin, &r.CreatedAt); err != nil {
			return nil, err
		}
		r.Applied = ap == 1
		r.Pinned = pin == 1
		_ = json.Unmarshal([]byte(raw), &r.SysctlMap)
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *proxyStore) GetTuningSnapshot(ctx context.Context, id string, rev int64) (tuningSnapshotRecord, error) {
	var r tuningSnapshotRecord
	var raw string
	var ap, pin int
	var err error
	if id != "" {
		err = s.readDB().QueryRowContext(ctx, `
			SELECT id, revision, reason, role, bandwidth_mbps, rtt_ms, sysctl_json, applied, pinned, created_at
			FROM tuning_snapshots WHERE id = ?`, id).
			Scan(&r.ID, &r.Revision, &r.Reason, &r.Role, &r.BandwidthMbps, &r.RTTMs, &raw, &ap, &pin, &r.CreatedAt)
	} else {
		err = s.readDB().QueryRowContext(ctx, `
			SELECT id, revision, reason, role, bandwidth_mbps, rtt_ms, sysctl_json, applied, pinned, created_at
			FROM tuning_snapshots WHERE revision = ?`, rev).
			Scan(&r.ID, &r.Revision, &r.Reason, &r.Role, &r.BandwidthMbps, &r.RTTMs, &raw, &ap, &pin, &r.CreatedAt)
	}
	if err != nil {
		return r, pluginsdk.Errorf("NOT_FOUND", "调优快照不存在")
	}
	r.Applied = ap == 1
	r.Pinned = pin == 1
	_ = json.Unmarshal([]byte(raw), &r.SysctlMap)
	return r, nil
}

// filterCapabilitySysctlKV 仅保留 qwq-capability sysctl 白名单允许的内核键，并确保禁止全局 brutal。
func filterCapabilitySysctlKV(kv map[string]string) map[string]string {
	out := make(map[string]string, len(kv))
	for k, v := range kv {
		validator, ok := sysctl.AllowedSysctlValidators[k]
		if !ok {
			continue
		}
		cleanVal := strings.TrimSpace(v)
		if cleanVal == "" || validator(cleanVal) != nil {
			continue
		}
		out[k] = cleanVal
	}
	return out
}

// applySysctlConfigWithCapability 优先通过宿主特权能力 qwq-capability (sysctl.apply / sysctl.rollback) 原子落盘生效；
// 在非默认路径（单元测试隔离目录）或宿主能力套接字未就绪时优雅回退至本地落盘。
func applySysctlConfigWithCapability(ctx context.Context, targetPath string, kv map[string]string, rendered string, dryRun bool, rollback bool) (bool, string, error) {
	if dryRun {
		return false, "dry_run 模式：已保存基线快照与渲染配置，未改动宿主机内核参数。", nil
	}
	if targetPath == sysctlDropInPath {
		if _, statErr := os.Stat(sandbox.DefaultCapabilitySocket); statErr == nil {
			filtered := filterCapabilitySysctlKV(kv)
			var op string
			var params []byte
			if rollback {
				op = "sysctl.rollback"
				params, _ = json.Marshal(map[string]any{"baseline": filtered})
			} else if len(filtered) > 0 {
				op = "sysctl.apply"
				params, _ = json.Marshal(map[string]any{"values": filtered})
			}
			if op != "" {
				capClient := sandbox.NewCapabilityClient(sandbox.DefaultCapabilitySocket)
				resp, callErr := capClient.Call(ctx, sandbox.CapabilityRequest{
					Op:         op,
					ID:         "proxy.advanced",
					ParamsJSON: params,
				})
				if callErr == nil {
					if !resp.OK {
						return false, resp.Error, fmt.Errorf("qwq-capability %s rejected (%s): %s", op, resp.Code, resp.Error)
					}
					return true, "applied via qwq-capability (" + op + ")", nil
				}
			}
		}
	}
	return applySysctlConfig(ctx, targetPath, rendered, dryRun)
}

// applySysctlConfig 将渲染好的调优文件原子落盘，并在系统具备权限时执行 sysctl -p 生效。
func applySysctlConfig(ctx context.Context, targetPath string, rendered string, dryRun bool) (bool, string, error) {
	if dryRun {
		return false, "dry_run 模式：已保存基线快照与渲染配置，未改动宿主机内核参数。", nil
	}
	if err := os.MkdirAll(filepath.Dir(targetPath), 0o755); err != nil {
		return false, "", err
	}
	tmp := targetPath + ".tmp"
	if err := os.WriteFile(tmp, []byte(rendered), 0o644); err != nil {
		return false, "", err
	}
	if err := os.Rename(tmp, targetPath); err != nil {
		_ = os.Remove(tmp)
		return false, "", err
	}
	sysctlBin, err := exec.LookPath("sysctl")
	if err != nil {
		return false, "已写入配置文件 " + targetPath + "，但宿主机未找到 sysctl 命令。", nil
	}
	cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	out, runErr := exec.CommandContext(cctx, sysctlBin, "-p", targetPath).CombinedOutput()
	if runErr != nil {
		return false, strings.TrimSpace(string(out)), runErr
	}
	return true, strings.TrimSpace(string(out)), nil
}

// runIperf3Sweep 执行无 Shell 注入的 iperf3 拐点探测（当宿主机未装 iperf3 时诚实返回不可用与参考命令）。
func runIperf3Sweep(ctx context.Context, peerHost string, peerPort int, durationSec int) (map[string]any, error) {
	peerHost = strings.TrimSpace(peerHost)
	if !sweepPeerRe.MatchString(peerHost) {
		return nil, pluginsdk.Errorf("INVALID_ARGUMENT", "peer_host 格式非法")
	}
	if peerPort <= 0 || peerPort > 65535 {
		peerPort = 5201
	}
	if durationSec <= 0 || durationSec > 15 {
		durationSec = 5
	}
	cmdHint := fmt.Sprintf("iperf3 -c %s -p %d -t %d -J", peerHost, peerPort, durationSec)
	bin, err := exec.LookPath("iperf3")
	if err != nil {
		return map[string]any{
			"iperf3_available": false,
			"peer":             peerHost,
			"port":             peerPort,
			"reason":           "宿主机未安装 iperf3，无法执行实测限速器拐点扫描（可先 apt install -y iperf3）。",
			"command_hint":     cmdHint,
		}, nil
	}
	sctx, cancel := context.WithTimeout(ctx, time.Duration(durationSec+10)*time.Second)
	defer cancel()
	raw, runErr := exec.CommandContext(sctx, bin, "-c", peerHost, "-p", strconv.Itoa(peerPort), "-t", strconv.Itoa(durationSec), "-J").Output()
	if runErr != nil {
		var exitErr *exec.ExitError
		detail := runErr.Error()
		if errors.As(runErr, &exitErr) && len(exitErr.Stderr) > 0 {
			detail = strings.TrimSpace(string(exitErr.Stderr))
		}
		return map[string]any{
			"iperf3_available": true,
			"ok":               false,
			"peer":             peerHost,
			"port":             peerPort,
			"error":            detail,
			"command_hint":     cmdHint,
		}, nil
	}
	var parsed struct {
		End struct {
			SumSent struct {
				BitsPerSecond float64 `json:"bits_per_second"`
				Retransmits   int     `json:"retransmits"`
			} `json:"sum_sent"`
			SumReceived struct {
				BitsPerSecond float64 `json:"bits_per_second"`
			} `json:"sum_received"`
		} `json:"end"`
	}
	_ = json.Unmarshal(raw, &parsed)
	sentMbps := parsed.End.SumSent.BitsPerSecond / 1e6
	recvMbps := parsed.End.SumReceived.BitsPerSecond / 1e6
	retrans := parsed.End.SumSent.Retransmits
	advice := "线路未见明显重传，可按实测带宽直接推导 tcpfit 参数。"
	if retrans > 50 {
		advice = fmt.Sprintf("检测到 %d 次重传，疑似母机或线路存在限速器/拥塞，建议将 tcpfit 带宽设为实测 85%% 或对指定 TCP 端口启用 TCP Brutal（125%% 超发）。", retrans)
	}
	return map[string]any{
		"iperf3_available": true,
		"ok":               true,
		"peer":             peerHost,
		"port":             peerPort,
		"sent_mbps":        sentMbps,
		"recv_mbps":        recvMbps,
		"retransmits":      retrans,
		"advice":           advice,
	}, nil
}
