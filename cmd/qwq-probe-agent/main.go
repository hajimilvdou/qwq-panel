// SPDX-License-Identifier: AGPL-3.0-only

// qwq-probe-agent：部署在各个被监控小鸡 / 软路由 / NAS 上的极简安全单向探针 Agent。
//
// 安全设计铁律（吸收 DiTing Lite / Simple Server Status / CF-Server-Monitor 精髓）：
// 1. 【零入站监听】：本程序不调用 net.Listen，不占用任何 TCP/UDP 端口；
// 2. 【零远程执行】：本程序不导入 os/exec，不包含任何 WebSSH、脚本拉取或远程指令执行逻辑；
// 3. 【单向出站上报 + Pull-on-Push 只读配置同步】：仅向指定 HTTPS 端点 POST 结构化系统指标，
//    并从 HTTP 200 JSON 回包读取管理员调整的采样间隔（1..60s）与三网 TCP 延迟测试目标。

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type reportFrame struct {
	NodeID        string           `json:"node_id"`
	TimestampUnix int64            `json:"timestamp_unix"`
	TimestampNano int64            `json:"timestamp_nano"`
	SessionEpoch  int64            `json:"session_epoch"`
	Sequence      uint64           `json:"seq"`
	BootEpoch     uint64           `json:"boot_epoch"`
	OSName        string           `json:"os_name"`
	KernelVersion string           `json:"kernel"`
	Arch          string           `json:"arch"`
	VirtType      string           `json:"virt"`
	CPUModel      string           `json:"cpu_model"`
	CPUCores      int              `json:"cpu_cores"`
	MemTotal      uint64           `json:"mem_total"`
	MemUsed       uint64           `json:"mem_used"`
	SwapTotal     uint64           `json:"swap_total"`
	SwapUsed      uint64           `json:"swap_used"`
	DiskTotal     uint64           `json:"disk_total"`
	DiskUsed      uint64           `json:"disk_used"`
	RawRxBytes    uint64           `json:"raw_rx_bytes"`
	RawTxBytes    uint64           `json:"raw_tx_bytes"`
	NetRxBps      uint64           `json:"net_rx_bps"`
	NetTxBps      uint64           `json:"net_tx_bps"`
	CPUPercent    float64          `json:"cpu_pct"`
	Load1         float64          `json:"load1"`
	Load5         float64          `json:"load5"`
	Load15        float64          `json:"load15"`
	TCPConns      uint32           `json:"tcp_conns"`
	UDPConns      uint32           `json:"udp_conns"`
	UptimeSeconds uint64           `json:"uptime_seconds"`
	HasIPv4       bool             `json:"has_ipv4"`
	HasIPv6       bool             `json:"has_ipv6"`
	CarrierPingMs map[string]int32 `json:"carrier_ping_ms"`
}

type pullReply struct {
	Accepted          bool              `json:"accepted"`
	ReportIntervalSec int               `json:"report_interval_sec"`
	CarrierTargets    map[string]string `json:"carrier_targets"`
}

type cpuSample struct {
	total uint64
	idle  uint64
}

// BuildPinnedProbeTLSConfig 构造探针 TLS 客户端配置：
//   - 未传 pinnedCertSHA256 且 !allowInsecure：使用操作系统标准根证书库；
//   - 传入 pinnedCertSHA256（64 位 hex，自动兼容冒号与 sha256: 前缀）：通过 VerifyConnection 在握手完成后
//     强制校验有效期与证书链：要么叶证书 DER SHA-256 与指纹常量时间匹配（已由 TLS 握手证明私钥持有），
//     要么链中匹配指纹的 CA 证书能够用 x509.Verify 验证叶证书与目标主机名，彻底阻断拼接虚假附带证书的 MITM。
func BuildPinnedProbeTLSConfig(pinnedCertSHA256 string, allowInsecure bool) (*tls.Config, error) {
	normPin := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(pinnedCertSHA256), ":", ""))
	normPin = strings.TrimPrefix(normPin, "sha256")
	if normPin == "" && !allowInsecure {
		return &tls.Config{MinVersion: tls.VersionTLS12}, nil
	}
	var wantPinBytes []byte
	if normPin != "" {
		if len(normPin) != 64 {
			return nil, fmt.Errorf("invalid --ca-sha256 fingerprint length (want 64 hex chars)")
		}
		dec, err := hex.DecodeString(normPin)
		if err != nil {
			return nil, fmt.Errorf("invalid --ca-sha256 hex fingerprint: %w", err)
		}
		wantPinBytes = dec
	}
	return &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: true, // 仅通过下方 VerifyConnection 的加密指纹校验或显式 allowInsecure 放行
		VerifyConnection: func(cs tls.ConnectionState) error {
			if allowInsecure && len(wantPinBytes) == 0 {
				return nil
			}
			if len(cs.PeerCertificates) == 0 {
				return errors.New("probe tls pin mismatch: server presented no certificates")
			}
			now := time.Now()
			leaf := cs.PeerCertificates[0]
			if now.Before(leaf.NotBefore) || now.After(leaf.NotAfter) {
				return errors.New("probe tls pin rejected: server leaf certificate is expired or not yet valid")
			}
			leafSum := sha256.Sum256(leaf.Raw)
			if subtle.ConstantTimeCompare(leafSum[:], wantPinBytes) == 1 {
				return nil
			}
			for _, candidate := range cs.PeerCertificates[1:] {
				cSum := sha256.Sum256(candidate.Raw)
				if subtle.ConstantTimeCompare(cSum[:], wantPinBytes) != 1 {
					continue
				}
				roots := x509.NewCertPool()
				roots.AddCert(candidate)
				inter := x509.NewCertPool()
				for _, ic := range cs.PeerCertificates[1:] {
					inter.AddCert(ic)
				}
				if _, err := leaf.Verify(x509.VerifyOptions{
					DNSName:       cs.ServerName,
					Roots:         roots,
					Intermediates: inter,
					CurrentTime:   now,
					KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
				}); err == nil {
					return nil
				}
			}
			return errors.New("probe tls pin mismatch: server certificate SHA-256 does not match --ca-sha256")
		},
	}, nil
}

func main() {
	var (
		endpoint      = flag.String("endpoint", os.Getenv("QWQ_PROBE_ENDPOINT"), "主控上报 HTTPS 地址，如 https://status.example.com/api/probe/v1/report")
		nodeID        = flag.String("node", os.Getenv("QWQ_PROBE_NODE"), "主控分配的节点 ID")
		token         = flag.String("token", os.Getenv("QWQ_PROBE_TOKEN"), "主控签发的单向节点令牌 prb_agt_*（优先从环境变量或 0600 凭据文件读取）")
		caSHA256      = flag.String("ca-sha256", os.Getenv("QWQ_PROBE_CA_SHA256"), "可选：固定主控服务端证书 SHA-256 指纹（用于自签证书面板免 MITM 接入）")
		allowInsecure = flag.Bool("insecure", os.Getenv("QWQ_PROBE_INSECURE") == "1", "可选：跳过 TLS 证书校验（仅限内网排障，推荐改用 --ca-sha256）")
		checkOnce     = flag.Bool("check", false, "执行一次首包上报自检并输出诊断结果后立即退出")
	)
	flag.Parse()

	if *endpoint == "" || *nodeID == "" || !strings.HasPrefix(*token, "prb_agt_") {
		fmt.Fprintln(os.Stderr, "[qwq-probe-agent] 缺少必需参数 --endpoint / --node / --token (prb_agt_*)")
		os.Exit(2)
	}
	tlsCfg, err := BuildPinnedProbeTLSConfig(*caSHA256, *allowInsecure)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[qwq-probe-agent] TLS 参数无效: %v\n", err)
		os.Exit(2)
	}
	debug.SetMemoryLimit(16 << 20) // 16 MiB 软内存上限，适配 128M/256M 超小 NAT 机器

	client := &http.Client{
		Timeout: 8 * time.Second,
		Transport: &http.Transport{
			MaxIdleConns:       2,
			IdleConnTimeout:    60 * time.Second,
			TLSClientConfig:    tlsCfg,
			DisableCompression: false,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	bootEpoch := readBootEpoch()
	sessionEpoch := time.Now().UnixNano()
	var (
		seq          uint64
		prevCPU      cpuSample
		prevRx       uint64
		prevTx       uint64
		prevMono     = time.Now()
		interval     = 2 * time.Second
		pingTargets  = map[string]string{}
		pingTickStep uint64
		lastErrLogAt time.Time
		hadError     bool
	)
	prevCPU = readProcStat()
	prevRx, prevTx = readProcNetDev()

	logReportError := func(msg string) {
		nowLog := time.Now()
		if !hadError || nowLog.Sub(lastErrLogAt) >= 60*time.Second {
			fmt.Fprintf(os.Stderr, "[qwq-probe-agent] 上报失败: %s\n", msg)
			lastErrLogAt = nowLog
		}
		hadError = true
	}

	for {
		if !*checkOnce {
			select {
			case <-ctx.Done():
				return
			case <-time.After(interval):
			}
		}

		now := time.Now()
		dt := now.Sub(prevMono).Seconds()
		prevMono = now

		curCPU := readProcStat()
		var cpuPct float64
		if curCPU.total > prevCPU.total {
			dTotal := curCPU.total - prevCPU.total
			dIdle := curCPU.idle - prevCPU.idle
			if dTotal >= dIdle && dTotal > 0 {
				cpuPct = float64(dTotal-dIdle) * 100.0 / float64(dTotal)
			}
		}
		prevCPU = curCPU

		rawRx, rawTx := readProcNetDev()
		var rxBps, txBps uint64
		if dt > 0 && rawRx >= prevRx {
			rxBps = uint64(float64((rawRx-prevRx)*8) / dt)
		}
		if dt > 0 && rawTx >= prevTx {
			txBps = uint64(float64((rawTx-prevTx)*8) / dt)
		}
		prevRx, prevTx = rawRx, rawTx

		memTotal, memAvail, swapTotal, swapFree := readProcMeminfo()
		diskTotal, diskUsed := readRootDiskUsage()
		tcpConns, udpConns := readProcNetConns()
		l1, l5, l15 := readProcLoadavg()
		uptime := readProcUptime()

		pings := map[string]int32{}
		if pingTickStep%10 == 0 && len(pingTargets) > 0 {
			pings = measureCarrierTCP(ctx, pingTargets)
		}
		pingTickStep++
		seq++

		cpuModel, cpuCores := readCPUInfo()
		hasIPv4, hasIPv6 := detectDualStack()
		frame := reportFrame{
			NodeID:        *nodeID,
			TimestampUnix: now.Unix(),
			TimestampNano: now.UnixNano(),
			SessionEpoch:  sessionEpoch,
			Sequence:      seq,
			BootEpoch:     bootEpoch,
			OSName:        readOSRelease(),
			KernelVersion: readKernelRelease(),
			Arch:          runtime.GOOS + "/" + runtime.GOARCH,
			CPUModel:      cpuModel,
			CPUCores:      cpuCores,
			MemTotal:      memTotal,
			MemUsed:       memTotal - min(memTotal, memAvail),
			SwapTotal:     swapTotal,
			SwapUsed:      swapTotal - min(swapTotal, swapFree),
			DiskTotal:     diskTotal,
			DiskUsed:      diskUsed,
			RawRxBytes:    rawRx,
			RawTxBytes:    rawTx,
			NetRxBps:      rxBps,
			NetTxBps:      txBps,
			CPUPercent:    cpuPct,
			Load1:         l1,
			Load5:         l5,
			Load15:        l15,
			TCPConns:      tcpConns,
			UDPConns:      udpConns,
			UptimeSeconds: uptime,
			HasIPv4:       hasIPv4,
			HasIPv6:       hasIPv6,
			CarrierPingMs: pings,
		}

		body, _ := json.Marshal(frame)
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, *endpoint, bytes.NewReader(body))
		if err != nil {
			logReportError(err.Error())
			if *checkOnce {
				os.Exit(1)
			}
			continue
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+*token)

		resp, err := client.Do(req)
		if err != nil {
			logReportError(err.Error())
			if *checkOnce {
				os.Exit(1)
			}
			continue
		}
		rawReply, _ := io.ReadAll(io.LimitReader(resp.Body, 16<<10))
		_ = resp.Body.Close()

		var reply pullReply
		_ = json.Unmarshal(rawReply, &reply)

		if resp.StatusCode < 200 || resp.StatusCode >= 300 || !reply.Accepted {
			logReportError(fmt.Sprintf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(rawReply))))
			if *checkOnce {
				os.Exit(1)
			}
			continue
		}

		if hadError {
			fmt.Fprintln(os.Stderr, "[qwq-probe-agent] 遥测上报已恢复正常")
			hadError = false
		}
		if *checkOnce {
			fmt.Fprintf(os.Stderr, "[qwq-probe-agent] 首包上报验收通过 (node=%s, interval=%ds)\n", *nodeID, max(1, reply.ReportIntervalSec))
			return
		}
		if reply.ReportIntervalSec >= 1 && reply.ReportIntervalSec <= 60 {
			interval = time.Duration(reply.ReportIntervalSec) * time.Second
		}
		if len(reply.CarrierTargets) <= 8 {
			pingTargets = reply.CarrierTargets
		}
	}
}

var blockedAgentPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("0000::/8"),
	netip.MustParsePrefix("fd00:ec2::254/128"),
	netip.MustParsePrefix("64:ff9b::/96"),
	netip.MustParsePrefix("64:ff9b:1::/48"),
	netip.MustParsePrefix("100::/64"),
	netip.MustParsePrefix("2001::/32"),
	netip.MustParsePrefix("2002::/16"),
}

func isBlockedTargetAddr(ip netip.Addr) bool {
	u := ip.Unmap()
	if !u.IsValid() || u.IsLoopback() || u.IsPrivate() || u.IsLinkLocalUnicast() || u.IsLinkLocalMulticast() || u.IsMulticast() || u.IsUnspecified() {
		return true
	}
	for _, p := range blockedAgentPrefixes {
		if p.Contains(u) {
			return true
		}
	}
	return false
}

// measureCarrierTCP 在受控节点侧同样核验目标为纯公网 IP 后再拨号，防止主控被攻陷后借 CarrierTargets 探测受控机器内网或云元数据。
func measureCarrierTCP(ctx context.Context, targets map[string]string) map[string]int32 {
	out := make(map[string]int32, len(targets))
	for tag, addr := range targets {
		host, portStr, err := net.SplitHostPort(addr)
		if err != nil || host == "" || portStr == "" || strings.EqualFold(host, "localhost") {
			continue
		}
		portNum, err := strconv.Atoi(portStr)
		if err != nil || portNum <= 0 || portNum > 65535 {
			continue
		}
		host = strings.Trim(host, "[]")
		var dialAddrs []netip.Addr
		if ip, err := netip.ParseAddr(host); err == nil {
			if isBlockedTargetAddr(ip) {
				continue
			}
			dialAddrs = []netip.Addr{ip.Unmap()}
		} else {
			rctx, cancel := context.WithTimeout(ctx, 1200*time.Millisecond)
			ips, err := net.DefaultResolver.LookupNetIP(rctx, "ip", host)
			cancel()
			if err != nil || len(ips) == 0 {
				continue
			}
			blocked := false
			for _, cand := range ips {
				if isBlockedTargetAddr(cand) {
					blocked = true
					break
				}
				dialAddrs = append(dialAddrs, cand.Unmap())
			}
			if blocked || len(dialAddrs) == 0 {
				continue
			}
		}

		d := net.Dialer{Timeout: 1500 * time.Millisecond}
		for _, dialAddr := range dialAddrs {
			start := time.Now()
			dctx, dcancel := context.WithTimeout(ctx, 1500*time.Millisecond)
			conn, derr := d.DialContext(dctx, "tcp", netip.AddrPortFrom(dialAddr, uint16(portNum)).String())
			dcancel()
			if derr == nil {
				_ = conn.Close()
				out[tag] = int32(time.Since(start).Milliseconds())
				break
			}
			if ctx.Err() != nil {
				break
			}
		}
	}
	return out
}

func readBootEpoch() uint64 {
	raw, err := os.ReadFile("/proc/stat")
	if err != nil {
		return uint64(time.Now().Unix())
	}
	for _, line := range strings.Split(string(raw), "\n") {
		if strings.HasPrefix(line, "btime ") {
			v, _ := strconv.ParseUint(strings.TrimSpace(strings.TrimPrefix(line, "btime ")), 10, 64)
			if v > 0 {
				return v
			}
		}
	}
	return 1
}

func readProcStat() cpuSample {
	raw, err := os.ReadFile("/proc/stat")
	if err != nil {
		return cpuSample{}
	}
	first, _, _ := strings.Cut(string(raw), "\n")
	fields := strings.Fields(first)
	if len(fields) < 5 || fields[0] != "cpu" {
		return cpuSample{}
	}
	var vals [8]uint64
	for i := 0; i < 8 && i+1 < len(fields); i++ {
		vals[i], _ = strconv.ParseUint(fields[i+1], 10, 64)
	}
	var tot uint64
	for _, v := range vals {
		tot += v
	}
	return cpuSample{total: tot, idle: vals[3] + vals[4]}
}

func readProcMeminfo() (total, avail, swapTotal, swapFree uint64) {
	raw, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0, 0, 0, 0
	}
	for _, line := range strings.Split(string(raw), "\n") {
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		kb, _ := strconv.ParseUint(f[1], 10, 64)
		val := kb * 1024
		switch f[0] {
		case "MemTotal:":
			total = val
		case "MemAvailable:":
			avail = val
		case "SwapTotal:":
			swapTotal = val
		case "SwapFree:":
			swapFree = val
		}
	}
	return
}

func readProcNetDev() (rx, tx uint64) {
	raw, err := os.ReadFile("/proc/net/dev")
	if err != nil {
		return 0, 0
	}
	for _, line := range strings.Split(string(raw), "\n") {
		name, rest, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		iface := strings.TrimSpace(name)
		if iface == "lo" || strings.HasPrefix(iface, "veth") || strings.HasPrefix(iface, "docker") || strings.HasPrefix(iface, "tun") {
			continue
		}
		f := strings.Fields(rest)
		if len(f) >= 9 {
			r, _ := strconv.ParseUint(f[0], 10, 64)
			t, _ := strconv.ParseUint(f[8], 10, 64)
			rx += r
			tx += t
		}
	}
	return
}

func readProcLoadavg() (l1, l5, l15 float64) {
	raw, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return 0, 0, 0
	}
	f := strings.Fields(string(raw))
	if len(f) >= 3 {
		l1, _ = strconv.ParseFloat(f[0], 64)
		l5, _ = strconv.ParseFloat(f[1], 64)
		l15, _ = strconv.ParseFloat(f[2], 64)
	}
	return
}

func readProcUptime() uint64 {
	raw, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return 0
	}
	f := strings.Fields(string(raw))
	if len(f) >= 1 {
		sec, _ := strconv.ParseFloat(f[0], 64)
		return uint64(sec)
	}
	return 0
}

func readOSRelease() string {
	raw, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return runtime.GOOS
	}
	for _, line := range strings.Split(string(raw), "\n") {
		if v, ok := strings.CutPrefix(line, "PRETTY_NAME="); ok {
			return strings.Trim(v, `"`)
		}
	}
	return runtime.GOOS
}

func readKernelRelease() string {
	raw, err := os.ReadFile("/proc/sys/kernel/osrelease")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(raw))
}

func readCPUInfo() (model string, cores int) {
	raw, err := os.ReadFile("/proc/cpuinfo")
	if err == nil {
		for _, line := range strings.Split(string(raw), "\n") {
			key, val, ok := strings.Cut(line, ":")
			if !ok {
				continue
			}
			k := strings.TrimSpace(key)
			v := strings.TrimSpace(val)
			switch k {
			case "processor":
				cores++
			case "model name", "Hardware", "Processor":
				if model == "" && v != "" {
					model = v
				}
			}
		}
	}
	if cores <= 0 {
		cores = runtime.NumCPU()
	}
	return model, cores
}

// detectDualStack 基于本机非环回网络地址与 /proc/net/if_inet6 真实探测 IPv4/IPv6 双栈能力。
func detectDualStack() (hasIPv4, hasIPv6 bool) {
	if addrs, err := net.InterfaceAddrs(); err == nil {
		for _, a := range addrs {
			var ip net.IP
			switch v := a.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip == nil || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
				continue
			}
			if ip.To4() != nil {
				hasIPv4 = true
			} else {
				hasIPv6 = true
			}
		}
	}
	if !hasIPv6 {
		if raw, err := os.ReadFile("/proc/net/if_inet6"); err == nil {
			for _, line := range strings.Split(string(raw), "\n") {
				fields := strings.Fields(line)
				if len(fields) < 6 {
					continue
				}
				// 跳过 loopback (lo) 与 link-local (fe80...)
				if fields[5] == "lo" || strings.HasPrefix(strings.ToLower(fields[0]), "fe80") || fields[0] == "00000000000000000000000000000001" {
					continue
				}
				hasIPv6 = true
				break
			}
		}
	}
	return hasIPv4, hasIPv6
}
