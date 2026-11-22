// SPDX-License-Identifier: AGPL-3.0-only
//go:build linux

package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"unsafe"
)

const tcpBrutalParamsOpt = 23301 // apernet/HyNetworks tcp-brutal TCP_BRUTAL_PARAMS

// brutalEnvInfo 诚实探测当前 Linux 宿主机对 tcp-brutal（内核模块或 eBPF CO-RE）及 brutalctl 的支持情况。
type brutalEnvInfo struct {
	KernelVersion    string   `json:"kernel_version"`
	AvailableCC      []string `json:"available_cc"`
	CurrentCC        string   `json:"current_cc"`
	BrutalAvailable  bool     `json:"brutal_available"`
	EBPFPinned       bool     `json:"ebpf_pinned"`
	BrutalctlPath    string   `json:"brutalctl_path,omitempty"`
	InstallHint      string   `json:"install_hint"`
	DegradedGuidance string   `json:"degraded_guidance,omitempty"`
}

func detectBrutalEnv() brutalEnvInfo {
	info := brutalEnvInfo{
		InstallHint: "bash <(curl -fsSL https://tcp.hy2.sh/)",
	}
	if b, err := os.ReadFile("/proc/sys/kernel/osrelease"); err == nil {
		info.KernelVersion = strings.TrimSpace(string(b))
	}
	if b, err := os.ReadFile("/proc/sys/net/ipv4/tcp_congestion_control"); err == nil {
		info.CurrentCC = strings.TrimSpace(string(b))
	}
	if b, err := os.ReadFile("/proc/sys/net/ipv4/tcp_available_congestion_control"); err == nil {
		fields := strings.Fields(string(b))
		info.AvailableCC = fields
		for _, cc := range fields {
			if cc == "brutal" {
				info.BrutalAvailable = true
				break
			}
		}
	}
	if _, err := os.Stat("/sys/fs/bpf/brutal_cc"); err == nil {
		info.EBPFPinned = true
	}
	if p, err := exec.LookPath("brutalctl"); err == nil {
		info.BrutalctlPath = p
	}
	if !info.BrutalAvailable {
		info.DegradedGuidance = "宿主机内核尚未加载 tcp-brutal 模块或 eBPF struct_ops；透明端口接管层仍可正常运行并统计流量，但 setsockopt(TCP_CONGESTION=brutal) 将诚实记录回退至系统默认拥塞算法。"
	}
	return info
}

// applyTCPBrutalSockopt 在真实 Linux TCP 套接字上设置 TCP_CONGESTION="brutal" 与 TCP_BRUTAL_PARAMS(23301)。
func applyTCPBrutalSockopt(conn *net.TCPConn, rateBytesPerSec uint64, cwndGain uint32) error {
	if conn == nil {
		return fmt.Errorf("nil tcp connection")
	}
	rawConn, err := conn.SyscallConn()
	if err != nil {
		return err
	}
	var sockErr error
	ctrlErr := rawConn.Control(func(fd uintptr) {
		if err := syscall.SetsockoptString(int(fd), syscall.IPPROTO_TCP, syscall.TCP_CONGESTION, "brutal"); err != nil {
			sockErr = fmt.Errorf("setsockopt TCP_CONGESTION=brutal: %w", err)
			return
		}
		var packed [12]byte
		binary.LittleEndian.PutUint64(packed[0:8], rateBytesPerSec)
		binary.LittleEndian.PutUint32(packed[8:12], cwndGain)
		_, _, errno := syscall.Syscall6(
			syscall.SYS_SETSOCKOPT,
			fd,
			uintptr(syscall.IPPROTO_TCP),
			uintptr(tcpBrutalParamsOpt),
			uintptr(unsafe.Pointer(&packed[0])),
			uintptr(len(packed)),
			0,
		)
		if errno != 0 {
			sockErr = fmt.Errorf("setsockopt TCP_BRUTAL_PARAMS(%d): %w", tcpBrutalParamsOpt, errno)
		}
	})
	if ctrlErr != nil {
		return ctrlErr
	}
	return sockErr
}
