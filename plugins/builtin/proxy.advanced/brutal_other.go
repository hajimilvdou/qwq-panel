// SPDX-License-Identifier: AGPL-3.0-only
//go:build !linux

package main

import (
	"errors"
	"net"
)

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
	return brutalEnvInfo{
		InstallHint:      "bash <(curl -fsSL https://tcp.hy2.sh/)",
		DegradedGuidance: "TCP Brutal 仅支持 Linux 内核宿主机。",
	}
}

func applyTCPBrutalSockopt(_ *net.TCPConn, _ uint64, _ uint32) error {
	return errors.New("tcp-brutal setsockopt is only supported on Linux")
}
