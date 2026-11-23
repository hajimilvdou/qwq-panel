// SPDX-License-Identifier: AGPL-3.0-only

package sshd

import (
	"bufio"
	"encoding/hex"
	"net/netip"
	"os"
	"strconv"
	"strings"
)

// HostNetnsHasExternalSSHConn 在宿主真实网络命名空间（PrivateNetwork=no 的 qwq-capability）
// 检查目标端口是否存在至少一条来自非回环、非链路本地外部地址的 TCP_ESTABLISHED 连接。
func HostNetnsHasExternalSSHConn(port uint32) bool {
	if port == 0 || port > 65535 {
		return false
	}
	return scanHostProcNetTCP("/proc/net/tcp", port, false) ||
		scanHostProcNetTCP("/proc/net/tcp6", port, true)
}

func scanHostProcNetTCP(procPath string, targetPort uint32, ipv6 bool) bool {
	f, err := os.Open(procPath)
	if err != nil {
		return false
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	// 跳过表头行
	if !sc.Scan() {
		return false
	}
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 4 {
			continue
		}
		// st == "01" 代表 TCP_ESTABLISHED
		if fields[3] != "01" {
			continue
		}
		_, localPort, ok1 := parseProcHexAddrPort(fields[1], ipv6)
		remoteIP, _, ok2 := parseProcHexAddrPort(fields[2], ipv6)
		if !ok1 || !ok2 || localPort != targetPort {
			continue
		}
		remoteIP = remoteIP.Unmap()
		if !remoteIP.IsValid() || remoteIP.IsLoopback() || remoteIP.IsUnspecified() || remoteIP.IsLinkLocalUnicast() {
			continue
		}
		return true
	}
	return false
}

func parseProcHexAddrPort(token string, ipv6 bool) (netip.Addr, uint32, bool) {
	addrHex, portHex, ok := strings.Cut(token, ":")
	if !ok {
		return netip.Addr{}, 0, false
	}
	p64, err := strconv.ParseUint(portHex, 16, 16)
	if err != nil {
		return netip.Addr{}, 0, false
	}
	raw, err := hex.DecodeString(addrHex)
	if err != nil {
		return netip.Addr{}, 0, false
	}
	if !ipv6 {
		if len(raw) != 4 {
			return netip.Addr{}, 0, false
		}
		// Linux /proc/net/tcp 小端序存储 32-bit IPv4
		ip := netip.AddrFrom4([4]byte{raw[3], raw[2], raw[1], raw[0]})
		return ip, uint32(p64), true
	}
	if len(raw) != 16 {
		return netip.Addr{}, 0, false
	}
	// Linux /proc/net/tcp6 按 4 个 32-bit 小端字存储 IPv6
	var v6 [16]byte
	for word := 0; word < 4; word++ {
		base := word * 4
		v6[base+0] = raw[base+3]
		v6[base+1] = raw[base+2]
		v6[base+2] = raw[base+1]
		v6[base+3] = raw[base+0]
	}
	return netip.AddrFrom16(v6), uint32(p64), true
}
