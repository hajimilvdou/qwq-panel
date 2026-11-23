// SPDX-License-Identifier: AGPL-3.0-only

package firewall

import (
	"context"
	"errors"
	"regexp"
	"strconv"
	"strings"

	"github.com/qwq-panel/qwq/internal/capability/local"
)

var socketPID = regexp.MustCompile(`\bpid=([0-9]+)\b`)

// RuntimeSSHPorts 保护当前监听，避免只按尚未重载的 sshd -T 配置摘掉旧端口。
// ss 的 PID 必须来自标准 SSH 单元；不按可由普通进程伪造的名称判断归属。
func (g SystemGuard) RuntimeSSHPorts(ctx context.Context) ([]uint32, error) {
	result, err := g.Executor.Execute(ctx, local.Systemctl, []string{"show", "ssh.service", "sshd.service", "ssh.socket", "sshd.socket", "--property=Id", "--property=MainPID", "--property=Listen", "--property=ActiveState"}, nil)
	if err != nil || result.ExitCode != 0 {
		clear(result.Output)
		return nil, errors.New("firewall: runtime SSH units are unavailable")
	}
	defer clear(result.Output)
	pids := make(map[string]bool)
	var ports []uint32
	for _, block := range strings.Split(strings.TrimSpace(string(result.Output)), "\n\n") {
		properties := make(map[string]string)
		for _, line := range strings.Split(block, "\n") {
			key, value, ok := strings.Cut(line, "=")
			if !ok {
				continue
			}
			if key == "Listen" && properties[key] != "" {
				value = properties[key] + " " + value
			}
			properties[key] = value
		}
		id := properties["Id"]
		if id != "ssh.service" && id != "sshd.service" && id != "ssh.socket" && id != "sshd.socket" {
			return nil, errors.New("firewall: runtime SSH unit identity is invalid")
		}
		state := properties["ActiveState"]
		switch state {
		case "active":
		case "inactive", "failed", "activating", "deactivating", "reloading":
			continue
		default:
			return nil, errors.New("firewall: runtime SSH active state is invalid")
		}
		if text := properties["MainPID"]; text != "" && text != "0" {
			if _, err := strconv.ParseUint(text, 10, 31); err != nil {
				return nil, errors.New("firewall: runtime SSH PID is invalid")
			}
			pids[text] = true
		}
		if strings.HasSuffix(id, ".socket") {
			fields := strings.Fields(properties["Listen"])
			if len(fields)%2 != 0 {
				return nil, errors.New("firewall: runtime SSH socket state is invalid")
			}
			for i := 0; i < len(fields); i += 2 {
				if fields[i+1] != "(Stream)" {
					return nil, errors.New("firewall: SSH socket transport is invalid")
				}
				if strings.HasPrefix(fields[i], "/") {
					continue
				}
				port, err := ListenerPort(fields[i])
				if err != nil {
					return nil, err
				}
				ports = mergePorts(ports, []uint32{port})
			}
		}
	}
	if len(pids) != 0 {
		result, err := g.Executor.Execute(ctx, local.SocketStats, []string{"-H", "-ltnp"}, nil)
		if err != nil || result.ExitCode != 0 {
			clear(result.Output)
			return nil, errors.New("firewall: listening SSH sockets are unavailable")
		}
		defer clear(result.Output)
		for _, line := range strings.Split(string(result.Output), "\n") {
			matches := socketPID.FindAllStringSubmatch(line, -1)
			owned := false
			for _, match := range matches {
				if pids[match[1]] {
					owned = true
				}
			}
			if !owned {
				continue
			}
			fields := strings.Fields(line)
			if len(fields) < 6 || fields[0] != "LISTEN" {
				return nil, errors.New("firewall: SSH socket row is invalid")
			}
			port, err := ListenerPort(fields[3])
			if err != nil {
				return nil, err
			}
			ports = mergePorts(ports, []uint32{port})
		}
	}
	if len(ports) == 0 {
		return nil, errors.New("firewall: no standard SSH listener could be confirmed")
	}
	return preservedPorts(ports, ports)
}

// ListenerPort 解析 ss/systemd 的监听端点，不推测默认端口。
// 改用 LastIndexByte(':') 截取末尾端口号，兼容 127.0.0.53%lo:53 与 [fe80::1]%eth0:22。
func ListenerPort(endpoint string) (uint32, error) {
	if endpoint == "" || strings.HasSuffix(endpoint, "]") {
		return 0, errors.New("firewall: listener endpoint is invalid")
	}
	text := endpoint
	if idx := strings.LastIndexByte(endpoint, ':'); idx >= 0 {
		host := endpoint[:idx]
		if host == "" {
			return 0, errors.New("firewall: listener endpoint is invalid")
		}
		if strings.Contains(host, ":") && !strings.HasPrefix(host, "[") {
			return 0, errors.New("firewall: listener endpoint is invalid")
		}
		if strings.HasPrefix(host, "[") && !strings.Contains(host, "]") {
			return 0, errors.New("firewall: listener endpoint is invalid")
		}
		text = endpoint[idx+1:]
	}
	port, err := strconv.ParseUint(text, 10, 16)
	if err != nil || port == 0 {
		return 0, errors.New("firewall: listener port is invalid")
	}
	return uint32(port), nil
}
