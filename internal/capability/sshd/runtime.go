// SPDX-License-Identifier: AGPL-3.0-only

package sshd

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/qwq-panel/qwq/internal/capability/firewall"
	"github.com/qwq-panel/qwq/internal/capability/local"
)

type SystemRuntime struct {
	Executor local.Executor
	Guard    firewall.SystemGuard
	Firewall *firewall.Service
}

func (r SystemRuntime) Ports(ctx context.Context) ([]uint32, error) {
	return r.Guard.RuntimeSSHPorts(ctx)
}
func (r SystemRuntime) ManagementPorts(ctx context.Context) ([]uint32, error) {
	return r.Guard.ManagementPorts(ctx)
}

// RequireSSHPort 复用真实防火墙服务；调用方已持有共用的 capability.lock。
func (r SystemRuntime) RequireSSHPort(ctx context.Context, port uint32) error {
	if r.Firewall == nil {
		return errors.New("sshd: firewall admission is not configured")
	}
	return r.Firewall.RequireSSHPort(ctx, port)
}

func (r SystemRuntime) Conflicts(ctx context.Context, port uint32) (bool, error) {
	result, err := r.Executor.Execute(ctx, local.SocketStats, []string{"-H", "-ltn"}, nil)
	if err != nil || result.ExitCode != 0 {
		return false, errors.New("sshd: TCP listener state unavailable")
	}
	defer clear(result.Output)
	for _, line := range strings.Split(string(result.Output), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if len(fields) < 5 || fields[0] != "LISTEN" {
			return false, errors.New("sshd: invalid listener row")
		}
		bound, err := firewall.ListenerPort(fields[3])
		if err != nil {
			return false, err
		}
		if bound == port {
			return true, nil
		}
	}
	return false, nil
}

// Reload 优先标准 socket 激活；传统服务仅使用 reload，保留已有会话子进程。
func (r SystemRuntime) Reload(ctx context.Context) error {
	result, err := r.Executor.Execute(ctx, local.Systemctl, []string{"show", "ssh.socket", "sshd.socket", "ssh.service", "sshd.service", "--property=Id", "--property=ActiveState", "--property=LoadState"}, nil)
	if err != nil || result.ExitCode != 0 {
		return errors.New("sshd: SSH unit state unavailable")
	}
	defer clear(result.Output)
	var socket, service string
	for _, block := range strings.Split(strings.TrimSpace(string(result.Output)), "\n\n") {
		properties := make(map[string]string)
		for _, line := range strings.Split(block, "\n") {
			key, value, ok := strings.Cut(line, "=")
			if ok {
				properties[key] = value
			}
		}
		unit := properties["Id"]
		if unit != "ssh.socket" && unit != "sshd.socket" && unit != "ssh.service" && unit != "sshd.service" {
			return errors.New("sshd: unsupported SSH unit")
		}
		if properties["LoadState"] != "loaded" || properties["ActiveState"] != "active" {
			continue
		}
		if strings.HasSuffix(unit, ".socket") {
			if socket != "" && socket != unit {
				return errors.New("sshd: multiple SSH socket managers")
			}
			socket = unit
		} else {
			if service != "" && service != unit {
				return errors.New("sshd: multiple SSH service managers")
			}
			service = unit
		}
	}
	commands := [][]string{{"reload", service}}
	if socket != "" {
		commands = [][]string{{"daemon-reload"}, {"restart", socket}}
	} else if service == "" {
		return errors.New("sshd: active standard SSH manager missing")
	}
	for _, args := range commands {
		result, err := r.Executor.Execute(ctx, local.Systemctl, args, nil)
		clear(result.Output)
		if err != nil || result.ExitCode != 0 {
			return errors.New("sshd: SSH manager reload failed")
		}
	}
	return nil
}

func (r SystemRuntime) Verify(ctx context.Context, port uint32) (string, error) {
	if port == 0 || port > 65535 {
		return "", errPortVerification
	}
	for _, address := range []string{"127.0.0.1", "::1"} {
		banner, err := loopbackBanner(ctx, net.JoinHostPort(address, strconv.FormatUint(uint64(port), 10)))
		if err == nil {
			return banner, nil
		}
		if ctx.Err() != nil {
			return "", ctx.Err()
		}
	}
	return "", errPortVerification
}

// loopbackBanner 有界读取 SSH 横幅，不执行认证，不访问任何外部地址。
func loopbackBanner(ctx context.Context, address string) (string, error) {
	dialer := net.Dialer{Timeout: 750 * time.Millisecond}
	connection, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return "", err
	}
	defer connection.Close()
	deadline := time.Now().Add(time.Second)
	if outer, ok := ctx.Deadline(); ok && outer.Before(deadline) {
		deadline = outer
	}
	if err := connection.SetDeadline(deadline); err != nil {
		return "", err
	}
	reader := bufio.NewReader(io.LimitReader(connection, 4096))
	for range 10 {
		line, err := reader.ReadString('\n')
		if err != nil {
			return "", err
		}
		banner := strings.TrimSuffix(strings.TrimSuffix(line, "\n"), "\r")
		if !strings.HasPrefix(banner, "SSH-") {
			continue
		}
		if !strings.HasPrefix(banner, "SSH-2.0-") || len(banner) < 9 || len(banner) > 253 {
			return "", errPortVerification
		}
		for _, character := range banner {
			if character < 32 || character > 126 {
				return "", errPortVerification
			}
		}
		return banner, nil
	}
	return "", errPortVerification
}
