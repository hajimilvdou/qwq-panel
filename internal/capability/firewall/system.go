// SPDX-License-Identifier: AGPL-3.0-only

package firewall

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/qwq-panel/qwq/internal/capability/local"
	"github.com/qwq-panel/qwq/internal/platform/config"
	"github.com/qwq-panel/qwq/internal/sandbox"
)

// SystemGuard 从可信配置和受控工具读取当前节点事实，不接受插件提供的端口或 URL。
type SystemGuard struct {
	Executor local.Executor
	Config   local.State
	// RootPath/Trust 只由宿主装配或测试设置；零值读取真实 root 文件系统。
	RootPath string
	Trust    sandbox.TrustPolicy
}

// ManagementPorts 包含监听端口与管理入口端口，可同时保护 SSH 隧道及反向代理入口。
func ManagementPorts(http config.HTTP) ([]uint32, error) {
	_, text, err := net.SplitHostPort(http.Listen)
	if err != nil {
		return nil, errors.New("firewall: management listener is invalid")
	}
	port, err := strconv.ParseUint(text, 10, 16)
	if err != nil || port == 0 {
		return nil, errors.New("firewall: management port is invalid")
	}
	ports := []uint32{uint32(port)}
	for _, origin := range http.PublicOrigins {
		u, err := url.Parse(origin)
		if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
			return nil, errors.New("firewall: management origin is invalid")
		}
		value := u.Port()
		if value == "" {
			if u.Scheme == "https" {
				value = "443"
			} else {
				value = "80"
			}
		}
		port, err := strconv.ParseUint(value, 10, 16)
		if err != nil || port == 0 {
			return nil, errors.New("firewall: management origin port is invalid")
		}
		ports = mergePorts(ports, []uint32{uint32(port)})
	}
	return preservedPorts(ports, ports)
}

func (g SystemGuard) PreservedPorts(ctx context.Context) ([]uint32, error) {
	ports, err := g.ManagementPorts(ctx)
	if err != nil {
		return nil, err
	}
	result, err := g.Executor.Execute(ctx, local.Sshd, []string{"-T"}, nil)
	if err != nil || result.ExitCode != 0 {
		clear(result.Output)
		return nil, errors.New("firewall: effective SSH configuration is unavailable")
	}
	defer clear(result.Output)
	var sshPorts []uint32
	for _, line := range bytes.Split(result.Output, []byte{'\n'}) {
		fields := strings.Fields(string(line))
		if len(fields) == 0 || fields[0] != "port" {
			continue
		}
		if len(fields) != 2 {
			return nil, errors.New("firewall: effective SSH ports are invalid")
		}
		port, err := strconv.ParseUint(fields[1], 10, 16)
		if err != nil || port == 0 {
			return nil, errors.New("firewall: effective SSH ports are invalid")
		}
		sshPorts = mergePorts(sshPorts, []uint32{uint32(port)})
	}
	if len(sshPorts) == 0 {
		return nil, errors.New("firewall: effective SSH ports are missing")
	}
	ports = mergePorts(ports, sshPorts)
	live, err := g.RuntimeSSHPorts(ctx)
	if err != nil {
		return nil, err
	}
	return preservedPorts(mergePorts(ports, live), mergePorts(ports, live))
}

// ManagementPorts 复用可信面板配置读取，供 SSH 等能力检查管理入口冲突。
func (g SystemGuard) ManagementPorts(ctx context.Context) ([]uint32, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if g.Executor == nil || g.Config == nil {
		return nil, errors.New("firewall: guard is not configured")
	}
	raw, exists, err := g.Config.Read()
	if err != nil || !exists {
		return nil, errors.New("firewall: trusted host configuration is unavailable")
	}
	var cfg config.Config
	if decodeObject(raw, &cfg) != nil {
		return nil, errors.New("firewall: trusted host configuration is invalid")
	}
	ports, err := ManagementPorts(cfg.HTTP)
	if err != nil {
		return nil, err
	}
	if dynPort := g.readDynamicPanelPort(); dynPort > 0 {
		ports = mergePorts(ports, []uint32{dynPort})
	}
	return ports, nil
}

const dynamicPanelPortFile = "var/lib/qwq-capability/panel-port.json"

func (g SystemGuard) readDynamicPanelPort() uint32 {
	rootPath := g.RootPath
	if rootPath == "" {
		rootPath = "/"
	}
	full := filepath.Join(rootPath, dynamicPanelPortFile)
	dir, name := filepath.Dir(full), filepath.Base(full)
	raw, exists, err := (local.FileState{Directory: dir, Name: name, Trust: g.Trust}).Read()
	if err != nil || !exists || len(raw) == 0 {
		return 0
	}
	defer clear(raw)
	var doc struct {
		Port uint32 `json:"port"`
	}
	if decodeObject(raw, &doc) != nil || doc.Port == 0 || doc.Port > 65535 {
		return 0
	}
	return doc.Port
}

func (g SystemGuard) Managers(ctx context.Context) ([]Manager, error) {
	if g.Executor == nil {
		return nil, errors.New("firewall: manager detector is not configured")
	}
	rootPath := g.RootPath
	if rootPath == "" {
		rootPath = "/"
	}
	root, err := g.Trust.Open(rootPath)
	if err != nil {
		return nil, errors.New("firewall: manager filesystem is not trusted")
	}
	defer root.Close()
	kinds := []string{"ufw", "firewalld", "fail2ban", "bt", "1panel"}
	args := []string{"is-active", "ufw.service", "firewalld.service", "fail2ban.service", "bt.service", "1panel.service"}
	result, err := g.Executor.Execute(ctx, local.Systemctl, args, nil)
	if err != nil || result.ExitCode < 0 || result.ExitCode > 4 {
		clear(result.Output)
		return nil, errors.New("firewall: manager unit states are unavailable")
	}
	defer clear(result.Output)
	states := strings.Fields(string(result.Output))
	if len(states) != len(kinds) {
		return nil, errors.New("firewall: manager unit states are invalid")
	}
	managers := make([]Manager, len(kinds))
	ufwDisabled := false
	ufwNative := false
	for i, state := range states {
		switch state {
		case "active", "inactive", "unknown", "failed", "activating", "deactivating", "reloading":
		default:
			return nil, errors.New("firewall: manager unit state is unsupported")
		}
		managers[i] = Manager{Kind: kinds[i], Active: state == "active", Detail: "systemd 状态：" + state, Uncertain: state != "active" && state != "inactive" && state != "unknown"}
	}
	for i, path := range []string{"etc/ufw/ufw.conf", "etc/firewalld", "etc/fail2ban", "www/server/panel", "opt/1panel"} {
		_, err := root.Lstat(path)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, errors.New("firewall: manager presence could not be checked")
		}
		if err == nil && !managers[i].Active {
			managers[i].Uncertain = true
			managers[i].Detail = "检测到已有配置或面板目录，需明确接管状态"
			if i == 0 && states[i] == "inactive" {
				raw, exists, readErr := (local.FileState{Directory: filepath.Join(rootPath, "etc", "ufw"), Name: "ufw.conf", Trust: g.Trust}).Read()
				if readErr != nil {
					return nil, errors.New("firewall: UFW configuration could not be verified")
				}
				ufwDisabled = exists && ufwExplicitlyDisabled(raw)
				clear(raw)
			}
		}
	}
	result, err = g.Executor.Execute(ctx, local.Nft, []string{"-j", "list", "chains"}, nil)
	if err != nil || result.ExitCode != 0 {
		clear(result.Output)
		return nil, errors.New("firewall: existing nft managers could not be checked")
	}
	defer clear(result.Output)
	var document struct {
		Nftables []json.RawMessage `json:"nftables"`
	}
	if decodeObject(result.Output, &document) != nil {
		return nil, errors.New("firewall: existing nft manager state is invalid")
	}
	for _, raw := range document.Nftables {
		object, err := singleObject(raw)
		if err != nil {
			return nil, err
		}
		if object["chain"] == nil {
			continue
		}
		var fields map[string]json.RawMessage
		if decodeObject(object["chain"], &fields) != nil {
			return nil, errInvalidRuleset
		}
		var name, table string
		if json.Unmarshal(fields["name"], &name) != nil || json.Unmarshal(fields["table"], &table) != nil {
			return nil, errInvalidRuleset
		}
		for i, kind := range kinds {
			if strings.HasPrefix(name, kind+"-") || table == kind || (kind == "fail2ban" && strings.HasPrefix(name, "f2b-")) {
				if kind == "ufw" {
					ufwNative = true
				}
				if !managers[i].Active {
					managers[i].Uncertain = true
					managers[i].Detail = "发现同名 nft 管理对象，需核对共存状态"
				}
			}
		}
	}
	// --- 仅当服务、可信配置和两类原生事实一致时，解除 UFW 文件存在的疑虑 -----------
	if ufwDisabled && !ufwNative {
		result, err = g.Executor.Execute(ctx, local.Nft, []string{"-j", "list", "tables"}, nil)
		if err != nil || result.ExitCode != 0 {
			clear(result.Output)
			return nil, errors.New("firewall: existing UFW tables could not be checked")
		}
		defer clear(result.Output)
		if decodeObject(result.Output, &document) != nil {
			return nil, errors.New("firewall: existing UFW table state is invalid")
		}
		found := false
		for _, raw := range document.Nftables {
			object, err := singleObject(raw)
			if err != nil {
				return nil, err
			}
			if object["metainfo"] != nil {
				continue
			}
			var table tableObject
			if object["table"] == nil || decodeObject(object["table"], &table) != nil || table.Family == "" || table.Name == "" {
				return nil, errInvalidRuleset
			}
			if table.Name == "ufw" || strings.HasPrefix(table.Name, "ufw-") {
				found = true
			}
		}
		if !found {
			managers[0].Uncertain = false
			managers[0].Detail = "UFW 已明确停用，未发现残留原生规则"
		}
	}
	return managers, nil
}
