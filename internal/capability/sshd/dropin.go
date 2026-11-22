// SPDX-License-Identifier: AGPL-3.0-only

// Package sshd 实现仅管理 qwq 自有 drop-in 的 SSH 配置事务。
package sshd

import (
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"

	sshdv1 "github.com/qwq-panel/qwq/sdk/gen/qwq/capability/sshd/v1"
)

const managedHeader = "# qwq managed sshd settings\n"

type loginPolicy struct {
	Ports        []uint32
	PasswordAuth *bool
	KeyboardAuth *bool
	RootLogin    string
}

// parseDropIn 不接管同名外部文件，也不保留未经本能力授权的额外指令。
func parseDropIn(raw []byte) (loginPolicy, error) {
	var policy loginPolicy
	if raw == nil {
		return policy, nil
	}
	if len(raw) > 64<<10 || !strings.HasPrefix(string(raw), managedHeader) {
		return policy, errors.New("sshd: drop-in is not qwq-owned")
	}
	seen := make(map[string]bool)
	for _, line := range strings.Split(string(raw), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 || strings.HasPrefix(fields[0], "#") {
			continue
		}
		if len(fields) != 2 {
			return policy, errors.New("sshd: invalid owned directive")
		}
		key, value := strings.ToLower(fields[0]), strings.ToLower(fields[1])
		if key != "port" && seen[key] {
			return policy, errors.New("sshd: duplicate owned directive")
		}
		seen[key] = true
		switch key {
		case "port":
			port, err := strconv.ParseUint(value, 10, 16)
			if err != nil || port == 0 {
				return policy, errors.New("sshd: invalid owned port")
			}
			policy.Ports = append(policy.Ports, uint32(port))
		case "passwordauthentication", "kbdinteractiveauthentication":
			if value != "yes" && value != "no" {
				return policy, errors.New("sshd: invalid authentication flag")
			}
			flag := value == "yes"
			if key == "passwordauthentication" {
				policy.PasswordAuth = &flag
			} else {
				policy.KeyboardAuth = &flag
			}
		case "permitrootlogin":
			if value != "yes" && value != "no" && value != "prohibit-password" {
				return policy, errors.New("sshd: invalid root policy")
			}
			policy.RootLogin = value
		default:
			return policy, errors.New("sshd: unsupported owned directive")
		}
	}
	policy.Ports = uniquePorts(policy.Ports)
	return policy, nil
}

func renderDropIn(policy loginPolicy) []byte {
	var out strings.Builder
	out.WriteString(managedHeader)
	for _, port := range uniquePorts(policy.Ports) {
		fmt.Fprintf(&out, "Port %d\n", port)
	}
	writeFlag := func(key string, value *bool) {
		if value == nil {
			return
		}
		text := "no"
		if *value {
			text = "yes"
		}
		fmt.Fprintf(&out, "%s %s\n", key, text)
	}
	writeFlag("PasswordAuthentication", policy.PasswordAuth)
	writeFlag("KbdInteractiveAuthentication", policy.KeyboardAuth)
	if policy.RootLogin != "" {
		fmt.Fprintf(&out, "PermitRootLogin %s\n", policy.RootLogin)
	}
	return []byte(out.String())
}

func uniquePorts(ports []uint32) []uint32 {
	ports = slices.Clone(ports)
	slices.Sort(ports)
	return slices.Compact(ports)
}

func settingValue(settings []*sshdv1.Setting, key string) string {
	for _, setting := range settings {
		if setting.Key == key {
			return setting.Value
		}
	}
	return ""
}

func policySettings(policy loginPolicy) []*sshdv1.Setting {
	password, keyboard, root := "yes", "yes", "prohibit-password"
	if policy.PasswordAuth != nil && !*policy.PasswordAuth {
		password = "no"
	}
	if policy.KeyboardAuth != nil && !*policy.KeyboardAuth {
		keyboard = "no"
	}
	if policy.RootLogin != "" {
		root = policy.RootLogin
	}
	return []*sshdv1.Setting{{Key: "passwordauthentication", Value: password}, {Key: "kbdinteractiveauthentication", Value: keyboard}, {Key: "permitrootlogin", Value: root}, {Key: "pubkeyauthentication", Value: "yes"}}
}
