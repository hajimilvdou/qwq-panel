// SPDX-License-Identifier: AGPL-3.0-only

package sandbox

import (
	"errors"
	"path"
	"strconv"
	"strings"
)

// ======================== 控制组归属规则单源，旧 v1/v2 读取保持兼容 ========================

// CgroupUnit 从 proc cgroup 内容提取最近的 service/socket/scope，复用 systemd 转义规则。
func CgroupUnit(data string) string {
	for _, line := range strings.Split(data, "\n") {
		fields := strings.SplitN(strings.TrimSpace(line), ":", 3)
		if len(fields) != 3 {
			continue
		}
		parts := strings.Split(fields[2], "/")
		for index := len(parts) - 1; index >= 0; index-- {
			name := unescapeCgroupName(parts[index])
			if strings.HasSuffix(name, ".service") || strings.HasSuffix(name, ".socket") || strings.HasSuffix(name, ".scope") {
				return name
			}
		}
	}
	return ""
}

func unescapeCgroupName(value string) string {
	if !strings.Contains(value, "\\x") {
		return value
	}
	var result strings.Builder
	result.Grow(len(value))
	for index := 0; index < len(value); index++ {
		if value[index] == '\\' && index+3 < len(value) && value[index+1] == 'x' {
			if decoded, err := strconv.ParseUint(value[index+2:index+4], 16, 8); err == nil {
				result.WriteByte(byte(decoded))
				index += 3
				continue
			}
		}
		result.WriteByte(value[index])
	}
	return result.String()
}

// UnifiedCgroupPath 只接受唯一真实 v2 归属，不将 v1/default/root 路径当停止授权。
func UnifiedCgroupPath(data string) (string, error) {
	var found string
	for _, line := range strings.Split(data, "\n") {
		fields := strings.SplitN(strings.TrimSpace(line), ":", 3)
		if len(fields) != 3 || fields[0] != "0" || fields[1] != "" {
			continue
		}
		if found != "" || !validGenerationCgroupPath(fields[2]) {
			return "", errors.New("sandbox: the unified cgroup identity is unavailable")
		}
		found = fields[2]
	}
	if found == "" {
		return "", errors.New("sandbox: the unified cgroup identity is unavailable")
	}
	return found, nil
}

func validGenerationCgroupPath(value string) bool {
	return value != "/" && path.IsAbs(value) && path.Clean(value) == value && !strings.ContainsAny(value, "\x00\r\n")
}
