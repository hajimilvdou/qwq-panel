// SPDX-License-Identifier: AGPL-3.0-only

package firewall

import "strings"

// ======================== UFW 关闭事实只接受一个明确的可信赋值 ========================

func ufwExplicitlyDisabled(raw []byte) bool {
	if len(raw) == 0 || len(raw) > 64<<10 {
		return false
	}
	seen, disabled := false, false
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok || strings.TrimSpace(key) != "ENABLED" {
			continue
		}
		if seen {
			return false
		}
		seen, disabled = true, strings.TrimSpace(value) == "no"
	}
	return seen && disabled
}
