// SPDX-License-Identifier: AGPL-3.0-only

package sandbox

import "testing"

// ======================== 原归属规则与强停止所需的唯一统一层级 ========================

func TestGenerationUnifiedCgroupRejectsAmbiguousOrRoot(t *testing.T) {
	for _, value := range []string{"", "0::/", "0::/system.slice/../other", "4:name=systemd:/system.slice/alpha.service",
		"0::/system.slice/alpha.service\n0::/system.slice/beta.service", "0::/system.slice/alpha.service\n0::/"} {
		if _, err := UnifiedCgroupPath(value); err == nil {
			t.Fatalf("无确定统一控制组仍被接受：%q", value)
		}
	}
	valid := "0::/system.slice/qwq-plugin@alpha.service\n"
	if got, err := UnifiedCgroupPath(valid); err != nil || got != "/system.slice/qwq-plugin@alpha.service" {
		t.Fatalf("统一控制组 = %q, %v", got, err)
	}
}
