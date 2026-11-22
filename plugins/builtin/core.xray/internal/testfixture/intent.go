// SPDX-License-Identifier: AGPL-3.0-only

// Package testfixture 为 Core 测试共享独立、有效且不含真实材料的输入。
package testfixture

import "github.com/qwq-panel/qwq/sdk/coreapi"

// Intent 每次返回独立配置，避免不同包复制字段或共享可变测试数据。
func Intent() *coreapi.Intent {
	enabled := true
	return &coreapi.Intent{
		SchemaVersion: "1", Enabled: &enabled,
		Inbound: &coreapi.Inbound{
			ID: "main", Listen: "0.0.0.0", Port: 10443,
			Protocol: "vless", Transport: "raw", Flow: "xtls-rprx-vision",
			Security: &coreapi.Reality{
				Mode: "reality", Target: "example.com:443", ServerNames: []string{"example.com"},
				PrivateKey: coreapi.SecretRef{ID: "sec_00000000000000000000000000"}, ShortIDs: []string{"ab"},
			},
			Users: []coreapi.User{{ID: "alice", UUID: coreapi.SecretRef{ID: "sec_00000000000000000000000001"}}},
		},
		Outbound: &coreapi.Outbound{Type: "direct"},
	}
}
