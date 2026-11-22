// SPDX-License-Identifier: AGPL-3.0-only

package authz

import "testing"

func TestRoleAllowsSensitiveBoundaries(t *testing.T) {
	cases := []struct {
		role Role
		perm Permission
		want bool
	}{
		// ======================== 管理员完整权限 ========================
		{RoleAdmin, "host.users:read", true},
		{RoleAdmin, "host.users:create", true},
		{RoleAdmin, "host.service_accounts:read", true},
		{RoleAdmin, "host.service_accounts:create", true},
		{RoleAdmin, "host.delegations:read", true},
		{RoleAdmin, "host.audit:read", true},
		{RoleAdmin, "core.xray:export", true},

		// ======================== 运维自管与管理员集合边界 ========================
		{RoleOperator, "host.users:read", false},
		{RoleOperator, "host.users:create", false},
		{RoleOperator, "host.service_accounts:read", false},
		{RoleOperator, "host.service_accounts:create", false},
		{RoleOperator, "host.audit:read", false},
		{RoleOperator, "host.ai_providers:create", false},
		{RoleOperator, "host.ai_providers:update", false},
		{RoleOperator, "host.ai_providers:delete", false},
		{RoleOperator, "host.ai_providers:read", true},
		{RoleOperator, "host.delegations:read", true},
		{RoleOperator, "host.delegations:create", true},
		{RoleOperator, "host.delegations:revoke", true},
		{RoleOperator, "host.plugins:install", true},
		{RoleOperator, "host.operations:cancel", true},
		{RoleOperator, "core.xray:export", true},

		// ======================== 只读契约与敏感集合边界 ========================
		{RoleViewer, "host.users:read", false},
		{RoleViewer, "host.service_accounts:read", false},
		{RoleViewer, "host.delegations:read", true},
		{RoleViewer, "host.delegations:create", false},
		{RoleViewer, "host.delegations:revoke", false},
		{RoleViewer, "host.audit:read", false},
		{RoleViewer, "core.xray:export", true},
		{RoleViewer, "host.plugins:export", true},
		{RoleViewer, "host.nodes:read", true},
		{RoleViewer, "host.plugins:read", true},
		{RoleViewer, "host.operations:read", true},
		{RoleViewer, "host.operations:cancel", false},
		{RoleViewer, "host.agent_sessions:read", true},
		{RoleViewer, "host.agent_sessions:write", false},
		// 本人账户管理仍遵循既有自服务入口，不扩展到其他主体。
		{RoleViewer, "host.account:update", true},
	}

	for _, tc := range cases {
		if got := RoleAllows(tc.role, tc.perm); got != tc.want {
			t.Errorf("RoleAllows(%q, %q) = %v, want %v", tc.role, tc.perm, got, tc.want)
		}
	}
}
