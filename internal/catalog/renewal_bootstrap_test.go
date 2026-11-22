// SPDX-License-Identifier: AGPL-3.0-only

package catalog

import (
	"encoding/json"
	"slices"
	"testing"
)

// ======================== 续期创建入口的固定风险与最小公共参数 ========================

func TestRenewalBootstrapCatalogRequiresHumanApprovalAndPrivateScope(t *testing.T) {
	c := newCatalog(t)
	action, ok := c.Get("host.service_accounts.renewal_bootstrap")
	if !ok {
		t.Fatal("真实续期账号创建入口未进入原生操作目录")
	}
	if action.Source != Host || action.Risk != "high" || action.DeclaredRisk != "high" ||
		action.Effect != "write" || action.Mode != "invoke" || !action.Plannable ||
		action.Permission != "host.service_accounts:create" || action.Method != "POST" ||
		action.Path != "/api/v1/service-accounts/renewal-bootstrap" {
		t.Fatal("续期创建入口的风险、权限或统一调用方式被改变")
	}
	var schema struct {
		Properties           map[string]json.RawMessage `json:"properties"`
		Required             []string                   `json:"required"`
		AdditionalProperties *bool                      `json:"additionalProperties"`
	}
	if err := json.Unmarshal(action.ArgsSchema, &schema); err != nil {
		t.Fatal(err)
	}
	if len(schema.Properties) != 2 || len(schema.Required) != 2 ||
		!slices.Contains(schema.Required, "policy_id") || !slices.Contains(schema.Required, "expected_revision") ||
		schema.AdditionalProperties == nil || *schema.AdditionalProperties {
		t.Fatal("公共参数允许自报账号权限、身份或完整私有策略")
	}
}
