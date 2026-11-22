// SPDX-License-Identifier: AGPL-3.0-only

package catalog_test

import (
	"testing"

	"github.com/qwq-panel/qwq/internal/catalog"
	"github.com/qwq-panel/qwq/internal/operations"
	"github.com/qwq-panel/qwq/sdk/manifest"
)

func operationCaps(caps []catalog.Capability) []operations.Capability {
	result := make([]operations.Capability, len(caps))
	for index, capability := range caps {
		result[index] = operations.Capability{Name: capability.Name, Scope: capability.Scope}
	}
	return result
}

func TestP6CatalogClampsRiskAndApproval(t *testing.T) {
	c, err := catalog.New(
		func(declared, effect string, caps []catalog.Capability) string {
			return operations.RiskFloor(declared, effect, operationCaps(caps))
		},
		func(effect string, caps []catalog.Capability) bool {
			return operations.ForcedReachability(effect, operationCaps(caps))
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"system.account.keys", "system.account.password", "system.ban.manage"} {
		m := &manifest.Manifest{
			ID: "security.basic", Placement: "node", Capabilities: []manifest.Capability{{Name: name, Scope: "all"}},
			Operations: []manifest.Operation{{Name: "manage", APIVersion: "v1", Mode: "invoke", Effect: "write", Risk: "low", Approval: "auto", Permission: "security.basic:write", RequestSchema: "request.json", ResponseSchema: "response.json"}},
		}
		if err := c.SetPlugin(m, func(string) ([]byte, error) { return []byte(`{"type":"object"}`), nil }); err != nil {
			t.Fatal(err)
		}
		entry, ok := c.Get("security.basic/manage")
		if !ok || !entry.Reachability || entry.Risk != "high" || entry.Approval != "ai_confirm" {
			t.Errorf("catalog 未钳制 %s", name)
		}
	}
}
