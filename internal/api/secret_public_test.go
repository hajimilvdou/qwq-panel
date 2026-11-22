// SPDX-License-Identifier: AGPL-3.0-only

package api

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/qwq-panel/qwq/internal/agentsession"
	"github.com/qwq-panel/qwq/internal/operations"
)

func TestPublicPlanAndAgentApprovalDTOsHideReferences(t *testing.T) {
	args := json.RawMessage(`{"visible":"keep","password":{"$secret":"private-reference"}}`)
	original := bytes.Clone(args)
	plan := &operations.Plan{Args: args, Changes: []operations.PlannedChange{{Before: args, After: args}}}
	for name, value := range map[string]any{
		"REST plan":          newPlanDTO(plan),
		"stored plan":        plan,
		"legacy approval":    operations.Approval{Facts: operations.ApprovalFacts{Args: args}},
		"agent confirmation": newAgentApprovalDTOs([]agentsession.PendingApproval{{Args: args}}),
	} {
		t.Run(name, func(t *testing.T) {
			out, err := json.Marshal(value)
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Contains(out, []byte("$secret")) || bytes.Contains(out, []byte("private-reference")) {
				t.Fatal("public DTO exposed an internal reference")
			}
			if !bytes.Contains(out, []byte(`"visible":"keep"`)) {
				t.Fatal("public DTO lost nonsecret arguments")
			}
		})
	}
	if !bytes.Equal(args, original) || !bytes.Equal(plan.Args, original) || !bytes.Equal(plan.Changes[0].Before, original) {
		t.Fatal("a DTO changed private execution or preview data")
	}
}

func TestOpaqueArgumentObjectsKeepPublicAPIShape(t *testing.T) {
	args := json.RawMessage(`{"$secret":"private-reference"}`)
	plan := &operations.Plan{Args: args}
	for _, value := range []any{plan, newPlanDTO(plan), operations.ApprovalFacts{Args: args}} {
		out, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		var object map[string]any
		if json.Unmarshal(out, &object) != nil {
			t.Fatal("invalid public JSON")
		}
		arguments, ok := object["args"].(map[string]any)
		if !ok || arguments["$redacted"] != true {
			t.Fatal("whole-object secret redaction broke the public args object schema")
		}
	}
}
