// SPDX-License-Identifier: AGPL-3.0-only

package operations

import (
	"encoding/json"
	"testing"

	"github.com/qwq-panel/qwq/internal/actor"
	"github.com/qwq-panel/qwq/internal/platform/problem"
	"github.com/qwq-panel/qwq/internal/storage"
)

// ---------------------------------------------------------------------------
// ADR-0011 §5/§7：子 operation 的风险、权限模式、调用深度与参数 schema
// ---------------------------------------------------------------------------

// runChild submits a child of parentID as a plugin would: as the parent's actor.
func (e *testEnv) runChild(parentID, action string, args map[string]any) (*Response, error) {
	parent := e.operation(parentID)
	return e.runReq(parent.Actor, RunRequest{
		Action: action, Target: Target{Subject: resourceSubject},
		Args: mustJSON(e.t, args), ParentOperationID: parentID,
		Idempotency: Idempotency{Key: e.newKey(), Route: "/api/v1/test/" + action},
	})
}

func (e *testEnv) setColumn(id, column, value string) {
	e.t.Helper()
	if err := e.db.Update(e.ctx, func(tx *storage.Tx) error {
		_, err := tx.ExecContext(e.ctx, `UPDATE operations SET `+column+` = ? WHERE operation_id = ?`, value, id)
		return err
	}); err != nil {
		e.t.Fatalf("set %s: %v", column, err)
	}
}

// TestChildRecordsMaxRiskDecidesOnOwnRisk: the child shows the riskier of the
// two but is approved on its own risk.
func TestChildRecordsMaxRiskDecidesOnOwnRisk(t *testing.T) {
	e := newTestEnv(t)
	parent, err := e.run(humanActor(), actionHigh, Target{Subject: resourceSubject}, map[string]any{"value": "p"})
	if err != nil {
		t.Fatal(err)
	}
	child, err := e.runChild(parent.Operation.ID, actionWrite, map[string]any{"value": "c"})
	if err != nil {
		t.Fatalf("child: %v", err)
	}
	if child.Operation.Status != Succeeded {
		t.Fatalf("a low-risk child under a high-risk parent must not be re-approved, got %s", child.Operation.Status)
	}
	if child.Operation.EffectiveRisk != RiskHigh {
		t.Fatalf("child effective risk = %s, want the parent's high", child.Operation.EffectiveRisk)
	}
}

// TestChildInheritsPermissionMode: the mode is stored with the operation and a
// child can never run under a wider one than its parent.
func TestChildInheritsPermissionMode(t *testing.T) {
	e := newTestEnv(t)
	e.policy.set(humanActor(), Limits{PermissionMode: PermissionFull})
	parent, err := e.run(humanActor(), actionWrite, Target{Subject: resourceSubject}, map[string]any{"value": "p"})
	if err != nil {
		t.Fatal(err)
	}
	if got := e.operation(parent.Operation.ID).PermissionMode; got != PermissionFull {
		t.Fatalf("stored permission mode = %q, want full", got)
	}
	e.setColumn(parent.Operation.ID, "permission_mode", string(PermissionReadOnly))
	if _, err := e.runChild(parent.Operation.ID, actionWrite, map[string]any{"value": "c"}); !problem.HasCode(err, problem.PermissionDenied) {
		t.Fatalf("write child of a read_only parent = %v, want PERMISSION_DENIED", err)
	}
	// A row written before the column reads as safe, never wider.
	if got := stricterMode(PermissionFull, PermissionMode("").normalized()); got != PermissionSafe {
		t.Fatalf("stricterMode(full, unset) = %s, want safe", got)
	}
}

// TestChildDepthLimit: a chain stops at MaxCallDepth operations.
func TestChildDepthLimit(t *testing.T) {
	e := newTestEnv(t)
	root, err := e.run(humanActor(), actionWrite, Target{Subject: resourceSubject}, map[string]any{"value": "0"})
	if err != nil {
		t.Fatal(err)
	}
	id := root.Operation.ID
	for depth := 2; depth <= MaxCallDepth; depth++ {
		child, err := e.runChild(id, actionWrite, map[string]any{"value": "x"})
		if err != nil {
			t.Fatalf("depth %d: %v", depth, err)
		}
		id = child.Operation.ID
	}
	if _, err := e.runChild(id, actionWrite, map[string]any{"value": "x"}); !problem.HasCode(err, problem.PermissionDenied) {
		t.Fatalf("depth %d = %v, want PERMISSION_DENIED", MaxCallDepth+1, err)
	}
}

// TestChildRequiresParentsActor: another principal cannot hang work on a
// parent it does not own.
func TestChildRequiresParentsActor(t *testing.T) {
	e := newTestEnv(t)
	parent, err := e.run(humanActor(), actionWrite, Target{Subject: resourceSubject}, map[string]any{"value": "p"})
	if err != nil {
		t.Fatal(err)
	}
	other := actor.Actor{Kind: actor.Human, ID: "usr_other", SessionID: "ses_other"}
	_, err = e.runReq(other, RunRequest{
		Action: actionWrite, Target: Target{Subject: resourceSubject},
		Args: mustJSON(t, map[string]any{"value": "c"}), ParentOperationID: parent.Operation.ID,
		Idempotency: Idempotency{Key: e.newKey(), Route: "/api/v1/test/" + actionWrite},
	})
	if !problem.HasCode(err, problem.PermissionDenied) {
		t.Fatalf("foreign parent = %v, want PERMISSION_DENIED", err)
	}
}

// TestRunValidatesArgsSchema: arguments that break the plugin's request schema
// never reach the plugin (ARCH §5.4).
func TestRunValidatesArgsSchema(t *testing.T) {
	e := newTestEnv(t)
	e.setAction(actionPlugin, func(a *Action) {
		a.ArgsSchema = json.RawMessage(`{"type":"object","properties":{"mode":{"enum":["full","quick"]}},"additionalProperties":false}`)
	})
	_, err := e.run(humanActor(), actionPlugin, nodeTarget(), map[string]any{"mode": "rm -rf"})
	var pe *problem.Error
	if !asProblemError(err, &pe) || pe.Code != problem.ValidationFailed || len(pe.Violations) == 0 ||
		pe.Violations[0].Pointer != "/args/mode" {
		t.Fatalf("bad args = %+v, want VALIDATION_FAILED at /args/mode", err)
	}
	if n := e.dispatcher.invokeCount(); n != 0 {
		t.Fatalf("invokes = %d, want 0", n)
	}
	if n := e.countOperations(); n != 0 {
		t.Fatalf("operations = %d, want 0", n)
	}
	if _, err := e.run(humanActor(), actionPlugin, nodeTarget(), map[string]any{"mode": "full"}); err != nil {
		t.Fatalf("valid args: %v", err)
	}
	e.setAction(actionPlugin, func(a *Action) {
		a.ArgsSchema = json.RawMessage(`{"$ref":"https://example.com/evil.json"}`)
	})
	if _, err := e.run(humanActor(), actionPlugin, nodeTarget(), map[string]any{"mode": "full"}); !problem.HasCode(err, problem.ValidationFailed) {
		t.Fatalf("external $ref = %v, want VALIDATION_FAILED", err)
	}
}
