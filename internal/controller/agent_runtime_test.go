// SPDX-License-Identifier: AGPL-3.0-only

package controller

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/qwq-panel/qwq/internal/actor"
	"github.com/qwq-panel/qwq/internal/agentsession"
	"github.com/qwq-panel/qwq/internal/authz"
	"github.com/qwq-panel/qwq/internal/identity"
	"github.com/qwq-panel/qwq/internal/operations"
	"github.com/qwq-panel/qwq/internal/platform/ids"
	"github.com/qwq-panel/qwq/internal/platform/problem"
	"github.com/qwq-panel/qwq/internal/storage"
	platformv1 "github.com/qwq-panel/qwq/sdk/gen/qwq/platform/v1"
	"github.com/qwq-panel/qwq/sdk/manifest"
)

// agentEnv is a real controller (SQLite, identity, authz, operations and
// catalog) plus the production agent wiring. A fixture plugin is installed in
// the catalog and served by a fake plugin client, so the operation path is
// exercised without a plugin process or systemd. The human-only host actions
// get an executor too, so the tests prove they are refused by authorization
// and not merely by a missing handler.
type agentEnv struct {
	t      *testing.T
	c      *Controller
	runner *AgentRunner
	bridge *AgentApprovals
	admin  identity.User
	viewer identity.User
}

// The fixture plugin's actions the model may call.
const (
	agentPlugin  = "com.example.agent"
	agentWrite   = agentPlugin + "/rule.update"
	agentDestroy = agentPlugin + "/rule.delete"
	agentArgs    = `{"rule":"r1"}`
)

// newAgentEnv builds the environment.
func newAgentEnv(t *testing.T) *agentEnv {
	t.Helper()
	opts := testOptions(t)
	client := &fakePluginClient{invokeResp: &platformv1.InvokeResponse{PayloadJson: []byte(`{"updated":true}`)}}
	opts.PluginRuntime = &PluginRuntime{dispatcher: &pluginDispatcher{clients: &fakeClients{client: client}}}
	c, err := New(t.Context(), opts)
	if err != nil {
		t.Fatalf("controller.New: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })

	e := &agentEnv{t: t, c: c}
	e.admin = e.createUser("agent-admin", identity.RoleAdmin)
	e.viewer = e.createUser("agent-viewer", identity.RoleViewer)

	m := &manifest.Manifest{
		ID:        agentPlugin,
		Placement: "controller",
		Operations: []manifest.Operation{
			{
				Name: "rule.update", APIVersion: "1", Permission: agentPlugin + ":update",
				Mode: "invoke", Effect: "write", Risk: "high", Idempotent: true, Approval: "auto",
				Summary: "Update a rule", RequestSchema: "request.json", ResponseSchema: "response.json",
			},
			{
				Name: "rule.delete", APIVersion: "1", Permission: agentPlugin + ":delete",
				Mode: "invoke", Effect: "destructive", Risk: "high", Idempotent: true, Approval: "auto",
				Summary: "Delete a rule", RequestSchema: "request.json", ResponseSchema: "response.json",
			},
		},
	}
	if err := c.Catalog().SetPlugin(m, func(string) ([]byte, error) {
		return []byte(`{"type":"object","additionalProperties":true}`), nil
	}); err != nil {
		t.Fatalf("install fixture plugin: %v", err)
	}

	handler := func(context.Context, *storage.Tx, operations.HostRequest) (json.RawMessage, error) {
		return json.RawMessage(`{"updated":true}`), nil
	}
	for _, action := range []string{"host.users.create", "host.users.update", "host.users.delete", "host.account.update"} {
		if _, ok := c.Catalog().Get(action); !ok {
			t.Fatalf("catalog has no action %q", action)
		}
		c.Operations().RegisterHostAction(action, handler, nil)
	}
	logger := slog.New(slog.DiscardHandler)
	e.runner = &AgentRunner{
		Ops: c.Operations(), Catalog: c.Catalog(), NodeID: "local",
		Clock: c.Clock(), IDs: c.IDs(), Logger: logger,
	}
	e.bridge = &AgentApprovals{
		Ops: c.Operations(), Clock: c.Clock(), Logger: logger,
		Interval: 10 * time.Millisecond,
	}
	return e
}

func (e *agentEnv) createUser(username string, role identity.Role) identity.User {
	e.t.Helper()
	system := actor.SystemActor("test")
	var out identity.User
	err := e.c.DB().Update(e.t.Context(), func(tx *storage.Tx) error {
		tx.SetOrigin(storage.Origin{Actor: system})
		res, err := e.c.Identity().CreateUser(e.t.Context(), tx, identity.CreateUserInput{
			Username: username, DisplayName: username, Role: role, Actor: system,
		})
		out = res.User
		return err
	})
	if err != nil {
		e.t.Fatalf("create user %s: %v", username, err)
	}
	return out
}

// call builds a tool call for the session owner. The call id is unique per
// call, as the session service mints it.
func (e *agentEnv) call(owner string, mode operations.PermissionMode,
	action, args string, n int) agentsession.ToolCall {
	return agentsession.ToolCall{
		CallID:         fmt.Sprintf("call_agenttest_%016d", n),
		SessionID:      "sess_" + owner,
		Actor:          actor.Actor{Kind: ownerKind(owner), ID: owner},
		PermissionMode: mode,
		Action:         action,
		Args:           json.RawMessage(args),
	}
}

// ownerKind returns the actor kind of a session owner: a user or a service
// account.
func ownerKind(owner string) actor.Kind {
	if ids.Valid(owner, ids.Service) {
		return actor.Service
	}
	return actor.Human
}

// run executes one call with the session's mode on the context, exactly as
// internal/agentsession does.
func (e *agentEnv) run(call agentsession.ToolCall) agentsession.ToolResult {
	e.t.Helper()
	ctx := operations.WithPermissionMode(e.t.Context(), call.PermissionMode)
	res, err := e.runner.RunTool(ctx, call)
	if err != nil {
		e.t.Fatalf("RunTool: %v", err)
	}
	return res
}

func humanActor(u identity.User) actor.Actor {
	return actor.Actor{Kind: actor.Human, ID: u.ID, SessionID: "ses_test_agent"}
}

// decide decides one approval as the human administrator, through the operation
// manager the API route uses.
func (e *agentEnv) decide(approvalID, decision string) *operations.Response {
	e.t.Helper()
	resp, err := e.c.Operations().Decide(e.t.Context(), operations.DecisionRequest{
		Actor:      humanActor(e.admin),
		ApprovalID: approvalID,
		Decision:   decision,
		Idempotency: operations.Idempotency{
			Key:    "decide_" + approvalID + "_" + decision,
			Method: http.MethodPost,
			Route:  "/api/v1/approvals/" + approvalID + "/decision",
		},
	})
	if err != nil {
		e.t.Fatalf("Decide(%s): %v", decision, err)
	}
	return resp
}

// expireApproval moves the approval's deadline into the past, as the sweeper
// would after its TTL.
func (e *agentEnv) expireApproval(approvalID string) {
	e.t.Helper()
	err := e.c.DB().Update(e.t.Context(), func(tx *storage.Tx) error {
		_, err := tx.ExecContext(e.t.Context(),
			`UPDATE approvals SET expires_at = ? WHERE approval_id = ?`,
			storage.FormatTime(time.Now().Add(-time.Minute)), approvalID)
		return err
	})
	if err != nil {
		e.t.Fatalf("expire approval: %v", err)
	}
}

// waitBridge runs Wait in the background and returns its channels.
type bridgeWait struct {
	decision chan agentsession.ApprovalDecision
	err      chan error
}

func (e *agentEnv) waitBridge(ctx context.Context, approvalID string) bridgeWait {
	w := bridgeWait{
		decision: make(chan agentsession.ApprovalDecision, 1),
		err:      make(chan error, 1),
	}
	go func() {
		dec, err := e.bridge.Wait(ctx, approvalID)
		if err != nil {
			w.err <- err
			return
		}
		w.decision <- dec
	}()
	return w
}

func (w bridgeWait) result(t *testing.T, timeout time.Duration) agentsession.ApprovalDecision {
	t.Helper()
	select {
	case dec := <-w.decision:
		return dec
	case err := <-w.err:
		t.Fatalf("bridge.Wait: %v", err)
	case <-time.After(timeout):
		t.Fatal("bridge.Wait did not return before the test deadline")
	}
	return agentsession.ApprovalDecision{}
}

// pending starts a tool call that needs a human decision and returns its
// result.
func (e *agentEnv) pending(mode operations.PermissionMode, n int) agentsession.ToolResult {
	e.t.Helper()
	res := e.run(e.call(e.admin.ID, mode, agentWrite, agentArgs, n))
	if res.Status != agentsession.ToolAwaitingApproval {
		e.t.Fatalf("status = %q, want awaiting_approval (error %+v)", res.Status, res.Error)
	}
	if res.ApprovalID == "" || res.OperationID == "" {
		e.t.Fatalf("awaiting approval without ids: %+v", res)
	}
	return res
}

// TestAgentRunnerUsesAIActor checks the actor of a tool call: the operation and
// the approval record say that an AI agent acted for the owner, never that the
// owner acted directly.
func TestAgentRunnerUsesAIActor(t *testing.T) {
	e := newAgentEnv(t)
	call := e.call(e.admin.ID, operations.PermissionSafe, agentWrite, agentArgs, 1)
	res := e.run(call)
	if res.Status != agentsession.ToolAwaitingApproval {
		t.Fatalf("status = %q, want awaiting_approval (error %+v)", res.Status, res.Error)
	}

	ctx := e.t.Context()
	op, err := e.c.Operations().Get(ctx, humanActor(e.admin), res.OperationID)
	if err != nil {
		t.Fatalf("Get operation: %v", err)
	}
	if op.Actor.Kind != actor.AIAgent || op.Actor.ID != operations.SessionActorID(call.SessionID) {
		t.Fatalf("operation actor = %+v, want the session actor", op.Actor)
	}
	if op.Actor.OnBehalfOf != e.admin.ID {
		t.Fatalf("operation on_behalf_of = %q, want %q", op.Actor.OnBehalfOf, e.admin.ID)
	}
	if op.EffectiveRisk != operations.RiskHigh {
		t.Fatalf("effective risk = %q, want high", op.EffectiveRisk)
	}

	approval, err := e.c.Operations().GetApproval(ctx, humanActor(e.admin), res.ApprovalID)
	if err != nil {
		t.Fatalf("GetApproval: %v", err)
	}
	if approval.Facts.RequestedBy.Kind != actor.AIAgent ||
		approval.Facts.RequestedBy.OnBehalfOf != e.admin.ID {
		t.Fatalf("approval requested_by = %+v, want the session actor for the owner",
			approval.Facts.RequestedBy)
	}
	if res.Approval == nil || res.Approval.Deadline == nil {
		t.Fatalf("confirmation card = %+v, want catalog text and a deadline", res.Approval)
	}
	if res.Approval.Summary == "" || res.Approval.Risk != operations.RiskHigh {
		t.Fatalf("confirmation card = %+v", res.Approval)
	}

	// The same call id is idempotent: no second operation, no second approval.
	again := e.run(call)
	if again.OperationID != res.OperationID || again.ApprovalID != res.ApprovalID {
		t.Fatalf("replay = %s/%s, want %s/%s",
			again.OperationID, again.ApprovalID, res.OperationID, res.ApprovalID)
	}
}

// TestAgentRunnerFullModeRunsWithoutApproval checks that full skips the
// high-risk rule of a plugin action but still pauses on a destructive one.
func TestAgentRunnerFullModeRunsWithoutApproval(t *testing.T) {
	e := newAgentEnv(t)
	res := e.run(e.call(e.admin.ID, operations.PermissionFull, agentWrite, agentArgs, 2))
	if res.Status != agentsession.ToolSucceeded {
		t.Fatalf("status = %q, want succeeded (error %+v)", res.Status, res.Error)
	}
	if res.ApprovalID != "" || res.OperationID == "" {
		t.Fatalf("full-mode result = %+v", res)
	}

	destructive := e.run(e.call(e.admin.ID, operations.PermissionFull, agentDestroy, agentArgs, 3))
	if destructive.Status != agentsession.ToolAwaitingApproval {
		t.Fatalf("destructive full-mode status = %q, want awaiting_approval", destructive.Status)
	}
}

// TestAgentRunnerReadOnlyDeniesWrite checks that read_only refuses a write
// instead of queuing it, and that nothing was created.
func TestAgentRunnerReadOnlyDeniesWrite(t *testing.T) {
	e := newAgentEnv(t)
	res := e.run(e.call(e.admin.ID, operations.PermissionReadOnly, agentWrite, agentArgs, 4))
	if res.Status != agentsession.ToolFailed {
		t.Fatalf("status = %q, want failed", res.Status)
	}
	if res.Error == nil || res.Error.Code != problem.PermissionDenied {
		t.Fatalf("error = %+v, want PERMISSION_DENIED", res.Error)
	}
	if res.OperationID != "" {
		t.Fatalf("read_only created operation %q", res.OperationID)
	}
}

// TestAgentRunnerOwnerRoleDecides checks that the session uses its owner's RBAC
// role: a viewer cannot run an administrator action even though the AI actor
// itself has no delegation.
func TestAgentRunnerOwnerRoleDecides(t *testing.T) {
	e := newAgentEnv(t)
	res := e.run(e.call(e.viewer.ID, operations.PermissionSafe, agentWrite, agentArgs, 5))
	if res.Status != agentsession.ToolFailed || res.Error == nil ||
		res.Error.Code != problem.PermissionDenied {
		t.Fatalf("viewer session result = %+v", res)
	}
	if res.OperationID != "" {
		t.Fatalf("denied call created operation %q", res.OperationID)
	}
}

// TestAgentRunnerMapsErrors checks the error mapping of a refused call and of a
// reused idempotency key.
func TestAgentRunnerMapsErrors(t *testing.T) {
	e := newAgentEnv(t)
	unknown := e.run(e.call(e.admin.ID, operations.PermissionSafe, "host.does.not.exist", `{}`, 6))
	if unknown.Status != agentsession.ToolFailed || unknown.Error == nil ||
		unknown.Error.Code != problem.NotFound {
		t.Fatalf("unknown action result = %+v", unknown)
	}

	call := e.call(e.admin.ID, operations.PermissionSafe, agentWrite, agentArgs, 7)
	if res := e.run(call); res.Status != agentsession.ToolAwaitingApproval {
		t.Fatalf("first call = %+v", res)
	}
	reused := call
	reused.Args = json.RawMessage(`{"rule":"r2"}`)
	res := e.run(reused)
	if res.Status != agentsession.ToolFailed || res.Error == nil ||
		res.Error.Code != problem.IdempotencyKeyReused {
		t.Fatalf("reused key result = %+v", res)
	}
}

// TestAgentApprovalsApproveWaitsForDecision checks the polling bridge and the
// approved outcome of a real host action.
func TestAgentApprovalsApproveWaitsForDecision(t *testing.T) {
	e := newAgentEnv(t)
	res := e.pending(operations.PermissionSafe, 8)

	ctx, cancel := context.WithTimeout(e.t.Context(), 10*time.Second)
	defer cancel()
	w := e.waitBridge(ctx, res.ApprovalID)

	// Nothing was decided yet: the bridge must not answer.
	select {
	case dec := <-w.decision:
		t.Fatalf("bridge decided before the human: %+v", dec)
	case err := <-w.err:
		t.Fatalf("bridge failed before the human: %v", err)
	case <-time.After(80 * time.Millisecond):
	}

	e.decide(res.ApprovalID, operations.DecisionApprove)
	dec := w.result(t, 5*time.Second)
	if dec.Decision != agentsession.DecisionApprove {
		t.Fatalf("decision = %q, want approve", dec.Decision)
	}
	if dec.Status != agentsession.ToolSucceeded {
		t.Fatalf("status = %q, want succeeded (error %+v)", dec.Status, dec.Error)
	}
	if len(dec.Result) == 0 {
		t.Fatal("approved decision has no operation outcome")
	}

	op, err := e.c.Operations().Get(e.t.Context(), humanActor(e.admin), res.OperationID)
	if err != nil {
		t.Fatalf("Get operation: %v", err)
	}
	if op.Status != operations.Succeeded {
		t.Fatalf("operation status = %q, want SUCCEEDED", op.Status)
	}
}

// TestAgentApprovalsReject checks that a rejected approval terminates the call.
func TestAgentApprovalsReject(t *testing.T) {
	e := newAgentEnv(t)
	res := e.pending(operations.PermissionSafe, 9)
	e.decide(res.ApprovalID, operations.DecisionReject)

	dec, err := e.bridge.Wait(e.t.Context(), res.ApprovalID)
	if err != nil {
		t.Fatalf("Wait: %v", err)
	}
	if dec.Decision != agentsession.DecisionReject || dec.Status != agentsession.ToolRejected {
		t.Fatalf("decision = %+v, want reject/rejected", dec)
	}
	if dec.Error == nil || dec.Error.Code != problem.PermissionDenied {
		t.Fatalf("error = %+v, want PERMISSION_DENIED", dec.Error)
	}
}

// TestAgentApprovalsExpired checks that an expired approval is reported without
// waiting for the sweeper.
func TestAgentApprovalsExpired(t *testing.T) {
	e := newAgentEnv(t)
	res := e.pending(operations.PermissionSafe, 10)
	e.expireApproval(res.ApprovalID)

	dec, err := e.bridge.Wait(e.t.Context(), res.ApprovalID)
	if err != nil {
		t.Fatalf("Wait: %v", err)
	}
	if dec.Decision != agentsession.DecisionReject || dec.Status != agentsession.ToolFailed {
		t.Fatalf("decision = %+v, want reject/failed", dec)
	}
	if dec.Error == nil || dec.Error.Code != problem.StateConflict {
		t.Fatalf("error = %+v, want STATE_CONFLICT", dec.Error)
	}
}

// TestAgentApprovalsCancel checks that a canceled operation ends the wait.
func TestAgentApprovalsCancel(t *testing.T) {
	e := newAgentEnv(t)
	res := e.pending(operations.PermissionSafe, 11)

	_, err := e.c.Operations().Cancel(e.t.Context(), operations.CancelRequest{
		Actor:       humanActor(e.admin),
		OperationID: res.OperationID,
		Reason:      "test",
		Idempotency: operations.Idempotency{
			Key:    "cancel_" + res.OperationID,
			Method: http.MethodPost,
			Route:  "/api/v1/operations/" + res.OperationID + "/cancel",
		},
	})
	if err != nil {
		t.Fatalf("Cancel: %v", err)
	}

	dec, err := e.bridge.Wait(e.t.Context(), res.ApprovalID)
	if err != nil {
		t.Fatalf("Wait: %v", err)
	}
	if dec.Decision != agentsession.DecisionReject || dec.Status != agentsession.ToolRejected {
		t.Fatalf("decision = %+v, want reject/rejected", dec)
	}
}

// TestAgentApprovalsContextEndsWait checks that cancelling the wait returns the
// context error, which internal/agentsession maps to a cancelled turn.
func TestAgentApprovalsContextEndsWait(t *testing.T) {
	e := newAgentEnv(t)
	res := e.pending(operations.PermissionSafe, 12)

	ctx, cancel := context.WithTimeout(e.t.Context(), 80*time.Millisecond)
	defer cancel()
	if _, err := e.bridge.Wait(ctx, res.ApprovalID); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Wait error = %v, want the context deadline", err)
	}
}

// TestAgentApprovalsUnknownAndUnwired covers the two error paths of the bridge.
func TestAgentApprovalsUnknownAndUnwired(t *testing.T) {
	e := newAgentEnv(t)
	if _, err := e.bridge.Wait(e.t.Context(), "apv_doesnotexist"); err == nil ||
		!problem.HasCode(err, problem.NotFound) {
		t.Fatalf("unknown approval error = %v, want NOT_FOUND", err)
	}
	if _, err := (&AgentApprovals{}).Wait(e.t.Context(), "apv_x"); err == nil ||
		!problem.HasCode(err, problem.Unavailable) {
		t.Fatalf("unwired bridge error = %v, want UNAVAILABLE", err)
	}
}

// TestAICannotApprove checks the hard rule of ADR-0010 §5: the session actor
// itself can never decide an approval.
func TestAICannotApprove(t *testing.T) {
	e := newAgentEnv(t)
	res := e.pending(operations.PermissionSafe, 13)
	ai := actor.Actor{
		Kind:       actor.AIAgent,
		ID:         operations.SessionActorID("sess_" + e.admin.ID),
		OnBehalfOf: e.admin.ID,
	}
	_, err := e.c.Operations().Decide(e.t.Context(), operations.DecisionRequest{
		Actor:      ai,
		ApprovalID: res.ApprovalID,
		Decision:   operations.DecisionApprove,
		Idempotency: operations.Idempotency{
			Key:    "decide_ai_" + res.ApprovalID,
			Method: http.MethodPost,
			Route:  "/api/v1/approvals/" + res.ApprovalID + "/decision",
		},
	})
	if err == nil || !problem.HasCode(err, problem.PermissionDenied) {
		t.Fatalf("AI decision error = %v, want PERMISSION_DENIED", err)
	}
	op, err := e.c.Operations().Get(e.t.Context(), humanActor(e.admin), res.OperationID)
	if err != nil {
		t.Fatalf("Get operation: %v", err)
	}
	if op.Status != operations.AwaitingApproval {
		t.Fatalf("operation status = %q, want AWAITING_APPROVAL", op.Status)
	}
	if op.Actor.Kind != actor.AIAgent {
		t.Fatalf("operation actor = %+v, want the AI actor", op.Actor)
	}
}

// TestAgentToolCatalog checks the production ToolCatalog adapter: a plugin
// action is offered with its catalog metadata and the schema the model needs,
// while an action no operation handler serves is hidden.
func TestAgentToolCatalog(t *testing.T) {
	e := newAgentEnv(t)
	tools := AgentToolCatalog{
		Catalog: e.c.Catalog(), HostAction: e.c.Operations().HasHostAction,
	}.Actions(e.t.Context())
	var found bool
	for _, tool := range tools {
		if tool.Action == "host.plugins.install" {
			t.Fatal("an action without an operation handler is offered")
		}
		if tool.Action != agentWrite {
			continue
		}
		found = true
		if tool.Effect != operations.EffectWrite || tool.Risk != operations.RiskHigh ||
			tool.Permission != agentPlugin+":update" || tool.Summary == "" {
			t.Fatalf("tool = %+v", tool)
		}
		if len(tool.Parameters) == 0 || !json.Valid(tool.Parameters) {
			t.Fatalf("tool parameters are not JSON: %q", tool.Parameters)
		}
	}
	if !found {
		t.Fatalf("%s is not offered: %+v", agentWrite, tools)
	}
	if got := (AgentToolCatalog{}).Actions(e.t.Context()); got != nil {
		t.Fatalf("nil catalog returned %+v", got)
	}
}

// TestAgentToolCatalogHidesHumanOnly checks that no human-only action reaches
// the model, even with an executor registered for it (ADR-0004 D6).
func TestAgentToolCatalogHidesHumanOnly(t *testing.T) {
	e := newAgentEnv(t)
	tools := AgentToolCatalog{Catalog: e.c.Catalog()}.Actions(e.t.Context())
	if len(tools) == 0 {
		t.Fatal("no tools offered")
	}
	for _, tool := range tools {
		if strings.HasPrefix(tool.Action, "host.users.") || authz.IsHumanOnly(tool.Permission) {
			t.Fatalf("human-only tool offered: %s (%s)", tool.Action, tool.Permission)
		}
	}
}

// TestAgentRunnerHumanOnlyDenied checks that an administrator's session can
// neither manage users nor change its owner's account in any mode, and that the
// refusal leaves no operation behind.
func TestAgentRunnerHumanOnlyDenied(t *testing.T) {
	e := newAgentEnv(t)
	calls := []struct{ action, args string }{
		{"host.users.create", `{"username":"ops2","role":"admin"}`},
		{"host.users.update", `{"user_id":"usr_target"}`},
		{"host.users.delete", `{"user_id":"usr_target"}`},
		{"host.account.update", `{"display_name":"renamed by the model","expected_revision":"1"}`},
	}
	n := 100
	for _, mode := range []operations.PermissionMode{operations.PermissionSafe, operations.PermissionFull} {
		for _, c := range calls {
			n++
			res := e.run(e.call(e.admin.ID, mode, c.action, c.args, n))
			if res.Status != agentsession.ToolFailed || res.Error == nil ||
				res.Error.Code != problem.PermissionDenied {
				t.Fatalf("%s/%s result = %+v, want PERMISSION_DENIED", mode, c.action, res)
			}
			if res.OperationID != "" || res.ApprovalID != "" {
				t.Fatalf("%s/%s created operation %q approval %q", mode, c.action, res.OperationID, res.ApprovalID)
			}
		}
	}
}

// TestAgentRunnerServiceOwner checks a session owned by a service account: its
// role applies, minus the human-only permissions.
func TestAgentRunnerServiceOwner(t *testing.T) {
	e := newAgentEnv(t)
	var svc authz.CreatedServiceAccount
	err := e.c.DB().Update(e.t.Context(), func(tx *storage.Tx) error {
		tx.SetOrigin(storage.Origin{Actor: humanActor(e.admin)})
		var err error
		svc, err = e.c.Authorizer().CreateServiceAccount(e.t.Context(), tx, authz.CreateServiceAccountInput{
			Actor: humanActor(e.admin), Name: "agent-owner", Role: authz.RoleAdmin,
		})
		return err
	})
	if err != nil {
		t.Fatalf("create service account: %v", err)
	}
	res := e.run(e.call(svc.ID, operations.PermissionFull, agentWrite, agentArgs, 200))
	if res.Status != agentsession.ToolSucceeded {
		t.Fatalf("service-owned plugin call = %+v, want succeeded", res)
	}
	denied := e.run(e.call(svc.ID, operations.PermissionFull, "host.users.create", `{"username":"ops2","role":"admin"}`, 201))
	if denied.Status != agentsession.ToolFailed || denied.Error == nil ||
		denied.Error.Code != problem.PermissionDenied || denied.OperationID != "" {
		t.Fatalf("service-owned human-only call = %+v, want PERMISSION_DENIED", denied)
	}
}

// TestAgentApprovalsCancelWithdrawsOperation: a session that stops waiting
// withdraws the operation, so nobody can still approve it.
func TestAgentApprovalsCancelWithdrawsOperation(t *testing.T) {
	e := newAgentEnv(t)
	res := e.pending(operations.PermissionSafe, 41)
	owner := actor.Actor{Kind: actor.Human, ID: e.admin.ID}
	sessionID := "sess_" + e.admin.ID

	if err := e.bridge.CancelApproval(e.t.Context(), owner, sessionID, res.OperationID, "session cancelled"); err != nil {
		t.Fatalf("CancelApproval: %v", err)
	}
	system := actor.SystemActor("test")
	op, err := e.c.Operations().Get(e.t.Context(), system, res.OperationID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if op.Status != operations.Canceled {
		t.Fatalf("status = %s", op.Status)
	}
	_, err = e.c.Operations().Decide(e.t.Context(), operations.DecisionRequest{
		Actor: humanActor(e.admin), ApprovalID: res.ApprovalID, Decision: "approve",
		Idempotency: operations.Idempotency{
			Key: "decide_" + res.ApprovalID, Method: http.MethodPost,
			Route: "/api/v1/approvals/" + res.ApprovalID + "/decision",
		},
	})
	if !problem.HasCode(err, problem.StateConflict) {
		t.Fatalf("Decide after withdraw = %v", err)
	}
	// Withdrawing a finished operation reports the conflict the session handles.
	res2 := e.pending(operations.PermissionSafe, 42)
	e.decide(res2.ApprovalID, "reject")
	err = e.bridge.CancelApproval(e.t.Context(), owner, sessionID, res2.OperationID, "session cancelled")
	if !problem.HasCode(err, problem.StateConflict) {
		t.Fatalf("CancelApproval after decision = %v", err)
	}
}
