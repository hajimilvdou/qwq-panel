// SPDX-License-Identifier: AGPL-3.0-only

package controller

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/qwq-panel/qwq/internal/actor"
	"github.com/qwq-panel/qwq/internal/authz"
	"github.com/qwq-panel/qwq/internal/operations"
	"github.com/qwq-panel/qwq/internal/platform/clock"
	"github.com/qwq-panel/qwq/internal/platform/ids"
	"github.com/qwq-panel/qwq/internal/pluginhost/hostsvc"
	"github.com/qwq-panel/qwq/internal/prerequisites/testsupport"
	"github.com/qwq-panel/qwq/internal/secrets"
	"github.com/qwq-panel/qwq/internal/storage"
)

// ======================== 真实派发、权限、AES-GCM 与原参数 ========================

type secretTestCatalog map[string]operations.Action

func (c secretTestCatalog) Action(id string) (operations.Action, bool) {
	value, ok := c[id]
	return value, ok
}

type secretTestDispatch struct {
	started chan json.RawMessage
	release chan struct{}
	once    sync.Once
}

func (*secretTestDispatch) Plan(context.Context, operations.PluginPlanRequest) (operations.Preview, error) {
	return operations.Preview{}, nil
}

func (*secretTestDispatch) Cancel(context.Context, operations.PluginCancelRequest) error {
	return nil
}

func (d *secretTestDispatch) hold(ctx context.Context, args json.RawMessage) error {
	select {
	case d.started <- bytes.Clone(args):
	case <-ctx.Done():
		return ctx.Err()
	}
	select {
	case <-d.release:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
func (d *secretTestDispatch) Invoke(ctx context.Context, req operations.PluginInvokeRequest) (operations.PluginInvokeResponse, error) {
	err := d.hold(ctx, req.Payload)
	return operations.PluginInvokeResponse{Result: json.RawMessage(`{"complete":true}`)}, err
}
func (d *secretTestDispatch) RunJob(ctx context.Context, req operations.PluginRunJobRequest, progress func(operations.JobProgress) error) error {
	if err := d.hold(ctx, req.Payload); err != nil {
		return err
	}
	return progress(operations.JobProgress{Completed: true, Result: json.RawMessage(`{"complete":true}`)})
}

type secretTestFixture struct {
	host      *testsupport.HostFixture
	catalog   secretTestCatalog
	human     actor.Actor
	opID, ref string
	dispatch  *secretTestDispatch
	revealer  *hostSecretRevealer
}

func newSecretTestFixture(t *testing.T, mode, capability string) *secretTestFixture {
	t.Helper()
	dispatch := &secretTestDispatch{started: make(chan json.RawMessage, 1), release: make(chan struct{})}
	const actionID = "alpha/secret.use"
	action := operations.Action{ID: actionID, Summary: "秘密派发回归", Source: operations.PluginSource, PluginID: "alpha",
		Operation: "secret.use", APIVersion: "1", Placement: operations.PlacementNode, Effect: operations.EffectWrite,
		Risk: operations.RiskHigh, Mode: mode, Idempotent: true, TimeoutMS: 60000, Permission: "host.plugins:config",
		Approval:   operations.ApprovalConfirm,
		ArgsSchema: json.RawMessage(`{"type":"object","properties":{"password":{"type":"string","writeOnly":true}},"required":["password"]}`)}
	if capability != "" {
		action.Capabilities = []operations.Capability{{Name: "secret.reveal", Scope: capability}}
	}
	catalog := secretTestCatalog{actionID: action}
	host := testsupport.NewHost(t, clock.NewFake(time.Date(2026, 11, 18, 1, 0, 0, 0, time.UTC)), catalog, dispatch)
	human := host.User(t, "secret-owner", authz.RoleAdmin)
	t.Cleanup(func() { dispatch.once.Do(func() { close(dispatch.release) }) })
	response, err := host.Operations.Run(host.Context, operations.RunRequest{Actor: human, Action: actionID,
		Target:      operations.Target{NodeID: "local", PluginID: "alpha", InstanceID: "default"},
		Args:        json.RawMessage(`{"password":"TEST-ONLY-dispatched-secret"}`),
		Idempotency: operations.Idempotency{Key: host.IDs.New(ids.Operation), Method: "POST", Route: "/fixture/secret"}})
	if err != nil || response.Operation == nil || response.Operation.Status != operations.AwaitingApproval {
		t.Fatal("real secret operation did not enter approval")
	}
	approval, err := host.Operations.GetApproval(host.Context, human, response.Operation.ApprovalID)
	if err != nil {
		t.Fatal(err)
	}
	decision := make(chan error, 1)
	go func() {
		_, err := host.Operations.Decide(host.Context, operations.DecisionRequest{Actor: human, ApprovalID: approval.ID,
			Decision: operations.DecisionApprove, ExpectedRevision: approval.Revision,
			Idempotency: operations.Idempotency{Key: host.IDs.New(ids.Operation), Method: "POST", Route: "/fixture/secret-approve"}})
		decision <- err
	}()
	t.Cleanup(func() {
		dispatch.once.Do(func() { close(dispatch.release) })
		select {
		case err := <-decision:
			if err != nil {
				t.Errorf("secret decision failed: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("secret decision did not finish")
		}
	})
	var payload json.RawMessage
	select {
	case payload = <-dispatch.started:
	case <-time.After(5 * time.Second):
		t.Fatal("real secret operation did not dispatch")
	}
	defer clear(payload)
	var args map[string]any
	if json.Unmarshal(payload, &args) != nil {
		t.Fatal("invalid protected dispatch JSON")
	}
	ref, ok := secrets.RefFromObject(args["password"])
	if !ok {
		t.Fatal("real operation did not extract its sensitive parameter")
	}
	return &secretTestFixture{host: host, catalog: catalog, human: human, opID: response.Operation.ID, ref: string(ref), dispatch: dispatch,
		revealer: &hostSecretRevealer{operations: host.Operations, secrets: host.Secrets, pluginID: "alpha", instanceID: "default", nodeID: "local"}}
}

func TestOperationSecretRevealUsesRealExecutorAndExactScope(t *testing.T) {
	for _, mode := range []string{operations.ModeJob, operations.ModeInvoke} {
		t.Run(mode, func(t *testing.T) {
			f := newSecretTestFixture(t, mode, "operation")
			accepted, err := f.host.Operations.ResolveDispatchedInstance(t.Context(), "alpha", "default", "local", f.opID)
			if err != nil {
				t.Fatalf("real dispatch lookup failed: %v", err)
			}
			schema := accepted.ArgumentSchema()
			member, memberErr := secrets.SensitiveArgumentReference(schema, accepted.Args, secrets.Ref(f.ref))
			clear(schema)
			accepted.Clear()
			if !member || memberErr != nil {
				t.Fatalf("original sensitive member failed: matched=%v error=%v", member, memberErr)
			}
			value, err := f.revealer.Reveal(t.Context(), f.ref, f.opID, []string{"operation"})
			defer clear(value)
			if err != nil || string(value) != `"TEST-ONLY-dispatched-secret"` {
				t.Fatalf("authorized original operation reveal failed: error=%v bytes=%d", err, len(value))
			}
			for _, scopes := range [][]string{nil, {"config"}, {"*"}} {
				if value, err := f.revealer.Reveal(t.Context(), f.ref, f.opID, scopes); !errors.Is(err, hostsvc.ErrSecretDenied) || len(value) != 0 {
					clear(value)
					t.Fatal("another secret scope substituted for operation scope")
				}
			}
			var other secrets.Ref
			if err := f.host.DB.Update(t.Context(), func(tx *storage.Tx) error {
				var err error
				other, err = f.host.Secrets.Put(t.Context(), tx, "plugins/alpha", "plugin.operation", []byte("TEST-ONLY-another-operation"))
				return err
			}); err != nil {
				t.Fatal(err)
			}
			if value, err := f.revealer.Reveal(t.Context(), string(other), f.opID, []string{"operation"}); !errors.Is(err, hostsvc.ErrSecretDenied) || len(value) != 0 {
				clear(value)
				t.Fatal("same owner authorized a reference outside the original arguments")
			}
		})
	}
}

func TestOperationSecretRevealRequiresDeclaredCapability(t *testing.T) {
	f := newSecretTestFixture(t, operations.ModeJob, "")
	if value, err := f.revealer.Reveal(t.Context(), f.ref, f.opID, []string{"operation"}); !errors.Is(err, hostsvc.ErrSecretDenied) || len(value) != 0 {
		clear(value)
		t.Fatal("manifest scope alone authorized an undeclared operation capability")
	}
}

// ======================== 创建时快照、公开出口与旧记录 ========================

func TestOperationSecretRevealKeepsAcceptedSchemaAfterCatalogChange(t *testing.T) {
	f := newSecretTestFixture(t, operations.ModeJob, "operation")
	current := f.catalog["alpha/secret.use"]
	expected := bytes.Clone(current.ArgsSchema)
	defer clear(expected)
	clear(current.ArgsSchema)
	current.ArgsSchema = json.RawMessage(`{"type":"object","properties":{"password":{"type":"string"}}}`)
	f.catalog[current.ID] = current
	accepted, err := f.host.Operations.ResolveDispatchedInstance(t.Context(), "alpha", "default", "local", f.opID)
	if err != nil {
		t.Fatal(err)
	}
	defer accepted.Clear()
	schema := accepted.ArgumentSchema()
	defer clear(schema)
	if !bytes.Equal(schema, expected) {
		t.Fatal("current catalog or its mutable buffer replaced the accepted secret schema")
	}
	value, err := f.revealer.Reveal(t.Context(), f.ref, f.opID, []string{"operation"})
	defer clear(value)
	if err != nil || string(value) != `"TEST-ONLY-dispatched-secret"` {
		t.Fatal("catalog schema change altered original operation secret authority")
	}
}

func TestSecretSchemaSnapshotsStayPrivateAndOnlyWhereRequired(t *testing.T) {
	for _, scope := range []string{"operation", "config"} {
		t.Run(scope, func(t *testing.T) {
			f := newSecretTestFixture(t, operations.ModeJob, scope)
			var stored string
			if err := f.host.DB.Reader().QueryRowContext(t.Context(), `SELECT action_meta FROM operations WHERE operation_id = ?`, f.opID).Scan(&stored); err != nil {
				t.Fatal(err)
			}
			var metadata map[string]json.RawMessage
			if err := json.Unmarshal([]byte(stored), &metadata); err != nil {
				t.Fatal(err)
			}
			_, hasSchema := metadata["args_schema"]
			if hasSchema != (scope == "operation") {
				t.Fatal("private schema was lost or persisted for an operation that does not need it")
			}
			op, err := f.host.Operations.Get(t.Context(), f.human, f.opID)
			if err != nil {
				t.Fatal(err)
			}
			for _, public := range []any{op, op.Meta} {
				raw, err := json.Marshal(public)
				if err != nil || bytes.Contains(raw, []byte(`"args_schema"`)) {
					t.Fatal("private stored schema reached a public operation or Action JSON")
				}
			}
		})
	}
}

func TestOperationSecretRevealRejectsLegacyMetadataWithoutSchema(t *testing.T) {
	f := newSecretTestFixture(t, operations.ModeJob, "operation")
	legacy, err := json.Marshal(f.catalog["alpha/secret.use"])
	if err != nil {
		t.Fatal(err)
	}
	if err := f.host.DB.Update(t.Context(), func(tx *storage.Tx) error {
		_, err := tx.ExecContext(t.Context(), `UPDATE operations SET action_meta = ? WHERE operation_id = ?`, string(legacy), f.opID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if value, err := f.revealer.Reveal(t.Context(), f.ref, f.opID, []string{"operation"}); !errors.Is(err, hostsvc.ErrSecretDenied) || len(value) != 0 {
		clear(value)
		t.Fatal("legacy metadata without an accepted schema borrowed authority from the current catalog")
	}
}

func TestConfigSecretScopePreservesRealConfigApplyBoundary(t *testing.T) {
	f := newSecretTestFixture(t, operations.ModeJob, "config")
	var ref secrets.Ref
	if err := f.host.DB.Update(t.Context(), func(tx *storage.Tx) error {
		var err error
		ref, err = f.host.Secrets.Put(t.Context(), tx, "plugins/alpha", "plugin.config", []byte("TEST-ONLY-config-secret"))
		return err
	}); err != nil {
		t.Fatal(err)
	}
	value, err := f.revealer.Reveal(t.Context(), string(ref), f.opID, []string{"config"})
	defer clear(value)
	if err != nil || string(value) != "TEST-ONLY-config-secret" {
		t.Fatal("real config scope lost the existing config purpose")
	}
	if value, err := f.revealer.Reveal(t.Context(), f.ref, f.opID, []string{"config", "operation"}); !errors.Is(err, hostsvc.ErrSecretDenied) || len(value) != 0 {
		clear(value)
		t.Fatal("config declaration authorized operation-purpose material")
	}
}

func TestOperationSecretRevealRechecksCancellationAfterDecryption(t *testing.T) {
	f := newSecretTestFixture(t, operations.ModeJob, "operation")
	cancelled := false
	f.revealer.secrets = revokeAfterReveal{store: f.host.Secrets, revoke: func() error {
		_, err := f.host.Operations.Cancel(t.Context(), operations.CancelRequest{Actor: f.human,
			OperationID: f.opID, Idempotency: operations.Idempotency{Key: f.host.IDs.New(ids.Operation), Method: "POST", Route: "/fixture/secret-cancel"}})
		cancelled = err == nil
		return err
	}}
	if value, err := f.revealer.Reveal(t.Context(), f.ref, f.opID, []string{"operation"}); !errors.Is(err, hostsvc.ErrSecretDenied) || len(value) != 0 {
		clear(value)
		t.Fatal("cancellation during decryption returned plaintext")
	}
	if !cancelled {
		// hook 必须实际执行，不能把前置拒绝算作读中取消验收。
		t.Fatal("secret reveal was denied before the decryption/cancellation boundary was exercised")
	}
}

type revokeAfterReveal struct {
	store  *secrets.Store
	revoke func() error
}

func (r revokeAfterReveal) RevealOwnedAnyPurpose(ctx context.Context, ref secrets.Ref, owner string, purposes ...string) (secrets.Secret, error) {
	value, err := r.store.RevealOwnedAnyPurpose(ctx, ref, owner, purposes...)
	if err == nil {
		if err := r.revoke(); err != nil {
			value.Clear()
			return secrets.Secret{}, err
		}
	}
	return value, err
}

func TestOperationSecretRevealRechecksRoleAfterDecryption(t *testing.T) {
	f := newSecretTestFixture(t, operations.ModeJob, "operation")
	revoked := false
	f.revealer.secrets = revokeAfterReveal{store: f.host.Secrets, revoke: func() error {
		err := f.host.DB.Update(t.Context(), func(tx *storage.Tx) error {
			_, err := tx.ExecContext(t.Context(), `UPDATE users SET role='viewer' WHERE user_id = ?`, f.human.ID)
			return err
		})
		revoked = err == nil
		return err
	}}
	if value, err := f.revealer.Reveal(t.Context(), f.ref, f.opID, []string{"operation"}); !errors.Is(err, hostsvc.ErrSecretDenied) || len(value) != 0 {
		clear(value)
		t.Fatal("role revocation during decryption returned plaintext")
	}
	if !revoked {
		// hook 必须实际执行，不能把前置拒绝算作读中撤权验收。
		t.Fatal("secret reveal was denied before the decryption/role-revocation boundary was exercised")
	}
}
