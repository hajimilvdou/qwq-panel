// SPDX-License-Identifier: AGPL-3.0-only

package operations

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/qwq-panel/qwq/internal/platform/problem"
)

const operationSecretSchema = `{"type":"object","properties":{"password":{"type":"string","x-secret":true},"user":{"type":"string"}},"required":["password"],"additionalProperties":false}`
const operationSecretSentinel = "TEST-ONLY-operation-password-sentinel"

// ======================== 未标记的外部引用也不能穿过 operation/plan ========================

func TestExternalPluginArgumentsCannotEmbedSecretReferences(t *testing.T) {
	for _, action := range []string{actionPlugin, actionRead} {
		t.Run(action, func(t *testing.T) {
			e := newTestEnv(t)
			_, err := e.run(humanActor(), action, nodeTarget(), map[string]any{"nested": []any{map[string]any{"$secret": "sec_00000000000000000000000000"}}})
			if !problem.HasCode(err, problem.ValidationFailed) || e.countOperations() != 0 {
				t.Fatalf("external reference passed an unmarked plugin action: %v", err)
			}
		})
	}
}

type fakeArgumentProtector struct {
	extractions int
	cleanups    int
	owner       string
	purpose     string
}

func (f *fakeArgumentProtector) Fingerprint(scope string, raw []byte) string {
	mac := hmac.New(sha256.New, []byte("TEST-ONLY-fingerprint-key"))
	mac.Write([]byte(scope))
	mac.Write(raw)
	return hex.EncodeToString(mac.Sum(nil))
}

func (f *fakeArgumentProtector) Protect(_ context.Context, _, raw []byte, owner, purpose string) ([]byte, func(context.Context) error, error) {
	f.extractions++
	f.owner, f.purpose = owner, purpose
	var args map[string]any
	if err := json.Unmarshal(raw, &args); err != nil {
		return nil, nil, err
	}
	args["password"] = map[string]any{"$secret": "TEST-ONLY-owned-reference"}
	out, err := json.Marshal(args)
	return out, func(context.Context) error { f.cleanups++; return nil }, err
}

func secretAction(e *testEnv, action string) Target {
	e.setAction(action, func(a *Action) { a.ArgsSchema = json.RawMessage(operationSecretSchema); a.Plannable = true })
	return Target{NodeID: "local", PluginID: pluginID, InstanceID: "default"}
}

func TestOperationSecretsBeforePersistenceAndReplay(t *testing.T) {
	e := newTestEnv(t)
	p := new(fakeArgumentProtector)
	e.svc.argumentProtector = p
	target := secretAction(e, actionPluginH)
	req := RunRequest{Actor: humanActor(), Action: actionPluginH, Target: target, Args: mustJSON(t, map[string]any{"password": operationSecretSentinel}), Idempotency: Idempotency{Key: e.newKey()}}
	req.Idempotency.Fingerprint = "TEST-ONLY-precomputed-request-fingerprint"
	first, err := e.svc.Run(e.ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	if first.Operation == nil || bytes.Contains(first.Operation.Args, []byte(operationSecretSentinel)) {
		t.Fatal("operation retained a plaintext secret")
	}
	if p.owner != "plugins/"+pluginID || p.purpose != "plugin.operation" {
		t.Fatal("secret owner or purpose was not bound by the host")
	}
	replayed, err := e.svc.Run(e.ctx, req)
	if err != nil || !replayed.Replayed || p.extractions != 1 {
		t.Fatalf("replay failed: extractions=%d err=%v", p.extractions, err)
	}
	changed := req
	changed.Args = mustJSON(t, map[string]any{"password": operationSecretSentinel + "-changed"})
	_, err = e.svc.Run(e.ctx, changed)
	if problem.From(err).Code != problem.IdempotencyKeyReused || p.extractions != 1 {
		t.Fatal("changed secret reused the idempotency key")
	}
	for _, query := range []string{"SELECT args FROM operations", "SELECT response_body FROM idempotency_keys", "SELECT details FROM audit_log", "SELECT payload FROM event_journal"} {
		rows, err := e.db.Reader().QueryContext(e.ctx, query)
		if err != nil {
			t.Fatal(err)
		}
		for rows.Next() {
			var raw []byte
			if err := rows.Scan(&raw); err != nil {
				rows.Close()
				t.Fatal(err)
			}
			if bytes.Contains(raw, []byte(operationSecretSentinel)) {
				rows.Close()
				t.Fatal("persistent public record retained a plaintext secret")
			}
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			t.Fatal(err)
		}
		rows.Close()
	}
}

func TestPlanSecretsBeforePreviewAndPersistence(t *testing.T) {
	e := newTestEnv(t)
	p := new(fakeArgumentProtector)
	e.svc.argumentProtector = p
	target := secretAction(e, actionPluginH)
	e.dispatcher.planFn = func(_ context.Context, req PluginPlanRequest) (Preview, error) {
		if bytes.Contains(req.Payload, []byte(operationSecretSentinel)) {
			t.Error("preview received plaintext")
		}
		return Preview{}, nil
	}
	plan, err := e.svc.CreatePlan(e.ctx, PlanRequest{Actor: humanActor(), Action: actionPluginH, Target: target, Args: mustJSON(t, map[string]any{"password": operationSecretSentinel})})
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(plan.Args, []byte(operationSecretSentinel)) || !bytes.Contains(plan.Args, []byte("$secret")) {
		t.Fatal("plan did not persist only the secret reference")
	}
	var stored []byte
	if err := e.db.Reader().QueryRowContext(e.ctx, "SELECT args FROM plans WHERE plan_id = ?", plan.ID).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(stored, []byte(operationSecretSentinel)) {
		t.Fatal("plan database retained plaintext")
	}
	if p.cleanups != 0 || p.extractions != 1 {
		t.Fatal("a persisted plan lost its secret")
	}
}

func TestOperationSecretsFailClosedAndCleanup(t *testing.T) {
	t.Run("read rejects new material", func(t *testing.T) {
		e := newTestEnv(t)
		p := new(fakeArgumentProtector)
		e.svc.argumentProtector = p
		target := secretAction(e, actionRead)
		_, err := e.run(humanActor(), actionRead, target, map[string]any{"password": operationSecretSentinel})
		if problem.From(err).Code != problem.ValidationFailed || p.extractions != 0 {
			t.Fatal("read action accepted new secret material")
		}
	})
	t.Run("missing protector", func(t *testing.T) {
		e := newTestEnv(t)
		target := secretAction(e, actionPluginH)
		_, err := e.run(humanActor(), actionPluginH, target, map[string]any{"password": operationSecretSentinel})
		if problem.From(err).Code != problem.Unavailable {
			t.Fatal("plaintext was accepted without a protector")
		}
	})
	t.Run("failed preview", func(t *testing.T) {
		e := newTestEnv(t)
		p := new(fakeArgumentProtector)
		e.svc.argumentProtector = p
		target := secretAction(e, actionPluginH)
		e.dispatcher.planFn = func(context.Context, PluginPlanRequest) (Preview, error) {
			return Preview{}, errors.New("TEST-ONLY-preview-failure")
		}
		_, err := e.svc.CreatePlan(e.ctx, PlanRequest{Actor: humanActor(), Action: actionPluginH, Target: target, Args: mustJSON(t, map[string]any{"password": operationSecretSentinel})})
		if err == nil || p.cleanups != 1 {
			t.Fatalf("unpersisted secret cleanup failed: %v", err)
		}
	})
	t.Run("invalid arguments", func(t *testing.T) {
		e := newTestEnv(t)
		p := new(fakeArgumentProtector)
		e.svc.argumentProtector = p
		target := secretAction(e, actionPluginH)
		_, err := e.run(humanActor(), actionPluginH, target, map[string]any{"password": operationSecretSentinel, "unexpected": true})
		if err == nil || p.extractions != 0 {
			t.Fatal("invalid arguments created secrets")
		}
		if strings.Contains(err.Error(), operationSecretSentinel) {
			t.Fatal("validation error disclosed a secret")
		}
	})
}
