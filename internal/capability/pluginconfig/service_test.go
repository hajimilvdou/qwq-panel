// SPDX-License-Identifier: AGPL-3.0-only

package pluginconfig

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/qwq-panel/qwq/internal/pluginhost/hostsvc"
	pluginconfigv1 "github.com/qwq-panel/qwq/sdk/gen/qwq/capability/pluginconfig/v1"
)

type fakeBackend struct {
	cfg       []byte
	rev       string
	lastPut   []byte
	lastApply bool
	nextRev   string
	applyOpID string
}

func (b *fakeBackend) GetPluginConfig(_ context.Context, _ string) ([]byte, string, error) {
	return append([]byte(nil), b.cfg...), b.rev, nil
}

func (b *fakeBackend) PutPluginConfig(_ context.Context, _ string, configJSON []byte, _ string, triggerApply bool) (string, string, error) {
	b.lastPut = append([]byte(nil), configJSON...)
	b.lastApply = triggerApply
	b.cfg = append([]byte(nil), configJSON...)
	b.rev = b.nextRev
	return b.nextRev, b.applyOpID, nil
}

func TestPluginConfigRedactionKeepSecretAndForgeryRejection(t *testing.T) {
	existing := []byte(`{
		"schema_version": "2",
		"profiles": [{
			"id": "vless-main",
			"vless": {"security": {"private_key": {"$secret": "sec_00000000000000000000000001"}}},
			"users": [
				{"id": "alice", "uuid": {"$secret": "sec_00000000000000000000000002"}}
			]
		}]
	}`)
	backend := &fakeBackend{cfg: existing, rev: "rev-1", nextRev: "rev-2", applyOpID: "op-apply-2"}
	fwd := Forwarder{Backend: backend}

	// 1. GetConfig 必须脱敏全部真实 sec_ 引用
	res, err := fwd.Forward(t.Context(), hostsvc.CapabilityCall{
		Service: "pluginconfig",
		Method:  "GetConfig",
		Request: &pluginconfigv1.GetConfigRequest{TargetPluginId: "core.xray"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Error != nil {
		t.Fatalf("unexpected domain error: %+v", res.Error)
	}
	getResp := res.Response.(*pluginconfigv1.GetConfigResponse)
	if getResp.GetRevision() != "rev-1" {
		t.Fatalf("unexpected revision: %q", getResp.GetRevision())
	}
	redactedStr := string(getResp.GetRedactedConfigJson())
	if strings.Contains(redactedStr, "sec_00000000000000000000000001") || strings.Contains(redactedStr, "sec_00000000000000000000000002") {
		t.Fatalf("real secret IDs leaked: %s", redactedStr)
	}
	if !strings.Contains(redactedStr, `"$secret_present":true`) {
		t.Fatalf("expected $secret_present marker: %s", redactedStr)
	}

	// 2. PutConfig 用 $keep_secret 保留 alice 与 private_key，并新增 bob 明文 UUID
	proposed := []byte(`{
		"schema_version": "2",
		"profiles": [{
			"id": "vless-main",
			"vless": {"security": {"private_key": {"$keep_secret": true}}},
			"users": [
				{"id": "bob", "uuid": "22222222-3333-4444-5555-666666666666"},
				{"id": "alice", "uuid": {"$keep_secret": true}}
			]
		}]
	}`)
	putRes, err := fwd.Forward(t.Context(), hostsvc.CapabilityCall{
		Service: "pluginconfig",
		Method:  "PutConfig",
		Request: &pluginconfigv1.PutConfigRequest{
			TargetPluginId:   "core.xray",
			ConfigJson:       proposed,
			ExpectedRevision: "rev-1",
			TriggerApply:     true,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if putRes.Error != nil {
		t.Fatalf("unexpected PutConfig domain error: %+v", putRes.Error)
	}
	putResp := putRes.Response.(*pluginconfigv1.PutConfigResponse)
	if putResp.GetRevision() != "rev-2" || putResp.GetApplyOperationId() != "op-apply-2" || !backend.lastApply {
		t.Fatalf("unexpected PutConfig response: %+v", putResp)
	}
	mergedStr := string(backend.lastPut)
	if !strings.Contains(mergedStr, "sec_00000000000000000000000001") || !strings.Contains(mergedStr, "sec_00000000000000000000000002") {
		t.Fatalf("$keep_secret failed to inherit existing refs by id: %s", mergedStr)
	}
	if !strings.Contains(mergedStr, "22222222-3333-4444-5555-666666666666") {
		t.Fatalf("new user plaintext uuid missing: %s", mergedStr)
	}

	// 3. 伪造陌生 $secret 引用必须被拒绝
	forged := []byte(`{
		"schema_version": "2",
		"profiles": [{
			"id": "vless-main",
			"vless": {"security": {"private_key": {"$secret": "sec_ffffffffffffffffffffffffff"}}},
			"users": []
		}]
	}`)
	if _, err := MergeKeptSecrets(existing, forged); err == nil {
		t.Fatal("expected forged $secret reference to be rejected")
	}

	// 4. 乐观并发版本冲突必须返回 PRECONDITION_FAILED
	conflictRes, err := fwd.Forward(t.Context(), hostsvc.CapabilityCall{
		Service: "pluginconfig",
		Method:  "PutConfig",
		Request: &pluginconfigv1.PutConfigRequest{
			TargetPluginId:   "core.xray",
			ConfigJson:       proposed,
			ExpectedRevision: "rev-1",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if conflictRes.Error == nil || conflictRes.Error.Code != "PRECONDITION_FAILED" {
		t.Fatalf("expected PRECONDITION_FAILED on revision mismatch, got %+v", conflictRes.Error)
	}

	var checkValid map[string]any
	if err := json.Unmarshal(backend.lastPut, &checkValid); err != nil {
		t.Fatalf("merged output is not valid JSON: %v", err)
	}
}
