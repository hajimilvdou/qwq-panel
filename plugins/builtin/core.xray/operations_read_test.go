// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/qwq-panel/qwq/plugins/builtin/core.xray/internal/state"
	pb "github.com/qwq-panel/qwq/sdk/gen/qwq/platform/v1"
	"github.com/qwq-panel/qwq/sdk/pluginsdk"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

// fakeRuntimeSource 只验证驱动状态组合，不代表 Xray 真机证据。
type fakeRuntimeSource struct {
	mu       sync.Mutex
	snapshot runtimeSnapshot
	err      error
}

func (f *fakeRuntimeSource) Snapshot(ctx context.Context) (runtimeSnapshot, error) {
	if err := ctx.Err(); err != nil {
		return runtimeSnapshot{}, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.snapshot, f.err
}

func fakeReadServer(t *testing.T, source *fakeRuntimeSource, config []byte) (*pluginsdk.Server, string) {
	t.Helper()
	return pluginServer(t, &Plugin{runtimeFactory: func(string) runtimeSource { return source }}, config)
}

func readInvoke(t *testing.T, srv *pluginsdk.Server, name, payload string) *pb.InvokeResponse {
	t.Helper()
	response, err := srv.Invoke(t.Context(), &pb.InvokeRequest{
		Context: testContext(), Operation: name, ApiVersion: "v1", PayloadJson: []byte(payload), Attempt: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if response.GetError() == nil {
		assertResponseSchema(t, name, response.GetPayloadJson())
	}
	return response
}

func assertResponseSchema(t *testing.T, name string, responsePayload []byte) {
	t.Helper()
	schemaData, err := os.ReadFile("schemas/" + name + ".response.json")
	if err != nil {
		t.Fatal(err)
	}
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(schemaData))
	if err != nil {
		t.Fatal(err)
	}
	compiler := jsonschema.NewCompiler()
	id := "urn:qwq:plugin:core.xray:" + name + ":response:v1"
	if err := compiler.AddResource(id, doc); err != nil {
		t.Fatal(err)
	}
	schema, err := compiler.Compile(id)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := jsonschema.UnmarshalJSON(bytes.NewReader(responsePayload))
	if err != nil {
		t.Fatal(err)
	}
	if err := schema.Validate(payload); err != nil {
		t.Fatalf("%s response violated the public schema: %v", name, err)
	}
}

func decodeReadResult[T any](t *testing.T, response *pb.InvokeResponse) T {
	t.Helper()
	if response.GetError() != nil {
		t.Fatalf("read operation failed: %s", response.GetError().GetCode())
	}
	var result T
	if err := json.Unmarshal(response.GetPayloadJson(), &result); err != nil {
		t.Fatal(err)
	}
	return result
}

func fakeRunningSnapshot() runtimeSnapshot {
	return runtimeSnapshot{coreVersion: "26.11.9", processState: "RUNNING", apiState: "READY",
		metadata: &state.Metadata{SchemaVersion: "1", State: "RUNNING", ResetEpoch: "fake-epoch",
			Current: &state.Generation{Digest: "sha256:" + strings.Repeat("a", 64), Revision: "1", Version: "26.11.9", Enabled: true}}}
}

// ======================== fake 状态与真实 SDK 派发 ========================
func TestFakeReadStatusDesiredRevisionAndAPIHealth(t *testing.T) {
	source := &fakeRuntimeSource{snapshot: fakeRunningSnapshot()}
	srv, _ := fakeReadServer(t, source, testIntent(t))
	current := decodeReadResult[statusResult](t, readInvoke(t, srv, "core.status", `{}`))
	if current.State != "RUNNING" || !current.ProxyAvailable || current.RunningRevision != "1" {
		t.Fatal("fake healthy core was not recognized")
	}
	if _, err := srv.ApplyConfig(t.Context(), &pb.ApplyConfigRequest{Context: testContext(), ConfigJson: testIntent(t), ProposedRevision: "2"}); err != nil {
		t.Fatal(err)
	}
	pending := decodeReadResult[statusResult](t, readInvoke(t, srv, "core.status", `{}`))
	if pending.State != "PENDING_APPLY" || pending.DesiredRevision != "2" || pending.RunningRevision != "1" || !pending.ProxyAvailable {
		t.Fatal("desired change hid the still-running old revision")
	}
	source.mu.Lock()
	source.snapshot.apiState = "UNAVAILABLE"
	source.mu.Unlock()
	degraded := decodeReadResult[statusResult](t, readInvoke(t, srv, "core.status", `{}`))
	if degraded.State != "DEGRADED" || degraded.ProxyAvailable || degraded.ProcessState != "RUNNING" || degraded.LastError != "CORE_API_UNAVAILABLE" {
		t.Fatal("live process hid a failed API")
	}
	health, err := srv.CheckHealth(t.Context(), &pb.CheckHealthRequest{Context: testContext()})
	if err != nil || !strings.Contains(string(health.GetDetailsJson()), `"state":"DEGRADED"`) || strings.Contains(string(health.GetDetailsJson()), `"proxy_available":true`) {
		t.Fatal("Health disagreed with Status")
	}
}

func TestFakeReadUnconfiguredAndCorruptSnapshot(t *testing.T) {
	source := &fakeRuntimeSource{snapshot: runtimeSnapshot{processState: "STOPPED", apiState: "UNAVAILABLE"}}
	srv, dataDir := fakeReadServer(t, source, nil)
	unconfigured := decodeReadResult[statusResult](t, readInvoke(t, srv, "core.status", `{}`))
	if unconfigured.State != "UNCONFIGURED" || unconfigured.ProxyAvailable || unconfigured.RunningRevision != "" {
		t.Fatal("unconfigured driver advertised a core")
	}
	validated := decodeReadResult[validateResult](t, readInvoke(t, srv, "core.validate", `{}`))
	if validated.Valid || len(validated.Violations) == 0 || validated.NativePreflightPerformed {
		t.Fatal("unconfigured intent was reported as valid")
	}
	if _, err := os.Stat(dataDir); !os.IsNotExist(err) {
		t.Fatal("read created runtime files")
	}
	source.mu.Lock()
	source.err = state.ErrCorrupt
	source.mu.Unlock()
	corrupt := readInvoke(t, srv, "core.status", `{}`)
	if corrupt.GetError().GetCode() != "SNAPSHOT_CORRUPT" || len(corrupt.GetPayloadJson()) != 0 {
		t.Fatal("corrupt state did not fail closed")
	}
	health, err := srv.CheckHealth(t.Context(), &pb.CheckHealthRequest{Context: testContext()})
	if err != nil || !strings.Contains(string(health.GetDetailsJson()), "SNAPSHOT_CORRUPT") {
		t.Fatal("Health hid a corrupt snapshot")
	}
}

func TestFakeReadFailedAndDisabledStateCannotAdvertiseAvailability(t *testing.T) {
	for _, condition := range []string{"process-stopped", "committed-failed", "disabled"} {
		t.Run(condition, func(t *testing.T) {
			snapshot := fakeRunningSnapshot()
			want := "FAILED"
			config := testIntent(t)
			switch condition {
			case "process-stopped":
				snapshot.processState = "STOPPED"
			case "committed-failed":
				snapshot.metadata.State, snapshot.metadata.LastError = "FAILED", "RECOVERY_FAILED"
			case "disabled":
				snapshot.metadata.State, snapshot.metadata.Current.Enabled = "STOPPED", false
				snapshot.processState, snapshot.apiState = "STOPPED", "UNAVAILABLE"
				config = bytes.Replace(config, []byte(`"enabled":true`), []byte(`"enabled":false`), 1)
				want = "STOPPED"
			}
			srv, _ := fakeReadServer(t, &fakeRuntimeSource{snapshot: snapshot}, config)
			result := decodeReadResult[statusResult](t, readInvoke(t, srv, "core.status", `{}`))
			if result.State != want || result.ProxyAvailable {
				t.Fatal("failed/disabled core advertised availability")
			}
		})
	}
}

func TestFakeReadValidateAndCapabilitiesDoNotRevealSecrets(t *testing.T) {
	source := &fakeRuntimeSource{snapshot: fakeRunningSnapshot()}
	srv, _ := fakeReadServer(t, source, testIntent(t))
	validated := decodeReadResult[validateResult](t, readInvoke(t, srv, "core.validate", `{}`))
	if !validated.Valid || validated.ConfigRevision != "1" || validated.NativePreflightPerformed || len(validated.Warnings) == 0 {
		t.Fatal("pure validation claimed a native preflight")
	}
	if response := readInvoke(t, srv, "core.validate", `{"config_revision":"2"}`); response.GetError().GetCode() != "CONFIG_REVISION_NOT_FOUND" {
		t.Fatal("missing historical revision was guessed")
	}
	capabilities := decodeReadResult[capabilitiesResult](t, readInvoke(t, srv, "core.capabilities", `{}`))
	if capabilities.CoreVersion != "26.11.9" || capabilities.DriverVersion != "0.1.0" || capabilities.SchemaVersion != "2" {
		t.Fatal("capabilities omitted locked versions")
	}
	for _, verified := range capabilities.Verified {
		if verified == "connection_forwarding" || verified == "per_user_mark" {
			t.Fatal("unverified capability was advertised")
		}
	}
	for _, operation := range []string{"core.status", "core.validate", "core.capabilities"} {
		response := readInvoke(t, srv, operation, `{}`)
		for _, forbidden := range []string{"sec_", "private_key", "uuid", "config.json", "api.sock", "-config", "QWQ_"} {
			if strings.Contains(string(response.GetPayloadJson()), forbidden) {
				t.Fatal("read response exposed private configuration")
			}
		}
	}
}

func TestFakeReadRejectsUnknownDuplicateNullAndInvalidRevision(t *testing.T) {
	srv, _ := fakeReadServer(t, &fakeRuntimeSource{}, testIntent(t))
	for _, payload := range []string{`null`, `[]`, `{"config_revision":null}`, `{"config_revision":1}`, `{"config_revision":"01"}`, `{"config_revision":"0"}`, `{"config_revision":"9223372036854775808"}`, `{"config_revision":"1","config_revision":"1"}`, `{"native":{}}`, `{} {}`} {
		if response := readInvoke(t, srv, "core.validate", payload); response.GetError().GetCode() != "INVALID_REQUEST" {
			t.Fatal("invalid request was accepted")
		}
	}
	for _, operation := range []string{"core.status", "core.capabilities"} {
		if response := readInvoke(t, srv, operation, `{"config_revision":"1"}`); response.GetError().GetCode() != "INVALID_REQUEST" {
			t.Fatal("field outside the operation schema was accepted")
		}
	}
}
