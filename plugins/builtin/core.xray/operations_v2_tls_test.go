// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/qwq-panel/qwq/internal/prerequisites/certificates"
	"github.com/qwq-panel/qwq/internal/prerequisites/consumerfiles"
	"github.com/qwq-panel/qwq/internal/secrets"
	"github.com/qwq-panel/qwq/internal/tlsmgr"
	"github.com/qwq-panel/qwq/plugins/builtin/core.xray/internal/apply"
	"github.com/qwq-panel/qwq/plugins/builtin/core.xray/internal/state"
	corev2 "github.com/qwq-panel/qwq/sdk/coreapi/v2"
	pb "github.com/qwq-panel/qwq/sdk/gen/qwq/platform/v1"
	"github.com/qwq-panel/qwq/sdk/pluginsdk"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// ======================== Core Intent v2 Schema 与秘密提取验证 ========================

func TestConfigSchemaV2SecretExtraction(t *testing.T) {
	schemaBytes, err := os.ReadFile(filepath.Join("schemas", "config.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	v2Plain := []byte(`{
		"schema_version": "2",
		"enabled": true,
		"profiles": [
			{
				"id": "h2-edge",
				"enabled": true,
				"listen": "127.0.0.1",
				"port": 18443,
				"protocol": "hysteria2",
				"users": [{"id": "alice", "auth": "hy2-auth-secret-value-0001"}],
				"hysteria2": {"tls": {"binding_ref": "bind-h2-01", "server_name": "h2.example.test"}}
			},
			{
				"id": "ss-edge",
				"enabled": true,
				"listen": "127.0.0.1",
				"port": 18388,
				"protocol": "shadowsocks2022",
				"users": [{"id": "bob", "psk": "AAAAAAAAAAAAAAAAAAAAAA=="}],
				"shadowsocks2022": {
					"method": "2022-blake3-aes-128-gcm",
					"server_key": "BBBBBBBBBBBBBBBBBBBBBB==",
					"obfs": {"mode": "none"}
				}
			}
		],
		"outbound": {"type": "direct"}
	}`)

	var seen map[string]any
	if err := secrets.ValidateWithSecretReferences(schemaBytes, v2Plain, func(preview []byte) error {
		return json.Unmarshal(preview, &seen)
	}); err != nil {
		t.Fatalf("v2 config schema 秘密预览提取失败：%v", err)
	}
	rawPreview, err := json.Marshal(seen)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(rawPreview), "hy2-auth-secret-value-0001") ||
		strings.Contains(string(rawPreview), "AAAAAAAAAAAAAAAAAAAAAA==") ||
		strings.Contains(string(rawPreview), "BBBBBBBBBBBBBBBBBBBBBB==") {
		t.Fatalf("v2 schema 未替换全部敏感字段：%s", string(rawPreview))
	}
	if !strings.Contains(string(rawPreview), `"$secret"`) {
		t.Fatalf("v2 schema 预览未生成 $secret 引用：%s", string(rawPreview))
	}
}

// ======================== Hysteria2 v2 Apply + consumerfiles + tls.reload/inspect 闭环 ========================

type v2TestHost struct {
	*fakeApplyHost
	secrets map[string][]byte
}

func (h *v2TestHost) RevealSecret(_ context.Context, reference, purpose string) ([]byte, error) {
	if purpose != "core.xray.apply" {
		return nil, errors.New("unexpected purpose")
	}
	val, ok := h.secrets[reference]
	if !ok {
		return nil, errors.New("secret not found")
	}
	cp := append([]byte(nil), val...)
	h.revealed = append(h.revealed, cp)
	return cp, nil
}

type v2FakeConn struct{ host *v2TestHost }

func (c *v2FakeConn) Invoke(ctx context.Context, method string, input, output any, _ ...grpc.CallOption) error {
	switch method {
	case pb.HostConfigService_GetConfig_FullMethodName:
		req := input.(*pb.GetConfigRequest)
		data, rev, err := c.host.GetConfig(ctx, req.GetRevision())
		resp := output.(*pb.GetConfigResponse)
		resp.ConfigJson, resp.Revision = data, rev
		return err
	case pb.HostSecretsService_RevealSecret_FullMethodName:
		req := input.(*pb.RevealSecretRequest)
		val, err := c.host.RevealSecret(ctx, req.GetSecretRef(), req.GetPurpose())
		output.(*pb.RevealSecretResponse).Value = val
		return err
	case pb.HostStateService_GetState_FullMethodName:
		req := input.(*pb.GetStateRequest)
		data, rev, found, err := c.host.GetState(ctx, req.GetKey())
		resp := output.(*pb.GetStateResponse)
		resp.ValueJson, resp.Revision, resp.Found = data, rev, found
		return err
	case pb.HostStateService_PutState_FullMethodName:
		req := input.(*pb.PutStateRequest)
		rev, err := c.host.PutState(ctx, req.GetKey(), req.GetValueJson(), pluginsdk.PutOption{
			MustNotExist:     req.GetMustNotExist(),
			ExpectedRevision: req.GetExpectedRevision(),
		})
		output.(*pb.PutStateResponse).Revision = rev
		return err
	case pb.HostStateService_DeleteState_FullMethodName:
		req := input.(*pb.DeleteStateRequest)
		return c.host.DeleteState(ctx, req.GetKey(), req.GetExpectedRevision())
	case pb.HostEventsService_ReportChanges_FullMethodName:
		return c.host.ReportChanges(ctx)
	}
	return status.Error(codes.Unimplemented, "unsupported RPC")
}

func (*v2FakeConn) NewStream(context.Context, *grpc.StreamDesc, string, ...grpc.CallOption) (grpc.ClientStream, error) {
	return nil, errors.New("no stream")
}

func reserveFreeUDPPort(t *testing.T) int {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := pc.LocalAddr().(*net.UDPAddr).Port
	_ = pc.Close()
	if port < 1024 {
		t.Skip("ephemeral port below 1024")
	}
	return port
}

func stageAndActivateConsumerCert(t *testing.T, dataDir string, now time.Time, binding certificates.HostBinding) (consumerfiles.Proof, string) {
	t.Helper()
	mat, err := tlsmgr.GenerateTestMaterial(now, []string{binding.Consumer.SNI})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(mat.Clear)

	meta, err := tlsmgr.ValidateMaterial(mat, tlsmgr.MaterialOptions{
		SANs:    []string{binding.Consumer.SNI},
		Now:     now,
		Purpose: tlsmgr.TestServerTLS,
		Trust:   tlsmgr.TestTrust,
	})
	if err != nil {
		t.Fatal(err)
	}

	root, err := os.OpenRoot(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	store, err := consumerfiles.New(root)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	prev, err := store.Current(t.Context(), binding.ID)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := store.Stage(t.Context(), binding, mat)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Activate(t.Context(), prev, proof); err != nil {
		t.Fatal(err)
	}
	return proof, strings.ToLower(strings.ReplaceAll(strings.TrimSpace(meta.Fingerprint), ":", ""))
}

type v2TestBinary struct{ err error }

func (b *v2TestBinary) Preflight(context.Context, string) error { return b.err }

func TestCoreV2Hysteria2ApplyInspectReloadAndRollback(t *testing.T) {
	now := time.Date(2026, 11, 21, 14, 0, 0, 0, time.UTC)
	dataDir, err := os.MkdirTemp("", "core-xray-v2-tls-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dataDir) })
	if err := os.Chmod(dataDir, 0o700); err != nil {
		t.Fatal(err)
	}

	const (
		bindingRef = "bind-h2-first"
		profileID  = "h2-first"
		sni        = "h2.example.test"
	)
	consumer := certificates.Consumer{
		PluginID:  "core.xray",
		ProfileID: profileID,
		NodeID:    "local",
		SNI:       sni,
		Purpose:   "proxy.hysteria2",
	}
	bindingG1 := certificates.HostBinding{
		ID:             bindingRef,
		CertificateID:  "cert-h2",
		Generation:     1,
		PolicyRevision: "policy-rev-1",
		Consumer:       consumer,
	}
	proof1, fp1 := stageAndActivateConsumerCert(t, dataDir, now, bindingG1)

	udpPort := reserveFreeUDPPort(t)
	enabled := true
	profileEnabled := true
	authRef := corev2.SecretRef{ID: "sec_00000000000000000000000022"}
	intentV2 := &corev2.Intent{
		SchemaVersion: "2",
		Enabled:       &enabled,
		Profiles: []corev2.Profile{{
			ID:       profileID,
			Enabled:  &profileEnabled,
			Listen:   "127.0.0.1",
			Port:     udpPort,
			Protocol: corev2.ProtocolHysteria2,
			Users:    []corev2.User{{ID: "alice", Auth: &authRef}},
			Hysteria2: &corev2.Hysteria2{
				TLS: &corev2.TLSBinding{BindingRef: bindingRef, ServerName: sni},
			},
		}},
		Outbound: &corev2.Outbound{Type: "direct"},
	}
	intentBytes, err := json.Marshal(intentV2)
	if err != nil {
		t.Fatal(err)
	}

	host := &v2TestHost{
		fakeApplyHost: &fakeApplyHost{config: intentBytes, revision: "1"},
		secrets: map[string][]byte{
			authRef.ID: []byte(`"hysteria2-strong-auth-secret-01"`),
		},
	}
	store := state.NewStore(dataDir)
	proc := &fakeApplyProcess{}
	bin := &v2TestBinary{}
	engine, err := apply.New(apply.Options{
		Store:                  store,
		Process:                proc,
		Binary:                 bin,
		Socket:                 filepath.Join(dataDir, "runtime", "api.sock"),
		DataDir:                dataDir,
		PermitTestCertificates: true,
		Now:                    func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}

	plugin := &Plugin{driverFactory: func(*instance) (*driverRuntime, error) {
		return &driverRuntime{store: store, process: proc, controller: engine, coreVersion: state.CoreVersion, trusted: true}, nil
	}}
	srv, _ := newPluginServer(t, plugin, intentBytes, &v2FakeConn{host: host}, dataDir)

	// 1. v2 Plan 不应揭示任何秘密。
	planResp, err := srv.PlanOperation(t.Context(), &pb.PlanOperationRequest{
		Context: testContext(), Operation: "core.apply", ApiVersion: "v2", PayloadJson: []byte(`{"config_revision":"1"}`),
	})
	if err != nil || planResp.GetError() != nil || len(planResp.GetChanges()) == 0 || len(host.revealed) != 0 {
		t.Fatalf("v2 Plan 失败或意外揭示秘密：err=%v perr=%v revealed=%d", err, planResp.GetError(), len(host.revealed))
	}

	// 2. v2 core.apply 读取 consumerfiles 渲染 Hysteria2 TLS 1.3 (h3) 配置并启动。
	term := runSDKApply(t, srv, "1")
	if term.GetError() != nil {
		t.Fatalf("v2 core.apply 失败：%s", term.GetError().GetCode())
	}
	var applyRes apply.Result
	if err := json.Unmarshal(term.GetResultJson(), &applyRes); err != nil || !applyRes.Enabled || applyRes.RunningRevision != "1" {
		t.Fatalf("v2 apply 结果不符：%s err=%v", string(term.GetResultJson()), err)
	}

	// 3. tls.inspect 诚实报告 Generation 1、指纹与监听端点。
	inspectPayload, _ := json.Marshal(map[string]string{"binding_ref": bindingRef, "profile_id": profileID})
	inspectResp, err := srv.Invoke(t.Context(), &pb.InvokeRequest{
		Context: testContext(), Operation: "tls.inspect", ApiVersion: "v2", PayloadJson: inspectPayload, Attempt: 1,
	})
	if err != nil || inspectResp.GetError() != nil {
		t.Fatalf("tls.inspect 失败：err=%v perr=%v", err, inspectResp.GetError())
	}
	var st1 apply.TLSBindingStatus
	if err := json.Unmarshal(inspectResp.GetPayloadJson(), &st1); err != nil {
		t.Fatal(err)
	}
	if !st1.Running || st1.Generation != 1 || st1.LeafFingerprint != fp1 || st1.SNI != sni || st1.FullchainSHA256 != proof1.FullchainSHA256 || !strings.HasPrefix(st1.Endpoint, "127.0.0.1:") {
		t.Fatalf("tls.inspect G1 状态不符：%+v (want fp=%s)", st1, fp1)
	}

	// 4. 轮换至 Generation 2 并通过无 PEM 的 tls.reload 热切换。
	bindingG2 := bindingG1
	bindingG2.Generation = 2
	bindingG2.PolicyRevision = "policy-rev-2"
	proof2, fp2 := stageAndActivateConsumerCert(t, dataDir, now.Add(time.Minute), bindingG2)
	if fp2 == fp1 {
		t.Fatal("新旧证书叶指纹不应相同")
	}

	reloadPayload, _ := json.Marshal(map[string]any{
		"binding_ref":        bindingRef,
		"profile_id":         profileID,
		"generation":         2,
		"policy_revision":    "policy-rev-2",
		"fullchain_sha256":   proof2.FullchainSHA256,
		"private_key_sha256": proof2.PrivateKeySHA256,
		"sni":                sni,
	})
	reloadResp, err := srv.Invoke(t.Context(), &pb.InvokeRequest{
		Context: testContext(), Operation: "tls.reload", ApiVersion: "v2", PayloadJson: reloadPayload, Attempt: 1,
	})
	if err != nil || reloadResp.GetError() != nil {
		t.Fatalf("tls.reload G2 失败：err=%v perr=%v", err, reloadResp.GetError())
	}
	var st2 apply.TLSBindingStatus
	if err := json.Unmarshal(reloadResp.GetPayloadJson(), &st2); err != nil {
		t.Fatal(err)
	}
	if !st2.Running || st2.Generation != 2 || st2.LeafFingerprint != fp2 || st2.FullchainSHA256 != proof2.FullchainSHA256 {
		t.Fatalf("tls.reload G2 返回状态不符：%+v (want fp=%s)", st2, fp2)
	}

	// 5. 摘要篡改与未知字段必须严格拒绝。
	badReload, _ := json.Marshal(map[string]any{
		"binding_ref":        bindingRef,
		"profile_id":         profileID,
		"generation":         2,
		"policy_revision":    "policy-rev-2",
		"fullchain_sha256":   strings.Repeat("0", 64),
		"private_key_sha256": proof2.PrivateKeySHA256,
		"sni":                sni,
	})
	badResp, err := srv.Invoke(t.Context(), &pb.InvokeRequest{
		Context: testContext(), Operation: "tls.reload", ApiVersion: "v2", PayloadJson: badReload, Attempt: 1,
	})
	if err != nil || badResp.GetError() == nil || badResp.GetError().GetCode() != "TLS_PROOF_MISMATCH" {
		t.Fatalf("篡改摘要应返回 TLS_PROOF_MISMATCH：err=%v perr=%v", err, badResp.GetError())
	}

	// 6. Generation 3 预检失败必须自动回滚，保持 Generation 2 运行态不变。
	bindingG3 := bindingG1
	bindingG3.Generation = 3
	bindingG3.PolicyRevision = "policy-rev-3"
	proof3, _ := stageAndActivateConsumerCert(t, dataDir, now.Add(2*time.Minute), bindingG3)
	bin.err = errors.New("simulated xray preflight reject")
	reloadG3, _ := json.Marshal(map[string]any{
		"binding_ref":        bindingRef,
		"profile_id":         profileID,
		"generation":         3,
		"policy_revision":    "policy-rev-3",
		"fullchain_sha256":   proof3.FullchainSHA256,
		"private_key_sha256": proof3.PrivateKeySHA256,
		"sni":                sni,
	})
	failResp, err := srv.Invoke(t.Context(), &pb.InvokeRequest{
		Context: testContext(), Operation: "tls.reload", ApiVersion: "v2", PayloadJson: reloadG3, Attempt: 1,
	})
	bin.err = nil
	if err != nil || failResp.GetError() == nil || failResp.GetError().GetCode() != "CORE_CONFIG_INVALID" {
		t.Fatalf("预检失败应拒绝并保留旧代际：err=%v perr=%v", err, failResp.GetError())
	}
	inspectAfter, err := srv.Invoke(t.Context(), &pb.InvokeRequest{
		Context: testContext(), Operation: "tls.inspect", ApiVersion: "v2", PayloadJson: inspectPayload, Attempt: 1,
	})
	if err != nil || inspectAfter.GetError() != nil {
		t.Fatalf("回滚后 tls.inspect 失败：err=%v perr=%v", err, inspectAfter.GetError())
	}
	var stAfter apply.TLSBindingStatus
	if err := json.Unmarshal(inspectAfter.GetPayloadJson(), &stAfter); err != nil {
		t.Fatal(err)
	}
	if !stAfter.Running || stAfter.Generation != 2 || stAfter.LeafFingerprint != fp2 {
		t.Fatalf("预检失败后应维持 Generation 2 运行态：%+v", stAfter)
	}
}
