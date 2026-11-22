// SPDX-License-Identifier: AGPL-3.0-only

package sandbox

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"
)

// ======================== 消费者证书协议回归：精确字段、边界、大小限制与脱敏 ========================

func consumerCertTestBinding(pluginID, bindingID string, generation uint64) ConsumerCertBinding {
	return ConsumerCertBinding{
		ID:            bindingID,
		CertificateID: "cert-01",
		Generation:    generation,
		Consumer: ConsumerCertConsumer{
			PluginID:  pluginID,
			ProfileID: "profile-main",
			NodeID:    "node-a1",
			SNI:       "edge.example.com",
			Purpose:   "tls-server",
			Test:      false,
		},
		PolicyRevision: "rev-001",
	}
}

func consumerCertTestProof(pluginID, bindingID string, generation uint64) ConsumerCertProof {
	return ConsumerCertProof{
		Binding:          consumerCertTestBinding(pluginID, bindingID, generation),
		FullchainSHA256:  strings.Repeat("a", 64),
		PrivateKeySHA256: strings.Repeat("b", 64),
	}
}

func consumerCertTestStageRequest() ConsumerCertStageRequest {
	return ConsumerCertStageRequest{
		Op:               HelperOpConsumerCertStage,
		PluginID:         "alpha",
		Binding:          consumerCertTestBinding("alpha", "bind-01", 1),
		FullchainBase64:  base64.StdEncoding.EncodeToString([]byte("synthetic-fullchain-material")),
		PrivateKeyBase64: base64.StdEncoding.EncodeToString([]byte("synthetic-private-key-material")),
	}
}

func consumerCertTestActivateRequest(withExpected bool) ConsumerCertActivateRequest {
	req := ConsumerCertActivateRequest{
		Op:       HelperOpConsumerCertActivate,
		PluginID: "alpha",
		Wanted:   consumerCertTestProof("alpha", "bind-01", 2),
	}
	if withExpected {
		expected := consumerCertTestProof("alpha", "bind-01", 1)
		req.Expected = &expected
	}
	return req
}

func TestConsumerCertProtocolDecodeAllFourRequests(t *testing.T) {
	stageReq := consumerCertTestStageRequest()
	activateWithoutExpected := consumerCertTestActivateRequest(false)
	activateWithExpected := consumerCertTestActivateRequest(true)
	currentReq := ConsumerCertCurrentRequest{Op: HelperOpConsumerCertCurrent, PluginID: "alpha", BindingID: "bind-01"}
	removeReq := ConsumerCertRemoveRequest{Op: HelperOpConsumerCertRemove, PluginID: "alpha", BindingID: "bind-01"}

	t.Run("stage", func(t *testing.T) {
		raw := generationProtocolJSON(t, stageReq)
		decoded, err := DecodePrivilegedHelperRequest(raw)
		if err != nil || decoded.ConsumerStage == nil || *decoded.ConsumerStage != stageReq {
			t.Fatalf("stage 解码失败：%v %+v", err, decoded)
		}
		var direct ConsumerCertStageRequest
		if err := json.Unmarshal(raw, &direct); err != nil || direct != stageReq {
			t.Fatalf("stage 直接 Unmarshal 失败：%v", err)
		}
	})

	t.Run("activate-no-expected", func(t *testing.T) {
		raw := generationProtocolJSON(t, activateWithoutExpected)
		decoded, err := DecodePrivilegedHelperRequest(raw)
		if err != nil || decoded.ConsumerActivate == nil || decoded.ConsumerActivate.Expected != nil ||
			decoded.ConsumerActivate.Wanted != activateWithoutExpected.Wanted {
			t.Fatalf("activate(无expected) 解码失败：%v %+v", err, decoded)
		}
	})

	t.Run("activate-with-expected", func(t *testing.T) {
		raw := generationProtocolJSON(t, activateWithExpected)
		decoded, err := DecodePrivilegedHelperRequest(raw)
		if err != nil || decoded.ConsumerActivate == nil || decoded.ConsumerActivate.Expected == nil ||
			*decoded.ConsumerActivate.Expected != *activateWithExpected.Expected ||
			decoded.ConsumerActivate.Wanted != activateWithExpected.Wanted {
			t.Fatalf("activate(含expected) 解码失败：%v %+v", err, decoded)
		}
	})

	t.Run("current", func(t *testing.T) {
		raw := generationProtocolJSON(t, currentReq)
		decoded, err := DecodePrivilegedHelperRequest(raw)
		if err != nil || decoded.ConsumerCurrent == nil || *decoded.ConsumerCurrent != currentReq {
			t.Fatalf("current 解码失败：%v %+v", err, decoded)
		}
	})

	t.Run("remove", func(t *testing.T) {
		raw := generationProtocolJSON(t, removeReq)
		decoded, err := DecodePrivilegedHelperRequest(raw)
		if err != nil || decoded.ConsumerRemove == nil || *decoded.ConsumerRemove != removeReq {
			t.Fatalf("remove 解码失败：%v %+v", err, decoded)
		}
	})
}

func TestConsumerCertProtocolRejectsMissingFieldsAliasesNullAndUnknown(t *testing.T) {
	stageRaw := generationProtocolJSON(t, consumerCertTestStageRequest())
	for _, path := range [][]string{
		{"op"}, {"plugin_id"}, {"binding"}, {"fullchain_base64"}, {"private_key_base64"},
		{"binding", "id"}, {"binding", "certificate_id"}, {"binding", "generation"}, {"binding", "consumer"}, {"binding", "policy_revision"},
		{"binding", "consumer", "plugin_id"}, {"binding", "consumer", "profile_id"}, {"binding", "consumer", "node_id"},
		{"binding", "consumer", "sni"}, {"binding", "consumer", "purpose"}, {"binding", "consumer", "test"},
	} {
		t.Run("stage-missing-"+strings.Join(path, "."), func(t *testing.T) {
			dropped := generationProtocolDrop(t, stageRaw, path...)
			if _, err := DecodePrivilegedHelperRequest(dropped); err == nil {
				t.Fatalf("stage 缺少 %v 仍被接受", path)
			}
			var target ConsumerCertStageRequest
			if err := json.Unmarshal(dropped, &target); !errors.Is(err, ErrConsumerCertDocument) {
				t.Fatalf("stage Unmarshal 缺少 %v 错误=%v，期望 ErrConsumerCertDocument", path, err)
			}
		})
	}

	activateRaw := generationProtocolJSON(t, consumerCertTestActivateRequest(true))
	for _, path := range [][]string{
		{"op"}, {"plugin_id"}, {"wanted"},
		{"wanted", "binding"}, {"wanted", "fullchain_sha256"}, {"wanted", "private_key_sha256"},
		{"expected", "fullchain_sha256"}, {"expected", "binding", "id"},
	} {
		t.Run("activate-missing-"+strings.Join(path, "."), func(t *testing.T) {
			dropped := generationProtocolDrop(t, activateRaw, path...)
			if _, err := DecodePrivilegedHelperRequest(dropped); err == nil {
				t.Fatalf("activate 缺少 %v 仍被接受", path)
			}
			var target ConsumerCertActivateRequest
			if err := json.Unmarshal(dropped, &target); !errors.Is(err, ErrConsumerCertDocument) {
				t.Fatalf("activate Unmarshal 缺少 %v 错误=%v", path, err)
			}
		})
	}

	// expected 显式 null 必须拒绝。
	nullExpected := generationProtocolEdit(t, activateRaw, []string{"expected"}, func(fields map[string]json.RawMessage, key string) {
		fields[key] = json.RawMessage("null")
	})
	if _, err := DecodePrivilegedHelperRequest(nullExpected); err == nil {
		t.Fatal("activate expected=null 仍被接受")
	}
	var activateOut ConsumerCertActivateRequest
	if err := json.Unmarshal(nullExpected, &activateOut); !errors.Is(err, ErrConsumerCertDocument) {
		t.Fatalf("activate Unmarshal expected=null 错误=%v", err)
	}

	// 大小写别名、未知字段、重复键与跨 verb 混合全部拒绝。
	malformed := []string{
		`{"OP":"consumer-cert-current","plugin_id":"alpha","binding_id":"bind-01"}`,
		`{"op":"consumer-cert-current","Plugin_ID":"alpha","binding_id":"bind-01"}`,
		`{"op":"consumer-cert-current","plugin_id":"alpha","binding_id":"bind-01","extra":1}`,
		`{"op":"consumer-cert-current","plugin_id":"alpha","binding_id":null}`,
		`{"op":"consumer-cert-current","op":"ping","plugin_id":"alpha","binding_id":"bind-01"}`,
		`{"OP":"consumer-cert-remove","plugin_id":"alpha","binding_id":"bind-01"}`,
		`{"op":"consumer-cert-remove","plugin_id":"alpha","binding_id":"bind-01","removed":true}`,
		`{"op":"consumer-cert-remove","plugin_id":"alpha","binding_id":null}`,
		`{"op":"consumer-cert-remove","plugin_id":"alpha"}`,
		`{"op":"consumer-cert-current","plugin_id":"alpha","binding_id":"bind-01"} {"op":"ping"}`,
	}
	for _, doc := range malformed {
		if _, err := DecodePrivilegedHelperRequest([]byte(doc)); err == nil {
			t.Fatalf("非法请求仍被接受：%s", doc)
		}
	}

	// 顶层与嵌套大小写别名/未知字段在 stage 上均拒绝。
	for _, extra := range []string{"Op", "PluginID", "path", "target_dir", "binding_id"} {
		changed := generationProtocolEdit(t, stageRaw, []string{extra}, func(fields map[string]json.RawMessage, key string) {
			fields[key] = json.RawMessage(`"x"`)
		})
		if _, err := DecodePrivilegedHelperRequest(changed); err == nil {
			t.Fatalf("stage 额外/别名字段 %q 被接受", extra)
		}
	}
	nestedAlias := generationProtocolEdit(t, stageRaw, []string{"binding", "ID"}, func(fields map[string]json.RawMessage, key string) {
		fields[key] = json.RawMessage(`"bind-01"`)
	})
	if _, err := DecodePrivilegedHelperRequest(nestedAlias); err == nil {
		t.Fatal("stage 嵌套大小写别名 binding.ID 被接受")
	}
}

func TestConsumerCertProtocolValidationAndBounds(t *testing.T) {
	// plugin_id 不一致必须拒绝。
	mismatchStage := consumerCertTestStageRequest()
	mismatchStage.PluginID = "beta"
	if err := mismatchStage.Validate(); !errors.Is(err, ErrConsumerCertDocument) {
		t.Fatalf("stage plugin_id 不匹配未拒绝：%v", err)
	}

	mismatchActivate := consumerCertTestActivateRequest(true)
	mismatchActivate.Expected.Binding.ID = "bind-other"
	if err := mismatchActivate.Validate(); !errors.Is(err, ErrConsumerCertDocument) {
		t.Fatalf("activate expected binding_id 不匹配未拒绝：%v", err)
	}

	mismatchActivatePlugin := consumerCertTestActivateRequest(true)
	mismatchActivatePlugin.Expected.Binding.Consumer.PluginID = "beta"
	if err := mismatchActivatePlugin.Validate(); !errors.Is(err, ErrConsumerCertDocument) {
		t.Fatalf("activate expected plugin_id 不匹配未拒绝：%v", err)
	}

	// 非法单段 ID（包含 . / .. / 路径分隔 / 超长 / 前导符号）。
	for _, badID := range []string{"", ".", "..", "../escape", "a/b", "-lead", ".lead", strings.Repeat("a", 129)} {
		req := ConsumerCertCurrentRequest{Op: HelperOpConsumerCertCurrent, PluginID: "alpha", BindingID: badID}
		if err := req.Validate(); !errors.Is(err, ErrConsumerCertDocument) {
			t.Fatalf("非法 binding_id %q 未拒绝：%v", badID, err)
		}
	}

	// 非法标签与 SNI。
	for _, mutate := range []struct {
		name string
		fn   func(*ConsumerCertBinding)
	}{
		{"zero-gen", func(b *ConsumerCertBinding) { b.Generation = 0 }},
		{"bad-cert-id", func(b *ConsumerCertBinding) { b.CertificateID = "../cert" }},
		{"bad-policy-rev", func(b *ConsumerCertBinding) { b.PolicyRevision = "" }},
		{"profile-slash", func(b *ConsumerCertBinding) { b.Consumer.ProfileID = "a/b" }},
		{"profile-ctrl", func(b *ConsumerCertBinding) { b.Consumer.ProfileID = "a\nb" }},
		{"node-long", func(b *ConsumerCertBinding) { b.Consumer.NodeID = strings.Repeat("n", 129) }},
		{"purpose-backslash", func(b *ConsumerCertBinding) { b.Consumer.Purpose = `a\b` }},
		{"sni-space", func(b *ConsumerCertBinding) { b.Consumer.SNI = "a b.example.com" }},
		{"sni-ctrl", func(b *ConsumerCertBinding) { b.Consumer.SNI = "a\x00.example.com" }},
		{"sni-long", func(b *ConsumerCertBinding) { b.Consumer.SNI = strings.Repeat("s", 254) }},
	} {
		t.Run(mutate.name, func(t *testing.T) {
			b := consumerCertTestBinding("alpha", "bind-01", 1)
			mutate.fn(&b)
			if err := b.Validate(); !errors.Is(err, ErrConsumerCertDocument) {
				t.Fatalf("非法 binding (%s) 未拒绝：%v", mutate.name, err)
			}
		})
	}

	// 非法 SHA-256 摘要格式。
	for _, badHash := range []string{
		"",
		strings.Repeat("A", 64),
		strings.Repeat("a", 63),
		strings.Repeat("a", 65),
		"sha256:" + strings.Repeat("a", 64),
		strings.Repeat("g", 64),
	} {
		p := consumerCertTestProof("alpha", "bind-01", 1)
		p.FullchainSHA256 = badHash
		if err := p.Validate(); !errors.Is(err, ErrConsumerCertDocument) {
			t.Fatalf("非法 sha256 %q 未拒绝：%v", badHash, err)
		}
	}

	// 材料 base64 长度上下限。
	oversizeChain := consumerCertTestStageRequest()
	oversizeChain.FullchainBase64 = strings.Repeat("A", MaxConsumerCertChainBase64+1)
	if err := oversizeChain.Validate(); !errors.Is(err, ErrConsumerCertDocument) {
		t.Fatalf("超限 fullchain_base64 未拒绝：%v", err)
	}
	oversizeKey := consumerCertTestStageRequest()
	oversizeKey.PrivateKeyBase64 = strings.Repeat("A", MaxConsumerCertKeyBase64+1)
	if err := oversizeKey.Validate(); !errors.Is(err, ErrConsumerCertDocument) {
		t.Fatalf("超限 private_key_base64 未拒绝：%v", err)
	}

	// 整帧超过 MaxConsumerCertMessage（含空白填充）必须在 DecodePrivilegedHelperRequest 被拒绝。
	currentRaw := generationProtocolJSON(t, ConsumerCertCurrentRequest{
		Op:        HelperOpConsumerCertCurrent,
		PluginID:  "alpha",
		BindingID: "bind-01",
	})
	padding := MaxConsumerCertMessage - len(currentRaw)
	atLimit := append([]byte(strings.Repeat(" ", padding)), currentRaw...)
	if _, err := DecodePrivilegedHelperRequest(atLimit); err != nil {
		t.Fatalf("精确 128KiB 合法帧被拒绝：%v", err)
	}
	overLimit := append(atLimit, ' ')
	if _, err := DecodePrivilegedHelperRequest(overLimit); !errors.Is(err, ErrConsumerCertDocument) {
		t.Fatalf("超 128KiB 整帧未返回 ErrConsumerCertDocument：%v", err)
	}
}

func TestConsumerCertProtocolResponseValidation(t *testing.T) {
	proof := consumerCertTestProof("alpha", "bind-01", 2)

	t.Run("stage-response", func(t *testing.T) {
		okRaw := generationProtocolJSON(t, ConsumerCertStageResponse{
			ConsumerCertResponseStatus: ConsumerCertResponseStatus{OK: true, UID: 0},
			Proof:                      &proof,
		})
		var decoded ConsumerCertStageResponse
		if err := json.Unmarshal(okRaw, &decoded); err != nil || decoded.Proof == nil || *decoded.Proof != proof {
			t.Fatalf("合法 stage 响应被拒绝：%v", err)
		}
		for _, bad := range []string{
			`{"ok":true,"uid":0}`,
			`{"ok":true,"uid":1,"proof":` + string(generationProtocolJSON(t, proof)) + `}`,
			`{"ok":true,"uid":0,"uncertain":true,"proof":` + string(generationProtocolJSON(t, proof)) + `}`,
			`{"ok":false,"uid":0,"code":"INTERNAL","error":"boom","proof":` + string(generationProtocolJSON(t, proof)) + `}`,
			`{"ok":false,"uid":0,"code":"","error":"boom"}`,
			`{"ok":true,"uid":0,"proof":null}`,
			`{"ok":true,"UID":0,"proof":` + string(generationProtocolJSON(t, proof)) + `}`,
		} {
			var out ConsumerCertStageResponse
			if err := json.Unmarshal([]byte(bad), &out); !errors.Is(err, ErrConsumerCertDocument) {
				t.Fatalf("非法 stage 响应被接受或错误不符 (%s)：%v", bad, err)
			}
		}
	})

	t.Run("activate-response", func(t *testing.T) {
		// OK=true 无 Previous、OK=true 有 Previous、OK=false+Uncertain=true 有/无 Previous 均合法。
		validCases := []ConsumerCertActivateResponse{
			{ConsumerCertResponseStatus: ConsumerCertResponseStatus{OK: true, UID: 0}},
			{ConsumerCertResponseStatus: ConsumerCertResponseStatus{OK: true, UID: 0}, Previous: &proof},
			{ConsumerCertResponseStatus: ConsumerCertResponseStatus{OK: false, UID: 0, Code: "INTERNAL", Error: "rollback uncertain", Uncertain: true}, Previous: &proof},
			{ConsumerCertResponseStatus: ConsumerCertResponseStatus{OK: false, UID: 0, Code: "INTERNAL", Error: "state uncertain", Uncertain: true}},
			{ConsumerCertResponseStatus: ConsumerCertResponseStatus{OK: false, UID: 0, Code: "CONFLICT", Error: "cas mismatch"}},
		}
		for i, tc := range validCases {
			raw := generationProtocolJSON(t, tc)
			var out ConsumerCertActivateResponse
			if err := json.Unmarshal(raw, &out); err != nil {
				t.Fatalf("合法 activate 响应 #%d 被拒绝：%v", i, err)
			}
		}

		// OK=false && !Uncertain 时携带 Previous 必须拒绝；OK=true && Uncertain=true 必须拒绝。
		for _, bad := range []string{
			`{"ok":false,"uid":0,"code":"CONFLICT","error":"cas mismatch","previous":` + string(generationProtocolJSON(t, proof)) + `}`,
			`{"ok":true,"uid":0,"uncertain":true}`,
			`{"ok":true,"uid":0,"previous":null}`,
			`{"ok":false,"uid":1,"code":"INTERNAL","error":"not root"}`,
		} {
			var out ConsumerCertActivateResponse
			if err := json.Unmarshal([]byte(bad), &out); !errors.Is(err, ErrConsumerCertDocument) {
				t.Fatalf("非法 activate 响应被接受 (%s)：%v", bad, err)
			}
		}
	})

	t.Run("current-response", func(t *testing.T) {
		for _, raw := range []string{
			`{"ok":true,"uid":0}`,
			`{"ok":true,"uid":0,"current":` + string(generationProtocolJSON(t, proof)) + `}`,
			`{"ok":false,"uid":0,"code":"NOT_FOUND","error":"missing"}`,
		} {
			var out ConsumerCertCurrentResponse
			if err := json.Unmarshal([]byte(raw), &out); err != nil {
				t.Fatalf("合法 current 响应被拒绝 (%s)：%v", raw, err)
			}
		}
		for _, bad := range []string{
			`{"ok":false,"uid":0,"code":"INTERNAL","error":"fail","current":` + string(generationProtocolJSON(t, proof)) + `}`,
			`{"ok":true,"uid":0,"current":null}`,
			`{"ok":true,"uid":0,"Current":` + string(generationProtocolJSON(t, proof)) + `}`,
		} {
			var out ConsumerCertCurrentResponse
			if err := json.Unmarshal([]byte(bad), &out); !errors.Is(err, ErrConsumerCertDocument) {
				t.Fatalf("非法 current 响应被接受 (%s)：%v", bad, err)
			}
		}
	})

	t.Run("remove-response", func(t *testing.T) {
		for _, raw := range []string{
			`{"ok":true,"uid":0}`,
			`{"ok":true,"uid":0,"removed":false}`,
			`{"ok":true,"uid":0,"removed":true}`,
			`{"ok":false,"uid":0,"code":"INTERNAL","error":"failed"}`,
		} {
			var out ConsumerCertRemoveResponse
			if err := json.Unmarshal([]byte(raw), &out); err != nil {
				t.Fatalf("合法 remove 响应被拒绝 (%s)：%v", raw, err)
			}
		}
		for _, bad := range []string{
			`{"ok":false,"uid":0,"code":"INTERNAL","error":"failed","removed":true}`,
			`{"ok":true,"uid":0,"removed":null}`,
			`{"ok":true,"uid":0,"Removed":true}`,
		} {
			var out ConsumerCertRemoveResponse
			if err := json.Unmarshal([]byte(bad), &out); !errors.Is(err, ErrConsumerCertDocument) {
				t.Fatalf("非法 remove 响应被接受 (%s)：%v", bad, err)
			}
		}
	})
}

func TestConsumerCertProtocolRedaction(t *testing.T) {
	proof := consumerCertTestProof("alpha", "bind-secret-01", 7)
	stage := consumerCertTestStageRequest()

	var logBuf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logBuf, nil))
	logger.Info("consumer-cert-redaction-check",
		"proof", proof,
		"proof_ptr", &proof,
		"stage", stage,
		"stage_ptr", &stage,
	)

	rendered := strings.Join([]string{
		proof.String(),
		proof.GoString(),
		fmt.Sprintf("%v", proof),
		fmt.Sprintf("%+v", proof),
		fmt.Sprintf("%#v", proof),
		stage.String(),
		stage.GoString(),
		fmt.Sprintf("%v", stage),
		fmt.Sprintf("%+v", stage),
		fmt.Sprintf("%#v", stage),
		logBuf.String(),
	}, "\n")

	if !strings.Contains(rendered, "[REDACTED]") {
		t.Fatalf("脱敏输出缺少 [REDACTED] 标记：%s", rendered)
	}
	for _, secret := range []string{
		proof.FullchainSHA256,
		proof.PrivateKeySHA256,
		proof.Binding.ID,
		proof.Binding.Consumer.SNI,
		stage.FullchainBase64,
		stage.PrivateKeyBase64,
	} {
		if strings.Contains(rendered, secret) {
			t.Fatalf("脱敏输出泄露敏感字段 %q", secret)
		}
	}
}
