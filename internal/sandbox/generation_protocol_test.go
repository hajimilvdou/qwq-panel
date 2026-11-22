// SPDX-License-Identifier: AGPL-3.0-only

package sandbox

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/qwq-panel/qwq/internal/platform/problem"
)

// ======================== 正式 wire/见证回归：省字段、别名、跨目标不能变成成功 ========================

func generationProtocolStopFixture() GenerationStopRequest {
	return GenerationStopRequest{Op: HelperOpGenerationStop, ID: "alpha", OperationID: "op_01h455vb4pex5vsknk084sn02q",
		TargetRef: "gen_01h455vb4pex5vsknk084sn02q", Expected: generationStopTestProof()}
}

func generationProtocolCompletionFixture(t *testing.T) GenerationCompletion {
	t.Helper()
	request := generationProtocolStopFixture()
	completion, err := NewGenerationCompletion(request,
		StopObservation{Proof: request.Expected, OriginalExited: true, OriginalCgroupEmpty: true},
		time.Date(2026, 11, 21, 10, 0, 0, 123000000, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	return completion
}

func generationProtocolJSON(t *testing.T, value any) []byte {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func generationProtocolEdit(t *testing.T, raw []byte, path []string, edit func(map[string]json.RawMessage, string)) []byte {
	t.Helper()
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		t.Fatal(err)
	}
	if len(path) == 1 {
		edit(fields, path[0])
	} else {
		fields[path[0]] = generationProtocolEdit(t, fields[path[0]], path[1:], edit)
	}
	return generationProtocolJSON(t, fields)
}

func generationProtocolDrop(t *testing.T, raw []byte, path ...string) []byte {
	t.Helper()
	return generationProtocolEdit(t, raw, path, func(fields map[string]json.RawMessage, key string) { delete(fields, key) })
}

func TestGenerationProtocolGoldenCompletionAndCanonicalWire(t *testing.T) {
	request := generationProtocolStopFixture()
	completion := generationProtocolCompletionFixture(t)
	if completion.Reference.ProofDigest != "sha256:5fb00d754f6275a5f7ec36c376d3feba70da9fd299f2c67c5aee4f27d600f1a1" ||
		completion.Reference.ReceiptDigest != "sha256:16dd7822680d49d863d51bc0e362062c2c8792789c8b315e1ed7a4a2b6b59511" {
		t.Fatalf("canonical golden摘要漂移：%+v", completion.Reference)
	}
	response := GenerationStopResponse{GenerationResponseStatus: GenerationResponseStatus{OK: true}, Stopped: &completion}
	raw, err := json.MarshalIndent(response, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	var decoded GenerationStopResponse
	if err := DecodeHelperDocument(raw, &decoded); err != nil || decoded.Stopped == nil || decoded.Stopped.ValidateFor(request) != nil {
		t.Fatalf("正式JSON空白改变typed witness：%v %+v", err, decoded)
	}
	if _, err := NewGenerationCompletion(request, StopObservation{Proof: request.Expected, OriginalExited: true}, time.Now()); !errors.Is(err, ErrGenerationDocument) {
		t.Fatalf("原主退出被构造成完整witness：%v", err)
	}
}

func TestGenerationProtocolRequiresEveryRequestAndProofField(t *testing.T) {
	raw := generationProtocolJSON(t, generationProtocolStopFixture())
	for _, key := range []string{"op", "id", "operation_id", "target_ref", "expected"} {
		t.Run(key, func(t *testing.T) {
			if _, err := DecodePrivilegedHelperRequest(generationProtocolDrop(t, raw, key)); err == nil {
				t.Fatal("缺少顶层字段仍被接受")
			}
		})
	}
	for _, key := range []string{"version", "unit", "pid", "kernel_start_ticks", "boot_id", "invocation_id", "uid", "cgroup", "cgroup_device", "cgroup_inode"} {
		t.Run("proof-"+key, func(t *testing.T) {
			if _, err := DecodePrivilegedHelperRequest(generationProtocolDrop(t, raw, "expected", key)); err == nil {
				t.Fatal("缺少proof字段仍被接受")
			}
		})
	}
	for _, op := range []string{HelperOpGenerationObserve, HelperOpGenerationRetire} {
		var request any = GenerationObserveRequest{Op: op, ID: "alpha"}
		if op == HelperOpGenerationRetire {
			ref := generationProtocolCompletionFixture(t).Reference
			request = GenerationRetireRequest{Op: op, ID: ref.ID, OperationID: ref.OperationID, TargetRef: ref.TargetRef,
				ProofDigest: ref.ProofDigest, ReceiptDigest: ref.ReceiptDigest}
		}
		encoded := generationProtocolJSON(t, request)
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(encoded, &fields); err != nil {
			t.Fatal(err)
		}
		for key := range fields {
			if _, err := DecodePrivilegedHelperRequest(generationProtocolDrop(t, encoded, key)); err == nil {
				t.Fatalf("%s缺%s仍接受", op, key)
			}
		}
	}
}

func TestGenerationProtocolRejectsAliasesMixingNullAndBounds(t *testing.T) {
	raw := generationProtocolJSON(t, generationProtocolStopFixture())
	for _, extra := range []string{"Op", "OP", "signal", "unit", "boot_id_path", "receipt_digest", "terminal", "ttl", "spec"} {
		changed := generationProtocolEdit(t, raw, []string{extra}, func(fields map[string]json.RawMessage, key string) {
			fields[key] = json.RawMessage(`"generation-stop"`)
		})
		if _, err := DecodePrivilegedHelperRequest(changed); err == nil {
			t.Fatalf("未知/别名/跨verb字段%s被接受", extra)
		}
	}
	for _, change := range []struct {
		path  []string
		value string
	}{
		{[]string{"expected"}, "null"}, {[]string{"id"}, "null"}, {[]string{"target_ref"}, `"original"`},
		{[]string{"expected", "uid"}, "0"}, {[]string{"expected", "pid"}, "1"},
		{[]string{"expected", "uid"}, "4294967296"}, {[]string{"expected", "kernel_start_ticks"}, "18446744073709551616"},
		{[]string{"expected", "PID"}, "42"}, {[]string{"expected", "cgroup_device"}, "null"},
	} {
		changed := generationProtocolEdit(t, raw, change.path, func(fields map[string]json.RawMessage, key string) { fields[key] = json.RawMessage(change.value) })
		if _, err := DecodePrivilegedHelperRequest(changed); err == nil {
			t.Fatalf("不安全字段%v=%s被接受", change.path, change.value)
		}
	}
	for _, malformed := range []string{
		`{"OP":"generation-observe","id":"alpha"}`,
		`{"op":"generation-observe","id":"alpha","expected":null}`,
		`{"op":"ping","operation_id":"op_01h455vb4pex5vsknk084sn02q"}`,
		`{"op":"generation-observe","op":"ping","id":"alpha"}`,
		`{"op":"generation-observe","id":"alpha"} {"op":"ping"}`,
	} {
		if _, err := DecodePrivilegedHelperRequest([]byte(malformed)); err == nil {
			t.Fatalf("混合/重复/trailing文档被接受：%s", malformed)
		}
	}
	oversize := append(append([]byte(nil), raw...), []byte(strings.Repeat(" ", MaxGenerationMessage))...)
	if _, err := DecodePrivilegedHelperRequest(oversize); err == nil {
		t.Fatal("generation超过16KiB仍接受")
	}
}

// ------------------------ PID 上界：两个正式入口必须遵守 Linux int32 范围 ------------------------

func TestGenerationProtocolRejectsPIDAboveInt32(t *testing.T) {
	setPID := func(fields map[string]json.RawMessage, key string) {
		fields[key] = json.RawMessage("2147483648")
	}
	t.Run("request", func(t *testing.T) {
		raw := generationProtocolJSON(t, generationProtocolStopFixture())
		changed := generationProtocolEdit(t, raw, []string{"expected", "pid"}, setPID)
		if _, err := DecodePrivilegedHelperRequest(changed); err == nil {
			t.Fatal("请求 proof 接受了超过 int32 上界的 PID")
		}
	})
	t.Run("observed-response", func(t *testing.T) {
		proof := generationProtocolStopFixture().Expected
		raw := generationProtocolJSON(t, GenerationObserveResponse{
			GenerationResponseStatus: GenerationResponseStatus{OK: true},
			Observed:                 &proof,
		})
		changed := generationProtocolEdit(t, raw, []string{"observed", "pid"}, setPID)
		var response GenerationObserveResponse
		if err := DecodeHelperDocument(changed, &response); err == nil {
			t.Fatal("观察回应 proof 接受了超过 int32 上界的 PID")
		}
	})
}

func TestGenerationProtocolRequiresCompleteResponseAndBinding(t *testing.T) {
	completion := generationProtocolCompletionFixture(t)
	raw := generationProtocolJSON(t, GenerationStopResponse{GenerationResponseStatus: GenerationResponseStatus{OK: true}, Stopped: &completion})
	for _, path := range [][]string{{"ok"}, {"uid"}, {"stopped"}, {"stopped", "reference"}, {"stopped", "completed_at"},
		{"stopped", "reference", "operation_id"}, {"stopped", "reference", "target_ref"}, {"stopped", "reference", "proof_digest"},
		{"stopped", "reference", "receipt_digest"}, {"stopped", "observation", "original_exited"}, {"stopped", "observation", "original_cgroup_empty"}} {
		var response GenerationStopResponse
		if err := DecodeHelperDocument(generationProtocolDrop(t, raw, path...), &response); err == nil {
			t.Fatalf("响应缺%v被接受", path)
		}
	}
	for _, edit := range []struct {
		path  []string
		value string
	}{
		{[]string{"UID"}, "0"}, {[]string{"stopped", "observation", "original_cgroup_empty"}, "false"},
		{[]string{"stopped", "reference", "receipt_digest"}, `"sha256:` + strings.Repeat("a", 64) + `"`},
		{[]string{"stopped", "completed_at"}, `"2026-11-21T10:00:00.123+00:00"`},
		{[]string{"ok"}, "false"}, {[]string{"stopped"}, "null"},
	} {
		changed := generationProtocolEdit(t, raw, edit.path, func(fields map[string]json.RawMessage, key string) { fields[key] = json.RawMessage(edit.value) })
		var response GenerationStopResponse
		if err := DecodeHelperDocument(changed, &response); err == nil {
			t.Fatalf("坏响应%v被接受", edit.path)
		}
	}
	other := generationProtocolStopFixture()
	other.OperationID = "op_01h455vb4pex5vsknk084sn02r"
	if completion.ValidateFor(other) == nil {
		t.Fatal("另一个operation消费了原完成witness")
	}
	other = generationProtocolStopFixture()
	other.TargetRef = "gen_01h455vb4pex5vsknk084sn02r"
	if completion.ValidateFor(other) == nil {
		t.Fatal("另一个target_ref消费了原完成witness")
	}
}

// ------------------------ 整帧预算：合法空白仍计入请求和三种响应的原始大小 ------------------------

func TestGenerationProtocolDocumentLimitIncludesPadding(t *testing.T) {
	stop := generationProtocolStopFixture()
	completion := generationProtocolCompletionFixture(t)
	proof := stop.Expected
	retire := GenerationRetireRequest{Op: HelperOpGenerationRetire, ID: completion.Reference.ID,
		OperationID: completion.Reference.OperationID, TargetRef: completion.Reference.TargetRef,
		ProofDigest: completion.Reference.ProofDigest, ReceiptDigest: completion.Reference.ReceiptDigest}
	for _, sample := range []struct {
		name   string
		value  any
		target func() any
	}{
		{"observe-request", GenerationObserveRequest{Op: HelperOpGenerationObserve, ID: "alpha"}, func() any { return &GenerationObserveRequest{} }},
		{"stop-request", stop, func() any { return &GenerationStopRequest{} }},
		{"retire-request", retire, func() any { return &GenerationRetireRequest{} }},
		{"observe-response", GenerationObserveResponse{GenerationResponseStatus: GenerationResponseStatus{OK: true}, Observed: &proof}, func() any { return &GenerationObserveResponse{} }},
		{"stop-response", GenerationStopResponse{GenerationResponseStatus: GenerationResponseStatus{OK: true}, Stopped: &completion}, func() any { return &GenerationStopResponse{} }},
		{"retire-response", GenerationRetireResponse{GenerationResponseStatus: GenerationResponseStatus{OK: true}, Retired: &completion.Reference}, func() any { return &GenerationRetireResponse{} }},
	} {
		t.Run(sample.name, func(t *testing.T) {
			raw := generationProtocolJSON(t, sample.value)
			padding := MaxGenerationMessage - len(raw)
			atLimit := append([]byte(strings.Repeat(" ", padding/2)), raw...)
			atLimit = append(atLimit, []byte(strings.Repeat(" ", padding-padding/2))...)
			if err := DecodeHelperDocument(atLimit, sample.target()); err != nil {
				t.Fatalf("精确16KiB合法整帧被拒绝：%v", err)
			}
			if err := DecodeHelperDocument(append(atLimit, ' '), sample.target()); err == nil {
				t.Fatal("剥离前后的合法空白绕过整帧16KiB预算")
			}
		})
	}
}

func TestGenerationProtocolWriterRejectsOversizeBeforeBody(t *testing.T) {
	response := GenerationObserveResponse{GenerationResponseStatus: GenerationResponseStatus{
		UID: 0, Code: string(problem.Internal), Error: strings.Repeat("x", MaxGenerationMessage),
	}}
	var body bytes.Buffer
	if err := WriteHelperJSON(&body, response); err == nil || body.Len() != 0 {
		t.Fatalf("超限typed响应在拒绝前写出正文：bytes=%d err=%v", body.Len(), err)
	}
}

func TestGenerationProtocolLegacyAndUnknownFailureRemainCompatible(t *testing.T) {
	document, err := DecodePrivilegedHelperRequest([]byte(`{"op":"ping"}`))
	if err != nil || document.Legacy == nil || document.Legacy.Op != HelperOpPing {
		t.Fatalf("旧ping协议被破坏：%+v %v", document, err)
	}
	var response GenerationObserveResponse
	if err := DecodeHelperDocument([]byte(`{"ok":false,"uid":0,"code":"UNKNOWN","error":"test failure"}`), &response); err != nil {
		t.Fatal(err)
	}
	var remote *problem.Error
	if err := generationRemoteFailure(response.GenerationResponseStatus); !errors.As(err, &remote) || remote.Code != problem.Internal {
		t.Fatalf("未知problem code未复用旧Internal映射：%v", err)
	}
}
