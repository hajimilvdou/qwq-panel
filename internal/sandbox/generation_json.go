// SPDX-License-Identifier: AGPL-3.0-only

package sandbox

import (
	"bytes"
	"encoding/json"
	"strings"
)

// ======================== 精确 key/presence：共用旧 scanner，不接受 Go 大小写别名 ========================

type generationJSONField struct {
	optional bool
	object   generationJSONSchema
}

type generationJSONSchema map[string]generationJSONField

func generationRequiredFields(names ...string) generationJSONSchema {
	schema := make(generationJSONSchema, len(names))
	for _, name := range names {
		schema[name] = generationJSONField{}
	}
	return schema
}

var generationProofSchema = generationRequiredFields("version", "unit", "pid", "kernel_start_ticks", "boot_id", "invocation_id", "uid", "cgroup", "cgroup_device", "cgroup_inode")
var generationReferenceSchema = generationRequiredFields("id", "operation_id", "target_ref", "proof_digest", "receipt_digest")
var generationObservationSchema = generationJSONSchema{
	"proof": {object: generationProofSchema}, "original_exited": {}, "original_cgroup_empty": {},
}
var generationCompletionSchema = generationJSONSchema{
	"reference": {object: generationReferenceSchema}, "observation": {object: generationObservationSchema}, "completed_at": {},
}
var generationObserveRequestSchema = generationRequiredFields("op", "id")
var generationStopRequestSchema = generationJSONSchema{
	"op": {}, "id": {}, "operation_id": {}, "target_ref": {}, "expected": {object: generationProofSchema},
}
var generationRetireRequestSchema = generationRequiredFields("op", "id", "operation_id", "target_ref", "proof_digest", "receipt_digest")

func generationResponseSchema(payload string, object generationJSONSchema) generationJSONSchema {
	schema := generationRequiredFields("ok", "uid")
	schema["code"] = generationJSONField{optional: true}
	schema["error"] = generationJSONField{optional: true}
	schema[payload] = generationJSONField{optional: true, object: object}
	return schema
}

func decodeGenerationDocument(raw []byte, target any, schema generationJSONSchema) error {
	if len(raw) == 0 || len(raw) > MaxGenerationMessage {
		return ErrGenerationDocument
	}
	if err := validateHelperDocument(raw); err != nil {
		return ErrGenerationDocument
	}
	if err := checkGenerationObject(raw, schema); err != nil {
		return err
	}
	if err := bindHelperDocument(raw, target); err != nil {
		return ErrGenerationDocument
	}
	return nil
}

func checkGenerationObject(raw []byte, schema generationJSONSchema) error {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil || fields == nil {
		return ErrGenerationDocument
	}
	for name, rule := range schema {
		if _, exists := fields[name]; !exists && !rule.optional {
			return ErrGenerationDocument
		}
	}
	for name, value := range fields {
		rule, allowed := schema[name]
		if !allowed || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return ErrGenerationDocument
		}
		if rule.object != nil {
			if err := checkGenerationObject(value, rule.object); err != nil {
				return err
			}
		}
	}
	return nil
}

func validateGenerationPayload(status GenerationResponseStatus, present bool) error {
	if status.validate() != nil || present != status.OK {
		return ErrGenerationDocument
	}
	return nil
}

// UnmarshalJSON 对所有正式入口核精确字段；类型别名避免递归调用自身。
func (request *GenerationObserveRequest) UnmarshalJSON(raw []byte) error {
	type wire GenerationObserveRequest
	var decoded wire
	if err := decodeGenerationDocument(raw, &decoded, generationObserveRequestSchema); err != nil {
		return err
	}
	value := GenerationObserveRequest(decoded)
	if err := value.Validate(); err != nil {
		return err
	}
	*request = value
	return nil
}

// UnmarshalJSON 要求完整原proof、精确字段名和受限消息大小。
func (request *GenerationStopRequest) UnmarshalJSON(raw []byte) error {
	type wire GenerationStopRequest
	var decoded wire
	if err := decodeGenerationDocument(raw, &decoded, generationStopRequestSchema); err != nil {
		return err
	}
	value := GenerationStopRequest(decoded)
	if err := value.Validate(); err != nil {
		return err
	}
	*request = value
	return nil
}

// UnmarshalJSON 只接受精确完成引用，拒绝跨verb字段。
func (request *GenerationRetireRequest) UnmarshalJSON(raw []byte) error {
	type wire GenerationRetireRequest
	var decoded wire
	if err := decodeGenerationDocument(raw, &decoded, generationRetireRequestSchema); err != nil {
		return err
	}
	value := GenerationRetireRequest(decoded)
	if err := value.Validate(); err != nil {
		return err
	}
	*request = value
	return nil
}

// UnmarshalJSON 拒绝缺uid/payload或仅零proof的观察成功。
func (response *GenerationObserveResponse) UnmarshalJSON(raw []byte) error {
	type wire GenerationObserveResponse
	var decoded wire
	if err := decodeGenerationDocument(raw, &decoded, generationResponseSchema("observed", generationProofSchema)); err != nil {
		return err
	}
	value := GenerationObserveResponse(decoded)
	if err := validateGenerationPayload(value.GenerationResponseStatus, value.Observed != nil); err != nil {
		return err
	}
	if value.Observed != nil {
		pluginID, ok := strings.CutPrefix(value.Observed.Unit, strings.TrimSuffix(ServiceTemplateName, ".service"))
		if !ok {
			return ErrGenerationDocument
		}
		pluginID, ok = strings.CutSuffix(pluginID, ".service")
		if !ok || value.Observed.Validate(pluginID) != nil || len(value.Observed.Cgroup) > 4096 {
			return ErrGenerationDocument
		}
	}
	*response = value
	return nil
}

// UnmarshalJSON 完整核witness引用、两flags与canonical摘要。
func (response *GenerationStopResponse) UnmarshalJSON(raw []byte) error {
	type wire GenerationStopResponse
	var decoded wire
	if err := decodeGenerationDocument(raw, &decoded, generationResponseSchema("stopped", generationCompletionSchema)); err != nil {
		return err
	}
	value := GenerationStopResponse(decoded)
	if validateGenerationPayload(value.GenerationResponseStatus, value.Stopped != nil) != nil || value.Stopped != nil && value.Stopped.Validate() != nil {
		return ErrGenerationDocument
	}
	*response = value
	return nil
}

// UnmarshalJSON 只接受准确同类型回应，不接受其他verb payload。
func (response *GenerationRetireResponse) UnmarshalJSON(raw []byte) error {
	type wire GenerationRetireResponse
	var decoded wire
	if err := decodeGenerationDocument(raw, &decoded, generationResponseSchema("retired", generationReferenceSchema)); err != nil {
		return err
	}
	value := GenerationRetireResponse(decoded)
	if validateGenerationPayload(value.GenerationResponseStatus, value.Retired != nil) != nil || value.Retired != nil && value.Retired.Validate() != nil {
		return ErrGenerationDocument
	}
	*response = value
	return nil
}

// ======================== server 分流：旧 union 不接收任何 generation 附加字段 ========================

// DecodedHelperRequest 恰有一支；它是内部解码结果，不是可序列化的请求 DTO。
type DecodedHelperRequest struct {
	Legacy           *HelperRequest               `json:"-"`
	Observe          *GenerationObserveRequest    `json:"-"`
	Stop             *GenerationStopRequest       `json:"-"`
	Retire           *GenerationRetireRequest     `json:"-"`
	ConsumerStage    *ConsumerCertStageRequest    `json:"-"`
	ConsumerActivate *ConsumerCertActivateRequest `json:"-"`
	ConsumerCurrent  *ConsumerCertCurrentRequest  `json:"-"`
	ConsumerRemove   *ConsumerCertRemoveRequest   `json:"-"`
}

// DecodePrivilegedHelperRequest 共用正式 scanner，再分别绑定 generation 或旧协议。
func DecodePrivilegedHelperRequest(raw []byte) (DecodedHelperRequest, error) {
	if err := validateHelperDocument(raw); err != nil {
		return DecodedHelperRequest{}, err
	}
	var fields map[string]json.RawMessage
	if err := bindHelperDocument(raw, &fields); err != nil {
		return DecodedHelperRequest{}, err
	}
	// 发现大小写 op 别名里的 generation 值也走严格分支，不能降回 legacy decoder。
	for name, encoded := range fields {
		if !strings.EqualFold(name, "op") {
			continue
		}
		var operation string
		if err := json.Unmarshal(encoded, &operation); err != nil {
			return DecodedHelperRequest{}, ErrGenerationDocument
		}
		switch operation {
		case HelperOpGenerationObserve:
			var request GenerationObserveRequest
			if err := DecodeHelperDocument(raw, &request); err != nil {
				return DecodedHelperRequest{}, err
			}
			return DecodedHelperRequest{Observe: &request}, nil
		case HelperOpGenerationStop:
			var request GenerationStopRequest
			if err := DecodeHelperDocument(raw, &request); err != nil {
				return DecodedHelperRequest{}, err
			}
			return DecodedHelperRequest{Stop: &request}, nil
		case HelperOpGenerationRetire:
			var request GenerationRetireRequest
			if err := DecodeHelperDocument(raw, &request); err != nil {
				return DecodedHelperRequest{}, err
			}
			return DecodedHelperRequest{Retire: &request}, nil
		case HelperOpConsumerCertStage:
			var request ConsumerCertStageRequest
			if err := decodeConsumerCertWire(raw, &request); err != nil {
				return DecodedHelperRequest{}, err
			}
			return DecodedHelperRequest{ConsumerStage: &request}, nil
		case HelperOpConsumerCertActivate:
			var request ConsumerCertActivateRequest
			if err := decodeConsumerCertWire(raw, &request); err != nil {
				return DecodedHelperRequest{}, err
			}
			return DecodedHelperRequest{ConsumerActivate: &request}, nil
		case HelperOpConsumerCertCurrent:
			var request ConsumerCertCurrentRequest
			if err := decodeConsumerCertWire(raw, &request); err != nil {
				return DecodedHelperRequest{}, err
			}
			return DecodedHelperRequest{ConsumerCurrent: &request}, nil
		case HelperOpConsumerCertRemove:
			var request ConsumerCertRemoveRequest
			if err := decodeConsumerCertWire(raw, &request); err != nil {
				return DecodedHelperRequest{}, err
			}
			return DecodedHelperRequest{ConsumerRemove: &request}, nil
		}
	}
	var legacy HelperRequest
	if err := bindHelperDocument(raw, &legacy); err != nil {
		return DecodedHelperRequest{}, err
	}
	if legacy.Op == "" {
		return DecodedHelperRequest{}, ErrGenerationDocument
	}
	return DecodedHelperRequest{Legacy: &legacy}, nil
}
