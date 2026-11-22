// SPDX-License-Identifier: AGPL-3.0-only

package sandbox

// ======================== 精确 key/presence 解码：拒绝别名、未知字段、null 与超限整帧 ========================

var consumerCertConsumerSchema = generationRequiredFields("plugin_id", "profile_id", "node_id", "sni", "purpose", "test")

var consumerCertBindingSchema = generationJSONSchema{
	"id":              {},
	"certificate_id":  {},
	"generation":      {},
	"consumer":        {object: consumerCertConsumerSchema},
	"policy_revision": {},
}

var consumerCertProofSchema = generationJSONSchema{
	"binding":            {object: consumerCertBindingSchema},
	"fullchain_sha256":   {},
	"private_key_sha256": {},
}

var consumerCertStageRequestSchema = generationJSONSchema{
	"op":                 {},
	"plugin_id":          {},
	"binding":            {object: consumerCertBindingSchema},
	"fullchain_base64":   {},
	"private_key_base64": {},
}

var consumerCertActivateRequestSchema = generationJSONSchema{
	"op":        {},
	"plugin_id": {},
	"expected":  {optional: true, object: consumerCertProofSchema},
	"wanted":    {object: consumerCertProofSchema},
}

var consumerCertCurrentRequestSchema = generationRequiredFields("op", "plugin_id", "binding_id")
var consumerCertRemoveRequestSchema = generationRequiredFields("op", "plugin_id", "binding_id")

func consumerCertResponseSchema(payload string, object generationJSONSchema) generationJSONSchema {
	schema := generationRequiredFields("ok", "uid")
	schema["code"] = generationJSONField{optional: true}
	schema["error"] = generationJSONField{optional: true}
	schema["uncertain"] = generationJSONField{optional: true}
	if payload != "" {
		schema[payload] = generationJSONField{optional: true, object: object}
	}
	return schema
}

// decodeConsumerCertWire 在进入统一 helper 解码前强制检查原始帧长度上限。
func decodeConsumerCertWire(raw []byte, target any) error {
	if len(raw) == 0 || len(raw) > MaxConsumerCertMessage {
		return ErrConsumerCertDocument
	}
	return DecodeHelperDocument(raw, target)
}

func decodeConsumerCertDocument(raw []byte, target any, schema generationJSONSchema) error {
	if len(raw) == 0 || len(raw) > MaxConsumerCertMessage {
		return ErrConsumerCertDocument
	}
	if err := validateHelperDocument(raw); err != nil {
		return ErrConsumerCertDocument
	}
	if err := checkGenerationObject(raw, schema); err != nil {
		return ErrConsumerCertDocument
	}
	if err := bindHelperDocument(raw, target); err != nil {
		return ErrConsumerCertDocument
	}
	return nil
}

// ======================== 四种请求的严格 UnmarshalJSON ========================

// UnmarshalJSON 要求精确字段名、完整嵌套绑定以及有界 base64 材料。
func (request *ConsumerCertStageRequest) UnmarshalJSON(raw []byte) error {
	type wire ConsumerCertStageRequest
	var decoded wire
	if err := decodeConsumerCertDocument(raw, &decoded, consumerCertStageRequestSchema); err != nil {
		return err
	}
	value := ConsumerCertStageRequest(decoded)
	if err := value.Validate(); err != nil {
		return err
	}
	*request = value
	return nil
}

// UnmarshalJSON 要求精确字段名与合法 CAS 证明；expected 缺失允许，显式 null 拒绝。
func (request *ConsumerCertActivateRequest) UnmarshalJSON(raw []byte) error {
	type wire ConsumerCertActivateRequest
	var decoded wire
	if err := decodeConsumerCertDocument(raw, &decoded, consumerCertActivateRequestSchema); err != nil {
		return err
	}
	value := ConsumerCertActivateRequest(decoded)
	if err := value.Validate(); err != nil {
		return err
	}
	*request = value
	return nil
}

// UnmarshalJSON 只接受精确的查询当前证明字段。
func (request *ConsumerCertCurrentRequest) UnmarshalJSON(raw []byte) error {
	type wire ConsumerCertCurrentRequest
	var decoded wire
	if err := decodeConsumerCertDocument(raw, &decoded, consumerCertCurrentRequestSchema); err != nil {
		return err
	}
	value := ConsumerCertCurrentRequest(decoded)
	if err := value.Validate(); err != nil {
		return err
	}
	*request = value
	return nil
}

// UnmarshalJSON 只接受精确的移除绑定字段。
func (request *ConsumerCertRemoveRequest) UnmarshalJSON(raw []byte) error {
	type wire ConsumerCertRemoveRequest
	var decoded wire
	if err := decodeConsumerCertDocument(raw, &decoded, consumerCertRemoveRequestSchema); err != nil {
		return err
	}
	value := ConsumerCertRemoveRequest(decoded)
	if err := value.Validate(); err != nil {
		return err
	}
	*request = value
	return nil
}

// ======================== 四种响应的严格 UnmarshalJSON ========================

// UnmarshalJSON 要求暂存成功时携带合法 Proof，失败时不得携带 Proof。
func (response *ConsumerCertStageResponse) UnmarshalJSON(raw []byte) error {
	type wire ConsumerCertStageResponse
	var decoded wire
	if err := decodeConsumerCertDocument(raw, &decoded, consumerCertResponseSchema("proof", consumerCertProofSchema)); err != nil {
		return err
	}
	value := ConsumerCertStageResponse(decoded)
	if value.ConsumerCertResponseStatus.validate() != nil ||
		(value.Proof != nil) != value.OK ||
		(value.Proof != nil && value.Proof.Validate() != nil) {
		return ErrConsumerCertDocument
	}
	*response = value
	return nil
}

// UnmarshalJSON 允许不确定失败保留 Previous 以供回滚对账，确定失败时禁止携带 Previous。
func (response *ConsumerCertActivateResponse) UnmarshalJSON(raw []byte) error {
	type wire ConsumerCertActivateResponse
	var decoded wire
	if err := decodeConsumerCertDocument(raw, &decoded, consumerCertResponseSchema("previous", consumerCertProofSchema)); err != nil {
		return err
	}
	value := ConsumerCertActivateResponse(decoded)
	if value.ConsumerCertResponseStatus.validate() != nil {
		return ErrConsumerCertDocument
	}
	if !value.OK && !value.Uncertain && value.Previous != nil {
		return ErrConsumerCertDocument
	}
	if value.Previous != nil && value.Previous.Validate() != nil {
		return ErrConsumerCertDocument
	}
	*response = value
	return nil
}

// UnmarshalJSON 允许查询成功时 Current 为空（尚未激活）；失败时不得携带 Current。
func (response *ConsumerCertCurrentResponse) UnmarshalJSON(raw []byte) error {
	type wire ConsumerCertCurrentResponse
	var decoded wire
	if err := decodeConsumerCertDocument(raw, &decoded, consumerCertResponseSchema("current", consumerCertProofSchema)); err != nil {
		return err
	}
	value := ConsumerCertCurrentResponse(decoded)
	if value.ConsumerCertResponseStatus.validate() != nil {
		return ErrConsumerCertDocument
	}
	if !value.OK && value.Current != nil {
		return ErrConsumerCertDocument
	}
	if value.Current != nil && value.Current.Validate() != nil {
		return ErrConsumerCertDocument
	}
	*response = value
	return nil
}

// UnmarshalJSON 要求移除失败时 Removed 必须为 false。
func (response *ConsumerCertRemoveResponse) UnmarshalJSON(raw []byte) error {
	type wire ConsumerCertRemoveResponse
	var decoded wire
	if err := decodeConsumerCertDocument(raw, &decoded, consumerCertResponseSchema("removed", nil)); err != nil {
		return err
	}
	value := ConsumerCertRemoveResponse(decoded)
	if value.ConsumerCertResponseStatus.validate() != nil {
		return ErrConsumerCertDocument
	}
	if !value.OK && value.Removed {
		return ErrConsumerCertDocument
	}
	*response = value
	return nil
}
