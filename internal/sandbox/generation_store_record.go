// SPDX-License-Identifier: AGPL-3.0-only

package sandbox

import (
	"encoding/json"
	"strings"

	"github.com/qwq-panel/qwq/internal/platform/ids"
)

// ======================== 私有记录：原 proof 只在退休后压缩，永久绑定仍由摘要守住 ========================

const (
	generationRecordVersion   = 1
	generationRecordBound     = "bound"
	generationRecordCompleted = "completed"
	generationRecordRetired   = "retired"
)

type generationStoredRecord struct {
	Version             uint32              `json:"version"`
	State               string              `json:"state"`
	Reference           GenerationRecordRef `json:"reference"`
	Expected            *ProcessProof       `json:"expected,omitempty"`
	OriginalExited      bool                `json:"original_exited,omitempty"`
	OriginalCgroupEmpty bool                `json:"original_cgroup_empty,omitempty"`
	CompletedAt         string              `json:"completed_at,omitempty"`
}

// generationRecordName 只使用全局 target_ref；插件或操作不能另选文件绕过原绑定。
func generationRecordName(targetRef string) (string, error) {
	if ids.Check(targetRef, ids.Generation) != nil {
		return "", ErrGenerationDocument
	}
	digest, err := generationCanonicalDigest(struct {
		Domain    string `json:"domain"`
		TargetRef string `json:"target_ref"`
	}{"qwq.generation.record-key.v1", targetRef})
	if err != nil {
		return "", err
	}
	return strings.TrimPrefix(digest, "sha256:") + ".json", nil
}

func generationStoredSchema(state string) generationJSONSchema {
	schema := generationRequiredFields("version", "state")
	schema["reference"] = generationJSONField{object: generationReferenceSchema}
	if state != generationRecordRetired {
		schema["expected"] = generationJSONField{object: generationProofSchema}
	}
	if state != generationRecordBound {
		for _, name := range []string{"original_exited", "original_cgroup_empty", "completed_at"} {
			schema[name] = generationJSONField{}
		}
	}
	return schema
}

func decodeGenerationStoredRecord(raw []byte) (generationStoredRecord, error) {
	if len(raw) == 0 || len(raw) > MaxGenerationMessage || validateHelperDocument(raw) != nil {
		return generationStoredRecord{}, ErrGenerationRecord
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil {
		return generationStoredRecord{}, ErrGenerationRecord
	}
	var state string
	if json.Unmarshal(fields["state"], &state) != nil {
		return generationStoredRecord{}, ErrGenerationRecord
	}
	switch state {
	case generationRecordBound, generationRecordCompleted, generationRecordRetired:
	default:
		return generationStoredRecord{}, ErrGenerationRecord
	}
	var record generationStoredRecord
	if decodeGenerationDocument(raw, &record, generationStoredSchema(state)) != nil || record.validate() != nil {
		return generationStoredRecord{}, ErrGenerationRecord
	}
	return record, nil
}

func encodeGenerationStoredRecord(record generationStoredRecord) ([]byte, error) {
	if record.validate() != nil {
		return nil, ErrGenerationRecord
	}
	raw, err := json.Marshal(record)
	if err != nil || len(raw) > MaxGenerationMessage {
		clear(raw)
		return nil, ErrGenerationRecord
	}
	return raw, nil
}

func (record generationStoredRecord) validate() error {
	reference := record.Reference
	if record.Version != generationRecordVersion || validateGenerationReference(reference.ID, reference.OperationID, reference.TargetRef) != nil ||
		!digestPattern.MatchString(reference.ProofDigest) {
		return ErrGenerationRecord
	}
	if record.Expected != nil {
		digest, err := GenerationProofDigest(reference.ID, *record.Expected)
		if err != nil || digest != reference.ProofDigest {
			return ErrGenerationRecord
		}
	}
	switch record.State {
	case generationRecordBound:
		if record.Expected == nil || reference.ReceiptDigest != "" || record.OriginalExited || record.OriginalCgroupEmpty || record.CompletedAt != "" {
			return ErrGenerationRecord
		}
	case generationRecordCompleted:
		if record.Expected == nil || record.completion(*record.Expected).Validate() != nil {
			return ErrGenerationRecord
		}
	case generationRecordRetired:
		if record.Expected != nil || reference.Validate() != nil || !record.OriginalExited || !record.OriginalCgroupEmpty {
			return ErrGenerationRecord
		}
		// guard 不伪造丢弃的 proof：receipt 仍绑定原 proof_digest、两条完成事实和规范时间。
		digest, err := generationCompletionDigest(record.completion(ProcessProof{}))
		if err != nil || digest != reference.ReceiptDigest {
			return ErrGenerationRecord
		}
	default:
		return ErrGenerationRecord
	}
	return nil
}

func (record generationStoredRecord) matches(request GenerationStopRequest, proofDigest string) bool {
	return record.Reference.ID == request.ID && record.Reference.OperationID == request.OperationID &&
		record.Reference.TargetRef == request.TargetRef && record.Reference.ProofDigest == proofDigest &&
		(record.Expected == nil || *record.Expected == request.Expected)
}

func (record generationStoredRecord) completion(proof ProcessProof) GenerationCompletion {
	return GenerationCompletion{Reference: record.Reference,
		Observation: StopObservation{Proof: proof, OriginalExited: record.OriginalExited, OriginalCgroupEmpty: record.OriginalCgroupEmpty},
		CompletedAt: record.CompletedAt}
}

func (record generationStoredRecord) replay(request GenerationStopRequest) (GenerationCompletion, error) {
	if record.State == generationRecordBound {
		return GenerationCompletion{}, ErrGenerationUnconfirmed
	}
	completion := record.completion(request.Expected)
	if completion.ValidateFor(request) != nil {
		return GenerationCompletion{}, ErrGenerationBinding
	}
	return completion, nil
}
