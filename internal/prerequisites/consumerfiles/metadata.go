// SPDX-License-Identifier: AGPL-3.0-only

// Package consumerfiles 只保存消费者证书的文件事实；授权与运行时健康由宿主核验。
package consumerfiles

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"strconv"

	"github.com/qwq-panel/qwq/internal/prerequisites/certificates"
	"github.com/qwq-panel/qwq/internal/prerequisites/fault"
	"github.com/qwq-panel/qwq/internal/prerequisites/names"
	"github.com/qwq-panel/qwq/internal/tlsmgr"
)

// ======================== 固定布局与宿主材料证明 ========================

const (
	metadataVersion  = 1
	maxMetadataBytes = 8 << 10
	chainName        = "fullchain.pem"
	keyName          = "privkey.pem"
	materialName     = "material.json"
	proofsName       = "proofs"
	currentName      = "current.json"
)

// Proof 的来源必须是宿主可信账本；从 Current 读出的同型值不具有授权效力。
// 私钥摘要只用于内部核对，不能加入公开 DTO、日志或插件自报许可。
type Proof struct {
	Binding          certificates.HostBinding `json:"binding"`
	FullchainSHA256  string                   `json:"fullchain_sha256"`
	PrivateKeySHA256 string                   `json:"private_key_sha256"`
}

func (Proof) String() string       { return "consumerfiles.Proof{[REDACTED]}" }
func (Proof) GoString() string     { return "consumerfiles.Proof{[REDACTED]}" }
func (Proof) LogValue() slog.Value { return slog.StringValue("[REDACTED]") }

// materialScope 固定同一代材料的完整消费范围；许可版本另存，不能替换材料。
type materialScope struct {
	ID            string                `json:"id"`
	CertificateID string                `json:"certificate_id"`
	Generation    uint64                `json:"generation"`
	Consumer      certificates.Consumer `json:"consumer"`
}

type generationMetadata struct {
	Version          int           `json:"version"`
	Scope            materialScope `json:"scope"`
	FullchainSHA256  string        `json:"fullchain_sha256"`
	PrivateKeySHA256 string        `json:"private_key_sha256"`
}

type proofMetadata struct {
	Version int   `json:"version"`
	Proof   Proof `json:"proof"`
}

// currentMetadata 是唯一切换点；保存前代完整证明，便于宿主精确回滚与重复请求。
type currentMetadata struct {
	Version  int    `json:"version"`
	Active   Proof  `json:"active"`
	Previous *Proof `json:"previous,omitempty"`
}

func bindingIDValid(id string) bool {
	return names.ID(id) && id != "." && id != ".."
}

func validateBinding(binding certificates.HostBinding) error {
	consumer, err := certificates.CanonicalConsumer(binding.Consumer)
	if err != nil {
		return err
	}
	if !bindingIDValid(binding.ID) || !names.ID(binding.CertificateID) || binding.Generation == 0 ||
		!names.ID(binding.PolicyRevision) || consumer != binding.Consumer {
		return fault.New("CONSUMER_FILES_INVALID", "消费绑定必须包含规范身份、generation 与许可版本")
	}
	return nil
}

func digest(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func digestValid(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size && hex.EncodeToString(decoded) == value
}

func validateProof(proof Proof) error {
	if err := validateBinding(proof.Binding); err != nil {
		return err
	}
	if !digestValid(proof.FullchainSHA256) || !digestValid(proof.PrivateKeySHA256) {
		return fault.New("CONSUMER_FILES_INVALID", "材料证明需要完整的规范 SHA-256 摘要")
	}
	return nil
}

func generationName(number uint64) string { return "g" + strconv.FormatUint(number, 10) }

// proofSnapshotName 只从精确许可版本生成固定单分量名，不把材料摘要或用户路径放进名字。
func proofSnapshotName(proof Proof) string {
	return "p-" + digest([]byte(proof.Binding.PolicyRevision)) + ".json"
}

func generationDescriptor(proof Proof) generationMetadata {
	binding := proof.Binding
	return generationMetadata{Version: metadataVersion,
		Scope:           materialScope{ID: binding.ID, CertificateID: binding.CertificateID, Generation: binding.Generation, Consumer: binding.Consumer},
		FullchainSHA256: proof.FullchainSHA256, PrivateKeySHA256: proof.PrivateKeySHA256}
}

func copyProof(proof *Proof) *Proof {
	if proof == nil {
		return nil
	}
	copy := *proof
	return &copy
}

func sameProof(a, b *Proof) bool {
	return (a == nil && b == nil) || (a != nil && b != nil && *a == *b)
}

// ======================== 有界解析与不泄露内容的错误 ========================

func checkContext(ctx context.Context) error {
	if ctx == nil {
		return fault.New("CONSUMER_FILES_INVALID", "文件操作需要明确的 context")
	}
	if err := ctx.Err(); err != nil {
		return errors.Join(fault.New("CANCELLED", "消费者材料文件操作已取消"), err)
	}
	return nil
}

func fileFailure(code, detail string, uncertain bool) error {
	failure := fault.New(code, detail)
	failure.Uncertain = uncertain
	return failure
}

func encodeMetadata(value any) ([]byte, error) {
	raw, err := json.Marshal(value)
	if err != nil || len(raw)+1 > maxMetadataBytes {
		return nil, fault.New("CONSUMER_FILES_INVALID", "消费者材料元数据无法编码或超过上限")
	}
	return append(raw, '\n'), nil
}

func decodeMetadata(raw []byte, target any) error {
	if len(raw) == 0 || len(raw) > maxMetadataBytes {
		return fault.New("CONSUMER_FILES_INVALID", "消费者材料元数据长度无效")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return fault.New("CONSUMER_FILES_INVALID", "消费者材料元数据格式无效")
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		return fault.New("CONSUMER_FILES_INVALID", "消费者材料元数据存在额外内容")
	}
	return nil
}

func decodeGeneration(raw []byte, wanted Proof) error {
	var metadata generationMetadata
	if err := decodeMetadata(raw, &metadata); err != nil {
		return err
	}
	if metadata != generationDescriptor(wanted) {
		return fault.New("CONSUMER_FILES_CONFLICT", "已保存 generation 的完整材料范围或摘要与宿主证明不符")
	}
	return nil
}

func decodeProof(raw []byte, wanted Proof) error {
	var metadata proofMetadata
	if err := decodeMetadata(raw, &metadata); err != nil {
		return err
	}
	if metadata.Version != metadataVersion || metadata.Proof != wanted {
		return fault.New("CONSUMER_FILES_CONFLICT", "已保存许可快照与宿主完整材料证明不符")
	}
	return nil
}

func decodeCurrent(raw []byte, bindingID string) (*currentMetadata, error) {
	var metadata currentMetadata
	if err := decodeMetadata(raw, &metadata); err != nil {
		return nil, err
	}
	if metadata.Version != metadataVersion || metadata.Active.Binding.ID != bindingID {
		return nil, fault.New("CONSUMER_FILES_INVALID", "当前文件事实与绑定身份或格式版本不符")
	}
	if err := validateProof(metadata.Active); err != nil {
		return nil, err
	}
	if metadata.Previous != nil {
		if metadata.Previous.Binding.ID != bindingID {
			return nil, fault.New("CONSUMER_FILES_INVALID", "前代文件事实与绑定身份不符")
		}
		if err := validateProof(*metadata.Previous); err != nil {
			return nil, err
		}
	}
	return &metadata, nil
}

// validatePair 复用现有 PEM 解析与标准库配对，只验证完整 pair 与消费者 SNI。
// exact SAN、用途、信任、时效及撤权必须在宿主账本/Vault 边界另外确认。
func validatePair(binding certificates.HostBinding, chain, key []byte) error {
	chainCertificates, err := tlsmgr.ParseCertificateChain(chain)
	if err != nil {
		return err
	}
	if err := tlsmgr.ValidatePrivateKeyPEM(key); err != nil {
		return err
	}
	if _, err := tls.X509KeyPair(chain, key); err != nil {
		return fault.New("PRIVATE_KEY_MISMATCH", "消费者证书与私钥无法解析或不匹配")
	}
	return tlsmgr.Covers(tlsmgr.CertificateMetadata{SANs: chainCertificates[0].DNSNames}, binding.Consumer.SNI)
}
