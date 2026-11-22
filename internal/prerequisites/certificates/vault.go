// SPDX-License-Identifier: AGPL-3.0-only

package certificates

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"

	"github.com/qwq-panel/qwq/internal/platform/clock"
	"github.com/qwq-panel/qwq/internal/platform/problem"
	"github.com/qwq-panel/qwq/internal/prerequisites/fault"
	"github.com/qwq-panel/qwq/internal/prerequisites/names"
	"github.com/qwq-panel/qwq/internal/secrets"
	"github.com/qwq-panel/qwq/internal/storage"
	"github.com/qwq-panel/qwq/internal/tlsmgr"
)

// ======================== 真实加密材料后端 ========================

// ImportKeyReader 只读取当前 operation 的指定导入私钥，不开放任意秘密引用。
type ImportKeyReader interface {
	ReadImportKey(context.Context, Caller, string) ([]byte, error)
}

// TrustRoots 的根证书来自宿主受控 CA 配置；请求不能传递根或 URL。
type TrustRoots interface {
	Roots(context.Context, tlsmgr.TrustClass) (*x509.CertPool, error)
}

type VaultOptions struct {
	DB      *storage.DB
	Secrets *secrets.Store
	Imports ImportKeyReader
	Roots   TrustRoots
	Clock   clock.Clock
}

// Vault 复用宿主 AES-GCM、owner/purpose AAD、单写事务和幂等秘密索引。
type Vault struct {
	db      *storage.DB
	secrets *secrets.Store
	imports ImportKeyReader
	roots   TrustRoots
	clock   clock.Clock
}

func NewVault(options VaultOptions) (*Vault, error) {
	if options.DB == nil || options.Secrets == nil || options.Imports == nil || options.Roots == nil {
		return nil, fault.New("BACKEND_REQUIRED", "证书材料库需要真实加密、导入授权和信任配置")
	}
	if options.Clock == nil {
		options.Clock = clock.System{}
	}
	return &Vault{db: options.DB, secrets: options.Secrets, imports: options.Imports, roots: options.Roots, clock: options.Clock}, nil
}

type materialEnvelope struct {
	Version       uint32            `json:"version"`
	OwnerID       string            `json:"owner_id"`
	CertificateID string            `json:"certificate_id"`
	AttemptID     string            `json:"attempt_id"`
	Spec          Spec              `json:"spec"`
	Trust         tlsmgr.TrustClass `json:"trust"`
	Chain         []byte            `json:"chain"`
	Key           []byte            `json:"key"`
}

func (materialEnvelope) String() string   { return "certificates.materialEnvelope{[REDACTED]}" }
func (materialEnvelope) GoString() string { return "certificates.materialEnvelope{[REDACTED]}" }

func materialOwner(caller Caller, certificateID string) (string, error) {
	if err := validateCaller(caller, false); err != nil {
		return "", err
	}
	if !names.ID(certificateID) {
		return "", fault.New("VALIDATION_FAILED", "证书资源标识无效")
	}
	return "plugins/tls.certificates/owners/" + caller.OwnerID + "/certificates/" + certificateID, nil
}

func materialPurpose(attemptID string) (string, string, error) {
	if !names.ID(attemptID) {
		return "", "", fault.New("VALIDATION_FAILED", "证书材料 attempt 无效")
	}
	sum := sha256.Sum256([]byte(attemptID))
	digest := hex.EncodeToString(sum[:])
	return "certificate.material." + digest, digest, nil
}

func parseMaterialLocator(reference MaterialRef) (secrets.Ref, string, error) {
	parts := strings.Split(string(reference), ".")
	if len(parts) != 2 || len(parts[1]) != 64 {
		return "", "", fault.New("VALIDATION_FAILED", "证书材料引用无效")
	}
	ref, err := secrets.ParseRef(parts[0])
	if err != nil {
		return "", "", fault.New("VALIDATION_FAILED", "证书材料引用无效")
	}
	if _, err := hex.DecodeString(parts[1]); err != nil {
		return "", "", fault.New("VALIDATION_FAILED", "证书材料引用无效")
	}
	return ref, "certificate.material." + parts[1], nil
}

func vaultFailure(err error) error {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	switch {
	case problem.HasCode(err, problem.NotFound):
		return fault.New("NOT_FOUND", "证书材料不可见或不存在")
	case problem.HasCode(err, problem.StateConflict):
		return fault.New("MATERIAL_CONFLICT", "同一证书 attempt 的材料不一致或索引有歧义")
	case problem.HasCode(err, problem.ValidationFailed):
		return fault.New("VALIDATION_FAILED", "证书材料输入无效")
	default:
		return fault.New("MATERIAL_UNAVAILABLE", "证书加密材料库暂不可用")
	}
}

// EnsureMaterial 在发出结果前提交密钥/链，重复 attempt 不替换已经保存的材料。
func (v *Vault) EnsureMaterial(ctx context.Context, caller Caller, certificateID, attemptID string, material tlsmgr.Material, spec Spec, trust tlsmgr.TrustClass) (MaterialRef, error) {
	if err := validateCaller(caller, true); err != nil {
		return "", err
	}
	owner, err := materialOwner(caller, certificateID)
	if err != nil {
		return "", err
	}
	purpose, digest, err := materialPurpose(attemptID)
	if err != nil {
		return "", err
	}
	canonical, err := canonicalSpec(spec)
	if err != nil {
		return "", err
	}
	roots, err := v.roots.Roots(ctx, trust)
	if err != nil {
		return "", backendFailure(err, "TRUST_UNAVAILABLE")
	}
	if _, err := tlsmgr.ValidateMaterial(material, tlsmgr.MaterialOptions{SANs: canonical.SANs, Now: v.clock.Now(), Purpose: canonical.Purpose, Trust: trust, Roots: roots}); err != nil {
		return "", err
	}
	key := material.PrivateKeyPEM()
	defer clear(key)
	raw, err := json.Marshal(materialEnvelope{Version: 1, OwnerID: caller.OwnerID, CertificateID: certificateID, AttemptID: attemptID, Spec: canonical, Trust: trust, Chain: material.CertificatePEM(), Key: key})
	if err != nil || len(raw) > secrets.MaxPlaintext {
		return "", fault.New("CERTIFICATE_INVALID", "证书材料无法安全编码")
	}
	defer clear(raw)
	var reference secrets.Ref
	err = v.db.Update(ctx, func(tx *storage.Tx) error {
		var err error
		reference, err = v.secrets.EnsureOwned(ctx, tx, owner, purpose, raw)
		return err
	})
	if err != nil {
		return "", vaultFailure(err)
	}
	return MaterialRef(string(reference) + "." + digest), nil
}

func (v *Vault) envelope(ctx context.Context, caller Caller, certificateID string, reference MaterialRef) (materialEnvelope, error) {
	owner, err := materialOwner(caller, certificateID)
	if err != nil {
		return materialEnvelope{}, err
	}
	ref, purpose, err := parseMaterialLocator(reference)
	if err != nil {
		return materialEnvelope{}, err
	}
	secret, err := v.secrets.RevealOwned(ctx, ref, owner, purpose)
	if err != nil {
		return materialEnvelope{}, vaultFailure(err)
	}
	defer secret.Clear()
	raw := secret.Bytes()
	defer clear(raw)
	var envelope materialEnvelope
	if len(raw) > secrets.MaxPlaintext || json.Unmarshal(raw, &envelope) != nil {
		clear(envelope.Key)
		return materialEnvelope{}, fault.New("CERTIFICATE_INVALID", "证书加密材料格式无效")
	}
	actualPurpose, _, err := materialPurpose(envelope.AttemptID)
	if err != nil || envelope.Version != 1 || envelope.OwnerID != caller.OwnerID || envelope.CertificateID != certificateID || actualPurpose != purpose {
		clear(envelope.Key)
		return materialEnvelope{}, fault.New("NOT_FOUND", "证书材料不属于该资源")
	}
	return envelope, nil
}

func (v *Vault) Find(ctx context.Context, caller Caller, certificateID, attemptID string) (Issued, error) {
	owner, err := materialOwner(caller, certificateID)
	if err != nil {
		return Issued{}, err
	}
	purpose, digest, err := materialPurpose(attemptID)
	if err != nil {
		return Issued{}, err
	}
	ref, found, err := v.secrets.FindOwned(ctx, owner, purpose)
	if err != nil {
		return Issued{}, vaultFailure(err)
	}
	if !found {
		return Issued{}, fault.New("NOT_FOUND", "该 attempt 尚无保存的证书材料")
	}
	locator := MaterialRef(string(ref) + "." + digest)
	envelope, err := v.envelope(ctx, caller, certificateID, locator)
	if err != nil {
		return Issued{}, err
	}
	defer clear(envelope.Key)
	return Issued{Material: locator, Trust: envelope.Trust}, nil
}

func (v *Vault) Inspect(ctx context.Context, caller Caller, certificateID string, reference MaterialRef, spec Spec, trust tlsmgr.TrustClass) (tlsmgr.CertificateMetadata, error) {
	envelope, err := v.envelope(ctx, caller, certificateID, reference)
	if err != nil {
		return tlsmgr.CertificateMetadata{}, err
	}
	defer clear(envelope.Key)
	canonical, err := canonicalSpec(spec)
	if err != nil || !sameSpec(envelope.Spec, canonical) || envelope.Trust != trust {
		return tlsmgr.CertificateMetadata{}, fault.New("SAN_MISMATCH", "材料 SAN 或信任范围不符")
	}
	material, err := tlsmgr.NewMaterial(envelope.Chain, envelope.Key)
	if err != nil {
		return tlsmgr.CertificateMetadata{}, err
	}
	defer material.Clear()
	roots, err := v.roots.Roots(ctx, trust)
	if err != nil {
		return tlsmgr.CertificateMetadata{}, backendFailure(err, "TRUST_UNAVAILABLE")
	}
	return tlsmgr.ValidateMaterial(material, tlsmgr.MaterialOptions{SANs: canonical.SANs, Now: v.clock.Now(), Purpose: canonical.Purpose, Trust: trust, Roots: roots})
}

func (v *Vault) Import(ctx context.Context, caller Caller, certificateID, attemptID string, chain []byte, keyReference string, spec Spec, trust tlsmgr.TrustClass) (MaterialRef, error) {
	if err := validateCaller(caller, true); err != nil {
		return "", err
	}
	if _, err := materialOwner(caller, certificateID); err != nil {
		return "", err
	}
	key, err := v.imports.ReadImportKey(ctx, caller, keyReference)
	if err != nil {
		return "", backendFailure(err, "IMPORT_KEY_DENIED")
	}
	defer clear(key)
	material, err := tlsmgr.NewMaterial(chain, key)
	if err != nil {
		return "", err
	}
	defer material.Clear()
	return v.EnsureMaterial(ctx, caller, certificateID, attemptID, material, spec, trust)
}

func (v *Vault) GenerateTest(ctx context.Context, caller Caller, certificateID, attemptID string, spec Spec) (MaterialRef, error) {
	if existing, err := v.Find(ctx, caller, certificateID, attemptID); err == nil {
		if _, err := v.Inspect(ctx, caller, certificateID, existing.Material, spec, tlsmgr.TestTrust); err != nil {
			return "", err
		}
		return existing.Material, nil
	} else if fault.Code(err) != "NOT_FOUND" {
		return "", err
	}
	material, err := tlsmgr.GenerateTestMaterial(v.clock.Now(), spec.SANs)
	if err != nil {
		return "", err
	}
	defer material.Clear()
	reference, err := v.EnsureMaterial(ctx, caller, certificateID, attemptID, material, spec, tlsmgr.TestTrust)
	if fault.Code(err) == "MATERIAL_CONFLICT" {
		existing, findErr := v.Find(ctx, caller, certificateID, attemptID)
		if findErr != nil {
			return "", findErr
		}
		if _, inspectErr := v.Inspect(ctx, caller, certificateID, existing.Material, spec, tlsmgr.TestTrust); inspectErr != nil {
			return "", inspectErr
		}
		return existing.Material, nil
	}
	return reference, err
}

func (v *Vault) Remove(ctx context.Context, caller Caller, certificateID string, reference MaterialRef) error {
	if err := validateCaller(caller, true); err != nil {
		return err
	}
	envelope, err := v.envelope(ctx, caller, certificateID, reference)
	if err != nil {
		if fault.Code(err) == "NOT_FOUND" {
			return nil
		}
		return err
	}
	defer clear(envelope.Key)
	ref, _, err := parseMaterialLocator(reference)
	if err != nil {
		return err
	}
	err = v.db.Update(ctx, func(tx *storage.Tx) error { return v.secrets.Delete(ctx, tx, ref) })
	if err != nil {
		return vaultFailure(err)
	}
	return nil
}

// LoadMaterial 仅供已确认消费许可的宿主 materialize；调用方必须先校验绑定。
func (v *Vault) LoadMaterial(ctx context.Context, caller Caller, certificateID string, reference MaterialRef) (tlsmgr.Material, error) {
	if err := validateCaller(caller, true); err != nil {
		return tlsmgr.Material{}, err
	}
	envelope, err := v.envelope(ctx, caller, certificateID, reference)
	if err != nil {
		return tlsmgr.Material{}, err
	}
	defer clear(envelope.Key)
	return tlsmgr.NewMaterial(envelope.Chain, envelope.Key)
}
