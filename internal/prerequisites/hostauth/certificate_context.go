// SPDX-License-Identifier: AGPL-3.0-only

package hostauth

import (
	"context"
	"encoding/json"

	"github.com/qwq-panel/qwq/internal/actor"
	"github.com/qwq-panel/qwq/internal/operations"
	"github.com/qwq-panel/qwq/internal/prerequisites/certificates"
	"github.com/qwq-panel/qwq/internal/prerequisites/fault"
	"github.com/qwq-panel/qwq/internal/prerequisites/names"
	"github.com/qwq-panel/qwq/internal/secrets"
	"github.com/qwq-panel/qwq/internal/tlsmgr"
)

// ======================== 原已接受证书参数与私有执行范围 ========================

type IssueCertificateArgs struct {
	CertificateID string            `json:"certificate_id"`
	AttemptID     string            `json:"attempt_id"`
	Spec          certificates.Spec `json:"spec"`
	ProviderID    string            `json:"provider_id"`
	ZoneID        string            `json:"zone_id"`
	CA            certificates.CA   `json:"ca"`
	AcceptTerms   bool              `json:"accept_terms"`
}

type ImportCertificateArgs struct {
	CertificateID string            `json:"certificate_id"`
	AttemptID     string            `json:"attempt_id"`
	Spec          certificates.Spec `json:"spec"`
	ChainPEM      string            `json:"chain_pem"`
	PrivateKey    json.RawMessage   `json:"private_key"`
	Trust         tlsmgr.TrustClass `json:"trust"`
}

type TestCertificateArgs struct {
	CertificateID string            `json:"certificate_id"`
	AttemptID     string            `json:"attempt_id"`
	Spec          certificates.Spec `json:"spec"`
}

type CertificateTargetArgs struct {
	CertificateID string `json:"certificate_id"`
	AttemptID     string `json:"attempt_id,omitempty"`
	Generation    uint64 `json:"generation,omitempty"`
}

type certificateExecutionKey struct{}

type certificateExecution struct {
	parent           *execution
	certificateID    string
	attemptID        string
	registryRevision string
	expectedRevision string
	spec             certificates.Spec
	issuance         *certificates.IssuanceScope
	providerRevision string
	zoneRevision     string
	generation       uint64
	access           certificates.Access
	trust            tlsmgr.TrustClass
	chainPEM         string
	keyRef           secrets.Ref
	acceptTerms      bool
}

func (*certificateExecution) String() string               { return "hostauth.certificateExecution{[REDACTED]}" }
func (*certificateExecution) GoString() string             { return "hostauth.certificateExecution{[REDACTED]}" }
func (*certificateExecution) MarshalJSON() ([]byte, error) { return []byte(`{"redacted":true}`), nil }

// CertificateContext 只从原 Args 建立 certificate/SAN/CA/generation 范围。
// consumer 与续期策略必须接真实宿主登记，不在此处从 RPC 或插件 KV 推断权限。
func (a *Authority) CertificateContext(ctx context.Context, certificateID, attemptID, expected string) (context.Context, certificates.Caller, error) {
	value, err := a.current(ctx)
	if err != nil {
		return nil, certificates.Caller{}, err
	}
	if value.invocation.PluginID != "tls.certificates" || value.snapshot.Actor.Kind == actor.Service || !names.ID(certificateID) || value.invocation.Subject != "plugins/tls.certificates/resources/certificates/"+certificateID {
		return nil, certificates.Caller{}, fault.New("PERMISSION_DENIED", "当前真实 operation 不能建立证书资源范围")
	}
	grant, create, err := a.certificateIntent(ctx, value)
	if err != nil {
		return nil, certificates.Caller{}, err
	}
	if grant.certificateID != certificateID || grant.attemptID != attemptID {
		return nil, certificates.Caller{}, fault.New("PERMISSION_DENIED", "证书或 attempt 不属于已接受参数")
	}
	if err := validateCertificateAction(value.snapshot.Action, grant.access); err != nil {
		return nil, certificates.Caller{}, err
	}
	if create || grant.access != certificates.Read {
		if err := a.RequireRevision(ctx, expected); err != nil {
			return nil, certificates.Caller{}, err
		}
		if !validRevision(expected) {
			return nil, certificates.Caller{}, fault.New("VALIDATION_FAILED", "原证书意图需要有效资源版本")
		}
		grant.expectedRevision = expected
	}
	if grant.issuance != nil {
		if err := a.checkCertificateProvider(ctx, grant); err != nil {
			return nil, certificates.Caller{}, err
		}
	}
	if create {
		_, revision, err := a.registerCertificate(ctx, value, certificateID, expected, grant.spec)
		if err != nil {
			return nil, certificates.Caller{}, err
		}
		grant.registryRevision = revision
	} else {
		state, revision, found, err := a.loadCertificate(ctx, certificateID)
		if err != nil {
			return nil, certificates.Caller{}, err
		}
		if !found {
			return nil, certificates.Caller{}, fault.New("NOT_FOUND", "证书宿主登记不存在")
		}
		grant.spec, grant.registryRevision = state.Spec, revision
	}
	grant.parent = value
	caller := certificates.Caller{OwnerID: a.ownerID, OperationID: value.invocation.OperationID}
	certificateCtx := context.WithValue(ctx, certificateExecutionKey{}, grant)
	if _, err := a.certificateGrant(certificateCtx, caller); err != nil {
		return nil, certificates.Caller{}, err
	}
	return certificateCtx, caller, nil
}

func (a *Authority) certificateIntent(ctx context.Context, value *execution) (*certificateExecution, bool, error) {
	grant := &certificateExecution{}
	switch value.invocation.Operation {
	case "certificates.issue":
		input, err := DecodeArguments[IssueCertificateArgs](ctx, a)
		if err != nil {
			return nil, false, err
		}
		if !input.AcceptTerms {
			return nil, false, fault.New("TERMS_REQUIRED", "原证书意图必须明确接受受控 CA 条款")
		}
		scope, providerRevision, zoneRevision, err := a.resolveScope(ctx, input.ProviderID, input.ZoneID)
		if err != nil {
			return nil, false, err
		}
		grant.certificateID, grant.attemptID, grant.spec = input.CertificateID, input.AttemptID, input.Spec
		grant.issuance = &certificates.IssuanceScope{Provider: scope, CA: input.CA}
		grant.providerRevision, grant.zoneRevision = providerRevision, zoneRevision
		grant.access, grant.acceptTerms = certificates.Issue, true
	case "certificates.import":
		input, err := DecodeArguments[ImportCertificateArgs](ctx, a)
		if err != nil {
			return nil, false, err
		}
		ref, valid := operationSecret(input.PrivateKey)
		validTrust := input.Trust == tlsmgr.PublicTrust || input.Trust == tlsmgr.StagingTrust || input.Trust == tlsmgr.TestTrust
		if !valid || !validTrust || input.ChainPEM == "" || len(input.ChainPEM) > tlsmgr.MaxCertificatePEM || (input.Spec.Purpose == tlsmgr.TestServerTLS) != (input.Trust == tlsmgr.TestTrust) {
			return nil, false, fault.New("VALIDATION_FAILED", "原证书导入的链、私钥引用或信任类别无效")
		}
		grant.certificateID, grant.attemptID, grant.spec = input.CertificateID, input.AttemptID, input.Spec
		grant.access, grant.trust, grant.chainPEM, grant.keyRef = certificates.Import, input.Trust, input.ChainPEM, ref
	case "certificates.test":
		input, err := DecodeArguments[TestCertificateArgs](ctx, a)
		if err != nil {
			return nil, false, err
		}
		if input.Spec.Purpose != tlsmgr.TestServerTLS {
			return nil, false, fault.New("CERTIFICATE_PURPOSE_INVALID", "测试签发必须明确选择测试服务端用途")
		}
		grant.certificateID, grant.attemptID, grant.spec = input.CertificateID, input.AttemptID, input.Spec
		grant.access, grant.trust = certificates.TestIssue, tlsmgr.TestTrust
	case "certificates.get", "certificates.remove", "generations.remove":
		input, err := DecodeArguments[CertificateTargetArgs](ctx, a)
		if err != nil {
			return nil, false, err
		}
		if err := validateCertificateTarget(value.invocation.Operation, input); err != nil {
			return nil, false, err
		}
		grant.certificateID, grant.attemptID, grant.generation = input.CertificateID, input.AttemptID, input.Generation
		grant.access = certificates.Read
		if value.invocation.Operation != "certificates.get" {
			grant.access = certificates.Remove
		}
		return grant, false, nil
	default:
		return nil, false, fault.New("PERMISSION_DENIED", "当前证书 operation 尚无宿主确认的权限入口")
	}
	if !names.ID(grant.certificateID) || !names.ID(grant.attemptID) {
		return nil, false, fault.New("VALIDATION_FAILED", "原证书意图的资源或 attempt ID 无效")
	}
	spec, err := certificates.CanonicalSpec(grant.spec)
	if err != nil {
		return nil, false, err
	}
	grant.spec = spec
	if grant.issuance != nil {
		grant.issuance.Spec = spec
		issuance, err := certificates.CanonicalIssuance(*grant.issuance)
		if err != nil {
			return nil, false, err
		}
		grant.issuance = &issuance
	}
	return grant, true, nil
}

func validateCertificateTarget(operation string, input CertificateTargetArgs) error {
	valid := names.ID(input.CertificateID)
	switch operation {
	case "certificates.get":
		valid = valid && input.AttemptID == "" && input.Generation == 0
	case "certificates.remove":
		valid = valid && names.ID(input.AttemptID) && input.Generation == 0
	case "generations.remove":
		valid = valid && names.ID(input.AttemptID) && input.Generation != 0
	default:
		valid = false
	}
	if !valid {
		return fault.New("VALIDATION_FAILED", "原证书目标缺少精确资源、attempt 或 generation")
	}
	return nil
}

func validateCertificateAction(action operations.Action, access certificates.Access) error {
	validPerm := action.Permission == "tls.certificates:read" || action.Permission == "system.certificates:read"
	validEffect := action.Effect == operations.EffectRead
	capable := false
	if access == certificates.Read {
		for _, declared := range action.Capabilities {
			capable = capable || ((declared.Name == "certificates.read" || declared.Name == "system.certificates.read") && declared.Scope == "self")
		}
	} else {
		validPerm = action.Permission == "tls.certificates:manage" || action.Permission == "system.certificates:manage"
		validEffect = (action.Effect == operations.EffectWrite || action.Effect == operations.EffectDestructive) && action.EffectiveRisk() == operations.RiskHigh
		for _, declared := range action.Capabilities {
			capable = capable || (declared.Name == "system.certificates.manage" && declared.Scope == "self")
		}
	}
	if !validPerm || action.Mode != operations.ModeJob || !validEffect || !capable {
		return fault.New("PERMISSION_DENIED", "原证书 action 缺少实际权限、能力或风险下限")
	}
	return nil
}
