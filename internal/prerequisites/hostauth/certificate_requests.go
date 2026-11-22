// SPDX-License-Identifier: AGPL-3.0-only

package hostauth

import (
	"context"

	"github.com/qwq-panel/qwq/internal/prerequisites/certificates"
	"github.com/qwq-panel/qwq/internal/prerequisites/fault"
)

// ======================== 只从原已接受参数构造后端请求 ========================

func (a *Authority) acceptedCertificate(ctx context.Context, access certificates.Access) (*certificateExecution, certificates.Caller, error) {
	value, err := a.current(ctx)
	if err != nil {
		return nil, certificates.Caller{}, err
	}
	caller := certificates.Caller{OwnerID: a.ownerID, OperationID: value.invocation.OperationID}
	grant, err := a.certificateGrant(ctx, caller)
	if err != nil {
		return nil, certificates.Caller{}, err
	}
	if grant.access != access {
		return nil, certificates.Caller{}, fault.New("PERMISSION_DENIED", "原证书意图与后端请求类型不匹配")
	}
	return grant, caller, nil
}

// AcceptedIssueRequest 不接收替代 SAN、provider、zone、CA、caller 或 attempt。
func (a *Authority) AcceptedIssueRequest(ctx context.Context) (certificates.IssueRequest, error) {
	grant, caller, err := a.acceptedCertificate(ctx, certificates.Issue)
	if err != nil {
		return certificates.IssueRequest{}, err
	}
	return certificates.IssueRequest{Caller: caller, CertificateID: grant.certificateID, AttemptID: grant.attemptID,
		ExpectedRevision: grant.expectedRevision, Scope: cloneCertificateIssuance(*grant.issuance)}, nil
}

// AcceptedImportRequest 私钥只保留宿主提取的引用，材料明文不经过 capability RPC。
func (a *Authority) AcceptedImportRequest(ctx context.Context) (certificates.ImportRequest, error) {
	grant, caller, err := a.acceptedCertificate(ctx, certificates.Import)
	if err != nil {
		return certificates.ImportRequest{}, err
	}
	if err := a.AllowImportKey(ctx, caller, grant.keyRef); err != nil {
		return certificates.ImportRequest{}, err
	}
	return certificates.ImportRequest{Caller: caller, CertificateID: grant.certificateID, AttemptID: grant.attemptID,
		ExpectedRevision: grant.expectedRevision, Spec: cloneCertificateSpec(grant.spec), ChainPEM: []byte(grant.chainPEM),
		PrivateKeyRef: string(grant.keyRef), Trust: grant.trust}, nil
}

// AcceptedTestRequest 保留明确的 test_server_tls 用途，不允许替换为生产签发。
func (a *Authority) AcceptedTestRequest(ctx context.Context) (certificates.TestRequest, error) {
	grant, caller, err := a.acceptedCertificate(ctx, certificates.TestIssue)
	if err != nil {
		return certificates.TestRequest{}, err
	}
	return certificates.TestRequest{Caller: caller, CertificateID: grant.certificateID, AttemptID: grant.attemptID,
		ExpectedRevision: grant.expectedRevision, Spec: cloneCertificateSpec(grant.spec)}, nil
}

// CertificateTargetRequest 只用于宿主读取和删除后端，不接受 RPC 自报材料引用。
type CertificateTargetRequest struct {
	Caller           certificates.Caller
	CertificateID    string
	AttemptID        string
	ExpectedRevision string
	Generation       uint64
}

func (CertificateTargetRequest) String() string {
	return "hostauth.CertificateTargetRequest{[REDACTED]}"
}
func (CertificateTargetRequest) GoString() string {
	return "hostauth.CertificateTargetRequest{[REDACTED]}"
}

func (a *Authority) AcceptedCertificateTarget(ctx context.Context) (CertificateTargetRequest, error) {
	value, err := a.current(ctx)
	if err != nil {
		return CertificateTargetRequest{}, err
	}
	caller := certificates.Caller{OwnerID: a.ownerID, OperationID: value.invocation.OperationID}
	grant, err := a.certificateGrant(ctx, caller)
	if err != nil {
		return CertificateTargetRequest{}, err
	}
	if grant.access != certificates.Read && grant.access != certificates.Remove {
		return CertificateTargetRequest{}, fault.New("PERMISSION_DENIED", "当前证书意图没有读取或删除目标")
	}
	return CertificateTargetRequest{Caller: caller, CertificateID: grant.certificateID, AttemptID: grant.attemptID,
		ExpectedRevision: grant.expectedRevision, Generation: grant.generation}, nil
}
