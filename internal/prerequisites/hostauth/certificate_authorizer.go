// SPDX-License-Identifier: AGPL-3.0-only

package hostauth

import (
	"context"
	"slices"

	"github.com/qwq-panel/qwq/internal/prerequisites/certificates"
	"github.com/qwq-panel/qwq/internal/prerequisites/fault"
)

// ======================== 每个关键步骤的证书范围复核 ========================

func cloneCertificateSpec(spec certificates.Spec) certificates.Spec {
	spec.SANs = slices.Clone(spec.SANs)
	return spec
}

func cloneCertificateIssuance(scope certificates.IssuanceScope) certificates.IssuanceScope {
	scope.Spec = cloneCertificateSpec(scope.Spec)
	return scope
}

func sameCertificateIssuance(one, two *certificates.IssuanceScope) bool {
	if one == nil || two == nil {
		return one == nil && two == nil
	}
	return one.CA == two.CA && one.Provider == two.Provider && sameCertificateSpec(one.Spec, two.Spec)
}

func (a *Authority) certificateGrant(ctx context.Context, caller certificates.Caller) (*certificateExecution, error) {
	value, err := a.current(ctx)
	if err != nil {
		return nil, err
	}
	grant, found := ctx.Value(certificateExecutionKey{}).(*certificateExecution)
	expected := certificates.Caller{OwnerID: a.ownerID, OperationID: value.invocation.OperationID}
	if permission, ok := ctx.Value(renewalExecutionKey{}).(*renewalExecution); ok && permission != nil {
		run, _, err := a.currentRenewalExecution(ctx, permission)
		if err != nil {
			return nil, err
		}
		if caller.PolicyID != "" {
			expected = permission.caller
		}
		if grant == nil || (grant.access == certificates.Issue && (grant.attemptID != run.IssueAttemptID || grant.expectedRevision != run.ExpectedRevision)) ||
			(grant.access == certificates.Bind && (grant.generation == 0 || grant.generation != run.DeployGeneration)) {
			return nil, fault.New("POLICY_REVOKED", "续期Context的原private阶段已经变化")
		}
	}
	if !found || grant == nil || grant.parent != value || caller != expected {
		return nil, fault.New("PERMISSION_DENIED", "证书调用缺少原宿主 operation 与资源范围")
	}
	state, revision, found, err := a.loadCertificate(ctx, grant.certificateID)
	if err != nil {
		return nil, err
	}
	if !found || revision != grant.registryRevision || !sameCertificateSpec(state.Spec, grant.spec) {
		return nil, fault.New("PERMISSION_DENIED", "证书私有登记或精确 SAN 发生变化")
	}
	if grant.issuance != nil {
		if err := a.checkCertificateProvider(ctx, grant); err != nil {
			return nil, err
		}
	}
	if _, err := a.current(ctx); err != nil {
		return nil, err
	}
	return grant, nil
}

func (a *Authority) checkCertificateProvider(ctx context.Context, grant *certificateExecution) error {
	scope := grant.issuance.Provider
	actual, providerRevision, zoneRevision, err := a.resolveScope(ctx, scope.ProviderID, scope.ZoneID)
	if err != nil {
		return err
	}
	if actual != scope || providerRevision != grant.providerRevision || zoneRevision != grant.zoneRevision {
		return fault.New("CREDENTIAL_REVOKED", "证书提供商、精确 zone 或凭据版本发生变化")
	}
	registration, revision, found, err := a.loadProvider(ctx, scope.ProviderID)
	if err != nil {
		return err
	}
	if !found || revision != grant.providerRevision || registration.Phase != providerActive {
		return fault.New("CREDENTIAL_REVOKED", "证书提供商已撤销或版本发生变化")
	}
	credentials, err := a.providerCredentials(ctx, registration)
	credentials.Clear()
	if err != nil {
		return err
	}
	actual, providerRevision, zoneRevision, err = a.resolveScope(ctx, scope.ProviderID, scope.ZoneID)
	if err != nil {
		return err
	}
	if actual != scope || providerRevision != grant.providerRevision || zoneRevision != grant.zoneRevision {
		return fault.New("CREDENTIAL_REVOKED", "凭据复核期间证书 DNS 授权发生变化")
	}
	return nil
}

// CertificateAuthorizer 只接受私有 CertificateContext，不从 caller 或请求生成权限。
type CertificateAuthorizer struct{ Authority *Authority }

func (p CertificateAuthorizer) Authorize(ctx context.Context, request certificates.Authorization) error {
	if p.Authority == nil {
		return fault.New("BACKEND_REQUIRED", "证书需要真实宿主权限后端")
	}
	grant, err := p.Authority.certificateGrant(ctx, request.Caller)
	if err != nil {
		return err
	}
	emptySpec := request.Spec.Purpose == "" && len(request.Spec.SANs) == 0
	if request.CertificateID != grant.certificateID || (!emptySpec && !sameCertificateSpec(request.Spec, grant.spec)) ||
		(request.Access != certificates.Bind && request.Access != certificates.Unbind && request.Consumer != nil) ||
		(request.Access != certificates.Unbind && (request.BindingID != "" || request.AttemptID != "")) {
		return fault.New("PERMISSION_DENIED", "证书、SAN 或消费者不属于原已接受意图")
	}
	switch request.Access {
	case certificates.Read:
		if request.Generation == 0 && request.Issuance == nil {
			return nil
		}
	case certificates.Issue, certificates.Import, certificates.TestIssue:
		if permission, ok := ctx.Value(renewalExecutionKey{}).(*renewalExecution); ok && permission != nil {
			delegation, delegated := ctx.Value(dnsExecutionKey{}).(*dnsExecution)
			if request.Access != certificates.Issue || !delegated || delegation == nil || delegation.certificate != grant {
				return fault.New("PERMISSION_DENIED", "续期不能换成普通签发、导入或测试访问")
			}
		}
		if request.Access == grant.access && request.Generation == 0 && !emptySpec && sameCertificateIssuance(request.Issuance, grant.issuance) {
			return nil
		}
	case certificates.RenewExisting:
		permission, ok := ctx.Value(renewalExecutionKey{}).(*renewalExecution)
		if ok && permission != nil && grant.access == certificates.Issue && request.Caller == permission.caller && request.Generation == 0 &&
			!emptySpec && sameCertificateIssuance(request.Issuance, grant.issuance) {
			return nil
		}
	case certificates.Remove:
		if grant.access == certificates.Remove && request.Generation == grant.generation && request.Issuance == nil {
			return nil
		}
	case certificates.Bind:
		if grant.access == certificates.Bind && request.Generation == grant.generation && request.Issuance == nil && request.Consumer != nil {
			permission, entry, err := p.Authority.bindingGrant(ctx, request.Caller)
			if err != nil {
				return err
			}
			if permission.certificate == grant && *request.Consumer == entry.Consumer {
				return nil
			}
		}
	case certificates.Unbind:
		if grant.access == certificates.Unbind && request.Generation == grant.generation && request.Issuance == nil && request.Consumer != nil &&
			request.AttemptID == grant.attemptID && request.AttemptID != "" {
			permission, entry, err := p.Authority.bindingGrant(ctx, request.Caller)
			if err != nil {
				return err
			}
			if request.BindingID == permission.id && *request.Consumer == entry.Consumer {
				return nil
			}
		}
	}
	return fault.New("PERMISSION_DENIED", "当前证书 operation 不能执行该访问、CA 或 generation")
}

var _ certificates.Authorizer = CertificateAuthorizer{}
