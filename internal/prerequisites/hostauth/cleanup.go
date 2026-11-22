// SPDX-License-Identifier: AGPL-3.0-only

package hostauth

import (
	"bytes"
	"context"
	"slices"
	"sync"
	"time"

	"github.com/qwq-panel/qwq/internal/actor"
	"github.com/qwq-panel/qwq/internal/operations"
	"github.com/qwq-panel/qwq/internal/prerequisites/acme"
	"github.com/qwq-panel/qwq/internal/prerequisites/certificates"
	"github.com/qwq-panel/qwq/internal/prerequisites/dns"
	"github.com/qwq-panel/qwq/internal/prerequisites/fault"
	"github.com/qwq-panel/qwq/internal/prerequisites/names"
	"github.com/qwq-panel/qwq/internal/prerequisites/provider"
)

// ======================== 正常原 CA 请求的私有 DNS 委托 ========================

type certificateDNSRequestKey struct{}
type certificateDNSRequest struct {
	parent *certificateExecution
	intent dns.ChallengeIntent
}

func certificateDNSCaller(ctx context.Context, caller dns.Caller) certificates.Caller {
	base := certificates.Caller{OwnerID: caller.OwnerID, OperationID: caller.OperationID}
	if permission, ok := ctx.Value(renewalExecutionKey{}).(*renewalExecution); ok && permission != nil &&
		permission.caller.OwnerID == caller.OwnerID && permission.caller.OperationID == caller.OperationID {
		return permission.caller
	}
	return base
}

// CertificateDNSContexts 只委托原已接受证书的正常 DNS 请求，取消清理使用另一接口。
type CertificateDNSContexts struct{ Authority *Authority }

func (p CertificateDNSContexts) Context(ctx context.Context, caller certificates.Caller, certificateID, attemptID string, scope certificates.IssuanceScope, cleanup bool) (context.Context, error) {
	if p.Authority == nil || p.Authority.challenges == nil {
		return nil, fault.New("BACKEND_REQUIRED", "证书 DNS 需要真实私有 CA 请求后端")
	}
	a := p.Authority
	grant, err := a.certificateGrant(ctx, caller)
	if err != nil {
		return nil, err
	}
	if cleanup || grant.access != certificates.Issue || grant.certificateID != certificateID || grant.attemptID != attemptID ||
		!sameCertificateIssuance(grant.issuance, &scope) {
		return nil, fault.New("PERMISSION_DENIED", "证书 DNS 委托不属于原正常签发意图")
	}
	delegation := &dnsExecution{parent: grant.parent, scope: scope.Provider, providerRevision: grant.providerRevision,
		zoneRevision: grant.zoneRevision, challenge: true, certificate: grant}
	return context.WithValue(ctx, dnsExecutionKey{}, delegation), nil
}

func (a *Authority) checkCertificateDNS(ctx context.Context, caller dns.Caller, grant *dnsExecution, access dns.Access) error {
	certificate := grant.certificate
	if certificate == nil || a.challenges == nil || (access != dns.Read && access != dns.Challenge) {
		return fault.New("PERMISSION_DENIED", "证书 DNS 不能执行普通记录管理或宽范围清理")
	}
	certCaller := certificateDNSCaller(ctx, caller)
	if err := (CertificateAuthorizer{Authority: a}).Authorize(ctx, certificates.Authorization{Caller: certCaller, CertificateID: certificate.certificateID,
		Spec: certificate.spec, Issuance: certificate.issuance, Access: certificates.Issue}); err != nil {
		return err
	}
	if ctx.Value(certificateExecutionKey{}) != certificate {
		return fault.New("PERMISSION_DENIED", "DNS 委托被用于另一个证书上下文")
	}
	request, found := ctx.Value(certificateDNSRequestKey{}).(*certificateDNSRequest)
	if !found || request == nil {
		if access == dns.Read {
			return nil // 原 zone 的 baseline/CAA/传播读取仍有正常 operation 权限。
		}
		return fault.New("PERMISSION_DENIED", "DNS challenge 缺少原 CA 实际请求")
	}
	if request.parent != certificate || request.intent.Caller != caller || request.intent.Scope != grant.scope {
		return fault.New("PERMISSION_DENIED", "DNS challenge 的私有请求范围发生变化")
	}
	return a.challenges.Match(ctx, certCaller, certificate.certificateID, certificate.attemptID, *certificate.issuance, request.intent, false)
}

func (p DNSAuthorizer) ChallengeContext(ctx context.Context, intent dns.ChallengeIntent) (context.Context, error) {
	if p.Authority == nil || p.Authority.challenges == nil || ctx == nil {
		return nil, fault.New("BACKEND_REQUIRED", "DNS challenge 需要真实原 CA journal")
	}
	a := p.Authority
	grant, found := ctx.Value(dnsExecutionKey{}).(*dnsExecution)
	if !found || grant == nil || grant.certificate == nil || grant.scope != intent.Scope || intent.CertificateID != grant.certificate.certificateID {
		return nil, fault.New("PERMISSION_DENIED", "DNS 实际请求没有原证书私有委托")
	}
	if err := a.checkDNS(ctx, intent.Caller, intent.Scope, dns.Read); err != nil {
		return nil, err
	}
	cert := grant.certificate
	caller := certificateDNSCaller(ctx, intent.Caller)
	if err := a.challenges.Match(ctx, caller, cert.certificateID, cert.attemptID, *cert.issuance, intent, false); err != nil {
		return nil, err
	}
	bound := context.WithValue(ctx, certificateDNSRequestKey{}, &certificateDNSRequest{parent: cert, intent: intent})
	if err := a.checkDNS(bound, intent.Caller, intent.Scope, dns.Challenge); err != nil {
		return nil, err
	}
	return bound, nil
}

// ======================== 首次 Source 开窗与逐记录不可序列化许可 ========================

type cleanupPreparationKey struct{}
type cleanupExecutionKey struct{}

type cleanupPreparation struct {
	mu        sync.RWMutex
	released  bool
	authority *Authority
	parent    *execution
	cert      *certificateExecution
	snapshot  operations.DispatchedContext
	caller    certificates.Caller
	scope     certificates.IssuanceScope
	ttl       time.Duration
}

type cleanupExecution struct {
	preparation *cleanupPreparation
	owned       dns.OwnedChallenge
	lease       *operations.CleanupLease
	source      operations.CleanupSource
}

func (*cleanupPreparation) String() string               { return "hostauth.cleanupPreparation{[REDACTED]}" }
func (*cleanupPreparation) GoString() string             { return "hostauth.cleanupPreparation{[REDACTED]}" }
func (*cleanupPreparation) MarshalJSON() ([]byte, error) { return []byte(`{"redacted":true}`), nil }
func (*cleanupExecution) String() string                 { return "hostauth.cleanupExecution{[REDACTED]}" }
func (*cleanupExecution) GoString() string               { return "hostauth.cleanupExecution{[REDACTED]}" }
func (*cleanupExecution) MarshalJSON() ([]byte, error)   { return []byte(`{"redacted":true}`), nil }

// CertificateCleanupContexts 固定宿主与 DNS Manager，不从 RPC 选择 owner/路径/凭据。
type CertificateCleanupContexts struct {
	Authority *Authority
	DNS       *dns.Manager
	Timeout   time.Duration
}

func copyCleanupSnapshot(value *execution) (operations.DispatchedContext, error) {
	value.mu.RLock()
	defer value.mu.RUnlock()
	if value.released {
		return operations.DispatchedContext{}, fault.New("PERMISSION_DENIED", "原宿主执行上下文已释放")
	}
	snapshot := value.snapshot
	snapshot.Args = bytes.Clone(value.snapshot.Args)
	snapshot.Action.Capabilities = slices.Clone(value.snapshot.Action.Capabilities)
	return snapshot, nil
}

func (p CertificateCleanupContexts) Source(ctx context.Context, caller certificates.Caller, certificateID, issueAttemptID string, scope certificates.IssuanceScope) (context.Context, context.CancelFunc, error) {
	if p.Authority == nil || p.Authority.challenges == nil || p.DNS == nil || ctx == nil {
		return nil, nil, fault.New("BACKEND_REQUIRED", "原证书清理需要真实 CA journal 与自有 TXT 后端")
	}
	parent, found := ctx.Value(executionKey{}).(*execution)
	cert, hasCert := ctx.Value(certificateExecutionKey{}).(*certificateExecution)
	a := p.Authority
	permission, hasRenewal := ctx.Value(renewalExecutionKey{}).(*renewalExecution)
	validRenewal := hasRenewal && permission != nil && permission.authority == a && permission.parent == parent &&
		permission.caller == caller && permission.scope.CertificateID == certificateID && sameCertificateIssuance(&permission.scope.Issuance, &scope)
	if !found || !hasCert || parent == nil || cert == nil || parent.authority != a || cert.parent != parent ||
		(parent.snapshot.Actor.Kind == actor.Service && !validRenewal) ||
		(caller != (certificates.Caller{OwnerID: a.ownerID, OperationID: parent.invocation.OperationID}) && !validRenewal) || cert.access != certificates.Issue ||
		certificateID != cert.certificateID || issueAttemptID != cert.attemptID || !sameCertificateIssuance(cert.issuance, &scope) {
		return nil, nil, fault.New("PERMISSION_DENIED", "清理 Source 不是原证书和签发意图")
	}
	ttl := p.Timeout
	if ttl == 0 {
		ttl = 15 * time.Second
	}
	if ttl <= 0 || ttl > 30*time.Second {
		return nil, nil, fault.New("VALIDATION_FAILED", "原清理窗口预算无效")
	}
	snapshot, err := copyCleanupSnapshot(parent)
	if err != nil {
		return nil, nil, err
	}
	source := operations.CleanupSource{CertificateID: certificateID, IssueAttemptID: issueAttemptID}
	bounded, cancel, err := a.operations.CleanupSourceContext(ctx, snapshot, source, ttl)
	if err != nil {
		snapshot.Clear()
		return nil, nil, err
	}
	preparation := &cleanupPreparation{authority: a, parent: parent, cert: cert, snapshot: snapshot, caller: caller,
		scope: cloneCertificateIssuance(scope), ttl: ttl}
	bound := context.WithValue(bounded, cleanupPreparationKey{}, preparation)
	var once sync.Once
	stop := func() {
		once.Do(func() {
			cancel()
			preparation.mu.Lock()
			defer preparation.mu.Unlock()
			preparation.released = true
			preparation.snapshot.Clear()
		})
	}
	if err := a.checkCleanupPreparation(bound, preparation, source); err != nil {
		stop()
		return nil, nil, err
	}
	return bound, stop, nil
}

func (p *cleanupPreparation) snapshotCopy() (operations.DispatchedContext, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.released {
		return operations.DispatchedContext{}, fault.New("PERMISSION_DENIED", "清理读取上下文已释放")
	}
	p.parent.mu.RLock()
	defer p.parent.mu.RUnlock()
	if p.parent.released {
		return operations.DispatchedContext{}, fault.New("PERMISSION_DENIED", "原宿主执行上下文已释放")
	}
	copy := p.snapshot
	copy.Args = bytes.Clone(p.snapshot.Args)
	return copy, nil
}

func (a *Authority) cleanupRegistration(ctx context.Context, p *cleanupPreparation) error {
	state, revision, found, err := a.loadCertificate(ctx, p.cert.certificateID)
	if err != nil {
		return err
	}
	if !found || revision != p.cert.registryRevision || !sameCertificateSpec(state.Spec, p.cert.spec) {
		return fault.New("PERMISSION_DENIED", "原证书清理登记或 SAN 已变化")
	}
	actual, providerRevision, zoneRevision, err := a.resolveScope(ctx, p.scope.Provider.ProviderID, p.scope.Provider.ZoneID)
	if err != nil {
		return err
	}
	if actual != p.scope.Provider || providerRevision != p.cert.providerRevision || zoneRevision != p.cert.zoneRevision {
		return fault.New("CREDENTIAL_REVOKED", "原清理提供商或 zone 版本已变化")
	}
	return nil
}

func (a *Authority) checkCleanupPreparation(ctx context.Context, p *cleanupPreparation, source operations.CleanupSource) error {
	if p == nil || p.cert == nil || p.parent == nil || p.authority != a || source.CertificateID != p.cert.certificateID || source.IssueAttemptID != p.cert.attemptID {
		return fault.New("PERMISSION_DENIED", "原清理读取来源不匹配")
	}
	snapshot, err := p.snapshotCopy()
	if err != nil {
		return err
	}
	defer snapshot.Clear()
	if err := a.operations.CheckCleanupSource(ctx, snapshot, source, p.ttl); err != nil {
		return err
	}
	if err := a.cleanupRegistration(ctx, p); err != nil {
		return err
	}
	return a.operations.CheckCleanupSource(ctx, snapshot, source, p.ttl)
}

func (p CertificateCleanupContexts) ForChallenge(ctx context.Context, caller certificates.Caller, certificateID, issueAttemptID string, scope certificates.IssuanceScope, owned dns.OwnedChallenge) (context.Context, context.CancelFunc, error) {
	if ctx == nil {
		return nil, nil, fault.New("PERMISSION_DENIED", "原自有 TXT 许可缺少宿主上下文")
	}
	preparation, found := ctx.Value(cleanupPreparationKey{}).(*cleanupPreparation)
	if p.Authority == nil || !found || preparation == nil || preparation.authority != p.Authority || !owned.BelongsTo(p.DNS) ||
		caller != preparation.caller || certificateID != preparation.cert.certificateID || issueAttemptID != preparation.cert.attemptID ||
		!sameCertificateIssuance(&preparation.scope, &scope) || owned.CertificateID() != certificateID || owned.Scope() != scope.Provider ||
		owned.Caller() != (dns.Caller{OwnerID: caller.OwnerID, OperationID: caller.OperationID}) || !names.ID(owned.DNSAttemptID()) {
		return nil, nil, fault.New("PERMISSION_DENIED", "原自有 TXT 许可的证书、scope 或 DNS attempt 无效")
	}
	record := owned.Record()
	if !names.ID(record.ID) || !validDigest(record.Revision) {
		return nil, nil, fault.New("PERMISSION_DENIED", "原自有 TXT 缺少完整身份或指纹")
	}
	source := operations.CleanupSource{CertificateID: certificateID, IssueAttemptID: issueAttemptID, DNSAttemptID: owned.DNSAttemptID()}
	a := p.Authority
	if err := a.checkCleanupPreparation(ctx, preparation, source); err != nil {
		return nil, nil, err
	}
	if err := a.challenges.Match(ctx, caller, certificateID, issueAttemptID, scope, owned.Intent(), true); err != nil {
		return nil, nil, err
	}
	snapshot, err := preparation.snapshotCopy()
	if err != nil {
		return nil, nil, err
	}
	defer snapshot.Clear()
	lease, err := a.operations.NewCleanupLease(ctx, snapshot, source, record.ID, record.Revision, preparation.ttl)
	if err != nil {
		return nil, nil, err
	}
	bounded, cancel, err := a.operations.CleanupContext(ctx, lease, source, record.ID, record.Revision)
	if err != nil {
		return nil, nil, err
	}
	execution := &cleanupExecution{preparation: preparation, owned: owned, lease: lease, source: source}
	bound := context.WithValue(bounded, cleanupExecutionKey{}, execution)
	if err := a.checkCleanupExecution(bound, owned.Caller(), owned.Scope(), execution); err != nil {
		cancel()
		return nil, nil, err
	}
	return bound, cancel, nil
}

func (a *Authority) checkCleanupExecution(ctx context.Context, caller dns.Caller, scope dns.Scope, execution *cleanupExecution) error {
	if execution == nil || execution.preparation == nil || execution.preparation.authority != a || caller != execution.owned.Caller() ||
		scope != execution.owned.Scope() || execution.source.DNSAttemptID == "" {
		return fault.New("PERMISSION_DENIED", "缺少原自有 TXT 的私有清理许可")
	}
	p := execution.preparation
	snapshot, err := p.snapshotCopy()
	if err != nil {
		return err
	}
	snapshot.Clear() // 只检查宿主 release；实际当前权限由原不可变 lease 校验。
	record := execution.owned.Record()
	if err := a.operations.CheckCleanupLease(ctx, execution.lease, execution.source, record.ID, record.Revision); err != nil {
		return err
	}
	if err := a.cleanupRegistration(ctx, p); err != nil {
		return err
	}
	if err := a.challenges.Match(ctx, p.caller, p.cert.certificateID, p.cert.attemptID, p.scope, execution.owned.Intent(), true); err != nil {
		return err
	}
	return a.operations.CheckCleanupLease(ctx, execution.lease, execution.source, record.ID, record.Revision)
}

// ======================== 仅私有 context 的权限与凭据选路 ========================

// RequestDNSAuthorizer 保持普通权限路径，只有绑定原记录的私有 context 能清理。
// 通过嵌入复用实际请求钩子，Source-only/错误私有值不会回落到普通 DNS 权限。
type RequestDNSAuthorizer struct{ DNSAuthorizer }

func (p RequestDNSAuthorizer) Authorize(ctx context.Context, caller dns.Caller, scope dns.Scope, access dns.Access) error {
	if p.Authority == nil || ctx == nil {
		return fault.New("BACKEND_REQUIRED", "DNS 权限选路需要真实宿主后端")
	}
	private := ctx.Value(cleanupPreparationKey{}) != nil || ctx.Value(cleanupExecutionKey{}) != nil
	if !private {
		return p.DNSAuthorizer.Authorize(ctx, caller, scope, access)
	}
	execution, found := ctx.Value(cleanupExecutionKey{}).(*cleanupExecution)
	if !found || execution == nil || (access != dns.Read && access != dns.Cleanup) {
		return fault.New("PERMISSION_DENIED", "Source或错误私有context不能执行DNS请求")
	}
	return p.Authority.checkCleanupExecution(ctx, caller, scope, execution)
}

func (p DNSAuthorizer) AuthorizeChallengeSource(ctx context.Context, caller dns.Caller, scope dns.Scope, certificateID, attemptID string) error {
	if p.Authority == nil || p.Authority.challenges == nil || ctx == nil || !names.ID(attemptID) {
		return fault.New("BACKEND_REQUIRED", "原 TXT 查询需要真实宿主 CA journal")
	}
	if ctx.Value(cleanupPreparationKey{}) == nil && ctx.Value(cleanupExecutionKey{}) == nil {
		grant, found := ctx.Value(dnsExecutionKey{}).(*dnsExecution)
		if !found || grant == nil || grant.certificate == nil || grant.scope != scope || grant.certificate.certificateID != certificateID {
			return fault.New("PERMISSION_DENIED", "原 TXT 查询缺少正常证书私有委托")
		}
		if err := p.Authority.checkDNS(ctx, caller, scope, dns.Read); err != nil {
			return err
		}
		certificate := grant.certificate
		certCaller := certificateDNSCaller(ctx, caller)
		if _, err := p.Authority.challenges.Intent(ctx, certCaller, certificateID, certificate.attemptID, *certificate.issuance, attemptID, false); err != nil {
			return err
		}
		return p.Authority.checkDNS(ctx, caller, scope, dns.Read)
	}
	preparation, found := ctx.Value(cleanupPreparationKey{}).(*cleanupPreparation)
	if !found || preparation == nil || preparation.cert == nil || preparation.authority != p.Authority ||
		caller != (dns.Caller{OwnerID: preparation.caller.OwnerID, OperationID: preparation.caller.OperationID}) ||
		scope != preparation.scope.Provider || certificateID != preparation.cert.certificateID {
		return fault.New("PERMISSION_DENIED", "私有 TXT 查询不是原证书和scope")
	}
	if value := ctx.Value(cleanupExecutionKey{}); value != nil {
		execution, valid := value.(*cleanupExecution)
		if !valid || execution == nil || execution.source.DNSAttemptID != attemptID {
			return fault.New("PERMISSION_DENIED", "记录清理context不能查询其他DNS attempt")
		}
		if err := p.Authority.checkCleanupExecution(ctx, caller, scope, execution); err != nil {
			return err
		}
	}
	source := operations.CleanupSource{CertificateID: certificateID, IssueAttemptID: preparation.cert.attemptID, DNSAttemptID: attemptID}
	if err := p.Authority.checkCleanupPreparation(ctx, preparation, source); err != nil {
		return err
	}
	if _, err := p.Authority.challenges.Intent(ctx, preparation.caller, certificateID, preparation.cert.attemptID, preparation.scope, attemptID, true); err != nil {
		return err
	}
	return p.Authority.checkCleanupPreparation(ctx, preparation, source)
}

func (p DNSAuthorizer) AuthorizeChallengeCleanup(ctx context.Context, owned dns.OwnedChallenge) error {
	if p.Authority == nil || ctx == nil {
		return fault.New("BACKEND_REQUIRED", "原自有 TXT 清理需要真实宿主授权")
	}
	execution, found := ctx.Value(cleanupExecutionKey{}).(*cleanupExecution)
	if !found || execution == nil || !execution.owned.SameRecord(owned) {
		return fault.New("PERMISSION_DENIED", "清理实际记录不属于原已确认ID和完整指纹")
	}
	return p.Authority.checkCleanupExecution(ctx, owned.Caller(), owned.Scope(), execution)
}

// CleanupCredentials 只为当前绑定记录请求代用凭据，不向 Source 或普通 context 揭示。
type CleanupCredentials struct{ Authority *Authority }

func (p CleanupCredentials) Read(ctx context.Context, scope dns.Scope) (provider.Credentials, error) {
	if p.Authority == nil || ctx == nil {
		return provider.Credentials{}, fault.New("BACKEND_REQUIRED", "原记录清理需要真实宿主凭据后端")
	}
	execution, found := ctx.Value(cleanupExecutionKey{}).(*cleanupExecution)
	if !found || execution == nil {
		return provider.Credentials{}, fault.New("PERMISSION_DENIED", "私有journal读取或普通context不能取清理凭据")
	}
	a := p.Authority
	if err := a.checkCleanupExecution(ctx, execution.owned.Caller(), scope, execution); err != nil {
		return provider.Credentials{}, err
	}
	registration, revision, found, err := a.loadProvider(ctx, scope.ProviderID)
	if err != nil {
		return provider.Credentials{}, err
	}
	if !found || registration.Phase != providerActive || revision != execution.preparation.cert.providerRevision {
		return provider.Credentials{}, fault.New("CREDENTIAL_REVOKED", "原清理凭据已撤销或提供商版本变化")
	}
	credentials, err := a.providerCredentials(ctx, registration)
	if err != nil {
		return provider.Credentials{}, err
	}
	if err := a.checkCleanupExecution(ctx, execution.owned.Caller(), scope, execution); err != nil {
		credentials.Clear()
		return provider.Credentials{}, err
	}
	return credentials, nil
}

// CredentialSource 由宿主固定构造；普通路径仍复用 Authority.Read 的严格派发规则。
type CredentialSource struct{ Authority *Authority }

func (p CredentialSource) Read(ctx context.Context, scope dns.Scope) (provider.Credentials, error) {
	if p.Authority == nil || ctx == nil {
		return provider.Credentials{}, fault.New("BACKEND_REQUIRED", "DNS凭据选路缺少真实宿主后端")
	}
	if ctx.Value(cleanupPreparationKey{}) != nil || ctx.Value(cleanupExecutionKey{}) != nil {
		return CleanupCredentials(p).Read(ctx, scope)
	}
	return p.Authority.Read(ctx, scope)
}

var _ acme.DNSContexts = CertificateDNSContexts{}
var _ acme.CleanupContexts = CertificateCleanupContexts{}
var _ dns.Authorizer = RequestDNSAuthorizer{}
var _ dns.ChallengeAuthorizations = RequestDNSAuthorizer{}
var _ provider.CredentialSource = CleanupCredentials{}
var _ provider.CredentialSource = CredentialSource{}
