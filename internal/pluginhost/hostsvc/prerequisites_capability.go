// SPDX-License-Identifier: AGPL-3.0-only

package hostsvc

import (
	"context"

	certificatesv1 "github.com/qwq-panel/qwq/sdk/gen/qwq/capability/certificates/v1"
	dnsv1 "github.com/qwq-panel/qwq/sdk/gen/qwq/capability/dns/v1"
)

// ======================== 独立准备能力；复用统一授权/审计门 ========================
// 方法名称和效果固定在宿主。资源、原 Args、owner 和策略由后端再次精确确认。

type dnsCapabilityService struct {
	dnsv1.UnimplementedDnsServiceServer
	s *Server
}

type certificatesCapabilityService struct {
	certificatesv1.UnimplementedCertificatesServiceServer
	s *Server
}

func (x *dnsCapabilityService) RegisterProvider(ctx context.Context, req *dnsv1.RegisterProviderRequest) (*dnsv1.RegisterProviderResponse, error) {
	return forwardCapability(x.s, ctx, req, capabilityPolicy{service: "dns", method: "RegisterProvider", verb: "dns.RegisterProvider", name: "system.dns.manage", write: true}, new(dnsv1.RegisterProviderResponse))
}

func (x *dnsCapabilityService) ListProviders(ctx context.Context, req *dnsv1.ListProvidersRequest) (*dnsv1.ListProvidersResponse, error) {
	return forwardCapability(x.s, ctx, req, capabilityPolicy{service: "dns", method: "ListProviders", verb: "dns.ListProviders", name: "dns.read"}, new(dnsv1.ListProvidersResponse))
}

func (x *dnsCapabilityService) DiscoverZones(ctx context.Context, req *dnsv1.DiscoverZonesRequest) (*dnsv1.DiscoverZonesResponse, error) {
	return forwardCapability(x.s, ctx, req, capabilityPolicy{service: "dns", method: "DiscoverZones", verb: "dns.DiscoverZones", name: "dns.read"}, new(dnsv1.DiscoverZonesResponse))
}

func (x *dnsCapabilityService) RevokeProvider(ctx context.Context, req *dnsv1.RevokeProviderRequest) (*dnsv1.RevokeProviderResponse, error) {
	return forwardCapability(x.s, ctx, req, capabilityPolicy{service: "dns", method: "RevokeProvider", verb: "dns.RevokeProvider", name: "system.dns.manage", write: true}, new(dnsv1.RevokeProviderResponse))
}

func (x *dnsCapabilityService) AuthorizeZone(ctx context.Context, req *dnsv1.AuthorizeZoneRequest) (*dnsv1.AuthorizeZoneResponse, error) {
	return forwardCapability(x.s, ctx, req, capabilityPolicy{service: "dns", method: "AuthorizeZone", verb: "dns.AuthorizeZone", name: "system.dns.manage", write: true}, new(dnsv1.AuthorizeZoneResponse))
}

func (x *dnsCapabilityService) RevokeZone(ctx context.Context, req *dnsv1.RevokeZoneRequest) (*dnsv1.RevokeZoneResponse, error) {
	return forwardCapability(x.s, ctx, req, capabilityPolicy{service: "dns", method: "RevokeZone", verb: "dns.RevokeZone", name: "system.dns.manage", write: true}, new(dnsv1.RevokeZoneResponse))
}

func (x *dnsCapabilityService) ListRecords(ctx context.Context, req *dnsv1.ListRecordsRequest) (*dnsv1.ListRecordsResponse, error) {
	return forwardCapability(x.s, ctx, req, capabilityPolicy{service: "dns", method: "ListRecords", verb: "dns.ListRecords", name: "dns.read"}, new(dnsv1.ListRecordsResponse))
}

func (x *dnsCapabilityService) ApplyRecord(ctx context.Context, req *dnsv1.ApplyRecordRequest) (*dnsv1.ApplyRecordResponse, error) {
	return forwardCapability(x.s, ctx, req, capabilityPolicy{service: "dns", method: "ApplyRecord", verb: "dns.ApplyRecord", name: "system.dns.manage", write: true}, new(dnsv1.ApplyRecordResponse))
}

func (x *dnsCapabilityService) ReconcileRecord(ctx context.Context, req *dnsv1.ReconcileRecordRequest) (*dnsv1.ReconcileRecordResponse, error) {
	return forwardCapability(x.s, ctx, req, capabilityPolicy{service: "dns", method: "ReconcileRecord", verb: "dns.ReconcileRecord", name: "system.dns.manage", write: true}, new(dnsv1.ReconcileRecordResponse))
}

func (x *dnsCapabilityService) CheckDns(ctx context.Context, req *dnsv1.CheckDnsRequest) (*dnsv1.CheckDnsResponse, error) {
	return forwardCapability(x.s, ctx, req, capabilityPolicy{service: "dns", method: "CheckDns", verb: "dns.CheckDns", name: "dns.read"}, new(dnsv1.CheckDnsResponse))
}

func (x *certificatesCapabilityService) ListCertificates(ctx context.Context, req *certificatesv1.ListCertificatesRequest) (*certificatesv1.ListCertificatesResponse, error) {
	return forwardCapability(x.s, ctx, req, capabilityPolicy{service: "certificates", method: "ListCertificates", verb: "certificates.ListCertificates", name: "certificates.read"}, new(certificatesv1.ListCertificatesResponse))
}

func (x *certificatesCapabilityService) GetCertificate(ctx context.Context, req *certificatesv1.GetCertificateRequest) (*certificatesv1.GetCertificateResponse, error) {
	return forwardCapability(x.s, ctx, req, capabilityPolicy{service: "certificates", method: "GetCertificate", verb: "certificates.GetCertificate", name: "certificates.read"}, new(certificatesv1.GetCertificateResponse))
}

func (x *certificatesCapabilityService) SubmitIssue(ctx context.Context, req *certificatesv1.SubmitIssueRequest) (*certificatesv1.SubmitIssueResponse, error) {
	return forwardCapability(x.s, ctx, req, capabilityPolicy{service: "certificates", method: "SubmitIssue", verb: "certificates.SubmitIssue", name: "system.certificates.manage", write: true}, new(certificatesv1.SubmitIssueResponse))
}

func (x *certificatesCapabilityService) SubmitImport(ctx context.Context, req *certificatesv1.SubmitImportRequest) (*certificatesv1.SubmitImportResponse, error) {
	return forwardCapability(x.s, ctx, req, capabilityPolicy{service: "certificates", method: "SubmitImport", verb: "certificates.SubmitImport", name: "system.certificates.manage", write: true}, new(certificatesv1.SubmitImportResponse))
}

func (x *certificatesCapabilityService) SubmitTestCertificate(ctx context.Context, req *certificatesv1.SubmitTestCertificateRequest) (*certificatesv1.SubmitTestCertificateResponse, error) {
	return forwardCapability(x.s, ctx, req, capabilityPolicy{service: "certificates", method: "SubmitTestCertificate", verb: "certificates.SubmitTestCertificate", name: "system.certificates.manage", write: true}, new(certificatesv1.SubmitTestCertificateResponse))
}

func (x *certificatesCapabilityService) GetTask(ctx context.Context, req *certificatesv1.GetTaskRequest) (*certificatesv1.GetTaskResponse, error) {
	return forwardCapability(x.s, ctx, req, capabilityPolicy{service: "certificates", method: "GetTask", verb: "certificates.GetTask", name: "certificates.read"}, new(certificatesv1.GetTaskResponse))
}

func (x *certificatesCapabilityService) CancelTask(ctx context.Context, req *certificatesv1.CancelTaskRequest) (*certificatesv1.CancelTaskResponse, error) {
	return forwardCapability(x.s, ctx, req, capabilityPolicy{service: "certificates", method: "CancelTask", verb: "certificates.CancelTask", name: "system.certificates.manage", write: true}, new(certificatesv1.CancelTaskResponse))
}

func (x *certificatesCapabilityService) ReserveBinding(ctx context.Context, req *certificatesv1.ReserveBindingRequest) (*certificatesv1.ReserveBindingResponse, error) {
	return forwardCapability(x.s, ctx, req, capabilityPolicy{service: "certificates", method: "ReserveBinding", verb: "certificates.ReserveBinding", name: "system.certificates.manage", write: true}, new(certificatesv1.ReserveBindingResponse))
}

func (x *certificatesCapabilityService) BindCertificate(ctx context.Context, req *certificatesv1.BindCertificateRequest) (*certificatesv1.BindCertificateResponse, error) {
	return forwardCapability(x.s, ctx, req, capabilityPolicy{service: "certificates", method: "BindCertificate", verb: "certificates.BindCertificate", name: "system.certificates.manage", write: true}, new(certificatesv1.BindCertificateResponse))
}

func (x *certificatesCapabilityService) UnbindCertificate(ctx context.Context, req *certificatesv1.UnbindCertificateRequest) (*certificatesv1.UnbindCertificateResponse, error) {
	return forwardCapability(x.s, ctx, req, capabilityPolicy{service: "certificates", method: "UnbindCertificate", verb: "certificates.UnbindCertificate", name: "system.certificates.manage", write: true}, new(certificatesv1.UnbindCertificateResponse))
}

func (x *certificatesCapabilityService) DeployBinding(ctx context.Context, req *certificatesv1.DeployBindingRequest) (*certificatesv1.DeployBindingResponse, error) {
	return forwardCapability(x.s, ctx, req, capabilityPolicy{service: "certificates", method: "DeployBinding", verb: "certificates.DeployBinding", name: "system.certificates.manage", write: true}, new(certificatesv1.DeployBindingResponse))
}

func (x *certificatesCapabilityService) RollbackBinding(ctx context.Context, req *certificatesv1.RollbackBindingRequest) (*certificatesv1.RollbackBindingResponse, error) {
	return forwardCapability(x.s, ctx, req, capabilityPolicy{service: "certificates", method: "RollbackBinding", verb: "certificates.RollbackBinding", name: "system.certificates.manage", write: true}, new(certificatesv1.RollbackBindingResponse))
}

func (x *certificatesCapabilityService) RemoveGeneration(ctx context.Context, req *certificatesv1.RemoveGenerationRequest) (*certificatesv1.RemoveGenerationResponse, error) {
	return forwardCapability(x.s, ctx, req, capabilityPolicy{service: "certificates", method: "RemoveGeneration", verb: "certificates.RemoveGeneration", name: "system.certificates.manage", write: true}, new(certificatesv1.RemoveGenerationResponse))
}

func (x *certificatesCapabilityService) RemoveCertificate(ctx context.Context, req *certificatesv1.RemoveCertificateRequest) (*certificatesv1.RemoveCertificateResponse, error) {
	return forwardCapability(x.s, ctx, req, capabilityPolicy{service: "certificates", method: "RemoveCertificate", verb: "certificates.RemoveCertificate", name: "system.certificates.manage", write: true}, new(certificatesv1.RemoveCertificateResponse))
}

func (x *certificatesCapabilityService) ConfigureRenewal(ctx context.Context, req *certificatesv1.ConfigureRenewalRequest) (*certificatesv1.ConfigureRenewalResponse, error) {
	return forwardCapability(x.s, ctx, req, capabilityPolicy{service: "certificates", method: "ConfigureRenewal", verb: "certificates.ConfigureRenewal", name: "system.certificates.manage", write: true}, new(certificatesv1.ConfigureRenewalResponse))
}

func (x *certificatesCapabilityService) RevokeRenewal(ctx context.Context, req *certificatesv1.RevokeRenewalRequest) (*certificatesv1.RevokeRenewalResponse, error) {
	return forwardCapability(x.s, ctx, req, capabilityPolicy{service: "certificates", method: "RevokeRenewal", verb: "certificates.RevokeRenewal", name: "system.certificates.manage", write: true}, new(certificatesv1.RevokeRenewalResponse))
}

func (x *certificatesCapabilityService) GetRenewal(ctx context.Context, req *certificatesv1.GetRenewalRequest) (*certificatesv1.GetRenewalResponse, error) {
	return forwardCapability(x.s, ctx, req, capabilityPolicy{service: "certificates", method: "GetRenewal", verb: "certificates.GetRenewal", name: "certificates.read"}, new(certificatesv1.GetRenewalResponse))
}
