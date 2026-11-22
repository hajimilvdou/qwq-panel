// SPDX-License-Identifier: AGPL-3.0-only

package hostsvc_test

import (
	"testing"

	"github.com/qwq-panel/qwq/internal/pluginhost/hostsvc"
	certificatesv1 "github.com/qwq-panel/qwq/sdk/gen/qwq/capability/certificates/v1"
	dnsv1 "github.com/qwq-panel/qwq/sdk/gen/qwq/capability/dns/v1"
	platformv1 "github.com/qwq-panel/qwq/sdk/gen/qwq/platform/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// ======================== 新准备能力仍使用真实公共 gRPC 门 ========================

func TestPrerequisiteServicesRemainUnregisteredWithoutGrant(t *testing.T) {
	s := startServer(t, nil)
	if _, err := dnsv1.NewDnsServiceClient(s.Conn()).ListProviders(testContext(t), &dnsv1.ListProvidersRequest{}); status.Code(err) != codes.Unimplemented {
		t.Fatal("未获授 DNS 服务仍进入注册表")
	}
	if _, err := certificatesv1.NewCertificatesServiceClient(s.Conn()).ListCertificates(testContext(t), &certificatesv1.ListCertificatesRequest{}); status.Code(err) != codes.Unimplemented {
		t.Fatal("未获授证书服务仍进入注册表")
	}
}

func TestPrerequisiteReadGrantsCannotBecomeWrites(t *testing.T) {
	s := startServer(t, func(config *hostsvc.Config) {
		config.GrantedCapabilities = []*platformv1.Capability{capability("dns.read", "self"), capability("certificates.read", "self")}
		config.OperationResolver = &capabilityResolver{binding: hostsvc.OperationBinding{Dispatched: true, Effect: "write", Capabilities: config.GrantedCapabilities}}
	})
	ctx := &platformv1.HostCallContext{OperationId: "operation-1"}
	if _, err := dnsv1.NewDnsServiceClient(s.Conn()).ApplyRecord(testContext(t), &dnsv1.ApplyRecordRequest{Context: ctx}); status.Code(err) != codes.PermissionDenied {
		t.Fatal("DNS 只读授权成为记录写权限")
	}
	if _, err := certificatesv1.NewCertificatesServiceClient(s.Conn()).SubmitIssue(testContext(t), &certificatesv1.SubmitIssueRequest{Context: ctx}); status.Code(err) != codes.PermissionDenied {
		t.Fatal("证书只读授权成为签发权限")
	}
}

func TestPrerequisiteWritesRequireDispatchAndBackend(t *testing.T) {
	resolver := &capabilityResolver{}
	s := startServer(t, func(config *hostsvc.Config) {
		config.GrantedCapabilities = []*platformv1.Capability{capability("system.dns.manage", "self")}
		config.OperationResolver = resolver
	})
	client := dnsv1.NewDnsServiceClient(s.Conn())
	if _, err := client.ApplyRecord(testContext(t), &dnsv1.ApplyRecordRequest{}); status.Code(err) != codes.FailedPrecondition {
		t.Fatal("无 operation 的 DNS 写入未拒绝")
	}
	request := &dnsv1.ApplyRecordRequest{Context: &platformv1.HostCallContext{OperationId: "operation-1"}}
	if _, err := client.ApplyRecord(testContext(t), request); status.Code(err) != codes.PermissionDenied {
		t.Fatal("未派发的 DNS operation 获得能力")
	}
	resolver.mu.Lock()
	resolver.binding = hostsvc.OperationBinding{Dispatched: true, Effect: "write", Capabilities: []*platformv1.Capability{capability("system.dns.manage", "self")}}
	resolver.mu.Unlock()
	if _, err := client.ApplyRecord(testContext(t), request); status.Code(err) != codes.Unavailable {
		t.Fatal("缺失 DNS 执行后端被伪装成功")
	}
}

func TestPrerequisiteReadResponsesUseTypedExistingForwarder(t *testing.T) {
	forward := &capabilityForwarder{response: &certificatesv1.GetCertificateResponse{Certificate: &certificatesv1.CertificateView{Id: "certificate-1"}}}
	s := startServer(t, func(config *hostsvc.Config) {
		config.GrantedCapabilities = []*platformv1.Capability{capability("certificates.read", "self")}
		config.CapabilityForwarder = forward
	})
	response, err := certificatesv1.NewCertificatesServiceClient(s.Conn()).GetCertificate(testContext(t), &certificatesv1.GetCertificateRequest{CertificateId: "certificate-1"})
	if err != nil || response.GetCertificate().GetId() != "certificate-1" {
		t.Fatal("证书强类型响应没有通过共用转发门")
	}
	calls := forward.snapshot()
	if len(calls) != 1 || calls[0].Service != "certificates" || calls[0].Method != "GetCertificate" || calls[0].Write {
		t.Fatal("证书转发门接受了自报方法或改变效果")
	}
}
