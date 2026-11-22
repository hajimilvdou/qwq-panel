// SPDX-License-Identifier: AGPL-3.0-only

package hostauth

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/qwq-panel/qwq/internal/authz"
	"github.com/qwq-panel/qwq/internal/operations"
	"github.com/qwq-panel/qwq/internal/prerequisites/certificates"
	"github.com/qwq-panel/qwq/internal/prerequisites/dns"
	"github.com/qwq-panel/qwq/internal/tlsmgr"
)

// ======================== 复用真实宿主 fixture 的证书调用 ========================

const fixtureCertificate = "certificate-one"
const fixtureCertificateAttempt = "certificate-attempt-one"

func certificateSubject(id string) string {
	return "plugins/tls.certificates/resources/certificates/" + id
}

func certificateSpec(purpose tlsmgr.MaterialPurpose) certificates.Spec {
	return certificates.Spec{SANs: []string{"proxy.example.test"}, Purpose: purpose}
}

func (f *authorityFixture) certificateProvider(t *testing.T) (providerRegistration, string, string) {
	t.Helper()
	registered, registration, providerRevision := f.register(t)
	registered.finish()
	confirmed, _, zoneRevision := f.zone(t, f.human, "absent")
	confirmed.finish()
	return registration, providerRevision, zoneRevision
}

func issueCertificateArgs() IssueCertificateArgs {
	return IssueCertificateArgs{CertificateID: fixtureCertificate, AttemptID: fixtureCertificateAttempt,
		Spec: certificateSpec(tlsmgr.ServerTLS), ProviderID: fixtureProvider, ZoneID: fixtureZone,
		CA: certificates.LetsEncryptStaging, AcceptTerms: true}
}

func (f *authorityFixture) issueCertificate(t *testing.T) (*fixtureCall, context.Context, certificates.IssueRequest) {
	t.Helper()
	call := f.start(t, f.human, "tls.certificates", "certificates.issue", certificateSubject(fixtureCertificate), "absent", issueCertificateArgs())
	ctx, _, err := f.authority.CertificateContext(call.ctx, fixtureCertificate, fixtureCertificateAttempt, "absent")
	if err != nil {
		t.Fatal(err)
	}
	request, err := f.authority.AcceptedIssueRequest(ctx)
	if err != nil {
		t.Fatal(err)
	}
	return call, ctx, request
}

func (f *authorityFixture) testCertificate(t *testing.T) (*fixtureCall, context.Context, certificates.TestRequest) {
	t.Helper()
	call := f.start(t, f.human, "tls.certificates", "certificates.test", certificateSubject(fixtureCertificate), "absent",
		TestCertificateArgs{CertificateID: fixtureCertificate, AttemptID: fixtureCertificateAttempt, Spec: certificateSpec(tlsmgr.TestServerTLS)})
	ctx, _, err := f.authority.CertificateContext(call.ctx, fixtureCertificate, fixtureCertificateAttempt, "absent")
	if err != nil {
		t.Fatal(err)
	}
	request, err := f.authority.AcceptedTestRequest(ctx)
	if err != nil {
		t.Fatal(err)
	}
	return call, ctx, request
}

// ======================== 原 SAN、CA、provider、zone 与 caller ========================

func TestHostCertificateIssueFreezesAcceptedScope(t *testing.T) {
	f := newAuthorityFixture(t)
	f.certificateProvider(t)
	call, ctx, request := f.issueCertificate(t)
	authorizer := CertificateAuthorizer{Authority: f.authority}
	valid := certificates.Authorization{Caller: request.Caller, CertificateID: request.CertificateID, Spec: request.Scope.Spec, Issuance: &request.Scope, Access: certificates.Issue}
	if err := authorizer.Authorize(ctx, valid); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*certificates.Authorization){
		func(r *certificates.Authorization) { r.Caller.OwnerID = "other-owner" },
		func(r *certificates.Authorization) { r.Caller.OperationID = "other-operation" },
		func(r *certificates.Authorization) {
			r.Caller.PolicyID, r.Caller.PolicyRevision = "policy-one", "revision-one"
		},
		func(r *certificates.Authorization) { r.CertificateID = "other-certificate" },
		func(r *certificates.Authorization) { r.Spec.SANs = []string{"other.example.test"} },
		func(r *certificates.Authorization) { r.Spec.Purpose = tlsmgr.TestServerTLS },
		func(r *certificates.Authorization) { r.Issuance.CA = certificates.LetsEncrypt },
		func(r *certificates.Authorization) { r.Issuance.Provider.ProviderID = "other-provider" },
		func(r *certificates.Authorization) { r.Issuance.Provider.ZoneID = "other-zone" },
		func(r *certificates.Authorization) { r.Issuance.Provider.ZoneName = "other.test" },
		func(r *certificates.Authorization) { r.Issuance.Provider.Kind = dns.Aliyun },
		func(r *certificates.Authorization) { r.Issuance.Provider.Revision = stringsDigest('a') },
		func(r *certificates.Authorization) { r.Generation = 1 },
		func(r *certificates.Authorization) { r.Consumer = &certificates.Consumer{PluginID: "core.xray"} },
		func(r *certificates.Authorization) { r.Access = certificates.Import },
		func(r *certificates.Authorization) { r.Access = certificates.Bind },
		func(r *certificates.Authorization) { r.Access = certificates.ConfigureRenewal },
		func(r *certificates.Authorization) { r.Access = certificates.RenewExisting },
		func(r *certificates.Authorization) { r.Access = "unknown" },
	} {
		changed := valid
		changed.Spec = cloneCertificateSpec(valid.Spec)
		scope := cloneCertificateIssuance(*valid.Issuance)
		changed.Issuance = &scope
		change(&changed)
		requireCode(t, authorizer.Authorize(ctx, changed), "PERMISSION_DENIED")
	}
	request.Scope.Spec.SANs[0] = "replacement.example.test"
	again, err := f.authority.AcceptedIssueRequest(ctx)
	if err != nil || again.Scope.Spec.SANs[0] != "proxy.example.test" || again.Caller.OperationID != call.invocation.OperationID || again.ExpectedRevision != "absent" {
		t.Fatal("返回值修改影响了私有授权，或原 operation/版本丢失")
	}
	for _, target := range []struct{ id, attempt, revision string }{
		{"other-certificate", fixtureCertificateAttempt, "absent"},
		{fixtureCertificate, "other-attempt", "absent"},
		{fixtureCertificate, fixtureCertificateAttempt, stringsDigest('a')},
	} {
		_, _, err := f.authority.CertificateContext(call.ctx, target.id, target.attempt, target.revision)
		requireCode(t, err, "PERMISSION_DENIED")
	}
	grant := ctx.Value(certificateExecutionKey{}).(*certificateExecution)
	raw, err := json.Marshal(grant)
	if err != nil || strings.Contains(string(raw)+fmt.Sprintf("%#v", grant), fixtureCertificate) {
		t.Fatal("私有证书范围进入日志或 JSON")
	}
}

func TestHostCertificateRejectsInvalidIssuanceIntent(t *testing.T) {
	f := newAuthorityFixture(t)
	f.certificateProvider(t)
	for _, test := range []struct {
		name, code string
		change     func(*IssueCertificateArgs)
	}{
		{"terms", "TERMS_REQUIRED", func(r *IssueCertificateArgs) { r.AcceptTerms = false }},
		{"ca", "CERTIFICATE_PURPOSE_INVALID", func(r *IssueCertificateArgs) { r.CA = "private-ca" }},
		{"san", "ZONE_DENIED", func(r *IssueCertificateArgs) { r.Spec.SANs = []string{"proxy.other.test"} }},
		{"empty-san", "SAN_INVALID", func(r *IssueCertificateArgs) { r.Spec.SANs = nil }},
		{"test-purpose", "CERTIFICATE_PURPOSE_INVALID", func(r *IssueCertificateArgs) { r.Spec.Purpose = tlsmgr.TestServerTLS }},
		{"provider", "ZONE_DENIED", func(r *IssueCertificateArgs) { r.ProviderID = "other-provider" }},
		{"zone", "ZONE_DENIED", func(r *IssueCertificateArgs) { r.ZoneID = "other-zone" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			input := issueCertificateArgs()
			input.CertificateID = "invalid-" + test.name
			test.change(&input)
			call := f.start(t, f.human, "tls.certificates", "certificates.issue", certificateSubject(input.CertificateID), "absent", input)
			defer call.finish()
			_, _, err := f.authority.CertificateContext(call.ctx, input.CertificateID, input.AttemptID, "absent")
			requireCode(t, err, test.code)
			_, _, found, err := f.authority.loadCertificate(f.ctx, input.CertificateID)
			if err != nil || found {
				t.Fatal("无效原意图留下了证书授权登记")
			}
		})
	}
}

func TestHostCertificateRequiresActualCapabilityAndPermission(t *testing.T) {
	for _, change := range []func(*operations.Action){
		func(a *operations.Action) { a.Permission = "system.dns:manage" },
		func(a *operations.Action) { a.Capabilities = nil },
	} {
		f := newAuthorityFixture(t)
		args := TestCertificateArgs{CertificateID: fixtureCertificate, AttemptID: fixtureCertificateAttempt, Spec: certificateSpec(tlsmgr.TestServerTLS)}
		job, invocation := f.dispatchCall(t, f.human, "tls.certificates", "certificates.test", certificateSubject(fixtureCertificate), "absent", args, change)
		ctx, release, err := f.authority.Begin(job.ctx, invocation)
		if err != nil {
			t.Fatal(err)
		}
		_, _, err = f.authority.CertificateContext(ctx, fixtureCertificate, fixtureCertificateAttempt, "absent")
		release()
		requireCode(t, err, "PERMISSION_DENIED")
	}
}

func TestHostCertificateTargetValidationAndViewerRead(t *testing.T) {
	f := newAuthorityFixture(t)
	created, _, _ := f.testCertificate(t)
	created.finish()
	viewer := f.user(t, "certificate-viewer", authz.RoleViewer)
	read := f.start(t, viewer, "tls.certificates", "certificates.get", certificateSubject(fixtureCertificate), "", CertificateTargetArgs{CertificateID: fixtureCertificate})
	ctx, caller, err := f.authority.CertificateContext(read.ctx, fixtureCertificate, "", "")
	if err != nil {
		t.Fatal(err)
	}
	authorizer := CertificateAuthorizer{Authority: f.authority}
	if err := authorizer.Authorize(ctx, certificates.Authorization{Caller: caller, CertificateID: fixtureCertificate, Access: certificates.Read}); err != nil {
		t.Fatal(err)
	}
	requireCode(t, authorizer.Authorize(ctx, certificates.Authorization{Caller: caller, CertificateID: fixtureCertificate, Access: certificates.Remove}), "PERMISSION_DENIED")
	read.finish()
	for _, test := range []struct {
		operation string
		input     CertificateTargetArgs
	}{
		{"certificates.get", CertificateTargetArgs{CertificateID: fixtureCertificate, AttemptID: "foreign-attempt"}},
		{"certificates.get", CertificateTargetArgs{CertificateID: fixtureCertificate, Generation: 1}},
		{"certificates.remove", CertificateTargetArgs{CertificateID: fixtureCertificate}},
		{"certificates.remove", CertificateTargetArgs{CertificateID: fixtureCertificate, AttemptID: "bad/attempt"}},
		{"certificates.remove", CertificateTargetArgs{CertificateID: fixtureCertificate, AttemptID: "remove-one", Generation: 1}},
		{"generations.remove", CertificateTargetArgs{CertificateID: fixtureCertificate, AttemptID: "remove-one"}},
	} {
		call := f.start(t, f.human, "tls.certificates", test.operation, certificateSubject(fixtureCertificate), stringsDigest('a'), test.input)
		_, _, err := f.authority.CertificateContext(call.ctx, fixtureCertificate, test.input.AttemptID, stringsDigest('a'))
		call.finish()
		requireCode(t, err, "VALIDATION_FAILED")
	}
}
