// SPDX-License-Identifier: AGPL-3.0-only

package hostauth

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"testing"

	"github.com/qwq-panel/qwq/internal/operations"
	"github.com/qwq-panel/qwq/internal/platform/ids"
	"github.com/qwq-panel/qwq/internal/platform/problem"
	"github.com/qwq-panel/qwq/internal/prerequisites/certificates"
	"github.com/qwq-panel/qwq/internal/prerequisites/testsupport"
	"github.com/qwq-panel/qwq/internal/secrets"
	"github.com/qwq-panel/qwq/internal/tlsmgr"
)

// ======================== 真实 ExtractSecrets、PEM、加密材料与引用授权 ========================

type certificateFixtureRoots struct{ pool *x509.CertPool }

func (r certificateFixtureRoots) Roots(context.Context, tlsmgr.TrustClass) (*x509.CertPool, error) {
	return r.pool, nil
}

func signedHostCertificate(t *testing.T, f *authorityFixture) testsupport.Certificate {
	t.Helper()
	certificate, err := testsupport.SignedCertificate(f.clock.Now(), func(leaf *x509.Certificate) {
		leaf.DNSNames = []string{"proxy.example.test"}
	}, 0)
	if err != nil {
		t.Fatal(err)
	}
	return certificate
}

func (f *authorityFixture) importCertificate(t *testing.T, certificate testsupport.Certificate, id, attempt string) (*fixtureCall, context.Context, certificates.ImportRequest) {
	t.Helper()
	call := f.start(t, f.human, "tls.certificates", "certificates.import", certificateSubject(id), "absent",
		map[string]any{"certificate_id": id, "attempt_id": attempt, "spec": certificateSpec(tlsmgr.ServerTLS),
			"chain_pem": string(certificate.Chain), "private_key": string(certificate.Key), "trust": tlsmgr.PublicTrust})
	ctx, _, err := f.authority.CertificateContext(call.ctx, id, attempt, "absent")
	if err != nil {
		t.Fatal(err)
	}
	request, err := f.authority.AcceptedImportRequest(ctx)
	if err != nil {
		t.Fatal(err)
	}
	return call, ctx, request
}

func TestHostCertificateImportReadsOnlyOriginalExtractedPrivateKey(t *testing.T) {
	f := newAuthorityFixture(t)
	certificate := signedHostCertificate(t, f)
	defer certificate.Clear()
	_, ctx, request := f.importCertificate(t, certificate, fixtureCertificate, fixtureCertificateAttempt)
	ref, err := secrets.ParseRef(request.PrivateKeyRef)
	if err != nil {
		t.Fatal(err)
	}
	input, err := DecodeArguments[ImportCertificateArgs](ctx, f.authority)
	if err != nil || bytes.Contains(input.PrivateKey, certificate.Key) {
		t.Fatal("原 private_key 没有沿真实 ExtractSecrets 变为私有引用")
	}
	extracted, valid := operationSecret(input.PrivateKey)
	if !valid || extracted != ref {
		t.Fatal("后端引用不属于原被接受参数")
	}
	key, err := f.authority.ReadImportKey(ctx, request.Caller, request.PrivateKeyRef)
	if err != nil || !bytes.Equal(key, certificate.Key) {
		clear(key)
		t.Fatal("原受控 PEM 读取失败")
	}
	clear(key)
	vault, err := certificates.NewVault(certificates.VaultOptions{DB: f.db, Secrets: f.secrets, Imports: f.authority,
		Roots: certificateFixtureRoots{certificate.Roots}, Clock: f.clock})
	if err != nil {
		t.Fatal(err)
	}
	material, err := vault.Import(ctx, request.Caller, request.CertificateID, request.AttemptID, request.ChainPEM, request.PrivateKeyRef, request.Spec, request.Trust)
	if err != nil {
		t.Fatal(err)
	}
	metadata, err := vault.Inspect(ctx, request.Caller, request.CertificateID, material, request.Spec, request.Trust)
	if err != nil || metadata.SANs[0] != "proxy.example.test" {
		t.Fatal("真实材料库没有校验原 exact SAN")
	}
	_, _, other := f.importCertificate(t, certificate, "certificate-two", "certificate-attempt-two")
	otherRef, err := secrets.ParseRef(other.PrivateKeyRef)
	if err != nil {
		t.Fatal(err)
	}
	requireCode(t, f.authority.AllowImportKey(ctx, request.Caller, otherRef), "PERMISSION_DENIED")
	foreign := request.Caller
	foreign.OperationID = other.Caller.OperationID
	requireCode(t, f.authority.AllowImportKey(ctx, foreign, ref), "PERMISSION_DENIED")
	if key, err := f.authority.ReadImportKey(context.Background(), request.Caller, request.PrivateKeyRef); err == nil || len(key) != 0 {
		clear(key)
		t.Fatal("普通 context 获得了导入私钥")
	}
	request.Spec.SANs[0] = "replacement.example.test"
	request.ChainPEM[0] = 'X'
	again, err := f.authority.AcceptedImportRequest(ctx)
	if err != nil || again.Spec.SANs[0] != "proxy.example.test" || !bytes.Equal(again.ChainPEM, certificate.Chain) {
		t.Fatal("调用方修改了私有导入意图")
	}
}

type cancelAfterImportRead struct {
	authority *Authority
	calls     int
	cancel    func() error
}

func (p *cancelAfterImportRead) AllowImportKey(ctx context.Context, caller certificates.Caller, ref secrets.Ref) error {
	p.calls++
	if p.calls == 2 {
		if err := p.cancel(); err != nil {
			return err
		}
	}
	return p.authority.AllowImportKey(ctx, caller, ref)
}

func TestHostCertificateImportRechecksCancellationAfterRead(t *testing.T) {
	f := newAuthorityFixture(t)
	certificate := signedHostCertificate(t, f)
	defer certificate.Clear()
	call, ctx, request := f.importCertificate(t, certificate, fixtureCertificate, fixtureCertificateAttempt)
	permissions := &cancelAfterImportRead{authority: f.authority, cancel: func() error {
		_, err := f.ops.Cancel(f.ctx, operations.CancelRequest{Actor: f.human, OperationID: call.invocation.OperationID,
			Idempotency: operations.Idempotency{Key: f.ids.New(ids.Operation), Method: "POST", Route: "/fixture/import-cancel"}})
		return err
	}}
	reader := certificates.OwnedImportKeys{Secrets: f.secrets, Authorizations: permissions}
	key, err := reader.ReadImportKey(ctx, request.Caller, request.PrivateKeyRef)
	defer clear(key)
	if err == nil || len(key) != 0 || permissions.calls != 2 {
		t.Fatal("读取期间取消后仍返回明文私钥，或没有执行第二次真实授权")
	}
}

func TestHostCertificateImportRejectsNonExtractedReferencesAndTrustMismatch(t *testing.T) {
	f := newAuthorityFixture(t)
	certificate := signedHostCertificate(t, f)
	defer certificate.Clear()
	created, _, request := f.importCertificate(t, certificate, fixtureCertificate, fixtureCertificateAttempt)
	created.finish()
	stringRef, err := json.Marshal(request.PrivateKeyRef)
	if err != nil {
		t.Fatal(err)
	}
	extraRef, err := json.Marshal(map[string]string{"$secret": request.PrivateKeyRef, "owner": "foreign"})
	if err != nil {
		t.Fatal(err)
	}
	inlineKey, err := json.Marshal(string(certificate.Key))
	if err != nil {
		t.Fatal(err)
	}
	defer clear(inlineKey)
	for _, test := range []struct {
		name  string
		key   json.RawMessage
		trust tlsmgr.TrustClass
	}{
		{"string-ref", stringRef, tlsmgr.PublicTrust},
		{"extra-field", extraRef, tlsmgr.PublicTrust},
		{"test-trust", inlineKey, tlsmgr.TestTrust},
	} {
		t.Run(test.name, func(t *testing.T) {
			input := ImportCertificateArgs{CertificateID: "invalid-import-" + test.name, AttemptID: fixtureCertificateAttempt,
				Spec: certificateSpec(tlsmgr.ServerTLS), ChainPEM: "invalid fixture chain", PrivateKey: test.key, Trust: test.trust}
			if test.name == "extra-field" {
				// 外部预埋对象必须在真实 Run 入口拒绝，不为夹具放宽输入防线。
				raw, err := json.Marshal(input)
				if err != nil {
					t.Fatal(err)
				}
				defer clear(raw)
				var before, after int
				if err := f.db.Reader().QueryRowContext(f.ctx, `SELECT COUNT(*) FROM operations`).Scan(&before); err != nil {
					t.Fatal(err)
				}
				_, err = f.ops.Run(f.ctx, operations.RunRequest{Actor: f.human, Action: "tls.certificates/certificates.import",
					Target: operations.Target{PluginID: "tls.certificates", Subject: certificateSubject(input.CertificateID)},
					Args:   raw, ExpectedRevision: "absent",
					Idempotency: operations.Idempotency{Key: f.ids.New(ids.Operation), Method: "POST", Route: "/fixture/run"}})
				if !problem.HasCode(err, problem.ValidationFailed) {
					t.Fatal("a preembedded malformed certificate reference entered the operation path")
				}
				if err := f.db.Reader().QueryRowContext(f.ctx, `SELECT COUNT(*) FROM operations`).Scan(&after); err != nil || before != after {
					t.Fatal("rejected client references created an operation")
				}
				if _, valid := operationSecret(test.key); valid {
					t.Fatal("legacy malformed references passed the host parser")
				}
				return
			}
			// 字符串引用保留旧无提取负例；信任类负例使用真实私钥提取与派发。
			job, invocation := f.dispatchCall(t, f.human, "tls.certificates", "certificates.import", certificateSubject(input.CertificateID), "absent", input,
				func(a *operations.Action) {
					if test.name == "string-ref" {
						a.ArgsSchema = nil
					}
				})
			ctx, release, err := f.authority.Begin(job.ctx, invocation)
			if err != nil {
				t.Fatal(err)
			}
			_, _, err = f.authority.CertificateContext(ctx, input.CertificateID, input.AttemptID, "absent")
			release()
			requireCode(t, err, "VALIDATION_FAILED")
		})
	}
}

// ======================== 固定 CA 条款与实际原 operation 证据 ========================

func TestHostCertificateTermsBindCAURLAndAcceptedOperation(t *testing.T) {
	f := newAuthorityFixture(t)
	f.certificateProvider(t)
	call, ctx, request := f.issueCertificate(t)
	terms := CertificateTerms{Authority: f.authority}
	const termsURL = "https://letsencrypt.org/documents/fixture-terms.pdf"
	if err := terms.Accept(ctx, request.Caller, request.Scope.CA, termsURL); err != nil {
		t.Fatal(err)
	}
	key, err := registryKey("terms", "installation", "local", fixtureCertificate, string(request.Scope.CA))
	if err != nil {
		t.Fatal(err)
	}
	var state certificateTermsRegistration
	revision, found, err := loadPrivate(ctx, f.authority, key, &state)
	if err != nil || !found || state.OperationID != call.invocation.OperationID || state.InitiatedBy.ID != f.human.ID || state.URL != termsURL {
		t.Fatal("条款没有保存原 CA 与实际发起 operation")
	}
	if err := terms.Accept(ctx, request.Caller, request.Scope.CA, termsURL); err != nil {
		t.Fatal(err)
	}
	again, _, err := loadPrivate(ctx, f.authority, key, &state)
	if err != nil || again != revision {
		t.Fatal("重复原条款确认改变了 CAS 证据")
	}
	for _, value := range []string{
		"http://letsencrypt.org/documents/terms.pdf",
		"https://letsencrypt.org.attacker.test/documents/terms.pdf",
		"https://user@letsencrypt.org/documents/terms.pdf",
		"https://letsencrypt.org:443/documents/terms.pdf",
		"https://letsencrypt.org/documents/../terms.pdf",
		"https://letsencrypt.org/documents/terms.pdf?redirect=other",
		"https://letsencrypt.org/documents/terms.pdf#other",
	} {
		requireCode(t, terms.Accept(ctx, request.Caller, request.Scope.CA, value), "TERMS_REQUIRED")
	}
	requireCode(t, terms.Accept(ctx, request.Caller, certificates.LetsEncrypt, termsURL), "TERMS_REQUIRED")
	call.release()
	if err := terms.Accept(ctx, request.Caller, request.Scope.CA, termsURL); err == nil {
		t.Fatal("释放后的 operation 仍可确认 CA 条款")
	}
}
