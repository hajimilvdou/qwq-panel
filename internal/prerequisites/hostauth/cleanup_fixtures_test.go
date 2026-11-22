// SPDX-License-Identifier: AGPL-3.0-only

package hostauth

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/qwq-panel/qwq/internal/operations"
	"github.com/qwq-panel/qwq/internal/platform/ids"
	"github.com/qwq-panel/qwq/internal/prerequisites/acme"
	"github.com/qwq-panel/qwq/internal/prerequisites/certificates"
	"github.com/qwq-panel/qwq/internal/prerequisites/dns"
	"github.com/qwq-panel/qwq/internal/prerequisites/fault"
	"github.com/qwq-panel/qwq/internal/prerequisites/provider"
	"github.com/qwq-panel/qwq/internal/prerequisites/store"
	"github.com/qwq-panel/qwq/internal/secrets"
	"github.com/qwq-panel/qwq/internal/storage"
)

// ======================== 真实身份、审批、加密 journal 与受控网络 fixture ========================

type cleanupRequestFixture struct {
	*authorityFixture
	call           *fixtureCall
	certificateCtx context.Context
	dnsCtx         context.Context
	request        certificates.IssueRequest
	challenge      dns.ChallengeRequest
	manager        *dns.Manager
	backend        *cleanupCredentialProvider
	contexts       CertificateCleanupContexts
}

// 网络端只模拟记录；每个请求仍读取真实宿主私有凭据并复查真实 operation。
type cleanupCredentialProvider struct {
	mu          sync.Mutex
	credentials provider.CredentialSource
	scope       dns.Scope
	records     []dns.Record
	network     int
	deletes     int
}

func (p *cleanupCredentialProvider) authorize(ctx context.Context, scope dns.Scope) error {
	if scope != p.scope {
		return fault.New("PERMISSION_DENIED", "fixture 网络只接原 zone")
	}
	credentials, err := p.credentials.Read(ctx, scope)
	defer credentials.Clear()
	if err != nil {
		return err
	}
	if len(credentials.Token) == 0 || credentials.Kind != dns.Cloudflare {
		return fault.New("CREDENTIAL_REVOKED", "fixture 没有真实受控凭据")
	}
	return ctx.Err()
}

func (p *cleanupCredentialProvider) For(ctx context.Context, scope dns.Scope) (dns.Provider, error) {
	if err := p.authorize(ctx, scope); err != nil {
		return nil, err
	}
	return p, nil
}

func (p *cleanupCredentialProvider) List(ctx context.Context, scope dns.Scope) ([]dns.Record, error) {
	if err := p.authorize(ctx, scope); err != nil {
		return nil, err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.network++
	return slices.Clone(p.records), nil
}

func (p *cleanupCredentialProvider) Create(ctx context.Context, scope dns.Scope, record dns.Record) (dns.Record, error) {
	if err := p.authorize(ctx, scope); err != nil {
		return dns.Record{}, err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.network++
	record.ID = "original-record"
	p.records = append(p.records, record)
	return record, nil
}

func (*cleanupCredentialProvider) Update(context.Context, dns.Scope, dns.Record, dns.Record) (dns.Record, error) {
	return dns.Record{}, fault.New("PERMISSION_DENIED", "fixture 不开放原 TXT 修改")
}

func (p *cleanupCredentialProvider) Delete(ctx context.Context, scope dns.Scope, record dns.Record) error {
	if err := p.authorize(ctx, scope); err != nil {
		return err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.network++
	for index, stored := range p.records {
		if stored.ID == record.ID {
			p.records = append(p.records[:index], p.records[index+1:]...)
			p.deletes++
			return nil
		}
	}
	return nil
}

func (p *cleanupCredentialProvider) counts() (int, int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.network, p.deletes
}

func newCleanupRequestFixture(t *testing.T) *cleanupRequestFixture {
	t.Helper()
	f := newAuthorityFixture(t, func(d *fixtureDispatch) { d.holdCancellation = true })
	f.certificateProvider(t)
	call, ctx, request := f.issueCertificate(t)
	caRepository, err := store.NewEncrypted(store.EncryptedOptions{DB: f.db, Secrets: f.secrets, Namespace: "certificates"})
	if err != nil {
		t.Fatal(err)
	}
	f.authority.challenges, err = acme.NewChallengeSource(acme.ChallengeSourceOptions{Repository: caRepository, Clock: f.clock})
	if err != nil {
		t.Fatal(err)
	}
	dnsCtx, err := (CertificateDNSContexts{Authority: f.authority}).Context(ctx, request.Caller, request.CertificateID, request.AttemptID, request.Scope, false)
	if err != nil {
		t.Fatal(err)
	}
	dnsRepository, err := store.NewEncrypted(store.EncryptedOptions{DB: f.db, Secrets: f.secrets, Namespace: "dns"})
	if err != nil {
		t.Fatal(err)
	}
	backend := &cleanupCredentialProvider{credentials: CredentialSource{Authority: f.authority}, scope: request.Scope.Provider}
	manager, err := dns.New(dns.Options{Repository: dnsRepository, Providers: backend, Authorizer: RequestDNSAuthorizer{DNSAuthorizer{Authority: f.authority}}, Clock: f.clock})
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := manager.List(dnsCtx, dns.Caller{OwnerID: request.Caller.OwnerID, OperationID: request.Caller.OperationID}, request.Scope.Provider)
	if err != nil {
		t.Fatal(err)
	}
	challenge := seedOriginalCAJournal(t, f, caRepository, request, snapshot.Revision)
	return &cleanupRequestFixture{authorityFixture: f, call: call, certificateCtx: ctx, dnsCtx: dnsCtx, request: request, challenge: challenge,
		manager: manager, backend: backend, contexts: CertificateCleanupContexts{Authority: f.authority, DNS: manager}}
}

// 宿主授权 fixture 注入固定 CA 状态，但 CSR、密钥引用与持久后端均实际生成。
// 真实 CA/JWS 交互由 acme 的独立协议测试覆盖，不能把此 fixture 当 staging 实测。
func seedOriginalCAJournal(t *testing.T, f *authorityFixture, repository *store.EncryptedRepository, request certificates.IssueRequest, revision string) dns.ChallengeRequest {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(encoded)
	owner := "plugins/tls.certificates/owners/" + request.Caller.OwnerID + "/certificates/" + request.CertificateID
	purpose := sha256.Sum256([]byte(request.AttemptID))
	var reference secrets.Ref
	if err := f.db.Update(f.ctx, func(tx *storage.Tx) error {
		var err error
		reference, err = f.secrets.EnsureOwned(f.ctx, tx, owner, "acme.key."+hex.EncodeToString(purpose[:]), encoded)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: slices.Clone(request.Scope.Spec.SANs)}, key)
	if err != nil {
		t.Fatal(err)
	}
	authorizationURI := "https://acme-staging-v02.api.letsencrypt.org/acme/authz/original"
	attempt := sha256.Sum256([]byte(request.AttemptID + "\x00" + authorizationURI + "\x00" + "1"))
	dnsAttempt := "acmedns_" + hex.EncodeToString(attempt[:])
	challenge := dns.ChallengeRequest{Caller: dns.Caller{OwnerID: request.Caller.OwnerID, OperationID: request.Caller.OperationID}, Scope: request.Scope.Provider,
		CertificateID: request.CertificateID, AttemptID: dnsAttempt, SAN: request.Scope.Spec.SANs[0], Value: strings.Repeat("V", 43), ExpectedRevision: revision}
	state := map[string]any{"version": 1, "owner_id": request.Caller.OwnerID, "certificate_id": request.CertificateID, "attempt_id": request.AttemptID,
		"scope": request.Scope, "key_ref": reference, "csr": csr, "phase": "order_created", "created_at": f.clock.Now(),
		"account_uri": "https://acme-staging-v02.api.letsencrypt.org/acme/acct/original", "order_uri": "https://acme-staging-v02.api.letsencrypt.org/acme/order/original",
		"finalize_uri": "https://acme-staging-v02.api.letsencrypt.org/acme/finalize/original", "challenges": []map[string]any{{
			"authorization_uri": authorizationURI, "uri": authorizationURI + "/challenge", "san": challenge.SAN, "token": "original-token", "value": challenge.Value,
			"dns_attempt": dnsAttempt, "dns_revision": revision, "dns_round": 1, "dns_submitted": true}}}
	journalID := sha256.Sum256([]byte(request.Caller.OwnerID + "\x00" + request.CertificateID + "\x00" + request.AttemptID))
	if _, err := store.Save(f.ctx, repository, "acme/attempt/"+hex.EncodeToString(journalID[:]), "", state); err != nil {
		t.Fatal(err)
	}
	return challenge
}

func (f *cleanupRequestFixture) present(t *testing.T) {
	t.Helper()
	if result, err := f.manager.PresentChallenge(f.dnsCtx, f.challenge); err != nil || result.State != dns.Applied {
		t.Fatalf("原 CA 请求未确认提交：%v", err)
	}
}

func (f *cleanupRequestFixture) source(t *testing.T) (context.Context, context.CancelFunc, dns.OwnedChallenge) {
	t.Helper()
	ctx, stop, err := f.contexts.Source(context.WithoutCancel(f.certificateCtx), f.request.Caller, f.request.CertificateID, f.request.AttemptID, f.request.Scope)
	if err != nil {
		t.Fatal(err)
	}
	owned, found, err := f.manager.OwnedChallenge(ctx, f.challenge.Caller, f.challenge.Scope, f.challenge.CertificateID, f.challenge.AttemptID)
	if err != nil || !found {
		stop()
		t.Fatalf("原自有 TXT 查询失败：%v", err)
	}
	return ctx, stop, owned
}

func (f *cleanupRequestFixture) bound(t *testing.T) (context.Context, context.CancelFunc) {
	t.Helper()
	source, stopSource, owned := f.source(t)
	bound, stopRecord, err := f.contexts.ForChallenge(source, f.request.Caller, f.request.CertificateID, f.request.AttemptID, f.request.Scope, owned)
	if err != nil {
		stopSource()
		t.Fatal(err)
	}
	return bound, func() { stopRecord(); stopSource() }
}

func (f *cleanupRequestFixture) cancel(t *testing.T) {
	t.Helper()
	if _, err := f.ops.Cancel(f.ctx, operations.CancelRequest{Actor: f.human, OperationID: f.call.invocation.OperationID,
		Idempotency: operations.Idempotency{Key: f.ids.New(ids.Operation), Method: "POST", Route: "/fixture/cancel"}}); err != nil {
		t.Fatal(err)
	}
}
