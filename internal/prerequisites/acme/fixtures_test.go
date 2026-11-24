// SPDX-License-Identifier: AGPL-3.0-only

package acme

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/qwq-panel/qwq/internal/platform/clock"
	"github.com/qwq-panel/qwq/internal/prerequisites/certificates"
	"github.com/qwq-panel/qwq/internal/prerequisites/dns"
	"github.com/qwq-panel/qwq/internal/prerequisites/fault"
	"github.com/qwq-panel/qwq/internal/prerequisites/testsupport"
	"github.com/qwq-panel/qwq/internal/tlsmgr"
)

// ======================== 实际 ACME JWS / CSR / AES-GCM fixture ========================

type fixtureGuard struct {
	mu      sync.Mutex
	revoked bool
	scope   certificates.IssuanceScope
}

func (g *fixtureGuard) Authorize(ctx context.Context, request certificates.Authorization) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.revoked || request.Caller.OwnerID != "owner-1" || request.CertificateID != "certificate-1" || request.Issuance == nil || !equalScope(*request.Issuance, g.scope) {
		return fault.New("POLICY_REVOKED", "fixture scoped authorization denied")
	}
	return nil
}
func (g *fixtureGuard) Context(ctx context.Context, caller certificates.Caller, certificateID, attemptID string, scope certificates.IssuanceScope, cleanup bool) (context.Context, error) {
	if caller.OwnerID != "owner-1" || caller.OperationID == "" || certificateID != "certificate-1" || attemptID == "" || !equalScope(scope, g.scope) {
		return nil, fault.New("PERMISSION_DENIED", "fixture DNS context denied")
	}
	if !cleanup {
		if err := g.Authorize(ctx, certificates.Authorization{Caller: caller, CertificateID: certificateID, Spec: scope.Spec, Issuance: &scope, Access: certificates.Issue}); err != nil {
			return nil, err
		}
	}
	return ctx, nil
}
func (*fixtureGuard) Accept(context.Context, certificates.Caller, certificates.CA, string) error {
	return nil
}

// 旧 ACME/JWS fixture 显式注入清理许可；不作为真实运行 proof 或自有 TXT 后端。
func (g *fixtureGuard) Source(ctx context.Context, caller certificates.Caller, certificateID, attemptID string, scope certificates.IssuanceScope) (context.Context, context.CancelFunc, error) {
	bound, err := g.Context(ctx, caller, certificateID, attemptID, scope, true)
	if err != nil {
		return nil, nil, err
	}
	return bound, func() {}, nil
}

func (g *fixtureGuard) ForChallenge(ctx context.Context, caller certificates.Caller, certificateID, attemptID string, scope certificates.IssuanceScope, owned dns.OwnedChallenge) (context.Context, context.CancelFunc, error) {
	if owned.CertificateID() != certificateID || owned.DNSAttemptID() == "" || owned.Scope() != scope.Provider {
		return nil, nil, fault.New("PERMISSION_DENIED", "fixture 原记录清理范围不匹配")
	}
	return g.Source(ctx, caller, certificateID, attemptID, scope)
}

type fixtureRoots struct{ pool *x509.CertPool }

func (r fixtureRoots) Roots(context.Context, tlsmgr.TrustClass) (*x509.CertPool, error) {
	return r.pool, nil
}

type deniedImport struct{}

func (deniedImport) ReadImportKey(context.Context, certificates.Caller, string) ([]byte, error) {
	return nil, fault.New("PERMISSION_DENIED", "fixture import unused")
}

type fixtureDNS struct {
	mu               sync.Mutex
	scope            dns.Scope
	records          []dns.Record
	created, deleted int
}

func (d *fixtureDNS) For(_ context.Context, scope dns.Scope) (dns.Provider, error) {
	if scope != d.scope {
		return nil, fault.New("SCOPE_INVALID", "fixture provider scope")
	}
	return d, nil
}
func (d *fixtureDNS) Authorize(ctx context.Context, caller dns.Caller, scope dns.Scope, _ dns.Access) error {
	if caller.OwnerID != "owner-1" || caller.OperationID == "" || scope != d.scope {
		return fault.New("PERMISSION_DENIED", "fixture DNS identity")
	}
	return ctx.Err()
}

func (d *fixtureDNS) ChallengeContext(ctx context.Context, intent dns.ChallengeIntent) (context.Context, error) {
	if err := d.Authorize(ctx, intent.Caller, intent.Scope, dns.Challenge); err != nil {
		return nil, err
	}
	return ctx, nil
}

func (d *fixtureDNS) AuthorizeChallengeSource(ctx context.Context, caller dns.Caller, scope dns.Scope, _, _ string) error {
	return d.Authorize(ctx, caller, scope, dns.Cleanup)
}

func (d *fixtureDNS) AuthorizeChallengeCleanup(ctx context.Context, owned dns.OwnedChallenge) error {
	return d.Authorize(ctx, owned.Caller(), owned.Scope(), dns.Cleanup)
}
func (d *fixtureDNS) List(ctx context.Context, _ dns.Scope) ([]dns.Record, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return slices.Clone(d.records), ctx.Err()
}
func (d *fixtureDNS) Create(ctx context.Context, _ dns.Scope, record dns.Record) (dns.Record, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return dns.Record{}, err
	}
	d.created++
	record.ID = fmt.Sprintf("record-%d", d.created)
	d.records = append(d.records, record)
	return record, nil
}
func (*fixtureDNS) Update(context.Context, dns.Scope, dns.Record, dns.Record) (dns.Record, error) {
	return dns.Record{}, fault.New("PERMISSION_DENIED", "fixture update unused")
}
func (d *fixtureDNS) Delete(ctx context.Context, _ dns.Scope, record dns.Record) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	for index, current := range d.records {
		if current.ID == record.ID {
			d.records = append(d.records[:index], d.records[index+1:]...)
			d.deleted++
			return nil
		}
	}
	return fault.New("NOT_FOUND", "fixture missing record")
}
func (d *fixtureDNS) Observe(ctx context.Context, _ dns.Scope, name string, _ dns.RecordType) ([]dns.Observation, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	values := []string{}
	for _, record := range d.records {
		if record.Name == name {
			values = append(values, record.Value)
		}
	}
	now := time.Now().UTC()
	return []dns.Observation{{Source: "fixture-authoritative", Kind: dns.Authoritative, Values: values, CollectedAt: now}, {Source: "fixture-recursive", Kind: dns.Recursive, Values: values, CollectedAt: now}}, ctx.Err()
}
func (*fixtureDNS) CheckCAA(_ context.Context, scope dns.Scope, _ []string, _ string) error {
	return dns.ValidateScope(scope)
}

type fixtureCA struct {
	mu                          sync.Mutex
	t                           *testing.T
	root                        *x509.Certificate
	rootKey                     *ecdsa.PrivateKey
	account                     *ecdsa.PublicKey
	sans                        []string
	validated                   map[string]bool
	orders, finalizes, requests int
	status                      string
	certificate                 []byte
	lostOrder, lostFinalize     bool
	rejectOrder                 int
	foreignDirectory            bool
	now                         time.Time
}

const fixtureCAOrigin = "https://acme-staging-v02.api.letsencrypt.org"

func (c *fixtureCA) result(status int, value any, location string) *http.Response {
	raw, err := json.Marshal(value)
	if err != nil {
		c.t.Fatal(err)
	}
	response := &http.Response{StatusCode: status, Header: http.Header{"Content-Type": []string{"application/json"}, "Replay-Nonce": []string{base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf("fixture-nonce-%d", c.requests)))}}, Body: io.NopCloser(bytes.NewReader(raw))}
	if location != "" {
		response.Header.Set("Location", location)
	}
	return response
}

func (c *fixtureCA) payload(request *http.Request) []byte {
	var envelope struct{ Protected, Payload, Signature string }
	if json.NewDecoder(request.Body).Decode(&envelope) != nil {
		c.t.Fatal("ACME JWS was not JSON")
	}
	protected, err := base64.RawURLEncoding.DecodeString(envelope.Protected)
	if err != nil {
		c.t.Fatal("invalid JWS protected field")
	}
	var header struct {
		Alg, URL, Kid, Nonce string
		Jwk                  struct{ Kty, Crv, X, Y string }
	}
	if json.Unmarshal(protected, &header) != nil || header.Alg != "ES256" || header.URL != request.URL.String() || header.Nonce == "" {
		c.t.Fatal("ACME JWS URL/algorithm/nonce mismatch")
	}
	key := c.account
	if header.Kid == "" {
		x, err := base64.RawURLEncoding.DecodeString(header.Jwk.X)
		if err != nil {
			c.t.Fatal(err)
		}
		y, err := base64.RawURLEncoding.DecodeString(header.Jwk.Y)
		if err != nil {
			c.t.Fatal(err)
		}
		if len(x) != 32 || len(y) != 32 {
			c.t.Fatal("invalid JWK coordinate size")
		}
		encoded := make([]byte, 65)
		encoded[0] = 4
		copy(encoded[1:33], x)
		copy(encoded[33:], y)
		key, err = ecdsa.ParseUncompressedPublicKey(elliptic.P256(), encoded)
		if err != nil {
			c.t.Fatal("invalid JWK public key")
		}
	}
	signature, err := base64.RawURLEncoding.DecodeString(envelope.Signature)
	if err != nil || len(signature) != 64 || key == nil {
		c.t.Fatal("invalid JWS signature")
	}
	hash := sha256.Sum256([]byte(envelope.Protected + "." + envelope.Payload))
	if !ecdsa.Verify(key, hash[:], new(big.Int).SetBytes(signature[:32]), new(big.Int).SetBytes(signature[32:])) {
		c.t.Fatal("ACME JWS signature did not verify")
	}
	if header.Kid == "" {
		c.account = key
	} else if header.Kid != fixtureCAOrigin+"/acme/acct/1" {
		c.t.Fatal("ACME account KID changed")
	}
	payload, err := base64.RawURLEncoding.DecodeString(envelope.Payload)
	if err != nil {
		c.t.Fatal(err)
	}
	return payload
}

func (c *fixtureCA) order() map[string]any {
	identifiers := []map[string]string{}
	authorizations := []string{}
	for index, san := range c.sans {
		identifiers = append(identifiers, map[string]string{"type": "dns", "value": san})
		authorizations = append(authorizations, fmt.Sprintf("%s/acme/authz/%d", fixtureCAOrigin, index))
	}
	result := map[string]any{"status": c.status, "identifiers": identifiers, "authorizations": authorizations, "finalize": fixtureCAOrigin + "/acme/finalize/1"}
	if c.status == "valid" {
		result["certificate"] = fixtureCAOrigin + "/acme/cert/1"
	}
	return result
}

func (c *fixtureCA) RoundTrip(request *http.Request) (*http.Response, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.requests++
	if request.URL.Scheme != "https" || request.URL.Host != "acme-staging-v02.api.letsencrypt.org" {
		c.t.Fatal("CA fixed endpoint escaped")
	}
	path := request.URL.Path
	if path == "/directory" {
		order := fixtureCAOrigin + "/acme/new-order"
		if c.foreignDirectory {
			order = "https://other.example/acme/order"
		}
		return c.result(200, map[string]any{"newNonce": fixtureCAOrigin + "/acme/new-nonce", "newAccount": fixtureCAOrigin + "/acme/new-account", "newOrder": order, "meta": map[string]any{"termsOfService": "https://letsencrypt.org/documents/fixture-tos.pdf"}}, ""), nil
	}
	if path == "/acme/new-nonce" {
		return c.result(204, map[string]any{}, ""), nil
	}
	payload := c.payload(request)
	if path == "/acme/new-account" {
		var body struct{ OnlyReturnExisting bool }
		if json.Unmarshal(payload, &body) != nil {
			c.t.Fatal("account payload invalid")
		}
		if body.OnlyReturnExisting && c.orders == 0 {
			return c.result(400, map[string]any{"type": "urn:ietf:params:acme:error:accountDoesNotExist", "detail": "fixture"}, ""), nil
		}
		return c.result(201, map[string]string{"status": "valid"}, fixtureCAOrigin+"/acme/acct/1"), nil
	}
	if path == "/acme/new-order" {
		c.orders++
		if c.rejectOrder != 0 {
			response := c.result(c.rejectOrder, map[string]any{"type": "urn:ietf:params:acme:error:rateLimited", "detail": "fixture"}, "")
			response.Header.Set("Retry-After", "120")
			return response, nil
		}
		c.status = "pending"
		if c.lostOrder {
			return nil, io.EOF
		}
		return c.result(201, c.order(), fixtureCAOrigin+"/acme/order/1"), nil
	}
	if path == "/acme/order/1" {
		return c.result(200, c.order(), fixtureCAOrigin+"/acme/order/1"), nil
	}
	if strings.HasPrefix(path, "/acme/authz/") {
		index := 0
		if _, err := fmt.Sscanf(path, "/acme/authz/%d", &index); err != nil || index >= len(c.sans) {
			c.t.Fatal("authz identity invalid")
		}
		san := c.sans[index]
		status := "pending"
		if c.validated[san] {
			status = "valid"
		}
		challenges := []any{
			map[string]any{
				"type":   "dns-01",
				"url":    fmt.Sprintf("%s/acme/challenge/%d", fixtureCAOrigin, index),
				"token":  base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf("fixture-challenge-%d", index))),
				"status": status,
			},
		}
		if !strings.HasPrefix(san, "*.") {
			challenges = append(challenges, map[string]any{
				"type":   "http-01",
				"url":    fmt.Sprintf("%s/acme/challenge/http/%d", fixtureCAOrigin, index),
				"token":  base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf("fixture-http01-%d", index))),
				"status": status,
			})
		}
		result := map[string]any{"status": status, "identifier": map[string]string{"type": "dns", "value": strings.TrimPrefix(san, "*.")}, "wildcard": strings.HasPrefix(san, "*."), "challenges": challenges}
		return c.result(200, result, fixtureCAOrigin+path), nil
	}
	if strings.HasPrefix(path, "/acme/challenge/http/") {
		index := 0
		_, _ = fmt.Sscanf(path, "/acme/challenge/http/%d", &index)
		c.validated[c.sans[index]] = true
		if len(c.validated) == len(c.sans) {
			c.status = "ready"
		}
		return c.result(200, map[string]any{"type": "http-01", "url": fixtureCAOrigin + path, "status": "valid"}, ""), nil
	}
	if strings.HasPrefix(path, "/acme/challenge/") {
		index := 0
		_, _ = fmt.Sscanf(path, "/acme/challenge/%d", &index)
		c.validated[c.sans[index]] = true
		if len(c.validated) == len(c.sans) {
			c.status = "ready"
		}
		return c.result(200, map[string]any{"type": "dns-01", "url": fixtureCAOrigin + path, "status": "valid"}, ""), nil
	}
	if path == "/acme/finalize/1" {
		c.finalizes++
		var body struct{ CSR string }
		if json.Unmarshal(payload, &body) != nil {
			c.t.Fatal("CSR payload invalid")
		}
		raw, err := base64.RawURLEncoding.DecodeString(body.CSR)
		if err != nil {
			c.t.Fatal(err)
		}
		csr, err := x509.ParseCertificateRequest(raw)
		if err != nil || csr.CheckSignature() != nil || !slices.Equal(csr.DNSNames, c.sans) {
			c.t.Fatal("original CSR signature/SAN changed")
		}
		template := &x509.Certificate{SerialNumber: big.NewInt(2), DNSNames: slices.Clone(c.sans), Subject: pkix.Name{CommonName: c.sans[0]}, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, NotBefore: c.now.Add(-time.Hour), NotAfter: c.now.Add(90 * 24 * time.Hour)}
		der, err := x509.CreateCertificate(rand.Reader, template, c.root, csr.PublicKey, c.rootKey)
		if err != nil {
			c.t.Fatal(err)
		}
		c.certificate = append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.root.Raw})...)
		c.status = "valid"
		if c.lostFinalize {
			return nil, io.EOF
		}
		return c.result(200, c.order(), fixtureCAOrigin+"/acme/order/1"), nil
	}
	if path == "/acme/cert/1" {
		response := c.result(200, nil, "")
		response.Header.Set("Content-Type", "application/pem-certificate-chain")
		response.Body = io.NopCloser(bytes.NewReader(c.certificate))
		return response, nil
	}
	c.t.Fatal("unexpected ACME path")
	return nil, io.EOF
}

type authorityFixture struct {
	authority  *Authority
	repository *testsupport.MemoryStore
	vault      *certificates.Vault
	ca         *fixtureCA
	dns        *fixtureDNS
	guard      *fixtureGuard
	caller     certificates.Caller
	scope      certificates.IssuanceScope
}

func newAuthorityFixture(t *testing.T, sans []string) *authorityFixture {
	t.Helper()
	now := time.Date(2026, 11, 16, 0, 0, 0, 0, time.UTC)
	source := clock.NewFake(now)
	root, signer, err := testsupport.CertificateAuthority(now)
	if err != nil {
		t.Fatal(err)
	}
	rootKey := signer.(*ecdsa.PrivateKey)
	t.Cleanup(func() { clearSigner(rootKey) })
	pool := x509.NewCertPool()
	pool.AddCert(root)
	db, secretStore := testsupport.EncryptedStorage(t, source)
	vault, err := certificates.NewVault(certificates.VaultOptions{DB: db, Secrets: secretStore, Imports: deniedImport{}, Roots: fixtureRoots{pool}, Clock: source})
	if err != nil {
		t.Fatal(err)
	}
	sans = slices.Clone(sans)
	slices.Sort(sans)
	scope := certificates.IssuanceScope{Spec: certificates.Spec{SANs: sans, Purpose: tlsmgr.ServerTLS}, Provider: dns.Scope{ProviderID: "provider-1", Kind: dns.Cloudflare, ZoneID: "zone-1", ZoneName: "example.com", Revision: "scope-1"}, CA: certificates.LetsEncryptStaging}
	guard := &fixtureGuard{scope: scope}
	resolver := &fixtureDNS{scope: scope.Provider}
	dnsManager, err := dns.New(dns.Options{Repository: &testsupport.MemoryStore{}, Providers: resolver, Authorizer: resolver, Clock: source})
	if err != nil {
		t.Fatal(err)
	}
	checker, err := dns.NewChecker(dns.CheckerOptions{Resolver: resolver, Authorizer: resolver, Clock: source})
	if err != nil {
		t.Fatal(err)
	}
	ca := &fixtureCA{t: t, root: root, rootKey: rootKey, sans: sans, validated: map[string]bool{}, now: now}
	repository := &testsupport.MemoryStore{}
	authority, err := New(Options{DB: db, Secrets: secretStore, Repository: repository, Vault: vault, DNS: dnsManager, Checker: checker, CAA: resolver, Authorizer: guard, DNSContexts: guard, CleanupContexts: guard, Terms: guard, Client: &http.Client{Transport: ca}, Clock: source})
	if err != nil {
		t.Fatal(err)
	}
	return &authorityFixture{authority: authority, repository: repository, vault: vault, ca: ca, dns: resolver, guard: guard, caller: certificates.Caller{OwnerID: "owner-1", OperationID: "operation-1"}, scope: scope}
}
