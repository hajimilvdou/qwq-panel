// SPDX-License-Identifier: AGPL-3.0-only

package certificates

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/qwq-panel/qwq/internal/prerequisites/testsupport"
	"github.com/qwq-panel/qwq/internal/tlsmgr"
)

// ======================== 实际签名链证明 public/staging 互不扩大信任 ========================

func trustFixtureRoot(t *testing.T, chain []byte) []byte {
	t.Helper()
	_, rest := pem.Decode(chain)
	root, rest := pem.Decode(rest)
	if root == nil || len(bytes.TrimSpace(rest)) != 0 {
		t.Fatal("fixture has no exact CA root")
	}
	return pem.EncodeToMemory(root)
}

func TestHostTrustRootsSeparateRealCertificateChains(t *testing.T) {
	now := time.Now().UTC()
	public, err := testsupport.SignedCertificate(now, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer public.Clear()
	staging, err := testsupport.SignedCertificate(now, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer staging.Clear()
	roots, err := NewHostTrustRoots(HostTrustRootsOptions{PublicRoots: public.Roots, StagingRootsPEM: trustFixtureRoot(t, staging.Chain)})
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name  string
		chain testsupport.Certificate
		trust tlsmgr.TrustClass
		valid bool
	}{
		{name: "public_in_public", chain: public, trust: tlsmgr.PublicTrust, valid: true},
		{name: "staging_in_public", chain: staging, trust: tlsmgr.PublicTrust},
		{name: "staging_in_staging", chain: staging, trust: tlsmgr.StagingTrust, valid: true},
		{name: "public_in_staging", chain: public, trust: tlsmgr.StagingTrust},
	} {
		t.Run(test.name, func(t *testing.T) {
			pool, err := roots.Roots(t.Context(), test.trust)
			if err != nil {
				t.Fatal(err)
			}
			material, err := tlsmgr.NewMaterial(test.chain.Chain, test.chain.Key)
			if err != nil {
				t.Fatal(err)
			}
			defer material.Clear()
			_, err = tlsmgr.ValidateMaterial(material, tlsmgr.MaterialOptions{SANs: []string{"proxy.example.com"}, Now: now,
				Purpose: tlsmgr.ServerTLS, Trust: test.trust, Roots: pool})
			if (err == nil) != test.valid {
				t.Fatalf("certificate trust widened or rejected a valid chain: %v", err)
			}
		})
	}
}

func TestHostTrustRootsRejectInvalidAnchors(t *testing.T) {
	certificate, err := testsupport.SignedCertificate(time.Now().UTC(), nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer certificate.Clear()
	root := trustFixtureRoot(t, certificate.Chain)
	leaf, _ := pem.Decode(certificate.Chain)
	for _, test := range []struct {
		name string
		data []byte
	}{
		{name: "empty", data: []byte{}},
		{name: "garbage_prefix", data: append([]byte("garbage"), root...)},
		{name: "damaged_first_block", data: append([]byte("-----BEGIN CERTIFICATE-----\ninvalid\n"), root...)},
		{name: "trailing_garbage", data: append(bytes.Clone(root), []byte("garbage")...)},
		{name: "private_key", data: append(bytes.Clone(root), certificate.Key...)},
		{name: "leaf_as_anchor", data: pem.EncodeToMemory(leaf)},
		{name: "duplicate_anchor", data: append(bytes.Clone(root), root...)},
		{name: "oversized", data: bytes.Repeat([]byte("x"), 64<<10)},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := NewHostTrustRoots(HostTrustRootsOptions{PublicRoots: certificate.Roots, StagingRootsPEM: test.data}); err == nil {
				t.Fatal("invalid host trust anchor was accepted")
			}
		})
	}
	if _, err := NewHostTrustRoots(HostTrustRootsOptions{PublicRoots: x509.NewCertPool(), StagingRootsPEM: root}); err == nil {
		t.Fatal("empty public trust pool was accepted")
	}
}

// ======================== 构造与返回值均隔离可变池；取消/未知类别拒绝 ========================

func TestHostTrustRootsCloneAndCancellation(t *testing.T) {
	certificate, err := testsupport.SignedCertificate(time.Now().UTC(), nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer certificate.Clear()
	rootPEM := trustFixtureRoot(t, certificate.Chain)
	want := certificate.Roots.Clone()
	roots, err := NewHostTrustRoots(HostTrustRootsOptions{PublicRoots: certificate.Roots, StagingRootsPEM: rootPEM})
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := pem.Decode(certificate.Chain)
	extra, err := x509.ParseCertificate(leaf.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	certificate.Roots.AddCert(extra)
	var workers sync.WaitGroup
	for range 16 {
		workers.Go(func() {
			for _, trust := range []tlsmgr.TrustClass{tlsmgr.PublicTrust, tlsmgr.StagingTrust} {
				pool, err := roots.Roots(t.Context(), trust)
				if err != nil || !pool.Equal(want) {
					t.Errorf("construction or concurrent clone changed anchors: %v", err)
					return
				}
				pool.AddCert(extra)
			}
		})
	}
	workers.Wait()
	for _, trust := range []tlsmgr.TrustClass{tlsmgr.PublicTrust, tlsmgr.StagingTrust} {
		pool, err := roots.Roots(t.Context(), trust)
		if err != nil || !pool.Equal(want) {
			t.Fatalf("returned pool changed the stored anchors: %v", err)
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := roots.Roots(ctx, tlsmgr.PublicTrust); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled root query = %v", err)
	}
	if _, err := roots.Roots(t.Context(), tlsmgr.TrustClass("unknown")); err == nil {
		t.Fatal("unknown trust silently used public roots")
	}
	pool, err := roots.Roots(t.Context(), tlsmgr.TestTrust)
	if err != nil || pool != nil {
		t.Fatal("test trust must use the validated certificate's own root")
	}
}

func TestHostTrustRootsUseOfficialStagingBundle(t *testing.T) {
	roots, err := NewHostTrustRoots(HostTrustRootsOptions{})
	if err != nil {
		t.Fatal(err)
	}
	chain, err := tlsmgr.ParseCertificateChain(append(bytes.Clone(stagingRootX1), stagingRootX2...))
	if err != nil || len(chain) != 2 {
		t.Fatalf("official staging source does not contain two complete anchors: %v", err)
	}
	wantStaging := x509.NewCertPool()
	for _, anchor := range chain {
		wantStaging.AddCert(anchor)
	}
	staging, err := roots.Roots(t.Context(), tlsmgr.StagingTrust)
	if err != nil || !staging.Equal(wantStaging) {
		t.Fatalf("official staging root bundle was not loaded independently: %v", err)
	}
	public, err := roots.Roots(t.Context(), tlsmgr.PublicTrust)
	if err != nil || public.Equal(x509.NewCertPool()) {
		t.Fatalf("system public roots were not loaded: %v", err)
	}
}

// ======================== 真实 Vault 复用此服务，错误信任不写机密或水位 ========================

func TestHostTrustRootsVaultIntegration(t *testing.T) {
	now := time.Date(2026, 11, 15, 0, 0, 0, 0, time.UTC)
	public, err := testsupport.SignedCertificate(now, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer public.Clear()
	staging, err := testsupport.SignedCertificate(now, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer staging.Clear()
	roots, err := NewHostTrustRoots(HostTrustRootsOptions{PublicRoots: public.Roots, StagingRootsPEM: trustFixtureRoot(t, staging.Chain)})
	if err != nil {
		t.Fatal(err)
	}
	_, db, secrets, permissions, caller, clk := vaultFixture(t, public.Roots)
	vault, err := NewVault(VaultOptions{DB: db, Secrets: secrets,
		Imports: OwnedImportKeys{Secrets: secrets, Authorizations: permissions}, Roots: roots, Clock: clk})
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		id    string
		chain testsupport.Certificate
		trust tlsmgr.TrustClass
		valid bool
	}{
		{id: "public-correct", chain: public, trust: tlsmgr.PublicTrust, valid: true},
		{id: "staging-correct", chain: staging, trust: tlsmgr.StagingTrust, valid: true},
		{id: "public-wrong", chain: public, trust: tlsmgr.StagingTrust},
		{id: "staging-wrong", chain: staging, trust: tlsmgr.PublicTrust},
	} {
		t.Run(test.id, func(t *testing.T) {
			material, err := tlsmgr.NewMaterial(test.chain.Chain, test.chain.Key)
			if err != nil {
				t.Fatal(err)
			}
			defer material.Clear()
			spec := Spec{SANs: []string{"proxy.example.com"}, Purpose: tlsmgr.ServerTLS}
			before := db.HeadSeq()
			reference, err := vault.EnsureMaterial(t.Context(), caller, test.id, test.id, material, spec, test.trust)
			if !test.valid {
				if err == nil || reference != "" || db.HeadSeq() != before {
					t.Fatal("wrong trust wrote a material or advanced the database sequence")
				}
				return
			}
			if err != nil {
				t.Fatalf("vault rejected its configured trust: %v", err)
			}
			metadata, err := vault.Inspect(t.Context(), caller, test.id, reference, spec, test.trust)
			if err != nil || metadata.Trust != test.trust {
				t.Fatalf("vault could not inspect its persisted material: %v", err)
			}
		})
	}
}
