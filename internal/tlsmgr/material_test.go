// SPDX-License-Identifier: AGPL-3.0-only

package tlsmgr

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/qwq-panel/qwq/internal/prerequisites/fault"
	"github.com/qwq-panel/qwq/internal/prerequisites/testsupport"
)

func signedMaterial(t *testing.T, mutate func(*x509.Certificate), weakRSA bool) (Material, *x509.CertPool) {
	t.Helper()
	bits := 0
	if weakRSA {
		bits = 1024
	}
	fixture, err := testsupport.SignedCertificate(testTime, mutate, bits)
	if err != nil {
		t.Fatal(err)
	}
	defer fixture.Clear()
	material, err := NewMaterial(fixture.Chain, fixture.Key)
	if err != nil {
		t.Fatal(err)
	}
	return material, fixture.Roots
}

func materialOptions(roots *x509.CertPool) MaterialOptions {
	return MaterialOptions{SANs: []string{"proxy.example.com"}, Now: testTime, Purpose: ServerTLS, Trust: PublicTrust, Roots: roots}
}

func materialCode(t *testing.T, err error, expected string) {
	t.Helper()
	if err == nil || fault.Code(err) != expected {
		t.Fatalf("validation error = %v, want %s", err, expected)
	}
}

func TestMaterialValidatesChainAndPublicMetadata(t *testing.T) {
	material, roots := signedMaterial(t, nil, false)
	defer material.Clear()
	metadata, err := ValidateMaterial(material, materialOptions(roots))
	if err != nil {
		t.Fatal(err)
	}
	if metadata.Issuer != "CN=Fake CA" || !fingerprintRE.MatchString(metadata.Fingerprint) || len(metadata.SANs) != 1 || metadata.SANs[0] != "proxy.example.com" || metadata.Purpose != ServerTLS || metadata.Trust != PublicTrust {
		t.Fatalf("public metadata = %v", metadata)
	}
	if err := Covers(metadata, "PROXY.example.com"); err != nil {
		t.Fatal(err)
	}
	materialCode(t, Covers(metadata, "other.example.com"), "SAN_MISMATCH")
}

func TestMaterialRejectsPrivateKeyMismatchAndUnsupportedStrength(t *testing.T) {
	material, roots := signedMaterial(t, nil, false)
	defer material.Clear()
	other, _ := signedMaterial(t, nil, false)
	defer other.Clear()
	mismatch, err := NewMaterial(material.CertificatePEM(), other.PrivateKeyPEM())
	if err != nil {
		t.Fatal(err)
	}
	defer mismatch.Clear()
	_, err = ValidateMaterial(mismatch, materialOptions(roots))
	materialCode(t, err, "PRIVATE_KEY_MISMATCH")
	weak, weakRoots := signedMaterial(t, nil, true)
	defer weak.Clear()
	_, err = ValidateMaterial(weak, materialOptions(weakRoots))
	materialCode(t, err, "PRIVATE_KEY_UNSUPPORTED")
}

func TestMaterialRejectsTimeSANAndPurposeViolations(t *testing.T) {
	for _, tc := range []struct {
		name, code string
		mutate     func(*x509.Certificate)
	}{
		{"expired", "CERTIFICATE_EXPIRED", func(c *x509.Certificate) { c.NotAfter = testTime }},
		{"not yet valid", "CERTIFICATE_NOT_YET_VALID", func(c *x509.Certificate) { c.NotBefore = testTime.Add(time.Minute) }},
		{"extra SAN", "SAN_MISMATCH", func(c *x509.Certificate) { c.DNSNames = append(c.DNSNames, "other.example.com") }},
		{"wrong SAN", "SAN_MISMATCH", func(c *x509.Certificate) { c.DNSNames = []string{"other.example.com"} }},
		{"client auth only", "CERTIFICATE_CHAIN_INVALID", func(c *x509.Certificate) { c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth} }},
		{"CA certificate", "CERTIFICATE_PURPOSE_INVALID", func(c *x509.Certificate) { c.IsCA = true; c.KeyUsage |= x509.KeyUsageCertSign }},
		{"encryption only", "CERTIFICATE_PURPOSE_INVALID", func(c *x509.Certificate) { c.KeyUsage = x509.KeyUsageKeyEncipherment }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			material, roots := signedMaterial(t, tc.mutate, false)
			defer material.Clear()
			_, err := ValidateMaterial(material, materialOptions(roots))
			materialCode(t, err, tc.code)
		})
	}
}

func TestMaterialRejectsUnknownTrustAndIncompleteChain(t *testing.T) {
	material, roots := signedMaterial(t, nil, false)
	defer material.Clear()
	options := materialOptions(roots)
	options.Roots = x509.NewCertPool()
	_, err := ValidateMaterial(material, options)
	materialCode(t, err, "CERTIFICATE_CHAIN_INVALID")
	options = materialOptions(nil)
	options.Trust = StagingTrust
	_, err = ValidateMaterial(material, options)
	materialCode(t, err, "TRUST_UNAVAILABLE")
	options.Trust = TrustClass("unconfigured")
	_, err = ValidateMaterial(material, options)
	materialCode(t, err, "CERTIFICATE_PURPOSE_INVALID")
}

func TestMaterialRejectsGarbageAndUnrelatedPEM(t *testing.T) {
	material, roots := signedMaterial(t, nil, false)
	defer material.Clear()
	damagedKeyPrefix := append(bytes.Clone(bytes.SplitN(material.PrivateKeyPEM(), []byte("\n"), 2)[0]), []byte("\ninvalid\n")...)
	for _, tc := range []struct {
		name       string
		chain, key []byte
		code       string
	}{
		{"chain prefix", append([]byte("ignored garbage\n"), material.CertificatePEM()...), material.PrivateKeyPEM(), "CERTIFICATE_INVALID"},
		{"chain damaged prefix block", append([]byte("-----BEGIN CERTIFICATE-----\ninvalid\n"), material.CertificatePEM()...), material.PrivateKeyPEM(), "CERTIFICATE_INVALID"},
		{"chain suffix", append(material.CertificatePEM(), []byte("trailing garbage")...), material.PrivateKeyPEM(), "CERTIFICATE_INVALID"},
		{"key prefix", material.CertificatePEM(), append([]byte("ignored garbage\n"), material.PrivateKeyPEM()...), "PRIVATE_KEY_INVALID"},
		{"key damaged prefix block", material.CertificatePEM(), append(damagedKeyPrefix, material.PrivateKeyPEM()...), "PRIVATE_KEY_INVALID"},
		{"key suffix", material.CertificatePEM(), append(material.PrivateKeyPEM(), []byte("trailing garbage")...), "PRIVATE_KEY_INVALID"},
		{"unrelated block", pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: []byte("invalid")}), material.PrivateKeyPEM(), "CERTIFICATE_INVALID"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			input, err := NewMaterial(tc.chain, tc.key)
			if err != nil {
				t.Fatal(err)
			}
			defer input.Clear()
			_, err = ValidateMaterial(input, materialOptions(roots))
			materialCode(t, err, tc.code)
		})
	}
}

func TestMaterialPrivateDataNeverSerializesOrLogs(t *testing.T) {
	material, _ := signedMaterial(t, nil, false)
	defer material.Clear()
	if _, err := json.Marshal(material); err == nil {
		t.Fatal("private material serialized")
	}
	for _, value := range []string{fmt.Sprintf("%v", material), fmt.Sprintf("%#v", material)} {
		if strings.Contains(value, "PRIVATE KEY") || !strings.Contains(value, "REDACTED") {
			t.Fatal("private data in string form")
		}
	}
	var output strings.Builder
	slog.New(slog.NewJSONHandler(&output, nil)).InfoContext(context.Background(), "material", "value", material)
	if strings.Contains(output.String(), "PRIVATE KEY") || !strings.Contains(output.String(), "REDACTED") {
		t.Fatal("private data in structured log")
	}
	input := material.PrivateKeyPEM()
	clone, err := NewMaterial(material.CertificatePEM(), input)
	if err != nil {
		t.Fatal(err)
	}
	defer clone.Clear()
	clear(input)
	if len(clone.PrivateKeyPEM()) == 0 {
		t.Fatal("material shared mutable input")
	}
}

func TestMaterialTestSelfSignedRequiresExplicitTestTrust(t *testing.T) {
	material, err := GenerateTestMaterial(testTime, []string{"*.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	defer material.Clear()
	options := MaterialOptions{SANs: []string{"*.example.com"}, Now: testTime, Purpose: TestServerTLS, Trust: TestTrust}
	metadata, err := ValidateMaterial(material, options)
	if err != nil {
		t.Fatal(err)
	}
	if !metadata.NotAfter.Equal(testTime.Add(24 * time.Hour)) {
		t.Fatal("test certificate validity was not bounded")
	}
	if err := Covers(metadata, "proxy.example.com"); err != nil {
		t.Fatal(err)
	}
	materialCode(t, Covers(metadata, "deep.proxy.example.com"), "SAN_MISMATCH")
	materialCode(t, Covers(metadata, "example.com"), "SAN_MISMATCH")
	options.Purpose, options.Trust = ServerTLS, PublicTrust
	if _, err := ValidateMaterial(material, options); err == nil {
		t.Fatal("test certificate accepted as ordinary production certificate")
	}
}
