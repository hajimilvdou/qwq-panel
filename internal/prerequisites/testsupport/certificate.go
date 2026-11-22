// SPDX-License-Identifier: AGPL-3.0-only

package testsupport

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"time"
)

// Certificate 仅供测试使用的 CA 签名链与私钥，不是生产信任配置。
type Certificate struct {
	Chain []byte
	Key   []byte
	Roots *x509.CertPool
}

func (Certificate) String() string   { return "testsupport.Certificate{[REDACTED]}" }
func (Certificate) GoString() string { return "testsupport.Certificate{[REDACTED]}" }
func (c *Certificate) Clear()        { clear(c.Key); c.Key = nil }

// SignedCertificate 共享真实密码学夹具；rsaBits 为零时使用 ECDSA P-256。
func SignedCertificate(now time.Time, mutate func(*x509.Certificate), rsaBits int) (Certificate, error) {
	root, rootKey, err := CertificateAuthority(now)
	if err != nil {
		return Certificate{}, err
	}
	rootDER := root.Raw
	var signer crypto.Signer
	if rsaBits != 0 {
		signer, err = rsa.GenerateKey(rand.Reader, rsaBits)
	} else {
		signer, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	}
	if err != nil {
		return Certificate{}, err
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), DNSNames: []string{"proxy.example.com"}, Subject: pkix.Name{CommonName: "proxy.example.com"},
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(90 * 24 * time.Hour)}
	if mutate != nil {
		mutate(leaf)
	}
	der, err := x509.CreateCertificate(rand.Reader, leaf, root, signer.Public(), rootKey)
	if err != nil {
		return Certificate{}, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(signer)
	if err != nil {
		return Certificate{}, err
	}
	defer clear(keyDER)
	roots := x509.NewCertPool()
	roots.AddCert(root)
	return Certificate{Chain: append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER})...),
		Key: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), Roots: roots}, nil
}

// CertificateAuthority 为实际 ACME/JWS fixture 复用相同 CA 生成，不用于生产。
func CertificateAuthority(now time.Time) (*x509.Certificate, crypto.Signer, error) {
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	rootTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Fake CA"}, IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		NotBefore: now.Add(-24 * time.Hour), NotAfter: now.Add(365 * 24 * time.Hour)}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	if err != nil {
		return nil, nil, err
	}
	root, err := x509.ParseCertificate(rootDER)
	if err != nil {
		return nil, nil, err
	}
	return root, rootKey, nil
}
