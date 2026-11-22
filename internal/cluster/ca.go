// SPDX-License-Identifier: AGPL-3.0-only

// Package cluster 实现多节点控制面与边缘 Agent 之间的独立集群 CA、SPKI 钉扎入网、
// TLS 1.3 mTLS 双向长连接会话、短寿期证书自动轮换与实时吊销拦截（Track 08 P4）。
package cluster

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// ======================== 常量与证书签发结果 ========================

const (
	// DefaultCertTTL 为边缘节点 mTLS 客户端证书默认有效期（30 天）。
	DefaultCertTTL = 30 * 24 * time.Hour

	caKeyFileName  = "ca.key"
	caCertFileName = "ca.crt"

	pemTypePrivateKey = "PRIVATE KEY"
	pemTypeCert       = "CERTIFICATE"
)

var validNodeIDPattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)

// SignedCert 描述集群 CA 为节点签发的短寿期客户端证书与摘要元数据。
type SignedCert struct {
	CertDER     []byte
	SerialHex   string
	Fingerprint string
	ExpiresAt   time.Time
}

// CA 管理独立的集群内部 ECDSA P-256 根证书颁发机构（绝不复用面板 Web HTTPS 证书）。
type CA struct {
	cert    *x509.Certificate
	certDER []byte
	certPEM []byte
	key     *ecdsa.PrivateKey
	now     func() time.Time
}

// ======================== 独立集群 Root CA 加载与初始化 ========================

// OpenCA 从 <dataDir>/cluster/{ca.key,ca.crt} 加载或首次生成独立的 ECDSA P-256 集群根 CA。
// 私钥以 0600 权限原子落盘，公钥证书以 0644 权限落盘。
func OpenCA(dataDir string) (*CA, error) {
	if strings.TrimSpace(dataDir) == "" {
		return nil, errors.New("cluster: dataDir is required")
	}
	dir := filepath.Join(dataDir, "cluster")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("cluster: create ca dir: %w", err)
	}
	keyPath := filepath.Join(dir, caKeyFileName)
	certPath := filepath.Join(dir, caCertFileName)

	keyExists := fileExists(keyPath)
	certExists := fileExists(certPath)
	if keyExists && certExists {
		return loadCAFromDisk(keyPath, certPath)
	}
	if keyExists != certExists {
		return nil, errors.New("cluster: incomplete ca key/cert pair on disk")
	}

	ca, err := newCA(time.Now)
	if err != nil {
		return nil, err
	}
	pkcs8DER, err := x509.MarshalPKCS8PrivateKey(ca.key)
	if err != nil {
		return nil, fmt.Errorf("cluster: marshal ca key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: pemTypePrivateKey, Bytes: pkcs8DER})
	clear(pkcs8DER)

	if err := writeFileAtomic(keyPath, keyPEM, 0o600); err != nil {
		clear(keyPEM)
		return nil, fmt.Errorf("cluster: write ca key: %w", err)
	}
	clear(keyPEM)
	if err := writeFileAtomic(certPath, ca.certPEM, 0o644); err != nil {
		return nil, fmt.Errorf("cluster: write ca cert: %w", err)
	}
	return ca, nil
}

// NewEphemeralCA 在内存中生成一次性独立 ECDSA P-256 集群根 CA（供测试使用）。
func NewEphemeralCA(now func() time.Time) (*CA, error) {
	return newCA(now)
}

func newCA(now func() time.Time) (*CA, error) {
	if now == nil {
		now = time.Now
	}
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("cluster: generate ca key: %w", err)
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	ts := now().UTC()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			Organization: []string{"qwq-cluster"},
			CommonName:   "qwq Internal Cluster Root CA",
		},
		NotBefore:             ts.Add(-10 * time.Minute),
		NotAfter:              ts.AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		return nil, fmt.Errorf("cluster: create ca cert: %w", err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("cluster: parse ca cert: %w", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: pemTypeCert, Bytes: certDER})
	return &CA{
		cert:    cert,
		certDER: certDER,
		certPEM: certPEM,
		key:     priv,
		now:     now,
	}, nil
}

func loadCAFromDisk(keyPath, certPath string) (*CA, error) {
	keyRaw, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("cluster: read ca key: %w", err)
	}
	defer clear(keyRaw)

	keyBlock, _ := pem.Decode(keyRaw)
	if keyBlock == nil {
		return nil, errors.New("cluster: invalid ca key pem")
	}
	priv, err := parseECDSAPrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("cluster: parse ca key: %w", err)
	}

	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("cluster: read ca cert: %w", err)
	}
	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil || certBlock.Type != pemTypeCert {
		return nil, errors.New("cluster: invalid ca cert pem")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("cluster: parse ca cert: %w", err)
	}
	if !cert.IsCA {
		return nil, errors.New("cluster: loaded certificate is not a CA")
	}
	return &CA{
		cert:    cert,
		certDER: append([]byte(nil), certBlock.Bytes...),
		certPEM: certPEM,
		key:     priv,
		now:     time.Now,
	}, nil
}

// ======================== SPKI 钉扎、证书签发与节点身份提取 ========================

// Cert 返回集群根 CA 的解析后证书对象。
func (c *CA) Cert() *x509.Certificate { return c.cert }

// CertDER 返回集群根 CA 的 DER 编码副本。
func (c *CA) CertDER() []byte { return append([]byte(nil), c.certDER...) }

// CertPEM 返回集群根 CA 的 PEM 编码副本。
func (c *CA) CertPEM() []byte { return append([]byte(nil), c.certPEM...) }

// CertPool 返回仅信任本集群根 CA 的证书池。
func (c *CA) CertPool() *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(c.cert)
	return pool
}

// SPKIPinSHA256 返回集群根 CA 公钥信息（SPKI）的 SHA-256 钉扎摘要，格式为 "sha256:<64hex>"。
func (c *CA) SPKIPinSHA256() string {
	return SPKIPinOfCert(c.cert)
}

// SPKIPinOfCert 计算单张证书 SubjectPublicKeyInfo 的 SHA-256 钉扎摘要。
func SPKIPinOfCert(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// CertFingerprintSHA256 计算完整 DER 证书的 SHA-256 指纹（"sha256:<64hex>"）。
func CertFingerprintSHA256(certDER []byte) string {
	sum := sha256.Sum256(certDER)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// VerifySPKIPin 返回用于 tls.Config.VerifyPeerCertificate 的防 MITM SPKI 钉扎校验回调。
// 校验目标可以是服务端叶证书本身，也可以是服务端证书链中签名该叶证书的根 CA 证书。
func VerifySPKIPin(expectedHash string) func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	want, validWant := normalizeSHA256Pin(expectedHash)
	return func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		if !validWant {
			return errors.New("cluster: invalid expected ca-hash format (want sha256:<64hex>)")
		}
		if len(rawCerts) == 0 {
			return errors.New("cluster: server presented no certificates")
		}
		certs := make([]*x509.Certificate, 0, len(rawCerts))
		for _, raw := range rawCerts {
			cert, err := x509.ParseCertificate(raw)
			if err != nil {
				return fmt.Errorf("cluster: parse peer cert: %w", err)
			}
			certs = append(certs, cert)
		}

		leaf := certs[0]
		if subtle.ConstantTimeCompare([]byte(SPKIPinOfCert(leaf)), []byte(want)) == 1 {
			return nil
		}

		// 若钉扎命中链中某个 CA 证书，必须进一步校验证书链密码学签名指向该钉扎根，防止 MITM 伪造叶证书并附带真 CA。
		for _, candidate := range certs[1:] {
			if subtle.ConstantTimeCompare([]byte(SPKIPinOfCert(candidate)), []byte(want)) != 1 {
				continue
			}
			roots := x509.NewCertPool()
			roots.AddCert(candidate)
			inters := x509.NewCertPool()
			for _, mid := range certs[1:] {
				if mid != candidate {
					inters.AddCert(mid)
				}
			}
			if _, err := leaf.Verify(x509.VerifyOptions{
				Roots:         roots,
				Intermediates: inters,
				KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			}); err != nil {
				return fmt.Errorf("cluster: leaf cert does not chain to pinned CA: %w", err)
			}
			return nil
		}
		return errors.New("cluster: peer SPKI pin mismatch (possible MITM)")
	}
}

// SignNodeCSR 严格校验 PKCS#10 CSR 签名并签发短寿期节点客户端证书。
// 该方法完全忽略调用方 CSR 中的 Subject/DNS/IP/URI SAN，仅写入控制面分配的 URI SAN "qwq://node/<nodeID>" 与 ExtKeyUsageClientAuth。
func (c *CA) SignNodeCSR(csrDER []byte, nodeID string, ttl time.Duration) (SignedCert, error) {
	if !validNodeIDPattern.MatchString(nodeID) {
		return SignedCert{}, errors.New("cluster: invalid node_id for certificate")
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return SignedCert{}, fmt.Errorf("cluster: parse csr: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return SignedCert{}, fmt.Errorf("cluster: invalid csr signature: %w", err)
	}
	if ttl <= 0 {
		ttl = DefaultCertTTL
	}

	serial, err := randomSerial()
	if err != nil {
		return SignedCert{}, err
	}
	now := c.nowTime()
	expiresAt := now.Add(ttl)

	nodeURI := &url.URL{Scheme: "qwq", Host: "node", Path: "/" + nodeID}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: nodeID},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              expiresAt,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
		URIs:                  []*url.URL{nodeURI},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, c.cert, csr.PublicKey, c.key)
	if err != nil {
		return SignedCert{}, fmt.Errorf("cluster: sign node cert: %w", err)
	}
	return SignedCert{
		CertDER:     certDER,
		SerialHex:   formatSerialHex(serial),
		Fingerprint: CertFingerprintSHA256(certDER),
		ExpiresAt:   expiresAt,
	}, nil
}

// SignServerCert 签发供控制面集群 gRPC 服务端使用的服务器证书，并附带根 CA 链以支持 SPKI 钉扎。
func (c *CA) SignServerCert(dnsNames []string, ips []net.IP) (tls.Certificate, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("cluster: generate server key: %w", err)
	}
	serial, err := randomSerial()
	if err != nil {
		return tls.Certificate{}, err
	}
	if len(dnsNames) == 0 && len(ips) == 0 {
		dnsNames = []string{"localhost"}
		ips = []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}
	}
	now := c.nowTime()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "qwq-cluster-controller"},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
		DNSNames:              append([]string(nil), dnsNames...),
		IPAddresses:           append([]net.IP(nil), ips...),
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, tmpl, c.cert, &priv.PublicKey, c.key)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("cluster: sign server cert: %w", err)
	}
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{
		Certificate: [][]byte{leafDER, c.CertDER()},
		PrivateKey:  priv,
		Leaf:        leaf,
	}, nil
}

// ExtractNodeID 仅从已验证的客户端证书 URI SAN 提取唯一的 qwq://node/<id>，绝不信任消息体或 Subject CN。
func ExtractNodeID(cert *x509.Certificate) (string, error) {
	if cert == nil {
		return "", errors.New("cluster: nil client certificate")
	}
	var matched string
	for _, u := range cert.URIs {
		if u == nil || u.Scheme != "qwq" || u.Host != "node" {
			continue
		}
		if matched != "" {
			return "", errors.New("cluster: multiple qwq://node URI SANs in certificate")
		}
		id := strings.TrimPrefix(u.Path, "/")
		if id == "" || strings.Contains(id, "/") || !validNodeIDPattern.MatchString(id) {
			return "", errors.New("cluster: malformed qwq://node URI SAN")
		}
		matched = id
	}
	if matched == "" {
		return "", errors.New("cluster: missing qwq://node/<id> URI SAN")
	}
	return matched, nil
}

// ======================== 内部工具函数 ========================

func (c *CA) nowTime() time.Time {
	if c.now != nil {
		return c.now().UTC()
	}
	return time.Now().UTC()
}

func randomSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	for {
		n, err := rand.Int(rand.Reader, limit)
		if err != nil {
			return nil, fmt.Errorf("cluster: generate serial: %w", err)
		}
		if n.Sign() > 0 {
			return n, nil
		}
	}
}

func formatSerialHex(serial *big.Int) string {
	if serial == nil {
		return ""
	}
	return strings.ToLower(serial.Text(16))
}

func normalizeSHA256Pin(raw string) (string, bool) {
	s := strings.ToLower(strings.TrimSpace(raw))
	hexPart, ok := strings.CutPrefix(s, "sha256:")
	if !ok || len(hexPart) != 64 {
		return "", false
	}
	if _, err := hex.DecodeString(hexPart); err != nil {
		return "", false
	}
	return "sha256:" + hexPart, true
}

func parseECDSAPrivateKey(der []byte) (*ecdsa.PrivateKey, error) {
	if k, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		ecKey, ok := k.(*ecdsa.PrivateKey)
		if !ok {
			return nil, errors.New("not an ECDSA private key")
		}
		return ecKey, nil
	}
	return x509.ParseECPrivateKey(der)
}

func fileExists(path string) bool {
	st, err := os.Stat(path)
	return err == nil && !st.IsDir()
}

func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	ok := false
	defer func() {
		if !ok {
			_ = os.Remove(tmpName)
		}
	}()
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	ok = true
	return nil
}
