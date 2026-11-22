// SPDX-License-Identifier: AGPL-3.0-only

package tlsmgr

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"log/slog"
	"slices"
	"strings"
	"time"
	"unicode"

	"github.com/qwq-panel/qwq/internal/prerequisites/fault"
	"github.com/qwq-panel/qwq/internal/prerequisites/names"
)

// ======================== 复用密码学材料边界 ========================

const (
	MaxCertificatePEM = 48 << 10
	MaxPrivateKeyPEM  = 16 << 10
)

// Material 的私钥没有可序列化字段，所有日志与字符串形式都脱敏。
// 只有宿主受控后端持有该值；插件 capability 返回资源引用和公开元数据。
type Material struct {
	certificatePEM []byte
	privateKeyPEM  []byte
}

func (Material) String() string       { return "tlsmgr.Material{[REDACTED]}" }
func (Material) GoString() string     { return "tlsmgr.Material{[REDACTED]}" }
func (Material) LogValue() slog.Value { return slog.StringValue("[REDACTED]") }
func (Material) MarshalJSON() ([]byte, error) {
	return nil, errors.New("tlsmgr: refusing to serialize private material")
}

// NewMaterial 复制受控输入，不使后续调用者修改影响正在校验的私钥。
func NewMaterial(chainPEM, keyPEM []byte) (Material, error) {
	if len(chainPEM) == 0 || len(chainPEM) > MaxCertificatePEM || len(keyPEM) == 0 || len(keyPEM) > MaxPrivateKeyPEM {
		return Material{}, fault.New("CERTIFICATE_INVALID", "证书链或私钥为空或超过长度上限")
	}
	return Material{certificatePEM: bytes.Clone(chainPEM), privateKeyPEM: bytes.Clone(keyPEM)}, nil
}

// CertificatePEM 返回可单独公开的证书链副本。
func (m Material) CertificatePEM() []byte { return bytes.Clone(m.certificatePEM) }

// PrivateKeyPEM 仅供宿主加密保存与受控 materialize，副本用完后必须清除。
func (m Material) PrivateKeyPEM() []byte { return bytes.Clone(m.privateKeyPEM) }

// Clear 尽力清除本值持有的材料，不承诺清除 Go 运行时已复制的内存。
func (m *Material) Clear() {
	clear(m.privateKeyPEM)
	clear(m.certificatePEM)
	m.privateKeyPEM, m.certificatePEM = nil, nil
}

type MaterialPurpose string

const (
	ServerTLS     MaterialPurpose = "tls_server"
	TestServerTLS MaterialPurpose = "tls_server_test"
)

type TrustClass string

const (
	PublicTrust  TrustClass = "public"
	StagingTrust TrustClass = "staging"
	TestTrust    TrustClass = "test"
)

// MaterialOptions 的信任根与用途只来自宿主受控配置，不从 operation 接收 CA URL。
type MaterialOptions struct {
	SANs    []string
	Now     time.Time
	Purpose MaterialPurpose
	Trust   TrustClass
	Roots   *x509.CertPool
}

// CertificateMetadata 只包含公开信息；不携带私钥、secret ref 或内部路径。
type CertificateMetadata struct {
	SANs        []string        `json:"sans"`
	Issuer      string          `json:"issuer"`
	Fingerprint string          `json:"fingerprint"`
	NotBefore   time.Time       `json:"not_before"`
	NotAfter    time.Time       `json:"not_after"`
	Purpose     MaterialPurpose `json:"purpose"`
	Trust       TrustClass      `json:"trust"`
}

// CanonicalSANs 与 DNS 模块共享 IDNA 规则并保持稳定集合顺序。
func CanonicalSANs(input []string) ([]string, error) {
	if len(input) == 0 || len(input) > 16 {
		return nil, fault.New("SAN_INVALID", "证书需要 1 至 16 个 SAN")
	}
	out := make([]string, 0, len(input))
	for _, value := range input {
		name, err := names.SAN(value)
		if err != nil {
			return nil, fault.New("SAN_INVALID", "证书 SAN 无效")
		}
		out = append(out, name)
	}
	slices.Sort(out)
	return slices.Compact(out), nil
}

// parsePair 与管理监听器共用最小解析路径；用途、信任根和 exact SAN 在外层校验。
func parsePair(chainPEM, keyPEM []byte) (*cert, error) {
	pair, err := tls.X509KeyPair(chainPEM, keyPEM)
	if err != nil {
		return nil, fault.New("PRIVATE_KEY_MISMATCH", "证书或私钥无法解析，或私钥与证书不匹配")
	}
	if len(pair.Certificate) == 0 {
		return nil, fault.New("CERTIFICATE_INVALID", "证书链没有叶证书")
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return nil, fault.New("CERTIFICATE_INVALID", "叶证书无法解析")
	}
	pair.Leaf = leaf
	return &cert{pair: &pair, leaf: leaf, fp: fingerprint(leaf.Raw)}, nil
}

// ValidateMaterial 校验证书链、exact SAN、用途、有效期、信任与私钥匹配。
func ValidateMaterial(material Material, options MaterialOptions) (CertificateMetadata, error) {
	if options.Now.IsZero() || (options.Purpose != ServerTLS && options.Purpose != TestServerTLS) || (options.Trust != PublicTrust && options.Trust != StagingTrust && options.Trust != TestTrust) {
		return CertificateMetadata{}, fault.New("CERTIFICATE_PURPOSE_INVALID", "证书时间、用途或信任配置无效")
	}
	if (options.Purpose == TestServerTLS) != (options.Trust == TestTrust) {
		return CertificateMetadata{}, fault.New("CERTIFICATE_PURPOSE_INVALID", "测试证书必须使用明确的测试用途与信任")
	}
	expected, err := CanonicalSANs(options.SANs)
	if err != nil {
		return CertificateMetadata{}, err
	}
	chain, err := parseCertificatePEM(material.certificatePEM)
	if err != nil {
		return CertificateMetadata{}, err
	}
	if err := validatePrivatePEM(material.privateKeyPEM); err != nil {
		return CertificateMetadata{}, err
	}
	loaded, err := parsePair(material.certificatePEM, material.privateKeyPEM)
	if err != nil {
		return CertificateMetadata{}, err
	}
	leaf := loaded.leaf
	actual, err := CanonicalSANs(leaf.DNSNames)
	if err != nil || !slices.Equal(expected, actual) || len(leaf.IPAddresses) != 0 || len(leaf.URIs) != 0 || len(leaf.EmailAddresses) != 0 {
		return CertificateMetadata{}, fault.New("SAN_MISMATCH", "证书 SAN 必须与授权域名集合完全一致")
	}
	if !options.Now.Before(leaf.NotAfter) {
		return CertificateMetadata{}, fault.New("CERTIFICATE_EXPIRED", "证书已过期")
	}
	if options.Now.Before(leaf.NotBefore) {
		return CertificateMetadata{}, fault.New("CERTIFICATE_NOT_YET_VALID", "证书尚未生效")
	}
	if leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 || (leaf.IsCA && options.Purpose != TestServerTLS) {
		return CertificateMetadata{}, fault.New("CERTIFICATE_PURPOSE_INVALID", "证书不支持 TLS 服务端签名用途")
	}
	if err := validatePublicKey(leaf.PublicKey); err != nil {
		return CertificateMetadata{}, err
	}
	roots := options.Roots
	if options.Trust == TestTrust {
		if err := leaf.CheckSignature(leaf.SignatureAlgorithm, leaf.RawTBSCertificate, leaf.Signature); err != nil {
			return CertificateMetadata{}, fault.New("CERTIFICATE_CHAIN_INVALID", "测试证书必须为受控自签名证书")
		}
		roots = x509.NewCertPool()
		roots.AddCert(leaf)
	} else if roots == nil {
		if options.Trust == StagingTrust {
			return CertificateMetadata{}, fault.New("TRUST_UNAVAILABLE", "staging 信任根尚未配置")
		}
		roots, err = x509.SystemCertPool()
		if err != nil {
			return CertificateMetadata{}, fault.New("TRUST_UNAVAILABLE", "系统信任根暂不可用")
		}
	}
	intermediates := x509.NewCertPool()
	for _, certificate := range chain[1:] {
		intermediates.AddCert(certificate)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, CurrentTime: options.Now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
		return CertificateMetadata{}, fault.New("CERTIFICATE_CHAIN_INVALID", "证书链或服务端用途验证失败")
	}
	return CertificateMetadata{SANs: actual, Issuer: safeIssuer(leaf.Issuer.String()), Fingerprint: loaded.fp,
		NotBefore: leaf.NotBefore.UTC(), NotAfter: leaf.NotAfter.UTC(), Purpose: options.Purpose, Trust: options.Trust}, nil
}

// ParseCertificateChain 只解析完整证书 PEM；根、用途和签名信任仍由调用方校验。
func ParseCertificateChain(raw []byte) ([]*x509.Certificate, error) {
	return parseCertificatePEM(raw)
}

func parseCertificatePEM(raw []byte) ([]*x509.Certificate, error) {
	if len(raw) == 0 || len(raw) > MaxCertificatePEM {
		return nil, fault.New("CERTIFICATE_INVALID", "证书链长度无效")
	}
	chain := []*x509.Certificate{}
	seen := map[string]bool{}
	for len(bytes.TrimSpace(raw)) > 0 {
		block, rest, valid := decodeFirstPEM(raw, "CERTIFICATE")
		if !valid || len(block.Headers) != 0 || len(chain) >= 8 {
			return nil, fault.New("CERTIFICATE_INVALID", "证书链 PEM 格式无效")
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil || seen[string(block.Bytes)] {
			return nil, fault.New("CERTIFICATE_INVALID", "证书链存在无效或重复证书")
		}
		seen[string(block.Bytes)] = true
		chain = append(chain, certificate)
		raw = rest
	}
	if len(chain) == 0 {
		return nil, fault.New("CERTIFICATE_INVALID", "证书链为空")
	}
	return chain, nil
}

// ValidatePrivateKeyPEM 只核完整单块未加密私钥 PEM；配对、用途和信任另行校验。
func ValidatePrivateKeyPEM(raw []byte) error {
	return validatePrivatePEM(raw)
}

func validatePrivatePEM(raw []byte) error {
	if len(raw) == 0 || len(raw) > MaxPrivateKeyPEM {
		return fault.New("PRIVATE_KEY_INVALID", "私钥长度无效")
	}
	block, rest, valid := decodeFirstPEM(raw, "PRIVATE KEY", "EC PRIVATE KEY", "RSA PRIVATE KEY")
	if !valid || len(bytes.TrimSpace(rest)) != 0 || len(block.Headers) != 0 {
		return fault.New("PRIVATE_KEY_INVALID", "私钥必须是未加密的受支持 PEM 格式")
	}
	return nil
}

// decodeFirstPEM 限定首个完整块，禁止 pem.Decode 跳过前缀垃圾或损坏块。
func decodeFirstPEM(raw []byte, allowed ...string) (*pem.Block, []byte, bool) {
	raw = bytes.TrimSpace(raw)
	for _, kind := range allowed {
		start := []byte("-----BEGIN " + kind + "-----")
		if !bytes.HasPrefix(raw, start) {
			continue
		}
		end := []byte("-----END " + kind + "-----")
		index := bytes.Index(raw, end)
		if index < len(start) || bytes.Contains(raw[len(start):index], []byte("-----BEGIN ")) {
			return nil, nil, false
		}
		boundary := index + len(end)
		block, remaining := pem.Decode(raw[:boundary])
		if block == nil || block.Type != kind || len(bytes.TrimSpace(remaining)) != 0 {
			return nil, nil, false
		}
		return block, raw[boundary:], true
	}
	return nil, nil, false
}

func validatePublicKey(key any) error {
	switch public := key.(type) {
	case *rsa.PublicKey:
		if public.N.BitLen() >= 2048 && public.N.BitLen() <= 8192 {
			return nil
		}
	case *ecdsa.PublicKey:
		if public.Curve.Params().BitSize >= 256 {
			return nil
		}
	case ed25519.PublicKey:
		if len(public) == ed25519.PublicKeySize {
			return nil
		}
	}
	return fault.New("PRIVATE_KEY_UNSUPPORTED", "证书公钥算法或强度不受支持")
}

func safeIssuer(value string) string {
	clean := strings.Map(func(char rune) rune {
		if unicode.IsControl(char) {
			return -1
		}
		return char
	}, value)
	runes := []rune(clean)
	if len(runes) > 256 {
		runes = runes[:256]
	}
	return string(runes)
}

// Covers 使用标准库主机名规则验证消费 SNI，不扩大通配符匹配范围。
func Covers(metadata CertificateMetadata, hostname string) error {
	name, err := names.DNS(hostname, false)
	if err != nil {
		return fault.New("SAN_MISMATCH", "消费者域名无效")
	}
	leaf := x509.Certificate{DNSNames: metadata.SANs}
	if err := leaf.VerifyHostname(name); err != nil {
		return fault.New("SAN_MISMATCH", "证书不覆盖消费者域名")
	}
	return nil
}

// GenerateTestMaterial 复用管理监听器的生成器，测试证书固定有效一天。
func GenerateTestMaterial(now time.Time, input []string) (Material, error) {
	sans, err := CanonicalSANs(input)
	if err != nil || now.IsZero() {
		return Material{}, fault.New("SAN_INVALID", "测试证书的时间或 SAN 无效")
	}
	chain, key, err := generateSelfSignedValidity(now, sanSet{dns: sans}, 24*time.Hour)
	if err != nil {
		return Material{}, fault.New("INTERNAL", "测试证书生成失败")
	}
	defer clear(key)
	return NewMaterial(chain, key)
}
