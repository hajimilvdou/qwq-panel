// SPDX-License-Identifier: AGPL-3.0-only

package certificates

import (
	"bytes"
	"context"
	"crypto/x509"
	_ "embed"

	"github.com/qwq-panel/qwq/internal/prerequisites/fault"
	"github.com/qwq-panel/qwq/internal/tlsmgr"
)

// ======================== 启动时固定根池，请求不能指定根或 CA 地址 ========================

//go:embed trustdata/letsencrypt-staging-root-x1.crt
var stagingRootX1 []byte

//go:embed trustdata/letsencrypt-staging-root-x2.crt
var stagingRootX2 []byte

type HostTrustRootsOptions struct {
	PublicRoots     *x509.CertPool
	StagingRootsPEM []byte
}

type HostTrustRoots struct {
	public  *x509.CertPool
	staging *x509.CertPool
}

// NewHostTrustRoots 在启动时准备系统根和独立 staging 根；显式空配置不会降级。
func NewHostTrustRoots(options HostTrustRootsOptions) (*HostTrustRoots, error) {
	public := options.PublicRoots
	if public == nil {
		var err error
		public, err = x509.SystemCertPool()
		if err != nil {
			return nil, fault.New("TRUST_UNAVAILABLE", "系统信任根暂不可用")
		}
	}
	if public == nil || public.Equal(x509.NewCertPool()) {
		return nil, fault.New("TRUST_UNAVAILABLE", "系统信任根为空")
	}
	stagingPEM := options.StagingRootsPEM
	if stagingPEM == nil {
		stagingPEM = append(bytes.Clone(stagingRootX1), stagingRootX2...)
	}
	staging, err := parseHostTrustAnchors(stagingPEM)
	if err != nil {
		return nil, err
	}
	return &HostTrustRoots{public: public.Clone(), staging: staging}, nil
}

// parseHostTrustAnchors 拒绝非 CA、私钥、重复根和不完整 PEM，不忽略任何尾部。
func parseHostTrustAnchors(input []byte) (*x509.CertPool, error) {
	if len(input) == 0 || len(input) > 32<<10 {
		return nil, fault.New("VALIDATION_FAILED", "staging 信任根为空或超过上限")
	}
	chain, err := tlsmgr.ParseCertificateChain(input)
	if err != nil {
		return nil, fault.New("VALIDATION_FAILED", "staging 信任根 PEM 无效")
	}
	pool := x509.NewCertPool()
	for _, certificate := range chain {
		if !certificate.BasicConstraintsValid || !certificate.IsCA || certificate.KeyUsage&x509.KeyUsageCertSign == 0 {
			return nil, fault.New("VALIDATION_FAILED", "staging 信任项必须为 CA 根证书")
		}
		if err := certificate.CheckSignatureFrom(certificate); err != nil {
			return nil, fault.New("VALIDATION_FAILED", "staging 根证书签名无效")
		}
		pool.AddCert(certificate)
	}
	return pool, nil
}

// Roots 只提供所选类别的独立池；test 的专属根仍由 ValidateMaterial 核定。
func (r *HostTrustRoots) Roots(ctx context.Context, trust tlsmgr.TrustClass) (*x509.CertPool, error) {
	if r == nil || ctx == nil {
		return nil, fault.New("TRUST_UNAVAILABLE", "宿主信任根未装配")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var pool *x509.CertPool
	switch trust {
	case tlsmgr.PublicTrust:
		pool = r.public
	case tlsmgr.StagingTrust:
		pool = r.staging
	case tlsmgr.TestTrust:
		return nil, nil
	default:
		return nil, fault.New("VALIDATION_FAILED", "信任类别无效")
	}
	if pool == nil {
		return nil, fault.New("TRUST_UNAVAILABLE", "指定信任根未装配")
	}
	return pool.Clone(), nil
}

var _ TrustRoots = (*HostTrustRoots)(nil)
