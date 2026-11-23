// SPDX-License-Identifier: AGPL-3.0-only

package deployment

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/qwq-panel/qwq/internal/platform/clock"
	"github.com/qwq-panel/qwq/internal/prerequisites/certificates"
	"github.com/qwq-panel/qwq/internal/prerequisites/consumerfiles"
	"github.com/qwq-panel/qwq/internal/prerequisites/fault"
	"github.com/qwq-panel/qwq/internal/sandbox"
	"github.com/qwq-panel/qwq/internal/tlsmgr"
)

// ======================== 真实 TLS 握手探针、运行时健康与特权后端错误映射测试 ========================

type testLeafBundle struct {
	chainPEM    []byte
	keyPEM      []byte
	tlsCert     tls.Certificate
	fingerprint string
	chainSHA256 string
}

func generateTestLeafBundle(t *testing.T, sni string, notBefore, notAfter time.Time) testLeafBundle {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("生成 ECDSA 测试密钥失败：%v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1001),
		Subject:               pkix.Name{CommonName: sni},
		DNSNames:              []string{sni},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("生成测试叶证书失败：%v", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("编码 PKCS8 私钥失败：%v", err)
	}
	defer clear(keyDER)

	chainPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	pair, err := tls.X509KeyPair(chainPEM, keyPEM)
	if err != nil {
		t.Fatalf("构造 tls.Certificate 失败：%v", err)
	}
	fp, err := LeafFingerprintPEM(chainPEM)
	if err != nil {
		t.Fatalf("计算叶证书指纹失败：%v", err)
	}
	chainSum := sha256.Sum256(chainPEM)
	return testLeafBundle{
		chainPEM:    chainPEM,
		keyPEM:      keyPEM,
		tlsCert:     pair,
		fingerprint: fp,
		chainSHA256: hex.EncodeToString(chainSum[:]),
	}
}

func startLocalTLS13Server(t *testing.T, cert tls.Certificate) string {
	t.Helper()
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{cert},
	})
	if err != nil {
		t.Fatalf("启动本地 TLS 1.3 测试监听器失败：%v", err)
	}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			conn, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			wg.Add(1)
			go func(c net.Conn) {
				defer wg.Done()
				defer func() { _ = c.Close() }()
				_ = c.SetDeadline(time.Now().Add(2 * time.Second))
				if tlsConn, ok := c.(*tls.Conn); ok {
					_ = tlsConn.Handshake()
				}
			}(conn)
		}
	}()
	t.Cleanup(func() {
		_ = listener.Close()
		wg.Wait()
	})
	return listener.Addr().String()
}

type stubRuntime struct {
	obs RuntimeObservation
	err error
}

func (s *stubRuntime) Apply(context.Context, certificates.HostBinding, consumerfiles.Proof) error {
	return nil
}

func (s *stubRuntime) Inspect(context.Context, certificates.Consumer, string) (RuntimeObservation, error) {
	return s.obs, s.err
}

func (s *stubRuntime) InUse(context.Context, certificates.HostBinding) (bool, error) {
	return s.obs.Running, nil
}

func TestVerifyRuntimeHealthAndTLSHandshakeProber(t *testing.T) {
	now := time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)
	sni := "edge.example.test"
	bundle := generateTestLeafBundle(t, sni, now.Add(-time.Hour), now.Add(24*time.Hour))
	otherBundle := generateTestLeafBundle(t, sni, now.Add(-time.Hour), now.Add(24*time.Hour))
	endpoint := startLocalTLS13Server(t, bundle.tlsCert)
	otherEndpoint := startLocalTLS13Server(t, otherBundle.tlsCert)

	consumer := certificates.Consumer{
		PluginID:  "alpha",
		ProfileID: "default",
		NodeID:    "node-1",
		SNI:       sni,
		Purpose:   "tls_server",
	}
	proof := consumerfiles.Proof{
		Binding: certificates.HostBinding{
			ID:             "bind-01",
			CertificateID:  "cert-01",
			Generation:     3,
			Consumer:       consumer,
			PolicyRevision: "rev-01",
		},
		FullchainSHA256:  bundle.chainSHA256,
		PrivateKeySHA256: strings.Repeat("c", 64),
	}
	goodObs := RuntimeObservation{
		Running:          true,
		BindingID:        proof.Binding.ID,
		ActiveGeneration: proof.Binding.Generation,
		PolicyRevision:   proof.Binding.PolicyRevision,
		FullchainSHA256:  proof.FullchainSHA256,
		LeafFingerprint:  bundle.fingerprint,
		SNI:              sni,
		Endpoint:         endpoint,
	}
	prober := &TLSHandshakeProber{
		Timeout: 2 * time.Second,
		Clock:   clock.NewFake(now),
	}

	t.Run("healthy-match", func(t *testing.T) {
		rt := &stubRuntime{obs: goodObs}
		if err := VerifyRuntimeHealth(t.Context(), consumer, proof, bundle.fingerprint, rt, prober); err != nil {
			t.Fatalf("匹配的叶指纹、SNI 与 Inspect 未通过健康校验：%v", err)
		}
	})

	t.Run("wrong-leaf-fingerprint-served", func(t *testing.T) {
		obs := goodObs
		obs.Endpoint = otherEndpoint
		rt := &stubRuntime{obs: obs}
		err := VerifyRuntimeHealth(t.Context(), consumer, proof, bundle.fingerprint, rt, prober)
		if err == nil || fault.Code(err) != "DEPLOYMENT_UNHEALTHY" {
			t.Fatalf("对端返回不同叶证书未被拒绝：%v", err)
		}
	})

	t.Run("wrong-sni", func(t *testing.T) {
		wrongConsumer := consumer
		wrongConsumer.SNI = "other.example.test"
		obs := goodObs
		obs.SNI = wrongConsumer.SNI
		rt := &stubRuntime{obs: obs}
		err := VerifyRuntimeHealth(t.Context(), wrongConsumer, proof, bundle.fingerprint, rt, prober)
		if err == nil || fault.Code(err) != "DEPLOYMENT_UNHEALTHY" {
			t.Fatalf("不匹配的 SNI 未被拒绝：%v", err)
		}
	})

	t.Run("expired-certificate", func(t *testing.T) {
		expiredProber := &TLSHandshakeProber{
			Timeout: 2 * time.Second,
			Clock:   clock.NewFake(now.Add(25 * time.Hour)),
		}
		rt := &stubRuntime{obs: goodObs}
		err := VerifyRuntimeHealth(t.Context(), consumer, proof, bundle.fingerprint, rt, expiredProber)
		if err == nil || fault.Code(err) != "DEPLOYMENT_UNHEALTHY" {
			t.Fatalf("过期证书未被拒绝：%v", err)
		}
	})

	t.Run("not-yet-valid-certificate", func(t *testing.T) {
		earlyProber := &TLSHandshakeProber{
			Timeout: 2 * time.Second,
			Clock:   clock.NewFake(now.Add(-2 * time.Hour)),
		}
		rt := &stubRuntime{obs: goodObs}
		err := VerifyRuntimeHealth(t.Context(), consumer, proof, bundle.fingerprint, rt, earlyProber)
		if err == nil || fault.Code(err) != "DEPLOYMENT_UNHEALTHY" {
			t.Fatalf("未到生效时间的证书未被拒绝：%v", err)
		}
	})

	t.Run("unreachable-endpoint", func(t *testing.T) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		closedAddr := ln.Addr().String()
		_ = ln.Close()

		obs := goodObs
		obs.Endpoint = closedAddr
		rt := &stubRuntime{obs: obs}
		err = VerifyRuntimeHealth(t.Context(), consumer, proof, bundle.fingerprint, rt, prober)
		if err == nil || fault.Code(err) != "DEPLOYMENT_UNHEALTHY" {
			t.Fatalf("不可达端点未被拒绝：%v", err)
		}
	})

	t.Run("inspect-mismatches-and-missing-deps", func(t *testing.T) {
		mutations := []struct {
			name   string
			mutate func(*RuntimeObservation)
		}{
			{"not-running", func(o *RuntimeObservation) { o.Running = false }},
			{"wrong-binding-id", func(o *RuntimeObservation) { o.BindingID = "bind-99" }},
			{"wrong-generation", func(o *RuntimeObservation) { o.ActiveGeneration = 99 }},
			{"wrong-policy-revision", func(o *RuntimeObservation) { o.PolicyRevision = "rev-99" }},
			{"wrong-fullchain-sha256", func(o *RuntimeObservation) { o.FullchainSHA256 = strings.Repeat("d", 64) }},
			{"wrong-leaf-fp-in-obs", func(o *RuntimeObservation) { o.LeafFingerprint = otherBundle.fingerprint }},
			{"wrong-sni-in-obs", func(o *RuntimeObservation) { o.SNI = "other.example.test" }},
		}
		for _, tc := range mutations {
			t.Run(tc.name, func(t *testing.T) {
				obs := goodObs
				tc.mutate(&obs)
				rt := &stubRuntime{obs: obs}
				err := VerifyRuntimeHealth(t.Context(), consumer, proof, bundle.fingerprint, rt, prober)
				if err == nil || fault.Code(err) != "DEPLOYMENT_UNHEALTHY" {
					t.Fatalf("Inspect 异常 (%s) 未被拒绝：%v", tc.name, err)
				}
			})
		}

		if err := VerifyRuntimeHealth(t.Context(), consumer, proof, bundle.fingerprint, &stubRuntime{obs: goodObs}, nil); err == nil || fault.Code(err) != "DEPLOYMENT_UNHEALTHY" {
			t.Fatalf("缺少 prober 未被拒绝：%v", err)
		}
		if err := VerifyRuntimeHealth(t.Context(), consumer, proof, bundle.fingerprint, nil, prober); err == nil || fault.Code(err) != "DEPLOYMENT_UNHEALTHY" {
			t.Fatalf("缺少 runtime 未被拒绝：%v", err)
		}
		if _, err := LeafFingerprintPEM([]byte("not-a-pem")); err == nil || fault.Code(err) != "CERTIFICATE_INVALID" {
			t.Fatalf("非法证书 PEM 未返回 CERTIFICATE_INVALID：%v", err)
		}
	})
}

func TestHelperFileBackendErrorMappingAndNilGuards(t *testing.T) {
	ce := &sandbox.ConsumerCertError{
		Code:      "CONSUMER_FILES_CONFLICT",
		Detail:    "cas state uncertain",
		Uncertain: true,
	}
	mapped := mapHelperError(ce)
	var fe *fault.Error
	if !errors.As(mapped, &fe) || fe.Code != "CONSUMER_FILES_CONFLICT" || !fe.Uncertain {
		t.Fatalf("ConsumerCertError 映射未保留错误码与 Uncertain：err=%v", mapped)
	}

	canceled := mapHelperError(context.Canceled)
	if fault.Code(canceled) != "CANCELLED" || !errors.Is(canceled, context.Canceled) {
		t.Fatalf("context.Canceled 未映射为 CANCELLED：%v", canceled)
	}

	generic := mapHelperError(errors.New("broken pipe"))
	if fault.Code(generic) != "CONSUMER_FILES_IO" {
		t.Fatalf("底层通道错误未映射为 CONSUMER_FILES_IO：%v", generic)
	}

	var nilClientBackend HelperFileBackend
	binding := certificates.HostBinding{
		ID:             "bind-01",
		CertificateID:  "cert-01",
		Generation:     1,
		Consumer:       certificates.Consumer{PluginID: "alpha", ProfileID: "default", NodeID: "n1", SNI: "edge.example.test", Purpose: "tls_server"},
		PolicyRevision: "rev-01",
	}
	now := time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)
	bundle := generateTestLeafBundle(t, "edge.example.test", now.Add(-time.Hour), now.Add(24*time.Hour))
	mat, err := tlsmgr.NewMaterial(bundle.chainPEM, bundle.keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	defer mat.Clear()

	proof := consumerfiles.Proof{
		Binding:          binding,
		FullchainSHA256:  bundle.chainSHA256,
		PrivateKeySHA256: strings.Repeat("e", 64),
	}

	if _, err := nilClientBackend.Stage(t.Context(), binding, mat); fault.Code(err) != "BACKEND_REQUIRED" {
		t.Fatalf("nil Client Stage 未返回 BACKEND_REQUIRED：%v", err)
	}
	if _, err := nilClientBackend.Activate(t.Context(), "alpha", nil, proof); fault.Code(err) != "BACKEND_REQUIRED" {
		t.Fatalf("nil Client Activate 未返回 BACKEND_REQUIRED：%v", err)
	}
	if _, err := nilClientBackend.Current(t.Context(), "alpha", "bind-01"); fault.Code(err) != "BACKEND_REQUIRED" {
		t.Fatalf("nil Client Current 未返回 BACKEND_REQUIRED：%v", err)
	}
	if _, err := nilClientBackend.Remove(t.Context(), "alpha", "bind-01"); fault.Code(err) != "BACKEND_REQUIRED" {
		t.Fatalf("nil Client Remove 未返回 BACKEND_REQUIRED：%v", err)
	}

	var nilDirectBackend DirectFileBackend
	if _, err := nilDirectBackend.Current(t.Context(), "alpha", "bind-01"); fault.Code(err) != "BACKEND_REQUIRED" {
		t.Fatalf("nil DirectFileBackend Current 未返回 BACKEND_REQUIRED：%v", err)
	}
}

func TestHasLocalUDPListenerChecksStateAndZeroRemote(t *testing.T) {
	dir := t.TempDir()
	udp4 := filepath.Join(dir, "udp")
	udp6 := filepath.Join(dir, "udp6")

	// Port 0x20FB = 8443: connected outbound socket (state 01, non-zero remote) must NOT match.
	// Port 0x20FC = 8444: state 07 but non-zero remote must NOT match.
	// Port 0x20FD = 8445: state 07 and zero remote MUST match.
	udp4Content := strings.Join([]string{
		"  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops",
		"   0: 0100007F:20FB 08080808:0035 01 00000000:00000000 00:00000000 00000000     0        0 1001 2 0 0",
		"   1: 00000000:20FC 01010101:0035 07 00000000:00000000 00:00000000 00000000     0        0 1002 2 0 0",
		"   2: 00000000:20FD 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 1003 2 0 0",
	}, "\n") + "\n"
	// Port 0x20FE = 8446 on IPv6: state 07 and zero IPv6 remote MUST match.
	udp6Content := strings.Join([]string{
		"  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops",
		"   0: 00000000000000000000000000000000:20FE 00000000000000000000000000000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 1004 2 0 0",
	}, "\n") + "\n"

	if err := os.WriteFile(udp4, []byte(udp4Content), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(udp6, []byte(udp6Content), 0o600); err != nil {
		t.Fatal(err)
	}

	paths := []string{udp4, udp6}
	if hasLocalUDPListenerInFiles(0x20FB, paths) {
		t.Fatal("connected UDP socket (state 01) must not be treated as local listener")
	}
	if hasLocalUDPListenerInFiles(0x20FC, paths) {
		t.Fatal("UDP socket with non-zero remote address must not be treated as local listener")
	}
	if !hasLocalUDPListenerInFiles(0x20FD, paths) {
		t.Fatal("unbound IPv4 UDP listener (state 07, zero remote) was not detected")
	}
	if !hasLocalUDPListenerInFiles(0x20FE, paths) {
		t.Fatal("unbound IPv6 UDP listener (state 07, zero remote) was not detected")
	}
}
