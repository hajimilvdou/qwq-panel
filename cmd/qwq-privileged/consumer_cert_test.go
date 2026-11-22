// SPDX-License-Identifier: AGPL-3.0-only

//go:build linux

package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"io/fs"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/qwq-panel/qwq/internal/prerequisites/fault"
	"github.com/qwq-panel/qwq/internal/sandbox"
)

// ======================== 测试夹具：临时 Unix Socket 与运行时证书 ========================

const testNobodyID = 65534

func startConsumerCertSocketServer(t *testing.T, h *testHost) *sandbox.HelperClient {
	t.Helper()
	sockDir, err := os.MkdirTemp("", "qwq-cc-*")
	if err != nil {
		t.Fatalf("create socket temp dir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(sockDir) })
	sockPath := filepath.Join(sockDir, "h.sock")
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("listen unix socket: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- h.server.serve(ctx, ln, false) }()
	t.Cleanup(func() {
		cancel()
		_ = ln.Close()
		select {
		case err := <-done:
			if err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, net.ErrClosed) {
				t.Errorf("helper server exited with error: %v", err)
			}
		case <-time.After(3 * time.Second):
			t.Error("helper server did not stop within timeout")
		}
	})
	return sandbox.NewHelperClient(sockPath)
}

func generateTestCertPair(t *testing.T, sni string) ([]byte, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ecdsa key: %v", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 62))
	if err != nil {
		t.Fatalf("generate serial: %v", err)
	}
	now := time.Now().UTC()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: sni},
		DNSNames:              []string{sni},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal pkcs8 key: %v", err)
	}
	defer clear(keyDER)
	chainPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	t.Cleanup(func() { clear(keyPEM) })
	return chainPEM, keyPEM
}

func sha256Hex(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func prepareConsumerStateDir(t *testing.T, h *testHost, pluginID string, pluginUID, defaultUID, defaultGID int, pluginMode, defaultMode fs.FileMode) string {
	t.Helper()
	if err := os.MkdirAll(h.cfg.PrivateDataRoot, 0o755); err != nil {
		t.Fatalf("mkdir PrivateDataRoot: %v", err)
	}
	if err := os.Chmod(filepath.Dir(h.cfg.PrivateDataRoot), 0o755); err != nil {
		t.Fatalf("chmod private parent: %v", err)
	}
	if err := os.Chmod(h.cfg.PrivateDataRoot, 0o755); err != nil {
		t.Fatalf("chmod PrivateDataRoot: %v", err)
	}
	pluginDir := filepath.Join(h.cfg.PrivateDataRoot, pluginID)
	if err := os.Mkdir(pluginDir, pluginMode); err != nil && !errors.Is(err, fs.ErrExist) {
		t.Fatalf("mkdir pluginDir: %v", err)
	}
	if err := os.Chmod(pluginDir, pluginMode); err != nil {
		t.Fatalf("chmod pluginDir: %v", err)
	}
	defaultDir := filepath.Join(pluginDir, "default")
	if err := os.Mkdir(defaultDir, defaultMode); err != nil && !errors.Is(err, fs.ErrExist) {
		t.Fatalf("mkdir defaultDir: %v", err)
	}
	if err := os.Chmod(defaultDir, defaultMode); err != nil {
		t.Fatalf("chmod defaultDir: %v", err)
	}
	if os.Geteuid() == 0 {
		if pluginUID >= 0 {
			if err := os.Chown(pluginDir, pluginUID, pluginUID); err != nil {
				t.Fatalf("chown pluginDir: %v", err)
			}
		}
		if defaultUID >= 0 && defaultGID >= 0 {
			if err := os.Chown(defaultDir, defaultUID, defaultGID); err != nil {
				t.Fatalf("chown defaultDir: %v", err)
			}
		}
	}
	return defaultDir
}

func testConsumerBinding(pluginID, bindingID string, generation uint64, policyRev string) sandbox.ConsumerCertBinding {
	return sandbox.ConsumerCertBinding{
		ID:            bindingID,
		CertificateID: "cert-edge-1",
		Generation:    generation,
		Consumer: sandbox.ConsumerCertConsumer{
			PluginID:  pluginID,
			ProfileID: "edge-h2",
			NodeID:    "local",
			SNI:       "edge.example.com",
			Purpose:   "proxy.hysteria2",
			Test:      true,
		},
		PolicyRevision: policyRev,
	}
}

func requireConsumerCertErrCode(t *testing.T, err error, wantCode string, forbiddenSubstrings ...string) {
	t.Helper()
	var ce *sandbox.ConsumerCertError
	if !errors.As(err, &ce) {
		t.Fatalf("error = %T (%v), want *sandbox.ConsumerCertError with code %s", err, err, wantCode)
	}
	if ce.Code != wantCode {
		t.Fatalf("ConsumerCertError.Code = %q (detail=%q), want %q", ce.Code, ce.Detail, wantCode)
	}
	for _, s := range forbiddenSubstrings {
		if s != "" && strings.Contains(ce.Detail, s) {
			t.Fatalf("ConsumerCertError.Detail leaked %q: %q", s, ce.Detail)
		}
	}
}

func requireFaultCode(t *testing.T, err error, wantCode string) {
	t.Helper()
	if err == nil || fault.Code(err) != wantCode {
		t.Fatalf("fault.Code(%v) = %q, want %q", err, fault.Code(err), wantCode)
	}
}

// ======================== 完整 Unix Socket 生命周期集成测试 ========================

func TestConsumerCertLifecycleOverUnixSocket(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("consumer-cert Unix 客户端集成测试要求真实 root peer，须在 Root Linux 门禁执行")
	}
	const (
		pluginID  = "core.xray"
		bindingID = "binding-edge-1"
	)
	h := newTestHost(t)
	defaultDir := prepareConsumerStateDir(t, h, pluginID, 0, testNobodyID, testNobodyID, 0o755, 0o700)
	client := startConsumerCertSocketServer(t, h)
	ctx := context.Background()

	chain1, key1 := generateTestCertPair(t, "edge.example.com")
	binding1 := testConsumerBinding(pluginID, bindingID, 1, "policy-r1")

	// 1. Stage g1（带 ProfileID: "edge-h2"）
	proof1, err := client.StageConsumerCert(ctx, sandbox.ConsumerCertStageRequest{
		PluginID:         pluginID,
		Binding:          binding1,
		FullchainBase64:  base64.StdEncoding.EncodeToString(chain1),
		PrivateKeyBase64: base64.StdEncoding.EncodeToString(key1),
	})
	if err != nil {
		t.Fatalf("Stage g1: %v", err)
	}
	if proof1.Binding != binding1 || proof1.FullchainSHA256 != sha256Hex(chain1) || proof1.PrivateKeySHA256 != sha256Hex(key1) {
		t.Fatalf("Stage g1 proof mismatch: %+v", proof1)
	}

	// 验证文件只落在 <PrivateDataRoot>/<pluginID>/default/tls/bindings/<id>/...，绝不落在 <pluginID>/edge-h2
	g1ChainPath := filepath.Join(defaultDir, "tls", "bindings", bindingID, "generations", "g1", "fullchain.pem")
	if _, err := os.Lstat(g1ChainPath); err != nil {
		t.Fatalf("expected staged file under default dir: %v", err)
	}
	profilePath := filepath.Join(h.cfg.PrivateDataRoot, pluginID, "edge-h2")
	if _, err := os.Lstat(profilePath); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("unexpected profile directory created at %s: %v", profilePath, err)
	}

	// 2. Current 尚未激活，应为 nil
	cur, err := client.CurrentConsumerCert(ctx, pluginID, bindingID)
	if err != nil || cur != nil {
		t.Fatalf("Current before activate = %+v, %v; want nil, nil", cur, err)
	}

	// 3. Activate nil -> g1
	prev, err := client.ActivateConsumerCert(ctx, sandbox.ConsumerCertActivateRequest{
		PluginID: pluginID,
		Expected: nil,
		Wanted:   proof1,
	})
	if err != nil || prev != nil {
		t.Fatalf("Activate nil->g1 = %+v, %v; want nil, nil", prev, err)
	}
	cur, err = client.CurrentConsumerCert(ctx, pluginID, bindingID)
	if err != nil || cur == nil || *cur != proof1 {
		t.Fatalf("Current after nil->g1 = %+v, %v; want %+v", cur, err, proof1)
	}

	// 4. 同代 Re-Stage 更新 PolicyRevision，再 Activate g1 -> g1_v2
	binding1v2 := testConsumerBinding(pluginID, bindingID, 1, "policy-r2")
	proof1v2, err := client.StageConsumerCert(ctx, sandbox.ConsumerCertStageRequest{
		PluginID:         pluginID,
		Binding:          binding1v2,
		FullchainBase64:  base64.StdEncoding.EncodeToString(chain1),
		PrivateKeyBase64: base64.StdEncoding.EncodeToString(key1),
	})
	if err != nil {
		t.Fatalf("Re-Stage g1 policy-r2: %v", err)
	}
	if proof1v2.Binding != binding1v2 || proof1v2.FullchainSHA256 != proof1.FullchainSHA256 || proof1v2.PrivateKeySHA256 != proof1.PrivateKeySHA256 {
		t.Fatalf("Re-Stage g1_v2 proof mismatch: %+v", proof1v2)
	}
	prev, err = client.ActivateConsumerCert(ctx, sandbox.ConsumerCertActivateRequest{
		PluginID: pluginID,
		Expected: &proof1,
		Wanted:   proof1v2,
	})
	if err != nil || prev == nil || *prev != proof1 {
		t.Fatalf("Activate g1->g1_v2 prev = %+v, %v; want %+v", prev, err, proof1)
	}
	cur, err = client.CurrentConsumerCert(ctx, pluginID, bindingID)
	if err != nil || cur == nil || *cur != proof1v2 {
		t.Fatalf("Current after g1->g1_v2 = %+v, %v; want %+v", cur, err, proof1v2)
	}

	// 5. Stage g2 -> Activate g1_v2 -> g2
	chain2, key2 := generateTestCertPair(t, "edge.example.com")
	binding2 := testConsumerBinding(pluginID, bindingID, 2, "policy-r2")
	proof2, err := client.StageConsumerCert(ctx, sandbox.ConsumerCertStageRequest{
		PluginID:         pluginID,
		Binding:          binding2,
		FullchainBase64:  base64.StdEncoding.EncodeToString(chain2),
		PrivateKeyBase64: base64.StdEncoding.EncodeToString(key2),
	})
	if err != nil {
		t.Fatalf("Stage g2: %v", err)
	}
	prev, err = client.ActivateConsumerCert(ctx, sandbox.ConsumerCertActivateRequest{
		PluginID: pluginID,
		Expected: &proof1v2,
		Wanted:   proof2,
	})
	if err != nil || prev == nil || *prev != proof1v2 {
		t.Fatalf("Activate g1_v2->g2 prev = %+v, %v; want %+v", prev, err, proof1v2)
	}
	cur, err = client.CurrentConsumerCert(ctx, pluginID, bindingID)
	if err != nil || cur == nil || *cur != proof2 {
		t.Fatalf("Current after g1_v2->g2 = %+v, %v; want %+v", cur, err, proof2)
	}

	// 6. Rollback Activate g2 -> g1_v2
	prev, err = client.ActivateConsumerCert(ctx, sandbox.ConsumerCertActivateRequest{
		PluginID: pluginID,
		Expected: &proof2,
		Wanted:   proof1v2,
	})
	if err != nil || prev == nil || *prev != proof2 {
		t.Fatalf("Rollback Activate g2->g1_v2 prev = %+v, %v; want %+v", prev, err, proof2)
	}
	cur, err = client.CurrentConsumerCert(ctx, pluginID, bindingID)
	if err != nil || cur == nil || *cur != proof1v2 {
		t.Fatalf("Current after rollback = %+v, %v; want %+v", cur, err, proof1v2)
	}

	// 7. Remove -> Current == nil -> 再次 Remove 幂等
	removed, err := client.RemoveConsumerCert(ctx, pluginID, bindingID)
	if err != nil || !removed {
		t.Fatalf("Remove = %v, %v; want true, nil", removed, err)
	}
	cur, err = client.CurrentConsumerCert(ctx, pluginID, bindingID)
	if err != nil || cur != nil {
		t.Fatalf("Current after Remove = %+v, %v; want nil, nil", cur, err)
	}
	if _, err := client.RemoveConsumerCert(ctx, pluginID, bindingID); err != nil {
		t.Fatalf("second Remove should be idempotent, got: %v", err)
	}
}

// ======================== 状态目录边界校验：符号链接、宽权限与缺失目录 ========================

func TestOpenConsumerStateRootSafetyChecks(t *testing.T) {
	t.Run("invalid plugin id", func(t *testing.T) {
		h := newTestHost(t)
		for _, bad := range []string{"", "../etc", "a/b", "UPPER"} {
			r, err := h.server.openConsumerStateRoot(bad)
			if r != nil {
				_ = r.Close()
			}
			requireFaultCode(t, err, "CONSUMER_FILES_INVALID")
		}
	})

	t.Run("missing roots never create dirs", func(t *testing.T) {
		h := newTestHost(t)
		r, err := h.server.openConsumerStateRoot("alpha")
		if r != nil {
			_ = r.Close()
		}
		requireFaultCode(t, err, "NOT_FOUND")
		if _, err := os.Lstat(h.cfg.PrivateDataRoot); !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("openConsumerStateRoot created PrivateDataRoot: %v", err)
		}

		if err := os.MkdirAll(h.cfg.PrivateDataRoot, 0o755); err != nil {
			t.Fatal(err)
		}
		r, err = h.server.openConsumerStateRoot("alpha")
		if r != nil {
			_ = r.Close()
		}
		requireFaultCode(t, err, "NOT_FOUND")
		if _, err := os.Lstat(filepath.Join(h.cfg.PrivateDataRoot, "alpha")); !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("openConsumerStateRoot created plugin dir: %v", err)
		}

		if err := os.Mkdir(filepath.Join(h.cfg.PrivateDataRoot, "alpha"), 0o755); err != nil {
			t.Fatal(err)
		}
		r, err = h.server.openConsumerStateRoot("alpha")
		if r != nil {
			_ = r.Close()
		}
		requireFaultCode(t, err, "NOT_FOUND")
		if _, err := os.Lstat(filepath.Join(h.cfg.PrivateDataRoot, "alpha", "default")); !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("openConsumerStateRoot created default dir: %v", err)
		}
	})

	t.Run("symlink at plugin or default rejected", func(t *testing.T) {
		h := newTestHost(t)
		victim := t.TempDir()
		if err := os.MkdirAll(filepath.Join(victim, "default"), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(h.cfg.PrivateDataRoot, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(victim, filepath.Join(h.cfg.PrivateDataRoot, "alpha")); err != nil {
			t.Fatal(err)
		}
		r, err := h.server.openConsumerStateRoot("alpha")
		if r != nil {
			_ = r.Close()
		}
		requireFaultCode(t, err, "CONSUMER_FILES_UNSAFE")

		betaDir := filepath.Join(h.cfg.PrivateDataRoot, "beta")
		if err := os.Mkdir(betaDir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(filepath.Join(victim, "default"), filepath.Join(betaDir, "default")); err != nil {
			t.Fatal(err)
		}
		r, err = h.server.openConsumerStateRoot("beta")
		if r != nil {
			_ = r.Close()
		}
		requireFaultCode(t, err, "CONSUMER_FILES_UNSAFE")
	})

	t.Run("unsafe permissions rejected", func(t *testing.T) {
		h := newTestHost(t)
		uid := os.Getuid()
		gid := os.Getgid()
		if os.Geteuid() == 0 {
			uid = testNobodyID
			gid = testNobodyID
		}
		// 组可写 <pluginID>
		prepareConsumerStateDir(t, h, "alpha", 0, uid, gid, 0o775, 0o700)
		r, err := h.server.openConsumerStateRoot("alpha")
		if r != nil {
			_ = r.Close()
		}
		requireFaultCode(t, err, "CONSUMER_FILES_UNSAFE")

		// default 非 0700（0755）
		prepareConsumerStateDir(t, h, "beta", 0, uid, gid, 0o755, 0o755)
		r, err = h.server.openConsumerStateRoot("beta")
		if r != nil {
			_ = r.Close()
		}
		requireFaultCode(t, err, "CONSUMER_FILES_UNSAFE")
	})
}

func TestConsumerCertUnsafeAndMissingOverUnixSocket(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("consumer-cert Unix 客户端集成测试要求真实 root peer，须在 Root Linux 门禁执行")
	}
	h := newTestHost(t)
	client := startConsumerCertSocketServer(t, h)
	ctx := context.Background()

	chain, key := generateTestCertPair(t, "edge.example.com")
	chainB64 := base64.StdEncoding.EncodeToString(chain)
	keyB64 := base64.StdEncoding.EncodeToString(key)

	// 1. 缺失 default：Stage/Activate/Current 返回 NOT_FOUND，Remove 返回 Removed: false 且无错误
	if err := os.MkdirAll(filepath.Join(h.cfg.PrivateDataRoot, "missing"), 0o755); err != nil {
		t.Fatal(err)
	}
	missingBinding := testConsumerBinding("missing", "binding-1", 1, "policy-r1")
	missingProof := sandbox.ConsumerCertProof{
		Binding:          missingBinding,
		FullchainSHA256:  sha256Hex(chain),
		PrivateKeySHA256: sha256Hex(key),
	}
	_, err := client.StageConsumerCert(ctx, sandbox.ConsumerCertStageRequest{
		PluginID:         "missing",
		Binding:          missingBinding,
		FullchainBase64:  chainB64,
		PrivateKeyBase64: keyB64,
	})
	requireConsumerCertErrCode(t, err, "NOT_FOUND", h.cfg.PrivateDataRoot)

	_, err = client.ActivateConsumerCert(ctx, sandbox.ConsumerCertActivateRequest{
		PluginID: "missing",
		Wanted:   missingProof,
	})
	requireConsumerCertErrCode(t, err, "NOT_FOUND", h.cfg.PrivateDataRoot)

	_, err = client.CurrentConsumerCert(ctx, "missing", "binding-1")
	requireConsumerCertErrCode(t, err, "NOT_FOUND", h.cfg.PrivateDataRoot)

	removed, err := client.RemoveConsumerCert(ctx, "missing", "binding-1")
	if err != nil || removed {
		t.Fatalf("Remove on missing default = %v, %v; want false, nil", removed, err)
	}

	// 2. 符号链接在 <pluginID> 和 default 均返回 CONSUMER_FILES_UNSAFE
	victim := t.TempDir()
	victimDefault := filepath.Join(victim, "default")
	if err := os.MkdirAll(victimDefault, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(victimDefault, testNobodyID, testNobodyID); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victim, filepath.Join(h.cfg.PrivateDataRoot, "symplugin")); err != nil {
		t.Fatal(err)
	}
	_, err = client.StageConsumerCert(ctx, sandbox.ConsumerCertStageRequest{
		PluginID:         "symplugin",
		Binding:          testConsumerBinding("symplugin", "binding-1", 1, "policy-r1"),
		FullchainBase64:  chainB64,
		PrivateKeyBase64: keyB64,
	})
	requireConsumerCertErrCode(t, err, "CONSUMER_FILES_UNSAFE", h.cfg.PrivateDataRoot)
	_, err = client.RemoveConsumerCert(ctx, "symplugin", "binding-1")
	requireConsumerCertErrCode(t, err, "CONSUMER_FILES_UNSAFE", h.cfg.PrivateDataRoot)

	symDefParent := filepath.Join(h.cfg.PrivateDataRoot, "symdefault")
	if err := os.Mkdir(symDefParent, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victimDefault, filepath.Join(symDefParent, "default")); err != nil {
		t.Fatal(err)
	}
	_, err = client.StageConsumerCert(ctx, sandbox.ConsumerCertStageRequest{
		PluginID:         "symdefault",
		Binding:          testConsumerBinding("symdefault", "binding-1", 1, "policy-r1"),
		FullchainBase64:  chainB64,
		PrivateKeyBase64: keyB64,
	})
	requireConsumerCertErrCode(t, err, "CONSUMER_FILES_UNSAFE", h.cfg.PrivateDataRoot)

	// 3. 组可写 <pluginID> 与 0755 default 均被拒绝
	prepareConsumerStateDir(t, h, "wideparent", 0, testNobodyID, testNobodyID, 0o775, 0o700)
	_, err = client.StageConsumerCert(ctx, sandbox.ConsumerCertStageRequest{
		PluginID:         "wideparent",
		Binding:          testConsumerBinding("wideparent", "binding-1", 1, "policy-r1"),
		FullchainBase64:  chainB64,
		PrivateKeyBase64: keyB64,
	})
	requireConsumerCertErrCode(t, err, "CONSUMER_FILES_UNSAFE", h.cfg.PrivateDataRoot)

	prepareConsumerStateDir(t, h, "widedefault", 0, testNobodyID, testNobodyID, 0o755, 0o755)
	_, err = client.StageConsumerCert(ctx, sandbox.ConsumerCertStageRequest{
		PluginID:         "widedefault",
		Binding:          testConsumerBinding("widedefault", "binding-1", 1, "policy-r1"),
		FullchainBase64:  chainB64,
		PrivateKeyBase64: keyB64,
	})
	requireConsumerCertErrCode(t, err, "CONSUMER_FILES_UNSAFE", h.cfg.PrivateDataRoot)
}

// ======================== Root 生产属主策略：DynamicUser backing owner 继承与拒绝 root/agent ========================

func TestConsumerCertRootOwnershipPolicyOverUnixSocket(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root 属主策略测试需要 euid=0，须在 Root Linux 门禁执行")
	}
	h := newTestHost(t)
	h.cfg.Trust = sandbox.TrustPolicy{UID: 0, StopAt: filepath.Dir(filepath.Dir(h.cfg.PrivateDataRoot))}
	h.server.cfg.Trust = h.cfg.Trust
	client := startConsumerCertSocketServer(t, h)
	ctx := context.Background()

	chain, key := generateTestCertPair(t, "edge.example.com")
	chainB64 := base64.StdEncoding.EncodeToString(chain)
	keyB64 := base64.StdEncoding.EncodeToString(key)

	t.Run("nobody owned default inherits 65534 ownership and strict modes", func(t *testing.T) {
		const (
			pluginID  = "core.xray"
			bindingID = "binding-root-1"
		)
		defaultDir := prepareConsumerStateDir(t, h, pluginID, 0, testNobodyID, testNobodyID, 0o755, 0o700)
		binding := testConsumerBinding(pluginID, bindingID, 1, "policy-r1")

		proof, err := client.StageConsumerCert(ctx, sandbox.ConsumerCertStageRequest{
			PluginID:         pluginID,
			Binding:          binding,
			FullchainBase64:  chainB64,
			PrivateKeyBase64: keyB64,
		})
		if err != nil {
			t.Fatalf("Stage: %v", err)
		}
		if _, err := client.ActivateConsumerCert(ctx, sandbox.ConsumerCertActivateRequest{
			PluginID: pluginID,
			Wanted:   proof,
		}); err != nil {
			t.Fatalf("Activate: %v", err)
		}
		cur, err := client.CurrentConsumerCert(ctx, pluginID, bindingID)
		if err != nil || cur == nil || *cur != proof {
			t.Fatalf("Current = %+v, %v; want %+v", cur, err, proof)
		}

		// 递归核验 tls/ 下所有新建目录与文件的 UID/GID 与权限位
		tlsDir := filepath.Join(defaultDir, "tls")
		visited := 0
		err = filepath.WalkDir(tlsDir, func(path string, d fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			info, err := os.Lstat(path)
			if err != nil {
				return err
			}
			st, ok := info.Sys().(*syscall.Stat_t)
			if !ok {
				t.Fatalf("missing Stat_t for %s", path)
			}
			if st.Uid != testNobodyID || st.Gid != testNobodyID {
				t.Errorf("%s owner = %d:%d, want %d:%d", path, st.Uid, st.Gid, testNobodyID, testNobodyID)
			}
			if info.IsDir() {
				if info.Mode().Perm() != 0o700 {
					t.Errorf("dir %s mode = %04o, want 0700", path, info.Mode().Perm())
				}
			} else {
				if info.Mode().Perm() != 0o600 {
					t.Errorf("file %s mode = %04o, want 0600", path, info.Mode().Perm())
				}
			}
			visited++
			return nil
		})
		if err != nil {
			t.Fatalf("walk tls dir: %v", err)
		}
		if visited < 6 {
			t.Fatalf("expected created tls tree entries >= 6, got %d", visited)
		}

		removed, err := client.RemoveConsumerCert(ctx, pluginID, bindingID)
		if err != nil || !removed {
			t.Fatalf("Remove = %v, %v; want true, nil", removed, err)
		}
	})

	t.Run("plugin dir owned by same dynamic uid succeeds", func(t *testing.T) {
		const (
			pluginID  = "dynparent"
			bindingID = "binding-dyn-1"
		)
		prepareConsumerStateDir(t, h, pluginID, testNobodyID, testNobodyID, testNobodyID, 0o700, 0o700)
		proof, err := client.StageConsumerCert(ctx, sandbox.ConsumerCertStageRequest{
			PluginID:         pluginID,
			Binding:          testConsumerBinding(pluginID, bindingID, 1, "policy-r1"),
			FullchainBase64:  chainB64,
			PrivateKeyBase64: keyB64,
		})
		if err != nil || proof.Binding.ID != bindingID {
			t.Fatalf("Stage with dynamic-owned plugin dir failed: %+v, %v", proof, err)
		}
	})

	t.Run("root owned default dir rejected", func(t *testing.T) {
		const pluginID = "rootowned"
		prepareConsumerStateDir(t, h, pluginID, 0, 0, 0, 0o755, 0o700)
		_, err := client.StageConsumerCert(ctx, sandbox.ConsumerCertStageRequest{
			PluginID:         pluginID,
			Binding:          testConsumerBinding(pluginID, "binding-root-reject", 1, "policy-r1"),
			FullchainBase64:  chainB64,
			PrivateKeyBase64: keyB64,
		})
		requireConsumerCertErrCode(t, err, "CONSUMER_FILES_UNSAFE", h.cfg.PrivateDataRoot)
	})

	t.Run("agent user owned default dir rejected", func(t *testing.T) {
		const pluginID = "agentowned"
		ah := newTestHost(t)
		ah.cfg.Trust = sandbox.TrustPolicy{UID: 0, StopAt: filepath.Dir(filepath.Dir(ah.cfg.PrivateDataRoot))}
		ah.server.cfg.Trust = ah.cfg.Trust
		ah.server.lookupUID = func(string) (int, error) { return testNobodyID, nil }
		prepareConsumerStateDir(t, ah, pluginID, 0, testNobodyID, testNobodyID, 0o755, 0o700)
		agentClient := startConsumerCertSocketServer(t, ah)

		_, err := agentClient.CurrentConsumerCert(ctx, pluginID, "binding-1")
		requireConsumerCertErrCode(t, err, "CONSUMER_FILES_UNSAFE", ah.cfg.PrivateDataRoot)
	})

	t.Run("unrelated plugin parent owner rejected", func(t *testing.T) {
		const pluginID = "otherparent"
		prepareConsumerStateDir(t, h, pluginID, testNobodyID-1, testNobodyID, testNobodyID, 0o755, 0o700)
		_, err := client.CurrentConsumerCert(ctx, pluginID, "binding-1")
		requireConsumerCertErrCode(t, err, "CONSUMER_FILES_UNSAFE", h.cfg.PrivateDataRoot)
	})
}

// ======================== 错误脱敏、取消与类型转换单元测试 ========================

func TestConsumerCertSanitizerAndConversions(t *testing.T) {
	leakedErr := fault.New("CONSUMER_FILES_IO", "/var/lib/private/secret/privkey.pem leaked detail")
	leakedErr.Uncertain = true
	status := consumerCertStatusFromError(0, leakedErr)
	if status.OK || status.Code != "CONSUMER_FILES_IO" || !status.Uncertain {
		t.Fatalf("unexpected status: %+v", status)
	}
	if strings.Contains(status.Error, "/var/lib") || strings.Contains(status.Error, "privkey") {
		t.Fatalf("error status leaked internal detail: %q", status.Error)
	}

	binding := testConsumerBinding("core.xray", "binding-conv", 3, "policy-r9")
	proof := sandbox.ConsumerCertProof{
		Binding:          binding,
		FullchainSHA256:  strings.Repeat("a", 64),
		PrivateKeySHA256: strings.Repeat("b", 64),
	}
	converted := toConsumerProof(proof)
	roundTrip := fromConsumerProof(&converted)
	if roundTrip == nil || *roundTrip != proof {
		t.Fatalf("proof round-trip mismatch: got %+v, want %+v", roundTrip, proof)
	}
	if fromConsumerProof(nil) != nil {
		t.Fatal("fromConsumerProof(nil) should return nil")
	}

	h := newTestHost(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	resp := h.server.handleConsumerCert(ctx, sandbox.DecodedHelperRequest{
		ConsumerCurrent: &sandbox.ConsumerCertCurrentRequest{PluginID: "alpha", BindingID: "b1"},
	})
	typed, ok := resp.(sandbox.ConsumerCertCurrentResponse)
	if !ok || typed.OK || typed.Code != "CANCELLED" {
		t.Fatalf("cancelled response = %#v, want CANCELLED", resp)
	}
}
