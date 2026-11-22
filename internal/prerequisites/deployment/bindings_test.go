// SPDX-License-Identifier: AGPL-3.0-only

//go:build linux

package deployment

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/qwq-panel/qwq/internal/platform/clock"
	"github.com/qwq-panel/qwq/internal/prerequisites/certificates"
	"github.com/qwq-panel/qwq/internal/prerequisites/consumerfiles"
	"github.com/qwq-panel/qwq/internal/prerequisites/fault"
	"github.com/qwq-panel/qwq/internal/prerequisites/testsupport"
	"github.com/qwq-panel/qwq/internal/tlsmgr"
)

// ======================== 真实 Vault + consumerfiles + TLS 1.3 端到端夹具 ========================

type denyImportKeys struct{}

func (denyImportKeys) ReadImportKey(context.Context, certificates.Caller, string) ([]byte, error) {
	return nil, fault.New("PERMISSION_DENIED", "测试不开放导入私钥读取")
}

type testDeployAuthorizer struct {
	mu               sync.Mutex
	bindingID        string
	policyRevision   string
	confirmCalls     int
	failConfirmOn    int
	mutateOnCall     int
	mutatedPolicyRev string
	removeErr        error
}

func (a *testDeployAuthorizer) ConfirmConsumerBinding(
	ctx context.Context,
	_ certificates.Caller,
	certificateID string,
	generation uint64,
	consumer certificates.Consumer,
) (certificates.HostBinding, error) {
	if err := ctx.Err(); err != nil {
		return certificates.HostBinding{}, err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.confirmCalls++
	if a.failConfirmOn > 0 && a.confirmCalls == a.failConfirmOn {
		return certificates.HostBinding{}, fault.New("BINDING_DENIED", "消费绑定授权已撤销")
	}
	rev := a.policyRevision
	if a.mutateOnCall > 0 && a.confirmCalls == a.mutateOnCall {
		rev = a.mutatedPolicyRev
	}
	return certificates.HostBinding{
		ID:             a.bindingID,
		CertificateID:  certificateID,
		Generation:     generation,
		Consumer:       consumer,
		PolicyRevision: rev,
	}, nil
}

func (a *testDeployAuthorizer) AuthorizeConsumerRemoval(ctx context.Context, _ certificates.Caller, _ certificates.HostBinding) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.removeErr
}

type faultFileBackend struct {
	base      *DirectFileBackend
	mu        sync.Mutex
	stageErr  error
	actErr    error
	removeErr error
}

func (f *faultFileBackend) Stage(ctx context.Context, binding certificates.HostBinding, material tlsmgr.Material) (consumerfiles.Proof, error) {
	f.mu.Lock()
	err := f.stageErr
	f.mu.Unlock()
	if err != nil {
		return consumerfiles.Proof{}, err
	}
	return f.base.Stage(ctx, binding, material)
}

func (f *faultFileBackend) Activate(ctx context.Context, pluginID string, expected *consumerfiles.Proof, wanted consumerfiles.Proof) (*consumerfiles.Proof, error) {
	f.mu.Lock()
	err := f.actErr
	f.mu.Unlock()
	if err != nil {
		return nil, err
	}
	return f.base.Activate(ctx, pluginID, expected, wanted)
}

func (f *faultFileBackend) Current(ctx context.Context, pluginID, bindingID string) (*consumerfiles.Proof, error) {
	return f.base.Current(ctx, pluginID, bindingID)
}

func (f *faultFileBackend) Remove(ctx context.Context, pluginID, bindingID string) (bool, error) {
	f.mu.Lock()
	err := f.removeErr
	f.mu.Unlock()
	if err != nil {
		return false, err
	}
	return f.base.Remove(ctx, pluginID, bindingID)
}

type liveTLSConsumerRuntime struct {
	storeRoot *os.Root
	endpoint  string

	mu          sync.RWMutex
	cert        *tls.Certificate
	observation RuntimeObservation
	inUse       bool
	applyHook   func(ctx context.Context, binding certificates.HostBinding, proof consumerfiles.Proof) (handled bool, err error)
	inspectHook func() (RuntimeObservation, bool, error)
}

func newLiveTLSConsumerRuntime(t *testing.T, root *os.Root) *liveTLSConsumerRuntime {
	t.Helper()
	rt := &liveTLSConsumerRuntime{storeRoot: root}
	tlsCfg := &tls.Config{
		MinVersion: tls.VersionTLS13,
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			rt.mu.RLock()
			defer rt.mu.RUnlock()
			if rt.cert == nil {
				return nil, errors.New("no certificate loaded")
			}
			return rt.cert, nil
		},
	}
	rawLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen tcp: %v", err)
	}
	ln := tls.NewListener(rawLn, tlsCfg)
	rt.endpoint = rawLn.Addr().String()
	rt.observation = RuntimeObservation{Endpoint: rt.endpoint}

	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer func() { _ = c.Close() }()
				_ = c.SetDeadline(time.Now().Add(2 * time.Second))
				if tc, ok := c.(*tls.Conn); ok {
					_ = tc.Handshake()
				}
				// 等待客户端完成 TLS 1.3 握手并关闭连接，避免过早 RST。
				var buf [1]byte
				_, _ = c.Read(buf[:])
			}(conn)
		}
	}()
	t.Cleanup(func() {
		_ = ln.Close()
		<-done
	})
	return rt
}

func (r *liveTLSConsumerRuntime) Apply(ctx context.Context, binding certificates.HostBinding, proof consumerfiles.Proof) error {
	r.mu.RLock()
	hook := r.applyHook
	r.mu.RUnlock()
	if hook != nil {
		handled, err := hook(ctx, binding, proof)
		if handled || err != nil {
			return err
		}
	}
	store, err := consumerfiles.New(r.storeRoot)
	if err != nil {
		return err
	}
	defer func() { _ = store.Close() }()

	mat, err := store.Load(ctx, proof)
	if err != nil {
		return err
	}
	defer mat.Clear()

	chain := mat.CertificatePEM()
	defer clear(chain)
	key := mat.PrivateKeyPEM()
	defer clear(key)

	pair, err := tls.X509KeyPair(chain, key)
	if err != nil {
		return err
	}
	fp, err := LeafFingerprintPEM(chain)
	if err != nil {
		return err
	}

	r.mu.Lock()
	r.cert = &pair
	r.inUse = true
	r.observation = RuntimeObservation{
		Running:          true,
		BindingID:        binding.ID,
		ActiveGeneration: binding.Generation,
		PolicyRevision:   binding.PolicyRevision,
		FullchainSHA256:  proof.FullchainSHA256,
		LeafFingerprint:  fp,
		SNI:              binding.Consumer.SNI,
		Endpoint:         r.endpoint,
	}
	r.mu.Unlock()
	return nil
}

func (r *liveTLSConsumerRuntime) Inspect(ctx context.Context, _ certificates.Consumer, _ string) (RuntimeObservation, error) {
	if err := ctx.Err(); err != nil {
		return RuntimeObservation{}, err
	}
	r.mu.RLock()
	hook := r.inspectHook
	obs := r.observation
	r.mu.RUnlock()
	if hook != nil {
		custom, use, err := hook()
		if err != nil {
			return RuntimeObservation{}, err
		}
		if use {
			return custom, nil
		}
	}
	return obs, nil
}

func (r *liveTLSConsumerRuntime) InUse(ctx context.Context, _ certificates.HostBinding) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.inUse, nil
}

func (r *liveTLSConsumerRuntime) setInUse(v bool) {
	r.mu.Lock()
	r.inUse = v
	r.mu.Unlock()
}

type deploymentHarness struct {
	now       *clock.Fake
	repo      *testsupport.MemoryStore
	vault     *certificates.Vault
	auth      *testDeployAuthorizer
	stateRoot *os.Root
	files     *faultFileBackend
	runtime   *liveTLSConsumerRuntime
	prober    *TLSHandshakeProber
	deployer  *Deployer

	caller   certificates.Caller
	certID   string
	consumer certificates.Consumer

	cert2 testsupport.Certificate
	ref1  certificates.MaterialRef
	ref2  certificates.MaterialRef
	fp1   string
	fp2   string
}

func newDeploymentHarness(t *testing.T) *deploymentHarness {
	t.Helper()
	now := clock.NewFake(time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC))
	c1, err := testsupport.SignedCertificate(now.Now(), nil, 0)
	if err != nil {
		t.Fatalf("SignedCertificate 1: %v", err)
	}
	t.Cleanup(c1.Clear)
	c2, err := testsupport.SignedCertificate(now.Now(), nil, 0)
	if err != nil {
		t.Fatalf("SignedCertificate 2: %v", err)
	}
	t.Cleanup(c2.Clear)

	pool := x509.NewCertPool()
	for _, chain := range [][]byte{c1.Chain, c2.Chain} {
		parsed, parseErr := tlsmgr.ParseCertificateChain(chain)
		if parseErr != nil || len(parsed) < 2 {
			t.Fatalf("parse test chain: %v (len=%d)", parseErr, len(parsed))
		}
		pool.AddCert(parsed[len(parsed)-1])
	}
	roots, err := certificates.NewHostTrustRoots(certificates.HostTrustRootsOptions{PublicRoots: pool})
	if err != nil {
		t.Fatalf("NewHostTrustRoots: %v", err)
	}

	db, secretStore := testsupport.EncryptedStorage(t, now)
	vault, err := certificates.NewVault(certificates.VaultOptions{
		DB:      db,
		Secrets: secretStore,
		Imports: denyImportKeys{},
		Roots:   roots,
		Clock:   now,
	})
	if err != nil {
		t.Fatalf("NewVault: %v", err)
	}

	caller := certificates.Caller{OwnerID: "owner-1", OperationID: "op-deploy-1"}
	certID := "cert-edge-1"
	spec := certificates.Spec{SANs: []string{"proxy.example.com"}, Purpose: tlsmgr.ServerTLS}

	mat1, err := tlsmgr.NewMaterial(c1.Chain, c1.Key)
	if err != nil {
		t.Fatal(err)
	}
	defer mat1.Clear()
	ref1, err := vault.EnsureMaterial(context.Background(), caller, certID, "attempt-g1", mat1, spec, tlsmgr.PublicTrust)
	if err != nil {
		t.Fatalf("EnsureMaterial g1: %v", err)
	}

	mat2, err := tlsmgr.NewMaterial(c2.Chain, c2.Key)
	if err != nil {
		t.Fatal(err)
	}
	defer mat2.Clear()
	ref2, err := vault.EnsureMaterial(context.Background(), caller, certID, "attempt-g2", mat2, spec, tlsmgr.PublicTrust)
	if err != nil {
		t.Fatalf("EnsureMaterial g2: %v", err)
	}

	fp1, err := LeafFingerprintPEM(c1.Chain)
	if err != nil {
		t.Fatal(err)
	}
	fp2, err := LeafFingerprintPEM(c2.Chain)
	if err != nil {
		t.Fatal(err)
	}
	if fp1 == fp2 {
		t.Fatal("distinct certificates produced identical leaf fingerprint")
	}

	stateDir := t.TempDir()
	if err := os.Chmod(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	stateRoot, err := os.OpenRoot(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = stateRoot.Close() })

	direct := &DirectFileBackend{
		Open: func(pluginID string) (*consumerfiles.Store, func(), error) {
			if pluginID != "core.xray" {
				return nil, nil, fault.New("NOT_FOUND", "未知测试插件")
			}
			s, openErr := consumerfiles.New(stateRoot)
			if openErr != nil {
				return nil, nil, openErr
			}
			return s, func() { _ = s.Close() }, nil
		},
	}
	files := &faultFileBackend{base: direct}
	rt := newLiveTLSConsumerRuntime(t, stateRoot)
	prober := &TLSHandshakeProber{Timeout: 3 * time.Second, Clock: now}
	repo := &testsupport.MemoryStore{}
	auth := &testDeployAuthorizer{bindingID: "binding-edge-1", policyRevision: "policy-r1"}

	deployer, err := New(Options{
		Repository: repo,
		Authority:  auth,
		Materials:  vault,
		Files:      files,
		Runtime:    rt,
		Prober:     prober,
		Clock:      now,
	})
	if err != nil {
		t.Fatalf("New Deployer: %v", err)
	}

	return &deploymentHarness{
		now:       now,
		repo:      repo,
		vault:     vault,
		auth:      auth,
		stateRoot: stateRoot,
		files:     files,
		runtime:   rt,
		prober:    prober,
		deployer:  deployer,
		caller:    caller,
		certID:    certID,
		consumer: certificates.Consumer{
			PluginID:  "core.xray",
			ProfileID: "edge-h2",
			NodeID:    "local",
			SNI:       "proxy.example.com",
			Purpose:   "proxy.hysteria2",
		},
		cert2: c2,
		ref1:  ref1,
		ref2:  ref2,
		fp1:   fp1,
		fp2:   fp2,
	}
}

func (h *deploymentHarness) confirm(t *testing.T, generation uint64) certificates.HostBinding {
	t.Helper()
	b, err := h.deployer.Confirm(context.Background(), h.caller, h.certID, generation, h.consumer)
	if err != nil {
		t.Fatalf("Confirm g%d: %v", generation, err)
	}
	return b
}

func hasRef(refs []certificates.Reference, generation uint64, kind string) bool {
	for _, r := range refs {
		if r.Generation == generation && r.Kind == kind {
			return true
		}
	}
	return false
}

// ======================== 场景 1：构造校验绝不放行缺失探针或后端 ========================

func TestNewRejectsMissingBackendsOrProber(t *testing.T) {
	h := newDeploymentHarness(t)
	valid := Options{
		Repository: h.repo,
		Authority:  h.auth,
		Materials:  h.vault,
		Files:      h.files,
		Runtime:    h.runtime,
		Prober:     h.prober,
		Clock:      h.now,
	}

	cases := []struct {
		name   string
		mutate func(*Options)
		want   string
	}{
		{"nil Repository", func(o *Options) { o.Repository = nil }, "BACKEND_REQUIRED"},
		{"nil Authority", func(o *Options) { o.Authority = nil }, "BACKEND_REQUIRED"},
		{"nil Materials", func(o *Options) { o.Materials = nil }, "BACKEND_REQUIRED"},
		{"nil Files", func(o *Options) { o.Files = nil }, "BACKEND_REQUIRED"},
		{"nil Runtime", func(o *Options) { o.Runtime = nil }, "BACKEND_REQUIRED"},
		{"nil Prober", func(o *Options) { o.Prober = nil }, "BACKEND_REQUIRED"},
		{"negative MaxRecords", func(o *Options) { o.MaxRecords = -1 }, "VALIDATION_FAILED"},
		{"oversized MaxRecords", func(o *Options) { o.MaxRecords = 257 }, "VALIDATION_FAILED"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			opts := valid
			tc.mutate(&opts)
			if _, err := New(opts); fault.Code(err) != tc.want {
				t.Fatalf("New(%s) code = %q (%v), want %q", tc.name, fault.Code(err), err, tc.want)
			}
		})
	}
}

// ======================== 场景 2 & 3：完整部署、升级与引用保护 ========================

func TestDeployHappyPathUpgradeAndReferencesProtection(t *testing.T) {
	h := newDeploymentHarness(t)
	ctx := context.Background()

	// 部署 g1：真实 Vault -> 真实 consumerfiles -> 真实 TLS 1.3 握手探针
	b1 := h.confirm(t, 1)
	out1, err := h.deployer.Deploy(ctx, h.caller, b1, h.ref1)
	if err != nil || out1.State != "applied" || out1.ActiveGeneration != 1 || !out1.Healthy {
		t.Fatalf("Deploy g1 = %+v, %v; want applied/1/true", out1, err)
	}
	refs, err := h.deployer.References(ctx, h.caller, h.certID)
	if err != nil || len(refs) != 1 || !hasRef(refs, 1, "current") {
		t.Fatalf("References after g1 = %+v, %v; want [g1/current]", refs, err)
	}

	// 升级到 g2：References 同时保护 g2/current 与 g1/previous
	b2 := h.confirm(t, 2)
	out2, err := h.deployer.Deploy(ctx, h.caller, b2, h.ref2)
	if err != nil || out2.State != "applied" || out2.ActiveGeneration != 2 || !out2.Healthy {
		t.Fatalf("Deploy g2 = %+v, %v; want applied/2/true", out2, err)
	}
	refs, err = h.deployer.References(ctx, h.caller, h.certID)
	if err != nil || len(refs) != 2 || !hasRef(refs, 2, "current") || !hasRef(refs, 1, "previous") {
		t.Fatalf("References after g2 = %+v, %v; want g2/current + g1/previous", refs, err)
	}

	// 持删除锁期间调用 References 不得死锁，且明确保护 g1 与 g2
	unlock, err := h.deployer.LockForRemoval(ctx, h.caller, h.certID, 1)
	if err != nil {
		t.Fatalf("LockForRemoval: %v", err)
	}
	lockedRefs, err := h.deployer.References(ctx, h.caller, h.certID)
	unlock()
	if err != nil || !hasRef(lockedRefs, 1, "previous") || !hasRef(lockedRefs, 2, "current") {
		t.Fatalf("References under LockForRemoval = %+v, %v", lockedRefs, err)
	}
}

// ======================== 场景 4：健康检查失败触发自动回滚与真实握手复验 ========================

func TestDeployHealthFailureAutoRollsBackToPrevious(t *testing.T) {
	h := newDeploymentHarness(t)
	ctx := context.Background()

	b1 := h.confirm(t, 1)
	if out, err := h.deployer.Deploy(ctx, h.caller, b1, h.ref1); err != nil || out.State != "applied" {
		t.Fatalf("Deploy g1 = %+v, %v", out, err)
	}

	// 模拟 g2 Apply 宣称已切到 g2，但监听端点仍提供旧 g1 证书（指纹不匹配）
	h.runtime.mu.Lock()
	h.runtime.applyHook = func(_ context.Context, binding certificates.HostBinding, proof consumerfiles.Proof) (bool, error) {
		if binding.Generation != 2 {
			return false, nil
		}
		h.runtime.mu.Lock()
		h.runtime.observation = RuntimeObservation{
			Running:          true,
			BindingID:        binding.ID,
			ActiveGeneration: 2,
			PolicyRevision:   binding.PolicyRevision,
			FullchainSHA256:  proof.FullchainSHA256,
			LeafFingerprint:  h.fp2,
			SNI:              binding.Consumer.SNI,
			Endpoint:         h.runtime.endpoint,
		}
		h.runtime.mu.Unlock()
		return true, nil
	}
	h.runtime.mu.Unlock()

	b2 := h.confirm(t, 2)
	out, err := h.deployer.Deploy(ctx, h.caller, b2, h.ref2)
	if err != nil || out.State != "rolled_back" || out.ActiveGeneration != 1 || !out.Healthy {
		t.Fatalf("Deploy g2 with mismatched TLS handshake = %+v, %v; want rolled_back/1/true", out, err)
	}

	// 验证磁盘 current.json 与真实 TLS 监听均恢复到 g1
	cur, err := h.files.Current(ctx, h.consumer.PluginID, b1.ID)
	if err != nil || cur == nil || cur.Binding != b1 {
		t.Fatalf("disk current after rollback = %+v, %v; want g1", cur, err)
	}
	if err := VerifyRuntimeHealth(ctx, h.consumer, *cur, h.fp1, h.runtime, h.prober); err != nil {
		t.Fatalf("runtime not healthy on g1 after rollback: %v", err)
	}
	refs, err := h.deployer.References(ctx, h.caller, h.certID)
	if err != nil || len(refs) != 1 || !hasRef(refs, 1, "current") {
		t.Fatalf("References after clean rollback = %+v, %v; want only g1/current", refs, err)
	}
}

// ======================== 场景 5：回滚失败返回 unknown、保留 Pending 并由 Reconcile 收敛 ========================

func TestDeployRollbackFailurePreservesPendingAndReconciles(t *testing.T) {
	h := newDeploymentHarness(t)
	ctx := context.Background()

	b1 := h.confirm(t, 1)
	if out, err := h.deployer.Deploy(ctx, h.caller, b1, h.ref1); err != nil || out.State != "applied" {
		t.Fatalf("Deploy g1 = %+v, %v", out, err)
	}

	// 模拟 g2 Apply 失败且随后回滚 g1 Apply 也失败
	h.runtime.mu.Lock()
	h.runtime.applyHook = func(context.Context, certificates.HostBinding, consumerfiles.Proof) (bool, error) {
		return true, fault.New("RUNTIME_UNAVAILABLE", "运行时暂时不可用")
	}
	h.runtime.mu.Unlock()

	b2 := h.confirm(t, 2)
	out, err := h.deployer.Deploy(ctx, h.caller, b2, h.ref2)
	if err == nil || out.State != "unknown" || out.Healthy {
		t.Fatalf("Deploy with failed rollback = %+v, %v; want unknown/false with error", out, err)
	}

	// Pending 未清除，References 必须同时保护 g1 与 g2 不被删除
	refs, err := h.deployer.References(ctx, h.caller, h.certID)
	if err != nil || !hasRef(refs, 1, "pending") || !hasRef(refs, 2, "pending") {
		t.Fatalf("References during unknown state = %+v, %v; want g1 & g2 protected", refs, err)
	}

	// 运行时恢复后，Reconcile 核验 g1 并收敛到 rolled_back/1/true
	h.runtime.mu.Lock()
	h.runtime.applyHook = nil
	h.runtime.mu.Unlock()

	recOut, err := h.deployer.Reconcile(ctx, h.caller, b2)
	if err != nil || recOut.State != "rolled_back" || recOut.ActiveGeneration != 1 || !recOut.Healthy {
		t.Fatalf("Reconcile after runtime recovery = %+v, %v; want rolled_back/1/true", recOut, err)
	}
	refs, err = h.deployer.References(ctx, h.caller, h.certID)
	if err != nil || len(refs) != 1 || !hasRef(refs, 1, "current") {
		t.Fatalf("References after Reconcile = %+v, %v; want only g1/current", refs, err)
	}
}

// ======================== 场景 6：首次部署失败清理文件；文件删除错误绝不忽略 ========================

func TestFirstDeployFailureCleanupAndRemoveErrorNotIgnored(t *testing.T) {
	ctx := context.Background()

	t.Run("first deploy failure removes files and confirms rolled_back/0/false", func(t *testing.T) {
		h := newDeploymentHarness(t)
		h.runtime.mu.Lock()
		h.runtime.applyHook = func(context.Context, certificates.HostBinding, consumerfiles.Proof) (bool, error) {
			return true, fault.New("RUNTIME_APPLY_FAILED", "首次加载失败")
		}
		h.runtime.mu.Unlock()

		b1 := h.confirm(t, 1)
		out, err := h.deployer.Deploy(ctx, h.caller, b1, h.ref1)
		if err != nil || out.State != "rolled_back" || out.ActiveGeneration != 0 || out.Healthy {
			t.Fatalf("first deploy rollback = %+v, %v; want rolled_back/0/false", out, err)
		}
		cur, err := h.files.Current(ctx, h.consumer.PluginID, b1.ID)
		if err != nil || cur != nil {
			t.Fatalf("disk current after first-deploy rollback = %+v, %v; want nil", cur, err)
		}
		refs, err := h.deployer.References(ctx, h.caller, h.certID)
		if err != nil || len(refs) != 0 {
			t.Fatalf("References after first-deploy rollback = %+v, %v; want empty", refs, err)
		}
	})

	t.Run("first deploy rollback never ignores file remove failure", func(t *testing.T) {
		h := newDeploymentHarness(t)
		h.runtime.mu.Lock()
		h.runtime.applyHook = func(context.Context, certificates.HostBinding, consumerfiles.Proof) (bool, error) {
			return true, fault.New("RUNTIME_APPLY_FAILED", "首次加载失败")
		}
		h.runtime.mu.Unlock()
		h.files.mu.Lock()
		h.files.removeErr = fault.New("CONSUMER_FILES_IO", "磁盘清理失败")
		h.files.mu.Unlock()

		b1 := h.confirm(t, 1)
		out, err := h.deployer.Deploy(ctx, h.caller, b1, h.ref1)
		if err == nil || out.State != "unknown" || out.Healthy {
			t.Fatalf("first deploy rollback with remove error = %+v, %v; want unknown with error", out, err)
		}
		refs, err := h.deployer.References(ctx, h.caller, h.certID)
		if err != nil || !hasRef(refs, 1, "pending") {
			t.Fatalf("Pending must stay protected when cleanup fails: %+v, %v", refs, err)
		}
	})
	t.Run("first deploy rollback rejects non-zero active gen on inspect", func(t *testing.T) {
		h := newDeploymentHarness(t)
		h.runtime.mu.Lock()
		h.runtime.applyHook = func(context.Context, certificates.HostBinding, consumerfiles.Proof) (bool, error) {
			return true, fault.New("RUNTIME_APPLY_FAILED", "首次加载失败")
		}
		h.runtime.inspectHook = func() (RuntimeObservation, bool, error) {
			return RuntimeObservation{Running: true, ActiveGeneration: 1}, true, nil
		}
		h.runtime.mu.Unlock()

		b1 := h.confirm(t, 1)
		out, err := h.deployer.Deploy(ctx, h.caller, b1, h.ref1)
		if err == nil || out.State != "unknown" || out.Healthy {
			t.Fatalf("first deploy rollback with active gen = %+v, %v; want unknown with error", out, err)
		}
	})
}

// ======================== 场景 7：激活前实时授权撤销、变更与文件边界错误 ========================

func TestDeployPreActivateRevocationNeverSwitchesCurrent(t *testing.T) {
	ctx := context.Background()

	t.Run("revoked before activate keeps g1 healthy", func(t *testing.T) {
		h := newDeploymentHarness(t)
		b1 := h.confirm(t, 1)
		if out, err := h.deployer.Deploy(ctx, h.caller, b1, h.ref1); err != nil || out.State != "applied" {
			t.Fatalf("Deploy g1 = %+v, %v", out, err)
		}

		b2 := h.confirm(t, 2)
		h.auth.mu.Lock()
		h.auth.failConfirmOn = h.auth.confirmCalls + 1
		h.auth.mu.Unlock()

		out, err := h.deployer.Deploy(ctx, h.caller, b2, h.ref2)
		if err != nil || out.State != "rolled_back" || out.ActiveGeneration != 1 || !out.Healthy {
			t.Fatalf("Deploy with pre-activate revocation = %+v, %v; want rolled_back/1/true", out, err)
		}
		cur, err := h.files.Current(ctx, h.consumer.PluginID, b1.ID)
		if err != nil || cur == nil || cur.Binding != b1 {
			t.Fatalf("current.json switched despite pre-activate revocation: %+v, %v", cur, err)
		}
	})

	t.Run("policy revision drift before activate aborts cleanly", func(t *testing.T) {
		h := newDeploymentHarness(t)
		b1 := h.confirm(t, 1)
		if out, err := h.deployer.Deploy(ctx, h.caller, b1, h.ref1); err != nil || out.State != "applied" {
			t.Fatalf("Deploy g1 = %+v, %v", out, err)
		}

		b2 := h.confirm(t, 2)
		h.auth.mu.Lock()
		h.auth.mutateOnCall = h.auth.confirmCalls + 1
		h.auth.mutatedPolicyRev = "policy-drifted"
		h.auth.mu.Unlock()

		out, err := h.deployer.Deploy(ctx, h.caller, b2, h.ref2)
		if err != nil || out.State != "rolled_back" || out.ActiveGeneration != 1 || !out.Healthy {
			t.Fatalf("Deploy with policy drift = %+v, %v; want rolled_back/1/true", out, err)
		}
	})

	t.Run("stage error aborts before activate and activate uncertain stays unknown", func(t *testing.T) {
		h := newDeploymentHarness(t)
		b1 := h.confirm(t, 1)
		if out, err := h.deployer.Deploy(ctx, h.caller, b1, h.ref1); err != nil || out.State != "applied" {
			t.Fatalf("Deploy g1 = %+v, %v", out, err)
		}

		b2 := h.confirm(t, 2)
		h.files.mu.Lock()
		h.files.stageErr = fault.New("CONSUMER_FILES_IO", "暂存磁盘写入失败")
		h.files.mu.Unlock()
		out, err := h.deployer.Deploy(ctx, h.caller, b2, h.ref2)
		if err != nil || out.State != "rolled_back" || out.ActiveGeneration != 1 || !out.Healthy {
			t.Fatalf("Deploy with stage error = %+v, %v; want rolled_back/1/true", out, err)
		}

		uncertainErr := fault.New("CONSUMER_FILES_IO", "激活持久化结果不确定")
		uncertainErr.Uncertain = true
		h.files.mu.Lock()
		h.files.stageErr = nil
		h.files.actErr = uncertainErr
		h.files.mu.Unlock()
		out, err = h.deployer.Deploy(ctx, h.caller, b2, h.ref2)
		if err == nil || out.State != "unknown" || out.Healthy {
			t.Fatalf("Deploy with uncertain activate = %+v, %v; want unknown with error", out, err)
		}
		refs, err := h.deployer.References(ctx, h.caller, h.certID)
		if err != nil || !hasRef(refs, 1, "pending") || !hasRef(refs, 2, "pending") {
			t.Fatalf("References during uncertain activate = %+v, %v; want g1 & g2 protected", refs, err)
		}
	})
}

// ======================== 场景 8：磁盘 current.json 与宿主账本冲突时拒绝盲信 ========================

func TestDeployDetectsDiskTamperAgainstHostLedger(t *testing.T) {
	h := newDeploymentHarness(t)
	ctx := context.Background()

	b1 := h.confirm(t, 1)
	if out, err := h.deployer.Deploy(ctx, h.caller, b1, h.ref1); err != nil || out.State != "applied" {
		t.Fatalf("Deploy g1 = %+v, %v", out, err)
	}

	// 绕过宿主账本，直接在磁盘把 current.json 篡改到 g2
	store, err := consumerfiles.New(h.stateRoot)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()
	cur1, err := store.Current(ctx, b1.ID)
	if err != nil || cur1 == nil {
		t.Fatalf("Current g1: %+v, %v", cur1, err)
	}
	tamperBinding := b1
	tamperBinding.Generation = 9
	mat2, err := tlsmgr.NewMaterial(h.cert2.Chain, h.cert2.Key)
	if err != nil {
		t.Fatal(err)
	}
	defer mat2.Clear()
	tamperedProof, err := store.Stage(ctx, tamperBinding, mat2)
	if err != nil {
		t.Fatalf("tamper Stage: %v", err)
	}
	if _, err := store.Activate(ctx, cur1, tamperedProof); err != nil {
		t.Fatalf("tamper Activate: %v", err)
	}

	b2 := h.confirm(t, 2)
	out, err := h.deployer.Deploy(ctx, h.caller, b2, h.ref2)
	if fault.Code(err) != "CONSUMER_FILES_CONFLICT" || out.State != "unknown" || out.Healthy {
		t.Fatalf("Deploy on tampered disk = %+v, %v; want unknown + CONSUMER_FILES_CONFLICT", out, err)
	}
}

// ======================== 场景 9：受控解绑（授权、占用保护、文件删除不忽略与彻底清理） ========================

func TestRemoveAuthorizationInUseAndCleanup(t *testing.T) {
	h := newDeploymentHarness(t)
	ctx := context.Background()

	b1 := h.confirm(t, 1)
	if out, err := h.deployer.Deploy(ctx, h.caller, b1, h.ref1); err != nil || out.State != "applied" {
		t.Fatalf("Deploy g1 = %+v, %v", out, err)
	}

	// 1. 宿主授权拒绝解绑
	h.auth.mu.Lock()
	h.auth.removeErr = fault.New("PERMISSION_DENIED", "未授权解绑")
	h.auth.mu.Unlock()
	if err := h.deployer.Remove(ctx, h.caller, b1); fault.Code(err) != "PERMISSION_DENIED" {
		t.Fatalf("Remove without authorization = %v, want PERMISSION_DENIED", err)
	}
	h.auth.mu.Lock()
	h.auth.removeErr = nil
	h.auth.mu.Unlock()

	// 2. 运行时仍在占用 -> RESOURCE_IN_USE，文件与账本均不动
	if err := h.deployer.Remove(ctx, h.caller, b1); fault.Code(err) != "RESOURCE_IN_USE" {
		t.Fatalf("Remove while in use = %v, want RESOURCE_IN_USE", err)
	}
	if cur, err := h.files.Current(ctx, h.consumer.PluginID, b1.ID); err != nil || cur == nil {
		t.Fatalf("files removed despite RESOURCE_IN_USE: %+v, %v", cur, err)
	}

	// 3. 脱离后若文件删除失败 -> 绝不忽略错误，且保留账本记录
	h.runtime.setInUse(false)
	h.files.mu.Lock()
	h.files.removeErr = fault.New("CONSUMER_FILES_IO", "删除文件失败")
	h.files.mu.Unlock()
	if err := h.deployer.Remove(ctx, h.caller, b1); fault.Code(err) != "CONSUMER_FILES_IO" {
		t.Fatalf("Remove with file error = %v, want CONSUMER_FILES_IO", err)
	}
	refs, err := h.deployer.References(ctx, h.caller, h.certID)
	if err != nil || !hasRef(refs, 1, "current") {
		t.Fatalf("ledger cleared despite file remove error: %+v, %v", refs, err)
	}

	// 4. 文件删除恢复后成功清理文件与账本，References 清空
	h.files.mu.Lock()
	h.files.removeErr = nil
	h.files.mu.Unlock()
	if err := h.deployer.Remove(ctx, h.caller, b1); err != nil {
		t.Fatalf("Remove after detach: %v", err)
	}
	if cur, err := h.files.Current(ctx, h.consumer.PluginID, b1.ID); err != nil || cur != nil {
		t.Fatalf("files still present after Remove: %+v, %v", cur, err)
	}
	refs, err = h.deployer.References(ctx, h.caller, h.certID)
	if err != nil || len(refs) != 0 {
		t.Fatalf("References after Remove = %+v, %v; want empty", refs, err)
	}
}

// ======================== 场景 10：同代重新授权（PolicyRevision 升级） ========================

func TestDeploySameGenerationReauthorizationUpdatesPolicyRevision(t *testing.T) {
	h := newDeploymentHarness(t)
	ctx := context.Background()

	b1 := h.confirm(t, 1)
	if out, err := h.deployer.Deploy(ctx, h.caller, b1, h.ref1); err != nil || out.State != "applied" {
		t.Fatalf("Deploy g1 policy-r1 = %+v, %v", out, err)
	}

	h.auth.mu.Lock()
	h.auth.policyRevision = "policy-r2"
	h.auth.mu.Unlock()

	b1v2 := h.confirm(t, 1)
	if b1v2.PolicyRevision != "policy-r2" || b1v2.Generation != 1 {
		t.Fatalf("unexpected reauthorized binding: %+v", b1v2)
	}
	out, err := h.deployer.Deploy(ctx, h.caller, b1v2, h.ref1)
	if err != nil || out.State != "applied" || out.ActiveGeneration != 1 || !out.Healthy {
		t.Fatalf("Deploy g1 policy-r2 = %+v, %v; want applied/1/true", out, err)
	}

	rec, found, err := h.deployer.readRecord(ctx, h.caller.OwnerID, b1.ID)
	if err != nil || !found || rec.Active == nil || rec.Previous == nil {
		t.Fatalf("ledger record after same-gen reauth = %+v, found=%v, err=%v", rec, found, err)
	}
	if rec.Active.Proof.Binding.PolicyRevision != "policy-r2" || rec.Previous.Proof.Binding.PolicyRevision != "policy-r1" {
		t.Fatalf("unexpected policy revisions active=%q previous=%q",
			rec.Active.Proof.Binding.PolicyRevision, rec.Previous.Proof.Binding.PolicyRevision)
	}
}

// ======================== 场景 11：首次部署激活前撤权必须清理已暂存私钥 ========================

func TestFirstDeployPreActivateRevocationCleansStagedPrivateKey(t *testing.T) {
	t.Run("revoked after stage removes staged generation and clears pending", func(t *testing.T) {
		h := newDeploymentHarness(t)
		ctx := context.Background()

		b1 := h.confirm(t, 1)
		h.auth.mu.Lock()
		h.auth.failConfirmOn = h.auth.confirmCalls + 1
		h.auth.mu.Unlock()

		out, err := h.deployer.Deploy(ctx, h.caller, b1, h.ref1)
		if err != nil || out.State != "rolled_back" || out.ActiveGeneration != 0 || out.Healthy {
			t.Fatalf("Deploy revoked before activate = %+v, %v; want rolled_back/0/false", out, err)
		}
		if _, statErr := h.stateRoot.Stat("tls/bindings/" + b1.ID); statErr == nil {
			t.Fatal("staged binding directory with private key remained on disk after pre-activate revocation")
		}
		refs, err := h.deployer.References(ctx, h.caller, h.certID)
		if err != nil || len(refs) != 0 {
			t.Fatalf("References after clean abort = %+v, %v; want empty", refs, err)
		}
	})

	t.Run("cleanup failure after pre-activate revocation keeps pending and returns unknown", func(t *testing.T) {
		h := newDeploymentHarness(t)
		ctx := context.Background()

		b1 := h.confirm(t, 1)
		h.auth.mu.Lock()
		h.auth.failConfirmOn = h.auth.confirmCalls + 1
		h.auth.mu.Unlock()
		h.files.mu.Lock()
		h.files.removeErr = fault.New("CONSUMER_FILES_IO", "清理暂存目录失败")
		h.files.mu.Unlock()

		out, err := h.deployer.Deploy(ctx, h.caller, b1, h.ref1)
		if err == nil || out.State != "unknown" || out.Healthy {
			t.Fatalf("Deploy with abort cleanup error = %+v, %v; want unknown", out, err)
		}
		refs, err := h.deployer.References(ctx, h.caller, h.certID)
		if err != nil || !hasRef(refs, 1, "pending") {
			t.Fatalf("pending reference lost despite staged cleanup failure: %+v, %v", refs, err)
		}
	})
}
