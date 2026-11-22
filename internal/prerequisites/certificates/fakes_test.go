// SPDX-License-Identifier: AGPL-3.0-only

package certificates

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/qwq-panel/qwq/internal/platform/clock"
	"github.com/qwq-panel/qwq/internal/prerequisites/dns"
	"github.com/qwq-panel/qwq/internal/prerequisites/fault"
	"github.com/qwq-panel/qwq/internal/prerequisites/testsupport"
	"github.com/qwq-panel/qwq/internal/tlsmgr"
)

type fakeAuthorization struct {
	mu          sync.Mutex
	revoked     bool
	policyCheck func(Authorization) error
}

func (a *fakeAuthorization) Authorize(ctx context.Context, request Authorization) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if request.Caller.OwnerID != "owner-1" {
		return fault.New("PERMISSION_DENIED", "owner 不符")
	}
	if a.revoked {
		return fault.New("PERMISSION_DENIED", "已撤权")
	}
	if a.policyCheck != nil {
		return a.policyCheck(request)
	}
	return nil
}

func (a *fakeAuthorization) revoke() { a.mu.Lock(); a.revoked = true; a.mu.Unlock() }

type fakeMaterial struct {
	owner, certificateID string
	material             tlsmgr.Material
	roots                *x509.CertPool
	trust                tlsmgr.TrustClass
}

type fakeMaterials struct {
	mu            sync.Mutex
	clock         *clock.Fake
	next          int
	data          map[MaterialRef]fakeMaterial
	attempts      map[string]MaterialRef
	importKeys    map[string][]byte
	importRoots   *x509.CertPool
	imports       int
	removes       int
	removeFailure error
	invalidSAN    bool
}

func attemptKey(caller Caller, certificateID, attemptID string) string {
	return caller.OwnerID + "\x00" + certificateID + "\x00" + attemptID
}

func (m *fakeMaterials) put(caller Caller, certificateID, attemptID string, material tlsmgr.Material, roots *x509.CertPool, trust tlsmgr.TrustClass) MaterialRef {
	if m.data == nil {
		m.data = map[MaterialRef]fakeMaterial{}
		m.attempts = map[string]MaterialRef{}
	}
	m.next++
	ref := MaterialRef(fmt.Sprintf("material-%d", m.next))
	m.data[ref] = fakeMaterial{owner: caller.OwnerID, certificateID: certificateID, material: material, roots: roots, trust: trust}
	m.attempts[attemptKey(caller, certificateID, attemptID)] = ref
	return ref
}

func (m *fakeMaterials) Find(_ context.Context, caller Caller, certificateID, attemptID string) (Issued, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	ref := m.attempts[attemptKey(caller, certificateID, attemptID)]
	item, found := m.data[ref]
	if !found {
		return Issued{}, fault.New("NOT_FOUND", "材料不存在")
	}
	return Issued{Material: ref, Trust: item.trust}, nil
}

func (m *fakeMaterials) Inspect(ctx context.Context, caller Caller, certificateID string, ref MaterialRef, spec Spec, trust tlsmgr.TrustClass) (tlsmgr.CertificateMetadata, error) {
	if err := ctx.Err(); err != nil {
		return tlsmgr.CertificateMetadata{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	item, found := m.data[ref]
	if !found || item.owner != caller.OwnerID || item.certificateID != certificateID || item.trust != trust {
		return tlsmgr.CertificateMetadata{}, fault.New("NOT_FOUND", "材料不可见")
	}
	return tlsmgr.ValidateMaterial(item.material, tlsmgr.MaterialOptions{SANs: spec.SANs, Now: m.clock.Now(), Purpose: spec.Purpose, Trust: trust, Roots: item.roots})
}

func (m *fakeMaterials) Import(_ context.Context, caller Caller, certificateID, attemptID string, chain []byte, keyRef string, spec Spec, trust tlsmgr.TrustClass) (MaterialRef, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if ref := m.attempts[attemptKey(caller, certificateID, attemptID)]; ref != "" {
		return ref, nil
	}
	key, allowed := m.importKeys[keyRef]
	if caller.OwnerID != "owner-1" || !allowed {
		return "", &fault.Error{Code: "PERMISSION_DENIED", Detail: "引用不属当前 operation", NotApplied: true}
	}
	m.imports++
	material, err := tlsmgr.NewMaterial(chain, key)
	if err != nil {
		return "", &fault.Error{Code: fault.Code(err), Detail: "材料无效", NotApplied: true}
	}
	return m.put(caller, certificateID, attemptID, material, m.importRoots, trust), nil
}

func (m *fakeMaterials) GenerateTest(_ context.Context, caller Caller, certificateID, attemptID string, spec Spec) (MaterialRef, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if ref := m.attempts[attemptKey(caller, certificateID, attemptID)]; ref != "" {
		return ref, nil
	}
	material, err := tlsmgr.GenerateTestMaterial(m.clock.Now(), spec.SANs)
	if err != nil {
		return "", err
	}
	return m.put(caller, certificateID, attemptID, material, nil, tlsmgr.TestTrust), nil
}

func (m *fakeMaterials) Remove(_ context.Context, caller Caller, certificateID string, ref MaterialRef) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.removeFailure != nil {
		return m.removeFailure
	}
	item, found := m.data[ref]
	if !found {
		return nil
	}
	if item.owner != caller.OwnerID || item.certificateID != certificateID {
		return fault.New("PERMISSION_DENIED", "不能删除其他材料")
	}
	item.material.Clear()
	delete(m.data, ref)
	m.removes++
	return nil
}

func (m *fakeMaterials) signed(caller Caller, certificateID, attemptID string, spec Spec, trust tlsmgr.TrustClass) (Issued, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if ref := m.attempts[attemptKey(caller, certificateID, attemptID)]; ref != "" {
		return Issued{Material: ref, Trust: trust}, nil
	}
	fixture, err := testsupport.SignedCertificate(m.clock.Now(), func(leaf *x509.Certificate) {
		leaf.DNSNames = slices.Clone(spec.SANs)
		if m.invalidSAN {
			leaf.DNSNames = []string{"unauthorized.example.com"}
		}
	}, 0)
	if err != nil {
		return Issued{}, err
	}
	defer fixture.Clear()
	material, err := tlsmgr.NewMaterial(fixture.Chain, fixture.Key)
	if err != nil {
		return Issued{}, err
	}
	ref := m.put(caller, certificateID, attemptID, material, fixture.Roots, trust)
	return Issued{Material: ref, Trust: trust}, nil
}

type fakeAuthority struct {
	mu                          sync.Mutex
	materials                   *fakeMaterials
	issues, reconciles, cancels int
	refused                     error
	lostReply                   bool
	cleanupFailure              error
	started, release            chan struct{}
	cancelOnIssue               context.CancelFunc
}

func (a *fakeAuthority) Issue(ctx context.Context, caller Caller, certificateID, attemptID string, scope IssuanceScope, progress Progress) (Issued, error) {
	a.mu.Lock()
	a.issues++
	refused, lost, started, release, cancel := a.refused, a.lostReply, a.started, a.release, a.cancelOnIssue
	a.mu.Unlock()
	if refused != nil {
		return Issued{}, refused
	}
	if started != nil {
		started <- struct{}{}
	}
	if release != nil {
		select {
		case <-release:
		case <-ctx.Done():
			return Issued{}, ctx.Err()
		}
	}
	if progress != nil {
		if err := progress("issuing", 80); err != nil {
			return Issued{}, err
		}
	}
	trust := tlsmgr.PublicTrust
	if scope.CA == LetsEncryptStaging {
		trust = tlsmgr.StagingTrust
	}
	issued, err := a.materials.signed(caller, certificateID, attemptID, scope.Spec, trust)
	if cancel != nil {
		cancel()
	}
	if lost {
		return Issued{}, errors.New("lost response must not expose DO-NOT-EXPOSE-KEY")
	}
	return issued, err
}

func (a *fakeAuthority) Reconcile(_ context.Context, caller Caller, certificateID, attemptID string, _ IssuanceScope, _ Progress) (Issued, error) {
	a.mu.Lock()
	a.reconciles++
	a.mu.Unlock()
	return a.materials.Find(context.Background(), caller, certificateID, attemptID)
}

func (a *fakeAuthority) Cancel(_ context.Context, _ Caller, _, _ string, _ IssuanceScope) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.cancels++
	return a.cleanupFailure
}

type fakeBindings struct {
	mu                                                     sync.Mutex
	refMu                                                  sync.Mutex
	active                                                 map[string]uint64
	outcomes                                               map[string]Deployment
	external                                               []Reference
	confirms, deploys, removes                             int
	failDeploy, failReconcile, lostReply, wrongNode, inUse bool
	unstableID                                             bool
	failConsumers                                          map[string]bool
}

func (b *fakeBindings) Confirm(_ context.Context, _ Caller, certificateID string, number uint64, consumer Consumer) (HostBinding, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.confirms++
	if b.wrongNode {
		consumer.NodeID = "another-node"
	}
	id := "binding-" + consumerKey(consumer)[:20]
	if b.unstableID {
		id += "-unexpected"
	}
	return HostBinding{ID: id, CertificateID: certificateID, Generation: number, Consumer: consumer, PolicyRevision: fmt.Sprintf("binding-revision-%d", number)}, nil
}

func (b *fakeBindings) Deploy(_ context.Context, _ Caller, binding HostBinding, _ MaterialRef) (Deployment, error) {
	b.refMu.Lock()
	defer b.refMu.Unlock()
	b.mu.Lock()
	defer b.mu.Unlock()
	b.deploys++
	if b.active == nil {
		b.active = map[string]uint64{}
		b.outcomes = map[string]Deployment{}
	}
	if b.failDeploy || b.failConsumers[consumerKey(binding.Consumer)] {
		outcome := Deployment{State: "rolled_back", ActiveGeneration: b.active[consumerKey(binding.Consumer)], Healthy: true}
		b.outcomes[binding.ID] = outcome
		return outcome, fault.New("DEPLOYMENT_FAILED", "确认回滚")
	}
	b.active[consumerKey(binding.Consumer)] = binding.Generation
	outcome := Deployment{State: "applied", ActiveGeneration: binding.Generation, Healthy: true}
	b.outcomes[binding.ID] = outcome
	if b.lostReply {
		return Deployment{}, errors.New("lost deploy response")
	}
	return outcome, nil
}

func (b *fakeBindings) Reconcile(_ context.Context, _ Caller, binding HostBinding) (Deployment, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.failReconcile {
		return Deployment{}, errors.New("backend unavailable")
	}
	return b.outcomes[binding.ID], nil
}

func (b *fakeBindings) Remove(_ context.Context, _ Caller, binding HostBinding) error {
	b.refMu.Lock()
	defer b.refMu.Unlock()
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.inUse {
		return &fault.Error{Code: "RESOURCE_IN_USE", Detail: "运行中", NotApplied: true}
	}
	delete(b.active, consumerKey(binding.Consumer))
	b.removes++
	return nil
}

func (b *fakeBindings) LockForRemoval(_ context.Context, _ Caller, _ string, _ uint64) (func(), error) {
	b.refMu.Lock()
	return b.refMu.Unlock, nil
}
func (b *fakeBindings) References(_ context.Context, _ Caller, _ string) ([]Reference, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return slices.Clone(b.external), nil
}

type fixture struct {
	manager       *Manager
	repository    *testsupport.MemoryStore
	materials     *fakeMaterials
	authority     *fakeAuthority
	bindings      *fakeBindings
	authorization *fakeAuthorization
	clock         *clock.Fake
	caller        Caller
	scope         IssuanceScope
}

func newFixture(t *testing.T) fixture {
	t.Helper()
	now := clock.NewFake(time.Date(2026, 11, 15, 0, 0, 0, 0, time.UTC))
	materials := &fakeMaterials{clock: now}
	authority := &fakeAuthority{materials: materials}
	bindings := &fakeBindings{}
	authorization := &fakeAuthorization{}
	repository := &testsupport.MemoryStore{}
	manager, err := New(Options{Repository: repository, Materials: materials, Authority: authority, Bindings: bindings, Authorizer: authorization, Clock: now})
	if err != nil {
		t.Fatal(err)
	}
	return fixture{manager: manager, repository: repository, materials: materials, authority: authority, bindings: bindings, authorization: authorization, clock: now,
		caller: Caller{OwnerID: "owner-1", OperationID: "operation-1"}, scope: IssuanceScope{Spec: Spec{SANs: []string{"proxy.example.com"}, Purpose: tlsmgr.ServerTLS},
			Provider: dns.Scope{ProviderID: "provider-1", Kind: dns.Cloudflare, ZoneID: "zone-1", ZoneName: "example.com", Revision: "scope-1"}, CA: LetsEncrypt}}
}

func (f fixture) issue(t *testing.T, attemptID string) Result {
	t.Helper()
	revision := MissingRevision
	if view, err := f.manager.Get(context.Background(), f.caller, "certificate-1"); err == nil {
		revision = view.Revision
	}
	result, err := f.manager.Issue(context.Background(), IssueRequest{Caller: f.caller, CertificateID: "certificate-1", AttemptID: attemptID, ExpectedRevision: revision, Scope: f.scope}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func consumer() Consumer {
	return Consumer{PluginID: "core.xray", ProfileID: "profile-1", NodeID: "node-1", SNI: "proxy.example.com", Purpose: "proxy.hysteria2"}
}
func requireCode(t *testing.T, err error, code string) {
	t.Helper()
	if err == nil || fault.Code(err) != code {
		t.Fatalf("error = %v, want %s", err, code)
	}
}
