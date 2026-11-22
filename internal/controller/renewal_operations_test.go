// SPDX-License-Identifier: AGPL-3.0-only

package controller

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/qwq-panel/qwq/internal/actor"
	"github.com/qwq-panel/qwq/internal/authz"
	"github.com/qwq-panel/qwq/internal/operations"
	"github.com/qwq-panel/qwq/internal/platform/clock"
	"github.com/qwq-panel/qwq/internal/platform/ids"
	"github.com/qwq-panel/qwq/internal/pluginhost/hostsvc"
	"github.com/qwq-panel/qwq/internal/prerequisites/capability"
	"github.com/qwq-panel/qwq/internal/prerequisites/certificates"
	"github.com/qwq-panel/qwq/internal/prerequisites/dns"
	"github.com/qwq-panel/qwq/internal/prerequisites/fault"
	"github.com/qwq-panel/qwq/internal/prerequisites/hostauth"
	"github.com/qwq-panel/qwq/internal/prerequisites/provider"
	"github.com/qwq-panel/qwq/internal/prerequisites/store"
	"github.com/qwq-panel/qwq/internal/prerequisites/testsupport"
	"github.com/qwq-panel/qwq/internal/storage"
	"github.com/qwq-panel/qwq/internal/tlsmgr"
)

// ======================== 真实 SQLite/Authz/Operations/Hostauth 续期夹具 ========================

const (
	renewalOpTestProvider = "provider-one"
	renewalOpTestZone     = "11111111111111111111111111111111"
	renewalOpTestCert     = "cert-one"
	renewalOpTestPolicy   = "policy-one"
	renewalOpTestNode     = "local"
	renewalOpTestOwner    = "tls.certificates"
)

type renewalOpTestCatalog struct {
	mu      sync.Mutex
	actions map[string]operations.Action
}

func (c *renewalOpTestCatalog) Action(id string) (operations.Action, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	act, ok := c.actions[id]
	return act, ok
}

func (c *renewalOpTestCatalog) put(act operations.Action) {
	c.mu.Lock()
	c.actions[act.ID] = act
	c.mu.Unlock()
}

type renewalOpTestJob struct {
	ctx  context.Context
	req  operations.PluginRunJobRequest
	done chan struct{}
	once sync.Once
}

func (j *renewalOpTestJob) finish() {
	j.once.Do(func() { close(j.done) })
}

type renewalOpTestDispatch struct {
	mu      sync.RWMutex
	renewal *RenewalOperations
	started chan *renewalOpTestJob
}

func (d *renewalOpTestDispatch) setRenewal(r *RenewalOperations) {
	d.mu.Lock()
	d.renewal = r
	d.mu.Unlock()
}

func (d *renewalOpTestDispatch) Plan(context.Context, operations.PluginPlanRequest) (operations.Preview, error) {
	return operations.Preview{}, errors.New("test dispatcher does not plan")
}

func (d *renewalOpTestDispatch) Invoke(context.Context, operations.PluginInvokeRequest) (operations.PluginInvokeResponse, error) {
	return operations.PluginInvokeResponse{}, errors.New("test dispatcher only handles jobs")
}

func (d *renewalOpTestDispatch) Cancel(context.Context, operations.PluginCancelRequest) error {
	return nil
}

func (d *renewalOpTestDispatch) RunJob(ctx context.Context, req operations.PluginRunJobRequest, progress func(operations.JobProgress) error) error {
	d.mu.RLock()
	renewal := d.renewal
	d.mu.RUnlock()
	if renewal != nil {
		handled, err := renewal.HandleJob(ctx, req)
		if handled {
			if err != nil {
				return err
			}
			return progress(operations.JobProgress{Completed: true})
		}
	}
	job := &renewalOpTestJob{ctx: ctx, req: req, done: make(chan struct{})}
	select {
	case d.started <- job:
	case <-ctx.Done():
		return ctx.Err()
	}
	select {
	case <-job.done:
		return progress(operations.JobProgress{Completed: true})
	case <-ctx.Done():
		return ctx.Err()
	}
}

type renewalOpTestCloudflare struct {
	token string
}

func (a *renewalOpTestCloudflare) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Scheme != "https" || req.URL.Host != "api.cloudflare.com" || req.URL.Path != "/client/v4/zones" ||
		req.Header.Get("Authorization") != "Bearer "+a.token {
		return nil, errors.New("unexpected cloudflare test request")
	}
	body, err := json.Marshal(map[string]any{
		"success":     true,
		"result":      []provider.Zone{{ID: renewalOpTestZone, Name: "example.test"}},
		"result_info": map[string]int{"page": 1, "count": 1, "total_pages": 1, "total_count": 1},
	})
	if err != nil {
		return nil, err
	}
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": {"application/json"}},
		Body:       io.NopCloser(bytes.NewReader(body)),
		Request:    req,
	}, nil
}

type renewalOpTestReservationSource struct {
	facts hostauth.ConsumerReservationFacts
}

func (s *renewalOpTestReservationSource) AuthorizeReservation(_ context.Context, _ hostauth.Invocation, _ certificates.Consumer) (hostauth.ConsumerReservationFacts, error) {
	return s.facts, nil
}

type renewalOpTestConsumerSource struct {
	mu    sync.Mutex
	facts hostauth.ConsumerFacts
}

func (s *renewalOpTestConsumerSource) CurrentConsumer(_ context.Context, _ hostauth.Invocation, _ certificates.Consumer) (hostauth.ConsumerFacts, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.facts, nil
}

type renewalOpTestEnv struct {
	clock      *clock.Fake
	catalog    *renewalOpTestCatalog
	dispatch   *renewalOpTestDispatch
	host       *testsupport.HostFixture
	human      actor.Actor
	authority  *hostauth.Authority
	runsRepo   store.Repository
	runs       *certificates.PrivateRenewalRuns
	renewalOps *RenewalOperations
	contexts   hostauth.RenewalContexts
	scope      certificates.RenewalScope
	service    authz.ServiceAccount
	expiresAt  time.Time
}

func newRenewalOpTestEnv(t *testing.T) *renewalOpTestEnv {
	t.Helper()
	now := time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)
	clk := clock.NewFake(now)
	cat := &renewalOpTestCatalog{actions: make(map[string]operations.Action)}
	disp := &renewalOpTestDispatch{started: make(chan *renewalOpTestJob, 8)}
	host := testsupport.NewHost(t, clk, cat, disp)
	human := host.User(t, "renewal-ops-admin", authz.RoleAdmin)

	var tokenRaw [24]byte
	if _, err := rand.Read(tokenRaw[:]); err != nil {
		t.Fatal(err)
	}
	cf := &renewalOpTestCloudflare{token: base64.RawURLEncoding.EncodeToString(tokenRaw[:])}
	clear(tokenRaw[:])

	consumer := certificates.Consumer{
		PluginID:  "core.xray",
		ProfileID: "h2-first",
		NodeID:    renewalOpTestNode,
		SNI:       "proxy.example.test",
		Purpose:   "proxy.hysteria2",
	}
	resSrc := &renewalOpTestReservationSource{
		facts: hostauth.ConsumerReservationFacts{
			Consumer:       consumer,
			ConfigRevision: "0",
			PluginVersion:  "0.2.0+test",
		},
	}
	consSrc := &renewalOpTestConsumerSource{}

	authority, err := hostauth.New(hostauth.Options{
		DB:           host.DB,
		Secrets:      host.Secrets,
		Operations:   host.Operations,
		Authorizer:   host.Authorizer,
		NodeID:       renewalOpTestNode,
		OwnerID:      renewalOpTestOwner,
		HTTPClient:   &http.Client{Transport: cf},
		Reservations: resSrc,
		Consumers:    consSrc,
		Clock:        clk,
	})
	if err != nil {
		t.Fatal(err)
	}

	runsRepo, err := store.NewEncrypted(store.EncryptedOptions{
		DB:        host.DB,
		Secrets:   host.Secrets,
		Namespace: "certificates",
	})
	if err != nil {
		t.Fatal(err)
	}
	runs, err := certificates.NewPrivateRenewalRuns(certificates.RenewalRunOptions{
		Repository: runsRepo,
		Clock:      clk,
	})
	if err != nil {
		t.Fatal(err)
	}

	renewalOps, err := NewRenewalOperations(RenewalOperationsOptions{
		Operations:    host.Operations,
		Authority:     authority,
		Runs:          runs,
		NodeID:        renewalOpTestNode,
		OwnerID:       renewalOpTestOwner,
		StartTimeout:  3 * time.Second,
		FinishTimeout: 3 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	disp.setRenewal(renewalOps)

	// 注册真实的 renew_existing 插件作业动作。
	cat.put(operations.Action{
		ID:           renewalActionID,
		Summary:      "证书自动续期",
		Effect:       operations.EffectWrite,
		Risk:         operations.RiskLow,
		Approval:     operations.ApprovalAuto,
		Mode:         operations.ModeJob,
		Idempotent:   true,
		Source:       operations.PluginSource,
		PluginID:     "tls.certificates",
		Placement:    operations.PlacementController,
		Operation:    "renew_existing",
		APIVersion:   "1",
		Permission:   "system.certificates:manage",
		TimeoutMS:    60000,
		Capabilities: []operations.Capability{{Name: "system.certificates.manage", Scope: "self"}},
	})

	env := &renewalOpTestEnv{
		clock:      clk,
		catalog:    cat,
		dispatch:   disp,
		host:       host,
		human:      human,
		authority:  authority,
		runsRepo:   runsRepo,
		runs:       runs,
		renewalOps: renewalOps,
		contexts:   hostauth.RenewalContexts{Authority: authority, Runs: runs},
		expiresAt:  now.Add(24 * time.Hour),
	}

	// 1. 登记 DNS 提供商与授权 zone。
	callCtx, finish := env.startHuman(t, "domain.dns", "providers.register",
		"plugins/domain.dns/resources/providers/"+renewalOpTestProvider, "absent",
		map[string]any{
			"provider_id": renewalOpTestProvider,
			"kind":        dns.Cloudflare,
			"name":        "test-cf",
			"credential":  map[string]string{"token": cf.token},
		})
	if _, _, err := authority.RegisterProvider(callCtx, renewalOpTestProvider, "absent"); err != nil {
		t.Fatal(err)
	}
	finish()

	callCtx, finish = env.startHuman(t, "domain.dns", "zones.authorize",
		"plugins/domain.dns/resources/zones/"+renewalOpTestProvider+"/"+renewalOpTestZone, "absent",
		hostauth.ZoneArgs{ProviderID: renewalOpTestProvider, ZoneID: renewalOpTestZone})
	dnsScope, _, err := authority.AuthorizeZone(callCtx, renewalOpTestProvider, renewalOpTestZone, "absent")
	if err != nil {
		t.Fatal(err)
	}
	finish()

	// 2. 运行时生成证书并在宿主登记证书资源。
	cert, err := testsupport.SignedCertificate(now, func(leaf *x509.Certificate) {
		leaf.DNSNames = []string{"proxy.example.test"}
		leaf.Subject.CommonName = "proxy.example.test"
	}, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(cert.Clear)

	spec := certificates.Spec{SANs: []string{"proxy.example.test"}, Purpose: tlsmgr.ServerTLS}
	certSubject := "plugins/tls.certificates/resources/certificates/" + renewalOpTestCert
	callCtx, finish = env.startHuman(t, "tls.certificates", "certificates.import", certSubject, "absent",
		map[string]any{
			"certificate_id": renewalOpTestCert,
			"attempt_id":     "import-cert-one",
			"spec":           spec,
			"chain_pem":      string(cert.Chain),
			"private_key":    string(cert.Key),
			"trust":          tlsmgr.PublicTrust,
		})
	certCtx, _, err := authority.CertificateContext(callCtx, renewalOpTestCert, "import-cert-one", "absent")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := authority.AcceptedImportRequest(certCtx); err != nil {
		t.Fatal(err)
	}
	finish()

	// 3. 预留并确认消费者绑定。
	revDigest := strings.Repeat("a", 64)
	callCtx, finish = env.startHuman(t, "tls.certificates", "bindings.reserve", certSubject, revDigest,
		hostauth.ReserveBindingArgs{
			CertificateID:          renewalOpTestCert,
			Consumer:               consumer,
			ExpectedConfigRevision: "0",
		})
	reservation, err := authority.ReserveBinding(callCtx, renewalOpTestCert, revDigest)
	if err != nil {
		t.Fatal(err)
	}
	finish()

	consSrc.mu.Lock()
	consSrc.facts = hostauth.ConsumerFacts{
		Consumer:       consumer,
		ConfigRevision: "1",
		PluginVersion:  "0.2.0+test",
		BindingRef:     reservation.BindingRef,
	}
	consSrc.mu.Unlock()

	callCtx, finish = env.startHuman(t, "tls.certificates", "bindings.bind", certSubject, revDigest,
		hostauth.BindCertificateArgs{
			CertificateID: renewalOpTestCert,
			BindingRef:    reservation.BindingRef,
			AttemptID:     "bind-cert-one",
			Generation:    1,
		})
	bindCtx, _, err := authority.BindingContext(callCtx, renewalOpTestCert, revDigest)
	if err != nil {
		t.Fatal(err)
	}
	bindReq, err := authority.AcceptedBindRequest(bindCtx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := authority.ConfirmConsumerBinding(bindCtx, bindReq.Caller, bindReq.CertificateID, bindReq.Generation, bindReq.Consumer); err != nil {
		t.Fatal(err)
	}
	finish()

	// 4. 登记续期策略并创建与策略精确匹配的受限服务账号。
	policySubject := "plugins/tls.certificates/resources/policies/" + renewalOpTestPolicy
	callCtx, finish = env.startHuman(t, "tls.certificates", "renewal.configure", policySubject, "absent",
		hostauth.RenewalPolicyArgs{
			PolicyID:      renewalOpTestPolicy,
			CertificateID: renewalOpTestCert,
			ProviderID:    renewalOpTestProvider,
			ZoneID:        renewalOpTestZone,
			CA:            certificates.LetsEncrypt,
			BindingRefs:   []string{reservation.BindingRef},
			ExpiresAt:     env.expiresAt,
		})
	policyView, err := authority.RegisterRenewalPolicy(callCtx, renewalOpTestPolicy, "absent")
	if err != nil {
		t.Fatal(err)
	}
	finish()

	svcScope := &authz.ServiceScope{
		Actions:   []string{renewalActionID},
		NodeIDs:   []string{renewalOpTestNode},
		Subjects:  []string{certSubject},
		ExpiresAt: env.expiresAt,
	}
	if err := host.DB.Update(context.Background(), func(tx *storage.Tx) error {
		created, err := host.Authorizer.CreateServiceAccount(context.Background(), tx, authz.CreateServiceAccountInput{
			Actor: human,
			Name:  "renewal-ops-test-svc",
			Role:  authz.RoleOperator,
			Scope: svcScope,
		})
		if err != nil {
			return err
		}
		created.Token = ""
		env.service = created.ServiceAccount
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	callCtx, finish = env.startHuman(t, "tls.certificates", "renewal.attach_service", policySubject, policyView.Revision,
		hostauth.RenewalServiceArgs{
			PolicyID:         renewalOpTestPolicy,
			ServiceAccountID: env.service.ID,
		})
	if _, err := authority.AttachRenewalService(callCtx, renewalOpTestPolicy, policyView.Revision); err != nil {
		t.Fatal(err)
	}
	finish()

	canonicalScope, err := certificates.CanonicalRenewalScope(certificates.RenewalScope{
		OwnerID:       renewalOpTestOwner,
		CertificateID: renewalOpTestCert,
		Issuance: certificates.IssuanceScope{
			Spec:     spec,
			Provider: dnsScope,
			CA:       certificates.LetsEncrypt,
		},
		Consumers: []certificates.Consumer{consumer},
	})
	if err != nil {
		t.Fatal(err)
	}
	env.scope = canonicalScope
	return env
}

func (e *renewalOpTestEnv) startHuman(t *testing.T, plugin, op, subject, expected string, args any) (context.Context, func()) {
	t.Helper()
	resource := "system.dns"
	if plugin == "tls.certificates" {
		resource = "system.certificates"
	}
	meta := operations.Action{
		ID:           plugin + "/" + op,
		Summary:      "renewal operations test action",
		Effect:       operations.EffectWrite,
		Risk:         operations.RiskHigh,
		Approval:     operations.ApprovalConfirm,
		Mode:         operations.ModeJob,
		Idempotent:   true,
		Source:       operations.PluginSource,
		PluginID:     plugin,
		Placement:    operations.PlacementController,
		Operation:    op,
		APIVersion:   "1",
		Permission:   resource + ":manage",
		TimeoutMS:    60000,
		Capabilities: []operations.Capability{{Name: resource + ".manage", Scope: "self"}},
	}
	if op == "providers.register" {
		meta.ArgsSchema = json.RawMessage(`{"type":"object","properties":{"provider_id":{"type":"string"},"kind":{"type":"string"},"name":{"type":"string"},"credential":{"type":"object","x-secret":true,"additionalProperties":true}},"required":["provider_id","kind","name","credential"],"additionalProperties":false}`)
	}
	if plugin == "tls.certificates" && op == "certificates.import" {
		meta.ArgsSchema = json.RawMessage(`{"type":"object","properties":{"certificate_id":{"type":"string"},"attempt_id":{"type":"string"},"spec":{"type":"object"},"chain_pem":{"type":"string"},"private_key":{"type":"string","writeOnly":true,"x-secret":true},"trust":{"type":"string"}},"required":["certificate_id","attempt_id","spec","chain_pem","private_key","trust"],"additionalProperties":false}`)
	}
	e.catalog.put(meta)

	raw, err := json.Marshal(args)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(raw)

	resp, err := e.host.Operations.Run(context.Background(), operations.RunRequest{
		Actor:            e.human,
		NodeID:           renewalOpTestNode,
		Action:           meta.ID,
		Target:           operations.Target{PluginID: plugin, Subject: subject},
		Args:             raw,
		ExpectedRevision: expected,
		Idempotency:      operations.Idempotency{Key: e.host.IDs.New(ids.Operation), Method: "POST", Route: "/test/human"},
	})
	if err != nil || resp == nil || resp.Operation == nil {
		t.Fatalf("发起人工 operation %s 失败：%v", meta.ID, err)
	}
	if resp.Operation.Status == operations.AwaitingApproval {
		approval, err := e.host.Operations.GetApproval(context.Background(), e.human, resp.Operation.ApprovalID)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := e.host.Operations.Decide(context.Background(), operations.DecisionRequest{
			Actor:            e.human,
			ApprovalID:       approval.ID,
			Decision:         operations.DecisionApprove,
			ExpectedRevision: approval.Revision,
			Idempotency:      operations.Idempotency{Key: e.host.IDs.New(ids.Operation), Method: "POST", Route: "/test/approve"},
		}); err != nil {
			t.Fatal(err)
		}
	}
	select {
	case job := <-e.dispatch.started:
		if job.req.OperationID != resp.Operation.ID {
			t.Fatalf("收到非预期 operation：%s != %s", job.req.OperationID, resp.Operation.ID)
		}
		inv := hostauth.Invocation{
			PluginID:    plugin,
			InstanceID:  operations.ControllerDispatchInstance,
			OperationID: job.req.OperationID,
			Operation:   op,
			Subject:     subject,
		}
		ctx, release, err := e.authority.Begin(job.ctx, inv)
		if err != nil {
			job.finish()
			t.Fatal(err)
		}
		finish := func() {
			release()
			job.finish()
		}
		t.Cleanup(finish)
		return ctx, finish
	case <-time.After(5 * time.Second):
		t.Fatalf("等待人工 operation %s 派发超时", meta.ID)
		return nil, nil
	}
}

func (e *renewalOpTestEnv) writeClaimedRun(t *testing.T, runNumber uint64, runAttemptID, operationID string) {
	t.Helper()
	now := e.clock.Now().UTC()
	payload := map[string]any{
		"policies": []map[string]any{
			{
				"id":         renewalOpTestPolicy,
				"version":    1,
				"scope":      e.scope,
				"enabled":    true,
				"attempts":   1,
				"run_number": runNumber,
				"next_at":    now.Add(-time.Minute),
				"expires_at": e.expiresAt,
				"job": map[string]any{
					"attempt_id":   runAttemptID,
					"operation_id": operationID,
					"started_at":   now,
					"lease_until":  now.Add(10 * time.Minute),
				},
			},
		},
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	entry, found, err := e.runsRepo.Get(context.Background(), "certificates/renewal-ledger")
	if err != nil {
		t.Fatal(err)
	}
	expected := ""
	if found {
		expected = entry.Revision
	}
	if _, err := e.runsRepo.Put(context.Background(), "certificates/renewal-ledger", expected, raw); err != nil {
		t.Fatal(err)
	}
}

func (e *renewalOpTestEnv) waitOpStatus(t *testing.T, opID string, want operations.Status) *operations.Operation {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		op, err := e.host.Operations.Get(context.Background(), e.human, opID)
		if err != nil {
			t.Fatal(err)
		}
		if op.Status == want {
			return op
		}
		time.Sleep(15 * time.Millisecond)
	}
	op, _ := e.host.Operations.Get(context.Background(), e.human, opID)
	t.Fatalf("operation %s 状态=%v，期望=%s", opID, op.Status, want)
	return nil
}

// ======================== 端到端 Begin/RenewalContexts/Finish 与真实取消验证 ========================

func TestRenewalOperationsEndToEndAndCancellation(t *testing.T) {
	env := newRenewalOpTestEnv(t)

	// 校验只读 ActiveRenewalServiceAccount 返回精确服务账号。
	serviceID, err := env.authority.ActiveRenewalServiceAccount(context.Background(), renewalOpTestPolicy, env.scope)
	if err != nil || serviceID != env.service.ID {
		t.Fatalf("ActiveRenewalServiceAccount=%q err=%v，期望=%q", serviceID, err, env.service.ID)
	}

	// 1. 完整成功闭环：claim -> Begin -> attach -> RenewalContexts.Context(Read) -> Finish("succeeded") -> SQLite SUCCEEDED。
	runAttempt1 := "renewrun_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	env.writeClaimedRun(t, 1, runAttempt1, "")
	// 显式收紧为只读模式时绝不能被放宽。
	if _, err := env.renewalOps.Begin(operations.WithPermissionMode(context.Background(), operations.PermissionReadOnly), renewalOpTestPolicy, "1", runAttempt1, env.scope); err == nil {
		t.Fatal("PermissionReadOnly 上下文发起 Begin 必须拒绝")
	}
	caller1, err := env.renewalOps.Begin(context.Background(), renewalOpTestPolicy, "1", runAttempt1, env.scope)
	if err != nil {
		t.Fatalf("RenewalOperations.Begin 失败：%v", err)
	}
	if caller1.OwnerID != renewalOpTestOwner || caller1.OperationID == "" || caller1.PolicyID != renewalOpTestPolicy || caller1.PolicyRevision != "1" {
		t.Fatalf("Begin 返回 caller 字段不符：%+v", caller1)
	}
	env.writeClaimedRun(t, 1, runAttempt1, caller1.OperationID)

	if _, _, err := env.contexts.Context(operations.WithPermissionMode(context.Background(), operations.PermissionReadOnly), certificates.RenewalContextRequest{
		Caller:       caller1,
		Scope:        env.scope,
		RunAttemptID: runAttempt1,
		Access:       certificates.Read,
	}); err == nil {
		t.Fatal("PermissionReadOnly 上下文获取 RenewalContexts 必须拒绝")
	}

	execCtx, release, err := env.contexts.Context(context.Background(), certificates.RenewalContextRequest{
		Caller:       caller1,
		Scope:        env.scope,
		RunAttemptID: runAttempt1,
		Access:       certificates.Read,
	})
	if err != nil {
		t.Fatalf("hostauth.RenewalContexts.Context(Read) 失败：%v", err)
	}
	if err := execCtx.Err(); err != nil {
		t.Fatalf("活跃续期上下文不应已取消：%v", err)
	}
	release()

	if err := env.renewalOps.Finish(context.Background(), caller1, "succeeded"); err != nil {
		t.Fatalf("RenewalOperations.Finish(succeeded) 失败：%v", err)
	}
	op1 := env.waitOpStatus(t, caller1.OperationID, operations.Succeeded)
	if op1.Actor.Kind != actor.Service || op1.Actor.ID != env.service.ID {
		t.Fatalf("SQLite operation actor 不符：%+v", op1.Actor)
	}

	// 2. 真实取消传播：ops.Cancel 立即取消由 hostauth.RenewalContexts 派生的上下文，HandleJob 干净退出。
	runAttempt2 := "renewrun_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	env.writeClaimedRun(t, 2, runAttempt2, "")
	caller2, err := env.renewalOps.Begin(context.Background(), renewalOpTestPolicy, "1", runAttempt2, env.scope)
	if err != nil {
		t.Fatalf("第二次 Begin 失败：%v", err)
	}
	env.writeClaimedRun(t, 2, runAttempt2, caller2.OperationID)

	cancelExecCtx, cancelRelease, err := env.contexts.Context(context.Background(), certificates.RenewalContextRequest{
		Caller:       caller2,
		Scope:        env.scope,
		RunAttemptID: runAttempt2,
		Access:       certificates.Read,
	})
	if err != nil {
		t.Fatalf("第二次 RenewalContexts.Context(Read) 失败：%v", err)
	}
	defer cancelRelease()

	if _, err := env.host.Operations.Cancel(context.Background(), operations.CancelRequest{
		Actor:       env.human,
		OperationID: caller2.OperationID,
		Reason:      "test cancel renewal",
		Idempotency: operations.Idempotency{
			Key:    env.host.IDs.New(ids.Operation),
			Method: "POST",
			Route:  "/test/cancel-renewal",
		},
	}); err != nil {
		t.Fatalf("ops.Cancel 失败：%v", err)
	}
	// 推进假时钟越过 JobCancelGrace，触发真实 executor context 取消并传播到 RenewalContexts。
	// Cancel 内部的宽限计时器在后台 goroutine 注册，周期推进假时钟避免抢先 Advance 导致假时钟漏触发。
	cancelDeadline := time.NewTimer(3 * time.Second)
	defer cancelDeadline.Stop()
	cancelTick := time.NewTicker(10 * time.Millisecond)
	defer cancelTick.Stop()
waitCancel:
	for {
		env.clock.Advance(env.host.Operations.Config().JobCancelGrace)
		select {
		case <-cancelExecCtx.Done():
			break waitCancel
		case <-cancelTick.C:
		case <-cancelDeadline.C:
			t.Fatal("ops.Cancel 后 RenewalContexts 派生上下文未及时取消")
		}
	}
	env.waitOpStatus(t, caller2.OperationID, operations.Canceled)
	// 取消退出后再调用 Finish 应幂等成功。
	if err := env.renewalOps.Finish(context.Background(), caller2, "failed"); err != nil {
		t.Fatalf("取消后调用 Finish 应幂等：%v", err)
	}

	// 3. 未登记的 HandleJob 绝不劫持外部调用。
	unregisteredPayload, _ := json.Marshal(hostauth.RenewExistingArgs{
		PolicyID:       renewalOpTestPolicy,
		PolicyRevision: "1",
		CertificateID:  renewalOpTestCert,
		RunAttemptID:   "renewrun_cccccccccccccccccccccccccccccccc",
		AttemptID:      "renewcert_1",
	})
	for _, req := range []operations.PluginRunJobRequest{
		{PluginID: "other.plugin", Operation: "renew_existing", Payload: unregisteredPayload},
		{PluginID: "tls.certificates", Operation: "other_op", Payload: unregisteredPayload},
		{PluginID: "tls.certificates", Operation: "renew_existing", Payload: unregisteredPayload},
		{PluginID: "tls.certificates", Operation: "renew_existing", Payload: []byte("{invalid")},
	} {
		handled, err := env.renewalOps.HandleJob(context.Background(), req)
		if handled || err != nil {
			t.Fatalf("未登记调用被错误接管：handled=%v err=%v req=%+v", handled, err, req)
		}
	}

	// 4. 不存在的策略或已撤销服务账号必须在 Begin 阶段失败，不创建任何 operation。
	_, err = env.renewalOps.Begin(context.Background(), "policy-missing", "1", "renewrun_dddddddddddddddddddddddddddddddd", env.scope)
	if err == nil || fault.Code(err) != "NOT_FOUND" {
		t.Fatalf("缺失策略 Begin 期望 NOT_FOUND，实际=%s err=%v", fault.Code(err), err)
	}

	if err := env.host.DB.Update(context.Background(), func(tx *storage.Tx) error {
		return env.host.Authorizer.RevokeServiceAccount(context.Background(), tx, authz.RevokeServiceAccountInput{
			Actor:            env.human,
			ServiceAccountID: env.service.ID,
			ExpectedRevision: env.service.Revision,
		})
	}); err != nil {
		t.Fatal(err)
	}
	runAttempt3 := "renewrun_eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
	env.writeClaimedRun(t, 3, runAttempt3, "")
	_, err = env.renewalOps.Begin(context.Background(), renewalOpTestPolicy, "1", runAttempt3, env.scope)
	if err == nil {
		t.Fatal("撤销服务账号后 Begin 必须拒绝")
	}
}

// ======================== RepositoryViews CAS 与键校验测试 ========================

func TestRepositoryViewsRoundTripAndCASConflicts(t *testing.T) {
	mem := &testsupport.MemoryStore{}
	views := capability.NewRepositoryViews(mem)
	ctx := context.Background()
	key := "prerequisites/certificates/resources/index"

	if _, found, err := views.Get(ctx, key); err != nil || found {
		t.Fatalf("空视图读取应返回 found=false：found=%v err=%v", found, err)
	}
	if _, err := views.Put(ctx, "../escape", []byte(`{}`), hostsvc.StateGuard{MustNotExist: true}); fault.Code(err) != "VALIDATION_FAILED" {
		t.Fatalf("非法路径键应返回 VALIDATION_FAILED：%v", err)
	}

	rev1, err := views.Put(ctx, key, []byte(`{"version":1,"ids":["cert-a"]}`), hostsvc.StateGuard{MustNotExist: true})
	if err != nil || rev1 == "" {
		t.Fatalf("首次 MustNotExist 写入失败：rev=%q err=%v", rev1, err)
	}
	if _, err := views.Put(ctx, key, []byte(`{"version":1,"ids":["cert-b"]}`), hostsvc.StateGuard{MustNotExist: true}); !errors.Is(err, hostsvc.ErrStateConflict) {
		t.Fatalf("重复 MustNotExist 应返回 ErrStateConflict：%v", err)
	}

	entry, found, err := views.Get(ctx, key)
	if err != nil || !found || entry.Key != key || entry.Revision != rev1 || string(entry.Value) != `{"version":1,"ids":["cert-a"]}` {
		t.Fatalf("Get 往返结果不符：entry=%+v found=%v err=%v", entry, found, err)
	}

	if _, err := views.Put(ctx, key, []byte(`{"version":1,"ids":["cert-c"]}`), hostsvc.StateGuard{ExpectedRevision: "stale-rev"}); !errors.Is(err, hostsvc.ErrStateConflict) {
		t.Fatalf("过期 ExpectedRevision 应返回 ErrStateConflict：%v", err)
	}
	rev2, err := views.Put(ctx, key, []byte(`{"version":1,"ids":["cert-a","cert-b"]}`), hostsvc.StateGuard{ExpectedRevision: rev1})
	if err != nil || rev2 == "" || rev2 == rev1 {
		t.Fatalf("匹配 ExpectedRevision 更新失败：rev2=%q err=%v", rev2, err)
	}

	// 无条件写入（空 StateGuard）应读取当前版本并覆盖成功。
	rev3, err := views.Put(ctx, key, []byte(`{"version":1,"ids":[]}`), hostsvc.StateGuard{})
	if err != nil || rev3 == "" || rev3 == rev2 {
		t.Fatalf("无条件 Put 失败：rev3=%q err=%v", rev3, err)
	}

	if err := views.Delete(ctx, key, "wrong-rev"); !errors.Is(err, hostsvc.ErrStateConflict) {
		t.Fatalf("Delete 版本不匹配应返回 ErrStateConflict：%v", err)
	}
	if err := views.Delete(ctx, key, rev3); err != nil {
		t.Fatalf("匹配版本 Delete 失败：%v", err)
	}
	if err := views.Delete(ctx, key, ""); err != nil {
		t.Fatalf("缺失键无条件 Delete 应幂等成功：%v", err)
	}
}
