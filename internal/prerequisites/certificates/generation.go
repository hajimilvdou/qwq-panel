// SPDX-License-Identifier: AGPL-3.0-only

package certificates

import (
	"context"
	"errors"
	"math"
	"slices"
	"sync"
	"time"

	"github.com/qwq-panel/qwq/internal/prerequisites/fault"
	"github.com/qwq-panel/qwq/internal/prerequisites/names"
	"github.com/qwq-panel/qwq/internal/prerequisites/store"
	"github.com/qwq-panel/qwq/internal/tlsmgr"
)

type startRequest struct {
	Caller           Caller
	CertificateID    string
	AttemptID        string
	ExpectedRevision string
	Spec             Spec
	Scope            *IssuanceScope
	Kind             string
	Hash             string
}

type materialSource func(context.Context, bool) (Issued, error)

// Issue 支持受控 DNS-01；自动 actor 只能续既有资源，不能新建证书。
func (m *Manager) Issue(ctx context.Context, input IssueRequest, progress Progress) (result Result, err error) {
	scope, err := canonicalScope(input.Scope)
	if err != nil {
		return Result{}, err
	}
	input.Scope = scope
	hash, err := fingerprint(input)
	if err != nil {
		return Result{}, err
	}
	request := startRequest{Caller: input.Caller, CertificateID: input.CertificateID, AttemptID: input.AttemptID, ExpectedRevision: input.ExpectedRevision,
		Spec: scope.Spec, Scope: &scope, Kind: "issue", Hash: hash}
	bounded, cancel := context.WithTimeout(ctx, m.callTimeout)
	defer cancel()
	defer func() {
		if result.View.ID != input.CertificateID {
			return
		}
		cleanup, stop := context.WithTimeout(context.WithoutCancel(ctx), m.cleanupTimeout)
		defer stop()
		if cleanupErr := m.authority.Cancel(cleanup, input.Caller, input.CertificateID, input.AttemptID, scope); cleanupErr != nil {
			err = errors.Join(err, backendFailure(cleanupErr, "DNS_CLEANUP_FAILED"))
		}
	}()
	return m.start(bounded, request, guardedProgress(progress), func(ctx context.Context, recover bool) (Issued, error) {
		if recover {
			return m.authority.Reconcile(ctx, input.Caller, input.CertificateID, input.AttemptID, scope, guardedProgress(progress))
		}
		return m.authority.Issue(ctx, input.Caller, input.CertificateID, input.AttemptID, scope, guardedProgress(progress))
	})
}

// ImportCertificate 接收提取后的私钥引用，明文只在宿主材料后端出现。
func (m *Manager) ImportCertificate(ctx context.Context, input ImportRequest) (Result, error) {
	spec, err := canonicalSpec(input.Spec)
	if err != nil {
		return Result{}, err
	}
	if !names.ID(input.PrivateKeyRef) || len(input.ChainPEM) == 0 || len(input.ChainPEM) > tlsmgr.MaxCertificatePEM ||
		(input.Trust != tlsmgr.PublicTrust && input.Trust != tlsmgr.StagingTrust && input.Trust != tlsmgr.TestTrust) ||
		(spec.Purpose == tlsmgr.TestServerTLS) != (input.Trust == tlsmgr.TestTrust) {
		return Result{}, fault.New("VALIDATION_FAILED", "证书导入链、私钥引用或信任用途无效")
	}
	input.Spec = spec
	hash, err := fingerprint(input)
	if err != nil {
		return Result{}, err
	}
	bounded, cancel := context.WithTimeout(ctx, m.callTimeout)
	defer cancel()
	request := startRequest{Caller: input.Caller, CertificateID: input.CertificateID, AttemptID: input.AttemptID, ExpectedRevision: input.ExpectedRevision, Spec: spec, Kind: "import", Hash: hash}
	return m.start(bounded, request, nil, func(ctx context.Context, _ bool) (Issued, error) {
		ref, err := m.materials.Import(ctx, input.Caller, input.CertificateID, input.AttemptID, input.ChainPEM, input.PrivateKeyRef, spec, input.Trust)
		return Issued{Material: ref, Trust: input.Trust}, err
	})
}

// GenerateTestCertificate 明确使用测试用途，不把自签名变成普通生产证书。
func (m *Manager) GenerateTestCertificate(ctx context.Context, input TestRequest) (Result, error) {
	spec, err := canonicalSpec(input.Spec)
	if err != nil {
		return Result{}, err
	}
	if spec.Purpose != tlsmgr.TestServerTLS {
		return Result{}, fault.New("CERTIFICATE_PURPOSE_INVALID", "自签名测试证书必须显式选择测试用途")
	}
	input.Spec = spec
	hash, err := fingerprint(input)
	if err != nil {
		return Result{}, err
	}
	bounded, cancel := context.WithTimeout(ctx, m.callTimeout)
	defer cancel()
	return m.start(bounded, startRequest{Caller: input.Caller, CertificateID: input.CertificateID, AttemptID: input.AttemptID, ExpectedRevision: input.ExpectedRevision, Spec: spec, Kind: "test", Hash: hash}, nil,
		func(ctx context.Context, _ bool) (Issued, error) {
			ref, err := m.materials.GenerateTest(ctx, input.Caller, input.CertificateID, input.AttemptID, spec)
			return Issued{Material: ref, Trust: tlsmgr.TestTrust}, err
		})
}

func accessFor(request startRequest) Access {
	if request.Caller.PolicyID != "" {
		return RenewExisting
	}
	switch request.Kind {
	case "issue":
		return Issue
	case "import":
		return Import
	default:
		return TestIssue
	}
}

func (m *Manager) start(ctx context.Context, request startRequest, progress Progress, source materialSource) (Result, error) {
	authorization := Authorization{Caller: request.Caller, CertificateID: request.CertificateID, Spec: request.Spec, Issuance: request.Scope, Access: accessFor(request)}
	if request.Caller.PolicyID != "" && request.Kind != "issue" {
		return Result{}, fault.New("POLICY_SCOPE_DENIED", "自动续期只能执行既定 ACME 签发")
	}
	if !names.ID(request.AttemptID) || request.ExpectedRevision == "" {
		return Result{}, fault.New("VALIDATION_FAILED", "证书写入需要 attempt 与 expected_revision")
	}
	if err := m.authorize(ctx, authorization); err != nil {
		return Result{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	state, revision, found, err := m.load(ctx, request.Caller, request.CertificateID)
	if err != nil {
		return Result{}, err
	}
	if found {
		for _, receipt := range state.Receipts {
			if receipt.ID == request.AttemptID {
				if receipt.Hash != request.Hash {
					return Result{}, fault.New("ATTEMPT_CONFLICT", "证书 attempt 已用于不同请求")
				}
				if receipt.Stage == "rejected" {
					return Result{View: m.view(state, revision), Stage: receipt.Stage}, &fault.Error{Code: receipt.ErrorCode, Detail: "上次证书任务已被拒绝", RetryAt: receipt.RetryAt}
				}
				return Result{View: m.view(state, revision), Stage: receipt.Stage}, nil
			}
		}
		if !sameSpec(state.Spec, request.Spec) {
			return Result{}, fault.New("SCOPE_CHANGE_REQUIRED", "SAN 或用途变更必须创建新的证书资源并重新绑定")
		}
	}
	if state.Pending != nil {
		if state.Pending.ID != request.AttemptID || state.Pending.Hash != request.Hash || state.Pending.Kind != request.Kind {
			return Result{}, fault.New("CERTIFICATE_BUSY", "证书存在待对账任务")
		}
		return m.obtain(ctx, request.Caller, &state, revision, progress, source, true)
	}
	if (!found && request.ExpectedRevision != MissingRevision) || (found && request.ExpectedRevision != revision) {
		return Result{}, fault.New("REVISION_CONFLICT", "证书版本已变化，请重新预演")
	}
	if !found && request.Caller.PolicyID != "" {
		return Result{}, fault.New("POLICY_SCOPE_DENIED", "自动续期不能创建证书资源")
	}
	if len(state.Generations) >= m.maxGenerations || len(state.Receipts) >= m.maxReceipts {
		return Result{}, fault.New("RESOURCE_EXHAUSTED", "证书历史或收据达到上限，请清理未引用历史")
	}
	state.Spec = request.Spec
	state.Pending = &pending{ID: request.AttemptID, Hash: request.Hash, Caller: request.Caller, Spec: request.Spec, Scope: request.Scope, Kind: request.Kind, StartedAt: m.clock.Now().UTC()}
	revision, err = store.Save(ctx, m.repository, key(request.Caller.OwnerID, request.CertificateID), revision, state)
	if err != nil {
		return Result{}, err
	}
	if err := m.authorize(ctx, authorization); err != nil {
		return m.reject(ctx, request.Caller, &state, revision, fault.Code(err))
	}
	return m.obtain(ctx, request.Caller, &state, revision, progress, source, false)
}

func (m *Manager) obtain(ctx context.Context, caller Caller, state *resource, revision string, progress Progress, source materialSource, recover bool) (Result, error) {
	active := state.Pending
	if active.Material == "" {
		issued, err := source(ctx, recover)
		if issued.Material == "" {
			var failure *fault.Error
			if errors.As(err, &failure) && failure.NotApplied {
				return m.rejectAt(ctx, caller, state, revision, fault.Code(backendFailure(err, "CA_UNAVAILABLE")), fault.Retry(err))
			}
			state.LastError = fault.Code(backendFailure(err, "CA_UNAVAILABLE"))
			if _, saveErr := m.save(ctx, caller, *state, revision); saveErr != nil {
				return Result{View: m.view(*state, revision), Stage: "unknown"}, unknown("证书材料结果与状态保存未确认")
			}
			return Result{View: m.view(*state, revision), Stage: "unknown"}, unknown("证书任务结果未确认，请读取原 attempt 对账")
		}
		if !validMaterialReference(issued.Material) || (issued.Trust != tlsmgr.PublicTrust && issued.Trust != tlsmgr.StagingTrust && issued.Trust != tlsmgr.TestTrust) {
			return Result{View: m.view(*state, revision), Stage: "unknown"}, unknown("受控 CA 返回无效材料引用，未发布 generation")
		}
		active.Material, active.Trust = issued.Material, issued.Trust
		var saveErr error
		revision, saveErr = m.save(ctx, caller, *state, revision)
		if saveErr != nil {
			return Result{View: m.view(*state, revision), Stage: "unknown"}, unknown("材料已生成，但引用未能持久化；不能重新签发")
		}
	}
	return m.publish(ctx, caller, state, revision, progress)
}

func (m *Manager) publish(ctx context.Context, caller Caller, state *resource, revision string, progress Progress) (Result, error) {
	active := state.Pending
	authorization := Authorization{Caller: caller, CertificateID: state.ID, Spec: state.Spec, Issuance: active.Scope, Access: accessFor(startRequest{Caller: caller, Kind: active.Kind})}
	if err := m.authorize(ctx, authorization); err != nil {
		return Result{View: m.view(*state, revision), Stage: "unknown"}, err
	}
	metadata, err := m.materials.Inspect(ctx, caller, state.ID, active.Material, state.Spec, active.Trust)
	if err != nil {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), m.cleanupTimeout)
		defer cancel()
		if removeErr := m.materials.Remove(cleanup, caller, state.ID, active.Material); removeErr != nil {
			return Result{View: m.view(*state, revision), Stage: "unknown"}, unknown("无效证书材料未能确认清理，保持待对账状态")
		}
		return m.reject(ctx, caller, state, revision, fault.Code(backendFailure(err, "CERTIFICATE_INVALID")))
	}
	if !sameSpec(Spec{metadata.SANs, metadata.Purpose}, state.Spec) || metadata.Trust != active.Trust || m.clock.Now().Before(metadata.NotBefore) || !m.clock.Now().Before(metadata.NotAfter) {
		return Result{View: m.view(*state, revision), Stage: "unknown"}, unknown("受控证书元数据与授权范围或时间不符")
	}
	if active.Kind == "issue" && ((active.Scope.CA == LetsEncrypt && active.Trust != tlsmgr.PublicTrust) || (active.Scope.CA == LetsEncryptStaging && active.Trust != tlsmgr.StagingTrust)) {
		return Result{View: m.view(*state, revision), Stage: "unknown"}, unknown("CA 信任类别与原授权不符，未发布 generation")
	}
	if state.CurrentGeneration == math.MaxUint64 {
		return Result{}, fault.New("RESOURCE_EXHAUSTED", "证书 generation 已达上限")
	}
	if progress != nil {
		if err := progress("persisting_generation", 95); err != nil {
			return Result{View: m.view(*state, revision), Stage: "unknown"}, err
		}
	}
	number := state.CurrentGeneration + 1
	source := ACME
	if active.Kind == "import" {
		source = Imported
	}
	if active.Kind == "test" {
		source = SelfSigned
	}
	published := *state
	published.Generations = append(slices.Clone(state.Generations), generationState{Generation: Generation{Number: number, Metadata: metadata, Source: source, CreatedAt: m.clock.Now().UTC()}, Material: active.Material})
	published.CurrentGeneration, published.LastError = number, ""
	published.Receipts = append(slices.Clone(state.Receipts), receiptState{ID: active.ID, Hash: active.Hash, Generation: number, Stage: "issued"})
	published.Pending = nil
	newRevision, err := m.save(ctx, caller, published, revision)
	if err != nil {
		return Result{View: m.view(*state, revision), Stage: "unknown"}, unknown("签发结果已校验，但 generation 未能持久化")
	}
	*state = published
	return Result{View: m.view(*state, newRevision), Stage: "issued"}, nil
}

func (m *Manager) reject(ctx context.Context, caller Caller, state *resource, revision, code string) (Result, error) {
	return m.rejectAt(ctx, caller, state, revision, code, time.Time{})
}

func (m *Manager) rejectAt(ctx context.Context, caller Caller, state *resource, revision, code string, retryAt time.Time) (Result, error) {
	active := state.Pending
	rejected := *state
	rejected.Receipts = append(slices.Clone(state.Receipts), receiptState{ID: active.ID, Hash: active.Hash, Stage: "rejected", ErrorCode: code, RetryAt: retryAt})
	rejected.Pending, rejected.LastError = nil, code
	newRevision, err := m.save(ctx, caller, rejected, revision)
	if err != nil {
		return Result{View: m.view(*state, revision), Stage: "unknown"}, unknown("证书失败终态未能保存")
	}
	*state = rejected
	return Result{View: m.view(*state, newRevision), Stage: "rejected"}, &fault.Error{Code: code, Detail: "证书任务已被拒绝", RetryAt: retryAt}
}

func guardedProgress(progress Progress) Progress {
	if progress == nil {
		return nil
	}
	var mu sync.Mutex
	var previous uint32
	return func(stage string, percent uint32) error {
		mu.Lock()
		defer mu.Unlock()
		switch stage {
		case "validating", "authorizing", "generating_key", "publishing_dns", "waiting_dns", "verifying", "issuing", "validating_certificate", "persisting_generation", "cleaning_dns", "deploying":
		default:
			return fault.New("INVALID_PROGRESS", "证书进度阶段无效")
		}
		if percent > 100 || percent < previous {
			return fault.New("INVALID_PROGRESS", "证书进度百分比无效")
		}
		previous = percent
		return progress(stage, percent)
	}
}
