// SPDX-License-Identifier: AGPL-3.0-only

package certificates

import (
	"context"
	"errors"
	"slices"
	"sync"
	"time"

	"github.com/qwq-panel/qwq/internal/platform/clock"
	"github.com/qwq-panel/qwq/internal/prerequisites/fault"
	"github.com/qwq-panel/qwq/internal/prerequisites/names"
	"github.com/qwq-panel/qwq/internal/prerequisites/store"
)

type Options struct {
	Repository     store.Repository
	Materials      Materials
	Authority      Authority
	Bindings       Bindings
	Authorizer     Authorizer
	Clock          clock.Clock
	MaxGenerations int
	MaxBindings    int
	MaxReceipts    int
	CallTimeout    time.Duration
	CleanupTimeout time.Duration
}

// Manager 不持有秘密材料，只保存宿主受控引用与公开证书元数据。
type Manager struct {
	mu             sync.Mutex
	repository     store.Repository
	materials      Materials
	authority      Authority
	bindings       Bindings
	authorizer     Authorizer
	clock          clock.Clock
	maxGenerations int
	maxBindings    int
	maxReceipts    int
	callTimeout    time.Duration
	cleanupTimeout time.Duration
}

func New(options Options) (*Manager, error) {
	if options.Repository == nil || options.Materials == nil || options.Authority == nil || options.Bindings == nil || options.Authorizer == nil {
		return nil, fault.New("BACKEND_REQUIRED", "证书模块需要受控状态、材料、CA、绑定和授权后端")
	}
	if options.Clock == nil {
		options.Clock = clock.System{}
	}
	if options.MaxGenerations == 0 {
		options.MaxGenerations = 32
	}
	if options.MaxBindings == 0 {
		options.MaxBindings = 32
	}
	if options.MaxReceipts == 0 {
		options.MaxReceipts = 128
	}
	if options.CallTimeout == 0 {
		options.CallTimeout = 10 * time.Minute
	}
	if options.CleanupTimeout == 0 {
		options.CleanupTimeout = 15 * time.Second
	}
	if options.MaxGenerations < 2 || options.MaxGenerations > 128 || options.MaxBindings < 1 || options.MaxBindings > 128 || options.MaxReceipts < 1 || options.MaxReceipts > 256 || options.CallTimeout <= 0 || options.CallTimeout > 15*time.Minute || options.CleanupTimeout <= 0 || options.CleanupTimeout > time.Minute {
		return nil, fault.New("VALIDATION_FAILED", "证书资源或任务上限无效")
	}
	return &Manager{repository: options.Repository, materials: options.Materials, authority: options.Authority, bindings: options.Bindings,
		authorizer: options.Authorizer, clock: options.Clock, maxGenerations: options.MaxGenerations, maxBindings: options.MaxBindings,
		maxReceipts: options.MaxReceipts, callTimeout: options.CallTimeout, cleanupTimeout: options.CleanupTimeout}, nil
}

func (m *Manager) authorize(ctx context.Context, request Authorization) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := validateCaller(request.Caller, request.Access != Read); err != nil {
		return err
	}
	if !names.ID(request.CertificateID) {
		return fault.New("VALIDATION_FAILED", "证书资源标识无效")
	}
	if request.Caller.PolicyID != "" && request.Access != Read && request.Access != RenewExisting && request.Access != Bind {
		return fault.New("PERMISSION_DENIED", "续期 actor 不能执行其他证书操作")
	}
	return m.authorizer.Authorize(ctx, request)
}

func (m *Manager) load(ctx context.Context, caller Caller, certificateID string) (resource, string, bool, error) {
	state := resource{ID: certificateID, OwnerID: caller.OwnerID, Generations: []generationState{}, Bindings: []Binding{}, Receipts: []receiptState{}}
	revision, found, err := store.Load(ctx, m.repository, key(caller.OwnerID, certificateID), &state)
	if err != nil || !found {
		return state, revision, found, err
	}
	if state.ID != certificateID || state.OwnerID != caller.OwnerID || len(state.Generations) > m.maxGenerations || len(state.Bindings) > m.maxBindings || len(state.Receipts) > m.maxReceipts {
		return resource{}, "", false, fault.New("STATE_INVALID", "证书持久资源无效")
	}
	canonical, err := canonicalSpec(state.Spec)
	if err != nil || !sameSpec(canonical, state.Spec) {
		return resource{}, "", false, fault.New("STATE_INVALID", "证书持久 SAN 或用途无效")
	}
	seen := map[uint64]bool{}
	for _, generation := range state.Generations {
		if generation.Number == 0 || seen[generation.Number] || !validMaterialReference(generation.Material) || !sameSpec(Spec{generation.Metadata.SANs, generation.Metadata.Purpose}, state.Spec) || !generation.Metadata.NotAfter.After(generation.Metadata.NotBefore) || generation.CreatedAt.IsZero() {
			return resource{}, "", false, fault.New("STATE_INVALID", "证书 generation 无效")
		}
		seen[generation.Number] = true
	}
	if state.CurrentGeneration != 0 && !seen[state.CurrentGeneration] {
		return resource{}, "", false, fault.New("STATE_INVALID", "证书当前 generation 不存在")
	}
	seenBindings := map[string]bool{}
	for _, binding := range state.Bindings {
		consumer, err := canonicalConsumer(binding.Host.Consumer)
		if err != nil || consumer != binding.Host.Consumer || !names.ID(binding.Host.ID) || !names.ID(binding.Host.PolicyRevision) || binding.Host.CertificateID != certificateID || binding.Host.Generation != binding.RunningGeneration || !seen[binding.RunningGeneration] || (binding.PreviousGeneration != 0 && !seen[binding.PreviousGeneration]) || seenBindings[consumerKey(consumer)] {
			return resource{}, "", false, fault.New("STATE_INVALID", "证书消费绑定无效")
		}
		seenBindings[consumerKey(consumer)] = true
	}
	if state.Pending != nil {
		active := state.Pending
		if !names.ID(active.ID) || len(active.Hash) != 64 || active.Caller.OwnerID != caller.OwnerID || validateCaller(active.Caller, true) != nil || !sameSpec(active.Spec, state.Spec) || active.StartedAt.IsZero() || (active.Material != "" && !validMaterialReference(active.Material)) {
			return resource{}, "", false, fault.New("STATE_INVALID", "证书待执行状态无效")
		}
		switch active.Kind {
		case "issue":
			if active.Scope == nil {
				return resource{}, "", false, fault.New("STATE_INVALID", "ACME 待执行状态缺少范围")
			}
			if scope, err := canonicalScope(*active.Scope); err != nil || !sameSpec(scope.Spec, state.Spec) {
				return resource{}, "", false, fault.New("STATE_INVALID", "ACME 持久范围无效")
			}
		case "import", "test":
		case "remove":
			if active.RemoveGeneration != 0 && (!seen[active.RemoveGeneration] || active.Material == "") {
				return resource{}, "", false, fault.New("STATE_INVALID", "证书删除状态无效")
			}
		case "bind", "unbind":
			if active.Binding == nil || !names.ID(active.Binding.ID) || !names.ID(active.Binding.PolicyRevision) || active.Binding.CertificateID != certificateID || !seen[active.Binding.Generation] {
				return resource{}, "", false, fault.New("STATE_INVALID", "证书待绑定状态无效")
			}
			if consumer, err := canonicalConsumer(active.Binding.Consumer); err != nil || consumer != active.Binding.Consumer {
				return resource{}, "", false, fault.New("STATE_INVALID", "持久消费者格式无效")
			}
		default:
			return resource{}, "", false, fault.New("STATE_INVALID", "证书待执行动作无效")
		}
	}
	seenReceipts := map[string]bool{}
	for _, receipt := range state.Receipts {
		if !names.ID(receipt.ID) || len(receipt.Hash) != 64 || seenReceipts[receipt.ID] {
			return resource{}, "", false, fault.New("STATE_INVALID", "证书收据无效")
		}
		if receipt.Stage == "unbound" {
			if receipt.Binding == nil {
				return resource{}, "", false, fault.New("STATE_INVALID", "解绑收据缺少原消费绑定")
			}
			binding := *receipt.Binding
			consumer, err := canonicalConsumer(binding.Consumer)
			if err != nil || consumer != binding.Consumer || !names.ID(binding.ID) || !names.ID(binding.PolicyRevision) ||
				binding.CertificateID != certificateID || binding.Generation == 0 || receipt.Generation != binding.Generation {
				return resource{}, "", false, fault.New("STATE_INVALID", "解绑收据的原绑定范围无效")
			}
		} else if receipt.Binding != nil {
			return resource{}, "", false, fault.New("STATE_INVALID", "其他证书收据不能携带解绑范围")
		}
		seenReceipts[receipt.ID] = true
	}
	return state, revision, true, nil
}

func (m *Manager) save(ctx context.Context, caller Caller, state resource, revision string) (string, error) {
	bounded, cancel := context.WithTimeout(context.WithoutCancel(ctx), m.cleanupTimeout)
	defer cancel()
	return store.Save(bounded, m.repository, key(caller.OwnerID, state.ID), revision, state)
}

func (m *Manager) view(state resource, revision string) View {
	view := View{ID: state.ID, Spec: Spec{SANs: slices.Clone(state.Spec.SANs), Purpose: state.Spec.Purpose}, Revision: revision,
		CurrentGeneration: state.CurrentGeneration, Generations: make([]Generation, 0, len(state.Generations)), Bindings: slices.Clone(state.Bindings), ConsumersReady: true, LastError: state.LastError}
	valid := map[uint64]bool{}
	for _, generation := range state.Generations {
		public := generation.Generation
		public.Metadata.SANs = slices.Clone(public.Metadata.SANs)
		view.Generations = append(view.Generations, public)
		valid[generation.Number] = !m.clock.Now().Before(generation.Metadata.NotBefore) && m.clock.Now().Before(generation.Metadata.NotAfter)
	}
	view.Ready = valid[state.CurrentGeneration]
	for _, binding := range view.Bindings {
		view.ConsumersReady = view.ConsumersReady && binding.Verified && valid[binding.RunningGeneration]
	}
	if state.Pending != nil {
		view.Pending = state.Pending.Kind
		view.ConsumersReady = false
		if state.Pending.Kind == "remove" && state.Pending.RemoveGeneration == 0 {
			view.Ready = false
		}
	}
	return view
}

// Get 不揭示证书或私钥引用；过期的运行代不会报告 ready。
func (m *Manager) Get(ctx context.Context, caller Caller, certificateID string) (View, error) {
	if err := m.authorize(ctx, Authorization{Caller: caller, CertificateID: certificateID, Access: Read}); err != nil {
		return View{}, err
	}
	state, revision, found, err := m.load(ctx, caller, certificateID)
	if err != nil {
		return View{}, err
	}
	if !found {
		return View{}, fault.New("NOT_FOUND", "证书不存在")
	}
	return m.view(state, revision), nil
}

func generationByNumber(state resource, number uint64) (generationState, bool) {
	for _, generation := range state.Generations {
		if generation.Number == number {
			return generation, true
		}
	}
	return generationState{}, false
}

func unknown(detail string) error {
	return &fault.Error{Code: "OUTCOME_UNKNOWN", Detail: detail, Uncertain: true}
}

func backendFailure(err error, fallback string) error {
	code := fault.Code(err)
	switch code {
	case "RATE_LIMITED", "CREDENTIAL_REVOKED", "PERMISSION_DENIED", "POLICY_REVOKED", "POLICY_SCOPE_DENIED", "SCOPE_INVALID", "SAN_INVALID", "SAN_MISMATCH", "CERTIFICATE_INVALID", "CERTIFICATE_EXPIRED", "CERTIFICATE_NOT_YET_VALID", "CERTIFICATE_CHAIN_INVALID", "CERTIFICATE_PURPOSE_INVALID", "PRIVATE_KEY_MISMATCH", "PRIVATE_KEY_INVALID", "PRIVATE_KEY_UNSUPPORTED", "TRUST_UNAVAILABLE", "OUTCOME_UNKNOWN", "RESOURCE_IN_USE", "NOT_FOUND", "REVISION_CONFLICT", "DEPLOYMENT_FAILED", "DNS_CLEANUP_FAILED", "DNS_NOT_PROPAGATED", "CAA_FORBIDDEN", "CA_REJECTED", "CA_UNAVAILABLE", "ZONE_DENIED", "RECORD_CONFLICT", "STATE_INVALID", "STATE_UNAVAILABLE", "RESOURCE_EXHAUSTED", "CERTIFICATE_BUSY", "ATTEMPT_CONFLICT", "RENEWAL_OPERATION_FAILED", "RENEWAL_AUDIT_FAILED", "RENEWAL_EXHAUSTED", "RETRY_BUDGET_EXCEEDED", "RENEWAL_FAILED":
	default:
		code = fallback
	}
	var original *fault.Error
	uncertain := errors.As(err, &original) && original.Uncertain
	return &fault.Error{Code: code, Detail: "证书受控后端拒绝操作或暂不可用", RetryAt: fault.Retry(err), Uncertain: uncertain}
}
