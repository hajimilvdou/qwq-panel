// SPDX-License-Identifier: AGPL-3.0-only

package certificates

import (
	"context"
	"slices"

	"github.com/qwq-panel/qwq/internal/prerequisites/fault"
	"github.com/qwq-panel/qwq/internal/prerequisites/names"
	"github.com/qwq-panel/qwq/internal/prerequisites/store"
	"github.com/qwq-panel/qwq/internal/tlsmgr"
)

// ======================== 消费绑定与确认部署 ========================

// BindCertificate 先校验精确代，再取得宿主许可；只有确认健康后发布运行代。
func (m *Manager) BindCertificate(ctx context.Context, input BindRequest) (Result, error) {
	consumer, err := canonicalConsumer(input.Consumer)
	if err != nil {
		return Result{}, err
	}
	input.Consumer = consumer
	if !names.ID(input.AttemptID) || input.Generation == 0 || input.ExpectedRevision == "" {
		return Result{}, fault.New("VALIDATION_FAILED", "绑定需要 generation、attempt 和 expected_revision")
	}
	if err := m.authorize(ctx, Authorization{Caller: input.Caller, CertificateID: input.CertificateID, Generation: input.Generation, Consumer: &consumer, Access: Bind}); err != nil {
		return Result{}, err
	}
	hash, err := fingerprint(input)
	if err != nil {
		return Result{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	state, revision, found, err := m.load(ctx, input.Caller, input.CertificateID)
	if err != nil {
		return Result{}, err
	}
	if !found {
		return Result{}, fault.New("NOT_FOUND", "证书不存在")
	}
	for _, receipt := range state.Receipts {
		if receipt.ID != input.AttemptID {
			continue
		}
		if receipt.Hash != hash {
			return Result{}, fault.New("ATTEMPT_CONFLICT", "绑定 attempt 已用于不同请求")
		}
		if receipt.Stage == "rejected" {
			return Result{View: m.view(state, revision), Stage: "issued_deployment_failed"}, fault.New(receipt.ErrorCode, "上次证书部署失败")
		}
		return Result{View: m.view(state, revision), Stage: receipt.Stage}, nil
	}
	if state.Pending != nil {
		if state.Pending.Kind != "bind" || state.Pending.ID != input.AttemptID || state.Pending.Hash != hash {
			return Result{}, fault.New("CERTIFICATE_BUSY", "证书存在其他待对账任务")
		}
		return m.reconcileBinding(ctx, input.Caller, &state, revision)
	}
	if input.ExpectedRevision != revision {
		return Result{}, fault.New("REVISION_CONFLICT", "证书或消费者绑定已变化")
	}
	bindingIndex := slices.IndexFunc(state.Bindings, func(binding Binding) bool { return consumerKey(binding.Host.Consumer) == consumerKey(consumer) })
	if len(state.Receipts) >= m.maxReceipts || (len(state.Bindings) >= m.maxBindings && bindingIndex < 0) {
		return Result{}, fault.New("RESOURCE_EXHAUSTED", "证书绑定或收据达到上限")
	}
	generation, found := generationByNumber(state, input.Generation)
	if !found {
		return Result{}, fault.New("NOT_FOUND", "指定证书 generation 不存在")
	}
	if err := m.validateConsumerMaterial(ctx, input.Caller, state, generation, consumer); err != nil {
		return Result{}, err
	}
	bounded, cancel := context.WithTimeout(ctx, m.callTimeout)
	defer cancel()
	host, err := m.bindings.Confirm(bounded, input.Caller, input.CertificateID, input.Generation, consumer)
	if err != nil {
		return Result{}, backendFailure(err, "BINDING_DENIED")
	}
	if !names.ID(host.ID) || !names.ID(host.PolicyRevision) || host.CertificateID != input.CertificateID || host.Generation != input.Generation || host.Consumer != consumer {
		return Result{}, fault.New("BINDING_DENIED", "宿主消费许可与请求范围不符")
	}
	if bindingIndex >= 0 && host.ID != state.Bindings[bindingIndex].Host.ID {
		return Result{}, fault.New("BINDING_DENIED", "同一消费者的稳定绑定引用不可在换代时更换")
	}
	state.Pending = &pending{ID: input.AttemptID, Hash: hash, Kind: "bind", Caller: input.Caller, Spec: state.Spec, Binding: &host, StartedAt: m.clock.Now().UTC()}
	revision, err = store.Save(ctx, m.repository, key(input.Caller.OwnerID, input.CertificateID), revision, state)
	if err != nil {
		return Result{}, err
	}
	if err := m.authorize(ctx, Authorization{Caller: input.Caller, CertificateID: input.CertificateID, Generation: input.Generation, Spec: state.Spec, Consumer: &consumer, Access: Bind}); err != nil {
		return m.reject(ctx, input.Caller, &state, revision, fault.Code(backendFailure(err, "BINDING_DENIED")))
	}
	outcome, deployErr := m.bindings.Deploy(bounded, input.Caller, host, generation.Material)
	if deployErr != nil || (outcome.State != "applied" && outcome.State != "rolled_back") {
		return m.reconcileBinding(ctx, input.Caller, &state, revision)
	}
	return m.completeBinding(ctx, input.Caller, &state, revision, outcome)
}

func (m *Manager) validateConsumerMaterial(ctx context.Context, caller Caller, state resource, generation generationState, consumer Consumer) error {
	metadata, err := m.materials.Inspect(ctx, caller, state.ID, generation.Material, state.Spec, generation.Metadata.Trust)
	if err != nil {
		return backendFailure(err, "CERTIFICATE_INVALID")
	}
	if !sameSpec(Spec{metadata.SANs, metadata.Purpose}, state.Spec) || metadata.Fingerprint != generation.Metadata.Fingerprint || metadata.Trust != generation.Metadata.Trust {
		return fault.New("CERTIFICATE_INVALID", "材料与保存的 generation 不符")
	}
	if !m.clock.Now().Before(metadata.NotAfter) {
		return fault.New("CERTIFICATE_EXPIRED", "消费者证书已过期")
	}
	if m.clock.Now().Before(metadata.NotBefore) {
		return fault.New("CERTIFICATE_NOT_YET_VALID", "消费者证书尚未生效")
	}
	if !consumer.Test && (metadata.Trust != tlsmgr.PublicTrust || metadata.Purpose != tlsmgr.ServerTLS) {
		return fault.New("TEST_CERTIFICATE_DENIED", "普通生产消费者需要公开可信 TLS 证书")
	}
	if err := tlsmgr.Covers(metadata, consumer.SNI); err != nil {
		return err
	}
	return nil
}

func (m *Manager) reconcileBinding(ctx context.Context, caller Caller, state *resource, revision string) (Result, error) {
	active := state.Pending
	if active == nil || active.Binding == nil || active.Kind != "bind" {
		return Result{}, fault.New("STATE_INVALID", "绑定对账状态无效")
	}
	consumer := active.Binding.Consumer
	bounded, cancel := context.WithTimeout(context.WithoutCancel(ctx), m.cleanupTimeout)
	defer cancel()
	if err := m.authorize(bounded, Authorization{Caller: caller, CertificateID: state.ID, Generation: active.Binding.Generation, Spec: state.Spec, Consumer: &consumer, Access: Bind}); err != nil {
		return Result{View: m.view(*state, revision), Stage: "unknown"}, err
	}
	outcome, err := m.bindings.Reconcile(bounded, caller, *active.Binding)
	if err != nil {
		return m.unknownBinding(ctx, caller, state, revision)
	}
	return m.completeBinding(ctx, caller, state, revision, outcome)
}

func (m *Manager) completeBinding(ctx context.Context, caller Caller, state *resource, revision string, outcome Deployment) (Result, error) {
	active := state.Pending
	host := *active.Binding
	index := -1
	for position, existing := range state.Bindings {
		if consumerKey(existing.Host.Consumer) == consumerKey(host.Consumer) {
			index = position
			break
		}
	}
	previous := uint64(0)
	if index >= 0 {
		previous = state.Bindings[index].RunningGeneration
	}
	if outcome.State == "rolled_back" && outcome.ActiveGeneration == previous && (previous == 0 || outcome.Healthy) {
		if index >= 0 {
			state.Bindings[index].Verified = true
			state.Bindings[index].LastError = "DEPLOYMENT_FAILED"
		}
		state.LastError = "DEPLOYMENT_FAILED"
		result, err := m.reject(ctx, caller, state, revision, "DEPLOYMENT_FAILED")
		result.Stage = "issued_deployment_failed"
		return result, err
	}
	if outcome.State != "applied" || !outcome.Healthy || outcome.ActiveGeneration != host.Generation {
		return m.unknownBinding(ctx, caller, state, revision)
	}
	deployed := *state
	deployed.Bindings = slices.Clone(state.Bindings)
	if index < 0 {
		deployed.Bindings = append(deployed.Bindings, Binding{Host: host, RunningGeneration: host.Generation, Verified: true})
	} else {
		old := deployed.Bindings[index]
		if old.RunningGeneration != host.Generation {
			old.PreviousGeneration = old.RunningGeneration
		}
		old.Host, old.RunningGeneration, old.Verified, old.LastError = host, host.Generation, true, ""
		deployed.Bindings[index] = old
	}
	deployed.Pending, deployed.LastError = nil, ""
	deployed.Receipts = append(slices.Clone(state.Receipts), receiptState{ID: active.ID, Hash: active.Hash, Generation: host.Generation, Stage: "bound"})
	newRevision, err := m.save(ctx, caller, deployed, revision)
	if err != nil {
		return Result{View: m.view(*state, revision), Stage: "unknown"}, unknown("宿主部署已确认，运行代记录未能保存")
	}
	*state = deployed
	return Result{View: m.view(*state, newRevision), Stage: "bound"}, nil
}

func (m *Manager) unknownBinding(ctx context.Context, caller Caller, state *resource, revision string) (Result, error) {
	unknownState := *state
	unknownState.Bindings = slices.Clone(state.Bindings)
	for index, binding := range unknownState.Bindings {
		if consumerKey(binding.Host.Consumer) == consumerKey(state.Pending.Binding.Consumer) {
			unknownState.Bindings[index].Verified = false
			unknownState.Bindings[index].LastError = "DEPLOYMENT_UNKNOWN"
		}
	}
	unknownState.LastError = "DEPLOYMENT_UNKNOWN"
	newRevision, err := m.save(ctx, caller, unknownState, revision)
	if err != nil {
		return Result{View: m.view(*state, revision), Stage: "unknown"}, unknown("部署结果与对账状态均未确认")
	}
	*state = unknownState
	return Result{View: m.view(*state, newRevision), Stage: "unknown"}, unknown("实际运行代未确认，仅允许对账或受控恢复")
}

// RollbackBinding 固定到之前保存的代，不能跟随当前最新证书。
func (m *Manager) RollbackBinding(ctx context.Context, caller Caller, certificateID, bindingID, attemptID, expectedRevision string) (Result, error) {
	view, err := m.Get(ctx, caller, certificateID)
	if err != nil {
		return Result{}, err
	}
	if expectedRevision == "" || view.Revision != expectedRevision {
		return Result{}, fault.New("REVISION_CONFLICT", "回滚前证书状态已变化")
	}
	for _, binding := range view.Bindings {
		if binding.Host.ID != bindingID {
			continue
		}
		if binding.PreviousGeneration == 0 {
			return Result{}, fault.New("ROLLBACK_UNAVAILABLE", "此绑定没有可回滚的证书代")
		}
		return m.BindCertificate(ctx, BindRequest{Caller: caller, CertificateID: certificateID, AttemptID: attemptID, ExpectedRevision: expectedRevision,
			Generation: binding.PreviousGeneration, Consumer: binding.Host.Consumer})
	}
	return Result{}, fault.New("NOT_FOUND", "证书消费绑定不存在")
}
