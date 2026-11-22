// SPDX-License-Identifier: AGPL-3.0-only

package certificates

import (
	"context"
	"slices"

	"github.com/qwq-panel/qwq/internal/prerequisites/fault"
	"github.com/qwq-panel/qwq/internal/prerequisites/names"
	"github.com/qwq-panel/qwq/internal/prerequisites/store"
)

// ======================== 精确消费者解绑，与材料/整份资源删除分离 ========================

func (m *Manager) authorizeUnbind(ctx context.Context, caller Caller, state resource, binding HostBinding, attemptID string) error {
	consumer := binding.Consumer
	return m.authorize(ctx, Authorization{Caller: caller, CertificateID: state.ID, Generation: binding.Generation,
		BindingID: binding.ID, AttemptID: attemptID, Spec: state.Spec, Consumer: &consumer, Access: Unbind})
}

// ======================== 引用保护与受控清理 ========================

func (m *Manager) checkReferences(ctx context.Context, caller Caller, state resource, number uint64) error {
	if number == 0 && len(state.Bindings) != 0 {
		return fault.New("RESOURCE_IN_USE", "证书仍有消费者绑定")
	}
	if number != 0 {
		if state.CurrentGeneration == number {
			return fault.New("GENERATION_IN_USE", "不能删除当前证书 generation")
		}
		for _, binding := range state.Bindings {
			if binding.RunningGeneration == number || binding.PreviousGeneration == number {
				return fault.New("GENERATION_IN_USE", "当前或回滚快照仍引用该证书代")
			}
		}
	}
	references, err := m.bindings.References(ctx, caller, state.ID)
	if err != nil {
		return backendFailure(err, "REFERENCES_UNAVAILABLE")
	}
	if len(references) > 256 {
		return fault.New("RESOURCE_EXHAUSTED", "宿主证书引用集合超过上限")
	}
	for _, reference := range references {
		if reference.Generation == 0 || (reference.Kind != "current" && reference.Kind != "previous" && reference.Kind != "pending") {
			return fault.New("REFERENCES_INVALID", "宿主证书引用无效，拒绝删除")
		}
		if _, err := canonicalConsumer(reference.Consumer); err != nil {
			return fault.New("REFERENCES_INVALID", "宿主证书消费者引用无效")
		}
		if number == 0 || reference.Generation == number {
			return fault.New("RESOURCE_IN_USE", "宿主当前、回滚或待部署快照仍引用证书")
		}
	}
	return nil
}

// RemoveGeneration 的宿主锁覆盖引用查询与材料删除，阻止竞态新增消费引用。
func (m *Manager) RemoveGeneration(ctx context.Context, caller Caller, certificateID, attemptID, expectedRevision string, number uint64) (View, error) {
	if !names.ID(attemptID) || expectedRevision == "" || number == 0 {
		return View{}, fault.New("VALIDATION_FAILED", "删除代需要有效 attempt、版本和 generation")
	}
	if err := m.authorize(ctx, Authorization{Caller: caller, CertificateID: certificateID, Generation: number, Access: Remove}); err != nil {
		return View{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	state, revision, found, err := m.load(ctx, caller, certificateID)
	if err != nil {
		return View{}, err
	}
	if !found {
		return View{}, fault.New("NOT_FOUND", "证书不存在")
	}
	if expectedRevision != revision {
		return View{}, fault.New("REVISION_CONFLICT", "证书引用已变化")
	}
	if state.Pending != nil {
		return View{}, fault.New("CERTIFICATE_BUSY", "证书存在待对账任务")
	}
	generation, found := generationByNumber(state, number)
	if !found {
		return View{}, fault.New("NOT_FOUND", "证书 generation 不存在")
	}
	unlock, err := m.bindings.LockForRemoval(ctx, caller, certificateID, number)
	if err != nil || unlock == nil {
		return View{}, backendFailure(err, "REFERENCES_UNAVAILABLE")
	}
	defer unlock()
	if err := m.checkReferences(ctx, caller, state, number); err != nil {
		return View{}, err
	}
	hash, err := fingerprint([]any{caller, certificateID, attemptID, expectedRevision, number})
	if err != nil {
		return View{}, err
	}
	state.Pending = &pending{ID: attemptID, Hash: hash, Kind: "remove", Caller: caller, Spec: state.Spec, Material: generation.Material, RemoveGeneration: number, StartedAt: m.clock.Now().UTC()}
	revision, err = store.Save(ctx, m.repository, key(caller.OwnerID, certificateID), revision, state)
	if err != nil {
		return View{}, err
	}
	return m.finishGenerationRemoval(ctx, caller, &state, revision)
}

func (m *Manager) finishGenerationRemoval(ctx context.Context, caller Caller, state *resource, revision string) (View, error) {
	active := state.Pending
	if err := m.authorize(ctx, Authorization{Caller: caller, CertificateID: state.ID, Generation: active.RemoveGeneration, Spec: state.Spec, Access: Remove}); err != nil {
		return m.view(*state, revision), err
	}
	if err := m.materials.Remove(ctx, caller, state.ID, active.Material); err != nil {
		return m.view(*state, revision), unknown("材料删除结果未确认，保留删除日志")
	}
	removed := *state
	removed.Generations = slices.DeleteFunc(slices.Clone(state.Generations), func(generation generationState) bool { return generation.Number == active.RemoveGeneration })
	removed.Pending = nil
	newRevision, err := m.save(ctx, caller, removed, revision)
	if err != nil {
		return m.view(*state, revision), unknown("材料已删除，历史更新未能保存，请对账")
	}
	*state = removed
	return m.view(*state, newRevision), nil
}

// RecoverGenerationRemoval 仅恢复保存的删除对象，仍重新获取宿主引用锁。
func (m *Manager) RecoverGenerationRemoval(ctx context.Context, caller Caller, certificateID, expectedRevision string) (View, error) {
	if err := m.authorize(ctx, Authorization{Caller: caller, CertificateID: certificateID, Access: Read}); err != nil {
		return View{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	state, revision, found, err := m.load(ctx, caller, certificateID)
	if err != nil {
		return View{}, err
	}
	if !found {
		return View{}, fault.New("NOT_FOUND", "证书不存在")
	}
	if expectedRevision == "" || expectedRevision != revision {
		return View{}, fault.New("REVISION_CONFLICT", "删除对账版本已变化")
	}
	if state.Pending == nil || state.Pending.Kind != "remove" || state.Pending.RemoveGeneration == 0 {
		return View{}, fault.New("RECOVERY_REQUIRED", "没有待对账的 generation 删除")
	}
	number := state.Pending.RemoveGeneration
	if err := m.authorize(ctx, Authorization{Caller: caller, CertificateID: certificateID, Generation: number, Spec: state.Spec, Access: Remove}); err != nil {
		return View{}, err
	}
	unlock, err := m.bindings.LockForRemoval(ctx, caller, certificateID, number)
	if err != nil || unlock == nil {
		return View{}, backendFailure(err, "REFERENCES_UNAVAILABLE")
	}
	defer unlock()
	if err := m.checkReferences(ctx, caller, state, number); err != nil {
		return View{}, err
	}
	return m.finishGenerationRemoval(ctx, caller, &state, revision)
}

// UnbindCertificate 由宿主确认消费者已停止或已脱离证书，清理它的私有副本。
func (m *Manager) UnbindCertificate(ctx context.Context, caller Caller, certificateID, bindingID, attemptID, expectedRevision string) (View, error) {
	if !names.ID(bindingID) || !names.ID(attemptID) || expectedRevision == "" {
		return View{}, fault.New("VALIDATION_FAILED", "解除绑定需要有效标识与版本")
	}
	if err := m.authorize(ctx, Authorization{Caller: caller, CertificateID: certificateID, Access: Read}); err != nil {
		return View{}, err
	}
	hash, err := fingerprint([]any{caller, certificateID, bindingID, attemptID, expectedRevision})
	if err != nil {
		return View{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	state, revision, found, err := m.load(ctx, caller, certificateID)
	if err != nil {
		return View{}, err
	}
	if !found {
		return View{}, fault.New("NOT_FOUND", "证书不存在")
	}
	index := slices.IndexFunc(state.Bindings, func(binding Binding) bool { return binding.Host.ID == bindingID })
	for _, receipt := range state.Receipts {
		if receipt.ID != attemptID {
			continue
		}
		if receipt.Hash != hash {
			return View{}, fault.New("ATTEMPT_CONFLICT", "解绑attempt已用于不同原意图")
		}
		if receipt.Stage == "unbound" && receipt.Binding != nil {
			if err := m.authorizeUnbind(ctx, caller, state, *receipt.Binding, attemptID); err != nil {
				return View{}, err
			}
			return m.view(state, revision), nil
		}
		if receipt.Stage == "rejected" && index >= 0 {
			if err := m.authorizeUnbind(ctx, caller, state, state.Bindings[index].Host, attemptID); err != nil {
				return View{}, err
			}
			return m.view(state, revision), fault.New(receipt.ErrorCode, "原解绑attempt已被拒绝")
		}
		return View{}, fault.New("ATTEMPT_CONFLICT", "原attempt不是可重放的解绑收据")
	}
	if state.Pending != nil {
		active := state.Pending
		if active.Kind != "unbind" || active.ID != attemptID || active.Hash != hash || active.Binding == nil || active.Binding.ID != bindingID {
			return View{}, fault.New("CERTIFICATE_BUSY", "证书存在其他待对账任务")
		}
		return m.executeUnbind(ctx, caller, state, revision)
	}
	if expectedRevision != revision {
		return View{}, fault.New("REVISION_CONFLICT", "证书绑定已变化")
	}
	if index < 0 {
		return View{}, fault.New("NOT_FOUND", "证书绑定不存在")
	}
	if len(state.Receipts) >= m.maxReceipts {
		return View{}, fault.New("RESOURCE_EXHAUSTED", "解绑收据达到有界上限")
	}
	binding := state.Bindings[index].Host
	if err := m.authorizeUnbind(ctx, caller, state, binding, attemptID); err != nil {
		return View{}, err
	}
	state.Pending = &pending{ID: attemptID, Hash: hash, Kind: "unbind", Caller: caller, Spec: state.Spec, Binding: &binding, StartedAt: m.clock.Now().UTC()}
	revision, err = store.Save(ctx, m.repository, key(caller.OwnerID, certificateID), revision, state)
	if err != nil {
		return View{}, err
	}
	return m.executeUnbind(ctx, caller, state, revision)
}

// executeUnbind复用真实Bindings的幂等清理；每次重放仍校验原精确绑定。
func (m *Manager) executeUnbind(ctx context.Context, caller Caller, state resource, revision string) (View, error) {
	active := state.Pending
	if active == nil || active.Kind != "unbind" || active.Binding == nil {
		return View{}, fault.New("STATE_INVALID", "原解绑执行状态无效")
	}
	if len(state.Receipts) >= m.maxReceipts {
		return m.view(state, revision), fault.New("RESOURCE_EXHAUSTED", "解绑收据达到有界上限")
	}
	if err := m.authorizeUnbind(ctx, caller, state, *active.Binding, active.ID); err != nil {
		return m.view(state, revision), err
	}
	bounded, cancel := context.WithTimeout(ctx, m.cleanupTimeout)
	defer cancel()
	if err := m.bindings.Remove(bounded, caller, *active.Binding); err != nil {
		code := fault.Code(backendFailure(err, "UNBIND_UNAVAILABLE"))
		if code == "RESOURCE_IN_USE" {
			result, err := m.reject(ctx, caller, &state, revision, code)
			return result.View, err
		}
		return m.view(state, revision), unknown("消费者清理结果未确认，保留绑定")
	}
	return m.finishUnbind(ctx, caller, state, revision)
}

func (m *Manager) finishUnbind(ctx context.Context, caller Caller, state resource, revision string) (View, error) {
	if err := m.authorizeUnbind(ctx, caller, state, *state.Pending.Binding, state.Pending.ID); err != nil {
		return m.view(state, revision), err
	}
	identifier := state.Pending.Binding.ID
	unbound := state
	unbound.Bindings = slices.DeleteFunc(slices.Clone(state.Bindings), func(candidate Binding) bool { return candidate.Host.ID == identifier })
	binding := *state.Pending.Binding
	unbound.Receipts = append(slices.Clone(state.Receipts), receiptState{ID: state.Pending.ID, Hash: state.Pending.Hash,
		Generation: binding.Generation, Stage: "unbound", Binding: &binding})
	unbound.Pending = nil
	newRevision, err := m.save(ctx, caller, unbound, revision)
	if err != nil {
		return m.view(state, revision), unknown("消费者已清理，绑定状态未能保存")
	}
	return m.view(unbound, newRevision), nil
}

// RecoverUnbind 保留原消费者范围，由宿主幂等确认其私有文件已清理。
func (m *Manager) RecoverUnbind(ctx context.Context, caller Caller, certificateID, expectedRevision string) (View, error) {
	if err := m.authorize(ctx, Authorization{Caller: caller, CertificateID: certificateID, Access: Read}); err != nil {
		return View{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	state, revision, found, err := m.load(ctx, caller, certificateID)
	if err != nil {
		return View{}, err
	}
	if !found {
		return View{}, fault.New("NOT_FOUND", "证书不存在")
	}
	if expectedRevision == "" || expectedRevision != revision {
		return View{}, fault.New("REVISION_CONFLICT", "解除绑定对账版本已变化")
	}
	if state.Pending == nil || state.Pending.Kind != "unbind" || state.Pending.Binding == nil {
		return View{}, fault.New("RECOVERY_REQUIRED", "没有待对账的解除绑定")
	}
	return m.executeUnbind(ctx, caller, state, revision)
}

// RemoveCertificate 仅在业务绑定和宿主所有快照引用解除后删除整个资源。
func (m *Manager) RemoveCertificate(ctx context.Context, caller Caller, certificateID, attemptID, expectedRevision string) error {
	if !names.ID(attemptID) || expectedRevision == "" {
		return fault.New("VALIDATION_FAILED", "删除证书需要 attempt 和 expected_revision")
	}
	if err := m.authorize(ctx, Authorization{Caller: caller, CertificateID: certificateID, Access: Remove}); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	state, revision, found, err := m.load(ctx, caller, certificateID)
	if err != nil {
		return err
	}
	if !found {
		return fault.New("NOT_FOUND", "证书不存在")
	}
	if expectedRevision != revision {
		return fault.New("REVISION_CONFLICT", "删除证书前引用已变化")
	}
	if state.Pending != nil {
		return fault.New("CERTIFICATE_BUSY", "证书存在待对账任务")
	}
	unlock, err := m.bindings.LockForRemoval(ctx, caller, certificateID, 0)
	if err != nil || unlock == nil {
		return backendFailure(err, "REFERENCES_UNAVAILABLE")
	}
	defer unlock()
	if err := m.checkReferences(ctx, caller, state, 0); err != nil {
		return err
	}
	hash, err := fingerprint([]any{caller, certificateID, attemptID, expectedRevision})
	if err != nil {
		return err
	}
	state.Pending = &pending{ID: attemptID, Hash: hash, Kind: "remove", Caller: caller, Spec: state.Spec, StartedAt: m.clock.Now().UTC()}
	revision, err = store.Save(ctx, m.repository, key(caller.OwnerID, certificateID), revision, state)
	if err != nil {
		return err
	}
	return m.finishResourceRemoval(ctx, caller, state, revision)
}

func (m *Manager) finishResourceRemoval(ctx context.Context, caller Caller, state resource, revision string) error {
	bounded, cancel := context.WithTimeout(ctx, m.callTimeout)
	defer cancel()
	for _, generation := range state.Generations {
		if err := m.materials.Remove(bounded, caller, state.ID, generation.Material); err != nil {
			return unknown("证书材料部分删除，保留资源日志等待对账")
		}
	}
	final, stop := context.WithTimeout(context.WithoutCancel(ctx), m.cleanupTimeout)
	defer stop()
	if err := m.repository.Delete(final, key(caller.OwnerID, state.ID), revision); err != nil {
		return unknown("证书材料已清理，资源记录删除未确认")
	}
	return nil
}

func (m *Manager) RecoverCertificateRemoval(ctx context.Context, caller Caller, certificateID, expectedRevision string) error {
	if err := m.authorize(ctx, Authorization{Caller: caller, CertificateID: certificateID, Access: Remove}); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	state, revision, found, err := m.load(ctx, caller, certificateID)
	if err != nil {
		return err
	}
	if !found {
		return nil
	}
	if expectedRevision == "" || expectedRevision != revision {
		return fault.New("REVISION_CONFLICT", "证书删除对账版本已变化")
	}
	if state.Pending == nil || state.Pending.Kind != "remove" || state.Pending.RemoveGeneration != 0 {
		return fault.New("RECOVERY_REQUIRED", "没有待对账的证书删除")
	}
	unlock, err := m.bindings.LockForRemoval(ctx, caller, certificateID, 0)
	if err != nil || unlock == nil {
		return backendFailure(err, "REFERENCES_UNAVAILABLE")
	}
	defer unlock()
	if err := m.checkReferences(ctx, caller, state, 0); err != nil {
		return err
	}
	return m.finishResourceRemoval(ctx, caller, state, revision)
}
