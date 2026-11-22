// SPDX-License-Identifier: AGPL-3.0-only

package deployment

import (
	"context"
	"errors"
	"time"

	"github.com/qwq-panel/qwq/internal/platform/clock"
	"github.com/qwq-panel/qwq/internal/prerequisites/certificates"
	"github.com/qwq-panel/qwq/internal/prerequisites/consumerfiles"
	"github.com/qwq-panel/qwq/internal/prerequisites/fault"
	"github.com/qwq-panel/qwq/internal/prerequisites/names"
)

var _ certificates.Bindings = (*Deployer)(nil)

const (
	defaultBindingMaxRecords  = 256
	deploymentRollbackTimeout = 15 * time.Second
)

// ======================== 构造与实时授权确认 ========================

// New 装配真实的消费者证书部署器；任何受控后端或 TLS 探针缺失均明确拒绝。
func New(options Options) (*Deployer, error) {
	if options.Repository == nil || options.Authority == nil || options.Materials == nil ||
		options.Files == nil || options.Runtime == nil || options.Prober == nil {
		return nil, fault.New("BACKEND_REQUIRED", "消费者部署器需要状态仓库、授权、材料库、文件后端、运行时适配器与真实 TLS 探针")
	}
	if options.Clock == nil {
		options.Clock = clock.System{}
	}
	if options.MaxRecords == 0 {
		options.MaxRecords = defaultBindingMaxRecords
	}
	if options.MaxRecords < 1 || options.MaxRecords > defaultBindingMaxRecords {
		return nil, fault.New("VALIDATION_FAILED", "部署账本最大记录数无效")
	}
	return &Deployer{
		repository:  options.Repository,
		authority:   options.Authority,
		materials:   options.Materials,
		files:       options.Files,
		runtime:     options.Runtime,
		prober:      options.Prober,
		clock:       options.Clock,
		maxRecords:  options.MaxRecords,
		removalGate: make(chan struct{}, 1),
	}, nil
}

// Confirm 直接委托宿主授权器确认精确消费者绑定与许可版本。
func (d *Deployer) Confirm(ctx context.Context, caller certificates.Caller, certificateID string, generation uint64, consumer certificates.Consumer) (certificates.HostBinding, error) {
	if ctx == nil {
		return certificates.HostBinding{}, fault.New("VALIDATION_FAILED", "确认消费绑定需要有效的 context")
	}
	return d.authority.ConfirmConsumerBinding(ctx, caller, certificateID, generation, consumer)
}

// ======================== 受控部署、核验与自动回滚 ========================

// Deploy 将宿主授权的精确证书代落盘、经由运行时加载，并通过真实 TLS 握手探针确认生效。
// 任何健康校验失败都必须完成确认回滚，否则保留 Pending 并返回 unknown 供宿主对账。
func (d *Deployer) Deploy(ctx context.Context, caller certificates.Caller, binding certificates.HostBinding, materialRef certificates.MaterialRef) (certificates.Deployment, error) {
	if ctx == nil {
		return certificates.Deployment{}, fault.New("VALIDATION_FAILED", "部署消费者证书需要有效的 context")
	}
	if err := ctx.Err(); err != nil {
		return certificates.Deployment{}, err
	}
	if !names.ID(caller.OwnerID) || !names.ID(binding.ID) || !names.ID(binding.CertificateID) ||
		!names.ID(binding.PolicyRevision) || binding.Generation == 0 || materialRef == "" {
		return certificates.Deployment{}, fault.New("VALIDATION_FAILED", "部署消费者证书需要规范属主、绑定、代次与材料引用")
	}
	canonical, err := certificates.CanonicalConsumer(binding.Consumer)
	if err != nil || canonical != binding.Consumer {
		return certificates.Deployment{}, fault.New("VALIDATION_FAILED", "消费者身份不规范")
	}

	unlock, err := d.acquireRemoval(ctx)
	if err != nil {
		return certificates.Deployment{}, err
	}
	defer unlock()

	material, err := d.materials.LoadMaterial(ctx, caller, binding.CertificateID, materialRef)
	if err != nil {
		return certificates.Deployment{}, err
	}
	defer material.Clear()

	chain := material.CertificatePEM()
	defer clear(chain)
	leafFP, err := LeafFingerprintPEM(chain)
	if err != nil {
		return certificates.Deployment{}, err
	}

	rec, _, err := d.readRecord(ctx, caller.OwnerID, binding.ID)
	if err != nil {
		return certificates.Deployment{}, err
	}
	if rec.Pending != nil && rec.Pending.Target != binding {
		return certificates.Deployment{}, fault.New("CERTIFICATE_BUSY", "消费者绑定存在其他待对账部署")
	}

	// Step A: 先在宿主账本持久化 Pending，使 References 立即同时保护旧代与目标代。
	var expected *proofRecord
	var priorTargetProof *proofRecord
	if err := d.mutateRecord(ctx, caller.OwnerID, binding.ID, func(record *bindingRecord) (bool, error) {
		if record.Pending != nil && record.Pending.Target != binding {
			return true, fault.New("CERTIFICATE_BUSY", "消费者绑定存在其他待对账部署")
		}
		exp := copyProofRecord(record.Active)
		if record.Pending != nil {
			exp = copyProofRecord(record.Pending.Expected)
			priorTargetProof = copyProofRecord(record.Pending.TargetProof)
		}
		expected = copyProofRecord(exp)
		record.ID = binding.ID
		record.Pending = &pendingDeployment{
			Target:      binding,
			TargetProof: copyProofRecord(priorTargetProof),
			Expected:    exp,
			Phase:       "staging",
			UpdatedAt:   d.clock.Now().UTC(),
		}
		return true, nil
	}); err != nil {
		return certificates.Deployment{}, err
	}

	// Step B: 暂存新代材料与许可快照；此步绝不修改 current.json。
	wantedProof, err := d.files.Stage(ctx, binding, material)
	if err != nil {
		return d.abortBeforeActivate(ctx, caller.OwnerID, binding.Consumer.PluginID, binding.ID, expected, err)
	}
	target := &proofRecord{Proof: wantedProof, LeafFingerprint: leafFP}
	if err := d.mutateRecord(ctx, caller.OwnerID, binding.ID, func(record *bindingRecord) (bool, error) {
		if record.Pending == nil || record.Pending.Target != binding {
			return true, fault.New("STATE_INVALID", "部署待对账记录已丢失或变化")
		}
		record.Pending.TargetProof = copyProofRecord(target)
		record.Pending.Phase = "activating"
		record.Pending.UpdatedAt = d.clock.Now().UTC()
		return true, nil
	}); err != nil {
		return certificates.Deployment{State: "unknown", Healthy: false}, err
	}

	// Step C: 激活前实时复核宿主授权，拒绝激活已被撤销或变更的消费许可。
	reconfirmed, err := d.authority.ConfirmConsumerBinding(ctx, caller, binding.CertificateID, binding.Generation, binding.Consumer)
	if err != nil || reconfirmed != binding {
		cause := err
		if cause == nil {
			cause = fault.New("BINDING_DENIED", "激活前宿主消费许可已变化或被撤销")
		}
		return d.abortBeforeActivate(ctx, caller.OwnerID, binding.Consumer.PluginID, binding.ID, expected, cause)
	}

	// Step D: 交叉核对磁盘 current 与宿主账本 expected，绝不盲信磁盘上的 previous。
	diskCur, err := d.files.Current(ctx, binding.Consumer.PluginID, binding.ID)
	if err != nil {
		return certificates.Deployment{State: "unknown", Healthy: false}, err
	}
	expectedProofPtr := proofPtrOf(expected)
	matchesExpected := sameConsumerProofPtr(diskCur, expectedProofPtr)
	resumingActivated := priorTargetProof != nil && priorTargetProof.Proof == wantedProof &&
		diskCur != nil && *diskCur == wantedProof
	if !matchesExpected && !resumingActivated {
		return certificates.Deployment{State: "unknown", Healthy: false}, fault.New("CONSUMER_FILES_CONFLICT", "磁盘当前证书证明与宿主账本不一致")
	}

	// Step E: 执行受控 CAS 切换 current.json，并核对返回的 previous 与宿主 expected 完全一致。
	prev, err := d.files.Activate(ctx, binding.Consumer.PluginID, expectedProofPtr, wantedProof)
	if err != nil {
		var fe *fault.Error
		if errors.As(err, &fe) && fe.Uncertain {
			return certificates.Deployment{State: "unknown", Healthy: false}, err
		}
		afterCur, curErr := d.files.Current(ctx, binding.Consumer.PluginID, binding.ID)
		if curErr != nil || !sameConsumerProofPtr(afterCur, expectedProofPtr) {
			return certificates.Deployment{State: "unknown", Healthy: false}, err
		}
		return d.abortBeforeActivate(ctx, caller.OwnerID, binding.Consumer.PluginID, binding.ID, expected, err)
	}
	if !sameConsumerProofPtr(prev, expectedProofPtr) {
		return certificates.Deployment{State: "unknown", Healthy: false}, fault.New("CONSUMER_FILES_CONFLICT", "磁盘返回的前代证明与宿主账本不一致")
	}

	// Step F: 触发运行时加载并执行强制实况检查与真实 TLS 握手指纹核验。
	if err := d.mutateRecord(ctx, caller.OwnerID, binding.ID, func(record *bindingRecord) (bool, error) {
		if record.Pending == nil || record.Pending.Target != binding {
			return true, fault.New("STATE_INVALID", "部署待对账记录已丢失或变化")
		}
		record.Pending.Phase = "verifying"
		record.Pending.UpdatedAt = d.clock.Now().UTC()
		return true, nil
	}); err != nil {
		return certificates.Deployment{State: "unknown", Healthy: false}, err
	}

	verifyErr := d.runtime.Apply(ctx, binding, wantedProof)
	if verifyErr == nil {
		verifyErr = VerifyRuntimeHealth(ctx, binding.Consumer, wantedProof, leafFP, d.runtime, d.prober)
	}
	if verifyErr == nil {
		if err := d.commitApplied(ctx, caller.OwnerID, binding.ID, binding, target, expected); err != nil {
			return certificates.Deployment{State: "unknown", Healthy: false}, err
		}
		return certificates.Deployment{
			State:            "applied",
			ActiveGeneration: binding.Generation,
			Healthy:          true,
		}, nil
	}
	return d.rollbackActivated(ctx, caller.OwnerID, binding, target, expected)
}

func (d *Deployer) abortBeforeActivate(ctx context.Context, ownerID, pluginID, bindingID string, expected *proofRecord, cause error) (certificates.Deployment, error) {
	abortCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), deploymentRollbackTimeout)
	defer cancel()

	if expected == nil {
		// 首次部署尚未激活但可能已暂存私钥，先幂等清理磁盘目录，绝不在撤权后残留孤儿私钥。
		if _, err := d.files.Remove(abortCtx, pluginID, bindingID); err != nil {
			return certificates.Deployment{State: "unknown", Healthy: false}, err
		}
		if err := d.mutateRecord(abortCtx, ownerID, bindingID, func(record *bindingRecord) (bool, error) {
			record.Pending = nil
			return record.Active != nil || record.Previous != nil, nil
		}); err != nil {
			return certificates.Deployment{State: "unknown", Healthy: false}, err
		}
		return certificates.Deployment{
			State:            "rolled_back",
			ActiveGeneration: 0,
			Healthy:          false,
		}, nil
	}

	if err := VerifyRuntimeHealth(abortCtx, expected.Proof.Binding.Consumer, expected.Proof, expected.LeafFingerprint, d.runtime, d.prober); err != nil {
		if cause != nil {
			return certificates.Deployment{State: "unknown", Healthy: false}, cause
		}
		return certificates.Deployment{State: "unknown", Healthy: false}, err
	}
	if err := d.mutateRecord(abortCtx, ownerID, bindingID, func(record *bindingRecord) (bool, error) {
		record.Pending = nil
		return true, nil
	}); err != nil {
		return certificates.Deployment{State: "unknown", Healthy: false}, err
	}
	return certificates.Deployment{
		State:            "rolled_back",
		ActiveGeneration: expected.Proof.Binding.Generation,
		Healthy:          true,
	}, nil
}

func (d *Deployer) commitApplied(ctx context.Context, ownerID, bindingID string, binding certificates.HostBinding, target, expected *proofRecord) error {
	return d.mutateRecord(ctx, ownerID, bindingID, func(record *bindingRecord) (bool, error) {
		if record.Pending == nil || record.Pending.Target != binding {
			return true, fault.New("STATE_INVALID", "提交部署结果前待对账记录已变化")
		}
		if expected != nil && !sameProofRecord(expected, target) {
			record.Previous = copyProofRecord(expected)
		}
		record.Active = copyProofRecord(target)
		record.Pending = nil
		return true, nil
	})
}

func (d *Deployer) rollbackActivated(ctx context.Context, ownerID string, binding certificates.HostBinding, target, expected *proofRecord) (certificates.Deployment, error) {
	rollbackCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), deploymentRollbackTimeout)
	defer cancel()

	// 尽力记录 rolling_back 阶段；即便更新阶段失败仍继续执行实际回滚。
	_ = d.mutateRecord(rollbackCtx, ownerID, binding.ID, func(record *bindingRecord) (bool, error) {
		if record.Pending != nil && record.Pending.Target == binding {
			record.Pending.Phase = "rolling_back"
			record.Pending.UpdatedAt = d.clock.Now().UTC()
		}
		return true, nil
	})

	if expected != nil {
		targetProof := target.Proof
		if _, err := d.files.Activate(rollbackCtx, binding.Consumer.PluginID, &targetProof, expected.Proof); err != nil {
			return certificates.Deployment{State: "unknown", Healthy: false}, err
		}
		if err := d.runtime.Apply(rollbackCtx, expected.Proof.Binding, expected.Proof); err != nil {
			return certificates.Deployment{State: "unknown", Healthy: false}, err
		}
		if err := VerifyRuntimeHealth(rollbackCtx, expected.Proof.Binding.Consumer, expected.Proof, expected.LeafFingerprint, d.runtime, d.prober); err != nil {
			return certificates.Deployment{State: "unknown", Healthy: false}, err
		}
		if err := d.mutateRecord(rollbackCtx, ownerID, binding.ID, func(record *bindingRecord) (bool, error) {
			record.Active = copyProofRecord(expected)
			record.Pending = nil
			return true, nil
		}); err != nil {
			return certificates.Deployment{State: "unknown", Healthy: false}, err
		}
		return certificates.Deployment{
			State:            "rolled_back",
			ActiveGeneration: expected.Proof.Binding.Generation,
			Healthy:          true,
		}, nil
	}

	// 首次部署回滚：严禁忽略文件删除错误，且必须确认运行时不再持有任何活动证书代。
	if _, err := d.files.Remove(rollbackCtx, binding.Consumer.PluginID, binding.ID); err != nil {
		return certificates.Deployment{State: "unknown", Healthy: false}, err
	}
	obs, err := d.runtime.Inspect(rollbackCtx, binding.Consumer, binding.ID)
	if err != nil {
		return certificates.Deployment{State: "unknown", Healthy: false}, err
	}
	if obs.Running && obs.ActiveGeneration != 0 {
		return certificates.Deployment{State: "unknown", Healthy: false}, fault.New("DEPLOYMENT_ROLLBACK_FAILED", "首次部署回滚后运行时仍报告活动证书代")
	}
	if err := d.mutateRecord(rollbackCtx, ownerID, binding.ID, func(record *bindingRecord) (bool, error) {
		record.Pending = nil
		return record.Active != nil || record.Previous != nil, nil
	}); err != nil {
		return certificates.Deployment{State: "unknown", Healthy: false}, err
	}
	return certificates.Deployment{
		State:            "rolled_back",
		ActiveGeneration: 0,
		Healthy:          false,
	}, nil
}

// ======================== 对账与受控解绑清理 ========================

// Reconcile 基于宿主账本、磁盘 current 证明与实时 TLS 探针对账未决或已生效的绑定。
func (d *Deployer) Reconcile(ctx context.Context, caller certificates.Caller, binding certificates.HostBinding) (certificates.Deployment, error) {
	if ctx == nil {
		return certificates.Deployment{State: "unknown", Healthy: false}, fault.New("VALIDATION_FAILED", "对账消费者证书需要有效的 context")
	}
	if err := ctx.Err(); err != nil {
		return certificates.Deployment{State: "unknown", Healthy: false}, err
	}
	if !names.ID(caller.OwnerID) || !names.ID(binding.ID) {
		return certificates.Deployment{State: "unknown", Healthy: false}, fault.New("VALIDATION_FAILED", "对账消费者证书需要有效的属主与绑定标识")
	}

	unlock, err := d.acquireRemoval(ctx)
	if err != nil {
		return certificates.Deployment{State: "unknown", Healthy: false}, err
	}
	defer unlock()

	rec, found, err := d.readRecord(ctx, caller.OwnerID, binding.ID)
	if err != nil {
		return certificates.Deployment{State: "unknown", Healthy: false}, err
	}
	if !found {
		return certificates.Deployment{State: "unknown", Healthy: false}, nil
	}

	if rec.Pending == nil {
		if rec.Active != nil && rec.Active.Proof.Binding == binding {
			diskCur, curErr := d.files.Current(ctx, binding.Consumer.PluginID, binding.ID)
			if curErr == nil && diskCur != nil && *diskCur == rec.Active.Proof &&
				VerifyRuntimeHealth(ctx, binding.Consumer, rec.Active.Proof, rec.Active.LeafFingerprint, d.runtime, d.prober) == nil {
				return certificates.Deployment{
					State:            "applied",
					ActiveGeneration: binding.Generation,
					Healthy:          true,
				}, nil
			}
		}
		return certificates.Deployment{State: "unknown", Healthy: false}, nil
	}

	if rec.Pending.Target != binding {
		return certificates.Deployment{State: "unknown", Healthy: false}, nil
	}

	diskCur, err := d.files.Current(ctx, binding.Consumer.PluginID, binding.ID)
	if err != nil {
		return certificates.Deployment{State: "unknown", Healthy: false}, err
	}

	// 若目标代已在磁盘生效且通过实时健康校验，则完成提交。
	if rec.Pending.TargetProof != nil && diskCur != nil && *diskCur == rec.Pending.TargetProof.Proof {
		if VerifyRuntimeHealth(ctx, binding.Consumer, rec.Pending.TargetProof.Proof, rec.Pending.TargetProof.LeafFingerprint, d.runtime, d.prober) == nil {
			if err := d.commitApplied(ctx, caller.OwnerID, binding.ID, binding, rec.Pending.TargetProof, rec.Pending.Expected); err != nil {
				return certificates.Deployment{State: "unknown", Healthy: false}, err
			}
			return certificates.Deployment{
				State:            "applied",
				ActiveGeneration: binding.Generation,
				Healthy:          true,
			}, nil
		}
	}

	if rec.Pending.Expected != nil {
		exp := rec.Pending.Expected
		if diskCur != nil && *diskCur == exp.Proof {
			healthErr := VerifyRuntimeHealth(ctx, exp.Proof.Binding.Consumer, exp.Proof, exp.LeafFingerprint, d.runtime, d.prober)
			if healthErr != nil {
				if applyErr := d.runtime.Apply(ctx, exp.Proof.Binding, exp.Proof); applyErr == nil {
					healthErr = VerifyRuntimeHealth(ctx, exp.Proof.Binding.Consumer, exp.Proof, exp.LeafFingerprint, d.runtime, d.prober)
				}
			}
			if healthErr == nil {
				if err := d.mutateRecord(ctx, caller.OwnerID, binding.ID, func(record *bindingRecord) (bool, error) {
					record.Active = copyProofRecord(exp)
					record.Pending = nil
					return true, nil
				}); err != nil {
					return certificates.Deployment{State: "unknown", Healthy: false}, err
				}
				return certificates.Deployment{
					State:            "rolled_back",
					ActiveGeneration: exp.Proof.Binding.Generation,
					Healthy:          true,
				}, nil
			}
			return certificates.Deployment{State: "unknown", Healthy: false}, nil
		}
		if rec.Pending.TargetProof != nil && diskCur != nil && *diskCur == rec.Pending.TargetProof.Proof {
			return d.rollbackActivated(ctx, caller.OwnerID, binding, rec.Pending.TargetProof, exp)
		}
		return certificates.Deployment{State: "unknown", Healthy: false}, nil
	}

	// 首次部署对账（Expected == nil）
	if diskCur == nil {
		obs, inspectErr := d.runtime.Inspect(ctx, binding.Consumer, binding.ID)
		if inspectErr != nil || (obs.Running && obs.ActiveGeneration != 0) {
			return certificates.Deployment{State: "unknown", Healthy: false}, nil
		}
		if _, err := d.files.Remove(ctx, binding.Consumer.PluginID, binding.ID); err != nil {
			return certificates.Deployment{State: "unknown", Healthy: false}, err
		}
		if err := d.mutateRecord(ctx, caller.OwnerID, binding.ID, func(record *bindingRecord) (bool, error) {
			record.Pending = nil
			return record.Active != nil || record.Previous != nil, nil
		}); err != nil {
			return certificates.Deployment{State: "unknown", Healthy: false}, err
		}
		return certificates.Deployment{
			State:            "rolled_back",
			ActiveGeneration: 0,
			Healthy:          false,
		}, nil
	}
	if rec.Pending.TargetProof != nil && *diskCur == rec.Pending.TargetProof.Proof {
		return d.rollbackActivated(ctx, caller.OwnerID, binding, rec.Pending.TargetProof, nil)
	}
	return certificates.Deployment{State: "unknown", Healthy: false}, nil
}

// Remove 先经宿主解绑授权与运行时占用核验，再清理消费者私有文件并删除账本记录。
func (d *Deployer) Remove(ctx context.Context, caller certificates.Caller, binding certificates.HostBinding) error {
	if ctx == nil {
		return fault.New("VALIDATION_FAILED", "移除消费者证书绑定需要有效的 context")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if !names.ID(caller.OwnerID) || !names.ID(binding.ID) || !names.ID(binding.CertificateID) {
		return fault.New("VALIDATION_FAILED", "移除消费者证书绑定需要有效的属主与绑定标识")
	}
	if _, err := certificates.CanonicalConsumer(binding.Consumer); err != nil {
		return err
	}
	if err := d.authority.AuthorizeConsumerRemoval(ctx, caller, binding); err != nil {
		return err
	}

	unlock, err := d.acquireRemoval(ctx)
	if err != nil {
		return err
	}
	defer unlock()

	inUse, err := d.runtime.InUse(ctx, binding)
	if err != nil {
		return err
	}
	if inUse {
		return fault.New("RESOURCE_IN_USE", "消费者仍在使用该证书绑定")
	}
	if _, err := d.files.Remove(ctx, binding.Consumer.PluginID, binding.ID); err != nil {
		return err
	}
	return d.mutateRecord(ctx, caller.OwnerID, binding.ID, func(*bindingRecord) (bool, error) {
		return false, nil
	})
}

func proofPtrOf(record *proofRecord) *consumerfiles.Proof {
	if record == nil {
		return nil
	}
	proof := record.Proof
	return &proof
}

func sameConsumerProofPtr(a, b *consumerfiles.Proof) bool {
	return (a == nil && b == nil) || (a != nil && b != nil && *a == *b)
}
