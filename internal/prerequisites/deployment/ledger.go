// SPDX-License-Identifier: AGPL-3.0-only

package deployment

import (
	"context"
	"errors"
	"sync"

	"github.com/qwq-panel/qwq/internal/prerequisites/certificates"
	"github.com/qwq-panel/qwq/internal/prerequisites/fault"
	"github.com/qwq-panel/qwq/internal/prerequisites/names"
	"github.com/qwq-panel/qwq/internal/prerequisites/store"
)

// ======================== 宿主部署账本键与值拷贝辅助 ========================

const (
	ledgerVersion     = 1
	maxReferenceCount = 256
)

func deploymentLedgerKey(ownerID string) string {
	return "certificates/deployments/" + ownerID
}

func copyProofRecord(in *proofRecord) *proofRecord {
	if in == nil {
		return nil
	}
	copied := *in
	return &copied
}

func sameProofRecord(a, b *proofRecord) bool {
	return (a == nil && b == nil) || (a != nil && b != nil && *a == *b)
}

func ledgerCopyPending(in *pendingDeployment) *pendingDeployment {
	if in == nil {
		return nil
	}
	copied := *in
	copied.TargetProof = copyProofRecord(in.TargetProof)
	copied.Expected = copyProofRecord(in.Expected)
	return &copied
}

func ledgerCopyRecord(in bindingRecord) bindingRecord {
	return bindingRecord{
		ID:       in.ID,
		Active:   copyProofRecord(in.Active),
		Previous: copyProofRecord(in.Previous),
		Pending:  ledgerCopyPending(in.Pending),
	}
}

func ledgerCheckContext(ctx context.Context) error {
	if ctx == nil {
		return fault.New("VALIDATION_FAILED", "部署操作需要明确的 context")
	}
	if err := ctx.Err(); err != nil {
		return errors.Join(fault.New("CANCELLED", "部署操作已取消"), err)
	}
	return nil
}

func (d *Deployer) ledgerRecordLimit() int {
	if d.maxRecords <= 0 || d.maxRecords > maxReferenceCount {
		return maxReferenceCount
	}
	return d.maxRecords
}

// ======================== 删除串行锁与严格锁序保护 ========================

func (d *Deployer) acquireRemoval(ctx context.Context) (func(), error) {
	if err := ledgerCheckContext(ctx); err != nil {
		return nil, err
	}
	if d == nil || d.removalGate == nil {
		return nil, fault.New("BACKEND_REQUIRED", "部署删除串行锁未初始化")
	}
	select {
	case d.removalGate <- struct{}{}:
	case <-ctx.Done():
		return nil, ledgerCheckContext(ctx)
	}
	// 防止 ctx 已取消但 channel 空闲时 select 随机命中发送分支。
	if err := ctx.Err(); err != nil {
		<-d.removalGate
		return nil, ledgerCheckContext(ctx)
	}
	var once sync.Once
	return func() {
		once.Do(func() { <-d.removalGate })
	}, nil
}

// LockForRemoval 串行化证书或代删除前的引用核查与清理，防止并发部署新增消费引用。
// generation == 0 表示整份证书删除，属于合法参数。
func (d *Deployer) LockForRemoval(ctx context.Context, caller certificates.Caller, certificateID string, generation uint64) (func(), error) {
	if err := ledgerCheckContext(ctx); err != nil {
		return nil, err
	}
	if !names.ID(caller.OwnerID) || !names.ID(certificateID) {
		return nil, fault.New("VALIDATION_FAILED", "删除锁需要有效的 owner 与证书标识")
	}
	return d.acquireRemoval(ctx)
}

// ======================== 乐观并发部署账本读写 ========================

// loadLedgerLocked 必须在已持有 d.ledgerMu 时调用。
func (d *Deployer) loadLedgerLocked(ctx context.Context, ownerID string) (deploymentLedger, string, error) {
	if err := ledgerCheckContext(ctx); err != nil {
		return deploymentLedger{}, "", err
	}
	if !names.ID(ownerID) {
		return deploymentLedger{}, "", fault.New("VALIDATION_FAILED", "部署账本需要有效的 owner 标识")
	}
	if d == nil || d.repository == nil {
		return deploymentLedger{}, "", fault.New("BACKEND_REQUIRED", "部署账本存储后端未配置")
	}
	var ledger deploymentLedger
	revision, found, err := store.Load(ctx, d.repository, deploymentLedgerKey(ownerID), &ledger)
	if err != nil {
		return deploymentLedger{}, "", err
	}
	if !found {
		return deploymentLedger{Version: ledgerVersion}, "", nil
	}
	if ledger.Version != ledgerVersion || len(ledger.Records) > d.ledgerRecordLimit() {
		return deploymentLedger{}, "", fault.New("STATE_INVALID", "部署账本版本无效或记录数超过上限")
	}
	return ledger, revision, nil
}

// saveLedgerLocked 必须在已持有 d.ledgerMu 时调用。
func (d *Deployer) saveLedgerLocked(ctx context.Context, ownerID, revision string, ledger deploymentLedger) (string, error) {
	if err := ledgerCheckContext(ctx); err != nil {
		return "", err
	}
	if !names.ID(ownerID) {
		return "", fault.New("VALIDATION_FAILED", "部署账本需要有效的 owner 标识")
	}
	if d == nil || d.repository == nil {
		return "", fault.New("BACKEND_REQUIRED", "部署账本存储后端未配置")
	}
	if len(ledger.Records) > d.ledgerRecordLimit() {
		return "", fault.New("RESOURCE_EXHAUSTED", "部署账本记录数超过上限")
	}
	ledger.Version = ledgerVersion
	return store.Save(ctx, d.repository, deploymentLedgerKey(ownerID), revision, ledger)
}

func (d *Deployer) mutateRecord(ctx context.Context, ownerID, bindingID string, fn func(*bindingRecord) (keep bool, err error)) error {
	if err := ledgerCheckContext(ctx); err != nil {
		return err
	}
	if !names.ID(ownerID) || !names.ID(bindingID) || fn == nil {
		return fault.New("VALIDATION_FAILED", "部署账本更新需要有效的 owner、绑定标识与更新函数")
	}
	if d == nil || d.repository == nil {
		return fault.New("BACKEND_REQUIRED", "部署账本存储后端未配置")
	}
	d.ledgerMu.Lock()
	defer d.ledgerMu.Unlock()
	ledger, revision, err := d.loadLedgerLocked(ctx, ownerID)
	if err != nil {
		return err
	}
	index := -1
	for i := range ledger.Records {
		if ledger.Records[i].ID == bindingID {
			index = i
			break
		}
	}
	var record bindingRecord
	if index >= 0 {
		record = ledgerCopyRecord(ledger.Records[index])
	} else {
		record = bindingRecord{ID: bindingID}
	}
	keep, err := fn(&record)
	if err != nil {
		return err
	}
	if keep {
		record.ID = bindingID
		if index >= 0 {
			ledger.Records[index] = record
		} else {
			if len(ledger.Records) >= d.ledgerRecordLimit() {
				return fault.New("RESOURCE_EXHAUSTED", "部署账本记录数超过上限")
			}
			ledger.Records = append(ledger.Records, record)
		}
	} else if index >= 0 {
		ledger.Records = append(ledger.Records[:index], ledger.Records[index+1:]...)
	} else {
		return nil
	}
	_, err = d.saveLedgerLocked(ctx, ownerID, revision, ledger)
	return err
}

func (d *Deployer) readRecord(ctx context.Context, ownerID, bindingID string) (bindingRecord, bool, error) {
	if err := ledgerCheckContext(ctx); err != nil {
		return bindingRecord{}, false, err
	}
	if !names.ID(ownerID) || !names.ID(bindingID) {
		return bindingRecord{}, false, fault.New("VALIDATION_FAILED", "部署账本查询需要有效的 owner 与绑定标识")
	}
	if d == nil || d.repository == nil {
		return bindingRecord{}, false, fault.New("BACKEND_REQUIRED", "部署账本存储后端未配置")
	}
	d.ledgerMu.Lock()
	defer d.ledgerMu.Unlock()
	ledger, _, err := d.loadLedgerLocked(ctx, ownerID)
	if err != nil {
		return bindingRecord{}, false, err
	}
	for i := range ledger.Records {
		if ledger.Records[i].ID == bindingID {
			return ledgerCopyRecord(ledger.Records[i]), true, nil
		}
	}
	return bindingRecord{}, false, nil
}

// ======================== 宿主引用快照查询（绝不获取 removalGate） ========================

// References 返回指定证书在宿主账本中仍被引用的全部 current/previous/pending 快照。
// 仅获取 ledgerMu、绝不获取 removalGate，避免 certificates.Manager 持锁查询时死锁。
func (d *Deployer) References(ctx context.Context, caller certificates.Caller, certificateID string) ([]certificates.Reference, error) {
	if err := ledgerCheckContext(ctx); err != nil {
		return nil, err
	}
	if !names.ID(caller.OwnerID) || !names.ID(certificateID) {
		return nil, fault.New("VALIDATION_FAILED", "引用查询需要有效的 owner 与证书标识")
	}
	if d == nil || d.repository == nil {
		return nil, fault.New("BACKEND_REQUIRED", "部署账本存储后端未配置")
	}
	d.ledgerMu.Lock()
	defer d.ledgerMu.Unlock()
	ledger, _, err := d.loadLedgerLocked(ctx, caller.OwnerID)
	if err != nil {
		return nil, err
	}
	var references []certificates.Reference
	seen := make(map[certificates.Reference]struct{})
	appendRef := func(binding certificates.HostBinding, kind string) error {
		if binding.CertificateID != certificateID {
			return nil
		}
		if binding.Generation == 0 {
			return fault.New("STATE_INVALID", "部署账本记录缺少有效 generation")
		}
		consumer, err := certificates.CanonicalConsumer(binding.Consumer)
		if err != nil {
			return fault.New("STATE_INVALID", "部署账本记录包含无效消费者身份")
		}
		ref := certificates.Reference{
			Generation: binding.Generation,
			Consumer:   consumer,
			Kind:       kind,
		}
		if _, duplicate := seen[ref]; duplicate {
			return nil
		}
		if len(references) >= maxReferenceCount {
			return fault.New("RESOURCE_EXHAUSTED", "宿主证书引用集合超过上限")
		}
		seen[ref] = struct{}{}
		references = append(references, ref)
		return nil
	}
	for _, rec := range ledger.Records {
		if rec.Active != nil {
			if err := appendRef(rec.Active.Proof.Binding, "current"); err != nil {
				return nil, err
			}
		}
		if rec.Previous != nil {
			if err := appendRef(rec.Previous.Proof.Binding, "previous"); err != nil {
				return nil, err
			}
		}
		if rec.Pending != nil {
			if err := appendRef(rec.Pending.Target, "pending"); err != nil {
				return nil, err
			}
			if rec.Pending.TargetProof != nil {
				if err := appendRef(rec.Pending.TargetProof.Proof.Binding, "pending"); err != nil {
					return nil, err
				}
			}
			if rec.Pending.Expected != nil {
				if err := appendRef(rec.Pending.Expected.Proof.Binding, "pending"); err != nil {
					return nil, err
				}
			}
		}
	}
	return references, nil
}
