// SPDX-License-Identifier: AGPL-3.0-only

package deployment

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/qwq-panel/qwq/internal/prerequisites/certificates"
	"github.com/qwq-panel/qwq/internal/prerequisites/consumerfiles"
	"github.com/qwq-panel/qwq/internal/prerequisites/fault"
	"github.com/qwq-panel/qwq/internal/prerequisites/testsupport"
)

// ======================== 部署账本测试夹具 ========================

func ledgerTestDeployer(maxRecords int) (*Deployer, *testsupport.MemoryStore) {
	repo := &testsupport.MemoryStore{}
	return &Deployer{
		repository:  repo,
		maxRecords:  maxRecords,
		removalGate: make(chan struct{}, 1),
	}, repo
}

func ledgerTestCaller() certificates.Caller {
	return certificates.Caller{
		OwnerID:     "owner-a",
		OperationID: "op-1",
	}
}

func ledgerTestConsumer(sni string) certificates.Consumer {
	return certificates.Consumer{
		PluginID:  "core.xray",
		ProfileID: "profile-a",
		NodeID:    "node-1",
		SNI:       sni,
		Purpose:   "proxy.hysteria2",
		Test:      true,
	}
}

func ledgerTestProofRecord(bindingID, certID string, gen uint64, sni string) *proofRecord {
	return &proofRecord{
		Proof: consumerfiles.Proof{
			Binding: certificates.HostBinding{
				ID:             bindingID,
				CertificateID:  certID,
				Generation:     gen,
				Consumer:       ledgerTestConsumer(sni),
				PolicyRevision: "policy-r1",
			},
			FullchainSHA256:  strings.Repeat("a", 64),
			PrivateKeySHA256: strings.Repeat("b", 64),
		},
		LeafFingerprint: strings.Repeat("c", 64),
	}
}

func ledgerRequireCode(t *testing.T, err error, want string) {
	t.Helper()
	if err == nil || fault.Code(err) != want {
		t.Fatalf("错误码=%s，期望=%s；err=%v", fault.Code(err), want, err)
	}
}

// ======================== 删除锁与引用查询无死锁及并发验证 ========================

func TestLedgerLockForRemovalAndReferencesDoNotDeadlock(t *testing.T) {
	deployer, _ := ledgerTestDeployer(16)
	caller := ledgerTestCaller()

	if err := deployer.mutateRecord(context.Background(), caller.OwnerID, "binding-1", func(rec *bindingRecord) (bool, error) {
		rec.Active = ledgerTestProofRecord("binding-1", "cert-a", 2, "a.example")
		return true, nil
	}); err != nil {
		t.Fatal(err)
	}

	// generation == 0（整份证书删除）与 generation > 0 均须放行且持锁调用 References 不死锁。
	for _, gen := range []uint64{0, 2} {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		unlock, err := deployer.LockForRemoval(ctx, caller, "cert-a", gen)
		if err != nil {
			cancel()
			t.Fatalf("LockForRemoval(gen=%d) 失败：%v", gen, err)
		}
		refs, err := deployer.References(ctx, caller, "cert-a")
		unlock()
		cancel()
		if err != nil {
			t.Fatalf("持锁调用 References(gen=%d) 失败：%v", gen, err)
		}
		if len(refs) != 1 || refs[0].Generation != 2 || refs[0].Kind != "current" {
			t.Fatalf("持锁查询引用结果不符：%+v", refs)
		}
	}
}

func TestLedgerLockForRemovalSerializesIdempotentUnlockAndRespectsContext(t *testing.T) {
	deployer, _ := ledgerTestDeployer(16)
	caller := ledgerTestCaller()

	// 非法参数与预取消 context 拒绝。
	_, err := deployer.LockForRemoval(context.Background(), certificates.Caller{OwnerID: ""}, "cert-a", 0)
	ledgerRequireCode(t, err, "VALIDATION_FAILED")
	_, err = deployer.LockForRemoval(context.Background(), caller, "../bad", 1)
	ledgerRequireCode(t, err, "VALIDATION_FAILED")

	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = deployer.LockForRemoval(cancelled, caller, "cert-a", 1)
	ledgerRequireCode(t, err, "CANCELLED")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("期望保留 context.Canceled：%v", err)
	}

	// 持锁阻塞竞争方，超时返回 CANCELLED。
	unlockFirst, err := deployer.LockForRemoval(context.Background(), caller, "cert-a", 0)
	if err != nil {
		t.Fatal(err)
	}
	bounded, stop := context.WithTimeout(context.Background(), 40*time.Millisecond)
	defer stop()
	_, err = deployer.LockForRemoval(bounded, caller, "cert-a", 1)
	ledgerRequireCode(t, err, "CANCELLED")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("期望保留 context.DeadlineExceeded：%v", err)
	}

	// 并发等待方在首次 unlock 后立即获得锁；重复调用 unlock 幂等且不干扰新持锁者。
	acquired := make(chan func(), 1)
	waitErr := make(chan error, 1)
	go func() {
		unlockSecond, err := deployer.LockForRemoval(context.Background(), caller, "cert-a", 2)
		if err != nil {
			waitErr <- err
			return
		}
		acquired <- unlockSecond
	}()

	time.Sleep(20 * time.Millisecond)
	select {
	case <-acquired:
		t.Fatal("首锁未释放前竞争方不应获得锁")
	default:
	}

	unlockFirst()
	var unlockSecond func()
	select {
	case err := <-waitErr:
		t.Fatalf("等待方获取锁失败：%v", err)
	case unlockSecond = <-acquired:
	case <-time.After(time.Second):
		t.Fatal("首锁释放后等待方未能及时获得锁")
	}

	// 再次调用第一个 unlock 必须为 no-op，不能错误释放第二个持锁者的闸门。
	unlockFirst()
	stillBlocked, stop2 := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer stop2()
	_, err = deployer.LockForRemoval(stillBlocked, caller, "cert-a", 3)
	ledgerRequireCode(t, err, "CANCELLED")

	unlockSecond()
	unlockSecond()
}

// ======================== 引用聚合、过滤、去重与损坏账本拒绝 ========================

func TestLedgerReferencesCollectsFiltersDeduplicatesAndRejectsCorruptLedger(t *testing.T) {
	deployer, repo := ledgerTestDeployer(16)
	caller := ledgerTestCaller()

	// binding-1: current(cert-a, g2), previous(cert-a, g1), pending(target=g3, targetProof=g3 去重, expected=g2)。
	if err := deployer.mutateRecord(context.Background(), caller.OwnerID, "binding-1", func(rec *bindingRecord) (bool, error) {
		rec.Active = ledgerTestProofRecord("binding-1", "cert-a", 2, "a.example")
		rec.Previous = ledgerTestProofRecord("binding-1", "cert-a", 1, "a.example")
		targetProof := ledgerTestProofRecord("binding-1", "cert-a", 3, "a.example")
		rec.Pending = &pendingDeployment{
			Target:      targetProof.Proof.Binding,
			TargetProof: targetProof,
			Expected:    ledgerTestProofRecord("binding-1", "cert-a", 2, "a.example"),
			Phase:       "activating",
			UpdatedAt:   time.Now().UTC(),
		}
		return true, nil
	}); err != nil {
		t.Fatal(err)
	}

	// binding-2: 与 binding-1 重复的 current(cert-a, g2, a.example)，以及无关证书 cert-b 的 previous。
	if err := deployer.mutateRecord(context.Background(), caller.OwnerID, "binding-2", func(rec *bindingRecord) (bool, error) {
		rec.Active = ledgerTestProofRecord("binding-2", "cert-a", 2, "a.example")
		rec.Previous = ledgerTestProofRecord("binding-2", "cert-b", 5, "b.example")
		return true, nil
	}); err != nil {
		t.Fatal(err)
	}

	// binding-3: 不同消费者 SNI 的 active(cert-a, g4)，pending 切换目标为 cert-b 但 expected 仍引用 cert-a g4。
	if err := deployer.mutateRecord(context.Background(), caller.OwnerID, "binding-3", func(rec *bindingRecord) (bool, error) {
		rec.Active = ledgerTestProofRecord("binding-3", "cert-a", 4, "c.example")
		rec.Pending = &pendingDeployment{
			Target:   ledgerTestProofRecord("binding-3", "cert-b", 1, "c.example").Proof.Binding,
			Expected: ledgerTestProofRecord("binding-3", "cert-a", 4, "c.example"),
			Phase:    "staging",
		}
		return true, nil
	}); err != nil {
		t.Fatal(err)
	}

	refs, err := deployer.References(context.Background(), caller, "cert-a")
	if err != nil {
		t.Fatalf("References(cert-a) 失败：%v", err)
	}
	want := map[certificates.Reference]bool{
		{Generation: 2, Consumer: ledgerTestConsumer("a.example"), Kind: "current"}:  true,
		{Generation: 1, Consumer: ledgerTestConsumer("a.example"), Kind: "previous"}: true,
		{Generation: 3, Consumer: ledgerTestConsumer("a.example"), Kind: "pending"}:  true,
		{Generation: 2, Consumer: ledgerTestConsumer("a.example"), Kind: "pending"}:  true,
		{Generation: 4, Consumer: ledgerTestConsumer("c.example"), Kind: "current"}:  true,
		{Generation: 4, Consumer: ledgerTestConsumer("c.example"), Kind: "pending"}:  true,
	}
	if len(refs) != len(want) {
		t.Fatalf("cert-a 引用去重数量=%d，期望=%d；refs=%+v", len(refs), len(want), refs)
	}
	for _, ref := range refs {
		if !want[ref] {
			t.Fatalf("出现非预期引用：%+v", ref)
		}
	}

	refsB, err := deployer.References(context.Background(), caller, "cert-b")
	if err != nil {
		t.Fatalf("References(cert-b) 失败：%v", err)
	}
	if len(refsB) != 2 {
		t.Fatalf("cert-b 引用数量=%d，期望=2；refs=%+v", len(refsB), refsB)
	}

	// 损坏账本版本号必须被明确拒绝。
	entry, found, err := repo.Get(context.Background(), deploymentLedgerKey(caller.OwnerID))
	if err != nil || !found {
		t.Fatalf("读取底层账本条目失败：%v found=%v", err, found)
	}
	if _, err := repo.Put(context.Background(), deploymentLedgerKey(caller.OwnerID), entry.Revision, []byte(`{"version":99,"records":[]}`)); err != nil {
		t.Fatal(err)
	}
	_, err = deployer.References(context.Background(), caller, "cert-a")
	ledgerRequireCode(t, err, "STATE_INVALID")
}

// ======================== 账本增删改、记录上限与敏感字段脱敏 ========================

func TestLedgerMutateRecordCRUDMaxRecordsAndProofRedaction(t *testing.T) {
	deployer, _ := ledgerTestDeployer(2)
	owner := "owner-a"

	// 不存在的记录读取返回 found=false，且非保留变更不产生错误。
	if _, found, err := deployer.readRecord(context.Background(), owner, "binding-1"); err != nil || found {
		t.Fatalf("空账本 readRecord 应返回 found=false：found=%v err=%v", found, err)
	}
	if err := deployer.mutateRecord(context.Background(), owner, "binding-missing", func(*bindingRecord) (bool, error) {
		return false, nil
	}); err != nil {
		t.Fatalf("删除不存在记录应幂等：%v", err)
	}

	// 创建并验证 readRecord 返回深拷贝。
	p1 := ledgerTestProofRecord("binding-1", "cert-a", 1, "a.example")
	if err := deployer.mutateRecord(context.Background(), owner, "binding-1", func(rec *bindingRecord) (bool, error) {
		rec.Active = copyProofRecord(p1)
		return true, nil
	}); err != nil {
		t.Fatal(err)
	}
	got, found, err := deployer.readRecord(context.Background(), owner, "binding-1")
	if err != nil || !found || !sameProofRecord(got.Active, p1) {
		t.Fatalf("读取新建记录失败：found=%v err=%v", found, err)
	}
	got.Active.LeafFingerprint = "mutated-by-caller"
	again, _, err := deployer.readRecord(context.Background(), owner, "binding-1")
	if err != nil || !sameProofRecord(again.Active, p1) {
		t.Fatal("readRecord 未隔离内部指针导致调用方污染账本")
	}

	// 回调函数返回错误时不落盘。
	sentinelErr := fault.New("TEST_ABORT", "中止写入")
	err = deployer.mutateRecord(context.Background(), owner, "binding-1", func(rec *bindingRecord) (bool, error) {
		rec.Active = ledgerTestProofRecord("binding-1", "cert-a", 9, "a.example")
		return true, sentinelErr
	})
	ledgerRequireCode(t, err, "TEST_ABORT")
	again, _, err = deployer.readRecord(context.Background(), owner, "binding-1")
	if err != nil || !sameProofRecord(again.Active, p1) {
		t.Fatal("回调失败后账本被意外修改")
	}

	// 创建第二条记录达到上限 2；更新已有记录允许，新增第三条记录返回 RESOURCE_EXHAUSTED。
	p2 := ledgerTestProofRecord("binding-2", "cert-a", 2, "b.example")
	if err := deployer.mutateRecord(context.Background(), owner, "binding-2", func(rec *bindingRecord) (bool, error) {
		rec.Active = copyProofRecord(p2)
		return true, nil
	}); err != nil {
		t.Fatal(err)
	}
	p1Updated := ledgerTestProofRecord("binding-1", "cert-a", 3, "a.example")
	if err := deployer.mutateRecord(context.Background(), owner, "binding-1", func(rec *bindingRecord) (bool, error) {
		rec.Previous = copyProofRecord(rec.Active)
		rec.Active = copyProofRecord(p1Updated)
		return true, nil
	}); err != nil {
		t.Fatalf("满上限时更新已有记录应成功：%v", err)
	}
	err = deployer.mutateRecord(context.Background(), owner, "binding-3", func(rec *bindingRecord) (bool, error) {
		rec.Active = ledgerTestProofRecord("binding-3", "cert-a", 4, "c.example")
		return true, nil
	})
	ledgerRequireCode(t, err, "RESOURCE_EXHAUSTED")

	// 删除 binding-1 后可正常删除并腾出名额。
	if err := deployer.mutateRecord(context.Background(), owner, "binding-1", func(*bindingRecord) (bool, error) {
		return false, nil
	}); err != nil {
		t.Fatalf("删除已有记录失败：%v", err)
	}
	if _, found, err := deployer.readRecord(context.Background(), owner, "binding-1"); err != nil || found {
		t.Fatalf("已删除记录仍存在：found=%v err=%v", found, err)
	}

	// proofRecord 格式化输出必须脱敏，不得泄露私钥摘要或证书指纹。
	formatted := fmt.Sprintf("%v %#v", *p1, *p1)
	if !strings.Contains(formatted, "[REDACTED]") ||
		strings.Contains(formatted, p1.Proof.PrivateKeySHA256) ||
		strings.Contains(formatted, p1.Proof.FullchainSHA256) ||
		strings.Contains(formatted, p1.LeafFingerprint) {
		t.Fatalf("proofRecord 脱敏失败：%s", formatted)
	}
	if !sameProofRecord(nil, nil) || sameProofRecord(p1, nil) || sameProofRecord(nil, p1) || sameProofRecord(p1, p2) {
		t.Fatal("sameProofRecord 比较语义错误")
	}
}
