// SPDX-License-Identifier: AGPL-3.0-only

package operations

import (
	"context"
	"testing"
	"time"
)

// ======================== 初始 Source 与记录清理共用原剩余预算 ========================

func TestCleanupSourceContextKeepsTheEarliestWindowAndParentDeadline(t *testing.T) {
	f := newCleanupAuthorityFixture(t, "human", true)
	e := f.env
	source := f.source
	source.DNSAttemptID = ""
	first, cancelFirst, err := e.svc.CleanupSourceContext(e.ctx, f.accepted(t), source, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer cancelFirst()
	if deadline, found := first.Deadline(); !found || time.Until(deadline) > 5*time.Second {
		t.Fatal("初始 Source 没有同窗硬期限")
	}
	e.clock.Advance(2 * time.Second)
	second, cancelSecond, err := e.svc.CleanupSourceContext(e.ctx, f.accepted(t), source, 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer cancelSecond()
	if deadline, found := second.Deadline(); !found || time.Until(deadline) > 3*time.Second {
		t.Fatal("重复 Source 重新延长了窗口")
	}
	parent, cancelParent := context.WithTimeout(e.ctx, time.Second)
	defer cancelParent()
	child, cancelChild, err := e.svc.CleanupSourceContext(parent, f.accepted(t), source, 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer cancelChild()
	parentDeadline, _ := parent.Deadline()
	childDeadline, _ := child.Deadline()
	if childDeadline.After(parentDeadline) {
		t.Fatal("Source 忽略了传入的更早期限")
	}
	e.clock.Advance(4 * time.Second)
	if _, cancel, err := e.svc.CleanupSourceContext(e.ctx, f.accepted(t), source, 30*time.Second); err == nil {
		cancel()
		t.Fatal("Source 窗口耗尽后仍可构造读取 context")
	}
}

func TestCleanupSourceContextRejectsOriginalExecutorExit(t *testing.T) {
	f := newCleanupAuthorityFixture(t, "human", true)
	e := f.env
	snapshot := f.accepted(t)
	f.job.finish()
	select {
	case <-snapshot.runtimeProof.job.done:
	case <-time.After(5 * time.Second):
		t.Fatal("原 executor 未退出")
	}
	if _, cancel, err := e.svc.CleanupSourceContext(e.ctx, snapshot, f.source, 30*time.Second); err == nil {
		cancel()
		t.Fatal("原 executor 结束后仍提供 Source context")
	}
}
