// SPDX-License-Identifier: AGPL-3.0-only

package hostauth

import (
	"context"
	"testing"
	"time"

	"github.com/qwq-panel/qwq/internal/platform/ids"
	"github.com/qwq-panel/qwq/internal/storage"
)

// ======================== 初次预留不依赖尚未存在的消费者配置 ========================

func TestHostBindingReservationPrecedesRealConfigurationAndIsStable(t *testing.T) {
	f := newReservationFixture(t)
	first := f.reserve(t)
	if !ids.Valid(first.BindingRef, "certbind") || first.CertificateID != fixtureCertificate || first.Consumer != f.want || first.Status != "reserved" {
		t.Fatal("预留没有生成受控、精确且非ready的稳定绑定")
	}
	second := f.reserve(t)
	if second != first || f.source.calls != 2 || f.source.origin != f.call.invocation || f.source.deadline.IsZero() {
		t.Fatal("预留重复调用更换了ID，或缓存了原operation/来源许可")
	}
	if err := f.f.authority.ValidateConsumerConfiguration(f.f.ctx, f.f.human, "local", "core.xray", "0", []ConsumerConfiguration{{BindingRef: first.BindingRef, Consumer: f.want}}); err != nil {
		t.Fatalf("没有已有配置时不能先校验预留引用：%v", err)
	}
	if f.f.authority.consumers != nil {
		t.Fatal("预留测试伪造了实际消费者配置")
	}
}

func TestHostBindingReservationRejectsChangedOriginalAndSource(t *testing.T) {
	f := newReservationFixture(t)
	authority := f.f.authority
	if _, err := authority.ReserveBinding(f.call.ctx, "other-certificate", stringsDigest('a')); err == nil {
		t.Fatal("RPC更换certificate获得了预留")
	}
	if _, err := authority.ReserveBinding(f.call.ctx, fixtureCertificate, stringsDigest('b')); err == nil {
		t.Fatal("RPC更换原expected_revision获得了预留")
	}
	authority.reservations = nil
	if _, err := authority.ReserveBinding(f.call.ctx, fixtureCertificate, stringsDigest('a')); err == nil {
		t.Fatal("缺少真实授权source仍可预留")
	}
	authority.reservations = f.source
	initial := f.source.facts
	for _, change := range []func(*ConsumerReservationFacts){
		func(v *ConsumerReservationFacts) { v.Consumer.NodeID = "other-node" },
		func(v *ConsumerReservationFacts) { v.Consumer.ProfileID = "other-profile" },
		func(v *ConsumerReservationFacts) { v.Consumer.SNI = "other.example.test" },
		func(v *ConsumerReservationFacts) { v.ConfigRevision = "1" },
		func(v *ConsumerReservationFacts) { v.PluginVersion = "bad\nversion" },
	} {
		f.source.facts = initial
		change(&f.source.facts)
		if _, err := authority.ReserveBinding(f.call.ctx, fixtureCertificate, stringsDigest('a')); err == nil {
			t.Fatal("替换的来源事实被接受为原预留许可")
		}
	}
}

func TestHostBindingReservationRechecksReleaseAndActorAndEarlierDeadline(t *testing.T) {
	for _, failure := range []string{"release", "actor", "deadline"} {
		t.Run(failure, func(t *testing.T) {
			f := newReservationFixture(t)
			ctx := f.call.ctx
			if failure == "release" {
				f.source.before = func(context.Context) { f.call.release() }
			}
			if failure == "actor" {
				f.source.before = func(context.Context) {
					if err := f.f.db.Update(f.f.ctx, func(tx *storage.Tx) error {
						_, err := tx.ExecContext(f.f.ctx, "UPDATE users SET disabled=1, revision=revision+1 WHERE user_id=?", f.f.human.ID)
						return err
					}); err != nil {
						t.Fatal(err)
					}
				}
			}
			if failure == "deadline" {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, 50*time.Millisecond)
				defer cancel()
				f.source.before = func(ctx context.Context) { <-ctx.Done() }
			}
			deadline, _ := ctx.Deadline()
			if _, err := f.f.authority.ReserveBinding(ctx, fixtureCertificate, stringsDigest('a')); err == nil {
				t.Fatal("读取source期间失效仍保存了预留")
			}
			if failure == "deadline" {
				// race下前置身份/KV读取可能先耗尽期限；提前拒绝同样正确。
				if ctx.Err() != context.DeadlineExceeded || f.source.calls > 1 || (f.source.calls == 1 && !f.source.deadline.Equal(deadline)) {
					t.Fatal("到期路径没有拒绝，或source重新延长了原预算")
				}
				state, _, err := f.f.authority.loadBindingLedger(f.f.ctx)
				if err != nil || len(state.Entries) != 0 {
					t.Fatal("前置或source阶段到期后仍提交了私有预留")
				}
				return
			}
			if f.source.calls != 1 || f.source.deadline.IsZero() {
				t.Fatal("预留source没有取得真实有界context")
			}
		})
	}
}
