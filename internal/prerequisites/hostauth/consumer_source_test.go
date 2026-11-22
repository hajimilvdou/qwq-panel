// SPDX-License-Identifier: AGPL-3.0-only

package hostauth

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/qwq-panel/qwq/internal/prerequisites/certificates"
	"github.com/qwq-panel/qwq/internal/storage"
)

// ======================== 明确事实 fixture，身份与 operation 保持真实 ========================

type consumerSourceFixture struct {
	facts    ConsumerFacts
	calls    int
	before   func()
	deadline time.Time
}

func (s *consumerSourceFixture) CurrentConsumer(ctx context.Context, _ Invocation, _ certificates.Consumer) (ConsumerFacts, error) {
	s.calls++
	s.deadline, _ = ctx.Deadline()
	if s.before != nil {
		s.before()
	}
	return s.facts, nil
}

func TestHostConsumerSourceReadsActualFactsOnEveryRequest(t *testing.T) {
	f, call, want, source := consumerSourceRequestFixture(t)
	first, err := f.authority.CurrentConsumer(call.ctx, want)
	if err != nil || first != source.facts || source.calls != 1 {
		t.Fatalf("没有读取真实消费方事实：%v", err)
	}
	source.facts.ConfigRevision = "2"
	second, err := f.authority.CurrentConsumer(call.ctx, want)
	if err != nil || second.ConfigRevision != "2" || source.calls != 2 {
		t.Fatal("消费方事实被缓存为永久权限")
	}
}

func TestHostConsumerSourceDoesNotTrustTheRequestedTestFlag(t *testing.T) {
	f, call, want, _ := consumerSourceRequestFixture(t)
	want.Test = true
	facts, err := f.authority.CurrentConsumer(call.ctx, want)
	if err != nil || facts.Consumer.Test {
		t.Fatalf("请求布尔值扩大了消费方的测试信任：%v", err)
	}
}

func consumerSourceRequestFixture(t *testing.T) (*authorityFixture, *fixtureCall, certificates.Consumer, *consumerSourceFixture) {
	t.Helper()
	f := newAuthorityFixture(t)
	call := f.start(t, f.human, "tls.certificates", "bindings.bind", certificateSubject(fixtureCertificate), "absent", map[string]string{"certificate_id": fixtureCertificate})
	want := certificates.Consumer{PluginID: "core.xray", ProfileID: "h2-one", NodeID: "local", SNI: "proxy.example.test", Purpose: "proxy.hysteria2"}
	source := &consumerSourceFixture{facts: ConsumerFacts{Consumer: want, ConfigRevision: "1", PluginVersion: "0.1.0+build", BindingRef: "certbind_00000000000000000000000000"}}
	f.authority.consumers = source
	return f, call, want, source
}

func TestHostConsumerSourceRejectsMissingAndInvalidFacts(t *testing.T) {
	f, call, want, source := consumerSourceRequestFixture(t)
	f.authority.consumers = nil
	if _, err := f.authority.CurrentConsumer(call.ctx, want); err == nil {
		t.Fatal("缺失真实 source 仍接受了消费者")
	}
	f.authority.consumers = source
	original := source.facts
	for _, change := range []func(*ConsumerFacts){
		func(f *ConsumerFacts) { f.Consumer.ProfileID = "other-profile" },
		func(f *ConsumerFacts) { f.Consumer.NodeID = "other-node" },
		func(f *ConsumerFacts) { f.Consumer.SNI = "other.example.test" },
		func(f *ConsumerFacts) { f.ConfigRevision = "" },
		func(f *ConsumerFacts) { f.PluginVersion = "0.1.0\n" },
		func(f *ConsumerFacts) { f.ConfigRevision = strings.Repeat("r", 129) },
		func(f *ConsumerFacts) { f.BindingRef = "../../key" },
	} {
		source.facts = original
		change(&source.facts)
		if _, err := f.authority.CurrentConsumer(call.ctx, want); err == nil {
			t.Fatal("无效配置事实或其他消费者被当成当前许可")
		}
	}
}

func TestHostConsumerSourceIsBoundedAndRechecksReleaseAndActor(t *testing.T) {
	for _, revoke := range []string{"none", "release", "actor"} {
		t.Run(revoke, func(t *testing.T) {
			f, call, want, source := consumerSourceRequestFixture(t)
			if revoke == "release" {
				source.before = call.release
			}
			if revoke == "actor" {
				source.before = func() {
					if err := f.db.Update(f.ctx, func(tx *storage.Tx) error {
						_, err := tx.ExecContext(f.ctx, "UPDATE users SET disabled=1, revision=revision+1 WHERE user_id=?", f.human.ID)
						return err
					}); err != nil {
						t.Fatal(err)
					}
				}
			}
			_, err := f.authority.CurrentConsumer(call.ctx, want)
			if revoke == "none" && err != nil {
				t.Fatal(err)
			}
			if revoke != "none" && err == nil {
				t.Fatal("source读取期间发生的失效没有在返回前复核")
			}
			if source.deadline.IsZero() || source.deadline.After(time.Now().Add(5*time.Second)) {
				t.Fatal("真实source查询缺少有界预算")
			}
		})
	}
}
