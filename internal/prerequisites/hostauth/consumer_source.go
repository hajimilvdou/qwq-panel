// SPDX-License-Identifier: AGPL-3.0-only

package hostauth

import (
	"context"
	"time"

	"github.com/qwq-panel/qwq/internal/prerequisites/certificates"
	"github.com/qwq-panel/qwq/internal/prerequisites/fault"
	"github.com/qwq-panel/qwq/internal/prerequisites/names"
)

// ======================== 当次宿主配置事实，不缓存授权结论 ========================

// CurrentConsumer 只返回真实 source 的当次事实；消费者权限由后续私有登记核对。
func (a *Authority) CurrentConsumer(ctx context.Context, want certificates.Consumer) (ConsumerFacts, error) {
	if a == nil || a.consumers == nil {
		return ConsumerFacts{}, fault.New("BACKEND_REQUIRED", "消费者需要真实宿主配置事实")
	}
	value, err := a.current(ctx)
	if err != nil {
		return ConsumerFacts{}, err
	}
	want, err = certificates.CanonicalConsumer(want)
	if err != nil {
		return ConsumerFacts{}, err
	}
	if value.invocation.PluginID != "tls.certificates" || want.NodeID != a.nodeID {
		return ConsumerFacts{}, fault.New("PERMISSION_DENIED", "消费者不属于当前证书 operation 的节点")
	}
	bounded, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	facts, err := a.readConsumerFacts(bounded, value.invocation, want)
	if err != nil {
		return ConsumerFacts{}, err
	}
	// Test 仅来自真实配置；请求不能把生产消费提升为测试信任。
	want.Test = facts.Consumer.Test
	if facts.Consumer != want {
		return ConsumerFacts{}, fault.New("BINDING_DENIED", "宿主消费者、绑定或配置版本与请求不符")
	}
	if _, err := a.current(bounded); err != nil {
		return ConsumerFacts{}, err
	}
	return facts, nil
}

// readConsumerFacts只校验当次事实形状；调用者负责当前权限与精确请求交集。
func (a *Authority) readConsumerFacts(ctx context.Context, origin Invocation, want certificates.Consumer) (ConsumerFacts, error) {
	if a == nil || a.consumers == nil {
		return ConsumerFacts{}, fault.New("BACKEND_REQUIRED", "消费者需要真实宿主配置来源")
	}
	facts, err := a.consumers.CurrentConsumer(ctx, origin, want)
	if err != nil {
		return ConsumerFacts{}, err
	}
	consumer, err := certificates.CanonicalConsumer(facts.Consumer)
	if err != nil || !names.ID(facts.BindingRef) || !boundedSourceVersion(facts.ConfigRevision) || !boundedSourceVersion(facts.PluginVersion) {
		return ConsumerFacts{}, fault.New("BINDING_DENIED", "宿主消费者或配置版本事实无效")
	}
	if err := ctx.Err(); err != nil {
		return ConsumerFacts{}, err
	}
	facts.Consumer = consumer
	return facts, nil
}

func boundedSourceVersion(value string) bool {
	if len(value) == 0 || len(value) > 128 {
		return false
	}
	for _, character := range value {
		if character < 33 || character > 126 {
			return false
		}
	}
	return true
}
