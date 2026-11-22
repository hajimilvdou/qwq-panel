// SPDX-License-Identifier: AGPL-3.0-only

package hostauth

import (
	"context"
	"time"

	"github.com/qwq-panel/qwq/internal/actor"
	"github.com/qwq-panel/qwq/internal/authz"
	"github.com/qwq-panel/qwq/internal/prerequisites/certificates"
	"github.com/qwq-panel/qwq/internal/prerequisites/fault"
	"github.com/qwq-panel/qwq/internal/prerequisites/names"
)

// ======================== 真实配置入口的权限交集与消费范围校验 ========================

func (a *Authority) authorizeConsumerConfiguration(ctx context.Context, who actor.Actor, nodeID, pluginID string) error {
	if a == nil || a.authorizer == nil || ctx == nil || who.Valid() != nil || who.Kind == actor.System ||
		nodeID != a.nodeID || !names.ID(pluginID) {
		return fault.New("PERMISSION_DENIED", "配置消费校验缺少当前真实主体或固定节点范围")
	}
	return a.authorizer.Authorize(ctx, who, "host.plugins:config", authz.Resource{Name: "host.plugins", NodeID: nodeID,
		Action: "host.plugins.config", Subject: "plugins/" + pluginID + "/config"})
}

// ValidateConsumerConfiguration 只由宿主的真实API/Host配置边界调用；
// 参数来自已经解析的完整候选，不创建配置Invocation或授予材料消费权限。
func (a *Authority) ValidateConsumerConfiguration(ctx context.Context, who actor.Actor, nodeID, pluginID, expectedConfigRevision string, inputs []ConsumerConfiguration) error {
	if ctx == nil {
		return fault.New("PERMISSION_DENIED", "配置消费校验缺少真实上下文")
	}
	bounded, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := a.authorizeConsumerConfiguration(bounded, who, nodeID, pluginID); err != nil {
		return err
	}
	if !boundedSourceVersion(expectedConfigRevision) || len(inputs) > 8 {
		return fault.New("VALIDATION_FAILED", "配置消费引用的版本或数量无效")
	}
	state, _, err := a.loadBindingLedger(bounded)
	if err != nil {
		return err
	}
	seen := make(map[string]bool, len(inputs))
	policies := make(map[string]string, len(inputs))
	for _, input := range inputs {
		consumer, err := certificates.CanonicalConsumer(input.Consumer)
		if err != nil || consumer.NodeID != nodeID || consumer.PluginID != pluginID || seen[input.BindingRef] {
			return fault.New("BINDING_DENIED", "候选消费引用的节点、插件或消费者无效")
		}
		seen[input.BindingRef] = true
		index := bindingIndex(state, input.BindingRef)
		if index < 0 {
			return fault.New("BINDING_DENIED", "候选绑定未在宿主私有账本中预留")
		}
		entry := state.Entries[index]
		if consumer.Test && !entry.Consumer.Test {
			return fault.New("TEST_CERTIFICATE_DENIED", "候选配置不能升级预留的测试信任")
		}
		consumer.Test = entry.Consumer.Test
		if consumer != entry.Consumer {
			return fault.New("BINDING_DENIED", "候选profile、SNI或用途超出私有预留")
		}
		if err := a.checkBindingRegistration(bounded, entry); err != nil {
			return err
		}
		if entry.Phase == bindingReserved {
			if entry.ConfigRevision != expectedConfigRevision {
				return fault.New("REVISION_CONFLICT", "首次配置需要预留时的原配置版本")
			}
		} else {
			origin := entry.Origin
			if entry.ConfirmedOrigin != nil {
				origin = *entry.ConfirmedOrigin
			}
			facts, err := a.currentRegisteredConsumer(bounded, origin.invocation(), entry.Consumer)
			if err != nil {
				return err
			}
			if facts.BindingRef != entry.ID || facts.PluginVersion != entry.PluginVersion {
				return fault.New("BINDING_REVOKED", "当前配置已换用绑定或实际安装版本")
			}
			if facts.ConfigRevision != expectedConfigRevision {
				return fault.New("REVISION_CONFLICT", "当前消费者配置版本已经变化")
			}
		}
		policies[entry.ID], err = bindingPolicyRevision(entry)
		if err != nil {
			return err
		}
	}
	// 不以第一次读取作为永久许可；源读取后复核私有撤权和当前API主体。
	current, _, err := a.loadBindingLedger(bounded)
	if err != nil {
		return err
	}
	for id, policy := range policies {
		index := bindingIndex(current, id)
		if index < 0 {
			return fault.New("BINDING_REVOKED", "配置验证期间预留登记已移除")
		}
		entry := current.Entries[index]
		actual, err := bindingPolicyRevision(entry)
		if err != nil {
			return err
		}
		if actual != policy {
			return fault.New("BINDING_REVOKED", "配置验证期间消费授权已换代")
		}
		if err := a.checkBindingRegistration(bounded, entry); err != nil {
			return err
		}
	}
	return a.authorizeConsumerConfiguration(bounded, who, nodeID, pluginID)
}

// 这里只读取真实当次配置事实；origin是受检存档，不是RUNNING证明。
func (a *Authority) currentRegisteredConsumer(ctx context.Context, origin Invocation, want certificates.Consumer) (ConsumerFacts, error) {
	facts, err := a.readConsumerFacts(ctx, origin, want)
	if err != nil {
		return ConsumerFacts{}, err
	}
	if facts.Consumer != want {
		return ConsumerFacts{}, fault.New("BINDING_DENIED", "真实消费者、测试授权或配置事实不符")
	}
	return facts, nil
}
