// SPDX-License-Identifier: AGPL-3.0-only

package firewall

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
)

var errSSHPortNotPreserved = errors.New("firewall: the new SSH port is not confirmed in the current and saved policy")

// ======================== SSH 摘旧前复用真实 input 链与持久策略 ========================

// RequireSSHPort 必须在 SSH 与防火墙共用的 capability 资源锁内调用。
// 这里只读取已有事实，不再次获取同一 flock，也不修改规则或持久状态。
func (s *Service) RequireSSHPort(ctx context.Context, port uint32) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if s == nil || s.Executor == nil || s.State == nil || port == 0 || port > 65535 {
		return errSSHPortNotPreserved
	}
	current, err := s.readSnapshot(ctx)
	if err != nil {
		return err
	}
	if current.pending {
		return errSSHPortNotPreserved
	}
	if !current.chainExists && !current.persistedExists {
		return nil
	}
	var document nftDocument
	if err := json.Unmarshal(current.definition, &document); err != nil {
		return errInvalidRuleset
	}
	for _, object := range document.Nftables {
		if object.Rule == nil {
			continue
		}
		rule := *object.Rule
		if err := normalizeRule(&rule); err != nil {
			return err
		}
		if rule.Comment == "qwq:preserve" {
			ports, err := preservedRulePorts(rule)
			if err == nil && slices.Contains(ports, port) {
				return nil
			}
			return errSSHPortNotPreserved
		}
		// 自有回环/已建立连接接受规则不会阻断入站；任意其他前置规则不能证明安全。
		if !generatedGuard(rule) {
			return errSSHPortNotPreserved
		}
	}
	return errSSHPortNotPreserved
}
