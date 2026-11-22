// SPDX-License-Identifier: AGPL-3.0-only

package sshd

import (
	"context"
	"slices"

	"github.com/qwq-panel/qwq/internal/capability/bridge"
	"github.com/qwq-panel/qwq/internal/sandbox"
	sshdv1 "github.com/qwq-panel/qwq/sdk/gen/qwq/capability/sshd/v1"
)

type LoginMutation struct {
	Kind             string   `json:"kind"`
	PasswordAuth     *bool    `json:"password_auth,omitempty"`
	RootLogin        string   `json:"root_login,omitempty"`
	ExpectedRevision string   `json:"expected_revision"`
	RecoveryUser     string   `json:"recovery_user,omitempty"`
	HostAddresses    []string `json:"host_addresses,omitempty"`
	OperationID      string   `json:"operation_id"`
	InstanceID       string   `json:"instance_id"`
}
type RemoveMutation struct {
	ExpectedRevision string   `json:"expected_revision"`
	RecoveryUser     string   `json:"recovery_user,omitempty"`
	HostAddresses    []string `json:"host_addresses,omitempty"`
	OperationID      string   `json:"operation_id"`
	InstanceID       string   `json:"instance_id"`
}

func validMutation(revision, operation, instance string) bool {
	return validRevision(revision) && validOperationID(operation) && sandbox.ValidateID(instance) == nil
}

func (s *Service) idleSnapshot(ctx context.Context, revision string) (Snapshot, string) {
	transaction, _, err := s.transaction()
	if err != nil {
		return Snapshot{}, "UNAVAILABLE"
	}
	if transaction != nil && transaction.Stage != "COMMITTED" {
		return Snapshot{}, "CONFLICT"
	}
	before, err := s.Repository.Read(ctx, Match{})
	if err != nil {
		return Snapshot{}, "UNAVAILABLE"
	}
	if before.Revision != revision {
		return Snapshot{}, "PRECONDITION_FAILED"
	}
	if !before.Writable {
		return Snapshot{}, "CONFLICT"
	}
	if _, err := parseDropIn(before.Content); err != nil {
		return Snapshot{}, "CONFLICT"
	}
	live, err := s.Runtime.Ports(ctx)
	if err != nil {
		return Snapshot{}, "UNAVAILABLE"
	}
	before.LivePorts = uniquePorts(live)
	if !slices.Equal(before.LivePorts, before.Ports) {
		return Snapshot{}, "CONFLICT"
	}
	return before, ""
}

func (s *Service) guardLogin(ctx context.Context, before, candidate Snapshot, raw []byte, user string, addresses []string, force bool) string {
	passwordBefore := settingValue(before.Settings, "passwordauthentication")
	passwordAfter := settingValue(candidate.Settings, "passwordauthentication")
	rootBefore := settingValue(before.Settings, "permitrootlogin")
	rootAfter := settingValue(candidate.Settings, "permitrootlogin")
	tightening := force || passwordAfter == "no" && passwordBefore != "no" || rootAfter != "yes" && rootBefore == "yes" || rootAfter == "no" && rootBefore != "no" || settingValue(candidate.Settings, "kbdinteractiveauthentication") == "no" && settingValue(before.Settings, "kbdinteractiveauthentication") != "no"
	if !tightening {
		return ""
	}
	if user == "" || len(addresses) == 0 || len(addresses) > 64 || s.Recovery == nil {
		return "PRECONDITION_FAILED"
	}
	if rootAfter == "no" && user == "root" {
		return "PRECONDITION_FAILED"
	}
	for _, address := range addresses {
		match := Match{User: user, Address: address}
		if address == "" || !validMatch(match) {
			return "PRECONDITION_FAILED"
		}
		scoped, err := s.Repository.Candidate(ctx, before, raw, match)
		if err != nil {
			return "VALIDATION_FAILED"
		}
		if settingValue(scoped.Settings, "pubkeyauthentication") != "yes" || s.Recovery.Check(ctx, user, address, scoped) != nil {
			return "PRECONDITION_FAILED"
		}
	}
	return ""
}

func (s *Service) setLogin(ctx context.Context, pluginID string, mutation LoginMutation) sandbox.CapabilityResponse {
	if mutation.Kind != "login" || !validMutation(mutation.ExpectedRevision, mutation.OperationID, mutation.InstanceID) || mutation.PasswordAuth == nil && mutation.RootLogin == "" || mutation.RootLogin != "" && mutation.RootLogin != "yes" && mutation.RootLogin != "no" && mutation.RootLogin != "prohibit-password" {
		return bridge.Failure("VALIDATION_FAILED", "登录策略参数无效")
	}
	before, code := s.idleSnapshot(ctx, mutation.ExpectedRevision)
	if code != "" {
		return bridge.Failure(code, "登录策略前置条件不满足")
	}
	policy, err := parseDropIn(before.Content)
	if err != nil {
		return bridge.Failure("CONFLICT", "同名 drop-in 不可管理")
	}
	if mutation.PasswordAuth != nil {
		policy.PasswordAuth = mutation.PasswordAuth
		if !*mutation.PasswordAuth {
			disabled := false
			policy.KeyboardAuth = &disabled
		}
	}
	if mutation.RootLogin != "" {
		policy.RootLogin = mutation.RootLogin
	}
	raw := renderDropIn(policy)
	candidate, err := s.Repository.Candidate(ctx, before, raw, Match{})
	if err != nil {
		return bridge.Failure("VALIDATION_FAILED", "登录候选未通过原生预检")
	}
	if mutation.PasswordAuth != nil {
		expected := "no"
		if *mutation.PasswordAuth {
			expected = "yes"
		}
		if settingValue(candidate.Settings, "passwordauthentication") != expected || !*mutation.PasswordAuth && settingValue(candidate.Settings, "kbdinteractiveauthentication") != "no" {
			return bridge.Failure("CONFLICT", "其他配置覆盖了登录策略")
		}
	}
	if mutation.RootLogin != "" && settingValue(candidate.Settings, "permitrootlogin") != mutation.RootLogin {
		return bridge.Failure("CONFLICT", "其他配置覆盖了 root 登录策略")
	}
	force := mutation.PasswordAuth != nil && !*mutation.PasswordAuth || mutation.RootLogin == "no" || mutation.RootLogin == "prohibit-password"
	if code := s.guardLogin(ctx, before, candidate, raw, mutation.RecoveryUser, mutation.HostAddresses, force); code != "" {
		return bridge.Failure(code, "恢复用户没有可验证的公钥登录路径")
	}
	_, previous, err := s.begin("login", pluginID, mutation.InstanceID, mutation.OperationID, before, candidate)
	if err != nil {
		return bridge.Failure("UNAVAILABLE", "无法持久化登录事务，未执行")
	}
	after, code := s.replace(ctx, before, candidate, raw)
	if code != "" {
		return bridge.Failure(s.finishFailure(code, previous), "登录策略变更未完成")
	}
	if s.Transactions.Commit(nil) != nil {
		return bridge.Failure("RECOVERY_REQUIRED", "登录策略已变化，旧事务清理失败")
	}
	return bridge.Pack(&sshdv1.SetLoginPolicyResponse{Revision: after.Revision, Effective: after.Settings})
}

func (s *Service) remove(ctx context.Context, pluginID string, mutation RemoveMutation) sandbox.CapabilityResponse {
	if !validMutation(mutation.ExpectedRevision, mutation.OperationID, mutation.InstanceID) {
		return bridge.Failure("VALIDATION_FAILED", "移除参数无效")
	}
	before, code := s.idleSnapshot(ctx, mutation.ExpectedRevision)
	if code != "" {
		return bridge.Failure(code, "移除前置条件不满足")
	}
	if !before.Exists {
		return bridge.Pack(&sshdv1.RemoveDropInResponse{Revision: before.Revision})
	}
	candidate, err := s.Repository.Candidate(ctx, before, nil, Match{})
	if err != nil {
		return bridge.Failure("VALIDATION_FAILED", "原始配置未通过原生预检")
	}
	if code := s.guardLogin(ctx, before, candidate, nil, mutation.RecoveryUser, mutation.HostAddresses, false); code != "" {
		return bridge.Failure(code, "原始登录策略缺少恢复路径")
	}
	first, firstRaw := candidate, []byte(nil)
	dual := !slices.Equal(before.Ports, candidate.Ports)
	if dual {
		// 先加入原始配置将要使用的端口并验证，再删除自有 drop-in。
		interimRaw := renderDropIn(loginPolicy{Ports: uniquePorts(append(slices.Clone(before.Ports), candidate.Ports...))})
		interim, err := s.Repository.Candidate(ctx, before, interimRaw, Match{})
		if err != nil {
			return bridge.Failure("VALIDATION_FAILED", "双端口恢复候选无效")
		}
		first, firstRaw = interim, interimRaw
	}
	record, previous, err := s.begin("remove", pluginID, mutation.InstanceID, mutation.OperationID, before, first)
	if err != nil {
		return bridge.Failure("UNAVAILABLE", "无法持久化移除事务，未执行")
	}
	current, code := s.replace(ctx, before, first, firstRaw)
	if code != "" {
		return bridge.Failure(s.finishFailure(code, previous), "原始配置未能安全验证")
	}
	if dual {
		candidate, err = s.Repository.Candidate(ctx, current, nil, Match{})
		if err != nil {
			if !s.restore(ctx, before, current) {
				return bridge.Failure("RECOVERY_REQUIRED", "原始候选失效，恢复未完成")
			}
			return bridge.Failure(s.finishFailure("PRECONDITION_FAILED", previous), "原始候选已变化")
		}
		record.ExpectedRevision, record.AppliedRevision = current.Revision, candidate.Revision
		if err := s.save(record); err != nil {
			return bridge.Failure("RECOVERY_REQUIRED", "双端口已生效，移除事务更新失败")
		}
		after, code := s.replace(ctx, current, candidate, nil)
		if code != "" {
			if !s.restore(ctx, before, current) {
				code = "RECOVERY_REQUIRED"
			}
			return bridge.Failure(s.finishFailure(code, previous), "自有 drop-in 未能移除")
		}
		current = after
	}
	if s.Transactions.Commit(nil) != nil {
		return bridge.Failure("RECOVERY_REQUIRED", "原始配置已恢复，事务清理失败")
	}
	return bridge.Pack(&sshdv1.RemoveDropInResponse{Revision: current.Revision})
}
