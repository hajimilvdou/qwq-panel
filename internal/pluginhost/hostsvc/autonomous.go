// SPDX-License-Identifier: AGPL-3.0-only

package hostsvc

import (
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

const autonomousOpPrefix = "auton:"

// AutonomousInstanceChecker verifies that a plugin instance is declared with
// manifest.lifecycle.background == true and is currently active in the host
// supervisor before permitting autonomous background capability writes.
type AutonomousInstanceChecker interface {
	IsActiveBackgroundInstance(pluginID, instanceID string) bool
}

// autonomousAllowedVerbs restricts background autonomous writes strictly to
// low-blast-radius self-healing / enforcement operations:
//   - ban.apply / ban.remove: security.basic brute-force IP banning & eviction
//   - sshd.set-port: strictly PORT_CHANGE_STAGE_ROLLBACK (enum 3) only
//   - firewall.apply: security.basic timeout rollback / preserved-port sync
//   - traffic.apply / traffic.clear: proxy.advanced HTB rate-limit sync
//   - pluginconfig.put: proxy.advanced quota-exceeded user revocation sync
var autonomousAllowedVerbs = map[string]bool{
	"ban.apply":        true,
	"ban.remove":       true,
	"sshd.set-port":    true,
	"firewall.apply":   true,
	"traffic.apply":    true,
	"traffic.clear":    true,
	"pluginconfig.put": true,
}

// authorizeAutonomousWrite validates a background capability write whose
// OperationID carries the reserved "auton:" prefix.
func (s *Server) authorizeAutonomousWrite(
	request proto.Message,
	policy capabilityPolicy,
	scope string,
	autonomousOpID string,
	bgChecker AutonomousInstanceChecker,
	autonBucket *tokenBucket,
) error {
	reason := strings.TrimPrefix(autonomousOpID, autonomousOpPrefix)
	if len(reason) == 0 || len(reason) > 48 {
		return status.Error(codes.InvalidArgument, "自治能力上下文标识无效")
	}
	if !autonomousAllowedVerbs[policy.verb] {
		return status.Error(codes.PermissionDenied, "该写能力不允许在后台无人工审批下自治执行")
	}
	if bgChecker == nil || !bgChecker.IsActiveBackgroundInstance(s.cfg.PluginID, s.cfg.InstanceID) {
		return status.Error(codes.FailedPrecondition, "当前插件实例未处于已激活的后台守护态")
	}
	if !s.capabilities.granted(policy, scope) {
		return status.Error(codes.PermissionDenied, "实例未获授此自治能力或作用域")
	}
	// Defense in depth: sshd.set-port via autonomous channel is strictly
	// restricted to PORT_CHANGE_STAGE_ROLLBACK (enum value 3).
	if policy.verb == "sshd.set-port" && !isSSHDPortRollbackStage(request) {
		return status.Error(codes.PermissionDenied, "后台自治通道仅允许执行 SSH 端口超时回滚 (ROLLBACK)")
	}
	if autonBucket != nil && !autonBucket.allow(s.clock.Now()) {
		return status.Error(codes.ResourceExhausted, "后台自治能力写入超过每分钟安全配额")
	}
	return nil
}

func isSSHDPortRollbackStage(request proto.Message) bool {
	if request == nil {
		return false
	}
	msg := request.ProtoReflect()
	stageField := msg.Descriptor().Fields().ByName("stage")
	if stageField == nil {
		return false
	}
	// qwq.capability.sshd.v1.PortChangeStage_PORT_CHANGE_STAGE_ROLLBACK == 3
	return int32(msg.Get(stageField).Enum()) == 3
}
