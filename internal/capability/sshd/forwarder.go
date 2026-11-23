// SPDX-License-Identifier: AGPL-3.0-only

package sshd

import (
	"context"
	"slices"

	"github.com/qwq-panel/qwq/internal/capability/bridge"
	"github.com/qwq-panel/qwq/internal/pluginhost/hostsvc"
	sshdv1 "github.com/qwq-panel/qwq/sdk/gen/qwq/capability/sshd/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type Forwarder struct {
	Helper        bridge.Caller
	HostPorts     []uint32
	HostPortsFunc func() []uint32
	// Addresses 从宿主有效会话读取并重新核验派发，插件不能选择或伪造。
	Addresses func(context.Context, hostsvc.CapabilityCall) ([]string, error)
}

func (f Forwarder) hostPorts() []uint32 {
	out := slices.Clone(f.HostPorts)
	if f.HostPortsFunc != nil {
		for _, p := range f.HostPortsFunc() {
			if p > 0 && !slices.Contains(out, p) {
				out = append(out, p)
			}
		}
	}
	return out
}

func (f Forwarder) Forward(ctx context.Context, call hostsvc.CapabilityCall) (hostsvc.CapabilityResult, error) {
	if call.Service != "sshd" || f.Helper == nil {
		return hostsvc.CapabilityResult{}, status.Error(codes.Unavailable, "SSH 执行器未接入")
	}
	switch call.Method {
	case "GetEffectiveConfig":
		request, ok := call.Request.(*sshdv1.GetEffectiveConfigRequest)
		if !ok || request == nil {
			return invalidCall()
		}
		return bridge.Invoke(ctx, f.Helper, call.PluginID, "sshd.get-effective", Match{User: request.MatchUser, Address: request.MatchAddress}, new(sshdv1.GetEffectiveConfigResponse))
	case "GetDropIn":
		if request, ok := call.Request.(*sshdv1.GetDropInRequest); !ok || request == nil {
			return invalidCall()
		}
		params := struct {
			InstanceID string `json:"instance_id"`
		}{InstanceID: call.InstanceID}
		return bridge.Invoke(ctx, f.Helper, call.PluginID, "sshd.get-dropin", params, new(sshdv1.GetDropInResponse))
	case "VerifyPort":
		request, ok := call.Request.(*sshdv1.VerifyPortRequest)
		if !ok || request == nil {
			return invalidCall()
		}
		params := struct {
			Port uint32 `json:"port"`
		}{Port: request.Port}
		return bridge.Invoke(ctx, f.Helper, call.PluginID, "sshd.verify-port", params, new(sshdv1.VerifyPortResponse))
	case "SetPort":
		request, ok := call.Request.(*sshdv1.SetPortRequest)
		if !ok || request == nil {
			return invalidCall()
		}
		stages := map[sshdv1.PortChangeStage]string{sshdv1.PortChangeStage_PORT_CHANGE_STAGE_ADD_NEW: "ADD_NEW", sshdv1.PortChangeStage_PORT_CHANGE_STAGE_COMMIT_NEW: "COMMIT_NEW", sshdv1.PortChangeStage_PORT_CHANGE_STAGE_ROLLBACK: "ROLLBACK"}
		stage, ok := stages[request.Stage]
		if !ok {
			return validationFailure("必须指定 SSH 端口事务阶段")
		}
		params := PortMutation{Kind: "port", NewPort: request.NewPort, Stage: stage, ExpectedRevision: request.ExpectedRevision, TransactionRef: request.TransactionRef, OperationID: call.OperationID, InstanceID: call.InstanceID, HostPorts: f.hostPorts()}
		return bridge.Invoke(ctx, f.Helper, call.PluginID, "sshd.write-dropin", params, new(sshdv1.SetPortResponse))
	case "SetLoginPolicy":
		request, ok := call.Request.(*sshdv1.SetLoginPolicyRequest)
		if !ok || request == nil {
			return invalidCall()
		}
		root, valid := rootMode(request)
		if !valid {
			return validationFailure("root 登录策略字段冲突或无效")
		}
		addresses, err := f.addresses(ctx, call)
		if err != nil {
			return hostsvc.CapabilityResult{}, err
		}
		params := LoginMutation{Kind: "login", PasswordAuth: request.PasswordAuth, RootLogin: root, ExpectedRevision: request.ExpectedRevision, RecoveryUser: request.RecoveryUser, HostAddresses: addresses, OperationID: call.OperationID, InstanceID: call.InstanceID}
		return bridge.Invoke(ctx, f.Helper, call.PluginID, "sshd.write-dropin", params, new(sshdv1.SetLoginPolicyResponse))
	case "RemoveDropIn":
		request, ok := call.Request.(*sshdv1.RemoveDropInRequest)
		if !ok || request == nil {
			return invalidCall()
		}
		addresses, err := f.addresses(ctx, call)
		if err != nil {
			return hostsvc.CapabilityResult{}, err
		}
		params := RemoveMutation{ExpectedRevision: request.ExpectedRevision, RecoveryUser: request.RecoveryUser, HostAddresses: addresses, OperationID: call.OperationID, InstanceID: call.InstanceID}
		return bridge.Invoke(ctx, f.Helper, call.PluginID, "sshd.remove-dropin", params, new(sshdv1.RemoveDropInResponse))
	case "RecoverDropIn":
		request, ok := call.Request.(*sshdv1.RecoverDropInRequest)
		if !ok || request == nil {
			return invalidCall()
		}
		addresses, err := f.addresses(ctx, call)
		if err != nil {
			return hostsvc.CapabilityResult{}, err
		}
		params := RecoveryMutation{ExpectedRevision: request.ExpectedRevision, TransactionRef: request.TransactionRef, RecoveryUser: request.RecoveryUser, HostAddresses: addresses, OperationID: call.OperationID, InstanceID: call.InstanceID}
		return bridge.Invoke(ctx, f.Helper, call.PluginID, "sshd.recover-dropin", params, new(sshdv1.RecoverDropInResponse))
	default:
		return hostsvc.CapabilityResult{}, status.Error(codes.Unimplemented, "SSH 方法不受支持")
	}
}

func (f Forwarder) addresses(ctx context.Context, call hostsvc.CapabilityCall) ([]string, error) {
	if f.Addresses == nil {
		return nil, status.Error(codes.Unavailable, "管理会话事实未接入")
	}
	addresses, err := f.Addresses(ctx, call)
	if err != nil {
		return nil, status.Error(codes.Unavailable, "管理会话事实不可用")
	}
	return addresses, nil
}

func rootMode(request *sshdv1.SetLoginPolicyRequest) (string, bool) {
	if request.PermitRootLogin != nil {
		if request.RootLoginMode != sshdv1.RootLoginMode_ROOT_LOGIN_MODE_UNSPECIFIED {
			return "", false
		}
		if *request.PermitRootLogin {
			return "yes", true
		}
		return "no", true
	}
	switch request.RootLoginMode {
	case sshdv1.RootLoginMode_ROOT_LOGIN_MODE_UNSPECIFIED:
		return "", true
	case sshdv1.RootLoginMode_ROOT_LOGIN_MODE_ALLOW:
		return "yes", true
	case sshdv1.RootLoginMode_ROOT_LOGIN_MODE_DENY:
		return "no", true
	case sshdv1.RootLoginMode_ROOT_LOGIN_MODE_KEYS_ONLY:
		return "prohibit-password", true
	default:
		return "", false
	}
}

func invalidCall() (hostsvc.CapabilityResult, error) {
	return hostsvc.CapabilityResult{}, status.Error(codes.Internal, "SSH 调用类型不匹配")
}
func validationFailure(message string) (hostsvc.CapabilityResult, error) {
	return hostsvc.CapabilityResult{Error: &hostsvc.DomainError{Code: "VALIDATION_FAILED", Message: message}}, nil
}

var _ hostsvc.CapabilityForwarder = Forwarder{}
