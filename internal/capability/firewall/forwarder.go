// SPDX-License-Identifier: AGPL-3.0-only

package firewall

import (
	"context"
	"encoding/json"

	"github.com/qwq-panel/qwq/internal/capability/bridge"
	"github.com/qwq-panel/qwq/internal/pluginhost/hostsvc"
	firewallv1 "github.com/qwq-panel/qwq/sdk/gen/qwq/capability/firewall/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

// Caller 允许测试用 fake helper，生产使用 connect-only 重试的 CapabilityClient。
type Caller = bridge.Caller

// Forwarder 仅处理经过能力门的四个 RPC，保留端口来自宿主配置及 helper 事实。
type Forwarder struct {
	Helper        Caller
	HostPorts     []uint32
	HostPortsFunc func() []uint32
}

func (f Forwarder) hostPorts() []uint32 {
	if f.HostPortsFunc != nil {
		if dynamic := f.HostPortsFunc(); len(dynamic) > 0 {
			return mergePorts(f.HostPorts, dynamic)
		}
	}
	return f.HostPorts
}

func (f Forwarder) Forward(ctx context.Context, call hostsvc.CapabilityCall) (hostsvc.CapabilityResult, error) {
	if call.Service != "firewall" || f.Helper == nil {
		return hostsvc.CapabilityResult{}, status.Error(codes.Unavailable, "防火墙执行器未接入")
	}
	switch call.Method {
	case "GetRuleset":
		if req, ok := call.Request.(*firewallv1.GetRulesetRequest); !ok || req == nil {
			return invalidCall()
		}
		response := new(firewallv1.GetRulesetResponse)
		result, err := f.invoke(ctx, call.PluginID, "firewall.get", struct{}{}, response)
		if err == nil && result.Error == nil {
			response.PreservedPorts = mergePorts(response.PreservedPorts, f.hostPorts())
		}
		return result, err
	case "DetectManagers":
		if req, ok := call.Request.(*firewallv1.DetectManagersRequest); !ok || req == nil {
			return invalidCall()
		}
		return f.invoke(ctx, call.PluginID, "firewall.detect", struct{}{}, new(firewallv1.DetectManagersResponse))
	case "ApplyRuleset":
		req, ok := call.Request.(*firewallv1.ApplyRulesetRequest)
		if !ok || req == nil {
			return invalidCall()
		}
		hostPorts := f.hostPorts()
		if _, err := preservedPorts(hostPorts, hostPorts); err != nil {
			return hostsvc.CapabilityResult{}, status.Error(codes.Unavailable, "宿主管理端口未配置")
		}
		observed := new(firewallv1.GetRulesetResponse)
		result, err := f.invoke(ctx, call.PluginID, "firewall.get", struct{}{}, observed)
		if err != nil || result.Error != nil {
			return result, err
		}
		required := mergePorts(observed.PreservedPorts, hostPorts)
		if _, err := Normalize(req.RulesetJson, required, req.PreservedPorts); err != nil {
			return hostsvc.CapabilityResult{Error: &hostsvc.DomainError{Code: "VALIDATION_FAILED", Message: "规则集不符合安全白名单或缺少管理端口"}}, nil
		}
		params := Mutation{Ruleset: append([]byte(nil), req.RulesetJson...), ExpectedRevision: req.ExpectedRevision, PreservedPorts: append([]uint32(nil), req.PreservedPorts...), HostPorts: required}
		return f.invoke(ctx, call.PluginID, "firewall.apply", params, new(firewallv1.ApplyRulesetResponse))
	case "ResetRuleset":
		req, ok := call.Request.(*firewallv1.ResetRulesetRequest)
		if !ok || req == nil {
			return invalidCall()
		}
		hostPorts := f.hostPorts()
		if _, err := preservedPorts(hostPorts, hostPorts); err != nil {
			return hostsvc.CapabilityResult{}, status.Error(codes.Unavailable, "宿主管理端口未配置")
		}
		return f.invoke(ctx, call.PluginID, "firewall.reset", Mutation{ExpectedRevision: req.ExpectedRevision, HostPorts: append([]uint32(nil), hostPorts...)}, new(firewallv1.ResetRulesetResponse))
	default:
		return hostsvc.CapabilityResult{}, status.Error(codes.Unimplemented, "防火墙方法不受支持")
	}
}

func (f Forwarder) invoke(ctx context.Context, pluginID, verb string, params any, response proto.Message) (hostsvc.CapabilityResult, error) {
	result, err := bridge.Invoke(ctx, f.Helper, pluginID, verb, params, response)
	if err != nil || result.Error != nil {
		return result, err
	}
	if rules, ok := response.(*firewallv1.GetRulesetResponse); ok {
		if len(rules.RulesetJson) > 512<<10 || !json.Valid(rules.RulesetJson) {
			return hostsvc.CapabilityResult{}, status.Error(codes.Unavailable, "防火墙 helper 返回了无效规则集")
		}
		if _, err := preservedPorts(rules.PreservedPorts, rules.PreservedPorts); err != nil {
			return hostsvc.CapabilityResult{}, status.Error(codes.Unavailable, "防火墙 helper 返回了无效保留端口")
		}
	}
	return hostsvc.CapabilityResult{Response: response}, nil
}

func invalidCall() (hostsvc.CapabilityResult, error) {
	return hostsvc.CapabilityResult{}, status.Error(codes.Internal, "防火墙调用类型不匹配")
}

var _ hostsvc.CapabilityForwarder = Forwarder{}
