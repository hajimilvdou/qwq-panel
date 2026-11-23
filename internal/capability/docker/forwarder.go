// SPDX-License-Identifier: AGPL-3.0-only

package docker

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/qwq-panel/qwq/internal/pluginhost/hostsvc"
	"github.com/qwq-panel/qwq/internal/sandbox"
	dockerv1 "github.com/qwq-panel/qwq/sdk/gen/qwq/capability/docker/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Helper 抽象特权辅助进程客户端（与 *sandbox.CapabilityClient 对齐）。
type Helper interface {
	Call(ctx context.Context, req sandbox.CapabilityRequest) (sandbox.CapabilityResponse, error)
}

// Forwarder 将 hostsvc 的 DockerService 能力调用转发至 qwq-capability helper。
type Forwarder struct {
	Helper        Helper
	HostPorts     []uint32
	HostPortsFunc func() []uint32
}

func (f Forwarder) reservedHostPorts() []uint16 {
	var raw []uint32
	if f.HostPortsFunc != nil {
		raw = f.HostPortsFunc()
	}
	if len(raw) == 0 {
		raw = f.HostPorts
	}
	out := make([]uint16, 0, len(raw))
	seen := make(map[uint16]bool, len(raw))
	for _, p := range raw {
		if p == 0 || p > 65535 {
			continue
		}
		u := uint16(p)
		if !seen[u] {
			seen[u] = true
			out = append(out, u)
		}
	}
	return out
}

// Forward 实现 hostsvc.CapabilityForwarder。
func (f Forwarder) Forward(ctx context.Context, call hostsvc.CapabilityCall) (hostsvc.CapabilityResult, error) {
	if f.Helper == nil {
		return hostsvc.CapabilityResult{}, status.Error(codes.Unavailable, "受控 Docker 辅助进程不可用")
	}
	callerID := call.PluginID
	if callerID == "" {
		callerID = "containers.docker"
	}

	switch call.Method {
	case "ProxyRead":
		req, ok := call.Request.(*dockerv1.ProxyReadRequest)
		if !ok {
			return hostsvc.CapabilityResult{}, status.Error(codes.InvalidArgument, "无效的 ProxyRead 请求")
		}
		payload, err := json.Marshal(ProxyAPIInput{
			Method:   http.MethodGet,
			Path:     req.GetPath(),
			RawQuery: req.GetRawQuery(),
		})
		if err != nil {
			return hostsvc.CapabilityResult{}, status.Error(codes.Internal, "编码 Docker 只读请求失败")
		}
		resp, err := f.Helper.Call(ctx, sandbox.CapabilityRequest{Op: "docker.api.read", ID: callerID, ParamsJSON: payload})
		if err != nil {
			return hostsvc.CapabilityResult{}, status.Error(codes.Unavailable, "调用 Docker 能力辅助进程失败")
		}
		if !resp.OK {
			return helperFail(resp), nil
		}
		var out ProxyAPIOutput
		if err := json.Unmarshal(resp.ResultJSON, &out); err != nil {
			return hostsvc.CapabilityResult{}, status.Error(codes.Internal, "解析 Docker 只读响应失败")
		}
		return hostsvc.CapabilityResult{
			Response: &dockerv1.ProxyReadResponse{
				StatusCode: int32(out.StatusCode),
				Body:       out.Body,
			},
		}, nil

	case "ProxyWrite":
		req, ok := call.Request.(*dockerv1.ProxyWriteRequest)
		if !ok {
			return hostsvc.CapabilityResult{}, status.Error(codes.InvalidArgument, "无效的 ProxyWrite 请求")
		}
		payload, err := json.Marshal(ProxyAPIInput{
			Method:   req.GetMethod(),
			Path:     req.GetPath(),
			RawQuery: req.GetRawQuery(),
			Body:     req.GetBody(),
		})
		if err != nil {
			return hostsvc.CapabilityResult{}, status.Error(codes.Internal, "编码 Docker 写请求失败")
		}
		resp, err := f.Helper.Call(ctx, sandbox.CapabilityRequest{Op: "docker.api.write", ID: callerID, ParamsJSON: payload})
		if err != nil {
			return hostsvc.CapabilityResult{}, status.Error(codes.Unavailable, "调用 Docker 能力辅助进程失败")
		}
		if !resp.OK {
			return helperFail(resp), nil
		}
		var out ProxyAPIOutput
		if err := json.Unmarshal(resp.ResultJSON, &out); err != nil {
			return hostsvc.CapabilityResult{}, status.Error(codes.Internal, "解析 Docker 写响应失败")
		}
		return hostsvc.CapabilityResult{
			Response: &dockerv1.ProxyWriteResponse{
				StatusCode: int32(out.StatusCode),
				Body:       out.Body,
			},
		}, nil

	case "ComposeAction":
		req, ok := call.Request.(*dockerv1.ComposeActionRequest)
		if !ok {
			return hostsvc.CapabilityResult{}, status.Error(codes.InvalidArgument, "无效的 ComposeAction 请求")
		}
		payload, err := json.Marshal(ComposeInput{
			StackName:   req.GetStackName(),
			Action:      req.GetAction(),
			YAMLContent: req.GetYamlContent(),
		})
		if err != nil {
			return hostsvc.CapabilityResult{}, status.Error(codes.Internal, "编码 Compose 请求失败")
		}
		resp, err := f.Helper.Call(ctx, sandbox.CapabilityRequest{Op: "docker.compose", ID: callerID, ParamsJSON: payload})
		if err != nil {
			return hostsvc.CapabilityResult{}, status.Error(codes.Unavailable, "调用 Docker Compose 辅助进程失败")
		}
		if !resp.OK {
			return helperFail(resp), nil
		}
		var out ComposeOutput
		if err := json.Unmarshal(resp.ResultJSON, &out); err != nil {
			return hostsvc.CapabilityResult{}, status.Error(codes.Internal, "解析 Compose 响应失败")
		}
		return hostsvc.CapabilityResult{
			Response: &dockerv1.ComposeActionResponse{
				Output:   out.Output,
				Warnings: out.Warnings,
			},
		}, nil

	case "ListBindableIPs":
		if _, ok := call.Request.(*dockerv1.ListBindableIPsRequest); !ok {
			return hostsvc.CapabilityResult{}, status.Error(codes.InvalidArgument, "无效的 ListBindableIPs 请求")
		}
		resp, err := f.Helper.Call(ctx, sandbox.CapabilityRequest{Op: "docker.bindable_ips", ID: callerID, ParamsJSON: []byte("{}")})
		if err != nil {
			return hostsvc.CapabilityResult{}, status.Error(codes.Unavailable, "调用 Docker 网卡探测辅助进程失败")
		}
		if !resp.OK {
			return helperFail(resp), nil
		}
		var out BindableIPsOutput
		if err := json.Unmarshal(resp.ResultJSON, &out); err != nil {
			return hostsvc.CapabilityResult{}, status.Error(codes.Internal, "解析可绑定 IP 响应失败")
		}
		pbIPs := make([]*dockerv1.BindableIP, 0, len(out.IPs))
		for _, item := range out.IPs {
			fam := "ipv4"
			if item.IsIPv6 {
				fam = "ipv6"
			}
			pbIPs = append(pbIPs, &dockerv1.BindableIP{
				Ip:          item.IP,
				Family:      fam,
				Iface:       item.Interface,
				Scope:       item.Scope,
				Recommended: item.IP == "127.0.0.1",
				Label:       item.Label,
				IsIpv6:      item.IsIPv6,
			})
		}
		return hostsvc.CapabilityResult{
			Response: &dockerv1.ListBindableIPsResponse{Ips: pbIPs},
		}, nil

	case "CreateNetwork":
		req, ok := call.Request.(*dockerv1.CreateNetworkRequest)
		if !ok {
			return hostsvc.CapabilityResult{}, status.Error(codes.InvalidArgument, "无效的 CreateNetwork 请求")
		}
		payload, err := json.Marshal(CreateNetworkInput{
			Name:       req.GetName(),
			Driver:     req.GetDriver(),
			Internal:   req.GetInternal(),
			EnableIPv6: req.GetEnableIpv6(),
			SubnetCIDR: req.GetSubnet(),
			GatewayIP:  req.GetGateway(),
			Labels:     req.GetLabels(),
		})
		if err != nil {
			return hostsvc.CapabilityResult{}, status.Error(codes.Internal, "编码 CreateNetwork 请求失败")
		}
		resp, err := f.Helper.Call(ctx, sandbox.CapabilityRequest{Op: "docker.network.create", ID: callerID, ParamsJSON: payload})
		if err != nil {
			return hostsvc.CapabilityResult{}, status.Error(codes.Unavailable, "调用 Docker 网络创建辅助进程失败")
		}
		if !resp.OK {
			return helperFail(resp), nil
		}
		var out CreateNetworkOutput
		if err := json.Unmarshal(resp.ResultJSON, &out); err != nil {
			return hostsvc.CapabilityResult{}, status.Error(codes.Internal, "解析 CreateNetwork 响应失败")
		}
		return hostsvc.CapabilityResult{
			Response: &dockerv1.CreateNetworkResponse{
				NetworkId: out.NetworkID,
				Name:      out.Name,
			},
		}, nil

	case "MutateContainerNetwork":
		req, ok := call.Request.(*dockerv1.MutateContainerNetworkRequest)
		if !ok {
			return hostsvc.CapabilityResult{}, status.Error(codes.InvalidArgument, "无效的 MutateContainerNetwork 请求")
		}
		payload, err := json.Marshal(NetworkMembershipInput{
			ContainerID: req.GetContainerId(),
			NetworkID:   req.GetNetworkId(),
			Action:      req.GetAction(),
			Aliases:     req.GetAliases(),
			IPv4Address: req.GetIpv4Address(),
			IPv6Address: req.GetIpv6Address(),
			Force:       req.GetForce(),
		})
		if err != nil {
			return hostsvc.CapabilityResult{}, status.Error(codes.Internal, "编码 MutateContainerNetwork 请求失败")
		}
		resp, err := f.Helper.Call(ctx, sandbox.CapabilityRequest{Op: "docker.network.membership", ID: callerID, ParamsJSON: payload})
		if err != nil {
			return hostsvc.CapabilityResult{}, status.Error(codes.Unavailable, "调用 Docker 网络挂载辅助进程失败")
		}
		if !resp.OK {
			return helperFail(resp), nil
		}
		return hostsvc.CapabilityResult{
			Response: &dockerv1.MutateContainerNetworkResponse{Ok: true},
		}, nil

	case "RecreateContainerPorts":
		req, ok := call.Request.(*dockerv1.RecreateContainerPortsRequest)
		if !ok {
			return hostsvc.CapabilityResult{}, status.Error(codes.InvalidArgument, "无效的 RecreateContainerPorts 请求")
		}
		rules := make([]PortMappingRule, 0, len(req.GetBindings()))
		for _, b := range req.GetBindings() {
			if b.GetContainerPort() < 1 || b.GetContainerPort() > 65535 || b.GetHostPort() < 0 || b.GetHostPort() > 65535 {
				return hostsvc.CapabilityResult{}, status.Error(codes.InvalidArgument, "端口编号超出 1..65535 范围")
			}
			mode := strings.TrimSpace(b.GetBindMode())
			hostIP := strings.TrimSpace(b.GetHostIp())
			if mode == "" {
				switch hostIP {
				case "", "127.0.0.1":
					mode = "loopback"
				case "0.0.0.0":
					mode = "public"
				default:
					mode = "specific_ip"
				}
			}
			rules = append(rules, PortMappingRule{
				BindMode:      mode,
				BindIP:        hostIP,
				IncludeIPv6:   b.GetIncludeIpv6(),
				HostPort:      uint16(b.GetHostPort()),
				ContainerPort: uint16(b.GetContainerPort()),
				Protocol:      b.GetProtocol(),
			})
		}
		var startAfter *bool
		if req.StartAfterRecreate != nil {
			v := req.GetStartAfterRecreate()
			startAfter = &v
		}
		payload, err := json.Marshal(RecreatePortsInput{
			ContainerID:               req.GetContainerId(),
			Rules:                     rules,
			CommitWritableLayer:       req.GetCommitWritableLayer(),
			AllowDiscardWritableLayer: req.GetAllowDiscardWritableLayer() || req.GetAllowPortOverride(),
			StartAfterRecreate:        startAfter,
			ReservedHostPorts:         f.reservedHostPorts(),
		})
		if err != nil {
			return hostsvc.CapabilityResult{}, status.Error(codes.Internal, "编码 RecreateContainerPorts 请求失败")
		}
		resp, err := f.Helper.Call(ctx, sandbox.CapabilityRequest{Op: "docker.recreate_ports", ID: callerID, ParamsJSON: payload})
		if err != nil {
			return hostsvc.CapabilityResult{}, status.Error(codes.Unavailable, "调用 Docker 端口重建辅助进程失败")
		}
		if !resp.OK {
			return helperFail(resp), nil
		}
		var out RecreatePortsOutput
		if err := json.Unmarshal(resp.ResultJSON, &out); err != nil {
			return hostsvc.CapabilityResult{}, status.Error(codes.Internal, "解析 RecreateContainerPorts 响应失败")
		}
		applied := make([]*dockerv1.PortBindingSpec, 0, len(out.AppliedRules))
		for _, r := range out.AppliedRules {
			applied = append(applied, &dockerv1.PortBindingSpec{
				ContainerPort: int32(r.ContainerPort),
				Protocol:      r.Protocol,
				HostIp:        r.BindIP,
				HostPort:      int32(r.HostPort),
				BindMode:      r.BindMode,
				IncludeIpv6:   r.IncludeIPv6,
			})
		}
		return hostsvc.CapabilityResult{
			Response: &dockerv1.RecreateContainerPortsResponse{
				NewContainerId:    out.NewContainerID,
				OldContainerId:    out.OldContainerID,
				CommittedImage:    out.CommittedSnapshot,
				ContainerName:     out.ContainerName,
				AppliedBindings:   applied,
				WritableSizeBytes: out.WritableSizeBytes,
			},
		}, nil

	default:
		return hostsvc.CapabilityResult{}, status.Error(codes.Unimplemented, "不支持的 docker 能力方法")
	}
}

func helperFail(resp sandbox.CapabilityResponse) hostsvc.CapabilityResult {
	code := resp.Code
	if code == "" {
		code = "INTERNAL"
	}
	return hostsvc.CapabilityResult{
		Error: &hostsvc.DomainError{Code: code, Message: resp.Error},
	}
}
