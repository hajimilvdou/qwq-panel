// SPDX-License-Identifier: AGPL-3.0-only

package docker

import (
	"context"
	"encoding/json"
	"net/http"

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
	Helper Helper
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
