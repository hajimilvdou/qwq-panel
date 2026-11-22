// SPDX-License-Identifier: AGPL-3.0-only

// Package bridge 复用宿主能力与独立 helper 的严格、有界转发约定。
package bridge

import (
	"context"
	"encoding/json"

	"github.com/qwq-panel/qwq/internal/pluginhost/hostsvc"
	"github.com/qwq-panel/qwq/internal/sandbox"
	platformv1 "github.com/qwq-panel/qwq/sdk/gen/qwq/platform/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

// Caller 的生产实现只重试连接失败，不重发已发送的能力写请求。
type Caller interface {
	Call(context.Context, sandbox.CapabilityRequest) (sandbox.CapabilityResponse, error)
}

// Invoke 只编码已由具体 forwarder 构造的参数；不接受外部 verb 或程序路径。
func Invoke(ctx context.Context, helper Caller, pluginID, verb string, params any, response proto.Message) (hostsvc.CapabilityResult, error) {
	raw, err := json.Marshal(params)
	if err != nil {
		return hostsvc.CapabilityResult{}, status.Error(codes.Internal, "能力请求编码失败")
	}
	defer clear(raw)
	return Exchange(ctx, helper, sandbox.CapabilityRequest{Op: verb, ID: pluginID, ParamsJSON: raw}, response)
}

// Exchange 将 helper 的原始错误映射为固定消息；执行器输出不会进入审计或响应。
func Exchange(ctx context.Context, helper Caller, request sandbox.CapabilityRequest, response proto.Message) (hostsvc.CapabilityResult, error) {
	if helper == nil || response == nil {
		return hostsvc.CapabilityResult{}, status.Error(codes.Unavailable, "宿主能力执行器未接入")
	}
	result, err := helper.Call(ctx, request)
	if err != nil {
		if ctx.Err() != nil {
			return hostsvc.CapabilityResult{}, status.FromContextError(ctx.Err()).Err()
		}
		return hostsvc.CapabilityResult{}, status.Error(codes.Unavailable, "宿主能力 helper 暂不可用")
	}
	defer clear(result.ResultJSON)
	if !result.OK {
		if result.Code == "UNIMPLEMENTED" {
			return hostsvc.CapabilityResult{}, status.Error(codes.Unimplemented, "宿主能力 helper 尚未支持该方法")
		}
		message, ok := domainMessages[result.Code]
		if !ok || len(result.ResultJSON) != 0 {
			return hostsvc.CapabilityResult{}, status.Error(codes.Unavailable, "能力 helper 返回了无效错误")
		}
		return hostsvc.CapabilityResult{Error: &hostsvc.DomainError{Code: result.Code, Message: message}}, nil
	}
	if result.Code != "" || result.Error != "" || len(result.ResultJSON) == 0 || protojson.Unmarshal(result.ResultJSON, response) != nil {
		return hostsvc.CapabilityResult{}, status.Error(codes.Unavailable, "能力 helper 返回了无效结果")
	}
	if detail, ok := response.(interface {
		GetError() *platformv1.ErrorDetail
	}); ok && detail.GetError() != nil {
		return hostsvc.CapabilityResult{}, status.Error(codes.Unavailable, "能力 helper 返回了矛盾结果")
	}
	return hostsvc.CapabilityResult{Response: response}, nil
}

var domainMessages = map[string]string{
	"VALIDATION_FAILED":   "能力参数或原生预检失败",
	"PRECONDITION_FAILED": "前置条件已变化，请重新预演",
	"PERMISSION_DENIED":   "能力资源或事务身份不匹配",
	"CONFLICT":            "资源被其他配置或管理者占用",
	"RESOURCE_EXHAUSTED":  "能力资源达到上限",
	"UNAVAILABLE":         "能力执行失败",
	"PORT_VERIFY_FAILED":  "新 SSH 端口验证失败，旧入口已保留",
	"RECOVERY_REQUIRED":   "恢复未完成，请检查实时状态",
	"RECOVERY_FAILED":     "恢复失败，请检查实时状态",
	"CANCELED":            "能力变更已取消",
	"INTERNAL":            "能力执行器发生内部错误",
}

// Failure 和 Pack 保持各能力一致的业务错误与 protobuf JSON 编码。
func Failure(code, message string) sandbox.CapabilityResponse {
	return sandbox.CapabilityResponse{Code: code, Error: message}
}

func Pack(message proto.Message) sandbox.CapabilityResponse {
	raw, err := protojson.Marshal(message)
	if err != nil {
		return Failure("INTERNAL", "能力结果编码失败")
	}
	return sandbox.CapabilityResponse{OK: true, ResultJSON: raw}
}
