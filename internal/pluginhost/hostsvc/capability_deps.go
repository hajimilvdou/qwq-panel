// SPDX-License-Identifier: AGPL-3.0-only

package hostsvc

import (
	"context"

	platformv1 "github.com/qwq-panel/qwq/sdk/gen/qwq/platform/v1"
	"google.golang.org/protobuf/proto"
)

// OperationBinding 是宿主确认的派发与权限快照，不能来自插件消息。
type OperationBinding struct {
	Dispatched   bool
	Capabilities []*platformv1.Capability
	Effect       string
}

// OperationResolver 校验 operation 是否仍派发给本实例，并返回其声明能力。
type OperationResolver interface {
	Resolve(ctx context.Context, instanceID, operationID string) (OperationBinding, error)
}

// CapabilityCall 只由能力门构造。身份与方法由宿主确定，Request 仍须由具体
// forwarder 校验；保留端口、会话地址和密码等宿主事实不取自 Request。
type CapabilityCall struct {
	PluginID    string
	InstanceID  string
	OperationID string
	TraceID     string
	Service     string
	Method      string
	Verb        string
	Capability  string
	Scope       string
	Write       bool
	Request     proto.Message
}

// String 防止调试日志展开含公钥、引用或敏感配置的请求体。
func (CapabilityCall) String() string { return "hostsvc.CapabilityCall{[REDACTED]}" }

// GoString 同样保护 %#v。
func (CapabilityCall) GoString() string { return "hostsvc.CapabilityCall{[REDACTED]}" }

// CapabilityResult 携带本 RPC 的强类型响应。Error 复用既有 DomainError；
// 能力适配器会将其编码为对应响应的 ErrorDetail，保持 gRPC OK。
type CapabilityResult struct {
	Response proto.Message
	Error    *DomainError
}

// CapabilityForwarder 只执行已经过授权门的白名单 RPC；具体实现负责参数校验、
// 宿主事实注入和执行。metrics 在宿主本地实现，其他能力通过独立 helper。
type CapabilityForwarder interface {
	Forward(ctx context.Context, call CapabilityCall) (CapabilityResult, error)
}

func cloneCapabilities(capabilities []*platformv1.Capability) []*platformv1.Capability {
	cloned := make([]*platformv1.Capability, 0, len(capabilities))
	for _, capability := range capabilities {
		if capability != nil {
			cloned = append(cloned, &platformv1.Capability{Name: capability.Name, Scope: capability.Scope})
		}
	}
	return cloned
}
