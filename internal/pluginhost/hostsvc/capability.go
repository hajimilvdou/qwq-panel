// SPDX-License-Identifier: AGPL-3.0-only

package hostsvc

import (
	"context"
	"regexp"
	"time"

	platformv1 "github.com/qwq-panel/qwq/sdk/gen/qwq/platform/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// ======================== 宿主能力授权门 ========================
const maxCapabilityRequestBytes = 1 << 20

var capabilityUserPattern = regexp.MustCompile(`^[a-z_][a-z0-9_.-]{0,31}$`)
var capabilityPluginPattern = regexp.MustCompile(`^[a-z][a-z0-9._-]{0,63}$`)

type capabilityPolicy struct {
	service, method, verb, name  string
	write, account, targetPlugin bool
}

type capabilityGate struct {
	grants                 map[string]struct{}
	writes, scans, metrics *tokenBucket
}

func newCapabilityGate(grants []*platformv1.Capability, limits Limits) *capabilityGate {
	gate := &capabilityGate{
		grants:  make(map[string]struct{}, len(grants)),
		writes:  newTokenBucket(limits.CapabilityWritesPerMinute, defaultBurst(limits.CapabilityWritesPerMinute)),
		scans:   newTokenBucket(limits.BanScansPerMinute, 1),
		metrics: newTokenBucket(limits.MetricsReadsPerMinute, 2),
	}
	for _, grant := range grants {
		gate.grants[grant.Name+"\x00"+grant.Scope] = struct{}{}
	}
	return gate
}

func capabilityMatches(capabilities []*platformv1.Capability, name, scope string, account bool) bool {
	for _, capability := range capabilities {
		if capability != nil && capability.Name == name && (capability.Scope == scope || (account && capability.Scope == "all")) {
			return true
		}
	}
	return false
}

func (g *capabilityGate) granted(policy capabilityPolicy, scope string) bool {
	_, ok := g.grants[policy.name+"\x00"+scope]
	if !ok && policy.account {
		_, ok = g.grants[policy.name+"\x00all"]
	}
	return ok
}

func (s *Server) authorizeCapability(ctx context.Context, request proto.Message, policy capabilityPolicy) (CapabilityCall, error) {
	if request == nil || proto.Size(request) > maxCapabilityRequestBytes {
		return CapabilityCall{}, status.Error(codes.ResourceExhausted, "能力请求超过 1 MiB")
	}
	scope := "self"
	if policy.account {
		user, ok := request.(interface{ GetUser() string })
		if !ok || !capabilityUserPattern.MatchString(user.GetUser()) {
			return CapabilityCall{}, invalidArg("系统用户名格式无效")
		}
		scope = user.GetUser()
	} else if policy.targetPlugin {
		target, ok := request.(interface{ GetTargetPluginId() string })
		if !ok || !capabilityPluginPattern.MatchString(target.GetTargetPluginId()) {
			return CapabilityCall{}, invalidArg("目标插件标识格式无效")
		}
		scope = target.GetTargetPluginId()
	}
	if !s.capabilities.granted(policy, scope) {
		return CapabilityCall{}, status.Error(codes.PermissionDenied, "实例未获授此能力或作用域")
	}
	meta := callMeta{}
	if contextual, ok := request.(interface {
		GetContext() *platformv1.HostCallContext
	}); ok {
		meta = callMetaOf(contextual.GetContext())
	}
	if policy.write {
		if meta.OperationID == "" {
			return CapabilityCall{}, status.Error(codes.FailedPrecondition, "能力写入需要正在派发的 operation")
		}
		if s.cfg.OperationResolver == nil {
			return CapabilityCall{}, unavailable("operation resolver")
		}
		binding, err := s.cfg.OperationResolver.Resolve(ctx, s.cfg.InstanceID, meta.OperationID)
		if err != nil {
			return CapabilityCall{}, capabilityFailure(err)
		}
		if !binding.Dispatched || (binding.Effect != "write" && binding.Effect != "destructive") || !capabilityMatches(binding.Capabilities, policy.name, scope, policy.account) {
			return CapabilityCall{}, status.Error(codes.PermissionDenied, "operation 未派发给本实例或未声明对应写能力")
		}
	}
	if s.cfg.CapabilityForwarder == nil {
		return CapabilityCall{}, unavailable("capability forwarder")
	}
	bucket := (*tokenBucket)(nil)
	switch {
	case policy.write:
		bucket = s.capabilities.writes
	case policy.verb == "ban.scan":
		bucket = s.capabilities.scans
	case policy.service == "metrics":
		bucket = s.capabilities.metrics
	}
	if bucket != nil && !bucket.allow(s.clock.Now()) {
		return CapabilityCall{}, status.Error(codes.ResourceExhausted, "能力调用超过频率上限")
	}
	return CapabilityCall{
		PluginID: s.cfg.PluginID, InstanceID: s.cfg.InstanceID, OperationID: meta.OperationID, TraceID: meta.TraceID,
		Service: policy.service, Method: policy.method, Verb: policy.verb, Capability: policy.name, Scope: scope, Write: policy.write,
		Request: proto.Clone(request),
	}, nil
}

// forwardCapability 是强类型能力 RPC 的共用执行路径；授权、限频、审计与错误
// 处理只在此实现一次。适配器只保留协议类型转换，不复制安全逻辑。
func forwardCapability[T proto.Message](s *Server, ctx context.Context, request proto.Message, policy capabilityPolicy, empty T) (T, error) {
	var zero T
	call, err := s.authorizeCapability(ctx, request, policy)
	if err != nil {
		return zero, err
	}
	if call.Write {
		if err := s.auditCapability(ctx, call, AuditSuccess, "started"); err != nil {
			return zero, capabilityAuditFailure(err, false)
		}
	}
	var result CapabilityResult
	if err = ctx.Err(); err == nil {
		result, err = safeCapabilityForward(s.cfg.CapabilityForwarder, ctx, call)
	}
	response := empty
	if err == nil && result.Error != nil {
		if setErr := setCapabilityDomainError(response, result.Error); setErr != nil {
			err = setErr
		} else {
			err = nil
		}
	} else if err == nil {
		var ok bool
		response, ok = result.Response.(T)
		if !ok || !response.ProtoReflect().IsValid() {
			err = status.Error(codes.Internal, "能力转发器响应类型无效")
		}
	}
	if call.Write {
		outcome := AuditSuccess
		if err != nil || capabilityDomainFailed(response) {
			outcome = AuditFailure
		}
		// 执行已可能改变系统；取消不应阻止终态审计，但审计等待仍有独立硬上限。
		auditCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
		auditErr := s.auditCapability(auditCtx, call, outcome, "finished")
		cancel()
		if auditErr != nil {
			return zero, capabilityAuditFailure(auditErr, true)
		}
	}
	if err != nil {
		return zero, capabilityFailure(err)
	}
	return response, nil
}

func safeCapabilityForward(forwarder CapabilityForwarder, ctx context.Context, call CapabilityCall) (result CapabilityResult, err error) {
	defer func() {
		if recover() != nil {
			result = CapabilityResult{}
			err = status.Error(codes.Internal, "能力执行器发生内部错误")
		}
	}()
	return forwarder.Forward(ctx, call)
}

func setCapabilityDomainError(response proto.Message, failure *DomainError) error {
	if failure.Code == "" || len(failure.DetailsJSON) > maxDetailsJSON || validateDetailsJSON(failure.DetailsJSON) != nil {
		return status.Error(codes.Internal, "能力业务错误格式无效")
	}
	detail := &platformv1.ErrorDetail{Code: clipString(failure.Code, 128), Message: clipString(failure.Message, 1024), Retryable: failure.Retryable, DetailsJson: append([]byte(nil), failure.DetailsJSON...)}
	message := response.ProtoReflect()
	field := message.Descriptor().Fields().ByName("error")
	if field == nil {
		return status.Error(codes.Internal, "能力响应缺少错误字段")
	}
	message.Set(field, protoreflect.ValueOfMessage(detail.ProtoReflect()))
	return nil
}

func capabilityDomainFailed(response proto.Message) bool {
	withError, ok := response.(interface {
		GetError() *platformv1.ErrorDetail
	})
	return ok && withError.GetError().GetCode() != ""
}

func (s *Server) auditCapability(ctx context.Context, call CapabilityCall, outcome AuditOutcome, phase string) error {
	return s.writeAudit(ctx, AuditRecord{
		Action: "capability." + call.Verb, Subject: "capabilities/" + call.Capability + "/" + call.Scope, Outcome: outcome,
		OperationID: call.OperationID, TraceID: call.TraceID, DetailsJSON: []byte(`{"phase":"` + phase + `"}`),
	})
}

// capabilityFailure 不把执行器的 argv、私钥、口令或原始错误内容带入响应/日志。
func capabilityFailure(err error) error {
	code := status.Code(statusFromError(err))
	if code == codes.OK || code == codes.Unknown {
		code = codes.Internal
	}
	return status.Error(code, "宿主能力调用失败")
}

func capabilityAuditFailure(err error, executed bool) error {
	code := status.Code(statusFromError(err))
	if code == codes.Internal {
		code = codes.Unavailable
	}
	message := "能力写入无法审计，未执行"
	if executed {
		message = "能力操作可能已完成，审计确认失败；请重读状态"
	}
	return status.Error(code, message)
}
