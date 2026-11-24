// SPDX-License-Identifier: AGPL-3.0-only

package controller

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"time"
	"unicode/utf8"

	"github.com/qwq-panel/qwq/internal/actor"
	"github.com/qwq-panel/qwq/internal/platform/problem"
	"github.com/qwq-panel/qwq/internal/prerequisites/certificates"
	"github.com/qwq-panel/qwq/internal/prerequisites/consumerfiles"
	"github.com/qwq-panel/qwq/internal/prerequisites/deployment"
	"github.com/qwq-panel/qwq/internal/prerequisites/fault"
	"github.com/qwq-panel/qwq/internal/prerequisites/names"
	corev2 "github.com/qwq-panel/qwq/sdk/coreapi/v2"
	platformv1 "github.com/qwq-panel/qwq/sdk/gen/qwq/platform/v1"
)

// ======================== 消费者插件 TLS 运行时桥接契约（无私钥跨 gRPC 传输） ========================

const (
	// ConsumerTLSReloadOperation 触发消费者插件从自身 StateDirectory 重载已落盘证书。
	ConsumerTLSReloadOperation = "tls.reload"
	// ConsumerTLSInspectOperation 只读查询消费者插件当前生效的 TLS 绑定状态与端点。
	ConsumerTLSInspectOperation = "tls.inspect"
	// ConsumerTLSAPIVersion 固定消费者 TLS 控制面的 ABI 版本。
	ConsumerTLSAPIVersion = "v2"

	maxConsumerTLSInspectResponse = 16 << 10
)

// ConsumerTLSReloadPayload 仅传递声明式绑定与摘要证明；证书与私钥文件由插件从自身私有目录读取。
type ConsumerTLSReloadPayload struct {
	BindingRef       string `json:"binding_ref"`
	ProfileID        string `json:"profile_id"`
	Generation       uint64 `json:"generation"`
	PolicyRevision   string `json:"policy_revision"`
	FullchainSHA256  string `json:"fullchain_sha256"`
	PrivateKeySHA256 string `json:"private_key_sha256"`
	SNI              string `json:"sni"`
}

func (ConsumerTLSReloadPayload) String() string {
	return "controller.ConsumerTLSReloadPayload{[REDACTED]}"
}
func (ConsumerTLSReloadPayload) GoString() string {
	return "controller.ConsumerTLSReloadPayload{[REDACTED]}"
}

// ConsumerTLSInspectPayload 指定要观测的绑定引用与配置 profile。
type ConsumerTLSInspectPayload struct {
	BindingRef string `json:"binding_ref"`
	ProfileID  string `json:"profile_id"`
}

// ConsumerTLSInspectResult 描述消费者插件汇报的当前运行时加载状态与监听端点。
type ConsumerTLSInspectResult struct {
	Running         bool   `json:"running"`
	BindingRef      string `json:"binding_ref"`
	Generation      uint64 `json:"generation"`
	PolicyRevision  string `json:"policy_revision"`
	FullchainSHA256 string `json:"fullchain_sha256"`
	LeafFingerprint string `json:"leaf_fingerprint"`
	SNI             string `json:"sni"`
	Endpoint        string `json:"endpoint"`
}

// ======================== 宿主消费者运行时实现 ========================

// PluginConsumerRuntime 把 deployment.ConsumerRuntime 桥接到受管插件控制面与已提交配置快照。
type PluginConsumerRuntime struct {
	Controller *Controller
	// invoke 仅测试注入覆盖插件 RPC 调用；生产为 nil，走 Controller.PluginRuntime()。
	invoke func(ctx context.Context, pluginID, operation string, payload []byte) ([]byte, error)
}

var _ deployment.ConsumerRuntime = (*PluginConsumerRuntime)(nil)

// Apply 确认消费者插件已安装且持有合法 v2 配置后，向其下发仅含证明摘要的热加载通知。
func (r *PluginConsumerRuntime) Apply(ctx context.Context, binding certificates.HostBinding, proof consumerfiles.Proof) error {
	if ctx == nil {
		return fault.New("CONSUMER_RUNTIME_INVALID", "消费者运行时热加载需要明确的 context")
	}
	if err := ctx.Err(); err != nil {
		return errors.Join(fault.New("CANCELLED", "消费者运行时热加载已取消"), err)
	}
	if r == nil || r.Controller == nil || r.Controller.closed.Load() {
		return fault.New("BACKEND_REQUIRED", "消费者运行时控制器尚未装配")
	}
	if binding != proof.Binding ||
		!names.ID(binding.ID) ||
		binding.Generation == 0 ||
		!names.ID(binding.PolicyRevision) ||
		binding.Consumer.PluginID == "" ||
		binding.Consumer.ProfileID == "" ||
		binding.Consumer.SNI == "" ||
		proof.FullchainSHA256 == "" ||
		proof.PrivateKeySHA256 == "" {
		return fault.New("CONSUMER_RUNTIME_INVALID", "热加载目标绑定与材料证明不一致或字段缺失")
	}

	snapshot, err := r.Controller.readPrerequisiteConfiguration(ctx, binding.Consumer.PluginID)
	if err != nil {
		return mapConsumerRuntimeError(err, "消费者插件未安装或已提交配置不可确认")
	}
	defer clear(snapshot.config.Config)
	if !snapshot.found {
		return fault.New("CONSUMER_RUNTIME_INVALID", "消费者插件尚无已提交配置")
	}
	intent, err := corev2.Decode(snapshot.config.Config)
	if err != nil || corev2.Validate(intent) != nil {
		return fault.New("CONSUMER_RUNTIME_INVALID", "已提交的消费者配置无效")
	}

	payload, err := json.Marshal(ConsumerTLSReloadPayload{
		BindingRef:       binding.ID,
		ProfileID:        binding.Consumer.ProfileID,
		Generation:       binding.Generation,
		PolicyRevision:   binding.PolicyRevision,
		FullchainSHA256:  proof.FullchainSHA256,
		PrivateKeySHA256: proof.PrivateKeySHA256,
		SNI:              binding.Consumer.SNI,
	})
	if err != nil {
		return fault.New("CONSUMER_RUNTIME_INVALID", "消费者热加载载荷编码失败")
	}
	defer clear(payload)

	if _, err := r.invokePlugin(ctx, binding.Consumer.PluginID, ConsumerTLSReloadOperation, payload, true); err != nil {
		return mapConsumerRuntimeError(err, "消费者运行时热加载失败")
	}
	return nil
}

// Inspect 查询已运行插件的 TLS 绑定状态；绝不拉起已停止插件，未运行时返回 Running=false。
func (r *PluginConsumerRuntime) Inspect(ctx context.Context, consumer certificates.Consumer, bindingID string) (deployment.RuntimeObservation, error) {
	if ctx == nil {
		return deployment.RuntimeObservation{}, fault.New("CONSUMER_RUNTIME_INVALID", "消费者运行时检查需要明确的 context")
	}
	if err := ctx.Err(); err != nil {
		return deployment.RuntimeObservation{}, errors.Join(fault.New("CANCELLED", "消费者运行时检查已取消"), err)
	}
	if r == nil || r.Controller == nil || r.Controller.closed.Load() {
		return deployment.RuntimeObservation{}, fault.New("BACKEND_REQUIRED", "消费者运行时控制器尚未装配")
	}
	if !names.ID(bindingID) || consumer.PluginID == "" || consumer.ProfileID == "" {
		return deployment.RuntimeObservation{}, fault.New("CONSUMER_RUNTIME_INVALID", "消费者运行时检查参数无效")
	}

	payload, err := json.Marshal(ConsumerTLSInspectPayload{
		BindingRef: bindingID,
		ProfileID:  consumer.ProfileID,
	})
	if err != nil {
		return deployment.RuntimeObservation{}, fault.New("CONSUMER_RUNTIME_INVALID", "消费者状态查询载荷编码失败")
	}

	raw, err := r.invokePlugin(ctx, consumer.PluginID, ConsumerTLSInspectOperation, payload, false)
	if err != nil {
		if problem.HasCode(err, problem.PluginUnavailable) {
			return deployment.RuntimeObservation{Running: false}, nil
		}
		return deployment.RuntimeObservation{}, mapConsumerRuntimeError(err, "消费者运行时状态查询失败")
	}

	result, err := decodeConsumerTLSInspectResult(raw)
	if err != nil {
		return deployment.RuntimeObservation{}, err
	}
	return deployment.RuntimeObservation{
		Running:          result.Running,
		BindingID:        result.BindingRef,
		ActiveGeneration: result.Generation,
		PolicyRevision:   result.PolicyRevision,
		FullchainSHA256:  result.FullchainSHA256,
		LeafFingerprint:  result.LeafFingerprint,
		SNI:              result.SNI,
		Endpoint:         result.Endpoint,
	}, nil
}

// InUse 同时核验已提交配置引用与活跃运行时占用；后端缺失或状态查询失败一律 fail-closed 返回 true。
func (r *PluginConsumerRuntime) InUse(ctx context.Context, binding certificates.HostBinding) (bool, error) {
	if ctx == nil {
		return true, fault.New("CONSUMER_RUNTIME_INVALID", "消费者占用检查需要明确的 context")
	}
	if err := ctx.Err(); err != nil {
		return true, errors.Join(fault.New("CANCELLED", "消费者占用检查已取消"), err)
	}
	if r == nil || r.Controller == nil || r.Controller.closed.Load() {
		return true, fault.New("BACKEND_REQUIRED", "消费者运行时控制器尚未装配")
	}
	if !names.ID(binding.ID) || binding.Consumer.PluginID == "" {
		return true, fault.New("CONSUMER_RUNTIME_INVALID", "消费者占用检查绑定参数无效")
	}
	u := r.Controller.Updater()
	if u == nil {
		return true, fault.New("BACKEND_REQUIRED", "插件配置来源尚未装配")
	}

	// 第一步：检查已提交的活跃配置是否仍引用该绑定。
	snapshot, err := r.Controller.readPrerequisiteConfiguration(ctx, binding.Consumer.PluginID)
	if err == nil {
		defer clear(snapshot.config.Config)
		if snapshot.found {
			intent, decErr := corev2.Decode(snapshot.config.Config)
			if decErr != nil {
				return true, fault.New("CONSUMER_RUNTIME_INVALID", "已提交的消费者配置无法解析")
			}
			if ProfileUsesBindingRef(intent, binding.ID) {
				return true, nil
			}
		}
	} else if problem.HasCode(err, problem.PermissionDenied) {
		// 仅当插件确实已卸载、已禁用或不具备 v2 契约时，才视为配置侧未占用；其余异常一律 fail-closed。
		version, installed := u.Active(binding.Consumer.PluginID)
		if installed {
			enabled, enErr := u.Enabled(ctx, binding.Consumer.PluginID)
			if enErr != nil {
				return true, mapConsumerRuntimeError(enErr, "无法确认消费者插件启用状态")
			}
			if enabled && supportsPrerequisiteConsumer(version, binding.Consumer.PluginID) {
				return true, mapConsumerRuntimeError(err, "无法确认已提交的消费者配置占用状态")
			}
		}
	} else {
		return true, mapConsumerRuntimeError(err, "无法读取消费者配置占用状态")
	}

	// 第二步：检查运行中的插件实例是否仍持有非零代次。
	obs, err := r.Inspect(ctx, binding.Consumer, binding.ID)
	if err != nil {
		return true, err
	}
	if obs.Running && obs.ActiveGeneration > 0 {
		return true, nil
	}
	return false, nil
}

func (r *PluginConsumerRuntime) invokePlugin(ctx context.Context, pluginID, operation string, payload []byte, attach bool) ([]byte, error) {
	if r.invoke != nil {
		return r.invoke(ctx, pluginID, operation, payload)
	}
	rt := r.Controller.PluginRuntime()
	if rt == nil {
		return nil, fault.New("BACKEND_REQUIRED", "插件运行时尚未装配")
	}
	var (
		client PluginClient
		err    error
	)
	if attach {
		client, err = rt.attach(ctx, pluginID)
	} else {
		client, err = rt.live(pluginID)
	}
	if err != nil {
		return nil, err
	}
	nodeID := rt.opts.NodeID
	if r.Controller.ops != nil {
		nodeID = r.Controller.ops.NodeID()
	}
	resp, err := client.Invoke(ctx, &platformv1.InvokeRequest{
		Context: requestContext(
			nodeID,
			DefaultInstanceID,
			"",
			"",
			"",
			"",
			actor.Actor{Kind: actor.System, ID: "host:tls-deployer"},
		),
		Operation:   operation,
		ApiVersion:  ConsumerTLSAPIVersion,
		PayloadJson: payload,
	})
	if err != nil {
		return nil, problem.From(err)
	}
	return resp.GetPayloadJson(), nil
}

func decodeConsumerTLSInspectResult(raw []byte) (ConsumerTLSInspectResult, error) {
	if len(raw) == 0 || len(raw) > maxConsumerTLSInspectResponse || !utf8.Valid(raw) {
		return ConsumerTLSInspectResult{}, fault.New("CONSUMER_RUNTIME_INVALID", "消费者运行时状态响应长度或编码无效")
	}
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return ConsumerTLSInspectResult{}, fault.New("CONSUMER_RUNTIME_INVALID", "消费者运行时状态响应必须是 JSON 对象")
	}
	dec := json.NewDecoder(bytes.NewReader(trimmed))
	dec.DisallowUnknownFields()
	var result ConsumerTLSInspectResult
	if err := dec.Decode(&result); err != nil {
		return ConsumerTLSInspectResult{}, fault.New("CONSUMER_RUNTIME_INVALID", "消费者运行时状态响应字段无效")
	}
	if err := dec.Decode(new(any)); !errors.Is(err, io.EOF) {
		return ConsumerTLSInspectResult{}, fault.New("CONSUMER_RUNTIME_INVALID", "消费者运行时状态响应包含多余内容")
	}
	return result, nil
}

func mapConsumerRuntimeError(err error, fallbackDetail string) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return errors.Join(fault.New("CANCELLED", "消费者运行时操作已取消"), err)
	}
	var fe *fault.Error
	if errors.As(err, &fe) {
		return fe
	}
	if problem.HasCode(err, problem.Unavailable) {
		return fault.New("BACKEND_REQUIRED", fallbackDetail)
	}
	return fault.New("CONSUMER_RUNTIME_ERROR", fallbackDetail)
}

// IngressHTTP01Presenter 通过内置 web.ingress 的 ingress.acme.{present,cleanup} 操作完成免 DNS Token 的 HTTP-01 验证。
type IngressHTTP01Presenter struct {
	Controller *Controller
}

func (p *IngressHTTP01Presenter) Present(ctx context.Context, token, keyAuth string, ttl time.Duration) error {
	payload, err := json.Marshal(map[string]any{
		"token":       token,
		"key_auth":    keyAuth,
		"ttl_seconds": max(30, int(ttl.Seconds())),
	})
	if err != nil {
		return fault.New("INTERNAL", "编码 ACME HTTP-01 验证请求失败")
	}
	return p.invoke(ctx, "ingress.acme.present", payload)
}

func (p *IngressHTTP01Presenter) CleanUp(ctx context.Context, token string) error {
	payload, err := json.Marshal(map[string]any{"token": token})
	if err != nil {
		return nil
	}
	return p.invoke(ctx, "ingress.acme.cleanup", payload)
}

func (p *IngressHTTP01Presenter) invoke(ctx context.Context, operation string, payload []byte) error {
	if p == nil || p.Controller == nil {
		return fault.New("HTTP01_UNAVAILABLE", "控制器尚未装配，无法调用 web.ingress HTTP-01 通道")
	}
	rt := p.Controller.PluginRuntime()
	if rt == nil {
		return fault.New("HTTP01_UNAVAILABLE", "插件运行时尚未装配，请先安装并启用 web.ingress 插件")
	}
	client, err := rt.attach(ctx, "web.ingress")
	if err != nil {
		return fault.New("HTTP01_UNAVAILABLE", "未检测到运行中的 web.ingress 插件，请先在应用商店安装并启用 web.ingress（确保 80 端口可达）")
	}
	nodeID := rt.opts.NodeID
	if p.Controller.ops != nil {
		nodeID = p.Controller.ops.NodeID()
	}
	resp, err := client.Invoke(ctx, &platformv1.InvokeRequest{
		Context: requestContext(
			nodeID,
			DefaultInstanceID,
			"",
			"",
			"",
			"",
			actor.Actor{Kind: actor.System, ID: "host:acme-http01"},
		),
		Operation:   operation,
		ApiVersion:  "v1",
		PayloadJson: payload,
	})
	if err != nil {
		return fault.New("HTTP01_UNAVAILABLE", "调用 web.ingress HTTP-01 验证接口失败: "+err.Error())
	}
	if e := resp.GetError(); e != nil && e.GetCode() != "" {
		msg := e.GetMessage()
		if msg == "" {
			msg = e.GetCode()
		}
		return fault.New("HTTP01_UNAVAILABLE", msg)
	}
	return nil
}
