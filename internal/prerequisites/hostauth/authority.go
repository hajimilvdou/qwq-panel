// SPDX-License-Identifier: AGPL-3.0-only

// Package hostauth 把固定模块作用域绑定到真实 operation、当前权限和私有登记。
package hostauth

import (
	"bytes"
	"context"
	"net/http"
	"strings"
	"sync"

	"github.com/qwq-panel/qwq/internal/actor"
	"github.com/qwq-panel/qwq/internal/authz"
	"github.com/qwq-panel/qwq/internal/operations"
	"github.com/qwq-panel/qwq/internal/platform/clock"
	"github.com/qwq-panel/qwq/internal/prerequisites/acme"
	"github.com/qwq-panel/qwq/internal/prerequisites/fault"
	"github.com/qwq-panel/qwq/internal/prerequisites/names"
	"github.com/qwq-panel/qwq/internal/prerequisites/store"
	"github.com/qwq-panel/qwq/internal/secrets"
	"github.com/qwq-panel/qwq/internal/storage"
)

// ======================== 宿主构造依赖与私有调用上下文 ========================

type Options struct {
	DB              *storage.DB
	Secrets         *secrets.Store
	Operations      *operations.Service
	Authorizer      *authz.Authorizer
	NodeID          string
	OwnerID         string
	HTTPClient      *http.Client
	Challenges      *acme.ChallengeSource
	Consumers       ConsumerSource
	Reservations    ConsumerReservationSource
	RenewalServices RenewalServiceSource
	Clock           clock.Clock
}

type Authority struct {
	operations      *operations.Service
	authorizer      *authz.Authorizer
	secrets         *secrets.Store
	db              *storage.DB
	repository      *store.EncryptedRepository
	nodeID          string
	ownerID         string
	httpClient      *http.Client
	challenges      *acme.ChallengeSource
	consumers       ConsumerSource
	reservations    ConsumerReservationSource
	renewalServices RenewalServiceSource
	clock           clock.Clock
}

// Invocation 由固定能力 forwarder 构造；operation/subject 不是 RPC 可选身份。
type Invocation struct {
	PluginID    string
	InstanceID  string
	OperationID string
	Operation   string
	Subject     string
}

func (Invocation) String() string               { return "hostauth.Invocation{[REDACTED]}" }
func (Invocation) GoString() string             { return "hostauth.Invocation{[REDACTED]}" }
func (Invocation) MarshalJSON() ([]byte, error) { return []byte(`{"redacted":true}`), nil }

type executionKey struct{}
type execution struct {
	mu         sync.RWMutex
	released   bool
	authority  *Authority
	invocation Invocation
	target     operations.DispatchTarget
	snapshot   operations.DispatchedContext
}

// 私有执行对象始终按指针传递；脱敏不读取可变状态，也不复制其中的互斥锁。
func (*execution) String() string               { return "hostauth.execution{[REDACTED]}" }
func (*execution) GoString() string             { return "hostauth.execution{[REDACTED]}" }
func (*execution) MarshalJSON() ([]byte, error) { return []byte(`{"redacted":true}`), nil }

func New(options Options) (*Authority, error) {
	if options.DB == nil || options.Secrets == nil || options.Operations == nil || options.Authorizer == nil {
		return nil, fault.New("BACKEND_REQUIRED", "准备能力需要真实 operation、身份、权限与加密后端")
	}
	if !names.ID(options.OwnerID) || !names.ID(options.NodeID) {
		return nil, fault.New("SCOPE_INVALID", "宿主资源登记作用域无效")
	}
	if options.Clock == nil {
		options.Clock = clock.System{}
	}
	repository, err := store.NewEncrypted(store.EncryptedOptions{DB: options.DB, Secrets: options.Secrets, Namespace: "authorizations"})
	if err != nil {
		return nil, err
	}
	return &Authority{operations: options.Operations, authorizer: options.Authorizer,
		secrets: options.Secrets, db: options.DB, repository: repository, nodeID: options.NodeID, ownerID: options.OwnerID, httpClient: options.HTTPClient,
		challenges: options.Challenges, consumers: options.Consumers, reservations: options.Reservations, renewalServices: options.RenewalServices, clock: options.Clock}, nil
}

// Begin 只接受宿主固定模块与真实派发。release 清除私有参数；后台任务必须在
// 自己的执行生命周期重新建立上下文，不能把此对象序列化或作为 bearer 保存。
func (a *Authority) Begin(ctx context.Context, call Invocation) (context.Context, func(), error) {
	if a == nil || ctx == nil || (call.PluginID != "domain.dns" && call.PluginID != "tls.certificates") || call.InstanceID != operations.ControllerDispatchInstance || !names.ID(call.OperationID) || call.Operation == "" || strings.ContainsAny(call.Operation, "/\x00\r\n") {
		return nil, nil, fault.New("PERMISSION_DENIED", "准备能力调用不属于固定宿主模块")
	}
	target := operations.DispatchTarget{ActionID: call.PluginID + "/" + call.Operation, NodeID: a.nodeID,
		PluginID: call.PluginID, InstanceID: call.InstanceID, Subject: call.Subject}
	snapshot, err := a.operations.ResolveDispatched(ctx, target, call.OperationID)
	if err != nil {
		return nil, nil, err
	}
	if snapshot.Actor.Kind == actor.Service && (call.PluginID != "tls.certificates" || call.Operation != "renew_existing") {
		snapshot.Clear()
		return nil, nil, fault.New("POLICY_SCOPE_DENIED", "服务账号只能执行已确认的既有证书续期")
	}
	value := &execution{authority: a, invocation: call, target: target, snapshot: snapshot}
	runCtx, cancel := context.WithCancel(ctx)
	var once sync.Once
	release := func() {
		once.Do(func() {
			cancel()
			value.mu.Lock()
			defer value.mu.Unlock()
			value.released = true
			value.snapshot.Clear()
		})
	}
	return context.WithValue(runCtx, executionKey{}, value), release, nil
}

// current 不缓存权限结论；每个关键阶段重新检查同一真实 operation 和不可变意图。
func (a *Authority) current(ctx context.Context) (*execution, error) {
	if a == nil || ctx == nil {
		return nil, fault.New("PERMISSION_DENIED", "缺少宿主确认的准备能力上下文")
	}
	value, ok := ctx.Value(executionKey{}).(*execution)
	if !ok || value == nil || value.authority != a {
		return nil, fault.New("PERMISSION_DENIED", "缺少宿主确认的准备能力上下文")
	}
	value.mu.RLock()
	defer value.mu.RUnlock()
	if value.released {
		return nil, fault.New("PERMISSION_DENIED", "准备能力执行上下文已释放")
	}
	snapshot, err := a.operations.ResolveDispatched(ctx, value.target, value.invocation.OperationID)
	if err != nil {
		return nil, err
	}
	defer snapshot.Clear()
	if snapshot.Actor != value.snapshot.Actor || snapshot.ArgsDigest != value.snapshot.ArgsDigest || !bytes.Equal(snapshot.Args, value.snapshot.Args) || snapshot.ExpectedRevision != value.snapshot.ExpectedRevision {
		return nil, fault.New("PERMISSION_DENIED", "已接受的准备能力意图发生变化")
	}
	return value, nil
}

// DecodeArguments 严格解码已经提取秘密后的原 operation 参数，不信任 RPC 携带
// 的替代 payload。额外字段、重复的 JSON 文档和尾随数据均失败关闭。
func DecodeArguments[T any](ctx context.Context, authority *Authority) (T, error) {
	var result T
	value, err := authority.current(ctx)
	if err != nil {
		return result, err
	}
	value.mu.RLock()
	defer value.mu.RUnlock()
	if value.released || ctx.Err() != nil {
		return result, fault.New("PERMISSION_DENIED", "准备能力执行上下文已释放")
	}
	if !strictObject(value.snapshot.Args, &result, 1<<20) {
		return result, fault.New("VALIDATION_FAILED", "已接受的准备 operation 参数无效")
	}
	return result, nil
}

// RequireRevision 拒绝 RPC 用另一个版本替代已接受 operation 的并发前置条件。
func (a *Authority) RequireRevision(ctx context.Context, requested string) error {
	value, err := a.current(ctx)
	if err != nil {
		return err
	}
	if requested == "" || requested != value.snapshot.ExpectedRevision {
		return fault.New("PERMISSION_DENIED", "RPC 版本不属于已接受的 operation")
	}
	return nil
}
