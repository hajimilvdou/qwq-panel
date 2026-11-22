# P2-T2 插件 SDK 与 P2-T4 空插件：实现报告

状态：实现完成，等待主会话集成与提交。
范围：`sdk/pluginsdk/**`、`plugins/builtin/noop/**`。传输层（go-plugin 握手、socket、SO_PEERCRED）不在本任务内，见第 8 节。
没有修改 proto、生成代码、`api/`、`sdk/gen/`、`sdk/manifest/`、`sdk/abi/`、`internal/`、`docs/`、`scripts/`、`tests/`，也没有改 `go.mod`、`go.sum`、`sdk/go.mod`、`sdk/go.sum`。

---

## 1. 交付文件

### SDK（Apache-2.0）

| 文件 | 内容 |
|---|---|
| `sdk/pluginsdk/doc.go` | 包文档：作者接口、实例隔离、生命周期、错误约定、subject、日志与内存 |
| `sdk/pluginsdk/types.go` | `Plugin`/`Instance`/`InstanceInfo`、请求响应类型、`Progress`、`Plan`、`ResourceChange`、`Precondition`、`FieldViolation`、`Call`、`LifecycleState`、`WithChanges` |
| `sdk/pluginsdk/handlers.go` | 原始 handler 类型与泛型注册辅助 `HandleInvoke` / `HandleJob` / `HandlePlan`，JSON 解码/编码 |
| `sdk/pluginsdk/instance.go` | `InstanceBase`、实例注册表、后台 `Go`、实例内状态机与存活计数、调用上下文 |
| `sdk/pluginsdk/server.go` | `PluginServiceServer` 生命周期 RPC、检查/配置 RPC、descriptor、manifest 一致性校验 |
| `sdk/pluginsdk/operations.go` | `Invoke` / `RunJob` / `PlanOperation` / `ServePublicRoute`，RunJob 流规则，错误与 proto 转换 |
| `sdk/pluginsdk/errors.go` | 域错误 `Error`、`Errorf` / `Validation` / `PreconditionFailed` / `CodeOf` / `IsConflict`，gRPC 状态映射 |
| `sdk/pluginsdk/subject.go` | 相对 subject 校验，Plan 与 ResourceChange 校验 |
| `sdk/pluginsdk/host.go` | Host Service 客户端：State/Events/Config/Secrets/Audit/Invoke，自动填充 `HostCallContext`；类型化 KV 也在本文件（`Host.KV()`、`KV`、`StateEntry`） |
| `sdk/pluginsdk/descriptor.go` | manifest → `PluginDescriptor` 的纯函数映射 |
| `sdk/pluginsdk/memory.go` | `GOMEMLIMIT` 解析（与 Go runtime 同一文法）与校验 |
| `sdk/pluginsdk/log.go` | 结构化 JSON 日志（stderr），`QWQ_PLUGIN_LOG_LEVEL` |
| `sdk/pluginsdk/serve.go` | `Options` / `Serve` / `Close`、ABI 与内存校验、传输接缝 TODO(P2-T1) |
| `sdk/pluginsdk/*_test.go` | bufconn 测试，见第 6 节 |

### 空插件（AGPL-3.0-only）

`plugins/builtin/noop/plugin.go`、`main.go`、`manifest.json`、`schemas/*.json`、`attestations/sbom.spdx.json`、`plugin_test.go`。

`plugins/builtin/noop` 是 **package main**：插件二进制入口和插件实现同目录，符合 manifest `entrypoint: bin/plugin`。如果以后需要让宿主 import 内置插件（当前不需要，ADR-0003 要求插件是独立进程），应把入口移到 `cmd/`，插件实现改为可导入包。

---

## 2. 作者 API

目标是"写一个插件要写的代码最少、最难写错"：必写接口只有 `Plugin`；实例必须嵌入 `*InstanceBase`（sealed interface 编译期强制），其余都是可选接口。

### 2.1 必需接口

```go
type Plugin interface {
    NewInstance(ctx context.Context, info InstanceInfo) (Instance, error)
}

type Instance interface { base() *InstanceBase } // sealed，由 InstanceBase 提供

type InstanceInfo struct {
    ID, DataDir string
    Config []byte
    ConfigRevision, StateSchemaVersion string
    HostABIMinor uint32
    // 私有字段：SDK 内部句柄
}
```

`Plugin.NewInstance` 中注册 operation 并返回实例：

```go
func (p *Plugin) NewInstance(_ context.Context, info pluginsdk.InstanceInfo) (pluginsdk.Instance, error) {
    inst := &instance{InstanceBase: pluginsdk.NewInstanceBase(info)}
    pluginsdk.HandleInvoke(inst, "noop.echo", inst.echo)
    pluginsdk.HandleJob(inst, "noop.wait", inst.wait)
    pluginsdk.HandleInvoke(inst, "noop.set", inst.set)
    pluginsdk.HandlePlan(inst, "noop.set", inst.planSet)
    return inst, nil
}
```

### 2.2 可选生命周期接口

```go
type Starter interface{ Start(ctx context.Context) error }
type Activator interface{ Activate(ctx context.Context) error }        // ctx 是后台 context，Deactivate/Stop/Release 时取消
type Deactivator interface{ Deactivate(ctx context.Context) error }    // ctx 带 grace period
type Stopper interface{ Stop(ctx context.Context) error }
type Releaser interface{ Release(ctx context.Context) error }
type ConfigValidator interface{ ValidateConfig(ctx context.Context, cfg Config) (ConfigValidation, error) }
type ConfigApplier interface{ ApplyConfig(ctx context.Context, cfg Config) error }
type HealthReporter interface{ Health(ctx context.Context) Health }
type PublicRouteHandler interface{ ServePublicRoute(ctx context.Context, req PublicRouteRequest) (PublicRouteResponse, error) }
```

`InstanceBase` 提供 `ID/DataDir/Info/Config/ConfigRevision/State/Host/Logger/Go` 与原始 `HandleInvoke/HandleJob/HandlePlan`。

`Go(fn)` 是唯一受支持的后台 goroutine 启动方式：只能在 `Activate` 之后调用，`Deactivate` / `Stop` / `ReleaseInstance` 会取消传给 `fn` 的 context 并等待它返回（带 grace period）。在 `Start` 里调用 `Go` 会返回错误，保证"Activate 之前没有后台工作"。

### 2.3 Operation 注册（泛型辅助）

```go
func HandleInvoke[In, Out any](inst Instance, name string, fn func(ctx context.Context, in In) (Out, error))
func HandleJob[In, Out any](inst Instance, name string, fn func(ctx context.Context, in In, progress Progress) (Out, error))
func HandlePlan[In any](inst Instance, name string, fn func(ctx context.Context, in In) (Plan, error))
```

- payload 自动 JSON 解码为 `In`；空 payload 视为零值；解码失败返回 `VALIDATION_FAILED/INVALID_JSON`。
- 返回值自动编码为 payload。`json.RawMessage` 原样透传；`nil` 表示无 payload。
- 需要上报资源变更时返回 `WithChanges[T]`：

```go
func (i *instance) set(ctx context.Context, in setRequest) (pluginsdk.WithChanges[setResponse], error) {
    call, _ := pluginsdk.CallFromContext(ctx)
    var opt pluginsdk.PutOption
    if pc, ok := call.Precondition("value"); ok {
        if pc.Revision == "" { opt.MustNotExist = true } else { opt.ExpectedRevision = pc.Revision }
    }
    rev, err := i.Host().KV().PutJSON(ctx, "value", in.Value, opt)
    if err != nil {
        if pluginsdk.IsConflict(err) {
            e := pluginsdk.PreconditionFailed("value", "")
            e.Message = pluginsdk.Localize(call.Locale, "值已被修改", "the value has changed")
            return pluginsdk.WithChanges[setResponse]{}, e
        }
        return pluginsdk.WithChanges[setResponse]{}, err
    }
    return pluginsdk.WithChanges[setResponse]{
        Value:   setResponse{Value: in.Value, Revision: rev},
        Changes: []pluginsdk.ResourceChange{{Subject: "value", Revision: rev, ChangedPointers: []string{"/value"}}},
    }, nil
}
```

- `Call` 包含 `RequestID/OperationID/TraceID/InstanceID/NodeID/Locale/Actor/Attempt/Preconditions`；
  `Call.Precondition(subject)` 取 plan 下发的锁。原始 handler 用 `Request.Precondition`。
- job 进度：

```go
if err := progress(pluginsdk.ProgressUpdate{
    Percent: 50, Message: "working", Step: "work", StepIndex: 2, StepCount: 3,
    Changes: []pluginsdk.ResourceChange{{Subject: "config", Revision: "1", ChangedPointers: []string{"/inbounds"}}},
}); err != nil {
    return waitResult{}, err // 流已取消或已终止
}
```

### 2.4 错误

调用到达 handler 之后，业务失败一律用 `ErrorDetail`（gRPC 状态 OK）：

```go
pluginsdk.Errorf("CODE", "message %d", n)
pluginsdk.Validation(violations...)
pluginsdk.PreconditionFailed(subject, observedRevision)
pluginsdk.CodeOf(err)
pluginsdk.IsConflict(err)
```

- 原始 Go error 会被记录日志并返回 `INTERNAL`，消息不回显内部文本。
- `Error` 的 `Message` 由作者按 `call.Locale` 本地化；`Errorf` 的格式串不本地化。
- 非法地址/生命周期（未知实例、未 Start、已 DRAINING/STOPPED）使用 gRPC 状态：NOT_FOUND / FAILED_PRECONDITION / INVALID_ARGUMENT。

### 2.5 Host 客户端

`i.Host()` / `req.Host()` 返回 `*pluginsdk.Host`：

```go
GetState(ctx, key) (value []byte, revision string, found bool, err error)
PutState(ctx, key, valueJSON []byte, opt PutOption) (revision string, err error)
DeleteState(ctx, key, expectedRevision string) error
ListState(ctx, prefix, pageToken string, pageSize uint32, includeValues bool) (*platformv1.ListStateResponse, error)

KV() *KV
    GetJSON(ctx, key string, v any) (revision string, found bool, err error)
    PutJSON(ctx, key string, v any, opt PutOption) (revision string, err error)
    Delete(ctx, key, expectedRevision string) error
    Each(ctx, prefix string, pageSize uint32, includeValues bool, fn func(StateEntry) error) error
    List(ctx, prefix string, pageSize uint32) ([]StateEntry, error)

PublishEvent(ctx, EventDraft) (*platformv1.PublishEventResponse, error)
SubscribeEvents(ctx, subscription string, topics []string, lastAcked uint64) (grpc.ServerStreamingClient[platformv1.SubscribeEventsResponse], error)
ConsumeEvents(ctx, subscription string, topics []string, lastAcked uint64, fn func(*platformv1.Event) error) error // 自动累计 ack
AckEvents(ctx, subscription string, sequence uint64) error
ReportChanges(ctx, changes ...ResourceChange) error

GetConfig(ctx, revision string) (configJSON []byte, appliedRevision string, err error)
RevealSecret(ctx, secretRef, purpose string) ([]byte, error) // 必须有已派发的 operation_id
WriteAudit(ctx, AuditRecord) error

InvokePlugin(ctx, InvokeRequest) (*platformv1.InvokePluginResponse, error)
WaitOperation(ctx, operationID string, timeout time.Duration) (*platformv1.WaitOperationResponse, error) // 上限 60s
AwaitOperation(ctx, operationID string) (*platformv1.WaitOperationResponse, error)                      // 循环到终态/待批准/未知状态
CancelOperation(ctx, operationID string) (platformv1.OperationState, error)
```

自动填充 `HostCallContext`：`instance_handle` 来自 Initialize，`operation_id`/`trace_id` 来自当前请求上下文；
`Activate` 之后的后台工作继承 Activate 的 trace_id，operation_id 为空。
Host 失败映射为域 `*Error`（`ABORTED → REVISION_CONFLICT`、`PERMISSION_DENIED`、`UNAVAILABLE(retryable)` 等），原始 gRPC error 保留在 `Unwrap` 链上。

### 2.6 Plan 与副作用

`PlanOperation` 的 handler ctx 带 `planning=true`；此时 Host 客户端本地拒绝
`PutState/DeleteState/ReportChanges/PublishEvent/InvokePlugin/CancelOperation`，返回 `PLAN_SIDE_EFFECT`。
这比 ABI 强：ABI 允许插件省略 `operation_id` 绕过宿主的 planning 检查，而 SDK 不依赖该字段。

### 2.7 运行时与入口

- `pluginsdk.Serve(ctx, Options{Plugin, Manifest, Registrar, Host, Logger, DefaultGracePeriod, ReleaseGracePeriod})`：
  校验 manifest、ABI（manifest 要求的 minor 不能高于 `sdk/abi.Minor`）、`GOMEMLIMIT`，构造 descriptor 并注册 `PluginService`；**不监听、不校验对端、不拥有进程**。
- `GOMEMLIMIT` 使用与 Go runtime 相同的文法（`^[0-9]+(([KMGT]i)?B)?$` 或 `off`）；非法值让 `Serve` 失败，高于 `resources.memory_max_mb` 只警告。
  健康检查 `details_json` 固定包含 `{"memory":{"gomemlimit_bytes","gomemlimit_set","memory_max_mb"}}`，作者详情放在 `"plugin"`。
- 日志：默认 `slog` JSON 到 stderr，字段含 `plugin`、`instance`，操作失败额外带 `rpc/request_id/operation_id/trace_id`；stdout 留给传输握手。
- 传输接缝：`serve.go` 的 TODO(P2-T1)，`plugins/builtin/noop/main.go` 的 `transport` 接口与 `notWired` 占位实现。

---

## 3. 服务端实现要点

- **实例隔离**：`RequestContext.instance_id` 路由到每实例的 author 对象、operation 注册表、config、后台 context、在途计数；`ReleaseInstance` 只清理该实例，进程继续服务其他实例。
- **状态机**：INITIALIZED → READY（Start）→ ACTIVE（Activate）→ DRAINING（Stop）→ STOPPED；另有 FAILED。
  只有 READY/ACTIVE 接受 `Invoke/RunJob/PlanOperation/ServePublicRoute` 与配置变更；DRAINING/STOPPED 拒绝新请求。
  `Initialize` 重复、`Start` 顺序错误、`Activate` 前 `Go` 都会被拒绝（后者返回错误，不启动 goroutine）。
- **Deactivate**：置 READY → 禁止新的 `Go` → 取消后台 context → 等待受跟踪 goroutine（grace）→ 调 `Deactivate` hook；总时长受 grace 与 RPC deadline 双重约束。
- **Stop**：DRAINING → 取消后台 → `drain=true` 时先等待在途请求（最多 grace），`drain=false` 立即返回 `drained=false` → 若来自 ACTIVE 调 `Deactivate` → `Stop` hook → STOPPED。先排空再执行 teardown，避免 hook 释放仍在使用的状态。
- **ReleaseInstance**：幂等；先从表移除（新调用 NOT_FOUND），取消后台、等待在途（最多 ReleaseGrace）、调 `Release`，记录仍未停止的告警。
- **RunJob 流规则**：handler 可发任意条进度；SDK 保证恰好一条终止消息（成功=completed/percent 100；失败=ErrorDetail）。
  handler 返回错误时若流已取消，不再尝试发送并返回 nil；`Progress` 在终止后调用会报错，防止并发 goroutine 写出终止消息之后的消息。
  进度校验 percent≤100、step_index/step_count 合法；changes subject 先校验。
- **PlanOperation**：不写状态；返回 PlannedChange/Precondition/Warnings；`PlanOperationResponse.violations` 不使用，错误统一走 `ErrorDetail`。
  校验 planned change 的 kind、subject、description≤200、before/after 是合法 JSON。
- **GetDescriptor**：从内嵌 manifest 的纯函数映射生成，`proto.Clone` 返回；handler 注册表在 Initialize 时与 manifest 逐项比对（模式、plannable、未声明 operation），不一致直接 FailedPrecondition。
- **错误策略**：`Start/Activate/Deactivate` 的 hook 失败返回 gRPC INTERNAL（实例置 FAILED 或保持 READY）；`Stop/Release` 失败只记录日志并继续清理（`drained` 仍可返回）。
- **identity**：SDK 从不信任 `RequestContext.actor/node_id` 做授权；`HostCallContext.instance_handle` 只来自 Initialize，符合 review C2。

---

## 4. 空插件（P2-T4）

- **manifest**：`id=noop`、`version=0.1.0`、`placement=node`、ABI 1.0；三个 operation：
  - `noop.echo`：invoke / read / idempotent / 5000ms；
  - `noop.wait`：job / read / idempotent / 60000ms；
  - `noop.set`：invoke / write / plannable / 10000ms，声明 `state.kv.read` + `state.kv.write`。
  - 顶层 capability 只有 `state.kv.read:self` 与 `state.kv.write:self`；`files`、`publisher.key_id` 是占位值（打包属 P2-T3）。
- **生命周期**：`Start/Activate/Deactivate/Stop/Release` 全部显式空方法，作为作者模板；`Health` 返回 "noop is empty"。
- **noop.echo**：校验 message 1..64 个字符，返回 message/instance_id/attempt；错误按 locale 本地化。
- **noop.wait**：3 步（prepare/work/finish）进度，`StepIndex/StepCount/Percent` 递增；每步检查 ctx，可取消；终止结果 `{"steps":3}`。
- **noop.set**：KV key/subject 都是 `value`；
  - `PlanOperation` 只读当前值与 revision，返回 CREATE/UPDATE + PlannedChange + Precondition（revision 空 = 不存在）；
  - `Invoke` 把 precondition 翻译成 `PutState` 的 `must_not_exist` / `expected_revision`，由宿主原子 CAS；冲突返回 `PRECONDITION_FAILED`，成功返回 payload + `ResourceChange{subject:"value", revision, changed_pointers:["/value"]}`。
- **main.go**：`transport` 接口 + `notWired` 占位，注释明确 P2-T1 要提供 socket、SO_PEERCRED、host 连接；当前运行会以清晰错误退出，不伪装成健康的插件。
- **测试**：manifest 解析、引用文件存在、descriptor 与 manifest 一致、单实例完整生命周期 + echo/wait/plan+set（含 stale precondition）。

---

## 5. 导出 API 清单（简）

类型：`Plugin`、`Instance`、`InstanceInfo`、`InstanceBase`、`Starter/Activator/Deactivator/Stopper/Releaser/ConfigValidator/ConfigApplier/HealthReporter/PublicRouteHandler`、`Request`、`Response`、`Result`、`Progress`、`ProgressUpdate`、`Plan`、`PlannedChange` + `ChangeUnspecified/Create/Update/Delete`、`ResourceChange`、`Precondition`、`FieldViolation`、`Call`、`Localize`、`LifecycleState` + `StateInitialized/Ready/Active/Draining/Stopped/Failed`、`Config`、`ConfigValidation`、`Health`、`HTTPHeader`、`PublicRouteRequest/Response`、`WithChanges[T]`、`Error`、`Host`、`KV`、`StateEntry`、`PutOption`、`EventDraft`、`AuditRecord`、`InvokeRequest`、`MemoryLimit`、`Options`、`Server`。

函数/方法：
`Serve`、`HandleInvoke`、`HandleJob`、`HandlePlan`、`NewInstanceBase`、`CallFromContext`、`Errorf`、`Validation`、`PreconditionFailed`、`CodeOf`、`IsConflict`、`ValidateSubject`、`Localize`、`MemoryLimitFromEnv`、`ReadMemoryLimit`、
`Server.GetDescriptor/Initialize/Start/Activate/Deactivate/Stop/ReleaseInstance/CheckHealth/ValidateConfig/ApplyConfig/Invoke/RunJob/PlanOperation/ServePublicRoute/Descriptor/MemoryLimit/Close`、
`Host.*`（第 2.5 节）、`KV.*`、`InstanceBase.*`、`Request.*`。
常量/变量：`DefaultGracePeriod`、`DefaultReleaseGracePeriod`、`EnvMemoryLimit`、`EnvLogLevel`、`ErrNoHost`。

---

## 6. 测试与验证

命令（Linux 构建机，`/root/qwq-dev/p2a`，`QWQ_REMOTE_SRC=p2a`）：

```text
cd /root/qwq-dev/p2a/sdk
GOWORK=off go test ./pluginsdk/                     -> ok
GOWORK=off go vet ./pluginsdk/                      -> ok
GOWORK=off staticcheck ./pluginsdk/                 -> ok
gofmt -l pluginsdk/                                 -> 空
CGO_ENABLED=1 GOWORK=off go test -race ./pluginsdk/ -> ok

cd /root/qwq-dev/p2a
GOWORK=off go test ./plugins/...                    -> ok
GOWORK=off go vet ./plugins/...                     -> ok
GOWORK=off staticcheck ./plugins/...                -> ok
gofmt -l plugins/                                   -> 空
CGO_ENABLED=1 GOWORK=off go test -race ./plugins/... -> ok
```

SDK 测试（bufconn；不依赖传输）：

- 生命周期：非法顺序、READY/ACTIVE/DRAINING/STOPPED 拒绝新请求、重复 Initialize、重复 Release、Stop 后再 Stop、ABI 低于 manifest、handler 与 manifest 不匹配、构造失败；
- 多实例隔离：两个实例各自的 instance_handle、Host 调用、KV 命名空间；释放 a 不影响 b；
- 后台：`Go` 只在 ACTIVE 成功，Deactivate/Release/直接 Stop 都会取消并等待受跟踪 goroutine（通道断言，不用 sleep 轮询状态）；`Stop(drain=true)` 等待在途请求完成，`drain=false` 不等待且 `drained=false`；
- RunJob：3 步进度 + 恰好 1 条终止、错误时 1 条终止、未知 operation 只有终止错误、取消后 handler 退出、非法 percent 被拒、变更 subject 校验；
- Plan：plan 期间零 PutState、precondition 绑定、stale precondition 失败、second plan 的 before/revision、非 plannable 拒绝、plan 期间写 Host 被本地拒绝；
- Host：自动 `HostCallContext`（handle/operation_id/trace_id）、KV CAS 冲突映射、ListState 分页（250 条，每页 7）、ConsumeEvents 自动 ack、RevealSecret 缺 operation_id、没有 Host 连接时 `ErrNoHost`；
- 配置：violations/warnings、热应用 revision、失败保持旧 revision；
- 公开路由：状态/头/正文、错误映射、未实现 UNIMPLEMENTED；
- 错误/内存/日志：ErrorDetail 映射与不泄露内部文本、GOMEMLIMIT 解析表、健康详情、`gofmt`/`go vet`/`staticcheck`。

与 `tests/abi` 三个场景的对应（未修改 `tests/abi`）：

| ABI 场景 | SDK 测试 |
|---|---|
| 场景一：空插件 + 生命周期/隔离 | `TestLifecycleOrder`、`TestTwoInstancesAreIsolated`、noop 包测试 |
| 场景二：controller 调 core.apply + Wait/Cancel | `TestScenarioTwoControllerInvokesCore`、`TestScenarioTwoCancelPropagatesToChild`、`TestScenarioTwoChildApproval`、`TestRunJobProgressChanges` |
| 场景三：plan → approve（宿主侧）→ 带 precondition 执行 job | `TestScenarioThreePlannableJob`、`TestPlanIsSideEffectFreeAndBindsPreconditions`、`TestRunJobFailingHandler` |

没有实现"approve"本身（属于宿主，不在插件 SDK）。

---

## 7. 发现的 ABI 问题

逐条给出：现象 / 涉及字段 / 建议 / 能否冻结后追加。

1. **相对 subject 的语法允许 "." 和 ".."**
   - 现象：proto 头部段语法 `[A-Za-z0-9._~-]{1,128}` 接受 `.`、`..`；宿主加 `resources/` 前缀后若按路径处理，存在越界风险。`tests/abi` 与 SDK 都额外拒绝这两个段。
   - 字段：`ResourceChange.subject`、`Precondition.subject`、`PlannedChange.subject`、`EventDraft.subject`。
   - 建议：在 proto 注释与公共 API 的 `Subject` schema 中明确"宿主必须拒绝 `.` 与 `..`"。
   - 冻结后：可追加（文档/校验规则），不需要改字段。

2. **KV 比较交换失败的状态码未定义**
   - 现象：HostStateService 的响应没有 ErrorDetail；`PutState`/`DeleteState` 的 precondition 失败只能用 gRPC 状态表示，proto 未规定用哪个。`tests/abi` 用 `ABORTED`；SDK 映射为 `REVISION_CONFLICT`。
   - 字段：`PutStateRequest.precondition`、`PutStateResponse`、`DeleteStateRequest.expected_revision`。
   - 建议：注释固定 `ABORTED = 版本冲突`，其余为 `PERMISSION_DENIED` / `INVALID_ARGUMENT`；P2-T6 按此实现。
   - 冻结后：可追加（约定，不需要新字段）。

3. **PlanOperation 的"无副作用"无法由 ABI 保证**
   - 现象：插件在 PlanOperation 中省略/伪造 `HostCallContext.operation_id` 就能写状态；宿主只能在"operation_id 指向正在 planning 的 operation"时拒绝。SDK 在自己的 Host 客户端里按 planning 标志本地拒绝写（Put/Delete/ReportChanges/PublishEvent/InvokePlugin/CancelOperation）。
   - 字段：`HostCallContext.operation_id`、`PlanOperationRequest.context`。
   - 建议：proto 写明"宿主必须拒绝 planning operation 的所有状态写入，即使 operation_id 为空"；后续 minor 可加 `HostCallContext.planning` 或 `PlanOperationRequest` 标志。
   - 冻结后：注释可追加；bool 字段可追加（minor+1）。

4. **`PlanOperationResponse.violations` 与 `ErrorDetail.violations` 重复**
   - 现象：两个字段都能报字段级错误；`tests/abi` 与 SDK 都使用 ErrorDetail，PlanOperationResponse.violations 空置。宿主必须同时处理两套。
   - 字段：`PlanOperationResponse.violations`、`ErrorDetail.violations`。
   - 建议：注释明确"计划失败用 ErrorDetail{VALIDATION_FAILED, violations}；PlanOperationResponse.violations 保留但不再使用"。
   - 冻结后：注释/废弃声明可追加；删除字段不可。

5. **`InvokeResponse.changes` 与 `error` 同时存在时的语义未定义**
   - 现象：handler 失败时 SDK 丢弃 changes；如果操作已经产生部分写入，Invoke 没有中间消息可上报，宿主收不到变更。RunJob 可以在失败前的进度消息里带 changes，Invoke 不能。
   - 字段：`InvokeResponse.changes`、`InvokeResponse.error`。
   - 建议：明确"error 非空时 changes 被忽略"或反之；部分写入建议走 `ReportChanges`（需要能力）或设计成可回滚。
   - 冻结后：注释可追加；如需新字段可 minor 追加。

6. **Host Service 失败到插件 operation 结果的映射未定义**
   - 现象：proto 说 gRPC 状态表示传输/宿主侧失败；插件调用宿主失败后，返回给宿主的结果只有 ErrorDetail 或 gRPC 状态两个选择。SDK 选择映射为带稳定 code 的 ErrorDetail（gRPC OK，`retryable` 反映 UNAVAILABLE/DEADLINE），因此宿主看到的是业务失败。
   - 字段：Host Service 响应（无 ErrorDetail）、`ErrorDetail.retryable`。
   - 建议：固定映射表（SDK 已实现，见第 2.5 节），并在 proto/ADR 中说明这属于插件业务结果。
   - 冻结后：文档可追加。

7. **生命周期 RPC 的失败没有 ErrorDetail 字段**
   - 现象：Initialize/Start/Activate/Deactivate/Stop/ReleaseInstance 的响应都没有 ErrorDetail；钩子失败只能用 gRPC 状态，而 gRPC 状态又被定义为传输/宿主侧失败。SDK 的策略见第 3 节。
   - 字段：上述响应消息。
   - 建议：注释规定钩子失败使用 gRPC `INTERNAL`/`FAILED_PRECONDITION`；后续 minor 可给这些响应追加 ErrorDetail。
   - 冻结后：追加字段可行（minor+1）。

8. **`details_json` 格式未约定**
   - 现象：`ErrorDetail.details_json` 与 `CheckHealthResponse.details_json` 都是 opaque；SDK 定义了 `PRECONDITION_FAILED` 的 `{subject,revision}` 与健康详情的 `{memory,plugin}`，但宿主/UI 无法依赖。
   - 字段：`ErrorDetail.details_json`、`CheckHealthResponse.details_json`。
   - 建议：为常见 code 固定 details 结构；健康详情给出版本化 schema。
   - 冻结后：文档可追加；强类型需新字段。

9. **`StopRequest.drain` / `grace_period_ms` 语义未写清**
   - 现象：`drain=false` 是否等待、0 的默认值、是否仍进入 DRAINING 都未定义。SDK 的语义：`drain=true` 等待在途（最多 grace），`drain=false` 立即返回 `drained=false`；0 用 SDK 默认 10s（可由 Options 覆盖）。
   - 字段：`StopRequest.drain`、`StopRequest.grace_period_ms`、`DeactivateRequest.grace_period_ms`、`StopResponse.drained`。
   - 建议：proto 写明，并要求宿主显式传 grace，避免插件各自发明默认值。
   - 冻结后：注释可追加。

10. **`api_version` 为空/不匹配的行为未定义**
    - 现象：没有说明空字符串含义；SDK 把空视为"不检查"，不匹配返回 `UNSUPPORTED_API_VERSION` 的 ErrorDetail。
    - 字段：`InvokeRequest.api_version`、`RunJobRequest.api_version`、`PlanOperationRequest.api_version`、`OperationDescriptor.api_version`。
    - 建议：明确"空 = 使用 descriptor 的值；不匹配由宿主拒绝或插件返回错误"。
    - 冻结后：注释可追加。

11. **新的 `OperationState` 值无法判断是否终态**
    - 现象：open enum；旧 SDK 看到新状态无法知道是否终态。`tests/abi` 也记录了这一点；SDK 的 `AwaitOperation` 遇到未知状态直接返回，由调用方决定。
    - 字段：`OperationState`、`WaitOperationResponse.state`。
    - 建议：约定新增状态必须可分类（等待类/终态），或后续 minor 加 `bool terminal`。
    - 冻结后：追加 bool 字段可行（minor+1）。

12. **`CheckHealthResponse.Status` 没有"降级"**
    - 现象：只有 SERVING/NOT_SERVING；插件"在服务但降级"只能写 message。
    - 字段：`CheckHealthResponse.Status`。
    - 建议：后续 minor 追加 `STATUS_DEGRADED`（open enum 可追加）；宿主需容忍未知值。
    - 冻结后：追加枚举值可行（minor+1）。

---

## 8. 依赖与需要其他任务配合的事项

### 需要的依赖

**没有新增依赖**。`sdk/go.mod` 保持 grpc + protobuf + jsonschema；`pluginsdk` 只用标准库、`google.golang.org/grpc`、`google.golang.org/protobuf` 与 `sdk/gen`、`sdk/manifest`、`sdk/abi`。没有改任何 go.mod/go.sum。

### P2-T1（传输）必须提供

1. 一个 `grpc.ServiceRegistrar`（通常是 `grpc.NewServer()`），监听 systemd socket activation 或 go-plugin 提供的 listener；在 `grpc.Server` 上调用 `pluginsdk.Serve(ctx, Options{Registrar: srv, ...})` 即完成注册。
2. 双向对端认证：插件侧只接受 Agent 的 UID（SO_PEERCRED/SO_PEERPIDFD）；SDK 不参与，也不从消息字段推导身份。
3. Host 连接：连到 Agent 为该插件单独监听的 UDS（ADR-0003 第 3 条），作为 `Options.Host` 传入；该连接上的 HostCallContext.handle 才是有效的。
4. 生命周期：ctx 取消时先 `srv.GracefulStop()`/`Stop()`，再 `pluginsdk.Server.Close()`；`Close` 会取消所有后台 context 并最多等待 `ReleaseGracePeriod`。
5. 如果继续用 go-plugin：transport 实现 `plugin.GRPCPlugin`（`GRPCServer` 里调 `Serve`，`GRPCClient` 不需要），但 ADR-0003 倾向 systemd socket + Reattach，此时 go-plugin 只作为进程监督/握手兼容层；SDK 对此无假设。
6. SDK 只读两个环境变量：`GOMEMLIMIT`（校验并上报，Go runtime 自己读）与可选的 `QWQ_PLUGIN_LOG_LEVEL`。实例 ID、socket 路径、凭据都由 transport 处理，不要塞进插件消息字段。

### P2-T3（打包）

- `plugins/builtin/noop` 是 `package main`；`go build -o bin/plugin ./plugins/builtin/noop` 产出 manifest 的 entrypoint。
- `manifest.json` 的 `files` 摘要与 `publisher.key_id` 是占位值；打包时重算并重新签名。
- `attestations/sbom.spdx.json` 是占位 SBOM，打包时替换。

### P2-T6（Host Service）

SDK 依赖以下宿主行为：

- `PutState`/`DeleteState` 的 CAS 失败返回 `ABORTED`（SDK 映射 REVISION_CONFLICT）；`expected_revision` 为空表示无条件删除。
- `ListState`：`page_token` 不透明且不回环；`next_page_token` 空表示结束；`include_values` 才带值；key 按字节序。
- Host 调用身份：`instance_handle` 未知 → `UNAUTHENTICATED`；`operation_id` 不属于当前实例/未派发 → `PERMISSION_DENIED`；缺能力 → `PERMISSION_DENIED`。
- `WaitOperation` 在终态、AWAITING_APPROVAL 或超时后返回；`timeout_ms` 上限 60s。
- `ReportChanges` 不需要 `operation_id`，但宿主仍需校验相对 subject 并加实例前缀。
- 事件订阅游标按 (instance, subscription) 保存；`sequence` 从 0 开始单调递增；`AckEvents` 是累计确认。
- `RevealSecret` 必须要求非空 `operation_id` 且绑定到已派发的 operation（SDK 会在缺少时直接返回 `MISSING_OPERATION_ID`，不打扰宿主）。

### 主会话集成

- 本任务没有提交；所有新文件在 `sdk/pluginsdk/` 与 `plugins/builtin/noop/`。
- `plugins/builtin/noop` 是 main 包，不能被 import；如果后续有内置插件注册表需要 import，需把 main 移到 `cmd/`（当前无需求）。
- `sdk/pluginsdk/REPORT.md` 是详细报告。

---

## 9. 已知限制 / 后续 TODO

- 不做自动状态迁移：`Initialize` 返回 manifest 的 `state.schema_version`，`InitializeRequest.state_schema_version` 只作为输入快照；需要迁移钩子时再追加作者接口（ABI 字段不能改，只能加 SDK 接口）。
- 没有实现 `Serialize/Deserialize`、UI、go-plugin 握手、socket/peer 校验（按任务约定留给 P2-T1）。
- `NewInstanceBase` 参数错误、重复注册、NewInstance 之后注册都会 panic：这是作者编程错误，panic 信息明确；gRPC 不 recovery，进程会退出，宿主按崩溃处理。
- Initialize 期间持 `Server.mu` 调作者 `NewInstance`；作者不能从 `NewInstance` 回调 SDK 的 PluginService（没有这种调用路径），因此没有死锁风险。
- 作者不通过 `InstanceBase.Go` 启动的 goroutine，SDK 无法等待；文档明确 `Go` 是唯一保证。
- `WithChanges` 只对泛型 handler 生效；原始 handler 用 `Response.Changes` / `Result.Changes`。
- ABI 问题清单中的第 1、3、9 条建议在宿主实现（P2-T6/P2-T7）前先统一，否则不同实现会有兼容性差异。
