<!-- SPDX-License-Identifier: AGPL-3.0-only -->

# P2-T6 Host Service：实现报告

状态：实现完成，等待主会话集成与提交。范围：`internal/pluginhost/hostsvc/**`（新包，未改
`go.mod`/`go.sum`、`api/`、`docs/`、`scripts/`、`sdk/`、`tests/` 或任何其它子代理的范围）。
构建/测试机：Ubuntu，Go 1.27.3，kernel 5.4.0-28-generic（`SO_PEERPIDFD` 在本机不可用，见 §5、§9）。

## 1. 文件

| 文件 | 内容 |
|---|---|
| `doc.go` | 包说明：per-plugin UDS、内核证实身份、六个服务、错误约定 |
| `config.go` | `Config`、`Limits`/`DefaultLimits`/`KVMaxBytes`、配置与限额校验、目录/字符串工具 |
| `deps.go` | 全部窄接口与领域类型：`StateStore`、`EventSink`、`ConfigSource`、`SecretRevealer`、`AuditSink`、`Invoker`、`PeerVerifier`、`PeerInfo`、`PeerFromContext`、错误哨兵 |
| `server.go` | `Server`（`New`/`Serve`/`Close`/`Ingest`）、listener、socket 权限、gRPC 选项、unary/stream 拦截器、deadline/大小限制 |
| `peer.go` | `peerAuthInfo`、`peerCredentials`（gRPC `TransportCredentials`，在 HTTP/2 preface 之前校验） |
| `peer_linux.go` | `SO_PEERCRED`（+ 尽力而为的 `SO_PEERPIDFD`）读取；pidfd 在校验期间持有 |
| `peer_other.go` | 非 Linux 构建占位：拒绝监听（fail closed） |
| `state.go` | `fileState`（单 JSON 文件、原子写、总量/CAS/分页）+ `HostStateService` |
| `events.go` | 有界发布 spool、订阅缓冲/游标、`HostEventsService` |
| `configservice.go` | `HostConfigService`（只读当前快照） |
| `secrets.go` | `HostSecretsService`：operation 绑定、审计、限频 |
| `audit.go` | 每插件审计配额 + `HostAuditService` |
| `invoke.go` | `HostInvokeService`：宿主侧调用者身份、参数校验、Wait 上限 |
| `validate.go` | key/subject/event type/topic/pointer/action/subscription/purpose 语法 |
| `ratelimit.go` | 注入时钟的 token bucket |
| `harness_test.go` | 真实 UDS + `grpc.NewClient` 的测试夹具与全部假实现 |
| `server_test.go` | socket 权限、真实 peer pid/uid、拒绝 peer、Close/stale socket、非 socket 路径、Config 校验 |
| `state_test.go` | CAS/分页/删除/上限/持久化/并发 CAS/请求大小/自定义 store |
| `events_test.go` | 发布校验、spool 满、sink 故障、订阅/断点续传/上限/游标上限/Ingest |
| `services_test.go` | config、secrets（缺 operation/拒绝/审计失败关闭/限频）、audit（字段/队列/速率）、invoke |
| `peer_linux_test.go` | 白盒验证 `readPeerCredentials` 返回本进程 pid/uid/gid |

## 2. 导出 API

```go
type Config struct {
    PluginID, InstanceID, SocketPath, StateDir string
    Clock clock.Clock; Logger *slog.Logger
    State StateStore; Events EventSink; Config ConfigSource; Secrets SecretRevealer
    Audit AuditSink; Invoke Invoker; Peer PeerVerifier; Limits Limits
}
func New(Config) (*Server, error)
func (s *Server) Serve(ctx context.Context) error
func (s *Server) Close() error
func (s *Server) Ingest(*platformv1.Event) error // 宿主日志 -> SubscribeEvents 的注入缝
func DefaultLimits() Limits
func KVMaxBytes(kvMaxKB int) int64             // manifest resources.kv_max_kb -> MaxTotalBytes
func PeerFromContext(ctx) (PeerInfo, bool)
```

窄接口：`StateStore`（`Get/Put/Delete/List`，`StateGuard`/`StateEntry`/`StatePage`，
`ErrStateConflict`/`StateConflictError`/`LimitError`）、`EventSink`（`Publish/ReportChanges/Ack`，
`EventDraft`/`EventRef`/`ResourceChange`/`ChangeSet`）、`ConfigSource.Current`、
`SecretRevealer.Reveal(ctx, ref, operationID)`、`AuditSink.Write`（`AuditRecord`/`AuditOutcome`）、
`Invoker`（`InvokePlugin/WaitOperation/CancelOperation`，`InvokeCall`/`InvokeResult`/`DomainError`/
`WaitCall`/`OperationSnapshot`/`CancelCall`/`OperationState`/`Progress`）、`PeerVerifier.Verify(pid, uid)`。

哨兵：`ErrStateConflict`、`ErrSecretDenied`（→ PERMISSION_DENIED）、`ErrOperationNotDispatched`
（→ FAILED_PRECONDITION）、`ErrRateLimited`（→ RESOURCE_EXHAUSTED）；依赖返回的 gRPC status 原样透传。

## 3. 六个服务

### 3.1 HostStateService

- key：1–256 字节 `[A-Za-z0-9._/-]`（ABI 语法）；value 必须是合法 JSON。
- `GetState`：不存在时 `found=false`，不是错误；返回 revision。
- `PutState`：oneof 未设置 = 无条件写；`must_not_exist` = 仅当不存在；`expected_revision` 必须匹配。
  **`expected_revision` 被显式设为空串时按 `must_not_exist` 处理**（空串不可能等于已存 revision，
  静默变成无条件写更危险）。失败 guard 一律 `ABORTED`（SDK 映射 REVISION_CONFLICT）。
- `DeleteState`：空 expected = 无条件（缺失也成功）；非空 = CAS，缺失或不匹配 → ABORTED。
- `ListState`：按 key 字节序；`prefix` 过滤；`page_token` 是本包签发的 base64url(最后一个 key)，
  无效 token → INVALID_ARGUMENT；`page_size` 0 → 默认 100，上限 1000；`include_values` 决定是否带 value。
- 上限：单值默认 1 MiB（ABI），总量默认 4 MiB（`KVMaxBytes` 从 `kv_max_kb` 换算）；超限
  RESOURCE_EXHAUSTED。总量由 store 负责（只有它知道其它 key）。
- revision：不透明十进制字符串，单实例单调递增，跨重启保持（文件里持久 `next_revision`）。

### 3.2 HostEventsService

- `PublishEvent`：校验 type（dotted，`resource.`/`operation.` 保留给宿主）、相对 subject、JSON payload
  （≤1 MiB）→ 写入**有界** spool（默认 1024 个在途 job，单 worker 保序）→ 同步交给 `EventSink`，
  返回 sink 分配的 event_id/sequence。spool 满 → RESOURCE_EXHAUSTED；sink 故障 → UNAVAILABLE。
- `ReportChanges`：先校验整批（subject 相对语法、空段/`.`/`..`/超长、deleted 与 revision 一致性、
  RFC 6901 pointer、条数上限），再一次性交给 sink；不信任插件自报的 instance。
- `AckEvents`：`[a-z0-9_-]{1,64}` 的 durable 名称 + 正 sequence；先更新本地游标，再调用
  `EventSink.Ack`，sink 失败则回滚本地游标，保证不会跳过未落 journal 的事件。
- `SubscribeEvents`：topics 为精确 type 或 `prefix.*`；`last_acked_sequence=0` 用该订阅已存游标，
  非 0 则显式从该位置开始。事件来源是 `Server.Ingest`（宿主 journal 派发）填充的**有界**本地缓冲
  （默认 1024 条 / 8 MiB）；缓冲溢出会丢最旧并记 warning。条件变量（broadcast channel）等待新事件，
  每条 stream 受 StreamTimeout（默认 1h）与并发订阅上限（默认 32）约束。
- 本地游标按 durable 名称保存，上限 `MaxSubscriptionCursors`（默认 1024），超限 RESOURCE_EXHAUSTED；
  游标只在内存中（见 §10）。

### 3.3 HostConfigService

`GetConfig` 返回 `ConfigSource.Current` 的 revision 与 JSON 快照（校验 JSON 合法；非法 → INTERNAL）。
请求了非当前 revision → NOT_FOUND（本宿主只保留当前快照）。只读。

### 3.4 HostSecretsService

`RevealSecret` 依次要求：已验证 peer（拦截器）→ 非空 `HostCallContext.operation_id`
（缺失 → FAILED_PRECONDITION）→ 合法 ref/purpose → 未超 per-plugin 限频（默认 30/min，
burst = max(1, rate/4)）→ 调 `SecretRevealer.Reveal(ref, operationID)`，由宿主实现校验该 operation
属于本实例且未结束。成功时**先写审计再返回明文**：审计失败（含配额耗尽/未配置 Audit）即 fail closed，
清空返回值并报错。拒绝/失败也写审计（best-effort）；审计 details 只含 purpose，绝不含 secret。
revealer 的错误可用哨兵选择 code，或直接返回 gRPC status。

### 3.5 HostAuditService

`WriteAudit` 校验 action（`[A-Za-z0-9._:-]{1,128}`）、subject（≤512、可打印 UTF-8）、outcome 枚举
（未知数字 → INVALID_ARGUMENT）、details JSON（≤64 KiB）。宿主填写 PluginID、InstanceID、
Source="plugin"、OccurredAt（注入 Clock）、OperationID/TraceID，插件无法伪造 actor/来源。
配额：每插件独立，`AuditQueue`（默认 256）个在途 + `AuditPerMinute`（默认 120，burst 30）；
满 → RESOURCE_EXHAUSTED。未配置 sink → UNAVAILABLE。secret 审计走同一配额。

### 3.6 HostInvokeService

`InvokePlugin` 先把 `CallerPluginID`/`CallerInstanceID` 设为 Config 中的宿主已知值（不是
HostCallContext 自报），把 `ParentOperationID`/`TraceID` 作为相关性字段传下去；
`Invoker` 负责 capability `plugin.invoke:<plugin_id>/<operation>`、目标 subject/instance/node 解析、
schema 校验、路由到 ACTIVE generation 与父子 operation 风险。本层校验 target 标识、operation 名、
api_version、JSON payload（≤1 MiB）、idempotency key。

`WaitOperation` 的 timeout_ms 被 cap 到 `WaitTimeout`（默认 60 s，ABI 上限）且沿用 gRPC deadline；
timeout=0 立即返回当前状态。`CancelOperation` 同样转发本实例身份。响应中的 `ErrorDetail` 来自
`InvokeResult.Error`（gRPC status 仍是 OK，符合 proto 的“域结果 vs 传输失败”约定）；
`OperationState` 字符串映射到 ABI 枚举，未知值映射 UNSPECIFIED。

## 4. State 文件格式与限额

`Config.State == nil` 时使用内置 `fileState`，文件为 `<StateDir>/state.json`（0600；目录 0750）：

```json
{
  "format": 1,
  "next_revision": 12,
  "entries": {
    "baseline": {"revision": "11", "value": {"enabled": true}},
    "logs/2026": {"revision": "7", "value": {"days": 30}}
  }
}
```

- `encoding/json` 对 map 排序 → 文件确定、可 diff；`value` 保存原始 JSON。
- 每次 Put/Delete 都重写整个文件：同目录 `os.CreateTemp` → chmod 0600 → write → `fsync` →
  `rename` → fsync 目录。崩溃只会留下旧文件或新文件，不会半截。失败时回滚内存状态。
- 加载时校验 format、key 语法、value JSON、单值/总量上限、revision 可解析；损坏 → 启动失败
  （不带着截断状态服务）。`next = max(文件值, 最大 revision+1)`，revision 跨重启单调。
- 总量 = Σ(len(key)+len(value))（ABI 只说总量受 `kv_max_kb` 限制；含 key 是保守取值）。
- 单文件单写者：一个 `Server` 独占一个 StateDir（进程内 mutex，无跨进程 flock），见 §10。
- 限额由 `Limits` 控制：`MaxKeyBytes` 256、`MaxValueBytes` 1 MiB、`MaxTotalBytes` 4 MiB（可由
  `KVMaxBytes(manifest.resources.kv_max_kb)` 覆盖）、`PageSize` 100、`MaxPageSize` 1000。

## 5. peer 校验

- listener：`Serve` 创建 socket 父目录（0750，已存在则保留 supervisor 的组/setgid 位）与 socket
  （0660），启动前探测 stale socket：若无人监听则删除；若是普通文件则拒绝启动；若已有服务应答
  （dial 成功）则拒绝启动。
- 连接认证放在 `peerCredentials`（实现 gRPC `credentials.TransportCredentials`）。gRPC 在
  accept 之后、读取 HTTP/2 preface 之前调用 `ServerHandshake`：本包用 `syscall.GetsockoptUcred`
  读取 `SO_PEERCRED`（pid/uid/gid），尽力读 `SO_PEERPIDFD`（Linux ≥ 6.5），在持有 pidfd 期间调用
  `PeerVerifier.Verify(pid, uid)`；verifier 返回错误则关闭连接并拒绝握手。拒绝的连接不会处理任何 RPC。
- 为什么用标准库 `syscall` 而不是 `x/sys/unix`：`x/sys` 在本模块是 indirect 依赖，直接 import 会让
  `go mod tidy` 改 `go.mod`，而本任务禁止改 `go.mod`/`go.sum`；`syscall.GetsockoptUcred` /
  `GetsockoptInt` 等价且无新依赖。`SO_PEERPIDFD` 的数值用注释说明。
- 每个 RPC 的 unary/stream 拦截器再从 gRPC `peer.FromContext(ctx).AuthInfo` 取回 `peerAuthInfo`，
  把 pid/uid/gid 放进 handler context（`PeerFromContext`）；缺失/类型不符直接 PERMISSION_DENIED
  （fail closed，即使有人忘记装 creds 也不会退化成匿名调用）。
- `HostCallContext` 的 `instance_handle`、`operation_id`、`trace_id` 只作相关性：身份只来自 listener、
  Config 与内核；`operation_id` 的“是否属于本实例且未结束”由 `SecretRevealer`/`Invoker` 校验。
- 生产 `PeerVerifier`（不在本包，由集成方实现）：读 `/proc/<pid>/cgroup` 得到单元名，要求等于
  systemd 报告的 `qwq-plugin@<id>.service`、uid 等于插件动态 uid、pid 等于 `systemctl show -p MainPID`，
  并用 `/proc/<pid>/stat` starttime 与 systemd 事实一起算 generation；每次上报都重读 MainPID
  （spike 报告 §1 的实测教训）。panic/错误必须返回 error（fail closed）。
- 本机 kernel 5.4 没有 `SO_PEERPIDFD`，白盒测试记录 `SO_PEERPIDFD available: false`，代码走
  SO_PEERCRED 回退；spike（kernel 6.8）已证明该选项存在。§9 列为未覆盖项。

## 6. 错误映射

| 情况 | gRPC code |
|---|---|
| key/subject/type/topic/pointer/枚举/JSON 非法 | INVALID_ARGUMENT |
| State CAS 失败（`StateConflictError`） | ABORTED（SDK → REVISION_CONFLICT） |
| 单值/总量/请求体/spool/审计队列/审计速率/reveal 速率/订阅数/游标数超限 | RESOURCE_EXHAUSTED |
| RevealSecret 缺 operation_id / operation 未派发 | FAILED_PRECONDITION |
| GetConfig 请求非当前 revision | NOT_FOUND |
| 未通过 peer 校验 | 连接被关，客户端看到 UNAVAILABLE |
| secret 被拒（`ErrSecretDenied`） | PERMISSION_DENIED |
| 可选依赖未配置（State 除外）/sink 基础设施故障/关闭中 | UNAVAILABLE |
| 未知内部错误 | INTERNAL（详情只进日志） |
| 客户端 deadline / cancel | DEADLINE_EXCEEDED / CANCELED |

拦截器为每个 unary 调用补 `RequestTimeout`（默认 30 s），为 stream 补 `StreamTimeout`（默认 1 h）；
客户端自带更短 deadline 时保留。gRPC 收发上限默认 4 MiB（`MaxRequestBytes`），
每实例最多 2 连接、`MaxConcurrentStreams` 16、在途调用 16（超出立即 RESOURCE_EXHAUSTED），spool/订阅/审计/游标/限频全部有界。

## 7. 测试

命令（构建机，`QWQ_REMOTE_SRC=hostsvc1`）：

```text
gofmt -l internal/pluginhost/hostsvc            # 空
go vet ./internal/pluginhost/hostsvc/...        # 通过
staticcheck ./internal/pluginhost/hostsvc/...   # 通过
CGO_ENABLED=1 go test -race -count=1 ./internal/pluginhost/hostsvc/...
# ok  github.com/qwq-panel/qwq/internal/pluginhost/hostsvc  2.8s
go test -count=5 ./internal/pluginhost/hostsvc/...   # ok 7.6s
go test -count=10 -run TestEventsSpoolFull ./internal/pluginhost/hostsvc/...   # ok 2.6s
go test -count=10 -run TestStaleSocketIsReplaced ./internal/pluginhost/hostsvc/... # ok 0.06s
```

39 个顶层测试 + 45 个子测试，全部在 `t.TempDir()` 的真实 Unix socket 上通过
`grpc.NewClient("unix://...")` 跑，`PeerVerifier` 用假实现；覆盖：六个服务 happy path；真实
`SO_PEERCRED` pid/uid（白盒 + 端到端）；拒绝 peer 且换用允许的 verifier 后恢复；socket 0660/目录 0750；
关闭删 socket；stale socket 替换；非 socket 路径拒绝；Config/限额校验；State CAS（含 8 并发只一个赢家）、
不存在、分页、单值/总量/请求大小上限、跨重启持久化与文件权限、自定义 store；Events spool 满
（sink 阻塞时恰好一个 RESOURCE_EXHAUSTED）、sink 故障 UNAVAILABLE、订阅主题过滤/断点续传/显式游标/
非法订阅/并发上限/游标上限/Ingest 校验；Config revision；Secrets 缺 operation、拒绝、未派发、
审计失败关闭、限频、非法 ref；Audit 字段映射、队列满、速率上限、未配置；Invoke 转发与调用者身份、
域错误、参数校验、payload 上限、Wait 60 s cap 与 0 timeout、Cancel、未配置。

## 8. 集成说明（给主会话）

- 每个插件实例一个 `Server` + 一个 socket；`Config.Peer` 必填，其它依赖按需注入。nil 依赖只让对应
  RPC 返回 UNAVAILABLE，不会静默成功。
- 宿主适配器：`EventSink` → `internal/events`/`internal/storage`（Publish 返回 journal id/sequence，
  ReportChanges 转 resource.changed，Ack 写 durable cursor）；`SecretRevealer` → `internal/secrets` +
  `internal/operations`（校验 operation 属于本实例、未结束）；`AuditSink` → `internal/operations/audit`
  或 storage；`Invoker` → operations 的插件调用路径；`State` 可用内置文件或 storage。
- `Server.Ingest` 是 journal → 插件订阅的接缝：宿主在节点 journal 派发到本插件时调用，
  事件必须带 journal sequence 和完整 subject。它是本包与 `internal/events` 解耦的关键。
- `Limits.MaxTotalBytes = hostsvc.KVMaxBytes(manifest resources.kv_max_kb)`；
  `clock.Clock`/`slog.Logger` 可直接用 `internal/platform` 的实现。
- capability（`state.kv.read`/`state.kv.write`/`events.publish:<type>`/`events.subscribe:<topic>`/
  `secret.reveal:<ref>` 等）**不在本包实现**：Config 没有 capabilities 字段（按任务给定的 Config 形状）。
  所有六个服务无条件注册，每个 RPC 不做 capability 判断；授权必须由 sink/Invoker 或后续
  `Authorizer` 钩子补上（见 §9 风险 1）。

## 9. 未完成 / 风险

1. **capability gating 缺失**：本包只做“内核证实是谁”和参数/资源限制，不做 manifest capability 检查。
   六个服务全部注册（proto 允许“按 capability 只注册部分服务”，但 Config 未提供授权信息）。
   建议下一步在 Config 增加 `Authorize(ctx, peer, method) error` 窄钩子，或在 controller 侧包装；
   在补上之前，能连上 host socket 的插件可以调用全部 RPC（但它只能触及自己的 state/事件/审计配额，
   跨实例能力仍在 sink/Invoker 内校验）。
2. **instance_handle 未校验**：一个 `Server` 服务一个实例。插件进程若同时承载多个实例（蓝绿），需要
   每实例一个 host socket，或在 accept 之后按 handle 多路复用；当前不支持同一 socket 多实例。
3. **订阅只覆盖本地缓冲**：`SubscribeEvents` 不读 journal 历史；durable 重放要么由宿主把事件
   `Ingest` 进来，要么后续增加 `EventSource` 接口。本地 ack 游标只在内存，Agent 重启后需要客户端
   用 `last_acked_sequence` 重新给起点（协议允许）。缓冲溢出会跳过最旧事件并记 warning，不保证
   at-least-once（journal 才是可靠来源）。
4. **SO_PEERPIDFD 路径未在本构建机执行**（kernel 5.4）。回退路径（仅 SO_PEERCRED）已测；pidfd
   代码用与 spike 相同的 getsockopt 语义，但需要在 ≥6.5 的 CI/测试机上补一条断言（白盒测试已记录
   `PIDFD available`）。
5. **生产 PeerVerifier 不在本包**：需要按 spike §5 实现 `/proc/<pid>/cgroup` + MainPID + uid +
   starttime 校验；失败必须返回 error。没有它，本包只保证“连接来自某个本地进程”。
6. **State 单写者假设**：无跨进程文件锁；必须由一个 supervisor 保证同一 StateDir 只有一个 Agent/
   Server。stale socket 的“探测后删除”在两进程同时启动时也有窄竞态（生产由 supervisor 串行化）。
7. **List 带 values 接近 4 MiB 时可能超过 gRPC 客户端默认 4 MiB 接收上限**（服务端 send 上限也是
   `MaxRequestBytes`）。建议大 state 用 `include_values=false` 或更小的 `MaxTotalBytes`/分页。
8. **配额是进程内状态**：审计/secret 限频在 Agent 重启后重置；审计队列是“在途”计数，不是持久队列。
   安全语义依赖 journal 审计而不是本包的配额。
9. **审计配额与 secret 审计共享**：插件刷 audit 可以耗尽自己的审计预算，从而使后续 secret reveal
   fail closed（拒绝）。这是有意的 fail-closed 取舍，但需要在集成文档中告知插件作者。
10. **未做**：并发 State 大值压测、长时间 Subscribe 稳定性、真实 journal 适配器联调、Windows/非 Linux
    （`peer_other.go` 只保证编译，`Serve` 会因缺少 SO_PEERCRED 失败）。

## 10. 参考

- `api/qwq/platform/v1/platform.proto`（Host 服务、HostCallContext、错误约定、Subjects）
- `spikes/p2t1/REPORT.md` §3/§5（SO_PEERCRED 在 Host 通道上的实测、每插件组/2750/0660 模板）
- `sdk/pluginsdk/errors.go`（ABORTED → REVISION_CONFLICT、Host 调用错误映射）
- ADR-0003（传输与身份）、ADR-0004 D2/D3/D7（CAS、变更、操作生命周期）、ADR-0007（错误与 capability）
