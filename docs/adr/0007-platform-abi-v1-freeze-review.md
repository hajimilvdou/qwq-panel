# ADR-0007：Platform ABI v1 冻结评审

- 状态：Accepted。冻结在三个场景测试通过后生效：`platform.proto` 头部改为 `ABI status: frozen`
- 日期：2026-11-01
- 关联：ADR-0002、ADR-0003、ADR-0004、ADR-0005；`IMPLEMENTATION-PLAN.md` P0-T7

## 背景

P0-T7 要求冻结前用三个场景走通生成代码的调用路径：空插件；订阅插件调用 Core Driver 的 Apply；AI 开启安全基线（plan → approve → execute）。同时评审节点协议的消息形态，避免首版之后再改 ABI。

逐个场景对照 proto 推演后，发现下表中的缺口。冻结后只能追加，所以缺口要么现在补，要么确认以后能用追加的方式补。

## 决策：本次改动

| # | 发现 | 改动 |
|---|---|---|
| 1 | ADR-0004 D3 只覆盖了宿主自有的表（同事务写 outbox）。插件自有资源（插件 KV、私有 SQLite 中的数据）被修改时，宿主不知道，`resource.changed` 发不出来，界面不同步 | 新增 `ResourceChange{subject, revision, changed_pointers, deleted}`。操作内的变更放进 `InvokeResponse.changes` 与 `JobProgress.changes`（宿主与 operation 结果一起发事件）；操作外的变更（Activate 之后的定时任务）用 `HostEventsService.ReportChanges`。插件不能自己发布 `resource.*`、`operation.*` 类型的事件 |
| 2 | subject 的写法没有定义，插件可能写出宿主或别的插件的 subject | 插件只写相对 subject（`<段>(/<段>)*`，段为 `[A-Za-z0-9._~-]{1,128}`）；宿主加实例命名空间前缀，如 `nodes/local/plugins/security.scan/instances/default/resources/baseline`，controller 插件为 `plugins/<plugin_id>/resources/<相对 subject>`；固定的 `resources/` 段使插件资源不会与实例路径下宿主自己的子资源冲突（与 OpenAPI 的 `Subject` 一致）。Precondition、PlannedChange、ResourceChange 用相对 subject，事件与公共 API 用完整 subject |
| 3 | ADR-0002 的公开路由 `/p/{plugin_id}/...` 没有对应的 RPC，插件无法响应请求 | `PluginService.ServePublicRoute`：宿主负责 TLS、限流、请求体上限和路由表，解析出目标实例后调用；请求中剥离 `Cookie`、`Authorization`、`Proxy-Authorization`，响应中剥离 `Set-Cookie` 与逐跳头并加上宿主的安全头；每个方向 4 MiB；匿名，`actor` 为空 |
| 4 | 有效风险 = max(声明风险, capability 下限)，但 capability 只在插件级声明：插件只要有一个高敏能力，所有写操作都被抬到 high | `OperationDescriptor.capabilities`（manifest `operations[].capabilities`）：operation 声明自己用到的 capability，必须是插件级声明的子集（安装器检查）。风险下限按它计算；带 `operation_id` 的宿主调用按它检查；不声明时等于插件的全部 capability（保守默认）；manifest 不允许空列表，因为 protobuf 的 repeated 字段无法区分"空"与"未声明"。插件级授权仍是安全边界，operation 级列表用于风险计算、确认卡片展示和纵深防御；`secret.reveal` 仍然必须带 `operation_id` |
| 5 | `InvokePlugin` 调用 `mode=job` 的目标（如 Core Driver 的 Apply）或需要批准的目标时，调用方拿到 `operation_id` 后没有办法等待或取消 | 新增 `OperationState` 枚举；`InvokePluginResponse.state`；`HostInvokeService.WaitOperation`（长轮询，上限 60 秒）与 `CancelOperation`，只能作用于本实例创建的 operation。子 operation 继承父 operation 的 actor，记录 `parent_operation_id`；有效风险高于父 operation 时，单独进入 `AWAITING_APPROVAL` |
| 6 | 多节点时 controller 插件（如订阅）要调用某个节点上的插件，请求里没有目标节点 | `InvokePluginRequest.target_node_id`，空为调用方所在节点；只有 `placement=controller` 的插件可以指定其他节点 |
| 7 | 事件游标按实例只有一个，同一实例的多个订阅、重启后的续传会互相覆盖 | `SubscribeEventsRequest.subscription` 与 `AckEventsRequest.subscription`：宿主按 (实例, 订阅名) 保存游标；`last_acked_sequence = 0` 表示从宿主保存的游标续传。`Event.sequence` 的作用域是订阅方读取的日志：node 插件读节点日志，controller 插件读 Controller 日志 |
| 8 | KV 无法枚举，插件只能自己维护索引 | `HostStateService.ListState`（前缀 + 分页，可选返回值）；写明 key 字符集与长度、单值 1 MiB 上限 |
| 9 | 跟随模式横幅需要"步骤 i/n"（ADR-0004 D9），只有 `step` 名不够 | `JobProgress.step_index`、`step_count` |
| 10 | 确认卡片面向不懂技术的用户，只有 before/after JSON 不够 | `PlannedChange.description`：一行说明，本地化，按不可信文本显示并标明"来自插件" |
| 11 | 插件返回的错误与说明无法本地化 | `RequestContext.locale`（BCP 47） |
| 12 | 插件无法知道宿主支持哪个 minor，不能按需使用新 RPC | `InitializeRequest.host_abi_minor` |
| 13 | 错误模型不一致：`InvokeResponse.violations` 与 `ErrorDetail` 并存，`RunJob` 失败时无法给字段级错误 | `ErrorDetail.violations`；删除 `InvokeResponse.violations`（字段号 3 保留）。规则：gRPC 状态码表示传输与宿主侧失败（UNAVAILABLE、DEADLINE_EXCEEDED、PERMISSION_DENIED、UNIMPLEMENTED）；调用到达处理函数后的业务结果用 `ErrorDetail` 的稳定 code，gRPC 状态为 OK |
| 14 | `InvokeRequest.idempotency_key` 多余：客户端幂等键由网关在创建 operation 时去重，插件看到的是 `operation_id` | 删除（字段号 5 保留），新增 `attempt`；插件按 `(operation_id, attempt)` 识别一次执行，与 `RunJobRequest` 一致 |
| 15 | `RunJob` 流的语义没有写明 | 零或多条进度 + 恰好一条终止消息；取消、超时、流中断（如 Agent 重启）都表现为流 context 取消；宿主不恢复中断的流，该次 attempt 记为失败，只有幂等 operation 才以 `attempt + 1` 重试 |

`buf breaking` 对照 `main` 报告的破坏性变更只有两处：删除 `InvokeRequest` 字段 5 与 `InvokeResponse` 字段 3。冻结前允许，字段号与名称已 `reserved`。

## 决策：本次不改

- KV 不提供多键事务：复杂状态用插件私有 SQLite（ARCH §5.6）；确有需要时以 minor 追加。
- 公开路由不支持流式与超过 4 MiB 的响应：订阅链接这类内容很小；以后以新 RPC 追加。
- 公开路由不传客户端 IP：涉及隐私。需要按设备限制的插件出现时，以新字段 + 显式 capability 追加。
- `JobProgress` 不带逐步骤的 `ui_route`：跟随模式用 operation 的 `ui_route` 与 `changed_pointers` 推导（ADR-0004 D9）。
- 防火墙、服务管理等高敏宿主能力不放进 platform v1：它们是独立、版本化的 Host Capability 服务（ARCH §5.4），随第一个需要它们的插件设计（P6）。
- `PluginDescriptor` 不列公开路由：路由由 `public.route:<name>` capability 声明。

## 节点协议（`api/qwq/node/v1/node.proto`，草案）

评审的是消息形态，冻结推迟到 P4（多节点）：

- Agent 主动建立一条双向流 `NodeSessionService.Session`，standalone 走本地 UDS（`node_id` 为 `local`），多节点走独立端口的 mTLS，`node_id` 只从证书取。
- 握手 `Hello`/`Welcome` 交换版本范围、节点事实与续传位置；节点协议有自己的版本号，与 Platform ABI 无关。
- 命令直接内嵌 Platform ABI 的请求（`InvokeRequest`、`RunJobRequest`、`PlanOperationRequest`、`ServePublicRouteRequest`），结果内嵌对应的响应，因此本地与远程的插件调用形态相同，Platform ABI 冻结后节点协议不需要复制或转换这些消息。
- 命令与可靠事件都是至少一次，按方向的序号 + 累计确认；Agent 重写 `RequestContext.node_id`。
- 期望状态 `DesiredState` + 实际状态 `StateReport` 收敛；日志窗口不够时 `ResyncRequest`。
- enroll 在单独端口；证书在会话内轮换。
- 生成代码与 Platform ABI 一起放在 `sdk/gen/`（插件不使用它；它同样是 Apache-2.0，单一生成目标更简单）。`buf.yaml` 在 P4 冻结前对 `qwq/node` 关闭破坏性检查。

## 冻结规则

- 三个场景测试（`tests/abi/`）通过后，把 `platform.proto` 头部改为 `ABI status: frozen`；此后 `scripts/check.sh` 遇到 `buf breaking` 报错即失败。
- 冻结后只追加字段、消息、枚举值和 RPC，每次追加把 `sdk/abi.Minor` 加 1。删除或改语义需要 v2（新 package `qwq.platform.v2`），宿主可以同时提供两个版本。
- 改动 proto 仍然先写 ADR。

## 代价

- P2 的宿主侧多实现 5 个 RPC：`ServePublicRoute`（插件侧）、`ReportChanges`、`ListState`、`WaitOperation`、`CancelOperation`。
- SDK 要处理相对 subject 与 `ResourceChange` 的上报；安装器多一条子集检查。
- 两处破坏性删除，只影响尚不存在的插件。

## 四个问题（HANDOFF §1.3）

1. 空闲开销：无新增常驻组件；新增的是消息字段与按需调用的 RPC。
2. 峰值：`WaitOperation` 是有上限的长轮询，宿主按实例限制并发；`ReportChanges` 限频。
3. 失败：插件不上报变更时，界面退化为"刷新可见"，不影响操作正确性；公开路由失败只影响该插件。
4. ABI：本 ADR 就是冻结前的 ABI 改动。

## 附录：冻结后的语义记录（线格式不变）

- 2026-11-09，包格式（SDK-05）：签名只覆盖 `manifest.json`，tar 头的执行位不受签名保护。因此执行位由 manifest 推导：`Pack` 与 `Read` 都把 `entrypoint` 强制为 `0755`；`Read` 对 `bin/` 之外的文件一律给 `0644`；`bin/` 下其他文件保留头部的执行位。Windows 上打包不再丢失入口点的执行位，篡改头部也无法让数据文件变成可执行文件。
- 2026-11-09，`ListState`（SDK-06）：proto 只加注释。宿主可以返回少于 `page_size` 条（至少一条），使响应不超过消息上限；`next_page_token` 从最后返回的 key 之后继续。SDK 把 `RESOURCE_EXHAUSTED` 改为不可重试，原样重试只会撞同一上限。
