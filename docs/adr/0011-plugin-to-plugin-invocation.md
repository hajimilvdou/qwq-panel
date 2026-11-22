# ADR-0011：插件间调用的授权与子 operation

- 状态：已接受（Accepted，2026-11-08，发起人批准）。正式方案由任务 EXT-02 实施；实施完成前宿主保持下文“临时收口”的行为
- 关联：ADR-0004 D1/D4/D6、ADR-0007 #4/#5/#6、ADR-0010 §2.1/§3、ARCH §5.4、§10.3；审查任务卡 PLG-03

## 背景

P2 的 `hostInvoker.InvokePlugin` 把调用直接转发给目标插件：以 `ACTOR_KIND_SYSTEM` 执行，没有 capability 检查、RBAC、审批和权限模式，不写审计，不建子 operation；转发给目标的 `operation_id` 是调用方自报的，目标插件停着还会被拉起。`CancelOperation` 先取消再查归属，`WaitOperation` 先等待最多 60 秒再查归属，而 `system` actor 能读到所有 operation，所以任何插件都能取消任何未结束的 operation。

失败场景：AI 会话（safe）调用插件 A 的 `auto` 低风险动作，A 内部调用插件 B 的高风险写操作，B 不经审批就执行，审计里只有 A 的那一次。被攻破的插件还能批量取消所有待审批和运行中的 operation。

## 临时收口（PLG-03，已实施）

正式方案落地前，宿主只提供下面的行为，不改 proto、manifest schema 和权限模型：

- `InvokePlugin` 一律拒绝：返回 `ErrorDetail{code: PERMISSION_DENIED}`，gRPC 状态为 OK；不解析目标、不启动目标插件、不建 operation。
- `WaitOperation`、`CancelOperation` 先 `Get` 再 `owns`，通过后才调用 `Wait`/`Cancel`。别人的 operation、不存在的 id、查询失败都返回同一个 `NOT_FOUND`，插件无法借此探测 operation 是否存在。

已知的宽松点：`owns` 现在比较的是 `operation.target`，即“派发给本实例的 operation”，比 ADR-0007 #5 的“本实例创建的 operation”宽。`InvokePlugin` 被拒绝期间插件创建不了 operation，这个差别的影响面限于插件自己的工作；§6 收紧。

## 决策（正式方案，已批准）

本方案不改 ABI 和 manifest schema。下述各项全部落地后，才移除上面的拒绝。

### 1. 走单一写入通路

`InvokePlugin` 改走 `operations.Run`（ADR-0004 D1），不再直连目标 client。`Action` 取目录 ID `<plugin_id>/<operation>`，`Target` 取目标的 plugin、实例和节点。审批、审计、事件、幂等都由这条通路提供，不另写一套。

- 目标必须已在运行（ARCH §5.4 的“路由到 ACTIVE generation”）。`pluginDispatcher` 的 `Invoke`/`RunJob` 用 `attach`，会启动单元；子 operation 的派发改用 `live`，目标未运行返回 `PLUGIN_UNAVAILABLE`。
- 目标 `effect=read` 时 `runRead` 不产生 operation 记录，因此没有子 operation，但 §4 的能力检查和 §7 的审计照做。

### 2. 父 operation 由宿主确定

`HostCallContext.operation_id` 由插件填写，只能当选择子，绝不能当事实。宿主在自己的记录里查它，满足 `status=RUNNING` 且 `target` 是本 plugin、实例、节点（与 `hostSecretRevealer.dispatchedTo` 同一判定，抽出来复用）时，才把**宿主记录里的** `op.ID` 填进 `RunRequest.ParentOperationID`。不满足一律 `PERMISSION_DENIED`，绝不退化成“无父调用”。

- 为什么还要用插件给的 id：冻结的 ABI 没有“本次派发”的凭据，同一实例并发多个 RUNNING operation 时，宿主无法从连接判断这次调用属于哪一个。
- 残余风险：被攻破的插件可以在“正在派发给自己的多个 operation”之间挑一个当父。它只能挑自己手上的，§4 的授权和 §5 的风险规则照常生效。要彻底消除需要以 minor 追加派发凭据，不在本 ADR 范围。
- 无父调用首版拒绝（`PERMISSION_DENIED`）：包括定时任务和事件回调，也包括父动作是 `read` 的情况（`runRead` 不落库，查不到父）。计划阶段父 operation 不是 RUNNING，同样被拒绝。需要插件自主发起调用时，另行设计授权。

### 3. actor：继承父 operation

子 operation 的 `actor` 等于父 operation 的 actor，并且**以这个 actor 调用 `Run`**。

任务卡 PLG-03 建议 `actor=plugin:<id>`、`OnBehalfOf=父 operation 的 actor`。本 ADR 采用 ADR-0007 #5 的继承语义，不采用该写法，原因：

1. ADR-0007 #5、`platform.proto`（“with the same actor”）、`operations.Run` 和 `TestChildOperationRiskEscalation` 都已是继承语义，ABI 已冻结。
2. `Actor.OnBehalfOf` 是用户 ID，且只对 `ai_agent`/`service` 合法（`Actor.Valid`），放不下父 actor 的 `(kind, id, on_behalf_of)`。
3. `plugin:<id>` 现有的表示是 `system`：authz 对它直接放行，`canReadAll` 为真，`ai_confirm` 也不会触发，等于重新打开本 ADR 要堵的口子。

任务卡想要的“能看出是哪个插件发起的”用单独的事实记录：子 operation 的审计 details 写 `invoked_by: {plugin_id, instance_id}`，再加 `parent_operation_id` 链。

必须用父 actor 提交而不是 `system`：`Run` 的 `authorize`、`limits` 在替换为父 actor 之前执行，以 `system` 提交时 RBAC 和委托策略（`MaxRisk`、`on_approval_required`、速率）都会失效。

### 4. 能力：`plugin.invoke:<plugin_id>/<operation>`

命名采用 ARCH §5.4、§10.3 和 `platform.proto` 的写法，manifest 中写作 `name: plugin.invoke`、`scope: <plugin_id>/<operation>`。任务卡的 `plugin.invoke:<target>` 是它的简写，不引入新名字；粒度必须到 operation，只到插件等于放开目标的全部动作。

- scope 精确匹配，不支持通配。
- 两层检查（ADR-0007 #4）：插件级授权是安全边界；父 operation 声明了 operation 级 capabilities 时，还必须在该列表内。
- 授权只取宿主已验证的 manifest，不取插件自报的任何内容。
- 跨节点沿用 ADR-0007 #6：只有 `placement=controller` 的插件可以指定其他节点。

有效权限因此是 RBAC ∩ 委托策略 ∩ 插件 capability（ADR-0004 D4），不超过父 actor，也不超过调用方插件。

### 5. 风险、审批与权限模式

- 子 operation 记录和展示的有效风险 = max(目标 operation 的有效风险, 父 operation 的有效风险)。`Run` 现在只记目标自身的风险，需要修改。
- 审批判定用**目标自身**的有效风险：高于父 operation 时必须单独 `AWAITING_APPROVAL`（ADR-0007 #5），其余按 `DecideApproval` 判定，ADR-0010 §3 的硬规则不变。不把 max 值作为判定输入，否则高风险父 operation 下的每个低风险子 operation 都要再批一次，与“更高时才单独审批”不符。
- 权限模式（ADR-0010 §2.1）沿用父 operation。模式现在只在请求 context 上（`WithPermissionMode`），插件的宿主调用拿不到；实施时给 `operations` 表追加 `permission_mode` 列（迁移只追加），子 operation 读父的值，读不到按 `safe`，永不放宽。

背景中的失败场景因此变为：B 的风险高于 A 的动作，子 operation 进入 `AWAITING_APPROVAL`，审批卡和审计都能看到完整链路。

### 6. Wait/Cancel 的归属收紧到“本实例创建”

`owns` 改为：`op.parent_operation_id` 非空，且父 operation 的 `target` 是本实例。子 operation 的 actor 继承自父，不能表示创建者；`parent_operation_id` 与 `target` 都已落库且不可变，不需要新增列。派发给插件但不是它创建的 operation，插件不再能等待或取消。先查后操作、统一 `NOT_FOUND` 的做法不变。

### 7. ARCH §5.4 的其余要求

- **schema 校验**：`Run` 目前只校验 args 是 JSON 对象，宿主还没有按 `ArgsSchema` 校验的实现，实施时必须补上，校验失败不派发。
- **审计**：拒绝也写审计（`plugin.invoke`，outcome `denied`，含调用方、目标和原因）；放行的调用由 operation 通路写审计，见 §3。
- **deadline**：沿用 gRPC 调用的 context。
- **幂等**：`idempotency_key` 按调用实例隔离（`platform.proto`）。子 operation 的 actor 是父 actor，所以 key 要加前缀 `plugin-invoke:<plugin_id>/<instance_id>:`，避免不同插件的 key 互相冲突；插件未提供时宿主生成一次性 key。
- **调用深度**：沿 `parent_operation_id` 计算，上限 3 层，超限 `PERMISSION_DENIED`，防止 A→B→A 环路。

## 后果

- 收口期间，依赖 `InvokePlugin` 的插件会收到 `PERMISSION_DENIED`。仓库内的产品插件都没有使用它；`tests/abi`、`sdk/pluginsdk` 用的是各自的假宿主，不受影响。
- 实施需要改 `operations.Run`（记录 max 风险）、`pluginDispatcher`（子 operation 用 `live`），新增 args schema 校验和一次只追加的迁移。
- 实施时用真实链路的测试替换 `TestHostInvokerRefusesPluginToPluginInvoke`，至少覆盖：背景中的失败场景、伪造父 operation、缺少 capability、无父调用、深度超限、他人 operation 的 Wait/Cancel。
- 残余风险见 §2，需要发起人知悉。

## 未采用

- 保留直连转发，只在 `hostInvoker` 里补 capability 检查：审批、权限模式和审计仍要再写一套，违反 ADR-0004 D1。
- 子 operation 以 `plugin:<id>` 为 actor：见 §3。
- 直接信任 `HostCallContext.operation_id`：插件可以把调用挂到任意 operation 上，继承其 actor。
- 按插件粒度授权（`plugin.invoke:<plugin_id>`）：一项授权放开目标的全部动作。
- 无父调用按“插件自身身份 + 中高风险一律审批”放行：`tests/abi` 的试验宿主这样做过，ABI 也未规定；但现有 actor 模型里没有合适的插件主体，首版先拒绝。
