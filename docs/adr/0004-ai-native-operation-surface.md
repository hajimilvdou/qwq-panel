# ADR-0004：AI 原生操作面

- 状态：Accepted
- 日期：2026-11-01
- 范围：宿主与插件契约中让 AI 能像人一样操作面板的底层部分；不含 AI 模块插件本身（对话界面、模型接入），后者按路线图第 7 项单独设计
- 关联：ADR-0001 A05、A06；ADR-0002；架构审查 C2、C8、S6、S7

## 背景

目标：操作人员既能手动操作面板，也能让 AI 直接操作；AI 的修改在所有打开的界面上实时出现，就像另一位管理员在操作；同时尽量节省 token。

现有 AI 操控面板时不同步的根因：

1. 绕过业务逻辑直接改数据库或配置文件，重载、校验等副作用没有触发。
2. 前端缓存数据、服务端不推送，只有刷新才能看到变化。
3. 业务逻辑写在前端（如向导在浏览器里串联多个请求），AI 只调其中一个接口，系统停在一半。
4. 没有版本号的"读-改-写"，人和 AI 互相覆盖。
5. 把"请求返回 200"当成"操作完成"。

截图加模拟点击能保持同步，但每一步都要看图（按 Anthropic 公式，1280×800 约 1,365 tokens），多步任务累计数万 tokens，界面改版即失效。

## 决策

### D1 单一写入通路
所有状态修改都经 Operation，包括 Shell 自己的按钮。禁止只存在于前端的业务逻辑；多步流程（如安装向导）是服务端 operation 的步骤，前端只是它的视图。插件 UI 在 sandbox iframe 中只能经 Shell 调用本插件的 operation（ARCH §5.5），宿主功能（用户、节点、插件管理）也以 operation 暴露。由此 AI 能做的事与人在界面上能做的事完全一致。

### D2 资源版本与乐观并发
每个可修改的资源都有单调递增的 `revision`。修改请求必须带 `expected_revision`，不匹配返回 `409 REVISION_CONFLICT` 并附当前 revision。配置 revision（ARCH §6.5）是其特例。

### D3 变更事件与界面投影
每次修改在同一事务中经 outbox 写入 `resource.changed { subject, revision, actor, operation_id, changed_pointers[] }`；operation 进度发 `operation.updated`。插件自有资源（插件 KV、私有 SQLite）由插件以 `ResourceChange` 上报，宿主补全 subject 前缀、actor 与 operation_id 后写 outbox（ADR-0007 补充）。Shell 经 SSE 订阅，只更新变化部分。正在编辑的表单被他人（含 AI）改动时，显示"已被 AI 修改为 revision N，查看差异/重新加载"，不静默覆盖。

### D4 操作者模型
`Actor { kind: human | ai_agent | service | system, id, on_behalf_of }`。AI 使用宿主签发的委托令牌（delegation），不使用人的会话 Cookie。有效权限 = 委托人 RBAC ∩ 委托策略 ∩ 插件 capability，永远不超过委托人。审计和事件都带 actor；AI 的操作记为"AI 代表某用户执行"。

### D5 动作目录与元数据
目录由插件 manifest 的 operations 和宿主 OpenAPI 自动生成。每个 operation 声明：

| 字段 | 含义 |
|---|---|
| `summary` | 一行说明，≤ 120 字，供检索与确认卡片 |
| `effect` | `read` / `write` / `destructive` |
| `risk` | `low` / `medium` / `high` |
| `mode` | `invoke`（同步）/ `job`（长任务，返回 202） |
| `idempotent` | 是否幂等 |
| `plannable` | 是否实现 `PlanOperation` 预览 |
| `undo` | 撤销用的 operation 名（可选） |
| `ui_route` | 对应的界面路由，用于跟随模式（可选） |
| `docs` | 包内说明与示例文件（可选，按需加载） |

`effect/idempotent` 可直接映射为 MCP 工具注解 `readOnlyHint/destructiveHint/idempotentHint`。插件提供的 `summary` 和文档按不可信文本处理：限制长度，作为数据展示，不作为指令。

### D6 风险分级与人工确认
- **有效风险** = max(声明的 `risk`，宿主按所需 capability 定的下限)；所需 capability 取 operation 级声明，未声明时取插件的全部 capability（ADR-0007）。例如需要 `system.*`、`secret.reveal:*`、`network.egress:*` 的 operation 下限为 `high`；`effect=destructive` 一律为 `high`。插件不能自己调低。
- 执行策略（由委托策略配置，以下为默认）：`read` 直接执行；`low` 执行后通知；`medium` 和 `high` 进入 `AWAITING_APPROVAL`；`destructive` 还需要二次验证（MFA）。
- **确认卡片由宿主渲染**：先列宿主已知的事实（operation、参数、目标节点/实例、所需能力、有效风险、能否撤销），再列插件 `PlanOperation` 返回的变更预览并标明"来自插件"。AI 写的说明文字不进入确认卡片。
- **批准只能来自真人会话**（带 CSRF 的 Web 会话，必要时 MFA），委托令牌永远不能批准。批准默认 15 分钟过期。

### D7 计划与执行绑定
`plan` 生成 `plan_id`，记录 operation、参数哈希、preconditions（`subject + revision` 列表）、有效风险和过期时间。`execute(plan_id)` 时：需要批准的检查已批准；宿主原子校验宿主侧 preconditions，插件侧 preconditions 随 `InvokeRequest/RunJobRequest` 传给插件，由插件在自己的状态上原子校验；任何不匹配返回 `PRECONDITION_FAILED`，保证"确认的"就是"执行的"。不可规划的 operation 仍可确认，卡片只显示参数。

Operation 状态机：

```text
PENDING ─▶ AWAITING_APPROVAL ─▶ APPROVED ─▶ RUNNING ─▶ SUCCEEDED / FAILED / CANCELED
              │                                 
              ├─▶ REJECTED
              └─▶ EXPIRED
PENDING ─▶ RUNNING（无需批准时）
```

### D8 面向 AI 的固定工具（宿主公共 API）
`/api/v1/agent/*` 提供一组固定工具，工具定义不随插件增减而变化，便于命中模型服务的提示缓存：

| 工具 | 作用 | 返回控制 |
|---|---|---|
| `find_actions(query, scope?)` | 宿主本地检索目录，不调用模型 | 每条只有 id、summary、effect、risk，默认 ≤ 8 条 |
| `describe_action(id)` | 单个动作的 schema 与示例 | 按需加载 |
| `read(subject, fields?, since_revision?)` | 读取状态，支持字段投影和增量 | 超过上限时分页并说明截断 |
| `plan(action, args, target)` | 无副作用预览 | 结构化 changes、violations、warnings |
| `execute(plan_id \| action+args)` | 创建 operation | 返回 operation_id 与状态 |
| `wait(operation_id, timeout)` | 服务端长轮询，直到结束或需要批准 | 只返回最终结果 |
| `cancel(operation_id)` | 取消 | — |

意图级动作（如"开启安全基线"）就是普通的 `mode=job` operation，由插件在服务端组合多个步骤，不需要特殊契约。校验错误使用字段级 `FieldViolation`，AI 一次即可改对。

### D9 跟随模式
Shell 根据 `operation.updated` / `resource.changed` 事件中的 `ui_route` 与 `changed_pointers` 自动导航和高亮，顶部横幅显示"AI 正在操作：…（步骤 i/n）"及"暂停""接管"。画面由界面自行推导，AI 并不点击，零额外 token。"暂停"挂起委托，"接管"撤销委托。

### D10 不可信内容与撤销
- 工具结果中来自节点、日志、插件的字符串标记为不可信数据。防护不依赖模型自觉，而依赖 D6 的确认与 D4 的权限上限。每个委托有速率限制。
- 可撤销：`undo` operation、配置 revision 回滚、插件版本回滚。不可逆的操作在确认卡片上明确标出。

### D11 分工
- **宿主**（信任边界，不能热更）：动作目录、`/api/v1/agent/*`、委托令牌、批准、审计、风险下限、事件推送。
- **AI 模块插件**（`placement=controller`，可热更）：对话界面、模型服务配置（API key 作为 secret 引用）、提示词、MCP 服务端适配。模型调用经 `network.egress` 出站代理。外部支持 MCP 的 Agent 也通过同一组工具接入，鉴权和委托仍由宿主签发。

### D12 边界
AI 只能执行目录中的 operation，不提供通用 shell；排障信息由只读的诊断类 operation 提供。

## 契约落点

| 位置 | 内容 |
|---|---|
| `api/qwq/platform/v1/platform.proto` | `Actor`、`OperationDescriptor` 新字段、`PlanOperation`、`Precondition`、`FieldViolation` |
| `api/manifest/v1/manifest.schema.json` | operation 的 `summary/effect/risk/mode/plannable/undo/ui_route/docs` |
| 公共 API（OpenAPI，P0-T5） | `/api/v1/agent/*`、`expected_revision`、409、approvals、`fields`/`since_revision` |
| Controller DB | `delegations`、`plans`、`approvals`；`operations` 增加 actor 与状态；所有资源表带 `revision` |

## 代价

- 每个 operation 都要写元数据；高风险 operation 最好实现 `PlanOperation`。
- 宿主多了委托、计划、批准三块逻辑；界面要处理冲突提示。
- "不会不同步"依赖三条纪律：无前端专属业务逻辑、不绕过 operation 写数据、每次写入都发事件。必须由 CI 契约测试守住（见实施计划）。

## 四个问题（HANDOFF §1.3）

1. 空闲开销：一个目录索引和几条路由，schema 已加载；AI 模块插件按需启动。
2. 峰值：AI 与人共用 operation 队列，1C1G 更新并发仍为 1。
3. 失败：AI 模块或模型服务故障只影响 AI 功能，不在任何手动请求的必经路径上。
4. ABI：会改变，因此在 P0 冻结前完成。

## 验收（P1/P4 阶段落实）

1. 人和 AI 同时修改同一资源：后到者得到 409，界面显示冲突，不丢更新。
2. AI 创建的 operation 在所有打开的界面上 1 秒内出现。
3. 委托令牌访问委托人 RBAC 之外的资源被拒绝；委托令牌调用批准接口被拒绝。
4. plan 之后资源被改动，execute 返回 `PRECONDITION_FAILED`。
5. 注入测试：日志中含"关闭防火墙"类指令时，高风险操作仍停在 `AWAITING_APPROVAL`。
6. 基准："开启安全基线"端到端的 token 用量与步数有记录，作为回归基线。

## 未采用

- 以截图/DOM 的 computer-use 作为主要方式：费 token、脆弱。可以作为没有 operation 的第三方网页的兜底，但不进入面板主路径。
- 把全部 operation 一次性作为工具交给模型：几百个工具的定义每轮就要几万 tokens。
- AI 直接读写数据库或配置文件：不同步的根源。
