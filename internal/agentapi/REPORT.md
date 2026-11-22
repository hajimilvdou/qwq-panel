# P1-T8：`/api/v1/agent/*` 七个 AI 工具

本包实现 ADR-0004 D8 的七个工具（`find_actions`、`describe_action`、`read`、
`plan`、`execute`、`wait`、`cancel`），全部 `POST + application/json`，只接受委托
Bearer（网关 `AccessDelegation`）。它不新增写入通路：写操作一律经
`internal/operations`（`CreatePlan` / `Run` / `ExecutePlan` / `Cancel`），授权一律由
`internal/authz` 决定，本包只在检索与读取时用 authz 的导出函数做**预过滤**。
响应体严格按 `api/public/v1/openapi.yaml` 的 schema 组装。依赖方向与 ADR-0008 §1
一致：只依赖既有域包，未改动本包以外的任何文件，未新增依赖。

## 1. 文件

| 文件 | 内容 |
|---|---|
| `doc.go` | 包说明：工具 ↔ 服务对应、三条纪律（只接受委托、只暴露委托人可见的、绝不静默截断） |
| `deps.go` | `Deps`、`Register`（七条路由）、`DocsLoader`、`x-qwq-limits` 常量、`handlers.register` |
| `handler.go` | `handlers`、`call`、`begin`、请求解码、problem 渲染、schema 正则与字段校验、`clipRunes`、`jsonObject` |
| `effective.go` | `delegationView`（委托记录 + 委托人当前角色）、`allowsAction`、`allowsRead`（human-only 判定用 `authz.IsHumanOnly`） |
| `find_actions.go` | `FindActionsRequest/Response`、校验、`catalog.Find` + 权限闭包、`actionNode` |
| `describe_action.go` | `DescribeActionRequest`、`ActionMeta`/`ActionDescription`/`Target` 组装、docs 截断、越权 404 |
| `read.go` | `ReadRequest/Response`、subject 分派、users/operations/approvals/plans/delegations 读取、投影、游标、增量 |
| `json.go` | JSON Pointer 解析/嵌套投影、`fitValues`/`fitItems`/`capItems`（字节上限与截断）、`planBody`/`outcomeBody`/`outcomeOf` |
| `plan.go` | `PlanRequest`、`targetInput`、`CreatePlan` 调用、`checkArgs` |
| `execute.go` | `ExecuteRequest`、"`plan_id` 或 `action+args`"校验、两形调用、`OperationOutcome` 归一化 |
| `idempotency.go` | `toolKey`：`Idempotency-Key` → 工具调用 ID → 请求 ID 的稳定推导 |
| `wait.go` | `WaitRequest`、先读起始状态再长轮询、`timed_out`、每委托并发上限 `waitLimiter` |
| `cancel.go` | `AgentCancelRequest`、`operations.Cancel`、越权 404 |
| `helpers_test.go` | 真实 SQLite + 真实 identity/authz/catalog/operations + 组装网关 + `httptest`；controller 适配器的本地副本；HTTP/断言工具 |
| `tools_test.go` / `read_test.go` / `lifecycle_test.go` / `internal_test.go` | 用例，见 §7 |

## 2. 导出 API

```go
type Deps struct {
    DB       *storage.DB
    Clock    clock.Clock
    IDs      *ids.Generator
    Logger   *slog.Logger
    Identity *identity.Service
    Authz    *authz.Authorizer
    Ops      *operations.Service
    Catalog  *catalog.Catalog
    NodeID   string
    // Docs 可选：读取插件包内文档（catalog.Entry.Docs 是包内相对路径）。
    // 为 nil 时 describe_action 不返回 docs（schema 中该字段可选）。
    Docs DocsLoader
}

type DocsLoader func(ctx context.Context, entry *catalog.Entry) ([]byte, error)

func Register(g *gateway.Gateway, d Deps) error
```

`Register` 在服务启动前注册七条路由；`Deps` 缺少必填项、路由重复或网关为 nil 时
返回错误（fail closed）。`Logger` 缺省为丢弃、`NodeID` 缺省 `local`、`Clock`/`IDs`
缺省为系统实现。

限制常量（与 `x-qwq-limits` 逐项对应）：
`FindActionsDefaultLimit=8`、`FindActionsMaxLimit=20`、`ReadItemsDefault=20`、
`ReadItemsMax=100`、`ReadResponseBytes=32768`、`WaitTimeoutDefault=25s`、
`WaitTimeoutMax=55s`、`ConcurrentWaitsPerDelegation=4`。

## 3. 工具与 OpenAPI 的对应

| 工具 | 请求 schema | 成功响应 | 主要错误 |
|---|---|---|---|
| `POST /agent/find_actions` | `FindActionsRequest` | 200 `FindActionsResponse` | 400/401/403/413/429 |
| `POST /agent/describe_action` | `DescribeActionRequest` | 200 `ActionDescription` | 400/401/403/404 |
| `POST /agent/read` | `ReadRequest` | 200 `ReadResponse` | 400/401/403/404 |
| `POST /agent/plan` | `PlanRequest` | 200 `Plan` | 400/403/404/503/504 |
| `POST /agent/execute` | `ExecuteRequest` | **200** `OperationOutcome` | 400/403/404/409/422 |
| `POST /agent/wait` | `WaitRequest` | **200** `OperationOutcome`（`timed_out`） | 400/403/404/429 |
| `POST /agent/cancel` | `AgentCancelRequest` | **200** `OperationOutcome` | 400/403/404/409 |

- **find_actions**：`catalog.Find(query, scope, limit, allow)`，`allow` 按委托有效权限
  过滤；每条只返回 `id/summary/effect/risk`（`ActionSummary`）。`limit` 缺省 8、上限
  20，越界是 `VALIDATION_FAILED /limit`；`query` 1..200 字符。`truncated` 表示还有
  更多匹配。`scope.node_id` 只有本机节点（`Deps.NodeID`）能作答：P1 是 standalone，
  其它节点返回空列表（不是伪造结果）；node 放置的插件动作按本机节点做策略过滤。
- **describe_action**：`catalog.Get` 后做同一套权限判断；不通过时与"不存在"返回**完全
  相同**的 404（不泄露存在性）。默认只给 `action/target/args_schema`；
  `include_result_schema=true` 才带 `result_schema`；`include_docs=true` 才调
  `DocsLoader`（截断到 16384 字符并置 `docs_truncated`，加载失败只记日志、不失败）。
  `target` 由放置方式推导：host 全 false；node 放置 `node_id/plugin_id/instance_id`；
  controller 放置只有 `plugin_id`。`args_schema` 缺失时回退 `{"type":"object"}`。
- **read**：见 §4.2 的 subject 矩阵。单资源返回 `values`（JSON Pointer → 值的**扁平
  映射**，符合 `ReadResponse.values` 的描述；无 `fields` 时整份文档放在 `""` 下），
  并列出不存在的指针到 `missing`。集合返回 `items`（`fields` 存在时对每条做**嵌套**
  投影，并保留 `id`/`*_id`/`revision`，与 REST `fields` 语义一致）与 `next_cursor`；
  `since_revision` 相等时单资源返回 `unchanged=true`，operations/approvals 集合返回
  增量（`delta=true` + `deleted_ids`）。`fields` 最多 32 个 RFC 6901 指针，拒绝数组
  下标（与 REST `fields` 一致，整数组用其自身指针选）。
- **plan**：`operations.CreatePlan`，委托 actor 原样传入；`args` 必填且必须是对象；
  `expected_revision` 必须配 `target.subject`。响应把 `changes/violations/warnings/
  preconditions` 从 null 归一成 `[]`，满足 `type: array`。
- **execute**：只允许一种形式——`plan_id`，或 `action` + `args`（+`target`、
  `expected_revision`）；两者同时给、都不给、`plan_id` 夹带 args/target/revision 都是
  `VALIDATION_FAILED`（指针 `/plan_id` 或 `/args`）。`plan_id` 走 `ExecutePlan`，
  否则走 `Run`；成功恒为 200 + `OperationOutcome`（状态在 body）。`Response` 的
  `Outcome`/`Operation`/重放 body 三种形态统一由 `outcomeOf` 归一；空 `revision`
  （read 动作无 operation 记录）按 schema 省略。
- **wait**：先 `Get` 取起始状态（顺带 404），再按"终态 / 首次进入
  `AWAITING_APPROVAL` / 到期"返回。**调用时已经在 `AWAITING_APPROVAL` 的操作会继续
  等人工决定**，到期返回 200 + `timed_out=true` + 当前状态。`timeout_seconds` 用
  指针类型，显式 0 也是越界（schema `minimum: 1`）。
- **cancel**：`operations.Cancel`；只能取消本委托自己创建的 operation，其它一律 404
  （与不存在的 ID 相同）；`PENDING/AWAITING_APPROVAL/APPROVED` 立即 `CANCELED`，
  `RUNNING` 只置 `cancel_requested`。`reason` ≤ 500 字符。

## 4. 鉴权与可见性

### 4.1 每个工具开头：`begin`
1. 网关 principal 必须是 `SchemeDelegation` 且 `actor.Kind == AIAgent`，否则
   `PERMISSION_DENIED`（服务账号/会话在这一层也拿不到）；
2. 读委托记录：不存在 → 403，`suspended`/`expired` → 403，`on_behalf_of` 与
   `owner_id` 不一致 → 403；
3. 用 `identity.PrincipalRole` 取委托人**当前**角色（被禁用 → 403），得到
   `delegationView{record, role}`。

因此即使某条路由将来被误配成别的 `Access`，七个工具仍会自己拒绝失效委托。

### 4.2 有效权限（= 委托人 RBAC ∩ 委托策略）
`delegationView` 用 authz 的导出件计算：`authz.ParsePermission`、
`authz.RoleAllows`、`Policy.AllowsAction`、`Policy.AllowsNode`，并复用 authz 的
human-only 规则（资源 `host.users/host.delegations/host.service_accounts/
host.approvals` 或动作 `approve/reject`）。`find_actions`/`describe_action` 用它过滤；
`plan`/`execute` 不依赖它——`operations` 会对每次操作调用 `authz.Authorize`（含委托
动作白名单、节点范围与限速），那才是最终裁决。

`read` 的可见性按 subject：

| subject | 规则 | 越权/未实现 |
|---|---|---|
| `users`、`users/<id>` | 委托人角色需 `host.users:read`（viewer 的 read 类权限即可；读取不是"管理"） | 404 |
| `operations`、`operations/<id>` | `host.operations:read` + `operations.Get/List` 自身的可见性（AI 只看自己创建的） | 404 |
| `approvals`、`approvals/<id>` | `host.approvals:read` + `GetApproval/ListApprovals` 的归属检查 | 404 |
| `plans/<id>` | `host.plans:read` + `GetPlan` 的 owner 检查（集合不支持） | 404 |
| `delegations/<id>` | 自己的记录永远可读；别人的要求委托人角色是 **admin**（记录含 owner 与 token 前缀） | 404 |
| `nodes`、`plugins`、`service_accounts`、插件自有 subject | P1 无宿主存储 / 不属于 Subject 列表 / 插件读取契约未实现 | 404 |

`CanApprove` 对 AI 恒 false：本包没有批准入口，`TestHighRiskStopsAtApproval` 断言
`authz.CanApprove(delegationActor) == false`、批准保持 `PENDING`、agent 路由里不存在
approve/decision 路径。高风险动作经 `execute` 停在 `AWAITING_APPROVAL`，AI 只能
`read`/`wait`/`cancel`。

## 5. 限制、截断与并发

- 请求体：plan/execute 按 `x-qwq-limits.max_body_bytes: 4194304` 用
  `BodyPluginJSON`，其余按 1 MiB 默认；JSON 深度、未知字段、类型错误由
  `gateway.DecodeJSON` 统一转成 `VALIDATION_FAILED` + JSON Pointer。
- `read` 单响应 ≤ 32768 字节：单资源按 key 排序逐个保留 `values`，超限丢弃并置
  `truncated{reason:max_bytes, returned:<保留 values 的字节数>, hint}`；集合从头保留
  `items`，超限丢弃尾部并**清空 `next_cursor`**（服务给出的游标指向已取到的最后一
  条，保留它会让调用方跳过被丢弃的条目），hint 提示"用同一 cursor 减小 limit 重试"。
  `max_items` 是安全网（服务已按 limit 裁剪），触发时同样标记。
- 并发：`wait` 每委托最多 4 个，超出返回 429 `RATE_LIMITED` 并带
  `limit{name:"agent_concurrent_waits_per_delegation",max:4}`；计数表在最后一个等待
  结束时删除键，内存只随**在飞**等待增长，不随历史 token 增长。其余工具用网关既有
  Limiter（按 principal 计数），未新增限流器。

## 6. 幂等键（execute / cancel）

`x-qwq-idempotency: required`，但 MCP 适配器重试时未必带 header，因此 `toolKey` 依次取：
`Idempotency-Key`（校验，格式错是 `VALIDATION_FAILED`）→ `X-Tool-Call-Id` →
`X-Request-Id` → 网关请求 ID → 新生成的 `idk_...`。组合成 `"<tool>:<id>"`，不符合
`IdempotencyKeyValue`（16..128、`[A-Za-z0-9_.:-]`）时取 SHA-256 前缀，保证同一个工具
调用重试得到同一个键。同一键不同请求 → `422 IDEMPOTENCY_KEY_REUSED`（operations 判定）。

## 7. 测试

环境：真实 SQLite（`t.TempDir()`）、`clock.Fake`、真实 `identity`/`authz`/`catalog`/
`operations`，`catalog` 里装一个 fixture 插件（低风险 write、高风险 write、read 三个
动作），`operations` 用与 `internal/controller` 相同形状的本地适配器连接，网关 +
`httptest`。委托令牌经 `authz.CreateDelegation` 真实签发。

命令与结果（构建机，`QWQ_REMOTE_SRC=agent1`）：

```text
gofmt -l internal/agentapi                       # 无输出
go vet ./internal/agentapi/...                   # 通过
staticcheck ./internal/agentapi/...              # 通过
go build ./...                                   # 通过
CGO_ENABLED=1 go test -race -count=1 -timeout 300s ./internal/agentapi/...
ok  github.com/qwq-panel/qwq/internal/agentapi   12.9s   （37 个顶层用例 + 15 个子用例）
```

覆盖点：无 token 401、服务账号 403、伪造/过期委托 403；find 的权限过滤（viewer 只见
read 动作、human-only 动作从不出现、scope/limit/truncated/校验）；describe 越权与不存在
返回同一 404、`include_result_schema`/`include_docs`、viewer 只能看 read 动作；read 的
投影与 `missing`、users 分页 3 页无重复无遗漏、集合投影保留标识、`unchanged`、
operations/plans/approvals/delegations 读取、40KB result 触发 `max_bytes` 且窄投影不被截断、
未知/插件 subject 404、字段/limit/cursor/revision 校验；请求体上限（read 1 MiB → 413、
plan 4 MiB → 到达 handler）；plan→execute→wait 全链路、
plan 只能执行一次（409）、幂等重放只执行一次且换 key 复用 422、execute 两形与 8 种
校验、计划不产生副作用；高风险停在 `AWAITING_APPROVAL`、AI 不能批准、对已等待的
operation 的 wait 会等到超时并 `timed_out=true`、cancel 后批准变 `CANCELED`；
cancel 越权 404、已完成 409；并发 wait 上限 429 + 限流字段、4 个等待在超时后全部返回
且计数归零；`toolKey`/`outcomeOf`/`checkFields`/`fitValues`/`fitItems`/`capItems`/
`waitLimiter`/pointer 投影的单元测试；human-only 镜像列表。

## 8. 已知限制与风险

1. **插件文档**：`catalog.Entry.Docs` 只是包内路径，本包没有插件包挂载点，因此文档
   通过可选的 `Deps.Docs` 注入；不接线时 `include_docs` 合法但不返回 `docs`
   （schema 中可选）。集成时建议由 controller 接到已安装插件包。
2. **read 的 approvals 集合**：`ReadRequest` 没有状态过滤参数，集合沿用 REST
   `listApprovals` 的默认值 `PENDING`（等待人工决定的那批）。需要全部状态时应走 REST。
3. **read 的用户目录**：权限按委托人角色判定，`viewer` 的 read 类权限也能读；这是
   "只读不写"的设计选择（读取不是管理），与 authz 的 human-only 规则（限制的是
   管理动作）不冲突。要更严可加 `policy.read_subjects`（P1 不做）。
4. **read 的 `since_revision`**：users 没有留存变更历史，因此返回全量快照并置
   `delta=false`（显式告知，不假装增量）。
5. **human-only 判定**：直接调用 `authz.IsHumanOnly`，本包不再复刻一份（GAP-1 起；
   原镜像与 `TestAuthzHumanOnlyMirror` 已删除，authz 增删 human-only 资源时无需同步）。
6. **node 语义**：standalone 只有本机节点，`scope.node_id` 为其它节点时返回空列表；
   多节点接入后应换成按节点目录检索。
7. **execute 的 args**：OpenAPI 的 ExecuteRequest 未把 `args` 列进 `required`
   （为了函数调用 schema 是普通对象），本包按描述"action + args"要求它存在；
   `{}` 是合法空参数。
8. **413 的 limit 名称**：plan/execute 用 `BodyPluginJSON`（4 MiB），网关报
   `limit.name = max_plugin_body_bytes`，而 OpenAPI 的覆盖键是 `max_body_bytes`；
   属网关路由枚举的表述差异，修它需要改 `internal/gateway`（不在本任务写入范围）。
9. **委托限速**：`policy.requests_per_minute` 只在 `authz.Authorize` 时消耗（即
   plan/execute），find/describe/read/wait/cancel 依赖网关限流器；如需对全部工具计
   委托预算，应在 authz 增加不消耗额度的检查入口。
10. **wait 的"新进入 AWAITING_APPROVAL"分支**：P1 没有从其它状态异步进入
    `AWAITING_APPROVAL` 的路径（进队即在创建事务内完成），该分支目前只有代码与
    `start != AwaitingApproval` 判断，无端到端用例；其余分支均已覆盖。
11. **`X-Request-Id` 推导的幂等键**：客户端若对不同的 execute 复用同一请求 ID，会得到
    422 `IDEMPOTENCY_KEY_REUSED`（这是幂等语义的正确结果，适配器应为每次调用生成新 ID
    或带 `Idempotency-Key`）。
