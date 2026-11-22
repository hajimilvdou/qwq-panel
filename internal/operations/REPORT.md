# P1-T5 / P1-T6：Operation 管理、plan、approval 与有效风险

本包是 ADR-0004「人和 AI 走同一条写入通路」的宿主侧实现：所有状态修改都经
`operations.Run`，plan / approval / 幂等键 / 审计 / 有效风险 / job worker /
重启恢复都在这里。依赖方向遵守 ADR-0008 §1：只依赖 `internal/storage`、
`internal/actor`、`internal/platform`；跨领域能力用本包的窄接口，适配在
`internal/controller`。

## 1. 文件

| 文件 | 内容 |
|---|---|
| `doc.go` | 包说明（两条纪律：写事务内不调插件；每次修改都 `tx.Changed` 并发 `operation.updated`） |
| `action.go` | `Action` 目录元数据、`RiskFloor`、`Limits`/`NeedsApproval`、窄接口 `Catalog`/`Authorizer`/`Policy`/`Revisions`/`HostHandler`/`HostPlanner`/`Dispatcher`/`Notifier`、`validateTarget` |
| `subject.go` | 相对/完整 subject 语法与实例命名空间前缀（ADR-0007 #2） |
| `types.go` | 公共 DTO：`Operation`、`Outcome`、`Plan`、`Approval`、`Progress`、`Response`、列表页、`AuditRecord` 之外的过滤类型 |
| `service.go` | `Config`/`Options`/`New`/`Start`/`Stop`/`WaitJobs`、host action 注册、策略与授权装配、响应组装 |
| `canonical.go` | 规范化 JSON（键排序、无空白、数字保留字面量）与 `canonicalObject` |
| `flow.go` | operation 生命周期：`insertOperation`、`writeOperation`、`transition`、`enterRunning`、`finishOperation`、`failOperation`、`checkExpectedRevision`、`applyChanges`、`pluginRelativeSubjectFor`、`invokeRequest` |
| `run.go` | `RunRequest`/`Run`/`Submit`、读动作、`createOperation`、`createAndRunHost`、`newOperation`、父 operation、approval 卡片事实、plan preconditions 校验 |
| `execute.go` | 已存在 operation 的执行：job 入队、插件 invoke、宿主 handler；`withOperation`、`recordFailure`、运行中注册表与取消 |
| `job.go` | 有界 job 队列、worker、`RunJob` 流、进度节流、尝试与重试 |
| `idempotency.go` | 幂等键绑定/重放/完成/释放、配额、过期与崩溃残留回收 |
| `approval.go` | `Decide`/`GetApproval`/`ListApprovals`/拒绝审计/过期 |
| `plan.go` | `CreatePlan`/`GetPlan`/`ExecutePlan`、插件预览与 subject 前缀化、宿主/插件 preconditions |
| `cancel.go` | `Cancel`：立刻取消或请求取消（202） |
| `recover.go` | `Recover`（重启恢复）、`Sweep`（过期扫描）、`sweepLoop` |
| `query.go` | `Get`/`List`/`Wait` |
| `audit.go` | 导出的 `Audit(ctx, tx, AuditRecord)` |
| `util.go` | 游标、violation、`stateConflict`、集合 watermark |
| `testenv_test.go` + `*_test.go` | 测试环境（真实 SQLite、`clock.Fake`、假 Catalog/Authorizer/Policy/Dispatcher/Notifier/Revisions）与用例，见 §5 |

迁移：`internal/storage/migrations/0004_operations.sql`（替换了占位）。

## 2. 导出 API

```go
// 构造与生命周期
func New(opts Options) (*Service, error)
func (s *Service) Start(ctx context.Context) error   // Recover + worker + 过期扫描
func (s *Service) Stop()                            // 之后不可再 Start
func (s *Service) WaitJobs(ctx context.Context) error
func (s *Service) Config() Config
func (s *Service) NodeID() string
func (s *Service) DB() *storage.DB
func (s *Service) RegisterHostAction(id string, h HostHandler, p HostPlanner)
func (s *Service) RegisterHostPlanner(id string, p HostPlanner)

// 唯一写入通路
func (s *Service) Run(ctx context.Context, req RunRequest) (*Response, error)
func (s *Service) Submit(ctx context.Context, req RunRequest) (*Operation, error)

// plan
func (s *Service) CreatePlan(ctx context.Context, req PlanRequest) (*Plan, error)
func (s *Service) GetPlan(ctx context.Context, a actor.Actor, id string) (*Plan, error)
func (s *Service) ExecutePlan(ctx context.Context, req ExecutePlanRequest) (*Response, error)

// approval
func (s *Service) Decide(ctx context.Context, req DecisionRequest) (*Response, error)
func (s *Service) GetApproval(ctx context.Context, a actor.Actor, id string) (*Approval, error)
func (s *Service) ListApprovals(ctx context.Context, a actor.Actor, f ApprovalFilter) (*ApprovalPage, error)

// operation
func (s *Service) Cancel(ctx context.Context, req CancelRequest) (*Response, error)
func (s *Service) Get(ctx context.Context, a actor.Actor, id string) (*Operation, error)
func (s *Service) List(ctx context.Context, a actor.Actor, f ListFilter) (*OperationPage, error)
func (s *Service) Wait(ctx context.Context, a actor.Actor, id string, timeout time.Duration) (*Operation, error)

// 维护
func (s *Service) Recover(ctx context.Context) ([]string, error)
func (s *Service) Sweep(ctx context.Context) (SweepResult, error)

// 审计（identity 等包经窄接口适配后调用）
func Audit(ctx context.Context, tx *storage.Tx, rec AuditRecord) error

// 有效风险（catalog.RiskFloor 的适配体）
func RiskFloor(declared, effect string, caps []Capability) string
```

请求/响应类型：`RunRequest`、`Submit` 复用前者、`PlanRequest`、`ExecutePlanRequest`、
`DecisionRequest`、`CancelRequest`、`Idempotency`、`Response{Status, Body, Replayed,
OperationID, Operation, Outcome, Approval}`、`ListFilter`/`OperationPage`、
`ApprovalFilter`/`ApprovalPage`、`SweepResult`、`AuditRecord`。

窄接口（由 controller 适配）：

```go
type Catalog interface { Action(id string) (Action, bool) }
type Authorizer interface { Authorize(ctx, a actor.Actor, act Action, target Target) error }
type Policy interface { Limits(ctx, a actor.Actor, act Action, target Target) (Limits, error) }
type Revisions interface { CurrentRevision(ctx, tx *storage.Tx, subject string) (string, error) }
type Dispatcher interface {
	Plan(ctx, PluginPlanRequest) (Preview, error)
	Invoke(ctx, PluginInvokeRequest) (PluginInvokeResponse, error)
	RunJob(ctx, PluginRunJobRequest, func(JobProgress) error) error
	Cancel(ctx, PluginCancelRequest) error
}
type Notifier interface { Notify(ctx, *Operation) }
type HostHandler func(ctx, tx *storage.Tx, req HostRequest) (json.RawMessage, error)
type HostPlanner func(ctx, tx *sql.Tx, req HostRequest) (Preview, error)
```

`Limits`（来自委托策略）：`MaxRisk`、`AutoApproveMaxRisk`（`none`/`low`，默认 low）、
`OnApprovalRequired`（`queue`/`fail`，默认 queue）。

## 3. 表

`0004_operations.sql`（全部 STRICT，JSON 列带 `json_valid` 检查）：

| 表 | 关键列 |
|---|---|
| `operations` | `operation_id` PK、`action`、`action_meta`（创建时冻结的目录元数据 JSON）、`status`、`target` JSON + `node_id`/`plugin_id`/`instance_id`/`subject`、`actor_kind`/`actor_id`/`actor_on_behalf_of`、`effective_risk`/`declared_risk`/`effect`/`mode`/`idempotent`、`permission`/`ui_route`、`args`/`args_digest`/`expected_revision`/`preconditions`（插件侧相对 preconditions）、`plan_id`/`approval_id`/`parent_operation_id`、`attempt`/`cancel_requested`/`progress`/`result`/`error`、`timeout_ms`、`request_id`/`trace_id`、`created_at`/`updated_at`/`started_at`/`finished_at`、`revision` |
| `operation_attempts` | `(operation_id, attempt)` PK、`status`、`started_at`/`finished_at`、`error`、FK→operations |
| `plans` | `plan_id` PK、`action`/`action_meta`/`target`/`args`/`args_digest`、`plannable`、`changes`/`changes_truncated`/`violations`/`warnings`、`preconditions`（宿主侧完整 subject）/`plugin_preconditions`（相对 subject）、`effective_risk`/`requires_approval`/`requires_mfa`/`executable`、`operation_id`、owner 与时间、`revision` |
| `approvals` | `approval_id` PK、`operation_id`/`plan_id`、`status`、`facts` JSON（确认卡片宿主已知事实）、`plugin_preview` JSON（来自插件的预览）、`requires_mfa`、`decided_by_*`/`decided_at`/`comment`、`created_at`/`expires_at`、`revision` |
| `idempotency_keys` | `key_id` PK、`principal`/`method`/`route`/`key`（UNIQUE）、`fingerprint`、`state`（`in_progress`/`completed`）、`operation_id`、`response_status`/`response_body`、`created_at`/`updated_at`/`expires_at` |
| `audit_log` | `audit_id` PK、`occurred_at`、actor、`source`、`action`、`subject`、`outcome`、`operation_id`/`node_id`/`trace_id`/`request_id`、`details` JSON |

索引覆盖状态+ID、actor、node+plugin、`revision`（`since_revision`）、父 operation、
plan、approval 状态与 operation、幂等过期与 principal、审计时间/actor/subject/operation。

## 4. 关键语义

### 4.1 写入与事件（ADR-0004 D1/D3，ADR-0008 §2/§4）

- 宿主动作：领域行 + operation 行 + 状态事件 + 审计行在**一个**写事务中；handler 失败
  整体回滚（不留下半个 operation），错误以 `Problem` 返回。
- 插件动作 / 审批后执行 / job：创建 operation 一个短事务；调用插件在事务外；结果、
  插件上报的 `ResourceChange`、终态在另一个短事务中写回。
- operation 自身是资源：每次状态/进度写都 `tx.Changed(operations/{id})`，返回序号即
  `revision`，并在同一事务 `AppendEvent(operation.updated)`（payload 符合
  `OperationUpdatedPayload`：operation_id/action/status/previous_status/attempt/actor/
  target/effective_risk/approval_id/progress/ui_route/error/revision）。
- 每次事务开头 `tx.SetOrigin(storage.Origin{Actor, OperationID, TraceID, NodeID})`；
  node 默认 `local`。
- 插件上报的资源变化按 ADR-0007 #2 校验相对 subject 并加命名空间前缀
  （`nodes/{node}/plugins/{plugin}/instances/{instance}/resources/…` 或
  `plugins/{plugin}/resources/…`）；非法 subject → `PLUGIN_ERROR`。

### 4.2 状态机（ADR-0004 D7）

`PENDING → AWAITING_APPROVAL → APPROVED/REJECTED/EXPIRED → RUNNING →
SUCCEEDED/FAILED/CANCELED`，`PENDING → RUNNING`，`PENDING/AWAITING_APPROVAL/APPROVED →
CANCELED`，`PENDING/APPROVED → FAILED`。非法迁移 → `409 STATE_CONFLICT`（带 operation_id）。
每次迁移一个短事务；批准把 operation 从 `APPROVED` 推进到 `RUNNING` 是同一决定之后的
独立事务，批准失败不会撤销人的决定（operation 记 `FAILED` 及原因）。

### 4.3 有效风险（ADR-0004 D6，ADR-0007 #4）

`max(声明风险, capability 下限)`；`effect=destructive` 一律 high。
下限：`system.*`、`secret.reveal[.*]`、`network.egress[.*]` → high；`state.*`、
`events.*`、`metrics.read[.*]` → low；未知 capability → medium；没有声明 operation 级
capability 时目录给的是插件全部 capability（目录侧完成）。声明的空/未知风险按 medium
（保守）。委托策略 `max_risk` 低于有效风险 → `403 PERMISSION_DENIED` 且 Problem 带
`effective_risk`。

### 4.4 执行策略

read 直接执行（插件读动作不建 operation，`OperationOutcome.operation_id` 为空；宿主读
动作走 GET 路由，不经本包）；low 执行完成后调用 `Notifier`；medium/high 进
`AWAITING_APPROVAL`；`on_approval_required=fail` → `403 APPROVAL_REQUIRED`；destructive
的批准要求 `actor.MFA`（MFA 由网关校验后置位）。

### 4.5 幂等键

作用域 principal（human/user、ai_agent/delegation+on_behalf_of、service、system）+
HTTP 方法 + 具体路由；指纹 = 规范化 JSON 的 SHA-256（调用方也可传
`Idempotency.Fingerprint`，例如原始 body + 排序 query 的哈希）。同 key 同指纹返回
第一次的 `Status`/`Body`（`Replayed=true`）；不同指纹 `422 IDEMPOTENCY_KEY_REUSED`；
处理中 `409 IDEMPOTENCY_IN_PROGRESS` + `Retry-After: 2`；TTL 24h（自首次使用），每
principal 10000 个活跃 key，超出 `429 RATE_LIMITED`（Problem 带 `limit`）；4xx 业务错误
也存储并可重放，5xx/429/401/CSRF 释放 key；崩溃留下的 `in_progress` 10 分钟后可被重试
接管，`Sweep` 也会删除过期与残留。写路由缺 key → `400 VALIDATION_FAILED`
（`/Idempotency-Key`）。规范 JSON 不是严格 RFC 8785：键排序、去空白、数字保留字面量
（无新依赖，见 `canonical.go` 注释）。

### 4.6 plan（ADR-0004 D7）

`CreatePlan` 校验参数、算有效风险、按 `expected_revision` 生成宿主侧（完整 subject）
或插件侧（相对 subject）precondition，再调宿主 planner（读事务）或
`Dispatcher.Plan`（事务外），把插件的 changes 前缀化为完整 subject 并标注
`source=plugin`、`plugin_id`，校验相对 subject（空段、`.`/`..`、超长、非法字符 → 
`PLUGIN_ERROR`）。不可规划的动作也生成 plan（`changes` 空，`plannable=false`）。
`ExecutePlan`：过期 `409 PLAN_EXPIRED`；有阻断 violations `400 VALIDATION_FAILED`；
已执行 `409 STATE_CONFLICT`（带原 operation_id）；宿主 preconditions 在建 operation 的
同一事务内用 `Revisions` 原子比对，失败 `409 PRECONDITION_FAILED` 并带
`failed_preconditions`；插件 preconditions 随 Invoke/RunJob 交给插件；plan 只能执行一次
（`UPDATE … WHERE operation_id=''` 守卫）。plan 私有于创建者（管理员可见性见 §6）。

### 4.7 approval

只接受 `actor.IsHumanSession()`：委托与服务账号一律 `403 PERMISSION_DENIED`（写审计，
outcome=denied）；批准者还要通过 `Authorizer`（RBAC）；destructive 需要 `actor.MFA`，
否则 `403 MFA_REQUIRED`；默认 15 分钟过期（`approval_ttl_seconds`），`Decide` 时惰性
过期、`Sweep`/`sweepLoop` 定时过期（Clock 驱动，测试可推进）；过期/拒绝/取消都写审计并
发 `resource.changed`（`approvals/{id}`）与 operation 状态事件。确认卡片数据
`facts`：action（effective/declared risk、permission、undo、ui_route、timeout）、参数、
`args_digest`、target、所需 capability、effect、是否可撤销、请求者；`plugin_preview`
只放插件 changes/warnings 并标为不可信。AI 写的说明文字不进入 `facts`。

### 4.8 job

有界队列（内存 FIFO，容量 128）+ 默认 1 个 worker（1C1G）；`RunJob` 零或多条进度 + 一条
终态。进度节流 500ms（最后一条必写，带 `changes` 的立即写）；`changes` 立即
`tx.Changed`；终态写入 result/error。取消：PENDING/AWAITING/APPROVED 立即 CANCELED；
RUNNING 置 `cancel_requested=true` 返回 202，调用 `Dispatcher.Cancel`，宽限 2s（Clock）
后取消 context；流返回后按 `cancel_requested` 决定 CANCELED。超时用 context deadline，
记为 `TIMEOUT` 失败。中断/失败：只有幂等动作、attempt < 3（可配）且未请求取消时才以
`attempt+1` 重试（operation 回到 PENDING，attempts 表记失败），否则 FAILED。
关停时中断的 job 保持 RUNNING，交给下次启动恢复。

### 4.9 子 operation（ADR-0007 #5）

`ParentOperationID`：继承父 actor（调用方必须是同一 principal 或 system），
`parent_operation_id` 落库；有效风险高于父 operation 时强制单独 `AWAITING_APPROVAL`。

### 4.10 重启恢复

`Recover`：RUNNING 的操作没有执行者——幂等且未超尝试上限则 attempt+1 回 PENDING 并
重新排队，否则 FAILED（`503 UNAVAILABLE`：host restarted）；APPROVED 与 PENDING 的 job
重新排队；PENDING/AWAITING_APPROVAL 保持。`Start` 在 worker 起来后对恢复列表逐个
`resume`（job 入队、invoke 重新调用、已批准宿主动作重新执行）。

### 4.11 查询与审计

列表按 `operation_id` 倒序游标分页（不透明 base64 游标），按状态/actor/node/plugin
过滤，`since_revision` 增量（`revision > ?`，`delta=true`），集合 `revision` 取查询时的
journal head。可见性：human/system 看全部；ai_agent/service 只看自己的。`Get` 对不可见
的操作返回 404（不确认存在）。审计：operation 创建/完成、approval 请求/批准/拒绝/过期、
取消、重试；`Audit` 自动补 actor/时间，details 为 JSON。

## 5. 测试与执行结果

`internal/operations` 共 7 个测试文件、46 个顶层用例（另含 2 个子用例）：

- `risk_test.go`：风险下限表、`NeedsApproval`、状态迁移表、相对/完整 subject、规范 JSON。
- `run_test.go`：写入契约（operation + `resource.changed` + `operation.updated` 三条 +
  审计）、并发 `expected_revision`（一成一败，带 current_revision）、plan 后资源被改 →
  `PRECONDITION_FAILED`（ADR-0004 验收 4）、子 operation 风险提升、读动作不建
  operation、缺幂等键、low 通知、列表/游标/增量/可见性。
- `approval_test.go`：AI 高风险停 `AWAITING_APPROVAL` 且 payload 注入文本不改变状态
  （验收 5）、委托与服务账号不能批准（验收 3）、无权限批准者被拒、destructive 需 MFA、
  拒绝、过期（Sweep）、取消、卡片事实。
- `idempotency_test.go`：重放、不同 body、并发同 key、4xx 存储后重放、24h 过期清理、
  配额、崩溃残留接管。
- `plan_test.go`：plan→execute、过期、阻断 violations、插件 subject 前缀化与插件侧
  precondition 透传、非法 subject、宿主 planner、plan 归属。
- `job_test.go`：进度/结果/插件变更事件/attempt、取消（202 → CANCELED）、幂等才重试、
  非幂等只跑一次、重启恢复（RUNNING 重试/失败、APPROVED/PENDING 重新排队）、关停保留
  RUNNING 供下次恢复。
- `extras_test.go`：委托 `max_risk` 拒绝（带 effective_risk）、`on_approval_required=fail`、
  插件 invoke 的事件契约、approval 列表/可见性、Wait/Submit、进度节流。

构建机（`QWQ_REMOTE_SRC=p1b`）：

```text
GOWORK=off go build ./internal/operations/...          # 通过
gofmt -l internal/operations                           # 无输出
GOWORK=off go vet ./internal/operations/...            # 通过
GOWORK=off staticcheck ./internal/operations/...       # 通过
CGO_ENABLED=1 GOWORK=off go test -race -count=1 ./internal/operations/...
ok  github.com/qwq-panel/qwq/internal/operations  16.7s
```

只改了 `internal/operations/**` 与 `internal/storage/migrations/0004_operations.sql`；
未改 `go.mod`/`go.sum`、未加依赖、未 git add/commit。

## 6. 与 OpenAPI 的对应与不一致

已按 OpenAPI 实现：错误码（`VALIDATION_FAILED`、`PERMISSION_DENIED`、`MFA_REQUIRED`、
`APPROVAL_REQUIRED`、`NOT_FOUND`、`REVISION_CONFLICT`(current_revision)、
`PRECONDITION_FAILED`(failed_preconditions)、`PLAN_EXPIRED`、`STATE_CONFLICT`、
`IDEMPOTENCY_IN_PROGRESS`(retry_after)、`IDEMPOTENCY_KEY_REUSED`、`RATE_LIMITED`(limit)、
`PLUGIN_ERROR`、`UNAVAILABLE`、`TIMEOUT`、`INTERNAL`）；响应形态（同步 200
`OperationOutcome`、异步 202 `Operation`、取消 RUNNING 202、审批决定返回 `Approval`）；
`x-qwq-idempotency`（required/conditional/exempt）；`x-qwq-limits` 中
`plan_ttl_seconds`、`approval_ttl_seconds`、`idempotency_ttl_seconds`、
`idempotency_keys_per_principal`、`list_limit_default/max`；`ApprovalFacts`、
`OperationUpdatedPayload`、`ResourceChangedPayload`、`Precondition`、
`FailedPrecondition`、`ListMeta` 的字段名与语义。

差异（需要主会话决定是否改 OpenAPI 或本包）：

1. **`PlannedChange.description`**：proto `PlannedChange.description`（ADR-0007 #10）与
   确认卡片需要，但 OpenAPI `PlannedChange` 没有该字段。本包在 JSON 中输出
   `description`（OpenAPI 默认允许额外属性）。建议给 schema 补上（`maxLength: 200`，
   `x-qwq-untrusted: true`）。
2. **`OperationProgress.step_index`/`step_count`**：proto `JobProgress`（ADR-0007 #9）与
   “步骤 i/n”横幅需要，OpenAPI `OperationProgress` 只有 percent/step/message。本包以
   额外属性输出。建议补进 schema。
3. **`Operation.parent_operation_id`**：ADR-0007 #5 要求可见，OpenAPI `Operation` 没有。
   本包以额外属性输出（空时省略）。
4. **`Plan.preconditions` 只含宿主侧**：OpenAPI `Precondition.subject` 是完整 Subject，
   而插件侧 precondition 是相对 subject（proto 语法可能不匹配 Subject 的 pattern，且
   暴露相对名称语义不清）。本包把插件侧单独存 `plugin_preconditions` 并只随
   Invoke/RunJob 交给插件；`Plan.preconditions` 不含它们。如需卡片展示，建议给
   `Plan` 增加 `plugin_preconditions` 或放宽 `Precondition.subject` 的 pattern。
5. **`fields` 投影与 `deleted_ids`**：`fields` 属网关；operations/approvals 不会被删除，
   所以 `deleted_ids` 恒为空（仍返回 `delta`/`revision`）。
6. **plan 的管理员可见性**：OpenAPI 说“创建者和管理员可读”，本包只做创建者（+system），
   管理员判断需要 authz 的 RBAC，适配层可在调用 `GetPlan` 前自行放行。
7. **`Operation.error`**：存的是渲染后的 `Problem`，`instance=/api/v1/operations/{id}`、
   `request_id` 取发起请求的 ID；重放的 4xx 保留首次请求的 `request_id`。
8. **`Subject` 正则**：OpenAPI 的 pattern 用 Go regexp 无法表达（`{0,15}` 报
   “invalid repeat count”），本包用等价正则 + 长度/段校验实现。
9. **`x-qwq-limits` 的按路由覆盖**（`max_body_bytes`、`max_json_depth`）属网关，本包不处理。
10. **审批 `expected_revision`**：OpenAPI `ApprovalDecisionRequest.expected_revision` 必填；
    本包允许为空（不校验），网关应传入。

## 7. 需要其他包配合

- **controller**：适配 `catalog.Catalog.Get` → `operations.Catalog`（`Entry` 已有
  Source/Effect/Risk/Mode/Idempotent/Plannable/Capabilities/Undo/UIRoute/Permission/
  TimeoutMS/PluginID/Placement/Operation/APIVersion）；`authz.Authorizer.Authorize`
  → `operations.Authorizer`（permission + Resource{Name,NodeID}）；
  `authz` 的委托策略 → `operations.Policy`（`MaxRisk` 用委托策略的 `max_risk` 语义、
  `AutoApproveMaxRisk` 用 `auto_approve_max_risk`、`OnApprovalRequired` 用
  `on_approval_required`）；各资源所有者实现 `Revisions`；`identity.Auditor` 适配到
  `operations.Audit`；P1 的假 `Dispatcher` 按 ADR-0007 场景实现（Plan/Invoke/RunJob/
  Cancel），P2 换 Supervisor；`Notifier` 接网关的“低风险已执行”提示。
- **gateway**：按 `Response.Status`/`Body` 写响应（`Replayed=true` 时原样写出并加
  `Idempotency-Replayed: true`），用 `OperationID` 填 `Location`；把 `*problem.Error`
  用 `problem.Write` 渲染（需要 request_id/instance）；`fields` 投影、请求体/深度限制、
  SSE 分发不在本包。
- **storage（可选）**：`Tx.Changed` 固定把事件 seq 写为 `revision`，插件上报的
  `ResourceChange.revision` 目前被忽略（事件里用宿主 seq）。ADR-0008 §4 说插件资源的
  revision 由插件给出；若要与文档完全一致，需要 `storage` 提供“指定 revision 的
  Changed”或允许本包改写该事件 payload。当前行为对 UI 一致（revision 只比较相等），
  不阻塞 P1。
- **authz**：委托/服务账号的速率限制、`actions`/`node_ids` 过滤不在本包（本包只用
  `Limits` 的 max_risk 与审批策略）。

## 8. 已知限制

- 宿主动作只支持 `mode=invoke`（handler 在写事务内跑，不能是长任务）；宿主读动作走
  GET 路由，不经 `Run`。
- job 队列在内存中；`Start` 只能调用一次（`Stop` 之后不可重启，重启由新进程的
  `Recover` 完成）。
- 进度节流按“上一条写入时间”计算，极端情况下（只有一条非终态进度）该条会被下一条或
  终态覆盖——终态必写。
- `Wait` 用 Clock 轮询（50ms），测试里需要推进 Fake 时钟才会等待；终态/待批准时立即返回。
- `Recover` 对 APPROVED 的 invoke 操作同步重新执行；恢复数量很大时启动会变慢（P1 规模
  可接受，后续可改为 queued）。
