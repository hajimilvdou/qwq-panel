# internal/api — P1 HTTP 公共 API 处理器

SPDX-License-Identifier: AGPL-3.0-only

状态：完成（P1 剩余 33 条非 agent 路由）。`Register` 已可在 `controller.New` 中直接接线；
测试用真实 SQLite + `controller.New` + 完整网关中间件链跑通。

> P3-T4 更新：插件安装/更新/回滚/配置/列表端点已接入真实 updater，`POST /plugins` 改为上传后同步安装。
> 本文件 §3 的插件行是 P1 的历史状态，最新契约与测试见 [`REPORT-PLUGIN-HTTP.md`](REPORT-PLUGIN-HTTP.md)。

## 1. 交付文件

| 文件 | 内容 |
|---|---|
| `internal/api/doc.go` | 包文档：职责、写入路径、网关边界 |
| `internal/api/api.go` | `Deps`、`Register`、路由表、认证/RBAC/会话 Cookie 辅助 |
| `internal/api/respond.go` | `fail`（problem.Write）、严格/可选 JSON 解码、`fields` 投影、ListMeta 信封、分页游标 |
| `internal/api/dto.go` | identity/authz 无 JSON tag 的 DTO，以及 `Plan` 的规范化映射 |
| `internal/api/setup.go` | GET/POST `/api/v1/setup` |
| `internal/api/sessions.go` | 登录、MFA、当前会话、登出 |
| `internal/api/users.go` | 用户 CRUD + `host.users.*` 宿主 handler/planner + 参数校验 |
| `internal/api/delegations.go` | 委托 CRUD（catalog-exempt，直写 authz 域） |
| `internal/api/nodes.go` | 合成节点 `local` |
| `internal/api/plugins.go` | 插件空列表/404/503、插件 operation 调用 |
| `internal/api/operations.go` | 操作列表/详情/取消 |
| `internal/api/plans.go` | 计划创建/读取/执行 |
| `internal/api/approvals.go` | 审批列表/详情/决定 |
| `internal/api/idempotency.go` | 请求指纹 + 委托路由的进程内幂等重放缓存 |
| `internal/api/*_test.go` | 见 §6 |

未修改任何其他包；没有新增依赖。

## 2. `Deps` 与 `Register`

```go
type Deps struct {
    Config   config.Config
    DB       *storage.DB
    Clock    clock.Clock
    IDs      *ids.Generator
    Logger   *slog.Logger
    Identity *identity.Service
    Authz    *authz.Authorizer
    Ops      *operations.Service
    Catalog  *catalog.Catalog
    Secrets  *secrets.Store
    TLS      *tlsmgr.Manager
    NodeID   string
}
func Register(g *gateway.Gateway, d Deps) error
```

- 必填：`DB/Identity/Authz/Ops/Catalog`（缺失返回错误，启动即失败，不会注册出 500 路由）。
- 默认：`Clock=clock.System{}`、`IDs=ids.New(Clock.Now)`、`Logger=discard`、`NodeID="local"`。
- `Secrets` 当前无对应路由（保留签名）；`IDs` 未使用（资源 ID 全部由域服务生成）。
- `Register` 先注册 3 个 `host.users.*` 宿主动作（`Ops.RegisterHostAction` + `RegisterHostPlanner`），
  再按 method+path 注册 33 条路由。重复调用会因 `gateway.Handle` 重复注册而报错。
- 日志：使用 `slog.ErrorContext/WarnContext`，网关已把 `request_id`/`trace_id` 放进 context
  （`internal/platform/logging`），因此日志自动带关联字段。

接入方式（父会话在 `internal/controller/controller.go` 里补一行）：

```go
if err := api.Register(gw, api.Deps{
    Config: cfg, DB: db, Clock: opts.Clock, IDs: opts.IDs, Logger: opts.Logger,
    Identity: id, Authz: az, Ops: ops, Catalog: cat, Secrets: sec, TLS: tm, NodeID: "local",
}); err != nil { ... }
```

`api` 只依赖 `gateway` 与各领域包，controller 依赖 api，无环。

## 3. 路由清单（33 条，对应 OpenAPI operationId）

Access：Public=`security: []`；Session=仅浏览器会话；S/S=session 或 service account。
Body：JSON=1 MiB；P-JSON=4 MiB（`x-qwq-limits.max_body_bytes: 4194304`）。Idem=`x-qwq-idempotency`。

| # | Method | Path | operationId | Access | Body | Idem | 成功响应 |
|---|---|---|---|---|---|---|---|
| 1 | GET | /api/v1/setup | getSetupStatus | Public | – | exempt | 200 SetupStatus（含自签名指纹） |
| 2 | POST | /api/v1/setup | completeSetup | Public | JSON | exempt | 201 Session + Set-Cookie |
| 3 | POST | /api/v1/sessions | createSession | Public | JSON | exempt | 201 Session+Cookie / 200 MfaChallenge |
| 4 | POST | /api/v1/sessions/mfa | verifySessionMfa | Public | JSON | exempt | 201 Session+Cookie |
| 5 | GET | /api/v1/sessions/current | getCurrentSession | Session | – | exempt | 200 Session |
| 6 | DELETE | /api/v1/sessions/current | deleteCurrentSession | Session | – | exempt | 204 + Clear-Cookie |
| 7 | GET | /api/v1/users | listUsers | S/S | – | exempt | 200 UserList |
| 8 | POST | /api/v1/users | createUser | S/S | JSON | required | 200/202 OperationOutcome/Operation |
| 9 | GET | /api/v1/users/{user_id} | getUser | S/S | – | exempt | 200 User |
| 10 | PATCH | /api/v1/users/{user_id} | updateUser | S/S | JSON | required | 200/202 |
| 11 | DELETE | /api/v1/users/{user_id} | deleteUser | S/S | – | required | 200/202 |
| 12 | GET | /api/v1/delegations | listDelegations | Session | – | exempt | 200 DelegationList |
| 13 | POST | /api/v1/delegations | createDelegation | Session | JSON | required | 201 DelegationCreated |
| 14 | GET | /api/v1/delegations/{delegation_id} | getDelegation | Session | – | exempt | 200 Delegation |
| 15 | PATCH | /api/v1/delegations/{delegation_id} | updateDelegation | Session | JSON | required | 200 Delegation |
| 16 | DELETE | /api/v1/delegations/{delegation_id} | deleteDelegation | Session | – | required | 204 |
| 17 | GET | /api/v1/nodes | listNodes | S/S | – | exempt | 200 NodeList（仅 `local`） |
| 18 | GET | /api/v1/nodes/{node_id} | getNode | S/S | – | exempt | 200 Node / 404 |
| 19 | GET | /api/v1/plugins | listPlugins | S/S | – | exempt | 200 PluginList（空数组） |
| 20 | POST | /api/v1/plugins | installPlugin | S/S | JSON | required | 503 PLUGIN_UNAVAILABLE |
| 21 | GET | /api/v1/plugins/{plugin_id} | getPlugin | S/S | – | exempt | 404 |
| 22 | DELETE | /api/v1/plugins/{plugin_id} | uninstallPlugin | S/S | – | required | 404 |
| 23 | POST | /api/v1/plugins/{plugin_id}/operations/{operation} | invokeControllerPluginOperation | S/S | P-JSON | conditional | 由 `Ops.Run` 决定（当前 NOT_FOUND） |
| 24 | POST | /api/v1/nodes/{node_id}/plugins/{plugin_id}/instances/{instance_id}/operations/{operation} | invokeNodePluginOperation | S/S | P-JSON | conditional | 同上；node≠local → 404 |
| 25 | GET | /api/v1/operations | listOperations | S/S | – | exempt | 200 OperationList |
| 26 | GET | /api/v1/operations/{operation_id} | getOperation | S/S | – | exempt | 200 Operation |
| 27 | POST | /api/v1/operations/{operation_id}/cancel | cancelOperation | S/S | 可选 JSON | required | 200/202 Operation |
| 28 | POST | /api/v1/plans | createPlan | S/S | P-JSON | exempt | 201 Plan + Location |
| 29 | GET | /api/v1/plans/{plan_id} | getPlan | S/S | – | exempt | 200 Plan |
| 30 | POST | /api/v1/plans/{plan_id}/execute | executePlan | S/S | – | required | 200/202 |
| 31 | GET | /api/v1/approvals | listApprovals | S/S | – | exempt | 200 ApprovalList（默认 PENDING） |
| 32 | GET | /api/v1/approvals/{approval_id} | getApproval | S/S | – | exempt | 200 Approval |
| 33 | POST | /api/v1/approvals/{approval_id}/decision | decideApproval | Session | JSON | required | 200 Approval |

`GET /healthz`、`GET /readyz`、`GET /api/v1/events` 仍由网关自己注册；`/api/v1/agent/*` 7 个工具
不在本包（P1-T8）。43 − 7 = 36 = 网关 3 + 本包 33，契约测试断言了这一点。

## 4. 写入路径

### 4.1 经 `operations`（单写入路径）

| 路由 | 调用 | 说明 |
|---|---|---|
| 用户 create/update/delete | `Ops.Run(RunRequest)` | catalog 动作 `host.users.create/update/delete`；宿主 handler/planner 用 `RegisterHostAction` 注册 |
| 操作列表/详情/取消 | `Ops.List/Get/Cancel` | 取消响应 200/202 由 operations 决定 |
| 计划创建/读取/执行 | `Ops.CreatePlan/GetPlan/ExecutePlan` | 执行重新校验过期、violations、preconditions |
| 审批列表/详情/决定 | `Ops.ListApprovals/GetApproval/Decide` | 仅真人会话；`Actor.MFA` 由 identity 从会话新鲜度写入 |
| 插件 operation | `Ops.Run`，action=`<plugin_id>/<operation>` | target 携带 node/plugin/instance/subject；`plan_id` 拒绝（见 §7） |

用户路由的参数在进入 operations 前按 catalog args schema 做边界校验（username 规则、role 枚举、
显示名长度/控制字符、`expected_revision` 可解析），避免把必然失败的请求排进审批队列。
`expected_revision` 同时放入 `RunRequest.ExpectedRevision` 和 flat args（与 OpenAPI PlanRequest 的
“path 参数 + body 拍平”一致），所以 plan→execute 走完全相同的校验。

### 4.2 例外：不经过 operations 的直写（catalog-exempt）

| 路由 | 处理 | 事务内容 |
|---|---|---|
| GET/POST `/setup` | `Identity.SetupInitialized` / `CompleteSetup` | identity 自己在事务内写 user/session/token/event/audit |
| POST `/sessions`、`/sessions/mfa`、DELETE `/sessions/current` | `Identity.Login/VerifyMFA/Logout` | 同上；审计由 identity 写 |
| 委托 list/get | `Authz.ListDelegations/Delegation` | 只读 |
| 委托 create/update/delete | `Authz.CreateDelegation/UpdateDelegation/RevokeDelegation`，在 `d.DB.Update` 内 | authz 调 `tx.Changed` 并把 revision 写回；同事务写 `operations.Audit`（`delegation.create/update/revoke`）；`tx.SetOrigin` 带 actor/trace |
| 插件 install/uninstall | 仅校验请求体后返回 503/404 | 无写入（P2 运行时未装配） |

这些路由在 OpenAPI 中是 `x-qwq-action-exempt`（审批、委托、认证、bootstrap），没有 catalog 动作，
因此 `Ops.Run` 无法承载；报告在此列为例外。委托请求的 `Idempotency-Key` 由网关强制存在，
响应重放由本包的小型缓存实现（§7）。

## 5. 边界语义

- **Cookie**：`gateway.SetSessionCookie/ClearSessionCookie`；TTL 取绝对期限 `ExpiresAt`（`sessionTTL`），
  空闲期由服务端强制；网关对失效会话 Cookie 回 401 时顺带清除。CSRF 由网关中间件校验，本包不重复。
- **fields**：`gateway.ParseFields`/`Projection.Apply`；列表逐项投影，单资源整体投影；未知指针
  由网关生成 `/fields` 的 VALIDATION_FAILED。
- **分页**：`limit`/`cursor` 用 `gateway.ListQuery`；多取 1 行判断 `next_cursor`（游标=最后一条 ID，
  客户端视为不透明）；用户/委托沿用域查询的 ID 升序。
- **revision 水位**：列表 `revision` 取 `storage.DB.HeadSeq()`（与 operations 同一水位）。
- **since_revision**：operations/approvals 透传给域（支持 delta）；users/delegations/nodes/plugins
  返回全量快照 `delta=false`（域包无增量查询，本包不写 SQL）。
- **错误**：领域 `*problem.Error` 直接 `problem.Write`；未知错误→INTERNAL 且只记日志；
  5xx 带 request context 记录。
- **幂等**：变更路由 `RequireIdempotency`；key 从 `gateway.IdempotencyKey` 读取并转成
  `operations.Idempotency{Key,Method,Route,Fingerprint}`；指纹是请求体的 SHA-256。
- **凭据**：按 OpenAPI security 选择 `AccessPublic/Session/SessionOrService`；委托令牌只能到
  `/agent/*`，本包任何路由都会由网关拒绝（403）。
- **RBAC**：网关只认证不授权，读路由额外调用 `Authz.Authorize`（`host.users:read`、
  `host.delegations:read`、`host.nodes:read`、`host.plugins:read`、`host.operations:read/cancel`、
  `host.plans:read`、`host.approvals:read`；写路由授权与 operations 内部一致）。

## 6. 测试与验证

测试用 `controller.New`（真实 SQLite in `t.TempDir()`、真实 keyring/TLS/identity/authz/operations/gateway）
+ `httptest` 走完整中间件链（Origin/Host、CSRF、cookie、body 限制、幂等头）。

覆盖：

| 测试 | 内容 |
|---|---|
| `TestSetupAndSessions` | setup GET 前/后、指纹、POST 创建管理员+Cookie 属性（Path=/api/、HttpOnly、Secure）、二次 POST 409、错误登录 401（不区分用户名/密码）、登录、current（CSRF/user/时间戳）、登出 204+清 Cookie、旧 Cookie 401、405+Allow、未知路径/尾斜杠 404 |
| `TestUsersAndApprovals` | 未认证 401；管理员列表；fields 投影与未知指针 400；缺 Idempotency-Key 400；未知字段 400；非法 role/username 400；创建用户 202+approval（Location）；同 key 重放（`Idempotency-Replayed`）；同 key 不同体 422；审批 facts/risk/requires_mfa；stale revision 409+current_revision；批准执行；分页两页；get/404；PATCH→审批→改显示名；DELETE 为 destructive→审批要求 MFA→403 MFA_REQUIRED；取消排队操作→200 CANCELED 且 approval CANCELED；service account 不能批准（403）；service account 只能看到自己的审批（空列表 + 他人审批 404） |
| `TestDelegations` | 未认证 401；创建 201（token 仅一次）；同 key 重放 201 且不含 token；不同体 422；列表/详情不含 token；404；suspend 200；stale revision 409；stale DELETE 409；正常 DELETE 204→404；service account 403 |
| `TestNodesPluginsPlansAndOperations` | 节点列表/local/fields/404；插件空数组/404/install 503/uninstall 404；plan 创建 201+Location+changes/preconditions 为数组；GET/fields；execute 202+Location；重复 execute 409+operation_id；operations 过滤/详情/fields/404/未知 status 400；cancel 200→再次 409；approvals 空数组、未知 status 400；405+Allow、415、未知字段 400、缺 args 400、未知 action 404 |
| `TestOpenAPIRouteContract` | 注册路由 ⊆ openapi.yaml；43−7=36 条全部有 handler；未注册任何 `/agent/*` |
| `TestRegisterRequiresServices` | nil gateway / 空 Deps 启动失败 |

命令与结果（构建机，`QWQ_REMOTE_SRC=api1`）：

```
gofmt -l internal/api                      # 无输出
GOWORK=off go vet ./internal/api/           # 通过
staticcheck ./internal/api/                 # 通过
GOWORK=off go test ./internal/api/ -count=1 # ok  0.86s
CGO_ENABLED=1 GOWORK=off go test -race ./internal/api/ -count=1 # ok 5.10s
```

`GOWORK=off go build ./...` 目前会在 `internal/pluginhost/hostsvc`（另一个并行会话新增的未跟踪文件，
`git status` 为 `??`）失败，与本包无关；本包 `go build ./internal/api/` 通过。

## 7. 未完成 / 风险 / 后续

1. **插件运行时缺失**：`GET /plugins` 返回空数组，`GET /plugins/{id}` 404，`POST /plugins` 校验请求体后
   503 PLUGIN_UNAVAILABLE，`DELETE` 404，插件 operation 走 `Ops.Run`（当前 catalog 无插件动作→404）。
   P2 supervisor 装配后需要把已安装插件列表/安装卸载接到对应服务，并重新评估这些状态码。
2. **`PluginInvokeRequest.plan_id`**：本包拒绝（400 VALIDATION_FAILED，pointer `/plan_id`），因为
   `Ops.Run` 无法绑定 plan 的 args_digest/preconditions。绑定只能经 `POST /plans/{id}/execute`。
   若后续要支持，需 operations 暴露 plan 绑定入口。
3. **`mfa_code` 未校验**：identity 没有“用 TOTP 校验当前用户”的导出原语（只有登录/Elevation 的
   challenge 流程），因此审批决定里的 `mfa_code` 只做格式校验，真正的门是 `Actor.MFA`
   （会话 15 分钟内通过过第二因子）。P1 又没有 TOTP 注册路由，所以纯 HTTP 客户端无法批准 destructive
   操作（测试断言 403 MFA_REQUIRED）。需要 identity 增加 `VerifySecondFactor(actor)` 类原语后补上。
4. **委托幂等重放缓存是进程内**（256 条、24h）：重启后同 key 会再次执行；`expected_revision` 仍能
   让 update/delete 的重复请求得到 409 而非二次变更，create 可能产生第二条委托。operations 的持久
   幂等表只覆盖 Run/ExecutePlan/Decide，暂无导出接口可复用。
5. **`since_revision` 增量**：users/delegations/nodes/plugins 未实现 delta（返回全量 + `delta=false`，
   符合“水位过旧则全量”的约定）；真正的 delta 需要域包提供按 revision 的查询。
6. **RBAC 与 OpenAPI 的既有偏差**（来自 authz 策略，不在本包改动范围）：
   - `host.users` 在 authz 中是 human-only，因此 OpenAPI 允许的 serviceAccountToken 访问
     `/users*` 实际得到 403。
   - `host.approvals` 写操作 human-only；读操作本包对 service account 放行（operations 已按 principal
     过滤），以便其查看自己操作的审批。
7. **响应 DTO**：users/sessions/delegations/nodes/plans 由本包映射（时间戳统一 RFC3339 毫秒 UTC）；
   operations/approvals 直接返回 operations 的 JSON，可能含未在 schema 中列出的追加字段
   （`parent_operation_id`、`progress.step_index/step_count`）和 RFC3339Nano 时间戳；schema 未
   `additionalProperties: false`，属向后兼容的附加成员。202/200 变更响应同样原样透传。
8. **分页上限**：`limit=200` 的满页无法给出 `next_cursor`（域查询把 >200 clamp 到 200），
   客户端应以水位重新拉取。
9. **节点是合成的**：`node_id=local`、`status=online`、`revision="1"`、`created_at`=注册时刻；
   没有 nodes 表，多节点（ADR-0005 Q8 之外）需要真正的节点域。
10. **单资源 `fields` 上限**：使用 `gateway.DefaultLimits().FieldsMax`（32），不读取网关自定义
    `Limits`；列表路由使用网关实际配置。
11. 接线后建议把 `internal/api` 加进 `scripts/check.sh` 的契约覆盖（本包的 OpenAPI 契约测试已随
    `go test ./...` 自动运行）。
