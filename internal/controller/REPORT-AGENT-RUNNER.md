# ADR-0010 A2 集成：原生 Agent 会话接入 operations（Runner + ApprovalBridge + 会话主体授权）

状态：完成（2026-11-02）。范围：`internal/controller`、`cmd/qwq`、`internal/operations` 的
一个 Actor 判定 helper、`internal/catalog` 的一个只增枚举方法，以及测试。
未改：`internal/agentsession` 的 loop/native/审批语义、`internal/operations` 的审批语义、
`api/public/v1/openapi.yaml`（无新路由）、`go.mod`/`go.sum`、`sdk/`、`api/` 的既有契约。

## 1. 文件

| 文件 | 内容 |
|---|---|
| `internal/controller/agent_runtime.go`（新） | `AgentRunner`、`AgentApprovals`、`AgentToolCatalog`、状态/错误/幂等映射 |
| `internal/controller/agent_runtime_test.go`（新） | 真实 controller/SQLite/operations + host action 的 13 个测试 |
| `internal/controller/adapters.go` | `authorizerAdapter` 会话主体授权；`policyAdapter.Limits` 跳过 delegation |
| `internal/controller/controller.go` | `NewAgentSessions` 构造 helper、`AgentSessions` 访问器、`Close` 关闭顺序 |
| `cmd/qwq/serve.go` | `registerPublicRoutes` 构造并传入 `api.Deps.AgentSessions` |
| `cmd/qwq/serve_test.go` | 接线测试：mount 后 controller 持有服务、可重复获取、Close 清理 |
| `internal/operations/session_actor.go`（新） | `SessionActorPrefix`/`SessionActorID`/`IsSessionActor`，不触碰审批规则 |
| `internal/operations/service.go` | 新增 `HasHostAction`（只读 introspection，供工具目录过滤），不改审批 |
| `internal/operations/session_actor_test.go`（新） | predicate 正反例 |
| `internal/catalog/catalog.go` | 新增 `Entries()`：只增的枚举方法（原包只有 Get/Find） |
| `internal/api/api.go` | 仅更新 `Deps.AgentSessions` 注释；nil 时仍为测试回退 |

## 2. Actor 语义（AI 不借用户身份）

- 每次工具调用的 actor 固定为
  `actor.Actor{Kind: actor.AIAgent, ID: "session:"+sessionID, OnBehalfOf: <session owner>}`
  （`Actor` 没有 `OwnerID` 字段，用 `OnBehalfOf` 表达“替谁执行”）。
- `operations.Run` 的 operation 行、审批卡 `facts.requested_by`、审计行都记录
  `ai_agent` + `session:<id>` + `on_behalf_of=<owner>`：审计能看出 AI 替哪个人执行，
  且没有任何一条记录伪装成 owner 本人。
- 没有用户可见的“委托”记录，也没有为会话创建 delegation；`session:` 前缀是纯内部标识。
- `internal/operations.DecideApproval` 现有逻辑（`who.Kind == AIAgent` → `ai_confirm`）
  不需要改动，session actor 自然命中；`full` 仍在 destructive 处提前返回审批。
- AI 不能批准：`Decide` 的 `IsHumanSession` 硬规则未改，测试覆盖。

## 3. AgentRunner

`RunTool(ctx, call)`：

1. 校验 call id/session id/action/owner，缺失即为 `ToolFailed`（UNAVAILABLE/INTERNAL/
   VALIDATION_FAILED/UNAUTHENTICATED），不构造半截 operation。
2. 若 ctx 没有权限模式而 `call.PermissionMode` 非空，补 `operations.WithPermissionMode`
   （生产路径由 `agentsession.runnerFor` 注入；模式只来自会话行）。
3. `operations.RunRequest`：
   - `Actor` 如上；`Action=call.Action`；`Args=call.Args`；`ExpectedRevision=""`；
   - `NodeID=r.NodeID`；`TraceID=sha256("qwq:agent-tool:"+callID)[:16]`（32 hex W3C 形状），
     `RequestID=call.CallID`；
   - `Idempotency{Key: call.CallID, Method:"POST", Route:"/api/v1/agent-sessions/tool",
     Fingerprint: sha256(session_id, call_id, action, args, target)}`。
     同一 call id 重复调用由 operations 幂等返回；指纹不同则原文返回
     `IDEMPOTENCY_KEY_REUSED`，不会重复写。Runner 不重试任何写操作。
4. Target：host action 传空 target（operations 明确拒绝 host action 带 node_id）；
   plugin action 传 `PluginID`，node placement 另加 `NodeID` 与
   `controller.DefaultInstanceID`（"default"）。`ToolCall` 没有 target 字段，会话无法
   自选节点/实例。
5. 映射：
   - `SUCCEEDED` → `succeeded`，`Result` 是 `OperationOutcome` JSON；
   - `FAILED`/`EXPIRED` → `failed`，`REJECTED` → `rejected`，`CANCELED` → `cancelled`，
     `RUNNING/PENDING/APPROVED` → `running`；
   - `AWAITING_APPROVAL` → `awaiting_approval` + `ApprovalID`/`OperationID` +
     `ApprovalInfo`（catalog 的 Summary/ApprovalDescription/Approval/Risk；deadline 取
     `GetApproval(...).ExpiresAt`；读不到审批卡时只丢 deadline，不让调用失败）；
   - `problem.Error` → `ToolFailed`，保留 code/detail/operation_id，`Cause` 从不外泄
     （`problem.Problem` 本身不含 cause）；不返回堆栈。
   - ctx 被取消/超时时把 `ctx.Err()` 作为 error 返回，让 turn 正确结束而不是继续跑。

## 4. AgentApprovals（只读审批，不 Decide）

- `Wait(ctx, approvalID)` 用 `actor.SystemActor("agent.approvals")` 调
  `Ops.GetApproval`；PENDING 时以默认 700ms（可配，clamp 10ms–2s）+ 最多 +50% jitter
  轮询；`ctx.Done()` 立即返回 `ctx.Err()`（会话侧映射为 cancelled，不会误改状态）。
- `APPROVED`：轮询 `Ops.Get` 到终态；host action 同步完成，job 最多跟随 30s，之后以
  `running` 结果返回（不让已批准的 turn 失败或永久挂起）。返回
  `DecisionApprove` + 最终 Status/Result/Error。
- `REJECTED`：`DecisionReject` + `rejected` + PERMISSION_DENIED 文案。
- `EXPIRED`（含本地发现 `ExpiresAt` 已过，不等 sweeper）：`DecisionReject` + `failed`
  + STATE_CONFLICT。
- `CANCELED`：`DecisionReject` + `rejected` + STATE_CONFLICT。
- 未知 id → NOT_FOUND；未接线的 bridge → UNAVAILABLE。
- 包内没有任何批准入口；人类决定仍只走 `POST /api/v1/approvals/{id}/decision`。

## 5. 授权适配

- `authorizerAdapter.Authorize`：`operations.IsSessionActor(act)` 时把
  `actor.Human{ID: act.OnBehalfOf}` 交给现有 `authz.Authorize`（owner 的实时角色，
  不信任请求体）；Actor 本身仍是 AIAgent。owner 缺失/禁用 → PERMISSION_DENIED。
  其它 AI（delegation）路径原样。
- `policyAdapter.Limits`：session actor 不查 `authz.Delegation`（它不存在），
  权限模式取 `operations.PermissionModeFromContext`（默认 safe）；
  `MaxRisk=high`、`AutoApproveMaxRisk=low`、`OnApprovalRequired=queue` 不变。
  其它 actor 的 delegation 逻辑原样。
- `CanApprove`/`Decide` 未改：AI 永远不能批准。
- operations 新增的 `IsSessionActor` 只是判定 helper，没有任何审批语义改动。

## 6. 接线

- `Controller.NewAgentSessions()` 构造 `agentsession.New(Options{DB,Clock,IDs,Logger,
  Secrets,Catalog:AgentToolCatalog,Runner:&AgentRunner{...},Approvals:&AgentApprovals{...}})`
  并原子保存；重复调用返回同一实例（race 安全）。`Controller.AgentSessions()` 供读取。
- `Controller.Close()` 先关闭会话（等待 turn/审批 goroutine），再按原顺序关插件、网关、
  operations、hub、数据库。
- `cmd/qwq/serve.go registerPublicRoutes` 在 `api.Register` 前构造服务并填入
  `api.Deps.AgentSessions`；生产路径不会再落到 internal/api 的“无 Runner 默认服务”。
  api 在 nil 时仍回退（测试/无 operations 的宿主），注释已说明。
- `AgentToolCatalog.Actions` 用 `catalog.Entries()` 枚举全部 host+plugin action，映射
  ToolSpec（Summary/ApprovalDescription/Effect/Risk/Approval/Permission/ArgsSchema）；
  host 的 `effect=read` action 不会被提供（它们走 GET 路由，operations.Run 会拒绝），
  没有注册 operation handler 的 host action（如 `host.plugins.install/uninstall`，
  它们由 P3 updater 路由提供）也不会被提供——`Controller.NewAgentSessions` 传
  `c.ops.HasHostAction`，回调在每次 Actions 时求值，所以 handler 注册顺序不影响。
  read_only 的过滤仍由 agentsession 自己做。
- P3 Updater 未改。

## 7. 测试

新增测试覆盖：

- AI actor 成功（full）、AWAITING_APPROVAL、approve 后拿到最终 outcome、reject 终止、
  full 跳过插件级/风险审批、full 下 destructive 仍审批、read_only 拒绝且不建 operation、
  owner 为 viewer 时按 owner RBAC 拒绝、AI `Decide` 被 PERMISSION_DENIED、幂等重放、
  幂等 key 复用、错误映射（NOT_FOUND）。
- ApprovalBridge：轮询不提前返回、approve、reject、过期、cancel、ctx 超时、未知 id、
  未接线。
- AgentToolCatalog 映射、无 operation handler 的 host action 过滤、nil catalog。
- `cmd/qwq`：mount 后 controller 持有服务、重复获取同一实例、Close 清理。
- operations：`IsSessionActor` 正反例。

构建机（`QWQ_REMOTE_SRC=runner1`，`CGO_ENABLED=1`，`-race`）：

```
ok  github.com/qwq-panel/qwq/internal/controller    15.447s
ok  github.com/qwq-panel/qwq/internal/operations     26.954s
ok  github.com/qwq-panel/qwq/internal/agentsession   19.442s
ok  github.com/qwq-panel/qwq/internal/api             9.953s
ok  github.com/qwq-panel/qwq/cmd/qwq                  3.202s
ok  github.com/qwq-panel/qwq/internal/catalog         1.190s
```

一次整套运行中出现过 `internal/operations/TestJobProgressAndResult` 的 `job submit =
202 RUNNING` 失败（测试期望提交时还是 PENDING，但 job worker 已抢先置为 RUNNING）。
该测试与本次改动无关（job_test.go 未改，operations 只新增 helper）；单独重跑与整套重跑
均通过，属构建机负载下的既有调度竞态，建议后续把断言放宽为 202 + PENDING/RUNNING。

`gofmt -l`（相关包）无输出；`go vet` 与 `staticcheck`（controller/operations/catalog/
api/cmd/qwq）无告警；`go build ./...` 通过。未启动真实插件或 systemd。

## 8. 剩余风险 / 待办

1. **服务账号拥有的会话**：本版按发起人确认把 session actor 翻译成 owner 的
   **人类角色**（`Kind:Human`）。`checkOwner` 允许 service 拥有会话，但
   `identity.PrincipalRole` 查 users 表，所以 service-owned session 的工具调用会
   fail-closed（PERMISSION_DENIED）。如需支持，需要把 owner kind 随会话传到
   authorizer（新增 helper 或 context 值），不能在请求体里读。
2. **approval_summary 未单独展示**：`agentsession.ToolSpec`/`ApprovalInfo` 只有一个
   Summary 字段；本实现按任务约定取 catalog 的 `Summary`（action 摘要）与
   `ApprovalDescription`。ADR-0010 §4 的 `approval_summary`（确认卡标题）需要
   agentsession 契约加字段后才能真正用上；`PendingApprovals` 的 summary 与
   approval_required 事件当前一致。
3. **plugin 工具的目标**：只支持本机节点 + `default` 实例；多实例/跨节点选择需要
   ToolCall 增加 target 信息（本任务明确不做）。
4. **bridge 的 running 分支**只做了逻辑实现与上限；现有 host action 是同步完成，
   没有测试 job 长时间 RUNNING 的路径（需要真实 plugin dispatcher）。
5. **“approve 后恢复”**在 Runner/Bridge 层验证（决定 → 最终 outcome），未做
   fake core + 真实 Service 的全链路 turn 测试；agentsession 自己的 A2 测试已覆盖
   finishApproval/重跑 turn，本任务只替换其中的 Runner/Bridge 实现。
6. `internal/catalog` 增加了 `Entries()`，严格来说超出“只改 controller/serve/
   agentsession 少量接线”的文件清单；但 ToolCatalog 必须能枚举，而 catalog 原本只有
   Get/Find（`internal/agentsession/REPORT.md` 也把生产适配器留待集成），该方法只增
   不改任何既有行为。如主会话希望把枚举放在别处，可整体回退这一个方法。
