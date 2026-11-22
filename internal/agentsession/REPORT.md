# ADR-0010 A2：原生 Agent 会话后端 — 实现报告

状态：完成（2026-11-02）。对应 ADR-0010 §2.1/§5 与 `docs/design/agent-sessions.md`（含 §11 落地说明）。
本包不做 UI；A3（外部 CLI 进程）只交付契约与 fake。

## 1. 文件

| 文件 | 内容 |
|---|---|
| `internal/agentsession/types.go` | Status/CoreName/ToolStatus、Session/Message/ToolCall/ToolResult/ApprovalInfo/PendingApproval、Turn/Core/Emit/Runner/ApprovalBridge/CLI 无关类型、Event、请求/分页类型 |
| `internal/agentsession/service.go` | Service/Options/Config、Create/Get/List/Messages/Update/Delete/Send/Cancel/Subscribe/WaitTurn/Close、turn goroutine、审批恢复、read_only 收窄、preflight、校验 |
| `internal/agentsession/stream.go` | 会话运行时（seq、ring、subscriber）、`publishLocked`（事件 → DB + SSE）、tool result 落库、`resync`/溢出 |
| `internal/agentsession/store.go` | SQL：会话/消息/工具调用 CRUD、owner 过滤、revision/事件、消息保留、client_message_id 幂等、tool call 扫描 |
| `internal/agentsession/native.go` | 内置 OpenAI-compatible core、配置解析/校验、key 解析与擦除、工具名映射、历史重建与 sanitize、超时/步数 |
| `internal/agentsession/cli.go` | `CLIAdapter` 契约、`CLIConfig`、ADR-0010 §2.1 模式映射表、`FakeCLI`（不启动进程） |
| `internal/agentsession/catalog.go` | `ToolCatalog` 接口与 `StaticCatalog`（生产接 catalog 的适配器待集成） |
| `internal/storage/migrations/0007_agent_sessions.sql` | `agent_sessions` / `agent_messages` / `agent_tool_calls`（STRICT、CHECK、索引） |
| `internal/api/agent_sessions.go` | 9 条 handler、DTO、SSE 帧/续传/心跳/resync |
| `internal/api/api.go` | `Deps.AgentSessions`（可选，缺省时构造默认服务）+ 9 条路由注册 |
| `internal/api/contract_test.go` | 路由数公式仍为 `len(spec)-7`；错误信息改为动态计数 |
| `internal/operations/permission.go` | `WithPermissionMode` / `PermissionModeFromContext` |
| `internal/controller/adapters.go` | `policyAdapter.Limits` 优先读 context 模式，其次 safe |
| `api/public/v1/openapi.yaml` | 9 paths + 17 schemas + `AgentSessionIdPath` + tag |
| `internal/api/agent_sessions_test.go` | API/SSE/审批/校验（真实 SQLite + httptest + 假模型） |
| `internal/agentsession/*_test.go` | store/service/native/cli/SSE 行为测试 |

## 2. 表（迁移 0007）

- `agent_sessions`：`session_id` PK、`plugin_id`（`agent.native`）、`owner_kind`/`owner_id`、
  `title`、`core`、`permission_mode`、`status`、`config_json`、`last_seq`、`created_at`、
  `updated_at`、`revision`。CHECK：owner∈{human,service}、core∈{native,claude-code,codex,opencode}、
  mode∈{read_only,safe,full,custom}、status∈{idle,running,waiting_approval,cancelled,failed}。
  索引：`(owner_kind,owner_id,session_id)`、`(status,session_id)`。
- `agent_messages`：`(session_id,seq)` PK、`message_id` 唯一、role、content、`content_json`
  （json_valid）、operation_id、approval_id、`client_message_id`（partial unique）、created_at。
- `agent_tool_calls`：`call_id` PK、`(session_id,seq)` 唯一、action_id、args_json、operation_id、
  approval_id、status∈{proposed,running,awaiting_approval,succeeded,failed,rejected,cancelled}、
  result_json/error_json、时间、revision。索引：session、session+status、approval_id。
- 写入一律 `storage.Tx`；会话行写 `tx.Changed("agent_sessions/<id>")` 得到 revision，
  同时维护 `last_seq`/`status`。消息保留默认 200 条（`Config.RetainMessages`），按消息 seq
  删除最旧；工具调用/审批关联不随窗口删除。

## 3. API（`/api/v1/agent-sessions`）

| 方法 | 路径 | 说明 |
|---|---|---|
| POST | `/agent-sessions` | 201 + AgentSession（`Location`）；默认 native/safe/“New session”；`config` 校验 |
| GET | `/agent-sessions` | 列表，`status=attention`（waiting_approval/failed）、`cursor/limit/fields/since_revision` |
| GET | `/agent-sessions/{id}` | AgentSessionDetail（会话 + 最近消息 + 待审批） |
| PATCH | `/agent-sessions/{id}` | title/permission_mode；必须 `expected_revision`；409/422 |
| DELETE | `/agent-sessions/{id}` | 取消 turn/关闭流/删行；204；审计行保留；可选 `expected_revision` |
| POST | `/agent-sessions/{id}/messages` | 201 `{session,message}`；`client_message_id` 幂等；忙碌 409 |
| POST | `/agent-sessions/{id}/cancel` | 200；运行中协作取消，等待审批则拒绝并结束 |
| GET | `/agent-sessions/{id}/events` | SSE（见 §5） |
| GET | `/agent-sessions/{id}/approvals` | 待审批列表（含 catalog 的 summary/description/risk/deadline） |

认证：`sessionCookie` 或 `serviceAccountToken`（delegation token 由网关拒绝）。授权：owner 隔离，
跨用户/跨服务账号一律 404；没有额外 RBAC 资源——工具调用由 operations 重新鉴权。
设计稿 §3 的可选便捷入口 `POST /{id}/tool-calls/{call_id}/approve` 未实现：审批决定只走既有的
`POST /api/v1/approvals/{approval_id}/decision`，避免出现第二条批准路径。
OpenAPI：全部变更路由 `x-qwq-idempotency: exempt`（含 reason）与 `x-qwq-action-exempt`（含 reason）；
`POST /messages` 用 `client_message_id` 而不是 Idempotency-Key；PATCH 的 requestBody 需要
`expected_revision`；vacuum（100 规则）100/100。

## 4. 事件（SSE）

`message.delta`、`message.completed`（可带 `tool_calls`）、`tool_call`、`tool_result`、
`approval_required`、`approval_decided`、`turn.completed`（idle/waiting_approval/cancelled/failed）、
`error`（code/detail）。`seq` 每会话单调递增，消息/工具/事件共享；`id` 即 seq。
控制帧：`ready`（head+heartbeat_seconds，retry 3000）、`heartbeat`（默认 15 s）、
`resync`（`out_of_window`/`buffer_overflow`）。续传：`Last-Event-ID` 优先于 `last_event_id`；
`0` 回放整个保留 ring；更旧位置 → resync 后由客户端重拉快照；重启后 ring 为空 → resync。
慢消费者缓冲溢出：关闭该流并标记 overflow，handler 发 resync。关浏览器不取消 turn。

## 5. 权限模式传递（AI 不能改）

- 模式只存在于 `agent_sessions.permission_mode`；只能由 `PATCH`（浏览器会话/服务账号）修改，
  `Create` 时默认 safe。delegation token 在网关就被拒绝，AI 没有 HTTP 路径修改。
- `runTurn` 用 `operations.WithPermissionMode(ctx, mode)` 启动 core；`runnerFor` 对**每次**
  工具调用重新读当前模式，填 `ToolCall.PermissionMode` 并再次 `WithPermissionMode`。
  因此运行中切模式会影响之后的调用。
- `controller.policyAdapter.Limits` 优先读 context 中的模式，否则 safe；`Limits.Mode()` 会把
  空值/未知值归一为 safe，坏数据不会放宽权限。
- `read_only` 时 `toolsFor` 只返回 `effect=read` 的 action；切到 read_only 时等待中的写调用被
  标为 `cancelled` 并发 `tool_result`，已批准的 operation 不受影响。
- `Runner` 收到 `ToolCall.Actor`（会话 owner）、`SessionID`、当前模式；生产 Runner 用它构造
  operations 调用者。首次审批/决定只能走 `POST /approvals/{id}/decision`（人类会话）；
  本包没有任何批准方法。

## 6. native core 配置

`config` 为 JSON object，字段：
`base_url`（必填，http/https 绝对 URL，尾部 `/` 去掉）、`model`（必填）、
`api_key_secret`（secret 引用，`secrets.Open` 解析；缺失则不发送 Authorization）、
`system_prompt`、`timeout_seconds`（1..300，默认 60）、`max_steps`（1..8，默认 8）、
`temperature`（0..2，可选）。缺少 base_url/model 时 `Send` 同步返回 503 UNAVAILABLE；
key 引用读不到时该 turn 以 `error{UNAVAILABLE}` 失败；端点非 200 只报状态码，不转发/记录响应体
（测试验证 key 不出现在错误/日志/消息中）；请求超时映射 `TIMEOUT`。
明文 `api_key/token/password/secret` 字段在创建时被拒（提示用引用）。工具调用步数用尽返回
`UNAVAILABLE` 并结束 turn（模型可继续，不静默）。

## 7. 测试与检查

构建机（`QWQ_REMOTE_SRC=agent2`，`CGO_ENABLED=1 go test -race`，Linux/Go 1.27.3）：

```
ok  internal/agentsession   13.3s   （store/service/native/cli/SSE，含 -race）
ok  internal/api             9.6s   （9 条新路由、SSE、审批、契约测试）
ok  internal/operations     25.1s
ok  internal/controller      4.5s
go build ./...              通过
go vet / staticcheck        通过（4 个包）
gofmt -l                    空
vacuum lint (100 rules)     100/100，0 error
```

覆盖：CRUD/owner 404/seq 单调/消息保留/重开 DB/模式切换与 stale revision/并发 Send 409/
Cancel（运行中与等待审批）/read_only 过滤与收窄/approval_required→approve 恢复与 reject 终止/
bridge nil 时等待/tool_result 与 tool message 配对/审批列表/SSE 回放、0 位置、resync、溢出、
心跳/原生 core 工具往返、Authorization 头、无配置 UNAVAILABLE、key 不泄漏、超时、步数上限、
工具名映射与历史 sanitize/CLI 模式映射与编解码/明文密钥拒绝。

## 8. 未接的生产部分（明确的边界）

1. **生产 Runner**：`Runner` 接口已定，宿主尚未把它接到 `operations.Run`。接线需要决定 agent
   调用的 `actor`（当前会话 owner 是 human/service；`ai_confirm` 语义要 AI actor + 委托），
   本任务按“本包只定义 + fake”执行。
2. **生产 ApprovalBridge**：谁监听 `operations` 的审批结果（事件/journal 或 `GetApproval` 轮询）
   未定；bridge 为 nil 时会话停在 `waiting_approval`，可 cancel/delete，不会恢复。
3. **ToolCatalog**：`internal/catalog` 只有检索/Get，没有枚举；本包定义 `ToolCatalog`，
   生产适配器（枚举 + 映射 ToolSpec）随集成补。缺省服务没有 catalog，因此没有工具。
4. **外部 CLI（A3）**：`CLIAdapter` + `FakeCLI` 就绪，真实进程/PTY/JSON 流、模式映射到 CLI 参数、
   沙箱与 UDS 桥均未实现；`claude-code/codex/opencode` 会话可以创建，`Send` 返回 503。
5. **未读**：attention 只含 waiting_approval/failed；未读由客户端按 `last_seq` 推导，没有读回执 API。
6. **全局 SSE**：只有会话 SSE；`agent.session.attention` 全局事件未加（设计 §8 的可选项）。
7. **RBAC**：会话路由不加 `host.agent_sessions` 权限（角色表没有该资源）；依赖 owner + operations。

## 9. 已知取舍/风险

- 单进程假设：`seq` 由内存运行时分配，宿主是单写连接的单进程；多进程部署需要把 seq 改为
  DB 分配（当前 `last_seq` 高水位已可支持，但未实现 CAS）。
- 删除与并发 Send 的极端竞争：`Delete` 取消并等待 turn 结束；如果 Send 在取消之后、删除之前
  抢到写锁，最终会因行不存在而失败，不会留下孤儿会话。
- 模型端点可指向任意 http(s) 地址（面板用户可控）；A3/P6 需要把 egress 限制纳入沙箱设计。
- 原生 core 非流式：`message.delta` 一次给整段文本；前端按 delta 追加即可，后续可换流式。
- 消息保留按条数，工具调用不删；长期会话的 tool_calls 由后续保留策略/审计清理。
- `Problem` 事件用 `{code,detail}`（`ErrorInfo`），不复用完整 RFC 9457 文档；HTTP 错误仍是 Problem。

## 10. 变更的既有文件

- `internal/operations/permission.go`：只新增两个导出 context helper，未改判定逻辑。
- `internal/controller/adapters.go`：`policyAdapter.Limits` 先看 context，其次默认 safe；其余不动。
- `internal/api/api.go`：`Deps` 新可选字段 + 9 条路由；`withDefaults` 在缺省时构造服务。
- `internal/api/contract_test.go`：只改断言消息（公式不变）。
- `api/public/v1/openapi.yaml`：新增内容，未改既有 schema。
