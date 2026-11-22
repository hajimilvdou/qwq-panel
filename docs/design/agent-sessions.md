# 原生 Agent 会话后端设计（ADR-0010 A2/A3）

> 状态：设计稿，2026-11-02。UI 由发起人指导，本文只定后端契约与数据模型。
> 关联：[ADR-0010](../adr/0010-ai-approval-levels-and-agent-plugin.md)、ADR-0004、ADR-0007。

## 1. 目标

1. 宿主内置 `agent.native` 页面所需的会话/消息/工具调用/审批桥/SSE。
2. 会话有权限模式（`read_only`/`safe`/`full`/`custom`），默认 `safe`；模式由用户选择，AI 不能自改。
3. 工具调用必须走 `operations.Run`；需要审批时暂停并发出 `approval_required`，用户决定后恢复。
4. 外部 CLI（claude code / codex / opencode）作为可替换“核心”，只通过受控适配器接入，宿主判定权限。
5. 悬浮窗/输入窗/聊天窗是 UI；后端提供“待确认/未读”汇总与会话 SSE。

## 2. 数据模型（迁移 0007）

```sql
agent_sessions(
  session_id TEXT PRIMARY KEY,
  plugin_id TEXT NOT NULL,            -- 首版固定 agent.native
  title TEXT NOT NULL,
  core TEXT NOT NULL,                 -- native | claude-code | codex | opencode
  permission_mode TEXT NOT NULL,      -- read_only | safe | full | custom
  status TEXT NOT NULL,               -- idle | running | waiting_approval | cancelled | failed
  config_json TEXT NOT NULL,          -- core 配置（不含密钥；密钥用 secret 引用）
  last_seq INTEGER NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

agent_messages(
  session_id TEXT NOT NULL,
  seq INTEGER NOT NULL,
  role TEXT NOT NULL,                 -- user | assistant | system | tool
  content TEXT NOT NULL,
  content_json TEXT,                  -- 结构化片段（工具调用/结果/审批），可选
  operation_id TEXT,
  approval_id TEXT,
  created_at TEXT NOT NULL,
  PRIMARY KEY(session_id, seq)
);

agent_tool_calls(
  call_id TEXT PRIMARY KEY,
  session_id TEXT NOT NULL,
  seq INTEGER NOT NULL,
  action_id TEXT NOT NULL,
  args_json TEXT NOT NULL,
  operation_id TEXT,
  approval_id TEXT,
  status TEXT NOT NULL,               -- proposed | running | awaiting_approval | succeeded | failed | rejected
  result_json TEXT,
  error_json TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
```

约束：

- `seq` 每会话单调递增；SSE `id` 用 `<session_id>:<seq>` 或纯整数 seq；消息/工具事件共享 seq。
- 消息保留有界（默认最近 200 条/会话，可配）；工具调用与审批关联保留更久（审计另有 operations 记录）。
- 所有写入在 `storage.Tx`，`tx.Changed` 回写会话 revision；会话事件进入宿主事件日志（`agent.session.*`），SSE 可从 journal 回放最近窗口。

## 3. 会话 API（OpenAPI 增补，挂在 `/api/v1/agent-sessions`）

| 方法 | 路径 | 说明 |
|---|---|---|
| POST | `/agent-sessions` | 创建会话（title、core、permission_mode；默认 native/safe） |
| GET | `/agent-sessions` | 列表；`?status=attention` 返回 `waiting_approval`/`failed`/未读，供悬浮窗 |
| GET | `/agent-sessions/{id}` | 会话 + 最近消息 + 待审批摘要 |
| PATCH | `/agent-sessions/{id}` | 改 title/permission_mode；切模式只影响之后的工具调用 |
| DELETE | `/agent-sessions/{id}` | 关闭并清理内存流；DB 保留审计 |
| POST | `/agent-sessions/{id}/messages` | 发送用户消息；返回 `seq`；核心异步运行 |
| POST | `/agent-sessions/{id}/cancel` | 取消当前 turn（协作式；工具调用按 operations 取消） |
| GET | `/agent-sessions/{id}/events` | SSE；`Last-Event-ID` 续传；事件见 §5 |
| GET | `/agent-sessions/{id}/approvals` | 待审批列表（操作 id、action、summary、description、风险、deadline） |
| POST | `/agent-sessions/{id}/tool-calls/{call_id}/approve` | 可选便捷入口；内部转 `/approvals/{id}` 决定（不替代正式审批 API） |

所有路由走现有网关认证：浏览器会话或服务账号；先按当前角色和服务范围核验 `host.agent_sessions:read/write`，再由后端限制本人归属。限定续期用途的服务账号不能跨用途读取会话或消耗全局模型；普通授权服务账号仍可管理自己的会话。SSE 不提供字段投影。

## 4. 核心接口

```go
type Core interface {
    Name() string
    Run(ctx context.Context, turn Turn, emit Emit) error
}

type Turn struct {
    SessionID      string
    PermissionMode PermissionMode
    Messages       []Message       // 最近 N 条
    Tools          []ToolSpec      // 目录中当前模式可见的 action
    Config         json.RawMessage
}

type Emit func(Event) error
```

- `native`：OpenAI-compatible chat completions（base_url/model/api_key secret），支持 tool calling；工具结果回填后继续，直到无 tool call 或达到步数上限（默认 8）。
- 外部 CLI：`CLIAdapter` 负责 command/args/env、模式映射、stdin/stdout 编解码；首版只定义接口与 fake，不启动真实 CLI。
- 核心不能直接执行 shell/网络；工具调用只经宿主适配层。

## 5. 事件（SSE）

```json
{"type":"message.delta","seq":12,"message_id":"...","delta":"..."}
{"type":"message.completed","seq":13,"message_id":"..."}
{"type":"tool_call","seq":14,"call_id":"...","action":"...","args":{...},"risk":"...","approval":"ai_confirm"}
{"type":"tool_result","seq":15,"call_id":"...","status":"succeeded","result":{...}}
{"type":"approval_required","seq":16,"call_id":"...","approval_id":"...","summary":"...","description":"...","risk":"...","deadline":"..."}
{"type":"approval_decided","seq":17,"approval_id":"...","decision":"approve|reject","comment":"..."}
{"type":"turn.completed","seq":18,"status":"idle|waiting_approval|failed"}
{"type":"error","seq":19,"code":"...","detail":"..."}
```

- `approval_required` 同时更新会话 `status=waiting_approval`；悬浮窗通过 `GET /agent-sessions?status=attention` 或全局 SSE 得到提醒。
- 审批决定由既有 `/api/v1/approvals/{id}` 完成（含 MFA）；会话监听审批状态并恢复/终止 turn。
- 断线重连：`Last-Event-ID` 从 journal/内存缓冲回放；`resync` 事件要求客户端重拉会话快照。

## 6. 权限模式与工具过滤

| 模式 | 可见工具 | operations 行为 |
|---|---|---|
| `read_only` | 只读 action | 写调用在宿主拒绝，不产生审批 |
| `safe` | 全部（按角色/委托） | 按 approval 级别与硬规则审批 |
| `full` | 全部 | 跳过插件级审批；destructive 仍审批 |
| `custom` | 按 allow/deny 表 | 逐项覆盖；首版可只存表不提供 UI |

- 模式在 `Turn` 中传给 `operations.Run`；AI 不能通过消息改模式，只能用户 PATCH。
- 切到 `read_only` 时取消正在等待的写工具调用（发出 `tool_result rejected`），不影响已批准的 operation。

## 7. 外部 CLI 适配契约（A3）

```go
type CLIAdapter interface {
    Command(cfg Config) (path string, args []string, env []string, err error)
    MapMode(mode PermissionMode) ([]string, error) // 例如 --permission-mode plan
    Encode(turn Turn) (stdin []byte, err error)
    Decode(r io.Reader, emit Emit) error
}
```

- 适配器只负责协议转换；不得把宿主 token/密钥传给 CLI。
- CLI 的 tool call 通过本地 UDS/MCP 桥回到宿主，由宿主执行 operations；CLI 的本地文件/网络权限由 systemd 沙箱与 CLI 自身模式共同限制。
- 模式映射见 ADR-0010 §2.1；宿主模式是权威，CLI 报的模式只作日志。
- 首版只实现 `native`；外部 CLI 适配器留接口 + fake 测试。

## 8. 悬浮窗/页面后端

- `GET /agent-sessions?status=attention`：`waiting_approval`、`failed`、`unread` 的会话摘要（id、title、待审批数、最后消息时间）。
- 全局 SSE `/api/v1/events` 增加 `agent.session.attention` 事件（或复用 session SSE；UI 可订阅一个全局流）。
- 悬浮窗展开/收起、动画、位置是前端状态；后端不持久化窗口位置（可存 localStorage）。
- 用户离开页面后会话继续运行（host 侧 goroutine + DB），审批等待不超时（可配 deadline）；关闭浏览器不取消 turn。

## 9. 测试

- 会话 CRUD、seq 单调、权限（他人会话 404）、模式切换。
- fake Core 产生 delta/tool_call/approval_required；审批通过/拒绝后恢复/终止；SSE 续传与 resync。
- `read_only` 拒绝写；`full` 跳过 confirm 但 destructive 仍审批；AI 不能批准。
- 工具调用关联 operation/approval；取消 turn 取消操作；重复消息幂等。
- 外部 CLI 适配器 fake：模式映射、stdin/stdout 编解码、超时/退出码、无密钥泄漏。

## 10. 非目标（本设计不做）

- 真实 LLM 供应商/模型选择 UI；只做 OpenAI-compatible 配置接口。
- 外部 CLI 的真实安装/升级/密钥管理；只定适配器契约。
- 悬浮窗视觉/动效；由发起人指导 UI 后实现。

## 11. A2 实现说明（2026-11-02）

以下是落地时对上面契约的细化和偏差，代码在 `internal/agentsession`、迁移
`0007_agent_sessions.sql`、`internal/api/agent_sessions.go`。

### 11.1 数据与 seq

- 三张表按 §2 建，`agent_sessions` 增加 owner 两列（`owner_kind`/`owner_id`，会话属于调用者；
  其他 principal 一律 404）和 `revision`（`resource.changed` 序号，用于 PATCH/DELETE 的
  `expected_revision` 与列表 `since_revision`）。
- `seq` 由每次会话运行时的计数器分配（`last_seq` 高水位），消息、工具调用、事件共享；
  消息保留窗口默认 200 条，按消息 seq 删除最旧消息；工具调用与审批关联不删除。
- 所有写入都在 `storage.Tx`，写会话行时 `tx.Changed("agent_sessions/<id>")` 回写 revision。
  该 subject 不在事件可见性映射内，所以会话变更不会进入全局 `/api/v1/events`。

### 11.2 API 细节

- 9 条路由与 §3 一致（§3 的最后一条可选便捷入口
  `POST /{id}/tool-calls/{call_id}/approve` 未实现：审批决定只走既有的
  `POST /api/v1/approvals/{approval_id}/decision`，避免出现第二条批准路径）。
  `POST /messages` 返回 `201` + `{session,message}`（turn 异步），
  `DELETE` 返回 `204`，其余返回 `200`。所有变更路由在 OpenAPI 里是
  `x-qwq-idempotency: exempt`：会话是调用者自己的聊天状态，不是 operation；
  发送消息的幂等用可选的 `client_message_id`（同一值返回第一次的消息）。
- `PATCH` 要求 `expected_revision`（与全站并发约定一致）；`DELETE` 的
  `expected_revision` 可选。
- `?status=attention` = `waiting_approval` + `failed`。未读没有单独 API：客户端用
  `last_seq` 与本地已读位置自行推导（悬浮窗只需要 attention 与 `pending_approvals`）。
- 路由复用现有 `host.agent_sessions:read/write` 角色权限，并由 owner 校验保留本人范围。
  viewer 可以查看已有本人会话，创建、发送、配置、API key、取消和删除需要 write。
  scoped service 仍按完整作用域授权，续期账号不能借本人归属使用全局模型；工具调用
  继续由 `operations.Run` 按角色/委托鉴权。2026-11-20 的收口见 ADR-0031。

### 11.3 Core 与 Turn

- `Turn` 在 §4 之外带 `Runner`（工具执行）与 `NextCallID`（本次 turn 的 call id 生成器）；
  core 不直接碰数据库、网络凭据或 shell。
- `native` 采用非流式 chat completions：一次 `message.delta`（整段文本）+
  `message.completed`，工具调用步的 `message.completed` 带 `tool_calls`，
  运行时会把它写入 `content_json` 以便下一轮重建模型上下文。步数上限默认 8（`max_steps`）。
- 工具名做 OpenAI 合法化（点/斜杠转下划线，≤64；冲突加稳定哈希后缀），调用再映射回 action id。
- 工具列表由 `ToolCatalog` 提供；`read_only` 时只保留 `effect=read`。当前宿主还没有把
  `internal/catalog` 适配成可枚举的 `ToolCatalog`（该包只有搜索接口），生产接线留待集成。

### 11.4 审批与模式

- Runner 返回 `awaiting_approval` 时 core 发 `approval_required` 并返回 `ErrWaitingApproval`；
  会话进入 `waiting_approval`，tool call 记 `awaiting_approval` 并关联 operation/approval。
  `ApprovalBridge.Wait` 拿到决定后：approve → `approval_decided` + `tool_result` + 用补全后的
  历史再跑一个 turn；reject → `approval_decided` + `tool_result(rejected)` + `turn.completed{idle}`。
  bridge 为 nil 时会话保持等待，直到用户 cancel（A2 没有内置审批监听，生产接线待集成）。
- 决定只能来自既有 `POST /api/v1/approvals/{approval_id}/decision`（人类会话）；本包不提供
  任何“批准”方法，AI 也没有路径调用它。
- `permission_mode` 只由 `PATCH` 修改（浏览器会话/服务账号；delegation token 被网关拒绝）。
  每次 Runner 调用读取会话当前模式并 `operations.WithPermissionMode(ctx, mode)`，所以运行中的
  turn 之后的调用也会用新模式；切到 `read_only` 会拒绝正在等待的写调用（`tool_result cancelled`），
  不影响已批准的 operation。
- Runner 收到的 `ToolCall` 带会话 owner（`Actor`）、当前模式与 session id；生产 Runner 用它
  构造 operations 的调用者，宿主判定仍是权威。

### 11.5 SSE

- 域事件帧 `id: <seq>` + 一行 `data:` JSON（`type` 字段区分）；控制帧 `event: ready`
  （head + 心跳秒数）、`event: heartbeat`（15 s）、`event: resync`
  （`reason`：`out_of_window` / `buffer_overflow`）。
- `Last-Event-ID` 或 `last_event_id` 续传：`0` 表示回放当前保留的整个 ring；命中 ring 回放；
  更旧的位置 → `resync`，客户端重拉 `GET /agent-sessions/{id}`。重启后 ring 为空，所以历史位置
  一律 resync。慢客户端缓冲溢出同样 resync 并关闭流。
- 关闭浏览器不取消 turn；`DELETE`/`Close` 取消并关闭流。

- 活跃订阅上限为每会话8、服务全局64。关闭、缓冲溢出、删除和服务退出共用一次额度释放；关闭后的旧运行时和已删除的旧行不能重新订阅。
- 单助手文本总预算为256KiB，delta 先按剩余字节在 UTF-8 Rune 边界截断；空段和满额后的文本不再分配序号或广播。公开 message.content / event.delta 的 maxLength 为262144，实际产出仍受总字节预算约束。
- 删除在原会话锁内提交数据库删除、标记 closed 并关闭订阅，之后才移除同一内存入口；提交失败保留原入口和订阅。停止后若又进入新工作，返回冲突，保留该工作。

