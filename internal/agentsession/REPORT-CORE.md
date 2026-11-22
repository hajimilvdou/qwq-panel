# 原生 Agent Core 重构报告（loop / tool / gate）

> 范围：`internal/agentsession/**` + 新增 `docs/design/agent-core-references.md`。
> 不改 `go.mod`/`go.sum`、`internal/api`、`controller`、`operations`、`sdk/`；无新依赖。
> 参考调研的完整对照（逐文件）在 [agent-core-references.md](../../docs/design/agent-core-references.md)。

## 1. 做了什么

原来的 `native.go`（612 行）把“OpenAI 协议 + 循环 + 工具名映射 + 事件 + 审批映射”混在一起。
本次拆成四层，都在 `internal/agentsession` 内：

```
RunLoop(ctx, Provider, ToolRegistry, Gate, LoopEmit, Options)   loop.go   通用循环
        ▲              ▲              ▲            ▲
        │              │              │            └─ nativeEmit     native.go 事件映射
        │              │              └────────────── nativeGate     native.go 权限模式/危险清单
        │              └───────────────────────────── nativeTools    native.go 目录 + Runner 适配
        └──────────────────────────────────────────── openAIProvider native.go OpenAI 协议
```

| 文件 | 行数 | 内容 |
|---|---:|---|
| `loop.go`（新） | 632 | `Provider` / `ToolRegistry` / `Gate` / `LoopEmit` / `RunLoop` / `SanitizeHistory` |
| `native.go`（重写） | 794 | OpenAI `Provider`、`ToolRegistry` 适配、`Gate`、事件桥、配置与密钥解析 |
| `loop_test.go`（新） | 627 | 16 个循环级测试 + sanitize 表驱动 |
| `native_loop_test.go`（新） | 296 | provider 拆分层、工具适配、gate 策略、service 注入 gate、步数文案 |
| `service.go` | +1 行 | `Options.Native.Gate` 透传给 `NewNativeCore` |

`native` 的对外契约完全不变：`Core` 接口、`Turn`/`Runner`/`Emit`、`ErrWaitingApproval`、
事件类型、错误码与文案都没有改；`service.go` 的暂停/恢复/SSE 逻辑没有动。

## 2. loop.go 设计

签名（与任务要求一致）：

```go
func RunLoop(ctx context.Context, provider Provider, tools ToolRegistry, gate Gate,
    emit LoopEmit, opts LoopOptions) (LoopResult, error)
```

- **消息历史**：`ModelMessage{Role, Content, ToolCalls, ToolCallID}`，角色常量
  `LoopRoleSystem/User/Assistant/Tool` 与持久化角色同值。历史在进入循环前过
  `SanitizeHistory`，之后每步把 assistant 消息与 tool 结果按序追加。
- **步数上限**：`LoopOptions.MaxSteps`（默认 `DefaultLoopSteps=8`）。每步一次
  `provider.Complete`；耗尽返回 `ErrLoopStepLimit`，由 `native` 映射成原来的
  “The agent did not finish within the tool-call step limit; …”。
- **工具调用**：每步的 calls 先做 `normalizeCalls`（空参数→`{}`、缺 id/重复 id 用
  `NextCallID` 补、无 id 且无生成器 → `INTERNAL`，与旧行为一致），再逐个：
  `Spec(name)` → 参数严格 `json.Valid` → 发 `tool_call` → `Gate.Check` → `Execute` →
  发 `tool_result` → 回填 tool 消息。
- **参数严格解析**：非法 JSON 不执行，回填 `VALIDATION_FAILED` 的 tool result（旧文案保留）；
  `tool_call` 事件在参数校验**之前**发出，因为 service 先落 tool call 行、再落结果行，
  没有 call 行的 result 会被 `loadToolCall` 拒绝（NOT_FOUND）。
  持久化时 `nativeEmit` 用 `storableArgs` 把非法参数替换成 `{}`：`content_json` 里存
  `json.RawMessage` 时，非法片段会让 `json.Marshal` 直接失败（旧实现在这条路径上同样会失败，
  只是没有测试覆盖，本次一并修掉；模型上下文里仍然是原始非法参数 + 明确的错误结果）。
- **错误回填**：`Execute` 返回 error → 转成 `problem.From(err)` 的 tool result；
  未知工具 → 旧行为保留：直接 `UNAVAILABLE` 失败（host 没有可记录该调用的 action id，
  也就无法落一条 result；已知工具的错误仍然是回填而不是中断）。
- **终止条件**：无 tool call 的文本回答（`LoopCompleted`）；Gate 或 Runner 要求审批
  （`LoopPaused` + `ErrLoopApproval`，**未执行**）；步数上限；provider/gate/emit 错误；
  `ctx` 取消（每步开头、每次工具执行前、每次 emit 后检查）。取消返回 `ctx.Err()`，
  由 service 用 `context.Cause` 区分用户取消与超时。
- **审批**：loop 只发 `LoopEventApproval`（含 `ApprovalRequest{ApprovalID, OperationID,
  Summary, Description, Risk, Approval, Deadline}`）并返回，不实现 UI/决定；
  `ApprovalID` 为空按 `INTERNAL` fail closed（不能生成一个没人能批准的状态）。
- **事件**：`delta` / `assistant` / `tool_call` / `tool_result` / `approval` / `done` / `error`。
  其中 `assistant` 是消息边界：host 需要在 tool 结果存在之前先持久化 assistant 的
  `tool_calls`（service 的 `message.completed` 语义），只有 delta 无法表达这个边界，
  这是对任务清单里 5 个事件的最小扩展；`done`/`error` 供其它 host 使用，
  `native` 不把它们映射成会话事件（避免 service 重复发 `turn.completed`/`error`）。
- **历史 sanitize**：`SanitizeHistory` 保证 assistant `tool_calls` 与随后 tool 结果
  一一配对，缺少任一结果则整步丢弃（连同其孤立结果），孤立 tool 结果丢弃，
  空文本消息丢弃，空工具输出记为 `(no output)`。旧 `buildChatMessages` 的三条断言
  （不完整步丢弃、孤立结果丢弃、名称重放一致）继续通过。

## 3. native.go 适配层

- `openAIProvider.Complete`：把 `ProviderRequest` 序列化成 `chat/completions` 请求
  （`tools`、`tool_choice=auto`、`temperature`），解析 `choices[0].message`，
  返回 `ProviderResponse{Content, ToolCalls}`；工具参数原样保留（不修 JSON）。
  超时、4 MiB 上限、非 200 不转发 body、密钥只进 Authorization 头并 `clear`，全部沿用。
- `nativeTools`：`Tools()/Spec()/Execute()`。`Spec` 通过 `toolNames` 把函数名解析回
  `ToolSpec`；`Execute` 构造 `ToolCall{CallID, SessionID, PermissionMode, Action, Args}` 调
  `Runner`，把 `ToolResult` 映射成 `ToolOutcome`（含 operation/approval 引用）；
  runner 为 nil 或 approve 缺 id 都返回明确的 tool 错误/`INTERNAL`。
- `toolNames`：名称合法化（点/斜杠→下划线、≤64、冲突加稳定哈希后缀）不变；
  新增 `defs()` 供 loop 的 `ToolDef`（name/description/schema/**action**）使用，
  action 只是透传，loop 不解释。
- `nativeEmit`：`delta→message.delta`、`assistant→message.completed`（有调用时带
  `tool_calls`）、`tool_call/tool_result/approval→` 同名会话事件；`done/error` 忽略。
  审批事件缺 approval id 时返回 `INTERNAL`（fail closed）；`storableArgs` 保证落库的参数
  一定是合法 JSON（见 §2 的参数解析）。
- `nativeGate`：宿主侧危险清单 + 模式上限。
  - `read_only`：`nativeDangerous` 为真的工具一律 `deny`（effect≠read，或 read+risk=high），
    理由回填给模型；
  - `safe` / `full` / `custom`：`allow`，审批仍由 `operations` 按 ADR-0010 判定
    （full 只跳过插件级审批，destructive 仍审批）；
  - 空模式按 `safe`；未知模式 fail closed（危险工具 deny、只读工具 allow）；
  - 未知工具 deny。
  - `NativeOptions.Gate` 可整体替换策略，供能提供真实 approval id 的集成使用。

### 3.1 为什么内置 Gate 不返回 approval（与任务文字的一处偏差）

审批必须带 `approval_id` 才能走 `POST /api/v1/approvals/{id}/decision`；这个 id 由
`operations` 在执行时生成。Gate 若自造 approval，会话会卡在 `waiting_approval` 且无法被批准。
所以内置策略只做**上限**（read_only 拒绝危险工具），`safe` 的“写操作需要审批”仍由
`Runner → operations` 的 `awaiting_approval` 实现：loop 收到后发 approval 事件并暂停
（`TestRunLoopApprovalFromTool`），service 的暂停/恢复逻辑原样消费。
需要“执行前”审批的集成可注入 `NativeOptions.Gate`（`TestNativeCoreUsesInjectedGate`），
只要它给出真实 id。这一点已在参考文档 §6.1 写明。

## 4. 与现有 API / 行为的兼容

- `Turn`、`Runner`、`RunnerFunc`、`ApprovalBridge`、`Event`、`ToolSpec`、`Core` 均未改；
  `NewNativeCore(NativeOptions)` 兼容（新增可选 `Gate` 字段）。
- 非流式：整段文本一个 `message.delta`，随后 `message.completed`；工具步的
  `message.completed` 带 `tool_calls`（现在还会保留该步的文本，旧实现会丢）。
- 步数：默认 8，`max_steps` 校验 1..8；`max_steps=1` 仍是一次模型请求后报上限。
- 错误文案：step limit、未配置、超时、4 MiB、非 200、无 completion、未知工具、
  参数非 JSON、缺 approval id 的文案都保持原样或语义等价。
- 密钥：只在 provider 的请求头出现，错误与事件都不含明文；`defer clear(apiKey)` 保留。
- 工具名映射与历史重放：`openAITools` / `buildChatMessages` / `toolNames.name` 保留，
  `native_test.go` 未改动且全部通过。
- `service.go` 仅新增 `Gate: opts.Native.Gate` 透传，不影响默认行为。

## 5. 测试

构建机：`QWQ_REMOTE_SRC=core1`，`CGO_ENABLED=1 go test -race`。

| 命令 | 结果 |
|---|---|
| `gofmt -l internal/agentsession` | 无输出 |
| `go vet ./internal/agentsession/...` | 通过 |
| `staticcheck ./internal/agentsession/...` | 通过（无输出） |
| `CGO_ENABLED=1 go test -race ./internal/agentsession/...` | ok，14.3s |

新增/覆盖（全部 PASS，`-race`）：

- 循环：单步文本、多步工具、工具错误回填、Execute 返回 error 回填、参数非法、
  未知工具、步数上限、ctx 启动前取消、工具执行中取消、provider 错误、emit 错误、
  Gate deny、Gate approval（暂停且不执行）、Runner approval、approval 缺 id、
  call id 补全/重复/缺生成器。
- 事件顺序：`delta→assistant→done`；工具步为
  `assistant→tool_call→tool_result→…→done`；暂停为 `assistant→tool_call→approval`。
- sanitize：完整配对、缺结果丢弃、孤立结果丢弃、半配对连同结果丢弃、空文本丢弃、
  空输出 `(no output)`。
- 适配层：`openAIProvider` 请求/响应映射与非法参数保留；`nativeTools` 的 action/args/
  session/mode 透传、未知工具、无 runner、approval 映射、缺 id；`nativeGate` 的
  read_only/safe/full/custom/空/未知模式与高风险只读工具。
- 集成：service 注入自定义 Gate 后拒绝调用且 runner 未被调用、turn 正常 idle；
  非法参数在 service 侧完整落库（tool_call 事件 + failed 结果 + 4 条消息，turn 仍 idle）；
  `max_steps=1` 的 UNAVAILABLE 文案仍含 "step limit"。
- 既有 `native_test.go`（往返、未配置、不泄漏密钥、超时、步数、名称映射、sanitize）
  与 `service_test.go` / `stream` / `store` / `cli` 测试全部通过。

## 6. 未做（明确不在本任务）

- 生产 `Runner` 接 `operations.Run`、审批桥、外部 CLI 适配器 —— 未动，仍由集成步骤负责。
- 流式 HTTP（SSE/chunked）与增量 delta：provider 仍是非流式，一个 delta 携带整段文本。
- 压缩/上下文预算（opencode compaction、piagent context engine）：未实现；
  现有 200 条消息上限 + 32KiB 工具文本裁剪保留。
- Gate 的插件级/逐 action 审批表：未实现；`custom` 模式当前等价 `safe`（由 operations 判定），
  与 ADR-0010 “首版可只存表不提供 UI”一致。
- DSH 的 cordis/ACP 结构没有可读源码，仅记录结构，未借鉴实现。
