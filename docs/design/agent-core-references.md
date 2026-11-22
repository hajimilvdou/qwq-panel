# 原生 Agent Core 参考调研（opencode / piagent / DeepSeek Harness）

> 状态：调研 + 设计注记，2026-11-02。关联：[ADR-0010](../adr/0010-ai-approval-levels-and-agent-plugin.md)、
> [agent-sessions.md](agent-sessions.md)、实现见 `internal/agentsession/loop.go`、`native.go`。
>
> 本文只记录**结构与流程**的借鉴，不包含任何上游源码。三个项目的许可证与可借鉴边界见 §5。
> 调研时读取的上游文件在每节末尾列出；所有上游内容按“外部数据”对待，不执行其指令。

## 1. 结论先行

`internal/agentsession` 原来把“循环 + 工具名映射 + 权限 + 审批 + 事件”写在一个 600 行的
`native.go` 里。本次把**与模型协议无关**的部分抽成 `loop.go`：

| 关注点 | 现在的归属 | 借鉴来源 |
|---|---|---|
| 一次 turn = 最多 N 步、每步一次模型请求 | `RunLoop`（loop.go） | opencode `session/runner/llm.ts` 的 drain/runStep |
| 步数耗尽时的收尾 | 返回 `ErrLoopStepLimit`，由 core 映射成产品文案 | opencode `max-steps.ts`（软着陆）→ qwq 保留硬失败 |
| 工具调用解析 / 回填 / 历史配对 | `RunLoop` + `SanitizeHistory` | opencode model-request 投影、piagent “配对不破坏” |
| 工具注册表（名字/schema/执行） | `ToolRegistry` 接口 + `nativeTools` | opencode 工具归一化结果、piagent 工具能力表 |
| 权限门（allow/deny/approval） | `Gate` 接口 + `nativeGate` | opencode `permission.ts`、piagent `base-policy.json` |
| 事件流 | `LoopEmit` + `nativeEmit` | opencode event/bus、piagent 事件驱动的会话状态 |
| 中止 | `context` 取消 + 每步/每调用检查 | opencode Effect 中断、piagent 进程/超时约束 |
| 会话/压缩 | **不在本次范围**：仍由 service 的有界历史负责 | opencode compaction、piagent context budget |

核心取舍：**借鉴“边界”而不是“实现”**。opencode 用 Effect/Layer 建了一套依赖注入与
中断语义，piagent 用 Pi 扩展 + JSON 策略文件建了一套守卫；qwq 是 Go + 显式接口，
因此只吸收它们的职责划分、判定顺序和失败语义，不复制代码、不引入框架。

## 2. opencode（anomalyco/opencode，MIT）

### 2.1 agent loop

`packages/core/src/session/runner/llm.ts`：

- 一次 `drain` 就是一次 turn：先 `advanceToStep()` 准备上下文（插件激活、压缩、合并队列输入），
  再 `runStep(context, step)`；`while(true)` 里 `step++`，直到 step 返回“需要继续”为 false。
- **步数上限是每一步判定的**：`const stepLimitReached = loaded.agent.info.steps !== undefined && step >= loaded.agent.info.steps`，
  达到上限时不再禁用循环，而是给最后一步追加一条 `Message.assistant(MAX_STEPS_PROMPT)` 并把
  `toolChoice` 设为 `"none"`，让模型用文本收尾（`max-steps.ts` 里是那段 “CRITICAL - MAXIMUM STEPS REACHED” 提示）。
- 每步有独立的 `assistantMessageID`；step 的 attempt 内部处理 retry、断流续写
  （`CONTINUE_AFTER_INCOMPLETE_STREAM`）、输出上限续写（连续 3 次 length 则失败）、溢出压缩。
- turn 开始时 `settleStaleCompactions` / `settleStaleToolCalls`：把上次进程死亡留下的
  `running/streaming` 工具调用补成 failed，避免历史里出现永远 running 的调用。

借鉴：turn/step 两层结构、每步一个 assistant message id、把“中断遗留的调用”在下一 turn 开头结清。
**不借鉴**：Effect/Layer/Service 依赖注入、模型 transport 与 websocket 复用、插件 hook 重写请求；
这些在 Go 里用接口 + `context` 更直接，qwq 也不需要多 provider/多 agent registry。

不采纳点：opencode 的软着陆（last step 注入提示 + `tool_choice=none`）会改变现有
`native` 的失败语义（现有测试与 UX 都是“达到上限 → 明确错误，用户再发一条”），
本次保持硬失败，文档记录该选项，留给后续产品决定。

### 2.2 tool registry / tool-output

- 工具以插件/内建两类目录组织（`packages/core/src/tool/`、`tool/plugin/*.ts`、`tool/mcp.ts`），
  模型侧 schema 与执行分离；`llm.ts` 在每次执行前包一层
  `plugins.awaitActivation.pipe(Effect.andThen(prepared.executeTool(call)))`，即“执行前重新确认运行环境”。
- 工具结果是**归一化结构**（`Tool.NormalizedResult`，见 `tool-output.ts` 的 import）：`content` 是
  `text` / `file` 条目数组，外加 `metadata`；`ToolOutput.truncate` 在结果超限时保留前
  `MAX_LINES=2000` / `MAX_BYTES=50KiB`，把完整内容写到 `tool-output/tool_*.…`，并在 content 里插入
  `[showing lines 1-N of M; full output saved to <path>]`，metadata 记 `truncated`/`outputPath`。
- 同一 `truncate` 对已处理结果幂等（`metadata.truncated !== undefined` 直接返回）。

借鉴：注册表只管“描述 + 执行”，执行结果用统一结构；结果超限要**显式标注**而不是静默截断；
`Spec(name)` 先解析再执行（未知工具不产生执行）。
**不借鉴**：50KiB + spill 文件、metadata 体系（qwq 的工具结果就是 JSON，且会话有界；
将来若要落盘再按 `outputPath` 思路做）。本次用 `MaxLoopToolBytes = 32KiB` 的文本裁剪，
与旧 `toolResultText` 行为一致。

### 2.3 permission / approval

`packages/core/src/permission.ts`（读到的语义）：

- 规则是 `{action, resource, effect}` 的 ruleset；`evaluate` 用 `findLast` + 通配匹配，
  **找不到规则默认 `ask`**（fail closed）；`merge` 按 agent rules → session rules → saved allow 规则叠加。
- `deny` **先判并短路**（配置的 deny 永远赢），然后才看 ask/allow；插件 hook 可以改 effect，但不能绕开 deny。
- `ask` 会创建 pending request（含 id/session/action/resources/source），并通过 `Deferred` 挂起调用者；
  `reply` 支持 `reject` / `allow` / `always`；`reject` 会级联拒绝**同一 session 的其它 pending ask**；
  `always` 把规则持久化成 saved rule，并重新评估其它 pending 请求批量放行。
- `Unattended` context：无人值守时，无法满足的 ask 直接变成 deny 并给出原因。
- `DeclinedError` 与 `CorrectedError` 区分“拒绝”与“拒绝并给反馈”，后者转成 tool failure 让模型改。

借鉴：判定顺序（deny → ask/allow）、默认 ask 的 fail-closed、审批是**暂停而不是执行**、
同一 turn 内多个待审批调用的连带处理、拒绝理由回填给模型。
**不借鉴**：规则文件与 saved 规则持久化（qwq 的权威是 `operations` 的审批级别 + RBAC，
ADR-0010 已定）；审批 id 由 operations 生成，agent 侧不另建一套审批存储。

### 2.4 abort / event / session-compaction

- 中断靠 Effect 的中断语义：`Effect.uninterruptibleMask` 保护关键段，关闭/超时是可中断的；
  `SessionStep.attempt` 里把“工具还在跑时进程被关”记成 `Tool.Failed`（`settleStaleToolCalls`）。
- 事件经 bus 发布（`SessionEvent.Tool.Failed`、`Permission.Event.Asked/Replied`、`Compaction.*`），
  消息与 part 是事件投影出来的（`message-updater.ts` / `projector.ts`）。
- 压缩：`session/compaction.ts` 在 step 边界估算 prompt，超预算自动压缩；压缩本身是一个 inbox 控制项，
  可以被打断、失败要发 `Compaction.Failed`；`SessionCompaction.estimatePrompt` 也被 step 使用。

借鉴：**事件是投影源**、暂停/恢复要显式事件、压缩放在 step 边界而不是工具执行中途。
**不借鉴**：完整 compaction（qwq 现有 200 条有界历史 + 服务层裁剪已够用；将来接入时再按 step 边界做）。

读取的文件：
[llm.ts](https://github.com/anomalyco/opencode/blob/dev/packages/core/src/session/runner/llm.ts)、
[max-steps.ts](https://github.com/anomalyco/opencode/blob/dev/packages/core/src/session/runner/max-steps.ts)、
[permission.ts](https://github.com/anomalyco/opencode/blob/dev/packages/core/src/permission.ts)、
[tool-output.ts](https://github.com/anomalyco/opencode/blob/dev/packages/core/src/tool-output.ts)、
[prompt.ts](https://github.com/anomalyco/opencode/blob/dev/packages/core/src/session/prompt.ts)、
[agent.ts](https://github.com/anomalyco/opencode/blob/dev/packages/core/src/agent.ts)。

## 3. piagent（Vt-mmm/piagent，MIT）

piagent 是 Pi 的扩展平台，**agent loop 本身属于 Pi**，piagent 提供的是“宿主侧的守卫 + 状态 + 预算”。
因此它最有价值的是权限/确认/中止的**判定位置**，而不是循环实现。

### 3.1 loop 的位置与生命周期

- 分层（`docs/en/architecture.md`）：composition（`extensions/piagent-guard.ts` 唯一入口）→ runtime
  适配器 → core services；依赖只能向下，`npm run architecture:check` 用 `architecture/layers.json` 强制。
- 运行时流程：Pi 加载唯一扩展 → 组合根解析 base policy / project profile / capability lock / 本地状态 →
  runtime hooks 归一化输入并收集证据 → core services 判定 path/shell/MCP/task/context/verify 策略 →
  runtime 注册工具与命令 → 本地状态记录证据。**prompt 只是引导，策略必须在 hook/guard 里强制**。
- 一条 turn 是 freeform 的（1.9.0 起没有 task contract），但每次工具调用都要过 guard。

借鉴：单一组合根、依赖方向、以及“策略判定必须能脱离 Pi 单测”的思想（qwq 用 `Gate` 接口 + fake 测试实现）。
**不借鉴**：把 Pi 当运行时的整体形态；qwq 的 core 自己在 Go 里跑循环，不需要扩展宿主。

### 3.2 tool registry / capability

- `runtime/tools/tool-groups.ts`：工具按用途分组（loader/intake/governance/task/recovery/policy/retrieval/…），
  由 prompt 分类结果决定**展示哪些组**；`PIAGENT_TOOL_ORDER` 固定注册顺序。
- 关键原则（architecture.md 原文意思）：**“Tool visibility is not authorization”**——分组只影响可见性，
  scope/read-only/protected-path/destructive/external-action guard 在任何模式、任何 mutation 路径都生效。
- `base-policy.json` 的 `toolRegistry.toolCapabilities`：把工具名映射到能力（`shell`、`filesystem-readonly`、
  `filesystem-write`、`browser`、`github`），`alwaysAllowedTools` 是白名单；未知工具按 fail-closed 处理。

借鉴：能力表 + 白名单、可见性与授权分离——qwq 里可见性由 `toolsFor` 过滤，授权由 `Gate` + `operations` 再看一次。
**不借鉴**：按 prompt 动态分组工具（qwq 的 `ToolCatalog` 已按权限模式过滤，避免同一会话内工具集抖动）。

### 3.3 permission / approval

- `policies/base-policy.json` 是策略数据的样板：
  - `protectedPaths` / `shellProtectedPaths`（`.git/**`、`.pi/**`、`**/.ssh/**`、`**/.env*` 等）；
  - `blockedCommandPatterns`（`rm -rf /`、`sudo `、`git reset --hard` …）；
  - `requireConfirmationPatterns`（`deploy`、`publish`、`git push` …）；
  - `execPolicy.rules`：`forbid` / `prompt` 两类动作，支持 `contains` / `regex`，并带 `reason`（给人和模型看）；
  - `permissionProfiles`：`read-only` / `workspace-write` / `trusted-full-access` / `bypass`，默认
    `workspace-write`，**非法值 fail closed 到 read-only**；
  - `externalActionPolicy`：provider 关键词 + 写动词 vs 安全动词（`get/list/read/search`）；
  - `contextBudget`、`finalGate`（验收证据）。
- 执行前的检查点：工具参数里的路径类字符串（嵌套数组、`file://`、百分号解码一次、深度上限 32，
  `content/query/pattern/text/command` 例外）、shell 命令的路径提取、MCP 调用的审批。
- 破坏性/外部动作必须人工确认；`/permission` 只切当前会话，profile 文件才是项目级默认。

借鉴：权限模式是**上限**、非法配置 fail closed、deny 与 prompt 分开、拒绝要给 reason、
破坏性动作单列一份清单。qwq 的 `nativeGate` 就是这条思路的 Go 版本（`read_only` 拒绝危险工具，
`safe/full` 交给 `operations` 判审批）。
**不借鉴**：JSON 策略文件 + 路径/命令模式匹配引擎（qwq 的权威是 operations 的 action 元数据 + RBAC；
引入第二套“字符串模式策略”会和 ADR-0010 的 approval 级别冲突）。

### 3.4 abort / event / session / compaction

- 中止：Pi 侧取消 + 进程树观察（`runtime/process-owner.mjs`、`process-tree-watch.mjs`，按文件名可知是
  进程归属与清理）；长任务用 `piagent_wait`；helper 的迟到结果在父任务终止时被丢弃，超时/溢出/取消都不合并输出。
- 会话状态：`.pi/piagent-state/` 下 tasks/trajectory/traces/context-engine 等，owner-only、拒绝祖先符号链接；
  JSONL 在跨进程锁下轮转，按年龄/数量/字节裁剪；journal 有哈希链与保留锚点（审计用，不作为运行时权威）。
- 压缩/上下文：Context Engine v2（FTS5 + 符号 + import 索引，token 预算 pack），
  `tool-result-compaction` 对大结果做预览 + 落盘捕获，`session/adaptive-context-*.ts` 做预算治理。

借鉴：**取消要在工具执行期间可见**（qwq 在每个工具前后检查 ctx，见 `RunLoop`）、
有界状态 + 裁剪、结果压缩要有回退路径。
**不借鉴**：索引/预算/证据体系（超出本任务；qwq 现有 200 条消息上限 + 32KiB 工具文本已足够）。

读取的文件：
[architecture.md](https://github.com/Vt-mmm/piagent/blob/main/docs/en/architecture.md)、
[base-policy.json](https://github.com/Vt-mmm/piagent/blob/main/packages/piagent-core/policies/base-policy.json)、
[tool-groups.ts](https://github.com/Vt-mmm/piagent/blob/main/packages/piagent-core/runtime/tools/tool-groups.ts)、
[piagent-core README](https://github.com/Vt-mmm/piagent/blob/main/packages/piagent-core/README.md)、
[AGENTS.md](https://github.com/Vt-mmm/piagent/blob/main/AGENTS.md)。

## 4. DeepSeek Harness（本地安装，仅结构参考）

本机只安装了**打包产物**，没有可读的 agent core 源码；按要求**不反编译**，只记录能从
`resources/app.asar` 索引与解包目录看到的**结构**（以下均为文件名/目录名，不代表已验证的行为）：

- `resources/app.asar.unpacked/dsh/node_modules/@deepseek-ai/` 只有 3 个包：
  `dsh-session-log-export`、`libreoffice-kit`、`libreoffice-kit-win32-x64`。
- `app.asar` 索引里 `dsh` 自身的代码与依赖在 `/dsh/node_modules/` 下（约 1.8 万条目），其中：
  - `@deepseek-ai/cordis`（`src/context.ts`、`fiber.ts`、`reflect.ts`、`events.ts`、`logger.ts`）+
    `cordis-plugin-{loader,group,timer,include}`：一个服务/插件生命周期与依赖注入内核；
  - `@agentclientprotocol/sdk`（`dist/protocol-router.js`、`server-permission.test.js`、`server-session-sse.js`、
    `jsonrpc.js`、`sse.js`、`stream.js`）：ACP 协议层，包含 permission 与 session 的 SSE/JSON-RPC 传输；
  - `pi-ai`（`dist/`）：模型 provider 适配层；
  - `dsh` 包内可见 `stream-protocol.ts`、`drain.ts`、`types.ts`、`skills/`、`presets/`、`runtime/`。
- `resources/runtime/cli/` 只有 `dsh.cmd` 与 `command-manager.js`（启动器），`resources/runtime/bin/` 是 node 包装。

据此只能得到的结论（不作为实现依据）：DSH 把 **agent 循环与 provider 适配、插件内核、会话协议**分层，
用协议（ACP）承载 permission 请求与会话流，用插件内核做组合。这与本任务“把循环/工具/权限/事件拆开”
的方向一致，但没有可借鉴的具体代码，因此 qwq 不引用其实现，只在设计上对齐“协议化事件 + 显式权限请求”。

## 5. 许可证与边界

| 项目 | 许可证 | 本文使用方式 |
|---|---|---|
| opencode（anomalyco/opencode） | MIT（上游 LICENSE） | 阅读公开源码，提炼流程；**未复制代码** |
| piagent（Vt-mmm/piagent） | MIT（上游 LICENSE） | 阅读文档/策略样例；**未复制代码** |
| DeepSeek Harness | 本地商业安装包（无源码许可） | 只看目录结构；不反编译、不复制；仅作本地参考 |

qwq 自身的产出（`loop.go`、`native.go`、测试）全部按 AGPL-3.0-only 编写，注释英文；
没有引入新依赖，没有把上游代码、提示词或策略文件搬进仓库。`max-steps` 这类上游提示词只做行为描述，
未逐字复制。

## 6. 映射到 qwq

```
domain: service.go                    (会话状态机、seq、SSE、审批桥、暂停/恢复)
            │  Turn{Messages, Tools, Config, Runner, PermissionMode}
            ▼
core:    native.go                    (OpenAI-compatible 适配器)
            ├─ openAIProvider  ── Provider  ──▶ loop.go RunLoop
            ├─ nativeTools     ── ToolRegistry ─┘     │
            ├─ nativeGate      ── Gate ───────────────┤
            └─ nativeEmit      ── LoopEmit ───────────┘
                                          │
                                          ▼
                              Event (message.delta/completed, tool_call, tool_result, approval_required)
```

| 概念 | 代码 | 说明 |
|---|---|---|
| `RunLoop(ctx, Provider, ToolRegistry, Gate, LoopEmit, LoopOptions)` | `loop.go` | 纯函数式循环：不改全局状态，不做 IO |
| `Provider` | `loop.go` / `openAIProvider`（native.go） | 一次 `Complete` = 一次 HTTP chat/completions；非流式，整段文本作为一个 delta |
| `ToolRegistry` | `loop.go` / `nativeTools` | 名字/schema/描述来自 `ToolSpec`，执行走 `Runner`（`operations.Run` 的生产接线由宿主提供） |
| `Gate` | `loop.go` / `nativeGate` | `allow/deny/approval`；`approval` 只发事件并暂停，不执行工具；上层 service 消费 `ErrWaitingApproval` |
| `Runner` | `types.go` | 不变：每次调用由 service 覆盖 owner/当前权限模式并 `operations.WithPermissionMode` |
| `Event` | `types.go` / `nativeEmit` | loop 事件 → 会话事件：delta→`message.delta`，assistant→`message.completed`（带 `tool_calls`），tool_call/tool_result/approval 一一对应；done/error 不重复发（service 从返回值发 `turn.completed`/`error`） |
| 历史 sanitize | `SanitizeHistory` | assistant `tool_calls` 必须被紧随其后的 tool 结果**全部**配对，否则整步（含孤立结果）丢弃；孤立 tool 结果丢弃；空文本消息丢弃 |
| 权限模式 | `nativeGate` + `service.toolsFor` | 双层：`toolsFor` 决定模型“看得见”什么，`nativeGate` 决定“能不能执行”（visibility ≠ authorization） |

### 6.1 approval 的责任边界（与任务描述的一处偏差）

任务描述里 `safe` 模式下“写/危险工具由 Gate 返回 approval”。实际落地时 Gate 可以返回 approval，
**但内置 `nativeGate` 不这么做**：审批必须有 `approval_id` 才能被人类用
`POST /api/v1/approvals/{id}/decision` 决定，而这个 id 由 `operations` 在执行时生成。
如果 Gate 自己造一个 approval，会话进入 `waiting_approval` 后无法被批准（死锁）。
因此：

- 内置策略只做**上限**：`read_only` 拒绝危险工具（deny + 给模型原因）；`safe/full/custom` 放行，
  由 `operations` 按 ADR-0010 的 approval 级别/风险/破坏性判定审批；
- 真正的“执行前审批”由 `Runner` 返回 `awaiting_approval` + `approval_id`，loop 发 approval 事件并暂停
  （`TestRunLoopApprovalFromTool` 覆盖）；
- 需要“执行前”审批的集成可以注入 `NativeOptions.Gate`（`service.Options.Native.Gate`），
  只要它能提供真实 approval id；`TestNativeCoreUsesInjectedGate` 覆盖了注入路径。

这样 `safe` 仍然“写操作需要审批”，只是审批权威没有从 operations 搬到一个造不出 id 的 Gate 里。
