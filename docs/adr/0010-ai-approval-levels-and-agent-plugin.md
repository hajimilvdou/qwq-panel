# ADR-0010：AI 操作审批分级与原生 Agent 插件

- 状态：Proposed（2026-11-02，发起人提出；实现中）
- 关联：ADR-0004 D4/D6/D7、ADR-0007（ABI 冻结）、ADR-0009（首版插件）、ARCH §4.1.1、§5.3、§6.5

## 背景

ADR-0004 目前按“有效风险 = max(声明风险, capability 下限)”决定是否需要审批：medium/high 一律进入 `AWAITING_APPROVAL`。实际使用中，插件的大量常规操作被逐条打断，AI 还要为每次审批花 token 解释；用户看到的确认卡也只有宿主拼出的事实，缺少插件作者写的“这次操作到底做什么”。

发起人的目标是：

- 插件作者在制作时给每个 operation 定级：**自动级**、**审批级**、**AI 操纵审批级**；
- 只有需要用户同意的级别才向用户报备；
- 审批级操作自带一段介绍，审批时直接展示，AI 不必再花 token 解释；
- 系统原生适配 AI，提供“原生 AI 插件”页面：内置自研 agent，也可安装 claude code / codex / opencode 等 CLI 作为 agent 核心；
- Agent 可在插件页正常对话/确认；用户离开页面后，用右下角可缩放悬浮窗提示待确认操作，点开是输入窗 + 聊天窗（UI 由发起人后续设计）。

## 决策

### 1. manifest operation 增加审批元数据

在 `api/manifest/v1/manifest.schema.json` 的 operation 上增加三个可选字段（schema minor 从 1.0 升到 1.1，宿主支持 1.0 与 1.1）：

| 字段 | 类型 | 规则 |
|---|---|---|
| `approval` | enum `auto` / `confirm` / `ai_confirm` | 可选；缺省按风险推导（见 §2） |
| `approval_summary` | string 1–200 | 单行、无控制字符/双向覆盖符；`confirm`/`ai_confirm` 必填 |
| `approval_description` | string 1–2000 | 可多行 Markdown 文本；按不可信文本转义展示 |

`approval_summary` 是确认卡标题，`approval_description` 是展开后的说明（作用、影响范围、是否可撤销、失败会怎样）。两者都来自已签名 manifest，安装时已验证；运行时仍按不可信文本处理，不执行 HTML/脚本。

### 2. 级别语义

- `auto`：不因插件声明而要求审批；宿主硬规则仍然生效（见 §3）。适合只读、可逆、影响面小的操作。
- `confirm`：任何调用者（真人或 AI）都需要一次用户确认；适合写操作、会影响线上状态但可回滚的操作。
- `ai_confirm`：**只有 AI/委托调用需要用户确认**；真人会话直接执行（仍受宿主硬规则约束）。适合“人点一下没问题，但不想让 AI 自己决定”的操作。
- 缺省推导：`effect=read` → `auto`；`effect=write` → `confirm`；`effect=destructive` → `confirm`。插件可显式提高，不能低于宿主硬规则。

### 2.1 用户权限模式（agent permission mode）

每个 agent 会话（以及委托）有一个用户可选的权限模式，默认 **safe**：

| 模式 | 语义 | operations 行为 |
|---|---|---|
| `read_only` | 只读/计划 | 拒绝所有写 operation，不产生审批 |
| `safe` | 需要用户审批（默认） | `confirm`、`ai_confirm`、destructive、high 都进审批；`auto` 只读/低风险直跑 |
| `full` | 完全权限 | 插件级审批全部跳过，包括 `confirm`/`ai_confirm`/high；仅保留不可逆 destructive。跳过的只是**插件**动作的审批：宿主动作（`host.*`）有效风险 ≥ high 时在 full 下仍须审批；human-only 权限（ADR-0004 D6）永不交给 AI 会话 |
| `custom` | 自定义 | 按 `approval` 级别逐项覆盖；用于后续“允许写但禁止删”等 |

规则：

- 模式由用户在 agent 插件页/会话设置中选择，持久化到会话与委托；AI 不能自行切换模式。
- 模式是**上限**：插件仍不能把 `destructive` 声明成 `auto` 来绕过 `read_only`/`safe`。
- 外部 CLI 的权限模式只影响该 CLI 自己的本地行为，**宿主 operations 的判定才是权威**；CLI 即使处于 bypass/full-auto，宿主仍按会话模式执行。
- 外部 CLI 适配层提供统一接口，后续按 CLI 映射：

| 统一模式 | Claude Code | Codex | opencode |
|---|---|---|---|
| `read_only` | `plan` | `suggest` | `plan` |
| `safe` | `default` | `auto-edit`（写仍由宿主审批） | `build` + 宿主审批 |
| `full` | `bypassPermissions`（显式确认） | `full-auto` | `build`（无宿主审批） |
| `custom` | 逐项 allow/deny | 逐项 approval policy | 逐项 permission |

```go
// 后续实现放在 agent CLI 适配层；本 ADR 先定契约。
type PermissionMode string // read_only, safe, full, custom
type CLIAdapter interface {
    MapMode(PermissionMode) (args []string, err error)
    // 宿主仍以 operations 判定为准，不信任 CLI 自报模式。
}
```

### 3. 宿主硬规则（不可被插件降级）

以下情况无论 `approval` 是什么都必须审批：

- `effect=destructive`；
- 有效风险为 `high`（capability 下限或声明风险）；
- capability 首次授予/敏感能力变更（安装向导另行确认）；
- 委托策略 `on_approval_required=fail` 时返回 `APPROVAL_REQUIRED`。

`auto` 只表示”插件不额外加一道审批”，不是绕过宿主安全策略。可达性动作（SSH/防火墙/面板端口/TLS）并入本分级执行（ADR-0016），没有额外的硬保护。

### 4. 审批卡内容

审批卡包含：

- 宿主事实：action、参数摘要、目标、所需 capability、有效风险、是否可撤销、来自插件的变更预览；
- 插件介绍：`approval_summary`（标题）+ `approval_description`（展开文本），标记为“来自插件”；
- AI 上下文：发起者、`on_behalf_of`、委托策略、operation_id；
- 需要 MFA 时输入 TOTP。

AI 在调用 `plan`/`execute` 时不需要重复解释操作；工具结果只返回 `approval_required` 与 operation/approval id，UI 直接展示插件介绍。

### 5. 原生 Agent 插件

新增宿主内置插件 `agent.native`（P6 交付）：

- 独立页面（`/plugins/agent.native`），提供会话列表、聊天、工具调用、审批卡、暂停/接管；
- 内置 agent 核心由宿主提供；外部 CLI agent（claude code / codex / opencode）作为可选的“agent 核心”配置，通过受控子进程 + PTY/JSON 流适配，不直接获得宿主权限；
- agent 的每次工具调用仍走 operations：读操作可自动，写/危险操作按 §2/§3 进入审批；AI 永远不能自己批准；
- 会话与消息持久化（有界），审批请求与 operation 关联；页面关闭后由宿主/SSE 保持会话；
- 悬浮窗、输入窗、聊天窗、动画、位置与折叠状态是纯 UI，由发起人后续设计；后端只提供会话状态、待审批列表与 SSE 事件。

### 6. 外部 CLI agent 的边界

- 每个 CLI 作为 agent 插件的一个核心，配置命令、参数、工作目录、环境变量（敏感值用 secret 引用）、超时与资源限制；
- 子进程默认无网络（除非插件声明 `network.egress` 并获批准）、无宿主凭据；只通过本地受控管道与 agent 服务通信；
- CLI 输出按不可信文本处理；工具调用必须由宿主适配层转成 operations，不允许 CLI 直接执行 shell；
- 具体协议（JSON lines / MCP / PTY）在 P6 设计 ADR 中定；本 ADR 只确定权限与审批模型。

## 后果

- manifest schema 升到 1.1；旧 1.0 manifest 继续可用，新字段被旧宿主拒绝是预期（旧宿主只支持 1.0）。
- `sdk/manifest`、`internal/catalog`、`internal/operations`、`internal/api` 的审批路径要一起改；新增测试覆盖三级语义、审批介绍、AI 不能批准。
- UI 可以少展示“AI 解释”，直接渲染签名 manifest 的介绍；坏文本按纯文本处理。
- 外部 CLI agent 的引入增加进程、凭据与网络攻击面，P6 前必须完成沙箱与审计设计。

## 未采用

- 只按风险自动决定：无法表达“人可以直接做、AI 需要确认”。
- 让 AI 在审批时生成解释：费 token、不可审计、与签名 manifest 不一致。
- 插件自定义审批 UI：审批卡必须由宿主渲染，插件只能提供文本与结构化预览。
- 让外部 CLI 直接拿宿主 token 执行：绕过 operations 与审计，拒绝。
