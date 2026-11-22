# ADR-0010：操作审批分级与审批介绍（后端/契约）

状态：已实现（后端与契约，无 UI）。范围：`api/manifest/v1`、`sdk/manifest`、`internal/catalog`、
`internal/operations`、`internal/api`、`api/public/v1/openapi.yaml`、`tools/manifest_check.py`。
未改动：`internal/controller`、`internal/agentapi`（见 §9 集成待办）、`api/qwq/platform/v1`（ABI 冻结）。

## 1. manifest schema 1.1（`api/manifest/v1/manifest.schema.json`）

operation 新增三个可选字段（`sdk/manifest/manifest.schema.json` 为逐字节副本）：

| 字段 | 约束 | 说明 |
|---|---|---|
| `approval` | `$defs/approval` = enum `auto`/`confirm`/`ai_confirm` | 缺省由 effect 推导 |
| `approval_summary` | `$defs/line`，1–200 字符 | 单行；无 C0/C1 控制符、DEL、bidi 覆盖/隔离符；`confirm`/`ai_confirm` 必填 |
| `approval_description` | `$defs/multiline`，1–2000 字符 | 可含 `\n`；同样排除控制符与 bidi |

- `schema_version`：说明改为“当前 1.1（ADR-0010 审批元数据），1.0 仍合法”，新增 `"examples": ["1.1"]`；
  pattern 不变（`^1\.(0|[1-9][0-9]*)$`），1.0 / 1.1 都通过，1.2+ 由安装器规则
  `UNSUPPORTED_SCHEMA_VERSION` 拒绝。
- 必填由 operation 的 `allOf` 条件表达：
  `if approval ∈ {confirm, ai_confirm} then required [approval_summary]`。
- `$id` 仍是 `urn:qwq:plugin-manifest:v1`（主版本不变）。

`sdk/manifest`：

- `Operation` 增加 `Approval` / `ApprovalSummary` / `ApprovalDescription`（JSON tag 与 schema 一致，
  `omitempty`；`TestStructCoversSchema` 保证结构体与 schema 一一对应）。
- `Operation.EffectiveApproval()`：显式值优先，否则按 effect 推导（read→auto，write/destructive→confirm）。
- `SupportedSchemaMinor = 1`。
- 安装器规则（`rules.go` 的 `approvalRules`，独立函数，由 `installerRules` 调用）：
  - `APPROVAL_INVALID`：level 不在三值内；
  - `APPROVAL_SUMMARY_MISSING`：`confirm`/`ai_confirm` 缺 summary；
  - `APPROVAL_SUMMARY_INVALID`：空白（仅空格）、含控制符/bidi/替换符 U+FFFD、超过 200；
  - `APPROVAL_DESCRIPTION_INVALID`：含控制符/bidi/替换符（`\n` 除外）、超过 2000。
  这些规则与 schema 重叠，作为**纵深防御**保留：`Parse` 在 schema 阶段即失败，所以只有
  “纯空格 summary”“U+FFFD”这类 schema 放行、安装器拒绝的输入能走到这里（共享夹具里各有一个用例）；
  schema 之外的路径（宿主直接持有解码后的 `Manifest`）也受保护，`TestApprovalRules` 直接验证。
  1.0 manifest 没有这些字段 → 全部通过；未知字段仍由 `additionalProperties: false` 拒绝。

示例与夹具：

- `api/manifest/v1/examples/security.scan.manifest.json`：`schema_version` 升到 `1.1`；
  `baseline.enable` 增加 `approval: ai_confirm` + `approval_summary` + 多行 `approval_description`。
- `api/manifest/v1/testdata/cases.json`：`schema_version 1.1` 改为 accept，新增 `1.2` 拒绝；
  另加 17 个审批用例（accept：confirm 带 summary、有 summary 无 level、其它 operation 加字段、示例本身；
  reject：缺 summary、非法 level（字符串/数字）、summary 换行/制表符/bidi/纯空格/U+FFFD/超长、
  description 回车/bidi/超长、审批旁的未知字段）。
- `tools/manifest_check.py`：`SUPPORTED_SCHEMA_MINOR = 1`，新增 `approval_text_ok` 与
  `add_approval_rules`（指针、错误码、消息与 Go 一致），`ANNOTATIONS` 增加 `examples`
  （schema 新增的注解关键字，校验语义不变）。

## 2. 目录与动作元数据（`internal/catalog`）

- `Entry` 增加 `Approval` / `ApprovalSummary` / `ApprovalDescription`，JSON 名与 ActionMeta 对齐。
- `SetPlugin` 用 `op.EffectiveApproval()` 填 `Approval`（声明值或 effect 推导值），summary 用
  `cleanText`、description 用新的 `cleanTextBlock`（保留 `\n`，仍剔除控制符/bidi/U+FFFD）清洗并截断。
- `host_gen.go` 由 `go generate ./internal/catalog` 重生成：**无差异**（宿主动作 `x-qwq-action` 不含审批字段，
  ActionMeta 只出现在响应 schema，不参与生成），宿主动作三项为空。

## 3. 审批级别语义（`internal/operations`）

`Action` 增加 `Approval` / `ApprovalSummary` / `ApprovalDescription`（随 `action_meta` 列持久化，无需迁移）。

判定入口：`Action.DecideApproval(who, effectiveRisk, limits) ApprovalDecision`（`permission.go`），
在 `Run`、`CreatePlan`、`ExecutePlan` 三条执行路径上使用；`DecideApproval` 返回
`Denied` / `NeedApproval` / `Reason`（`permission_mode.read_only`、`effect.destructive`、`risk.high`、
`approval.confirm`、`approval.ai_confirm`、`policy.risk`）。

判定顺序（级别语义）：

1. **read_only**：非 read → `Denied`（`PERMISSION_DENIED`，不排队、不建 operation）。
2. **destructive**：任何模式都 `NeedApproval`（宿主硬规则，`auto`/`full` 都不能降级），且审批卡要 MFA。
3. **full**：跳过插件级 `confirm`/`ai_confirm` 与 high 风险规则（destructive 已在第 2 步）。
4. **有效风险 high**：`NeedApproval`（safe/custom）。
5. `ApprovalLevel()`：
   - `confirm` → 任何 actor 都 `NeedApproval`；
   - `ai_confirm` → `actor.Kind == ai_agent` 时 `NeedApproval`，真人/服务账号落到第 6 步；
   - `auto` → 落到第 6 步（`auto` 只表示“插件不额外加一道审批”）；
   - 空（宿主动作，或 1.0 插件且未经 catalog 推导）→ 落到第 6 步。
6. **既有风险规则** `Limits.NeedsApproval`（ADR-0004 D6：默认 low 直跑，medium/high 审批，
   `auto_approve_max_risk=none` 一律审批）。`policy.NeedsApproval` 原样保留，46 个既有测试的语义不变。

缺省推导：`Action.ApprovalLevel()` 对 `Source == plugin` 且未声明的动作推导
read→`auto`、write/destructive→`confirm`；宿主动作保持空（宿主按自己的路由策略，不套 manifest 推导）。
catalog 在 `SetPlugin` 时已把生效值写进 `Entry.Approval`，所以真实 manifest 的动作总是带着显式级别。

`on_approval_required=fail`：仍在 `NeedApproval` 为真后返回 `APPROVAL_REQUIRED`（`Run` / `ExecutePlan`）。

## 4. 用户权限模式（ADR-0010 §2.1）

- 导出类型 `operations.PermissionMode`：`read_only` / `safe` / `full` / `custom`；
  `DefaultPermissionMode = safe`，空值/未知值 `normalized()` 一律 safe（坏数据不会放宽权限），
  `Valid()` 供上层校验。
- 传递方式：`Limits.PermissionMode`（`Policy` 已经按 actor/action/target 解析，天然来自
  agent 会话/委托记录，**不从请求体读取**，所以 AI 无法自行切模式）。`Limits.Mode()` 返回归一化值。
- 二维矩阵（模式 × 级别 × actor 种类）由 `DecideApproval` 实现，`TestDecideApprovalMatrix` 覆盖
  34 组：三种级别 × human/ai/service、默认 safe、full 跳过 confirm/ai_confirm/high、
  destructive 在 full 下仍审批、read_only 拒绝写（含 destructive）、custom、`none`/`high` 策略、
  未知模式回落 safe。
- `custom` 目前等价 safe（按级别），逐项覆盖留给后续（枚举已定，UI 与存储不在本任务）。
- 端到端测试：`TestApprovalLevelsEndToEnd`（confirm/ai_confirm × 三种 actor）、
  `TestPermissionModeFullSkipsPluginApprovals`、`TestPermissionModeReadOnlyDeniesWrites`
  （拒绝后 0 operation、0 approval；plan 可创建但执行被拒）、`TestApprovalCardCarriesPluginTextAndMode`、
  `TestApprovalLevelDoesNotChangeApprovers`（AI/服务账号仍不能批准）。

## 5. 审批卡

`operations.ApprovalFacts` 增加：

- `approval_summary`、`approval_description`：来自 `Action`，即插件作者写在签名 manifest 里的文本，
  宿主动作恒为空；OpenAPI 标 `x-qwq-untrusted: true`，UI 按纯文本渲染；
- `permission_mode`：发起调用时的模式，便于审批人理解为什么被要求确认。

`actionMeta`（ActionMeta）增加 `approval`（生效级别；宿主动作为空）、`approval_summary`、
`approval_description`。facts 随 `approvals.facts` 列持久化，因此**列表/详情/决定**三个响应
（`ListApprovals`、`GetApproval`、`Decide`）都自动带出，无需新列、无需迁移；
`internal/api` 里 Approval 是直接序列化的（`writeResource`），`approvals.go` 只补了说明注释。

AI 侧仍只拿 `operation_id` / `approval_id`（`Outcome`），不需要复述操作说明。

## 6. OpenAPI

`api/public/v1/openapi.yaml`：

- 新 `ApprovalLevel`（enum auto/confirm/ai_confirm）与 `PermissionMode`（enum read_only/safe/full/custom），
  带 ADR-0010 语义说明；
- `ActionMeta` 增加可选 `approval` / `approval_summary` / `approval_description`；
- `ApprovalFacts` 增加可选 `approval_summary` / `approval_description` / `permission_mode`，
  facts 的 description 改为“插件文本仅限 summary 与审批文本且标记不可信”；
- `vacuum lint -d api/public/v1/openapi.yaml`：0 errors（272 warnings / 43 informs 为既有风格提示）。

`api/qwq/platform/v1/platform.proto` 未改（ABI 冻结）。

## 7. 兼容性

- **旧 manifest（1.0）**：无审批字段 → schema 通过；catalog 推导 read→auto、write→confirm，
  与 1.1 语义一致（ADR-0010 §2 的缺省推导）。宿主不再支持 1.2+（显式 `UNSUPPORTED_SCHEMA_VERSION`）。
- **旧宿主**：遇到 1.1 字段按未知字段拒绝，属预期（ADR-0010 后果）。
- **旧数据**：`operations.action_meta`、`approvals.facts` 都是 JSON 列，新字段可空、旧行读出为空，
  无迁移；`permission_mode` 对旧审批缺省不输出。
- **Go SDK 消费者**：`Operation` 只增字段；`SupportedSchemaMinor` 1 → 旧 1.0 manifest 不受影响。
- **OpenAPI**：只增可选字段，无破坏。
- **测试夹具**：`internal/operations/testenv_test.go` 的 3 个假插件动作补了 `Approval: auto`
  （否则 ADR-0010 推导会把它们变成 confirm，46 个既有测试的语义就不是“低风险直跑”了）；
  既有断言一条未改。

## 8. 验证（构建机 `appr1`，Go 1.27.3）

| 命令 | 结果 |
|---|---|
| `cd sdk && GOWORK=off go test -race ./manifest/...` | ok |
| `CGO_ENABLED=1 GOWORK=off go test -race ./internal/catalog/... ./internal/operations/... ./internal/api/...` | ok |
| `gofmt -l internal sdk tools` | 空 |
| `go vet ./internal/catalog/... ./internal/operations/... ./internal/api/...`，`cd sdk && go vet ./manifest/...` | 通过 |
| `staticcheck`（同上范围） | 通过 |
| `PYTHONDONTWRITEBYTECODE=1 python3 tools/manifest_check.py` | exit 0（197 ok） |
| `go generate ./internal/catalog` | host_gen.go 无差异 |
| `vacuum lint -d api/public/v1/openapi.yaml` | 0 errors |

## 9. 未完成 / 集成待办（不在本子代理范围）

1. `internal/controller/adapters.go`：
   - `catalogAdapter.Action` 需补三行 `Approval: e.Approval, ApprovalSummary: e.ApprovalSummary,
     ApprovalDescription: e.ApprovalDescription`，否则 catalog 里的级别到不了 operations；
   - `policyAdapter.Limits` 需设置 `PermissionMode`（AI 取委托/会话记录，真人取 safe），
     现在恒为 safe —— 功能默认安全，但 `read_only`/`full`/`custom` 还无法被用户选中。
2. 权限模式的持久化与 API：会话/委托记录上的 `permission_mode` 字段、选择它的接口、`authz.Policy`
   的字段（默认 safe，AI 不可改）属于 agent/委托子代理范围。
3. `internal/agentapi/describe_action.go` 的 `actionMeta` 未加审批字段，`describe_action`/`find_actions`
   暂时看不到 `approval*`；是否对 AI 暴露摘要由该子代理决定。
4. UI（确认卡插件文本块、悬浮窗）按 ADR 由发起人后续设计；本 ADR 的 `ApprovalFacts` 已够用。
5. `custom` 的逐项覆盖（allow/deny 规则存储与匹配）未实现，当前按级别处理。
6. 外部 CLI 的 `MapMode` 只保留 ADR 契约，未实现（本任务范围外）。
7. 敏感能力首次授予属于安装向导，不在 `DecideApproval` 内；可达性动作（SSH/防火墙/面板端口/TLS）
   自 ADR-0016 起并入普通分级（定级下限在目录加载时钳制），由 `DecideApproval` 正常处理，无倒计时确认。
8. `effect=read` 的 operation 不走审批路径（既有行为），因此 read 上声明 `confirm` 不会产生审批卡；
   manifest 允许该写法，运行时按“读操作不审批”处理。
