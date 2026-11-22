# ADR-0016：可达性动作并入普通审批分级

- 状态：Accepted（2026-11-11，阶段 2 后端缺口 5；用户 2026-11-08 决定不做倒计时确认）
- 日期：2026-11-11
- 关联：ADR-0004 D6、ADR-0009（其第 3 条由本 ADR 取代）、ADR-0010 §2/§3、ADR-0018（manifest 1.3 的 `operations[].reachability`）、ARCH §4.1.1

## 背景

会切断管理通道的操作——改 SSH 端口或登录方式、改防火墙、改面板端口、换 TLS 证书——一旦出错会把用户锁在服务器外，而 1C1G 的用户往往没有 VNC 控制台。ADR-0009 第 3 条与 ARCH §4.1.1 原规定这类操作统一走"应用 → 倒计时确认 → 超时自动回滚"（默认 120 秒，只接受真人会话确认，AI 委托令牌不能确认）。

2026-11-08 用户决定不做倒计时确认：前端与 API 都不实现，可达性动作并入普通审批分级——"看用户给的权限即可"；宿主只保留一条下限规则：这类动作的定级不得低于 `ai_confirm`、风险不得低于 `high`。本 ADR 取代 ADR-0009 第 3 条与 ARCH §4.1.1，并删除 ADR-0010 中 full 模式的"可达性硬保护"例外。

## 决策

1. **R1 下限（目录加载时钳制）**：`reachability=true` 的动作进入动作目录时，`approval` 不低于 `ai_confirm`、`risk` 不低于 `high`；更严的声明原样保留，严格序为 `auto < ai_confirm < confirm`（`confirm` 对人也问，比 `ai_confirm` 严），钳制只把 `auto`（或宿主动作的空级别）提到 `ai_confirm`。插件只能声明更高，不能降低。钳制在宿主侧（`internal/catalog` 加载时）执行，与 manifest schema 的安装时校验（ADR-0018 决策 4）是两层互不替代：schema 拒绝作者漏标/错标的写法，宿主钳制兜底强制置真的操作。
2. **R2 能力名强制置真**：`effect ≠ read` 且 `required_capabilities` 命中可达性能力清单的插件操作，即使 manifest 未声明 `reachability` 也在目录加载时置真，再套用 R1 下限。清单是 `internal/operations/action.go` 的 `ReachabilityCapabilityPrefixes`：`system.firewall`、`system.sshd`、`system.account`、`system.ban`、`system.network`、`system.panel`、`system.tls`，按前缀加点边界匹配（名字等于前缀，或以 `前缀.` 开头）；判定由 `operations.ForcedReachability(effect, caps)` 给出，目录加载处（`catalog.SetPlugin`）接线。账户/封禁能力依据已批准的 ADR-0019 决策 5，于 CAP-11 纳入；新能力名不会自动进入清单。
3. **R3 宿主动作声明**：宿主自己的可达性动作在 OpenAPI 的操作上用扩展 `x-qwq-reachability: true` 声明（只允许 `effect` 为 `write`/`destructive` 且 `risk: high`）；宿主动作没有能力清单可查，声明即置真。当前没有宿主动作带此标记。
4. **R4 透出**：置真结果出现在 `ActionMeta.reachability`、审批 facts（`facts.action`）与上传包预检（`PluginPackageInspection.operations[]`），界面据此显示"可能导致无法连接服务器"。
5. **R5 执行语义（无硬保护）**：没有倒计时确认，也没有 full 模式的额外硬保护；定级之后按普通规则执行：
   - AI 在 safe 模式：`ai_confirm` 与 `high` 都进审批（`AWAITING_APPROVAL`）；
   - AI 在 full 模式：按授权直接执行（宿主动作 `host.*` 有效风险 ≥ high 时在 full 下仍须审批，不受本 ADR 影响）；
   - 人在界面操作：按高风险确认（`risk=high` 走既有确认卡流程）。

## 后果

- ADR-0009 第 3 条改写为指向本 ADR，防自锁的配套规则（保留当前 SSH/面板端口、新端口先验证、没有可用密钥不关密码登录）保留，但不再依赖倒计时回滚；ARCH §4.1.1 同步。
- ADR-0010 §2 的 full 模式行与 §3 不再提"可达性硬保护"。
- P6 安全插件（`security.basic`）在 manifest 里如实声明 `reachability`；漏报由 R2 兜底，误报只是更严的审批，无安全损失。
- 插件更新时 `reachability` 是包内 manifest 的一部分，随已验签内容生效，无需新表、无迁移。

## 未采用

- **倒计时确认（应用 → 确认 → 超时回滚）**：用户 2026-11-08 决定不做。120 秒交互与回滚状态机复杂度高，而普通审批分级（高风险确认 + `ai_confirm`）已覆盖"AI 不能悄悄改可达性"这一目标。
- **full 模式的"可达性硬保护"例外**：用户选择"full 模式按授权直接执行"，保留例外会让 full 模式的语义自相矛盾。
- **只靠能力名置真、不看 manifest 声明**：能力名是宿主名单，作者的真实意图只有 manifest 知道；两层并存，误报与漏报各有兜底。
