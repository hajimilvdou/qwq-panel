# ADR-0021：基础防护插件 `security.basic`

- 状态：Accepted（2026-11-13 用户批准全部待批准项;由 p6-sec 轨道实施）
- 日期：2026-11-13
- 关联：ADR-0009（安全规则根）、ADR-0019（firewall/sshd/account/ban 能力服务）、ADR-0016（可达性审批分级）、ADR-0018（manifest 1.3，p2-b）、ADR-0014（permission 命名）、ADR-0007（ABI 冻结）、ADR-0012/0013（运行时/token）；ARCH §4.1.1、§5.4、§5.6、§10
- 编号：0021（0019 能力服务、0020 监控;0022 core.xray、0023 proxy.advanced、0024 动态 HTTP 端点已预留，额外 ADR 从 0025 起）

## 背景

`security.basic` 是首版两个业务插件之一，`placement=node`、内置，不进宿主（ADR-0009）。范围：防火墙、登录防爆破、修改 SSH 端口、修改登录方式（密码/密钥/root）、SSH 密钥管理、系统用户密码修改。所有系统操作经 ADR-0019 的四个能力服务执行：**插件编排业务逻辑与状态机，宿主提供受控原语并强制防自锁**。

硬约束（ADR-0009）：1C1G 用户往往没有 VNC，改 SSH/防火墙出错会把用户锁在服务器外。测试机实测：sshd 取第一个 Include 值（`50-cloud-init.conf` 覆盖主配置）、SSH 由 `ssh.socket` 套接字激活（改端口要 `daemon-reload` + 重启 `ssh.socket`）、机器上常已有宝塔/ufw/fail2ban 另一个管理者。本 ADR 把 ADR-0009 的八条安全规则落到可实现的精度。

## 决策 1：插件形态与能力授予

- `placement=node`、`publisher.id=qwq-builtin`、`lifecycle.background=true`（防爆破扫描定时器在 `Activate` 后启动）、`update_strategy=auto`、`overlap_safe=true`。
- manifest 能力（`name`+`scope`，scope 约定见 ADR-0019 决策 4）：

| capability | scope | 用途 |
|---|---|---|
| `system.firewall.manage` | `self` | qwq 自有 nftables 表 |
| `system.sshd.configure` | `self` | qwq 自有 sshd drop-in |
| `system.account.keys` | `all` | 所有系统用户的 authorized_keys |
| `system.account.password` | `all` | 所有系统用户的密码 |
| `system.ban.manage` | `self` | 登录防爆破封禁集合 |
| `state.kv.read` / `state.kv.write` | `self` | 防爆破策略/扫描游标/接管状态/白名单 |
| `events.publish` | `security` | 封禁/接管/加固告警事件（可选） |

- 所有写 operation `risk=high`（`system.*` 经 `capabilityFloor` 自动抬升）、`reachability=true`（ADR-0016 R1 钳制 `approval≥ai_confirm`）。permission 资源段=插件 id：`security.basic:read` / `security.basic:write`（ADR-0014）。
- 安装向导把 `system.account.*:all`、`system.firewall.manage` 等列为高敏授权，逐项展示（ARCH §5.5）。

## 决策 2：operation 目录与小组件

读操作（`mode=invoke`、`effect=read`、`risk=low`、`permission=security.basic:read`，不写 operations 表，引用 p2-b 步骤 10 读豁免）：

| operation | 能力调用 | 用途 |
|---|---|---|
| `security.overview` | firewall/sshd/ban/keys 状态聚合 | 综合体检（checks 小组件） |
| `security.firewall.status` | `firewall.GetRuleset`+`DetectManagers` | 防火墙状态 |
| `security.sshd.status` | `sshd.GetEffectiveConfig`+`GetDropIn` | SSH 有效配置（含来源/覆盖） |
| `security.keys.list` | `account.ListKeys(user)` | 按用户列密钥 |
| `security.ban.status` | `ban.ListBans`+fail2ban 检测 | 封禁状态 |
| `security.ban.count` | `ban.ListBans` | 当前封禁数（stat 小组件） |
| `security.coexist` | `firewall.DetectManagers` | 共存管理者 |

写操作（`risk=high`、`reachability=true`、`permission=security.basic:write`，必须带 dispatched operation_id）：

| operation | mode | effect | plannable | 能力调用 |
|---|---|---|---|---|
| `security.firewall.apply` | invoke | write | ✓ | `firewall.ApplyRuleset` |
| `security.firewall.reset` | invoke | destructive | ✓ | `firewall.ResetRuleset` |
| `security.sshd.set_port` | job | write | ✓ | `sshd.SetPort`+`VerifyPort`+`firewall.ApplyRuleset`（saga，决策 5） |
| `security.sshd.set_login` | invoke | write | ✓ | `sshd.SetLoginPolicy` |
| `security.keys.import` | invoke | write | ✓ | `account.ImportKey` |
| `security.keys.remove` | invoke | write | ✓ | `account.RemoveKey` |
| `security.keys.generate` | invoke | write | — | `account.GenerateKey`（服务器 fallback） |
| `security.password.set` | invoke | write | — | `account.SetPassword` |
| `security.ban.configure` | invoke | write | ✓ | 设策略+启停扫描（KV+定时器） |
| `security.ban.add` | invoke | write | — | `ban.ApplyBans` |
| `security.ban.remove` | invoke | write | — | `ban.RemoveBan` |
| `security.takeover` | job | write | ✓ | 接管共存管理者（决策 10） |
| `security.harden` | job | write | ✓ | 一键加固（决策 11） |

小组件（`ui.widgets[]`，manifest 1.3，空 payload 轮询，结果形状与 ADR-0020/Shell 约定对齐）：

| id | kind | operation | refresh_seconds | size |
|---|---|---|---|---|
| `security` | checks | `security.overview` | 10 | m |
| `bans` | stat | `security.ban.count` | 5 | s |

- `security.overview` 的 checks 形状提案：`{checks:[{name:"防火墙",status:"ok|warn|crit",message?},{name:"防爆破",…},{name:"SSH 登录",…},{name:"密钥",…}]}`（待 Shell 约定确认）。
- `security.ban.count` 的 stat：`{value:<active_count>, unit:"个", label:"当前封禁"}`。

## 决策 3：防火墙（只动 qwq 自有表）

- 只操作 `inet qwq` 表（ADR-0019 决策 3.1），**不清空/不改写他表**。qwq 链 `policy accept`（**绝不**全局默认 drop，避免锁死），结构：

```nft
table inet qwq {
  set ssh_ports  { type inet_service; }
  set panel_ports{ type inet_service; }
  set ban_v4 { type ipv4_addr; flags timeout; }
  set ban_v6 { type ipv6_addr; flags timeout; }
  chain input {
    type filter hook input priority 0; policy accept;
    tcp dport @ssh_ports accept      # 强制保留 SSH（宿主注入）
    tcp dport @panel_ports accept    # 强制保留面板（宿主注入）
    ip saddr @ban_v4 drop            # 防爆破封禁
    ip6 saddr @ban_v6 drop
    # 用户自定义规则（允许端口/服务）
  }
}
```

- 保留端口集合 `ssh_ports`/`panel_ports` 由 forwarder 注入（当前 SSH 端口取自 sshd 有效配置，面板端口取自宿主配置）;`ApplyRuleset` 校验任何用户规则不得在保留端口 accept 之前 drop 它们，否则 `VALIDATION_FAILED`。
- 规则集以 `nft -j` JSON 表达，`ApplyRuleset` 先 `nft -j --check` 再原子替换 qwq 表;持久化 `/etc/nftables.d/qwq.nft`（不改主 `nftables.conf`）。
- 共存未接管时 `ApplyRuleset`/`ResetRuleset` 返回 `CONFLICT`（决策 10）。
- `security.firewall.apply` plannable：Plan 返回 before/after 规则集 + 保留端口 + description。

## 决策 4：登录防爆破（插件内置轻量封禁）

- 选定 ADR-0009 倾向：**插件内置**，从 journald 读 sshd 失败 + nftables 超时集合，常驻开销远小于 fail2ban（无常驻 root 进程，ADR-0019 决策 6）。
- 扫描循环（`Activate` 后定时器）：默认 `scan_interval=20s`（可配 10-60s），调 `ban.ScanAuthFailures(cursor, since_seconds, unit)`;`cursor` 存 KV，增量读。
- 策略（KV，`security.ban.configure` 设置，plannable）：

```jsonc
{
  "enabled": true,
  "window_seconds": 600,      // 统计窗口
  "max_failures": 5,          // 窗口内阈值
  "ban_ttl_seconds": 3600,    // 封禁时长（nft timeout）
  "whitelist": ["192.0.2.10"],// 用户白名单（宿主另注入当前会话 IP）
  "scan_interval_ms": 20000
}
```

- 判定：按 IP 聚合窗口内失败次数 ≥ `max_failures` → `ban.ApplyBans([{ip, ttl_seconds}])`。nft 集合 `flags timeout` 自动过期，**无需解封定时器**。
- 防自锁：forwarder 强制排除当前管理会话来源 IP + 白名单（ADR-0019 决策 3.4），插件无法封禁它们。
- 集合上限 4096（1C1G）;超限按最早过期淘汰。
- 共存 fail2ban：检测到 active fail2ban `sshd` jail → 只读展示其状态，**不启用 qwq 封禁**（避免双套）;用户显式接管后才启用（决策 10）。
- 封禁时可选 publish `security.ban` 事件（`events.publish:security`）。
- 资源：扫描限频（hostsvc 每实例 `ban.scan` 每分钟 ≤ 6）;策略/游标 KV < 128 KiB。

## 决策 5：SSH 端口修改 saga（双端口，验证后摘旧）

`security.sshd.set_port`（`mode=job`、`reachability=true`、plannable）。状态机（每步 `JobProgress.step_index/step_count` + `ResourceChange`）：

1. **预检**：`sshd.GetEffectiveConfig` 取当前 `Port` 列表;校验 `new_port`（1-65535、≠面板端口、≠已用端口）；快照当前 `00-qwq.conf` revision。
2. **先放行新端口**：`firewall.ApplyRuleset` 把 `new_port` 加入允许/保留（确保防火墙先放行）。
3. **双端口监听**：`sshd.SetPort(new_port)` 把新端口**加入** `00-qwq.conf` 的 `Port`（保留旧端口）→ `sshd -t` → `daemon-reload` + `restart ssh.socket`（socket 激活，ADR-0009）。
4. **验证新端口**：`sshd.VerifyPort(new_port)`（宿主回环 TCP + SSH banner，ADR-0019 决策 3.2）。**失败 → 回滚**（恢复 `00-qwq.conf` 快照、reload、撤防火墙新端口），job `FAILED`，提示"检查云厂商安全组是否放行新端口"。
5. **摘旧端口**：验证成功后 `sshd.SetPort(only new_port)`（只留新端口）→ `sshd -t` → reload `ssh.socket`。
6. **收尾验证**：`VerifyPort(new_port)` 仍可达;更新防火墙保留端口为 `new_port`。
7. **完成**：job `SUCCEEDED`，明确提示用户"云厂商安全组需放行 new_port，面板无法代改"。

- 防自锁：全程至少保留一个可达 SSH 端口（旧端口直到第 4 步验证成功才摘）;防火墙始终保留可达 SSH 端口。
- 回滚：任一步失败恢复 `00-qwq.conf` 到 saga 前快照（`expected_revision`）+ reload;幂等（`operation_id, attempt`）。
- 验证方式落点：回环 TCP + SSH 版本横幅（`SSH-2.0-…`）即判 sshd 监听正确;外部可达性另需云安全组（面板提示，不代改）。

## 决策 6：登录方式（密码/密钥/root）

- `security.sshd.set_login`（invoke/write/reachability/plannable）：写 `PasswordAuthentication`/`PermitRootLogin` 到 `00-qwq.conf`（ADR-0019 决策 3.2）。
- 读状态用 `sshd -T`（必要时 `-C user=…,addr=…`），返回每个设置的来源文件与 `overridden_by`（ADR-0009 规则 1，界面提示"被其他文件覆盖"）。
- **防自锁前置**：关密码登录或禁 root 前，目标用户必须有可用已授权密钥（`account.ListKeys` 非空 + sshd 有效配置允许公钥登录）;否则 `PRECONDITION_FAILED`（ADR-0009 规则 3）。
- 写前 `sshd -t`，失败不应用（规则 2）;只写 `00-qwq.conf`，不改主配置/其他 drop-in。
- Plan：before/after 取 `sshd -T` 当前值 vs 目标值 + description + preconditions（密钥可用性）。

## 决策 7：密钥管理

- 列出：`security.keys.list(user)` → `account.ListKeys`：类型/位数/SHA256 指纹/注释/行号。
- 导入：`security.keys.import(user, public_key)` → `account.ImportKey`：校验格式/类型，**拒 DSA 与 RSA<3072**（ADR-0009 规则 5），接受 Ed25519/ECDSA/RSA≥3072;保持 `authorized_keys` 0600/属主;重复指纹幂等。
- 删除：`security.keys.remove(user, fingerprint)` → `account.RemoveKey`：**防自锁**——最后一把密钥且密码登录关闭 → 拒绝（规则 4）。
- 生成（规则 5）：
  - **默认浏览器 WebCrypto**：前端用 `crypto.subtle.generateKey("Ed25519")` 生成密钥对，导出公钥（OpenSSH 格式）经 `security.keys.import` 上传；**私钥永不离开浏览器**（可选下载 `.pem`）。服务器不见私钥。
  - **服务器 fallback**：`security.keys.generate(user, type=ed25519)` → `account.GenerateKey`，私钥 PEM **只返回一次**，前端立即下载/展示;helper 不落盘/日志/事件/审计（ADR-0019 决策 3.3）。
- 按系统用户分别管理 `~<user>/.ssh/authorized_keys`。

## 决策 8：系统用户密码（secret 引用 + chpasswd）

- `security.password.set(user, password)`（invoke/write/reachability）。
- **入口（宿主前置改动）**：operation request schema 的 `password` 字段标 `writeOnly:true`/`x-secret:true`;宿主 operation dispatch 路径调 `secrets.ExtractSecrets`（复用 config 提取机制，owner=`plugins/security.basic`、purpose=`plugin.operation`）把明文替换为 `password_secret_ref` 再派发插件。**当前提取只用于 plugin config（openapi `PUT config`），operation payload 提取是新增宿主能力**，列入拆解前置卡。
- 插件收 `{user, password_secret_ref}` → `account.SetPassword(user, secret_ref)`。
- **reveal 在宿主侧**（ADR-0019 决策 3.3）：forwarder 以 owner+purpose 绑定 + operation 派发校验直接解密（复用 `hostSecretRevealer`），插件不见明文、无需 `secret.reveal` 能力;明文经 helper stdin 给 `chpasswd`，不入 argv/日志/事件/审计/配置历史。
- 强度检查在 forwarder（长度/复杂度，可配;弱密码 `VALIDATION_FAILED`）。
- purpose `plugin.operation` 与 core.xray 的 `RevealOwned`（owner+purpose 绑定）共享 `hostSecretRevealer` 接缝，需协调接受该 purpose（边界登记）。

## 决策 9：防自锁规则逐条（宿主双层强制）

| # | 规则 | 强制点 |
|---|---|---|
| 1 | 防火墙任何规则集强制保留当前 SSH 端口 + 面板端口 | forwarder 注入保留端口 + helper 校验 |
| 2 | 改 SSH 端口：先放行→双端口→回环验证→摘旧;全程至少一个可达 SSH 端口 | 插件 saga + helper `VerifyPort` |
| 3 | 关密码登录/禁 root：目标用户无可用密钥 → 拒绝 | forwarder 前置（读 keys + sshd 有效配置） |
| 4 | 删最后一把密钥且密码登录关闭 → 拒绝 | helper `account.RemoveKey` 前置 |
| 5 | 封禁名单永不含当前管理会话来源 IP + 白名单 | forwarder 注入 + helper 校验 |
| 6 | 共存管理者未接管 → 防火墙/封禁只读，写返回 `CONFLICT` | forwarder 接管状态门 |
| 7 | 可达性写操作 `reachability=true` → `approval≥ai_confirm`、`risk=high` | 目录加载钳制（ADR-0016） |

这些前置在**宿主能力门/forwarder 与 helper 双层**强制，插件（不可信）不能绕过;插件 saga 是业务编排，不是安全边界。

## 决策 10：共存检测与显式接管

- 检测（`firewall.DetectManagers` + 插件补充，只读）：

| 管理者 | 探测 |
|---|---|
| ufw | `systemctl is-active ufw` + `ufw status` |
| firewalld | `systemctl is-active firewalld` |
| 宝塔 | `/www/server/panel` 存在 + `bt` 进程 |
| 1Panel | `/opt/1panel` 存在 + `1panel` 进程 |
| fail2ban | `systemctl is-active fail2ban` + `fail2ban-client status sshd` |

- 默认**只读展示**各管理者状态（ADR-0009 规则 8）。
- 接管（`security.takeover`，job/write/reachability/plannable）：
  - Plan 确认卡片**逐项列出**：检测到哪些管理者、qwq 将接管什么、建议停用哪些冲突服务。
  - 用户显式选择"由 qwq 接管"后才写入。
  - **防火墙接管**：qwq 写自己的 `inet qwq` 表;不主动停 ufw/firewalld（避免破坏别人），而是提示用户停用冲突管理者，由用户决定;接管状态存 KV。
  - **fail2ban 接管**：用户确认后停用 fail2ban `sshd` jail（`fail2ban-client stop sshd` 或 `systemctl stop fail2ban`），启用 qwq 防爆破。**需扩展 helper systemctl/命令白名单**允许接管时停 fail2ban/ufw/firewalld（当前白名单只允许 `qwq-plugin@` 单元）——列入待批准。
  - 不同时运行两套封禁（规则 8）;接管可逆（可交还，恢复原管理者）。
  - 接管全程审计。

## 决策 11：一键加固（intent-level job）

- `security.harden`（`mode=job`、write/reachability/plannable，ADR-0009 规则 7）。
- 确认卡片**逐项列出将要改变的内容**（来自 Plan 的 `PlannedChange.description`，按不可信文本显示"来自插件"）。
- 加固项（用户勾选，默认建议）：
  1. 启用防爆破（决策 4 策略）
  2. 关密码登录（前提：目标用户有密钥，否则 skipped + 原因）
  3. 禁 root 密码登录（`PermitRootLogin prohibit-password`，前提同上）
  4. 防火墙保留 SSH/面板 + 收紧其他入站（可选）
  5. 改 SSH 端口（可选，默认跳过;若选则走决策 5 saga）
- Plan 返回每项 before/after + description + preconditions;不满足前置的项标 `skipped` + 原因，不强行执行。
- job 逐项执行，每步 progress + ResourceChange;**逐项独立**，某项失败不回滚已成功项，终止消息报告每项结果（succeeded/skipped/failed）。
- 防自锁规则（决策 9）全程生效;`reachability=true` 使整 job 进 `AWAITING_APPROVAL`（AI safe）或高风险确认（人）。

## 决策 12：资源预算与生命周期

- `memory_max_mb=32` → `GOMEMLIMIT≈27MiB`、`MemoryHigh≈28M`;`cpu_quota_percent=5`、`pids_max=8`、`fds_max=64`、`disk_max_mb=16`、`kv_max_kb=128`（策略/游标/接管状态/白名单）。
- `background=true`：防爆破扫描定时器 `Activate` 后启动、`Deactivate` 停（两代不双跑）。
- ban 集合 ≤ 4096（内核内存数百 KiB）;扫描 20s 增量；无常驻 root 进程（ADR-0019）。
- 更新 `overlap_safe=true`：策略在 KV（持久），扫描定时器随 Activate 切换;蓝绿短暂双跑 2×32M，preflight 通过，紧张时降级受控重启。

## 决策 13：manifest 与 config 要点

- `schema_version=1.3`；`ui.entry=ui/index.html`、`sandbox=true`、`connect_sources=[]`;`ui.routes` 含 `/security`（nav，`security.basic:read`）;`ui.widgets` 见决策 2。
- config schema（hot_apply）：防爆破策略默认值（决策 4）、白名单、加固默认勾选项、密码强度下限。`ValidateConfig` 校验范围;`ApplyConfig` 热调整策略/白名单（扫描定时器按新间隔重设）。
- `state.backup_paths=[]`：策略存 KV，不请求宿主 DataDir（边界登记）。
- 写操作 request/response schema 落 `schemas/`;`security.password.set` 的 `password` 标 `x-secret`。

## 测试纪律（ADR-0009）

- **构建机单测**：fake capability forwarder（firewall/sshd/account/ban）测端口 saga/防自锁每条/防爆破策略/接管/加固逐项;fake `OperationResolver`/secret reveal;operation payload x-secret 提取用 fake `secrets.Store`;nft 规则集校验用 fake runner。
- **nftables**：独立 netns 测 qwq 表/保留端口/超时集合/封禁排除白名单。
- **sshd**：独立配置 + 回环端口实例测改端口 saga/改登录方式/`sshd -t`/回滚/`VerifyPort`。
- **账户**：临时家目录测 authorized_keys 权限/属主/最后一把密钥拒绝;chpasswd 用 fake runner 校验 stdin 传递与"密码不入 argv/日志"。
- **真实系统集成**（改真实 sshd/防火墙/接管/加固端到端）：标注"**测试机执行，届时先经用户确认**"，需 VNC 控制台可用且发起人在场;本设计不安排碰测试机真实 SSH/防火墙。

## 已批准项（2026-11-13 用户批准）

1. **operation payload `x-secret` 提取**（宿主前置，复用 `secrets.ExtractSecrets`，purpose `plugin.operation`）。
2. **helper 命令白名单扩展**：接管时允许停 fail2ban/ufw/firewalld（当前只允许 `qwq-plugin@` 单元）。
3. **`ReachabilityCapabilityPrefixes` 补 `system.account`/`system.ban`**（跨 p2-b 轨道，ADR-0019 决策 5）。
4. **账户能力 scope 保留字 `all`**（ADR-0019 决策 4，无需改 schema）。
5. **共存接管策略**：qwq 不主动停别人服务，用户逐项确认;fail2ban 接管需停 jail。
6. **服务器生成密钥 fallback**（默认浏览器 WebCrypto）。
7. **purpose `plugin.operation`** 与 core.xray `RevealOwned` 协调。

## 边界登记（core.xray，只读参考）

- **RevealOwned**：core.xray 把 `hostSecretRevealer` 收紧为 owner=`plugins/<plugin_id>`+purpose 绑定。本插件密码 reveal 走同一宿主侧接缝，purpose 用 `plugin.operation`（区别于 config 的 `plugin.config`），需 core.xray 的 revealer 接受该 purpose;两者都不改 ABI/请求字段。
- **DataDir**：core.xray 用 `state.backup_paths` 非空触发宿主 DataDir 供给。`security.basic` 策略存 KV、`backup_paths=[]`、`DataDir=""`，不请求持久目录。
- **network.proxy:direct**：core.xray 的精确网络放宽与本插件 `system.*` 能力无交集;security.basic 不请求网络放宽（防爆破读 journald 经 helper，不经插件网络）。

## 代价

- 端口/接管/加固三个 saga + 防自锁双层校验，复杂度集中在宿主 forwarder 与 helper。
- 宿主前置改动（operation secret 提取、helper 白名单扩展）需先落地。
- 共存检测/接管增加工作量，但不做就会与宝塔等互相覆盖规则（ADR-0009）。
- 一键加固逐项独立执行，失败语义需清晰报告（不回滚已成功项）。