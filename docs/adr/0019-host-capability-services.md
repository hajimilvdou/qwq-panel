# ADR-0019：Host Capability 服务（firewall / sshd / account / ban）

- 状态：Accepted（2026-11-13 用户批准全部待批准项;由 p6-cap 轨道实施）
- 日期：2026-11-13
- 关联：ADR-0007"本次不改"（高敏能力不进 Platform ABI v1）、ADR-0009（首版插件范围与安全规则）、ADR-0012（root 拥有运行时布局）、ADR-0013（插件 token 校验）、ADR-0014（permission 命名）、ADR-0016（可达性审批分级）、ADR-0018（manifest 1.3，p2-b 轨道）；ARCH §5.4、§5.6、§10.2、§10.3
- 编号：0018 已被 p2-b 占用，本 ADR 用 0019;监控插件 0020、防护插件 0021。

## 背景

首版两个业务插件（`monitor.basic`、`security.basic`）都是 `placement=node` 的普通插件，不进宿主（ADR-0009）。防护插件要改防火墙、sshd、系统账户与封禁集合，这些是 ADR-0007 明确"本次不改"的高敏宿主能力：它们是独立、版本化的 Host Capability 服务，随第一个需要它们的插件（P6）设计。

现有两个组件的沙箱都挡死了这些操作，必须经一条受控链路：

- **插件单元**（`internal/sandbox/templates/qwq-plugin@.service`）：`DynamicUser=yes`、`PrivateNetwork=yes`、`RestrictAddressFamilies=AF_UNIX`、`ProtectSystem=strict`、`ProtectKernelLogs=yes`、`CapabilityBoundingSet=`（空）、`SystemCallFilter=@system-service ~@privileged @resources`。插件无法执行 `nft`/`sshd`/`chpasswd`，无法读 journald，无法做 TCP 连接，只能经 `AF_UNIX` 连自己的 host 通道。
- **安装 helper**（`cmd/qwq-privileged`，`deployments/systemd/qwq-privileged.service`）：socket 激活、一请求一激活即退出、root、`PrivateNetwork=yes`、`AF_UNIX`、`ProtectKernelLogs=yes`、`CapabilityBoundingSet=CAP_CHOWN CAP_DAC_OVERRIDE CAP_SETGID CAP_SETUID`。只跑白名单 `systemctl`（daemon-reload/show/enable/disable，限 `qwq-plugin@<id>` 单元）与 shadow 工具（groupadd/groupdel/getent，限 `qwq-p-<id>` 组）。它**没有** `CAP_NET_ADMIN`、不在宿主 netns、不能读 journald，因此现状无法承担防火墙/sshd/账户/封禁。

 host 通道是每插件私有的 UDS：`/run/qwq/host/<id>/host.sock`（0660，组 `qwq-p-<id>`），经 `BindPaths` 映射到插件的 `%t/qwq/link/host.sock`。`internal/pluginhost/hostsvc.Server` 在其上注册六个 Host 服务，拦截器 `prepareCall` 已做：`SO_PEERCRED`（+ 可选 `SO_PEERPIDFD`）内核身份、`PeerVerifier.Verify(pid,uid)`（cgroup 单元 + uid）、插件 token（metadata `qwq-plugin-token` 的 SHA-256 常量时间比对，ADR-0013）、每实例在途上限、deadline 钳制。SDK 的 `Host` 客户端（`sdk/pluginsdk/host.go`）持有这条 conn 与 `instance_handle`，token 由 conn 的 `PerRPCCredentials` 自动附带（`sdk/pluginsdk/systemd.go`）。

本 ADR 定清：插件如何在不改冻结 ABI 的前提下调用能力、root 执行形态、四个服务的方法/schema/错误码/capability/风险下限，以及 1C1G 预算与测试纪律。

## 决策 1：能力传输形态——每插件 UDS 上挂独立 gRPC 服务（选定）

### 候选评估

| 候选 | 说明 | 结论 |
|---|---|---|
| A. 复用每插件 host UDS，注册独立 capability gRPC 服务 | 四个 `qwq.capability.<name>.v1` 服务与六个 Host 服务挂在同一条 `host.sock` 上 | **选定** |
| B. 每能力一条独立 UDS | 每个能力服务各开 socket，各做身份校验 | 拒绝：重复 `SO_PEERCRED`/token/目录/socket 激活逻辑，徒增攻击面与 fd 预算，无收益 |
| C. 把能力 RPC 追加进 `platform.proto` | 进 Platform ABI v1 | 拒绝：违反 ADR-0007 冻结（高敏能力明确不进 v1），且把业务绑死在 ABI 版本上 |
| D. 通用 `Exec`/`ReadFile`/`HTTPRequest` 原语 | 插件传命令/路径，宿主执行 | 拒绝：ARCH §5.4 明令禁止，等于放弃白名单与参数 schema |

选 A 的理由：

1. **零 ABI 改动**：能力是独立 proto package，`platform.proto` 一字不动，`buf breaking` 不受影响。
2. **复用既有信任链**：能力 RPC 与 Host RPC 走同一条 conn，自动经过 `prepareCall` 的 `SO_PEERCRED` + `PeerVerifier` + token + 在途上限 + deadline。能力门只需在此之上再加"capability + operation + scope"绑定（决策 4），不重造身份层。
3. **复用 SDK conn**：token 已挂在 conn 的 `PerRPCCredentials` 上，能力客户端复用同一 conn 即自动携带 token 与 `instance_handle`，无需新认证。
4. **独立版本化**：每个能力 package 自带 `v1`，可独立追加字段/RPC，互不牵连，也不牵连 ABI minor。

### proto 与生成布局

- 文件：`api/qwq/capability/<name>/v1/<name>.proto`，`<name> ∈ {firewall, sshd, account, ban}`。
- package：`qwq.capability.<name>.v1`（满足 buf `PACKAGE_DIRECTORY_MATCH`，模块根 `api/`）。
- 生成：`sdk/gen/qwq/capability/<name>/v1/`（`buf.gen.yaml` managed mode，`go_package_prefix=github.com/qwq-panel/qwq/sdk/gen`，`paths=source_relative`）。与 `sdk/gen` 其余代码同为 Apache-2.0，插件作者无需装 buf。
- lint：buf STANDARD；breaking：`FILE` 对新文件无历史对照，能力 package 各自冻结后只追加（与 ADR-0007 同规则，但**不**计入 `sdk/abi.Minor`）。
- 每个服务消息携带 `qwq.platform.v1.HostCallContext context = 1;`（import `qwq/platform/v1/platform.proto`，只复用 `HostCallContext`/`ErrorDetail`/`FieldViolation`/`Precondition` 这几个稳定消息，不引入新 ABI 依赖）。错误约定与 ABI 一致：gRPC 状态码表示传输/宿主侧失败（`UNAVAILABLE`/`PERMISSION_DENIED`/`UNAUTHENTICATED`/`RESOURCE_EXHAUSTED`/`UNIMPLEMENTED`），到达 handler 后的业务结果用 `ErrorDetail.code`（gRPC OK）。

### 注册与可见性

- `hostsvc.Server.New` 在注册六个 Host 服务后，**按授予的 capability 选择性注册**四个能力服务：插件 manifest 未声明某能力，则不注册对应服务，插件调用得 `UNIMPLEMENTED`（纵深防御：即便插件猜到方法名也无法触达未授予的能力）。
- 能力服务 handler 全部经现有 `unaryInterceptor`/`streamInterceptor`（无流式能力 RPC，全部 unary），再经能力门（决策 4）。

### SDK 侧

- `sdk/pluginsdk` 暴露 host conn 与上下文构造：新增 `Host.Conn() grpc.ClientConnInterface` 与 `Host.CapabilityContext(ctx) (*platformv1.HostCallContext, error)`（复用现有 `callContext`，自动填 `instance_handle`/`operation_id`/`trace_id`，写操作在 `PlanOperation` 期间拒绝 `PLAN_SIDE_EFFECT`）。
- 插件用生成的 `qwqcapability<name>v1.New<Name>ServiceClient(host.Conn())` 调用，每次填 `CapabilityContext`。token 由 conn 自动附带，插件无需感知。
- 能力客户端是 SDK 的薄封装，可选提供 `pluginsdk.Capability[Client]` 泛型助手减少样板;首版直接暴露 conn 即可。

## 决策 2：root 执行形态——独立 socket 激活能力 helper `qwq-capability`（选定）

### 候选评估

| 候选 | 说明 | 结论 |
|---|---|---|
| A. 扩展 `qwq-privileged` 新 verb | 在安装 helper 上加 firewall/sshd/account/ban verb | 拒绝：必须给安装 helper 加 `CAP_NET_ADMIN`、宿主 netns（`PrivateNetwork=no`）、`AF_NETLINK`、journald 读、`nft`/`sshd`/`chpasswd` 白名单，**污染其已审查的最小沙箱**;安装 helper 同时写插件单元，能力 bug 会危及安装路径 |
| B. 常驻 root 能力守护 | 一个长期运行的 root 进程持有 nft/journald 状态 | 拒绝：永久 root 进程违反"空闲主机无 root 服务"（`qwq-privileged` 设计核心），常驻 RSS 与 fail2ban 相当甚至更高，违背 ADR-0009 低开销目标 |
| C. 独立 socket 激活能力 helper `qwq-capability` | 新二进制 + 新单元/socket，专用沙箱，一请求一激活 | **选定** |

选 C 的理由：

1. **沙箱隔离**：能力 helper 的宽沙箱（宿主 netns、`CAP_NET_ADMIN`、journald）与安装 helper 的最小沙箱物理分离。安装 helper 一字不改，其既有安全性质与测试全部保留。
2. **空闲无 root 进程**：socket 激活，一请求一激活即退出，`systemctl is-active qwq-capability.service` 在请求间为 inactive，只有 socket 单元 active。与安装 helper 同philosophy。
3. **复用成熟模式**：复用 `internal/sandbox` 的 helper JSON/UDS/socket 激活/`HelperClient` 重试/审计模式（独立 schema，见下），降低实现与审查成本。
4. **白名单不变**：无命令来自请求;每 verb 固定二进制 + 固定参数 schema + 路径前缀校验 + trusted `os.Root`（ADR-0012）。

### 二进制与协议

- 二进制：`cmd/qwq-capability`（Linux only，euid 0 才运行，复用 `qwq-privileged` 的 `run`/`listenSocket`/`activatedFDCount` 骨架）。
- socket：`/run/qwq/capability.sock`（`root:qwq 0660`，`SocketGroup=qwq`，`RemoveOnStop=yes`），由 `deployments/systemd/qwq-capability.socket` 监听;`/run/qwq` 已由 tmpfiles 创建（ADR-0012）。只有 qwq（agent/controller）能连，插件（DynamicUser）不能。
- 协议：每连接一个换行结尾 JSON 对象，`CapabilityRequest`/`CapabilityResponse`（独立于 `HelperRequest`，但复用 `ReadHelperJSON`/`WriteHelperJSON` 的 `DisallowUnknownFields` + 1 MiB 上限 + 单对象语义）。`CapabilityRequest{op, id, params_json, secret_base64?, cursor?}`;`op` 是白名单 verb;`params_json` 是该 verb 的强类型 schema;`secret_base64` 仅 `account.set-password` 携带（见决策 3.3）。
- 客户端：`internal/sandbox.CapabilityClient`（仿 `HelperClient`，只重试 connect，不重试已到达的请求;超时默认 30s）。hostsvc 的能力 forwarder 持有它。
- 一请求一激活;`maxConcurrentRequests=4` 上限;`RuntimeMaxSec=120` 硬顶;panic 转 JSON 错误（仿安装 helper）。

### 能力 helper 沙箱（宿主渲染，与安装 helper 不同）

`deployments/systemd/qwq-capability.service` 关键指令（**待批准**，需在测试机用 `systemd-analyze security` 与 strace 实测收敛）：

```
Type=exec
Restart=no
RuntimeMaxSec=120
MemoryMax=48M
Environment=GOMEMLIMIT=40MiB
Environment=GOMAXPROCS=2
TasksMax=24
UMask=0022

# 必须在宿主 netns：nftables 是 per-netns 状态，PrivateNetwork=yes 会改到私有 netns 而非宿主。
PrivateNetwork=no
RestrictAddressFamilies=AF_UNIX AF_NETLINK AF_INET AF_INET6
# 永不监听网络 socket;出站连接仅回环（sshd.verify-port），由 verb 参数白名单强制。

ProtectSystem=strict
# 精确写路径：sshd drop-in、qwq nft 持久化片段、账户 authorized_keys、shadow、运行时。
ReadWritePaths=/etc/ssh/sshd_config.d /etc/nftables.d /run/qwq /etc/shadow /etc/gshadow
# authorized_keys 按用户散在 /home 与 /root：用 BindPaths 或逐用户 ReadWritePaths，
# 由 verb 参数限定到目标用户家目录（trusted os.Root 校验属主/权限），不放开整个 /home。
ReadOnlyPaths=-/var/log/journal -/run/log/journal
ProtectKernelLogs=no          # 读 journald（ban.scan）;安装 helper 保持 yes
PrivateTmp=yes
PrivateDevices=yes
DevicePolicy=closed
ProtectHome=yes               # 经 ReadWritePaths/BindPaths 精确开目标用户 .ssh
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
ProtectProc=invisible
ProcSubset=pid
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
SystemCallArchitectures=native
SystemCallFilter=@system-service
SystemCallFilter=~@clock @module @raw-io @reboot @swap @resources
SystemCallFilter=~_sysctl acct bpf capset chroot fanotify_init fanotify_mark nfsservctl open_by_handle_at pivot_root quotactl quotactl_fd setdomainname setfsuid setfsuid32 setgroups setgroups32 sethostname setresuid setresuid32 setreuid setreuid32 setuid setuid32 vhangup
SystemCallErrorNumber=EPERM

# nft 需 CAP_NET_ADMIN;shadow/authorized_keys 需 DAC_OVERRIDE/CHOWN;chpasswd/PAM 需 SETUID/SETGID。
CapabilityBoundingSet=CAP_NET_ADMIN CAP_DAC_OVERRIDE CAP_CHOWN CAP_SETUID CAP_SETGID
AmbientCapabilities=
NoNewPrivileges=yes
KeyringMode=private
```

- `@system-service` 已含 `sendmsg`/`recvmsg`（nft 的 netlink 与回环 TCP 所需），无需放开 `@privileged`。`nft` 经 `AF_NETLINK`/`NETLINK_NETFILTER` 与内核通信，`CAP_NET_ADMIN` 在宿主 netns 生效。
- 二进制白名单（仿 `groupRunner`，每 verb 固定 name + 参数 schema，越界即拒）：`nft`、`sshd`、`ssh-keygen`、`chpasswd`、`journalctl`、`systemctl`（受限 args，见各服务）。**无通用 exec**。
- 审计：每 verb 写结构化 journald（不含 secret/私钥/密码），并经 hostsvc `AuditSink` 落库（actor/operation/subject/outcome）。helper 自身永不记 token、密码、私钥。
- 与安装 helper 的关系：两个独立 socket/单元/二进制，互不调用。hostsvc 按 verb 路由到 `capability.sock`;安装/卸载仍走 `privileged.sock`。

## 决策 3：四个能力服务

通用约定：

- 所有写操作 `effect≠read`、`risk=high`（`system.*` 经 `operations.capabilityFloor` 自动抬到 high）、`reachability=true`（ADR-0016 R1 钳制 `approval≥ai_confirm`）。读操作 `effect=read`、`risk=low`，不写 operations 表（引用 p2-b 步骤 10 的小组件/读路径豁免约定）。
- 写操作必须带当前派发给本实例的 `operation_id`（能力门校验，决策 4）;读操作只需 capability，不需 operation_id。
- 乐观并发：写操作携带 `expected_revision`（资源当前 revision），不符返回 `PRECONDITION_FAILED`;revision 由宿主对每个能力资源维护（如 `firewall/ruleset`、`sshd/dropin`、`account/<user>/keys`、`ban/set`）。
- 错误码（`ErrorDetail.code`，稳定、机器可读）：`VALIDATION_FAILED`（参数/schema/校验失败，附 `FieldViolation`）、`PRECONDITION_FAILED`（revision 不符/防自锁前置不满足）、`PERMISSION_DENIED`（capability/scope/operation 绑定不符）、`CONFLICT`（共存管理者未接管）、`RESOURCE_EXHAUSTED`（集合/配额超限）、`UNAVAILABLE`（底层工具失败）、`PORT_VERIFY_FAILED`（新端口验证失败）、`INTERNAL`。

### 3.1 firewall —— `qwq.capability.firewall.v1.FirewallService`

- capability：`system.firewall.manage`（scope 固定为 qwq 自有表，不接受任意表名）。
- 边界：**只操作 `inet qwq` 表及其链/集合**，不清空、不改写别人的表/链（ADR-0009 规则 2）。任何规则集强制保留当前 SSH 端口与面板端口——保留端口由**宿主注入**（hostsvc 从会话/配置得知），插件无法绕过。

| RPC | 请求 | 返回 | effect/风险 |
|---|---|---|---|
| `GetRuleset` | `{}` | `{ruleset_json, revision, preserved_ports[]}` | read/low |
| `ApplyRuleset` | `{ruleset_json, expected_revision, preserved_ports[]}` | `{revision}` | write/high，reachability |
| `ResetRuleset` | `{expected_revision}` | `{revision}` | destructive/high，reachability |
| `DetectManagers` | `{}` | `{managers[{kind, active, detail}]}` | read/low |

- `ruleset_json`：qwq input 链的 nft 输出 JSON（table/chain/rule 形态）。2026-11-14 实施收敛：仅接受首期闭合的端口、来源地址、lo、已建立连接及 accept/drop 子集；未知表达式一律拒绝。先 `nft -j --check -f -`，再在一个事务中按名称替换 `inet qwq input` 链，不删除整个表，保留同表的 ban 链/集合。强制保护规则总在用户规则之前。
- `preserved_ports`：宿主在 forwarder 处把当前 SSH 端口（取自 sshd 有效配置）与面板端口并入，插件声明的端口只能是超集;缺保留端口 → `VALIDATION_FAILED`。
- `DetectManagers`：检测 ufw/firewalld/宝塔/1Panel/fail2ban（详见 ADR-0021 共存检测），返回只读状态;未接管时 `ApplyRuleset` 返回 `CONFLICT`。
- helper verb：`firewall.get`（独立读取 tables/chains/本 input 链）、`firewall.apply`（原生 check + 原子 input 替换）、`firewall.reset`（只重置 input 链，保留 ban 状态）、`firewall.detect`（只读共存检测）。`firewall.restore` 仅恢复已保存策略，不接受新的规则或路径；无插件 RPC，开机无特权客户端经独立 root helper 请求恢复。
- 持久化：qwq input 策略规范化 JSON 写入 `/etc/nftables.d/qwq.nft`（root 0644），由 `qwq-firewall-restore.service` 在开机通过 helper 校验、编译后恢复，不直接交给 nft 当命令文件，不改 `/etc/nftables.conf`。跨进程锁及内容 revision 保护并发；执行/保存/核验失败回滚，无法确认恢复返回 `RECOVERY_REQUIRED`。Get 的 append-only `persistence_pending` 字段显示实时与持久状态差异。

- 保留端口还包括标准 SSH socket 单元的 Listen 和由标准 SSH service MainPID 绑定的 `ss -H -ltnp` 实际监听；仅按进程名称不能证明归属。管理端口在原生 check 后、写入前再次核验。非标准 SSH 管理布局无法核验时失败关闭，不猜测 22。`ss` 为新增只读白名单工具，无新权限。

### 3.2 sshd —— `qwq.capability.sshd.v1.SshdService`

- capability：`system.sshd.configure`。
- 边界：读有效配置用 `sshd -T`（必要时 `sshd -T -C user=…,addr=…`），标注每个设置来源文件并检测覆盖（ADR-0009 规则 1）;**只写 `/etc/ssh/sshd_config.d/00-qwq.conf`**（文件名排最前，qwq 拥有），不改主配置与其他 drop-in;写前 `sshd -t` 校验，失败不应用（规则 2）。

| RPC | 请求 | 返回 | effect/风险 |
|---|---|---|---|
| `GetEffectiveConfig` | `{match_user?, match_address?}` | `{settings[{key, value, source_file, overridden_by}], revision}` | read/low |
| `GetDropIn` | `{}` | `{content, revision, exists}` | read/low |
| `SetPort` | `{new_port, expected_revision, stage, transaction_ref?}` | `{revision, listening_ports[], transaction_ref}` | write/high，reachability |
| `VerifyPort` | `{port}` | `{reachable, banner}` | read/low |
| `SetLoginPolicy` | `{password_auth?, permit_root_login? / root_login_mode?, recovery_user?, expected_revision}` | `{revision, effective}` | write/high，reachability |
| `RemoveDropIn` | `{expected_revision, recovery_user?}` | `{revision}` | destructive/high，reachability |
| `RecoverDropIn` | `{expected_revision, transaction_ref, recovery_user?}` | `{revision, listening_ports[]}` | write/high，reachability |

- `SetPort` 是**双端口 saga 的显式一步**（完整状态机在 ADR-0021）：ADD_NEW 保留旧端口，COMMIT_NEW 在宿主锁内再次验证后摘旧，ROLLBACK 恢复本事务原始快照。未指定 stage 拒绝。事务引用绑定原派发 operation 和实例；Port 为累加项，先证明最终单端口可在自有范围生效。原生预检后核验版本；重载后的活动监听集合必须与候选完全一致，不能把仍存在旧端口报告为成功。
- 所有 SSH 写入使用 root 0700 持久事务目录 `/var/lib/qwq-capability`、0600 记录及共享跨进程锁。GetDropIn 的 append-only 字段显示 pending，详情仅返回原插件/实例。中断恢复使用独立 RecoverDropIn 写 RPC，仍须当前已授权 operation，只恢复同插件/实例的保存快照，不能提供任意文件内容或覆盖第三方修改；正常 SetPort 的原 operation 绑定不变。
- `VerifyPort`：**宿主侧**回环验证（插件 `PrivateNetwork=yes` 无法 TCP）。helper 在宿主 netns 内向 `127.0.0.1:<port>`/`::1:<port>` 发起 TCP，读取 SSH 版本横幅（`SSH-2.0-…`）即判可达;只连回环，端口由白名单校验（1-65535，排除面板端口冲突）。这是 ADR-0009"验证方式 P6 设计时定"的落点。
- `SetLoginPolicy`：写 `PasswordAuthentication`/`PermitRootLogin` 到 `00-qwq.conf`;**前置防自锁**——目标用户无可用已授权密钥时拒绝关密码登录/拒 root（`PRECONDITION_FAILED`，密钥状态经 account 服务读）;写前 `sshd -t`;返回生效后的 `sshd -T` 值。
- `GetEffectiveConfig` 的 `overridden_by`：当某 key 在主配置与更早 Include 的 drop-in 中重复，sshd 取第一个值;返回实际生效值与覆盖来源，界面据此提示"被其他文件覆盖"（ADR-0009 测试机实测的 `50-cloud-init.conf` 场景）。
- helper verb：`sshd.get-effective`（`sshd -T [-C …]` + 解析 Include 来源）、`sshd.get-dropin`、`sshd.write-dropin`（trusted `os.Root` 写 `00-qwq.conf`，root 0644）、`sshd.validate`（`sshd -t`）、`sshd.reload-socket`（`systemctl daemon-reload` + `systemctl restart ssh.socket`，白名单限这两个单元）、`sshd.verify-port`（回环 TCP + 横幅）。
- 文件：`/etc/ssh/sshd_config.d/00-qwq.conf`（root 0644）。

### 3.3 account —— `qwq.capability.account.v1.AccountService`

- capability：`system.account.keys:<user>`（密钥）与 `system.account.password:<user>`（密码），`<user>` 是 scope，必须匹配 RPC 的 `user` 参数（能力门校验，决策 4）。`user` 经 `userPattern`（`^[a-z_][a-z0-9_.-]{0,31}$`）校验，拒绝路径穿越。

密钥 RPC（capability `system.account.keys:<user>`）：

| RPC | 请求 | 返回 | effect/风险 |
|---|---|---|---|
| `ListKeys` | `{user}` | `{keys[{type, bits, fingerprint_sha256, comment, line_index}], revision}` | read/low |
| `ImportKey` | `{user, public_key, expected_revision}` | `{fingerprint_sha256, type, bits, comment, revision}` | write/high |
| `RemoveKey` | `{user, fingerprint_sha256, expected_revision}` | `{revision}` | write/high，reachability |
| `GenerateKey` | `{user, type, expected_revision}` | `{public_key, fingerprint_sha256, private_key_pem?}` | write/high |

- `ImportKey`：校验公钥格式与类型，**拒绝 DSA 与短于 3072 位的 RSA**（ADR-0009 规则 5）；接受 Ed25519/ECDSA/RSA≥3072;计算 SHA256 指纹;追加到 `~<user>/.ssh/authorized_keys`，**保持文件权限 0600 与属主**（trusted `os.Root` + 显式 fchmod/fchown）；重复指纹幂等。
- `RemoveKey`：**防自锁**——删除最后一把密钥且密码登录已关闭时拒绝（`PRECONDITION_FAILED`，读 sshd 有效配置判定）;按指纹定位行删除，保持权限/属主。
- `GenerateKey`：默认 `type=ed25519`。**默认路径是浏览器 WebCrypto 生成、只上传公钥**（ADR-0009 规则 5，前端职责，见 0021）；服务器生成是 fallback：`ssh-keygen -t ed25519 -N '' -f /dev/stdout` 形态，私钥 PEM **只在本次响应返回一次**，helper 不落盘、不写日志/事件/审计，hostsvc 转发后立即清零;公钥照常导入。`private_key_pem` 字段在默认浏览器路径为空。
- 密码 RPC（capability `system.account.password:<user>`）：

| RPC | 请求 | 返回 | effect/风险 |
|---|---|---|---|
| `SetPassword` | `{user, secret_ref, expected_revision}` | `{revision}` | write/high，reachability |

- `SetPassword`：新密码经 **secret 引用**传递（ADR-0009 规则 6）。**reveal 在宿主侧完成**：hostsvc forwarder 直接调宿主 secret 存储（`secrets.Store`，owner=`plugins/security.basic`、purpose=`plugin.operation`，并校验 operation 已派发给本实例，复用 `hostSecretRevealer` 的派发校验），**插件不调 `RevealSecret`、不见明文、无需 `secret.reveal` 能力**（ARCH §5.6"能由宿主代做的敏感动作优先由宿主代做"）。明文只在 hostsvc→helper 的 UDS 请求体 `secret_base64` 中;helper 解码后经**标准输入**交给 `chpasswd`（密码不出现在命令行/argv），用完立即 `clear`；不落盘、不写日志/事件/审计/配置历史。强度检查在 hostsvc forwarder（拒绝弱密码 `VALIDATION_FAILED`），helper 不记密码。密码 secret 的入口（operation payload 的 `x-secret` 字段提取）见 ADR-0021。
- helper verb：`account.list-keys`、`account.import-key`、`account.remove-key`、`account.generate-key`、`account.set-password`。
- 文件：`~<user>/.ssh/authorized_keys`（0600，属主 `<user>`）;密码经 `chpasswd` 写 `/etc/shadow`（helper 不直接编辑 shadow）。

### 3.4 ban —— `qwq.capability.ban.v1.BanService`

- capability：`system.ban.manage`。
- 倾向（ADR-0009）：**插件内置轻量封禁**——从 journald 读 sshd 认证失败，写入 nftables 带超时的集合;检测到系统已有 fail2ban 时只展示其状态，不同时跑两套封禁（共存检测见 0021）。

| RPC | 请求 | 返回 | effect/风险 |
|---|---|---|---|
| `ScanAuthFailures` | `{cursor, since_seconds, unit}` | `{failures[{ip, user, occurred_at, count}], next_cursor}` | read/low |
| `ApplyBans` | `{entries[{ip, ttl_seconds}], expected_revision}` | `{revision, active_count}` | write/high，reachability |
| `RemoveBan` | `{ip, expected_revision}` | `{revision}` | write/high |
| `ListBans` | `{}` | `{bans[{ip, expires_at}], revision}` | read/low |

- `ScanAuthFailures`：helper 用 `journalctl -u ssh.service -u sshd.service --since … --after-cursor <cursor> -o json --no-pager`（白名单 args）读 sshd 失败行，解析出 IP/用户/时间;`cursor` 增量，插件存于 KV，多数轮询只读新条目。`since_seconds` 上限 3600，`unit` 限白名单。
- `ApplyBans`：helper `nft add element inet qwq ban_v4 { <ip> timeout <ttl>s }`（v6 同理）。**宿主强制排除当前管理会话来源 IP 与白名单**（ADR-0009 规则 4）——白名单/会话 IP 由 hostsvc forwarder 注入并在 helper 再校验，插件无法封禁它们（`PRECONDITION_FAILED`）。集合带 `flags timeout`，元素自动过期，**无需常驻进程解封**。
- 集合规模上限 **4096 条**（1C1G 预算，约数百 KiB 内核内存）;超限 `RESOURCE_EXHAUSTED`，插件按 LRU/最早过期淘汰后再加。
- nft 对象：`table inet qwq` 内 `set ban_v4 { type ipv4_addr; flags timeout; }`、`set ban_v6 { type ipv6_addr; flags timeout; }`，挂在 qwq 自己的 input 链 `tcp dport 22 @ban_v4 drop`（端口取自保留 SSH 端口）。
- 防爆破策略（阈值/窗口/封禁时长/白名单）在**插件**（unprivileged），helper 只执行 scan/apply;策略变更不碰 helper。
- helper verb：`ban.scan`、`ban.apply`、`ban.remove`、`ban.list`。

## 决策 4：能力门与 operation 绑定（hostsvc 新增 seam）

`hostsvc.Config` 新增三个接缝（与现有 `Secrets SecretRevealer`/`Invoke Invoker` 同风格，宿主侧实现，测试可 fake）：

```go
// GrantedCapabilities 是安装时验签 manifest 授予本实例的能力（宿主已知事实，非插件自报）。
GrantedCapabilities []platformv1.Capability

// OperationResolver 解析 operation_id 的派发状态与声明能力（仿 SecretRevealer 的 operation 校验）。
type OperationResolver interface {
    // Resolve 返回 operation 是否当前派发给本实例且未结束、其声明的 capabilities、effect。
    Resolve(ctx context.Context, instanceID, operationID string) (OperationBinding, error)
}
type OperationBinding struct {
    Dispatched   bool
    Capabilities []platformv1.Capability
    Effect       string // read | write | destructive
}

// CapabilityForwarder 把已授权的能力调用转发到 qwq-capability，并注入宿主已知事实
//（保留端口、会话 IP、白名单、secret 明文）。每能力一个实现。
type CapabilityForwarder interface {
    Forward(ctx context.Context, call CapabilityCall) (CapabilityResult, error)
}
```

能力门（每个能力 handler 在 `prepareCall` 之后执行）：

1. **capability 检查**：RPC 所需 capability（含 scope）必须在 `GrantedCapabilities` 中;否则 `PERMISSION_DENIED`。
2. **operation 绑定**（仅写操作）：`HostCallContext.operation_id` 非空，`OperationResolver.Resolve` 返回 `Dispatched=true`，且该 operation 声明的 `capabilities` 包含本 RPC 所需 capability（ADR-0007 #4 的 operation 级子集）;否则 `PERMISSION_DENIED`/`FAILED_PRECONDITION`。读操作跳过此步（只需 capability）。
3. **scope 绑定**：`account.keys`/`account.password` 的 scope 与 RPC `user` 参数匹配——manifest scope 为保留字 `all` 时匹配任意用户（`security.basic` 管理所有用户），为具体用户名时只匹配该用户（受限第三方插件）。manifest schema 的 scope 模式 `^[A-Za-z0-9._:/@-]+$` 不含 `*`，故用字面保留字 `all`（无需改 schema;用户名恰为 `all` 的极端情况被该保留字遮蔽，文档注明）。`firewall`/`sshd`/`ban` 的 scope 固定为 `self`（本节点 qwq 自有对象），不接受插件指定他表/他集合。
4. **宿主事实注入**：forwarder 注入保留端口（firewall/sshd）、当前会话 IP + 白名单（ban）、secret 明文（account.password，**宿主侧 owner 绑定 reveal**，插件不经手）。这些**不来自插件消息**。
5. **审计与限流**：写操作经 `AuditSink` 记录（secret/私钥/密码不入审计）;每实例能力写令牌桶（复用 `ratelimit.go`），`ban.scan` 读单独限频（默认每分钟 ≤ 6 次，配合 20s 轮询）。

能力门**不重复定级**：风险/审批已在 operation 目录加载时钳制（`system.*`→high，reachability→`ai_confirm`，ADR-0016）;能力门只校验绑定与注入事实。

## 决策 5：风险下限与可达性清单

- `operations.capabilityFloor` 已对 `system.*` 返回 `RiskHigh`，四个能力的所有写操作自动 high;`destructive` 再抬 high。无需改风险代码。
- ADR-0016 R2 的 `ReachabilityCapabilityPrefixes`（p2-b `internal/operations/action.go`）当前为 `system.firewall`、`system.sshd`、`system.network`、`system.panel`、`system.tls`。**本 ADR 要求补入 `system.account`、`system.ban`**：删最后一把密钥/改密码/封禁都可能切断管理通道，应强制 reachability 置真。这是跨 p2-b 轨道的改动，列入待批准与拆解协调项（p6-sec 轨道在 p2-b 合入后追加，或由 p2-b 预留）。
- 插件 manifest 仍须如实声明 `reachability: true`（ADR-0018 schema 校验）;R2 清单是漏报兜底，两层互不替代。

## 决策 6：1C1G 内存与开销预算

- **空闲零 root 进程**：两个 helper 都 socket 激活，请求间 inactive。
- `qwq-capability`：`MemoryMax=48M`、`GOMEMLIMIT=40MiB`、`GOMAXPROCS=2`、`TasksMax=24`、`RuntimeMaxSec=120`;一请求一激活，峰值 RSS 远低于 48M（nft/sshd 子进程短命）。
- `ban.scan` 默认 20s 轮询（可配 10-60s），每激活只读增量 journald，短命;ban 集合 ≤ 4096 条（内核内存数百 KiB）。相比 fail2ban-server 约 16 MiB 常驻 RSS，本方案无常驻 root 进程，空闲开销更低。
- 能力写操作令牌桶限流，防止插件高频触发 root 激活;`ban.scan` 读限频。
- hostsvc 能力门是每实例内存中的少量映射，无新常驻组件;能力 forwarder 按需 dial `capability.sock`。

## 测试纪律（ADR-0009）

- **构建机单测**：能力门用 fake `OperationResolver`/`CapabilityForwarder`/`SecretRevealer`;helper verb 用 fake `Runner`（仿 `sandbox.ExecRunner` 的 fake）;proto 用 buf 生成 + 标准 lint。全部在构建机跑，不碰真实系统。
- **nftables**：独立 network namespace 内测试 qwq 表/集合/超时/保留端口（`ip netns exec`）。
- **sshd**：独立配置文件 + 回环端口另起 sshd 实例，测改端口/改登录方式/`sshd -t`/回滚;`VerifyPort` 对该回环实例验证。
- **chpasswd/账户**：fake runner 校验 stdin 传递与"密码不入 argv/日志";authorized_keys 用临时家目录测权限/属主保持。
- **真实系统集成**（改真实 sshd/防火墙的端到端验收）：标注"**测试机执行，届时先经用户确认**"，需 VNC 控制台可用且发起人在场;本设计不安排碰测试机真实 SSH/防火墙。

## 已批准项（2026-11-13 用户批准）

1. **独立 `qwq-capability` helper**（新二进制 `cmd/qwq-capability` + 单元/socket + `internal/sandbox.CapabilityClient`）而非扩展安装 helper。
2. **能力 helper 沙箱放宽**：`PrivateNetwork=no`（宿主 netns）、`CAP_NET_ADMIN`、`AF_NETLINK`/`AF_INET`、`ProtectKernelLogs=no`（journald）、精确 `ReadWritePaths`。需在测试机用 `systemd-analyze security` + strace 收敛（届时先经用户确认）。
3. **`ReachabilityCapabilityPrefixes` 补 `system.account`/`system.ban`**（跨 p2-b 轨道协调）。
4. **能力 proto 独立版本化**（`api/qwq/capability/`，不进 ABI、不计 `sdk/abi.Minor`）。
5. **服务器生成密钥为 fallback**：默认浏览器 WebCrypto;服务器生成私钥只返回一次（确认接受该路径的存在）。

## 代价

- 新 helper 二进制/单元/socket + 一轮沙箱审查与测试机实测。
- hostsvc 新增能力门 seam（`GrantedCapabilities`/`OperationResolver`/`CapabilityForwarder`）与四服务注册;每能力一个 forwarder 实现。
- SDK 暴露 host conn + `CapabilityContext`;生成四套能力客户端。
- 四个能力 proto package 各自维护版本与冻结规则。
- 共存检测/接管流程增加工作量（ADR-0021 细化），但不做就会与宝塔等互相覆盖规则。
