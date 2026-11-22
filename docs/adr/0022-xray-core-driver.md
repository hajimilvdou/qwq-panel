# ADR-0022：Xray Core Driver 首版进程、网络与秘密恢复

> 移植说明：源自 WorkBuddy 工作树 `main-50f25f0b`（基线 ea0bb91，2026-11-10）的 ADR-0016，2026-11-13 移植并按 main `ccbfb13` + p2-b 克隆 `f65bc36` 基线刷新。原编号 0016 与本仓「可达性审批分级」ADR-0016 冲突，重编号为 **0022**（0019/0020/0021 归 P6 设计）。源工作树只读，未改动。

- 状态：Accepted（2026-11-13 用户批准 X1–X12 施工，含 per-user mark 扩展；network.proxy 定级：列高敏安装同意 CapabilitySensitive，core.apply 保持 medium/confirm）
- 关联：ARCH §9、ADR-0003、0004、0007、0012、0013、0014、0016（可达性审批分级）、0018（manifest 1.3，p2-b 轨道）、0023（proxy.advanced 硬限速，per-user mark 扩展契约依赖 B-X4）
- 详细设计：`../plugins/core-xray/DESIGN.md`
- 总体计划：`../plugins/core-xray/PLAN.md`
- 扩展补遗（非 base）：per-user mark（`xray.mark`，供 proxy.advanced 硬限速）见 DESIGN §17；用户 2026-11-13 决定，首版 base 范围不变，与 ADR-0023 §2.4/§5 互为契约依赖。

## 背景

项目已有通用插件 ABI、生命周期、配置历史、operation、审批、secret 和事务式更新，但没有真实代理驱动。直接新增一个写 Xray JSON 的插件不足以交付：当前单元默认无网络，生产 Initialize 的 DataDir 为空，秘密只以引用传递，且运行配置与宿主期望配置不是同一状态。

首版目标仅为 VLESS + REALITY + Vision + RAW/TCP + direct outbound，真实进程、真实连接、真实统计和失败回滚缺一不可。

## 决策

### 1. 驱动与 Xray 同单元、不同进程

`core.xray` 驱动由 `qwq-plugin@core.xray.service` 启动；它从同一不可变插件包启动固定的 `bin/xray` 子进程。两者共用动态 UID、cgroup 和网络命名空间，停止时由 `KillMode=control-group` 一起回收。

驱动从 `os.Executable()` 推导版本目录，启动前核对 `bin/xray` 的签名清单摘要。不得使用 PATH、cwd、用户路径、shell 或系统已有 Xray 服务。

### 2. 首版使用受控完整配置切换

每次 Apply 生成完整候选配置，经原生预检后受控重启 Xray；不使用 HandlerService 局部修改入站或用户。首版只启用 StatsService 作为 API 健康检查和计数器来源。

插件版本更新与回滚强制 restart，`overlap_safe=false`，不允许两个版本同时占用同一业务端口或写同一运行快照。

### 3. 新增精确网络 capability `network.proxy:direct`

宿主只对该精确 `(name,scope)` 计算内部策略，渲染 `PrivateNetwork=no` 与 `RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6`。其他插件保持默认拒绝；不接受插件提交的 systemd 指令。

首版不授予 Linux capabilities，不允许绑定 1024 以下端口，不自动改防火墙或安全组。

基线复核（2026-11-13）：`network.proxy` 当前不在 `internal/operations/action.go` 的 `capabilityFloor` 高敏清单（落入默认 medium），也不在 `ReachabilityCapabilityPrefixes`（仅 `system.*`），因此 `CapabilitySensitive(network.proxy)=false`、不会被强制 reachability。这与 `core.apply` 声明 risk=medium 一致，但「开放宿主网络命名空间」是否应抬为 high/高敏同意行，是宿主侧定级问题，已登记为审查项（见 PLAN §4 与 ledger），不在本 ADR 擅自改动定级代码。

### 4. 宿主供给稳定、私有的持久 DataDir

路径为 `/var/lib/qwq-plugin-data/<plugin_id>/default/`，不含版本和 generation。由宿主推导，经内部 UnitSpec 校验，并由 systemd StateDirectory 创建、授权给动态 UID；Initialize 使用 ABI 既有 `data_dir` 字段传递。helper 仅接受与当前插件 ID 匹配的固定目录。

首版以非空 `state.backup_paths` 作为需要目录的信号，不修改 manifest schema。noop 等无目录需求的插件保持 `DataDir=""` 和原单元行为。

实施修正（2026-11-14）：`config.data_dir` 默认 `/var/lib/qwq`，该根为 qwq 私有的 0700，插件动态 UID 无法遍历。按已批准配套设计改用 root 拥有、0711 的专用插件根；不放宽宿主数据库和秘密树。`state.backup_paths` 信号与 `data_dir` ABI 字段未变。真机遍历及持久映射单独验收，不能以渲染单测代替。

### 5. 期望配置与运行配置分离

通用配置接口保存 desired revision；其 Validate/Apply 只做无副作用校验和内存中的期望快照替换，不启动或重启 Xray。`core.apply` 将指定 desired revision 变为 running revision。

desired 改变时，现有核心继续运行，状态显示 `PENDING_APPLY`。插件版本 revision、desired revision、running revision 和配置 digest 不得混用。

### 6. 秘密只在 Apply 中受控揭示，重启读私有运行快照

宿主数据库和 operation payload 只保存 secret 引用。`core.apply` 在 RUNNING job 中使用现有 `RevealSecret`，宿主存储调用必须改为 `RevealOwned`，绑定 `plugins/core.xray` 与 `plugin.config`，防止揭示其他 owner 的值。

候选原生配置经预检后，以 0600 原子写入当前插件动态 UID 私有的 DataDir。重启、宿主恢复和插件更新从已提交运行快照恢复，不在后台调用 reveal，不把明文加进 Platform ABI。

Plan 不 reveal、不启动 Xray、不写状态；完整原生预检只在 Apply 执行。

基线复核（2026-11-13）：`RevealOwned` 已存在（`internal/secrets/secrets.go:192`），但宿主 reveal 路径仍调用无 owner 绑定的 `Reveal`（`internal/controller/plugin_runtime.go:1159`），本决策的 owner 绑定仍是前置缺口。插件侧 `RevealSecret` 的 `purpose` 参数只是审计文本（`internal/pluginhost/hostsvc/secrets.go:48,74`），存储 purpose 由宿主固定为 `plugin.config`（`plugin_runtime.go:90`），两者不可混称。

### 7. Xray API 首选文件系统 UDS

API 只位于私有目录，文件权限 0600，只开启 StatsService，不使用抽象命名空间或无保护回环 TCP。驱动使用有 deadline、消息上限和固定 dialer 的 gRPC 客户端。

官方 API 页面只明确展示 IP+端口，并未证明 UDS。必须在锁定版本 spike 中验证传统 inbound/routing 能否提供所需文件系统 UDS；失败则回本 ADR，不能静默降级。

### 8. 统计不主动 reset

Observe 只读当前代次累计值，永不 reset。输出包含稳定面板 ID、方向、字节值和 reset epoch；核心重启后建立新 epoch，不生成负 delta，也不伪装成已持久化的生命周期总量。

### 9. Apply 使用可恢复状态机

候选预检前不动 last-good；进程切换后必须做 API 与健康检查；失败、取消、deadline 和中途 kill 均按设计恢复或从已提交 current 恢复。旧核心未恢复健康时，不得宣称回滚成功。

核心健康与宿主运行状态 CAS 不是原子事务。CAS 失败时首版选择回滚；回滚失败返回 RECOVERY_FAILED 并暴露真实诊断状态。

## 理由

该组合以最小宿主改动复用现有签名包、动态 UID、沙箱、生命周期、Operation 和 Secret 体系，同时允许真实代理流量。双 revision 和私有快照避免为了重启而放宽 ABI 或让后台任务绕过 operation 秘密授权。

## 后果

正面：

- 首版只维护一个核心和一个协议组合；
- 不增加通用 exec、任意文件、任意服务控制或公网管理 API；
- 配置失败不会摧毁最后可用配置；
- 统计与状态来自真实 Xray；
- 主线只有显式合并后才受影响。

代价与风险：

- 驱动与 Xray 同 UID、同网络和同一资源预算，故障隔离弱于独立核心单元；
- DataDir 中存在 0600 明文运行配置，备份必须保持同等或更强的保密边界；
- 完整切换会短暂中断既有连接，首版不宣称零中断；
- UDS、原生字段、预检和统计语义都依赖锁定版本，升级必须重跑兼容验收；
- desired/running 双状态增加 UI 和状态解释成本，但不能省略；
- 宿主补充网络与 DataDir 会触及共享代码，必须在当前工作树独立验证，未经批准不合入。

## 未采用

- **同时实现 Xray 与 sing-box**：首版协议需求未证明其必要性，双驱动会翻倍兼容和测试工作。
- **Xray 作为 Go 库嵌入驱动/宿主**：扩大依赖与内部 API 耦合；独立子进程更符合数据面边界。
- **独立 systemd 核心单元**：隔离更强，但需要新的服务管理能力；首版同单元已经足够且改动更小。
- **HandlerService 局部增删用户**：首版完整 Intent 更一致；局部 API 增加原子性和漂移处理。
- **宿主在 Initialize/ApplyConfig 前统一 ResolveSecrets**：与现有“只传引用”ABI 语义冲突，并绕过 operation 级 reveal 边界。
- **后台重启时重新 reveal**：后台没有 RUNNING operation，违反现有授权模型。
- **只在内存保存秘密**：进程和宿主重启后无法恢复代理。
- **API 回环 TCP 作为默认替代**：回环不是信任边界，除非另有经过评审的隔离方案。
- **首版绑定 443**：需要额外权限且可能冲突；先用非特权端口完成真实闭环。
- **首版生命周期流量累计**：需要额外持久化和跨代次合并；先返回原始值与 reset epoch。

## 批准前必须保留的验证项

1. Xray 锁定版本和供应链证据；
2. VLESS/REALITY/Vision/RAW 的真实服务端与客户端配置；
3. 原生预检是否绝不监听业务端口；
4. StatsService 的文件系统 UDS 可行性；
5. 最小 proto 客户端与统计字段；
6. 同单元双进程的 systemd 回收和故障注入；
7. 网络 capability 的默认拒绝回归；
8. DataDir 权限、备份保密和 owner 绑定；
9. Apply 每个故障点的恢复证据；
10. 1C1G 的驱动+Xray 合计资源实测。

## X6 实施登记（2026-11-15）

测试机已验证锁定二进制的原生预检不创建 TCP 监听或 API socket；传统入站 + routing 的 StatsService 可使用动态 UID 私有的 0600 文件系统 UDS，其他 UID 连接被拒绝，重启后进程/端口/socket 清理通过。握手前两个入站 counter 存在且为零，用户系列尚不存在；不能把缺失用户系列补成零。

最小客户端只保留已验证的 QueryStats wire RPC；精确读取使用固定 counter 名过滤并核对响应，列表查询只用驱动的两个固定前缀。调用有 deadline、消息与系列上限，reset 始终为 false，不导入 Xray Go 核心。

wire 子集及生成文件按原 MPL-2.0 保留；NOTICE 与 repo_lint 仅登记这三个具体文件的许可证，外围代码仍遵循原分区。独立生成配置及非修改式漂移检查接入现有门禁，不改变 Platform ABI。为复用生产渲染和二进制核验，真实 spike 通过显式 x6spike 测试标签构建，控制脚本在 spikes/corexray；它不进入产品构建。

以上证据不代替真实 VLESS 握手、流量增长、mark、Apply 故障恢复或资源验收。
