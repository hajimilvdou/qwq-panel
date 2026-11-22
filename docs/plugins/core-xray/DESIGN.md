# core.xray 首版架构与契约设计

> 移植说明：源自 WorkBuddy 工作树 `main-50f25f0b`（基线 ea0bb91，2026-11-12）的 `docs/plugins/core-xray/DESIGN.md`，2026-11-13 移植并按 main `ccbfb13` + p2-b 克隆 `f65bc36` 基线刷新。关联 ADR 由 0016 重编号为 **0022**；manifest 引用刷新为 schema 1.3；宿主配套三节补当前代码证据。技术契约（字段表、状态机、错误码、统计语义）不变。源工作树只读，未改动。

- 状态：Draft，供用户审查；尚未批准施工
- 日期：2026-11-12 提出；2026-11-13 移植刷新
- 关联：`PLAN.md`、ARCH §9、ADR-0003/0004/0007/0012/0013/0014/0016/0018/0022
- 设计基线：本仓克隆 `.cache/wt/core-xray`（基于 main `ccbfb13`）；不得据此改动 `main` 或部署环境

## 0. 设计结论

1. `core.xray` 是真实节点插件，管理一个随包提供的、锁定版本的 Xray 子进程；不接管系统已有 Xray 服务。
2. 驱动与 Xray 分属两个进程，但首版共用 `qwq-plugin@core.xray.service`、动态 UID、cgroup 和网络命名空间；停止单元时 `KillMode=control-group` 同时回收两者。
3. 上层只使用面板自有 Intent。首版仅声明 VLESS + REALITY + Vision + RAW/TCP + direct outbound；其他组合一律 `UNSUPPORTED`。
4. 配置分成两个 revision：宿主保存的 **desired revision** 与核心实际运行的 **running revision**。通用配置接口只改变 desired；`core.apply` 才改变运行状态。
5. 宿主配置和 operation payload 只保存 secret 引用。仅 `core.apply` 可在 RUNNING operation 中受控解密；重启从私有运行快照恢复，不在宿主 ABI 中新增明文通道。
6. 首版完整渲染并切换配置，不用 HandlerService 局部增删用户；Xray 管理面只启用 StatsService，用于 API 健康检查和真实计数器。
7. 为真实网络增加精确 capability `network.proxy:direct`；为私有快照补宿主供给的持久 `DataDir`；为 secret reveal 补 owner 绑定。三项都是首版前置工作，不得绕过。
8. Xray API 是否可用文件系统 UDS、锁定版本的 VLESS 原生字段名、StatsService 行为，必须通过 X0/X6 spike 证实；当前文档不把假设写成事实。
9. manifest 按 schema 1.3 编写（p2-b 轨道已实现，尚未合入 main）；首版不声明 `ui.widgets`（需 `ui.entry` 入口页，超出「不新建复杂业务 UI」范围），五项操作均不声明 `operations[].reachability`（代理数据面不切断管理通道）。详见 §7 与 PLAN §2。
10. **扩展补遗（非 base）**：为 `proxy.advanced` 首版硬限速提供可选 per-user mark（`xray.mark` 扩展，`users[].mark` → 专属 direct 出站 `sockopt.mark` + routing），与 ADR-0023（B-X4）互为契约依赖。base 首版范围不变，详见 §17。

## 1. 进程与信任边界

```text
浏览器 / CLI / 其他插件
        │ qwq operation（只有控制面数据）
        ▼
Controller / Agent / Operation Manager
        │ Platform ABI over per-plugin UDS
        ▼
core.xray 驱动进程（bin/plugin）
        │ 私有 Xray gRPC API；仅 StatsService
        ▼
Xray 子进程（bin/xray）
        │ 实际 TCP 入站与 direct 出站
        ▼
客户端和目标地址
```

### 1.1 驱动职责

- 严格解析、校验和预演 Intent；
- 在私有目录保存期望元数据、原生配置快照和运行元数据；
- 启动、预检、停止和健康检查 Xray；
- 通过私有 API 读取状态和统计；
- 上报结构化 operation 结果及资源变化；
- 对日志、错误和响应做秘密脱敏。

### 1.2 Xray 职责

- 处理真实 VLESS/REALITY/Vision 数据面；
- 监听用户指定的非特权 TCP 端口；
- 通过 direct outbound 连接目标；
- 维护原生入站和用户计数器。

Xray 不知道面板用户、RBAC、审批和 Platform ABI。代理字节绝不经过驱动 RPC。

### 1.3 为什么首版共用 systemd 单元

优点：复用现有安装、摘要校验、动态 UID、资源限制、启停和回滚，不需要新增通用 systemd 服务管理接口。

代价：驱动与 Xray 同 UID、同网络命名空间和资源上限；任一进程崩溃需要按同一故障域处理。首版选择这个代价，后续只有在有实测必要时才拆成独立核心单元。

## 2. 包、二进制与版本

### 2.1 包内容

```text
manifest.json
bin/plugin                 # Go 驱动入口
bin/xray                   # 与驱动锁定配套的 Xray
schemas/config.schema.json
schemas/*.json             # 每个 operation 的请求/响应契约
attestations/sbom.spdx.json
attestations/xray-source.json
LICENSES/...               # 对应许可证和通知
```

`manifest.json` 按 schema 1.3 编写（ADR-0018；1.2 包仍可装，但本插件用 1.3）。`manifest.files` 必须包含所有包文件及 SHA-256。`bin/xray` 不是宿主入口，但打包器会保留 `bin/` 下经审核的执行位（`sdk/pkgfile/read.go:489-505` 的 `contentMode`/`entryMode`：签名入口恒可执行，`bin/` 下按头部位保留）。

### 2.2 定位与校验

- 驱动从 `os.Executable()` 的已解析路径推导版本目录，不使用 cwd、PATH、环境变量或用户输入定位 Xray。
- 只允许固定相对路径 `bin/xray`。
- 在 Activate 和每次 Apply 启动前核对文件类型、所有者/只读状态和 `manifest.files["bin/xray"]` 的 SHA-256。
- 不匹配时拒绝执行，错误码 `CORE_BINARY_MISMATCH`。
- 使用 `exec.CommandContext` 和固定参数数组；不得拼接 shell 命令。

### 2.3 版本锁定

X0 必须记录：Xray tag、tag commit、发布包 URL、发布包和可执行文件哈希、目标架构、Go API proto 来源、MPL-2.0 许可证、构建/解包工具和验证结果。禁止 `@latest`、分支头和未核哈希文件。

首版不导入完整 Xray Go 核心。只引入或生成锁定版本所需的最小 StatsService 客户端；其 proto 来源、包名、RPC 和生成漂移必须可审查。

## 3. 宿主最小配套设计

### 3.1 网络 capability

新增宿主认可的精确项：

```text
name  = network.proxy
scope = direct
```

语义：允许该插件的数据面使用宿主网络命名空间、AF_INET/AF_INET6，并监听用户配置的非特权端口，同时保留 AF_UNIX 供 Platform ABI 和私有 API 使用。

实现设计：

1. `internal/controller.unitSpecFor`（当前 `internal/controller/updater_runtime.go:317`）只对已验收签名 manifest 中精确的 `(network.proxy,direct)` 计算一个宿主内部布尔值；不得前缀匹配。
2. `sandbox.UnitSpec`（`internal/sandbox/unit.go:287`）新增内部网络策略字段，不接受 systemd 指令文本。
3. `sandbox.renderService`（`internal/sandbox/unit.go:509`）仅在该字段为真时输出：
   - `PrivateNetwork=no`
   - `RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6`
4. 其他插件保持模板默认拒绝（`internal/sandbox/templates/qwq-plugin@.service:93-94`）；其余 `NoNewPrivileges`、空 capability set、文件系统和系统调用约束不变。
5. 不授予 `CAP_NET_BIND_SERVICE`；端口 1–1023 在 Intent 校验时拒绝。
6. 回滚重渲染必须得到相同策略；策略扩大必须走现有新增 capability 接受流程（`internal/api/plugins.go` 的 `accepted_capabilities`）。

该 capability 不表示可以连接宿主任意管理端口。其他插件仍有默认网络隔离；宿主已有服务的保护不由本插件改写。

当前基线复核（2026-11-16）：`capabilityFloor` 对 `network.proxy` 与 `secret.reveal` 均返回 high，安装须提供对应能力同意。`core.apply` 声明 write/medium，宿主有效风险为 high，默认策略等待真人审批；ADR-0004 的第二因素下限适用于 destructive。`ReachabilityCapabilityPrefixes` 只包含 `system.*`，代理数据面操作不会因此被强制视为管理通道变更。X10 夹具按实际 write 审批契约验收，TOTP 可以作为真人会话的附加验证。

### 3.2 持久 DataDir

路径由宿主计算：

```text
/var/lib/qwq-plugin-data/<plugin_id>/default/
```

首版 instance 为 `default`。路径不得包含插件版本或进程 generation。2026-11-14 按已批准配套设计修正：宿主数据根 `/var/lib/qwq` 保持 0700，插件使用 root:root 0711 的专用数据根；对应 systemd `StateDirectory=qwq-plugin-data/core.xray/default`，叶目录 0700。helper 校验路径必须属于本插件，不能指定其他 `/var/lib` 路径。真实动态 UID 遍历仍待 X6/X10 验收。

最小内部扩展：

- `updater.InstanceSpec`（`internal/pluginhost/updater/runtime.go:25`，当前无 DataDir 字段）增加宿主推导的 `DataDir`；
- `UpdaterRuntime.bootstrapInstance`（`internal/controller/updater_runtime.go:1438`，当前 :1651 传 `DataDir:""`）在 ABI 既有 `InitializeRequest.data_dir`（`api/qwq/platform/v1/platform.proto:214`）中传递它；
- `sandbox.UnitSpec` 只接收经宿主推导和校验的等价目录策略；
- 具体单元通过 systemd `StateDirectory=` 创建目录并赋给该单元的动态 UID；
- `ProtectSystem=strict` 下只写该目录；noop 等不请求备份目录的插件继续 `DataDir=""`，保持原单元行为。

首版以非空 `state.backup_paths` 作为宿主供给目录的显式信号，避免改 manifest schema。p2-b 的 schema 1.3 未改动 `state` 成员，本信号仍有效。若未来需要“有目录但不备份”，另立 ADR，不能复用含糊语义。

插件启动时必须验证：目录为绝对路径、无 symlink 逃逸、仅当前 UID 可写、目录权限不宽于 0700。失败则不启动 Xray。

### 3.3 Secret owner 绑定

当前插件配置的秘密 owner 是 `plugins/<plugin_id>`，purpose 是 `plugin.config`（`internal/controller/plugin_runtime.go:90`）。`core.apply` 的 reveal 必须由宿主使用 `RevealOwned` 绑定到这两个值，不能只依赖插件提供的 ref 字符串。

最小内部调整点：`internal/controller.hostSecretRevealer`（`plugin_runtime.go:1132`）的存储接口与调用；Platform ABI、请求字段和错误外形不变。外部 owner 或 purpose 的 ref 统一返回既有拒绝/不可用语义，不泄露其是否存在。

基线复核（2026-11-13）：`RevealOwned` 已存在（`internal/secrets/secrets.go:192`，owner/purpose 不符按 NOT_FOUND 处理），但 `hostSecretRevealer.Reveal` 的存储调用仍用无 owner 绑定的 `Reveal`（`plugin_runtime.go:1159`）；operation 派发校验（`dispatchedTo`，:1154）保持不变。插件侧 `RevealSecret(ctx, ref, purpose)` 的 `purpose` 仅作审计文本（`internal/pluginhost/hostsvc/secrets.go:48,74,105`），不是存储 purpose；X8 中「purpose 固定 core.xray.apply」指该审计声明。

`core.xray` 仅声明：

```text
secret.reveal:config
```

2026-11-18 接续 ADR-0030：共享 HostSecretsService 支持精确 operation scope，但
core.xray/core.apply 仍仅声明 config。两层 capability（已签名授予与原操作声明）、
真实 executor、当前授权及读取后重查适用于 config；operation 另外要求原敏感
参数成员和固定 plugin.operation purpose。请求 purpose 仍仅是审计文本，不用于
扩大 owner/purpose；X3 原约束没有变成通用解密通道。

且只有 `core.apply` operation 声明使用该 capability。Plan、Status、Observe 和后台 Activate 不得调用 reveal。

## 4. 私有目录与运行快照

默认实例布局：

```text
<DataDir>/
  runtime/
    generations/
      <config_digest>/
        config.json         # 不可变完整 Xray 原生配置，0600
    state.json              # current/previous 指针及无秘密元数据，0600
    api.sock                # 文件系统 UDS；仅当前 UID，0600
  work/
    <operation_id>/
      <attempt>/           # 候选配置与临时文件，0700
  logs/                    # 首版仅在有界测试需要时使用；默认不写访问日志
```

约束：

- `runtime/`、`work/` 为 0700；所有配置和状态文件为 0600。
- 所有写文件使用“同目录临时文件 → 写入 → fsync → 0600 检查 → rename → 目录 fsync”。
- 不使用 symlink 作为 current 指针；不跟随外部 symlink。
- `state.json` 同时记录 current/previous 的 `running_revision` 与配置 SHA-256，以及 Xray 版本、进程代次和统计 reset epoch；不记录秘密。
- generation 配置先完整写入并 fsync，再由一次原子替换 `state.json` 提交 current/previous 指针；Xray 始终从不可变 `generations/<digest>/config.json` 启动。
- 每次启动验证 state 指针、generation 文件和摘要一致；不一致时不得启动未知配置，也不得把候选目录当成已提交配置。
- 仅保留 current 和 previous 指向的两份运行配置；候选目录按明确 owner 清理。
- `/run` 中的插件通信 socket 与 DataDir 中 Xray API socket不混用。
- UDS 路径长度必须在 Linux 限制内；路径由固定 DataDir 和短文件名构成。

明文原生配置是 Xray 重启所需的最小运行快照。它保存在单插件动态 UID 的私有目录，而不是面板数据库、日志或通用备份中。若现有备份机制只收集 `state.backup_paths`，必须保证快照不会被另存到更宽松的存储位置。

## 5. Core Intent v1

### 5.1 设计原则

- Intent 是完整、不可变、可重复的期望快照，不是局部 patch。
- 配置 JSON 内不放 revision；宿主 `plugin_configs.revision` 是 desired revision。
- 所有数组有数量和长度上限；严格拒绝未知字段、重复键和无效 JSON 类型。
- 首版没有扩展对象；任何未声明字段都拒绝。未来核心专属能力必须使用 `xray.<extension>` 命名空间并另升契约版本。首个具体扩展机制（`xray.mark`，per-user mark）见 §17 补遗；base 首版仍不含任何扩展对象。
- Xray 原生字段如 `clients/users`、`tcp/raw`、`dest/target` 由 X0 按锁定版本固定，Core Intent 不随这些名称漂移。

### 5.2 逻辑形状

以下为“宿主已提取秘密后”的引用形式示例，不是可粘贴的真实配置：

```json
{
  "schema_version": "1",
  "enabled": true,
  "inbound": {
    "id": "main",
    "listen": "0.0.0.0",
    "port": 10443,
    "protocol": "vless",
    "transport": "raw",
    "flow": "xtls-rprx-vision",
    "security": {
      "mode": "reality",
      "target": "example.com:443",
      "server_names": ["example.com"],
      "private_key": {"$secret": "sec_example"},
      "short_ids": ["0123456789abcdef"]
    },
    "users": [
      {
        "id": "alice",
        "uuid": {"$secret": "sec_example_user"}
      }
    ]
  },
  "outbound": {"type": "direct"}
}
```

### 5.3 字段规则

| 字段 | 规则 |
|---|---|
| `schema_version` | 必须为 `"1"` |
| `enabled` | false 表示 Apply 后核心停止；入站仍需完整有效，便于再次启用 |
| `inbound` | 首版恰好一个对象 |
| `inbound.id` | `^[a-z][a-z0-9._-]{0,31}$`，用作稳定面板 ID |
| `listen` | 仅合法 IPv4/IPv6 地址；不得含 zone 歧义或其他地址格式 |
| `port` | 1024–65535 |
| `protocol` | 仅 `vless` |
| `transport` | 仅 `raw` |
| `flow` | 仅 `xtls-rprx-vision` |
| `security.mode` | 仅 `reality` |
| `target` | 合法 DNS 名或 IP + 明确端口；不含 URL、路径、用户信息和控制字符 |
| `server_names` | 1–8 个合法 DNS 名；无通配符；target 使用域名时至少包含该域名 |
| `private_key` | 仅 secret 引用；长度与格式在 reveal 后校验；响应永不返回 |
| `short_ids` | 1–8 个、去重、偶数长度十六进制，单个最多 16 个 hex；是否允许空字符串由锁定版本实测，不由普通模型猜测 |
| `users` | 1–256 个；id 唯一 |
| `users[].id` | 与 inbound.id 同类稳定 ID，不得使用 email 或流量标签充当永久主键 |
| `users[].uuid` | 仅 secret 引用；reveal 后必须是规范 UUID；响应永不返回 |
| `outbound.type` | 仅 `direct` |

补充上限：Intent 总大小沿用宿主配置上限并另由插件限制；DNS 名、ID 和每个数组都必须在 Schema 与 Go 语义校验中有双重上限。

### 5.4 秘密 Schema 形态

`config.schema.json` 中 `private_key` 和 `users[].uuid` 必须以 `writeOnly:true` 或 `x-secret:true` 标记，使 API 在持久化前提取秘密。为了同时支持用户输入和宿主引用，可使用 secret walker 已支持的 `anyOf`：

- 用户写入形态：字符串；
- 宿主保存/插件接收形态：严格对象 `{"$secret":"sec_…"}`。

Go 的 desired Intent 解码只接受引用对象；明文字符串只存在于 API 提取前和 Apply 的临时解析结果中。这样普通模型不会把明文误存到 operation 或 KV。

### 5.5 稳定原生标识

```text
Xray inbound tag = qwq-in-<inbound.id>
Xray user email  = qwq-user-<user.id>
```

这些映射是驱动内部实现；上层始终使用面板 ID。日志和状态响应不得把 email 当作秘密以外的自由文本输出。

## 6. Desired 与 Running 双 revision

| 名称 | 所有者 | 含义 |
|---|---|---|
| desired revision | 宿主 `plugin_configs` | 用户最新保存且通过插件无副作用校验的 Intent |
| running revision | 插件私有运行状态 | 当前通过 Xray 预检、启动和健康检查的 Intent |
| plugin version | 宿主 `plugin_versions` | 驱动与配套 Xray 二进制版本 |
| config digest | 插件计算 | 完整原生配置或规范化 Intent 的 SHA-256，用于识别实例内容 |

规则：

- 通用 PUT 配置只更新 desired；`core.xray` 的 `config.hot_apply=true`，但 `ApplyConfig` 仅原子替换内存中的 desired 快照，不启动、不停止、不重启 Xray。
- 通用配置 ValidateConfig 只做严格结构、引用形状和纯语义校验；它不能 reveal，不能声称已完成 Xray 原生预检。
- desired 改变后，运行核心保持旧配置，`core.status` 返回 `PENDING_APPLY`，不得报“已应用”。
- `core.apply` 指定一个 desired revision；成功后 running revision 等于它。
- 插件更新或回滚复用同一 DataDir，但版本兼容性由 state schema 与驱动版本检查；失败时停止并报告，不能悄悄使用旧二进制之外的未知状态。
- desired 快照被宿主保留策略裁剪不影响已保存的 current/previous 运行快照；恢复不依赖一次新的 secret reveal。

## 7. Operation 契约

所有 permission 资源段遵循 ADR-0014（资源段等于插件 id `core.xray`）。

| Operation | mode/effect/risk | permission | 说明 |
|---|---|---|---|
| `core.capabilities` | invoke/read/low | `core.xray:read` | 返回驱动、核心版本和已验证支持矩阵 |
| `core.validate` | invoke/read/low | `core.xray:read` | 对指定 desired revision 做无副作用校验；默认当前 desired |
| `core.status` | invoke/read/low | `core.xray:read` | 返回进程、API、desired/running revision 和状态 |
| `core.observe` | invoke/read/low | `core.xray:read` | 读取真实计数器；永不 reset |
| `core.apply` | job/write/medium | `core.xray:apply` | 将指定 desired 变为运行配置，可预演、取消、回滚 |

`core.apply` 声明 `plannable=true`、`idempotent=true`、`approval=confirm`。审批摘要必须说明监听地址、端口、用户增删数量、是否重启核心及失败回滚；不得显示 UUID、私钥或完整秘密引用。

manifest 1.3 适用性（2026-11-13）：

- 五项操作均**不声明** `reachability`（默认 false）。它们不切断管理员到服务器/面板的通道（代理数据面、非特权端口，不改防火墙/SSH/面板监听）；`network.proxy` 不在宿主 `ReachabilityCapabilityPrefixes`，不会被 R2 强制置真。`core.apply` 声明 write/medium/confirm；宿主按 high 下限计算有效风险并等待真人批准，MFA 下限仍按 destructive 判断。
- 首版**不声明** `ui.widgets`：widget 要求 `ui.entry` 入口页（ADR-0018），超出首版 UI 范围。`core.status`/`core.observe` 为 invoke/read，满足未来 widget 数据源条件（request schema 须接受 `{}`），留待后续版本。
- 扩展（非 base）：`core.capabilities` 在 `xray.mark` 扩展施工并 spike 通过后广告 `per_user_mark` 与可用 mark 段，供 proxy.advanced 探测（§17.4，ADR-0023 B-X4）；base 首版该能力为 unavailable。

### 7.1 输入

`core.apply` 只接受：

```json
{
  "config_revision": "7",
  "expected_running_revision": "3"
}
```

- `config_revision` 必填，必须等于执行时宿主当前 desired revision；空、非数字、过期均拒绝。
- `expected_running_revision` 可选；存在时与当前 running state 比较，冲突返回 `PRECONDITION_FAILED`。
- 请求不包含 Intent 或秘密，因此 operation 记录没有秘密明文。
- `core.validate/status/observe/capabilities` 的请求仅允许各自 Schema 声明的只读字段；禁止任意原生配置透传。

### 7.2 响应公共字段

Apply 结果至少包含：

- `desired_revision`、`running_revision`、`previous_revision`；
- `config_digest`、`core_version`；
- `enabled`、`process_state`、`api_state`；
- `restart_required`/`restarted` 的实际结果；
- `rollback_performed`；
- 非秘密警告列表。

不得返回原生配置、秘密、环境变量、命令行或任意本地路径。内部诊断路径只进受控宿主日志，并先脱敏。

## 8. Validate 与 Plan

### Validate

1. 从宿主读取指定 desired 快照；调用方只能操作本插件实例。
2. 严格解码并执行第 5 节语义校验。
3. 检查端口格式和纯静态冲突；不得绑定端口、写文件、reveal 或启动进程。
4. 返回字段级 violations 与 warnings。

### Plan

1. 执行同一纯校验；不调用 Xray `-test`，因为 Plan 没有 RUNNING operation，不能 reveal。
2. 读取当前 running 元数据，生成规范化、脱敏的 before/after Intent 差异。
3. 秘密变化只显示 `changed`/`unchanged`；可比较引用身份，但计划展示中不出现 ref。
4. 列出端口、监听、启停、用户数量和回滚能力；不产生任何资源或进程副作用。
5. 返回 `running/current` precondition，供 ExecutePlan 防止旧计划覆盖新状态。
6. 明确 warning：完整秘密解引用、Xray 原生预检和健康检查只在 Apply 执行。

## 9. Apply 状态机

每个实例一把互斥锁串行 Apply；不得使用全局锁。每一步检查 context cancellation。

```text
ACCEPTED
  → LOAD_DESIRED
  → CHECK_PRECONDITIONS
  → REVEAL_SECRETS
  → RENDER_CANDIDATE
  → WRITE_CANDIDATE
  → XRAY_TEST
  → SNAPSHOT_LAST_GOOD
  → SWITCH_PROCESS
  → WAIT_API_AND_HEALTH
  → COMMIT_RUNNING_STATE
  → REPORT_CHANGES
  → SUCCEEDED
```

### 9.1 各步骤硬要求

1. **LOAD_DESIRED**：通过 Host Config 读取当前 desired；比较 `config_revision`。
2. **CHECK_PRECONDITIONS**：读取 running state，检查 expected revision 和实例生命周期；未激活实例拒绝。
3. **REVEAL_SECRETS**：逐个揭示本次配置所需引用，绑定本插件 owner；任何失败立即终止，内存缓冲区尽快清零。
4. **RENDER_CANDIDATE**：使用固定模板生成完整原生配置；仅包含一个业务入站、direct outbound、必要 stats/policy 与私有 API。
5. **WRITE_CANDIDATE**：仅写 `work/<operation>/<attempt>`；生成确定性字节和摘要。
6. **XRAY_TEST**：调用锁定版本的配置测试命令，不启动业务监听；限制输出、时间和内存，错误输出脱敏。
7. **SNAPSHOT_LAST_GOOD**：保留 current/previous 指向的不可变 generation；不能在候选预检前覆盖 last-good 或修改 state 指针。
8. **SWITCH_PROCESS**：首版允许受控重启 Xray；先停止旧核心，再从已落盘的候选 generation 启动核心。`enabled=false` 时验证配置后停止核心并提交停止状态。
9. **WAIT_API_AND_HEALTH**：有界等待进程存活、UDS 可连且 StatsService 可用；不得只做进程存在检查。
10. **COMMIT_RUNNING_STATE**：在 generation 配置与目录 fsync 后，一次原子替换 `state.json` 提交 current/previous 指针，然后以 CAS 写宿主 KV 的运行元数据。
11. **REPORT_CHANGES**：上报 `config` 与 `runtime` 的非秘密 resource changes，附 running revision。

### 9.2 失败和回滚

- 在 SWITCH_PROCESS 之前失败：不接触现有进程；清理本次 work；running state 不变。
- SWITCH_PROCESS 之后失败：停止候选，从 previous 指向的不可变 generation 重启旧核心并做同一健康检查；state 指针保持旧值，直到旧核心恢复且健康。
- 只有旧核心恢复且健康时才能设置 `rollback_performed=true`；恢复失败返回 `RECOVERY_FAILED`，实例为故障状态，不得伪装成功。
- 用户取消和 deadline 走同一回滚路径；不能只返回 `context.Canceled` 而留下候选核心。
- 驱动在 Apply 中被杀：systemd 清理整个 cgroup；新进程只从已提交 current/state 恢复，忽略未完成 work。
- 若宿主在 plugin 返回后又因连接中断重试，新的 attempt 先读取 running state；目标已是 running revision 且 digest 相同则返回既有成功结果，不重复切换。

### 9.3 两阶段提交的已知边界

核心健康与宿主 KV CAS 不是跨系统原子事务。若核心已健康但 CAS 失败，Apply 必须回滚核心或明确返回不确定状态并触发状态重读；首版选择回滚，不能留下“运行新配置但记录旧 revision”的静默偏差。若回滚也失败，返回 `RECOVERY_FAILED` 并让 Status 从真实进程和磁盘状态诊断。

## 10. 生命周期与故障处理

| 场景 | 行为 |
|---|---|
| 首次安装，无运行快照 | 驱动可运行；Xray 不启动；状态 `UNCONFIGURED` |
| Activate，有有效 current | 校验二进制、目录、state 和摘要后启动 current；等待 API 健康 |
| Activate，有 desired 但无 current | 不 reveal；保持 `PENDING_APPLY`，提示调用 core.apply |
| Xray 子进程意外退出 | 驱动标记故障并上报；由所属 systemd 单元受控重启整个故障域；不做无界快速重试 |
| 驱动进程退出 | systemd 按单元策略回收 Xray 并重启；新进程从 current 恢复 |
| 宿主重启 | 新进程只读私有 current/state；不依赖 operation 或重新 reveal |
| 配置 desired 改变 | 现有 Xray 继续运行；状态显示 PENDING_APPLY |
| 插件更新/回滚 | 强制 restart，不蓝绿并行启动两个相同端口的核心 |
| 停止/卸载 | Deactivate/Stop 有界停止 API 与 Xray；卸载清理仍由宿主 owner 负责 |

健康信息必须区分：驱动存活、Xray 进程、Xray API、配置偏差、统计不可用。不能用“插件进程活着”代替“代理可用”。

## 11. Xray API 与统计

### 11.1 API 最小化

- 首选文件系统 UDS + 0600 + 私有目录；不使用抽象命名空间。
- 仅启用 StatsService；首版 Apply 不依赖 HandlerService，因此不开放它。
- API 配置和 socket 均由驱动生成，用户不能设置监听地址。
- 若锁定版本不支持所需 UDS 形式，X6 必须停止并上报；不得自动改成无保护的 `127.0.0.1`。
- gRPC 客户端设置 deadline、消息上限和受限 dialer；不使用环境代理。

### 11.2 计数器

原生名称：

```text
inbound>>>qwq-in-<id>>>>traffic>>>uplink
inbound>>>qwq-in-<id>>>>traffic>>>downlink
user>>>qwq-user-<id>>>>traffic>>>uplink
user>>>qwq-user-<id>>>>traffic>>>downlink
```

X0/X6 还需验证锁定版本的 policy 字段、原生用户字段和 StatsService RPC。当前已知配置概念包括 `stats:{}` 以及用户/入站上下行 policy 开关，但普通模型不得凭示例补字段。

### 11.3 标准化输出

每个系列返回：

- `kind`：`inbound` 或 `user`；
- `id`：面板稳定 ID；
- `uplink_bytes`、`downlink_bytes`；
- `reset_epoch`：当前 Xray 进程代次；
- `collected_at`、`source="xray"`。

首版返回当前代次的原始累计值，不把重启后的零值累加成虚假生命周期总量。调用方只能比较同一 reset epoch 的值；新 epoch 必须重新建基线。`Observe` 永不调用 reset=true。

## 12. 错误码

| 错误码 | 用途 |
|---|---|
| `INVALID_INTENT` | 结构或语义校验失败 |
| `UNSUPPORTED` | 首版之外的协议、传输、出站或字段 |
| `CONFIG_REVISION_CONFLICT` | 指定 desired 已不是当前 desired |
| `PRECONDITION_FAILED` | running precondition 不匹配 |
| `PENDING_APPLY` | desired 与 running 不同；仅状态使用，不作为 Apply 失败 |
| `CORE_BINARY_MISMATCH` | Xray 路径、类型或摘要不符 |
| `CORE_CONFIG_INVALID` | Xray 原生预检失败 |
| `CORE_START_FAILED` | 核心启动失败 |
| `CORE_API_UNAVAILABLE` | 私有 API 不可用 |
| `CORE_UNHEALTHY` | 健康检查失败 |
| `SECRET_UNAVAILABLE` | 秘密无法受控解密，不包含 ref/明文 |
| `RECOVERY_FAILED` | 旧配置恢复失败，或核心健康但运行状态提交失败后无法恢复一致状态 |
| `SNAPSHOT_CORRUPT` | 当前快照与状态摘要不一致 |
| `DATA_DIR_UNAVAILABLE` | 私有目录缺失、越权或权限不安全 |

字段错误优先使用 `pluginsdk.Validation`，带 RFC 6901 pointer。底层错误不能直接透传，因为可能含路径、配置片段或秘密。

## 13. 日志与脱敏

- 默认不启用 Xray access log；错误日志经有界 reader 转发并限长。
- 禁止记录：UUID、REALITY 私钥/公钥、完整配置、secret ref、环境变量、完整命令行、未脱敏上游 stderr。
- 可记录：operation id、attempt、插件/核心版本、端口、阶段、稳定面板 ID、摘要、进程退出码。
- 公钥是否可用于客户端分享属于后续导出功能；首版不导出，因此按敏感值处理。
- 所有响应、Plan before/after、operation result、event payload、audit details 必须通过同一脱敏测试夹具。

## 14. 技术 spike 与证据

在写正式实现前回答：

1. 锁定版本的 VLESS 入站用户字段、RAW 名称、Vision flow、REALITY target/serverNames/privateKey/shortIds 的准确形态是什么？
2. `xray run -test` 是否只校验而不监听业务端口？若不是，需换预检方式并重写 Apply。
3. Xray API 是否能通过传统 inbound + routing 在文件系统 UDS 上提供 StatsService？权限和实际 socket 模式是什么？
4. 最小 StatsService proto 的 import 路径、RPC、counter 查询方式及消息上限是什么？
5. VLESS/REALITY/Vision/RAW 的真实客户端配置能否建立连接并转发一次受控 HTTP 请求？
6. 用户/入站统计 policy 的准确字段、统计启动时点和进程重启清零行为是什么？
7. 驱动+Xray 在同一动态 UID/cgroup 下能否启动、停止和被完整回收？
8. 新网络 capability 开启前后，普通 noop 单元是否保持字节级默认拒绝，core.xray 是否只得到所需地址族？

证据包含锁定源码/文档引用、配置、命令、输出摘要和测试位置。任何失败都回到 ADR-0022，不允许普通模型自行扩大权限或协议范围。

## 15. 设计审查清单

施工前必须全部回答“是”：

- [ ] 没有改 Platform ABI、公共 API 或 manifest schema。
- [ ] 没有通用 shell、任意路径、任意服务管理或特权端口授权。
- [ ] 网络、DataDir 和 secret owner 三个宿主配套均有最小边界。
- [ ] desired 与 running 永不混称“已应用”。
- [ ] Plan 和后台恢复不依赖 reveal。
- [ ] 明文只存在于 Apply 临时内存和 0600 私有运行配置。
- [ ] Apply 中途取消、kill、CAS 失败和恢复失败都有确定行为。
- [ ] API 不暴露公网或不设防回环 TCP。
- [ ] 统计不 reset，reset epoch 能防止负流量。
- [ ] 首版能力矩阵与真实客户端测试一一对应。
- [ ] 所有普通模型停止条件在 PLAN 与任务卡中一致。

## 16. 参考资料

- Xray API：https://xtls.github.io/en/config/api.html
- Xray VLESS：https://xtls.github.io/en/config/inbounds/vless.html
- Xray REALITY：https://xtls.github.io/en/config/transports/reality.html
- Xray Stats：https://xtls.github.io/en/config/stats.html
- 本仓库现状证据（main ccbfb13）：`internal/sandbox/templates/qwq-plugin@.service`、`internal/sandbox/unit.go`、`internal/controller/updater_runtime.go`、`internal/controller/plugin_runtime.go`、`internal/pluginhost/updater/runtime.go`、`internal/pluginhost/updater/config.go`、`internal/secrets/secrets.go`、`internal/pluginhost/hostsvc/secrets.go`、`internal/operations/action.go`、`api/qwq/platform/v1/platform.proto`。
- manifest 1.3（p2-b f65bc36，尚未合入 main）：`sdk/manifest/manifest.schema.json`、`sdk/manifest/rules.go`、`sdk/manifest/types.go`、ADR-0018。
- proxy.advanced 硬限速契约（proxy-advanced 克隆，ADR-0023 §2.4/§5，B-X4；另一会话 d0ce9003 在制品，只读参考）：per-user fwmark + tc HTB 的契约依赖与 spike S1–S6。

## 17. 扩展补遗：per-user mark（供 proxy.advanced 硬限速）

> **本节是设计补遗，不是首版 base 范围。** 用户 2026-11-13 决定 `proxy.advanced` 首版就要硬限速（每用户 fwmark + tc HTB），需要 core.xray Core Intent 支持可选 per-user mark。本节与 ADR-0023（`proxy.advanced`，§2.4 契约依赖 B-X4、§5 硬速率限制设计）**互为契约依赖**：ADR-0023 明确把具体字段名/schema/版本交由 core.xray 移植会话定，本节即该决定；两边表述须一致。首版 base（§1–§16、X4–X12 基础验收）不变，mark 为**可选增量**，按 proxy.advanced 需要与 spike 结果单独施工。

### 17.1 契约与命名空间

按 §5.1 约定，核心专属能力用 `xray.<extension>` 命名空间并另升契约版本：

- 扩展标识 **`xray.mark`**，扩展契约版本 **`"1"`**（独立于 base）。base Intent `schema_version` 仍为 `"1"`，base 字段与校验一字不动。
- 扩展经顶层可选 `xray` 命名空间对象显式声明；声明后 `users[].mark` 才被识别。**未声明扩展时，base 严格解码拒绝 `xray` 对象与 `users[].mark`**（保持「任何未声明字段都拒绝」）。
- `users[].mark`：**可选 uint32**，同一 Intent 内**唯一**；缺省（不写 mark）= 现有行为，共享默认 direct 出站、不打 mark。

扩展声明形状（引用形式示例，非可粘贴真实配置）：

```json
{
  "schema_version": "1",
  "xray": { "mark": { "version": "1" } },
  "enabled": true,
  "inbound": { "...": "..." },
  "users": [
    { "id": "alice", "uuid": {"$secret": "sec_a"}, "mark": 20736 },
    { "id": "bob",   "uuid": {"$secret": "sec_b"} }
  ],
  "outbound": {"type": "direct"}
}
```

上例 `alice` 带 mark（20736 = 0x5100），`bob` 不带 mark 走默认 direct 出站。`xray.mark.version` 缺失或非 `"1"` 拒绝；未来 mark 契约变更升扩展版本，base 不动。

### 17.2 字段规则（增量）

| 字段 | 规则 |
|---|---|
| `xray.mark.version` | 声明扩展时必填，必须为 `"1"`；未知扩展键拒绝 |
| `users[].mark` | 可选；存在时必须为 uint32 且 ∈ [1, 0xFFFFFFFF]（**拒绝 0**：0 语义为「无 mark」，由缺省表达，避免专属出站却无标记的歧义）；同一 Intent 内唯一（重复 → `INVALID_INTENT`） |
| 其余字段 | 与 base §5.3 完全一致；mark 不放宽任何 base 上限（users 仍 1–256） |

保留 mark 段（暂定 `0x5100–0x51FF`，256 个，ADR-0023 §5.2，spike 确认与宿主无冲突后固化）是 **proxy.advanced 的分配策略**：由 proxy.advanced 在段内为每用户分配唯一 mark、qwq-capability helper 校验 mark 仅在保留段。core.xray 只做 uint32 + 唯一的结构校验，**不在 core.xray 硬编码暂定段**；可用 mark 段经 `core.capabilities` 广告（§17.4），proxy.advanced 以探测到的段为准。

### 17.3 渲染（per-user 专属 direct 出站 + routing）

- 每个带 mark 的用户渲染一个**专属 direct（freedom）出站**，稳定 tag `qwq-out-<user.id>`，`streamSettings.sockopt.mark = <mark>`；并渲染一条 routing 规则 `user: ["qwq-user-<user.id>"] → outboundTag: qwq-out-<user.id>`（Xray routing 按 VLESS email 匹配，email 即 §5.5 的 `qwq-user-<id>`）。
- 未带 mark 的用户与默认流量走 base 的共享 direct 出站；默认出站保留作 fallback。
- **仍仅 direct 出站，不开放任意上游或用户可配路由**：mark 是 socket 标记，不是上游选择器；routing 规则由驱动按固定模板生成（每用户一条 `user→专属 direct`），用户不能指定任意 outbound/路由。这与 base §3「不做自定义路由/任意 outbound」不冲突——扩展只增加驱动生成的固定 per-user direct 出站。
- 稳定标识增量：`OutboundTag(id) = qwq-out-<id>`（纯函数，与 `InboundTag`/`UserEmail` 同规则，禁止自由文本进入 tag）。**统计标识不变**（`user>>>qwq-user-<id>>>>traffic>>>…`），mark 扩展不影响 observe 契约（ADR-0023 §2.4 第 5 条）。
- `sockopt.mark` 的准确字段路径与 freedom 出站支持性由 X0/X6 按锁定版本证实，不凭示例假设。

### 17.4 capabilities 广告

`core.capabilities` 的已验证矩阵增量广告 **`per_user_mark`**：

- `declared`：本包声明支持 per-user mark；`verified`：仅在 X6 spike S1（REALITY+Vision+RAW 下 mark 正确传播）通过后置真；`unavailable` 及原因。
- 同时广告**可用 mark 段**（与 proxy.advanced 约定、spike 固化后的保留段），供 proxy.advanced 探测分配。
- proxy.advanced 经 `core.capabilities` 探测：未广告 `per_user_mark`（B-X4 未就绪）→ 其硬限速不可用（`HARD_SHAPE_UNSUPPORTED`，诚实降级，ADR-0023 §5.7），仅配额软执行。core.xray 不得在 spike 未过时把 `per_user_mark` 写成 verified。

### 17.5 方向与整形可行性（spike gated，不得宣称已支持）

- mark 打在**出站 socket**（proxy↔上游腿的 egress）。**上行**（用户→上游）：proxy→上游 egress 带 mark → 物理 iface egress HTB 按 mark 分类，相对成熟（ADR-0023 S2，仍 spike 确认）。
- **下行**（上游→用户）：上游→proxy 是带 mark socket 的 **ingress**，需 nft `socket mark` 取回 + clsact/ifb 重定向 + ifb egress HTB；**netfilter ingress hook 与 tc clsact ingress 的执行顺序**（mark 必须在 mirred redirect 之前设置）是成败关键，未验证（ADR-0023 S3）。**不得写成已支持**；无可行路径则下行硬限速首版不可交付，回退由用户决定。
- **职责边界**：tc/nft/ip 全部由 proxy.advanced 经 H4 → qwq-capability helper（CAP_NET_ADMIN、宿主 netns）执行；**core.xray 只渲染 sockopt.mark + routing，不碰内核、不建 tc/nft、不申请 `system.*` capability**。整形规则的生命周期/对账/热变更属 proxy.advanced（ADR-0023 §5.5/§5.6）。
- core.xray X6 增「REALITY 下 mark 传播（S1）+ ingress 方向整形可行性（S3）」验证项；完整 HTB 限速/规模/隔离/热变更（S2/S4/S5/S6）属 proxy.advanced 独立 spike（PA-S1，可随 X6）。任何失败回 ADR-0022/0023，不擅自扩权/扩协议。

### 17.6 资源与施工增量

- per-user 专属出站至 256 个（随 users 上限），FD/内存/渲染开销随之上升；X11 资源实测须覆盖带 mark 的满用户场景，manifest 资源上限据此复核。
- 施工：X4 增「可选 mark 严格校验 + `OutboundTag` 纯函数 + 扩展声明解码」（标注为扩展步骤，非 base 验收）；X6 增 per-user outbound/routing 渲染与 S1/S3 spike。**base 首版验收矩阵不变**；扩展未施工/未验证时，core.xray 仍按 base 交付，`per_user_mark` 广告为 unavailable。
- 审查增量：未声明扩展时 base 解码拒绝 mark/xray；mark 唯一性与 uint32 边界；渲染仍仅 direct；统计标识不变；capabilities 不把未验证 mark 写成 verified；core.xray 不碰 tc/nft。
